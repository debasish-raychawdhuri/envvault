//! Terminal lifecycle, event loop, and rendering for the interactive editor.

mod app;

use crate::crypto::Session;
use crate::vault::EnvVault;
use anyhow::{Context, Result};
use app::{App, Mode};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use std::io::Stdout;
use zeroize::Zeroizing;

/// Open the interactive editor for `vault`, saving back through `session` to
/// `path` when the user saves (`w`) or chooses save-on-quit.
pub fn run(session: &Session, path: &std::path::Path, vault: EnvVault) -> Result<()> {
    let mut terminal = setup_terminal()?;
    let label = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vault")
        .to_string();
    let mut app = App::new(vault, label);
    let result = event_loop(&mut terminal, &mut app, session, path);
    restore_terminal(&mut terminal)?;
    result
}

type Tui = Terminal<CrosstermBackend<Stdout>>;

fn setup_terminal() -> Result<Tui> {
    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
    let terminal = Terminal::new(CrosstermBackend::new(stdout))
        .context("failed to initialize terminal")?;
    Ok(terminal)
}

fn restore_terminal(terminal: &mut Tui) -> Result<()> {
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();
    Ok(())
}

fn event_loop(terminal: &mut Tui, app: &mut App, session: &Session, path: &std::path::Path) -> Result<()> {
    loop {
        terminal.draw(|f| draw(f, app))?;

        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        match app.mode {
            Mode::Browse => match key.code {
                KeyCode::Char('q') | KeyCode::Esc => app.request_quit(),
                KeyCode::Down | KeyCode::Char('j') => app.select_next(),
                KeyCode::Up | KeyCode::Char('k') => app.select_prev(),
                KeyCode::Char('a') => app.begin_add(),
                KeyCode::Char('e') | KeyCode::Enter => app.begin_edit(),
                KeyCode::Char('d') => app.begin_delete(),
                KeyCode::Char('s') => app.toggle_reveal(),
                KeyCode::Char('w') => save(app, session, path),
                _ => {}
            },
            Mode::AddKey | Mode::AddValue | Mode::EditValue => match key.code {
                KeyCode::Enter => app.submit_input(),
                KeyCode::Esc => app.cancel_input(),
                KeyCode::Backspace => app.backspace(),
                KeyCode::Char(c) => app.push_char(c),
                _ => {}
            },
            Mode::ConfirmDelete => match key.code {
                KeyCode::Char('y') => app.confirm_delete(),
                KeyCode::Char('n') | KeyCode::Esc => app.cancel_quit(),
                _ => {}
            },
            Mode::ConfirmQuit => match key.code {
                KeyCode::Char('s') => {
                    save(app, session, path);
                    if !app.dirty {
                        app.should_quit = true;
                    } else {
                        // Save failed; stay so the user can see the error.
                        app.cancel_quit();
                    }
                }
                KeyCode::Char('d') => app.quit_discarding(),
                KeyCode::Char('c') | KeyCode::Esc => app.cancel_quit(),
                _ => {}
            },
        }

        if app.should_quit {
            break;
        }
    }
    Ok(())
}

/// Encrypt and persist; on failure show the error in the footer instead of
/// tearing down the UI.
fn save(app: &mut App, session: &Session, path: &std::path::Path) {
    let data = Zeroizing::new(app.vault.serialize());
    match session.save(path, data.as_bytes()) {
        Ok(()) => app.mark_saved(),
        Err(e) => app.status = format!("save failed: {e}"),
    }
}

// --- rendering ------------------------------------------------------------

fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // title
            Constraint::Min(1),    // list
            Constraint::Length(3), // footer
        ])
        .split(f.area());

    draw_title(f, app, chunks[0]);
    draw_list(f, app, chunks[1]);
    draw_footer(f, app, chunks[2]);

    match app.mode {
        Mode::AddKey => draw_input(f, "New entry — key name, or KEY=VALUE", &app.input),
        Mode::AddValue => draw_input(f, "Value", &app.input),
        Mode::EditValue => draw_input(f, "Edit value", &app.input),
        Mode::ConfirmDelete => {
            let key = &app.vault.entries()[app.selected].key;
            draw_confirm(f, &format!("Delete '{key}'?  [y]es / [n]o"));
        }
        Mode::ConfirmQuit => {
            draw_confirm(f, "Unsaved changes — [s]ave & quit / [d]iscard / [c]ancel");
        }
        Mode::Browse => {}
    }
}

fn draw_title(f: &mut Frame, app: &App, area: Rect) {
    let dirty = if app.dirty { " *" } else { "" };
    let title = format!(" envvault — {}{} ", app.vault_label(), dirty);
    let p = Paragraph::new(title)
        .style(Style::default().add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(p, area);
}

fn draw_list(f: &mut Frame, app: &App, area: Rect) {
    if app.vault.is_empty() {
        let p = Paragraph::new("No secrets yet. Press 'a' to add one.")
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL).title(" secrets "));
        f.render_widget(p, area);
        return;
    }

    let items: Vec<ListItem> = app
        .vault
        .entries()
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let shown = if app.is_revealed(i) {
                e.value.clone()
            } else {
                mask(&e.value)
            };
            let line = Line::from(vec![
                Span::styled(
                    format!("{} ", e.key),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("= ", Style::default().fg(Color::DarkGray)),
                Span::raw(shown),
            ]);
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" secrets "))
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("› ");

    let mut state = ListState::default();
    state.select(Some(app.selected));
    f.render_stateful_widget(list, area, &mut state);
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let keys = "↑/↓ move  a add  e edit  d delete  s show/hide  w save  q quit";
    let text = if app.status.is_empty() {
        keys.to_string()
    } else {
        format!("{}   |   {keys}", app.status)
    };
    let p = Paragraph::new(text)
        .style(Style::default().fg(Color::Gray))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(p, area);
}

fn draw_input(f: &mut Frame, title: &str, value: &str) {
    let area = centered_rect(60, 20, f.area());
    f.render_widget(Clear, area);
    // Input is shown in plaintext while editing — you can't edit what you
    // can't see. Masking is only for the browse list.
    let body = format!("{value}█");
    let p = Paragraph::new(body)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {title} (Enter to confirm, Esc to cancel) ")),
        );
    f.render_widget(p, area);
}

fn draw_confirm(f: &mut Frame, message: &str) {
    let area = centered_rect(60, 20, f.area());
    f.render_widget(Clear, area);
    let p = Paragraph::new(message)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow))
                .title(" confirm "),
        );
    f.render_widget(p, area);
}

fn mask(value: &str) -> String {
    if value.is_empty() {
        "(empty)".to_string()
    } else {
        "•".repeat(value.chars().count().min(24))
    }
}

/// A rectangle centered within `r`, sized as a percentage of width/height.
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

//! Terminal lifecycle, event loop, and rendering for the interactive editor.

mod app;

use crate::crypto::Session;
use crate::vault::EnvVault;
use anyhow::{Context, Result};
use app::{App, Mode};
use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEventKind,
};
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
    // Overwrite ratatui's render buffers before teardown so any revealed
    // secret characters don't linger in the cell storage that is about to be
    // freed. `app` (and its vault) zeroize their own copies on drop.
    wipe_render_buffers(&mut terminal);
    restore_terminal(&mut terminal)?;
    result
}

/// Draw blank frames so the secret text in ratatui's internal `Buffer` cells
/// is overwritten in place. Two passes cover both of the terminal's swap
/// buffers (the current frame and the previously displayed one).
fn wipe_render_buffers(terminal: &mut Tui) {
    for _ in 0..2 {
        let _ = terminal.draw(|f| f.render_widget(Clear, f.area()));
    }
}

type Tui = Terminal<CrosstermBackend<Stdout>>;

fn setup_terminal() -> Result<Tui> {
    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = std::io::stdout();
    // Bracketed paste makes the terminal wrap pasted text so it arrives as a
    // single `Event::Paste` we can distinguish from typing — needed so we can
    // wipe the clipboard after a secret is pasted.
    execute!(stdout, EnterAlternateScreen, EnableBracketedPaste)
        .context("failed to enter alternate screen")?;
    let terminal = Terminal::new(CrosstermBackend::new(stdout))
        .context("failed to initialize terminal")?;
    Ok(terminal)
}

fn restore_terminal(terminal: &mut Tui) -> Result<()> {
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableBracketedPaste).ok();
    terminal.show_cursor().ok();
    Ok(())
}

fn event_loop(terminal: &mut Tui, app: &mut App, session: &Session, path: &std::path::Path) -> Result<()> {
    // Held for the whole session so a cleared (empty) clipboard keeps being
    // served on X11, where the setting process must stay alive to serve the
    // selection. `None` if no clipboard is reachable (e.g. headless / SSH
    // without a display, or ENVVAULT_NO_CLIPBOARD) — pasting still works, we
    // just can't wipe it.
    let mut clipboard = crate::open_clipboard();

    loop {
        terminal.draw(|f| draw(f, app))?;

        let ev = event::read()?;
        if let Event::Paste(text) = &ev {
            handle_paste(app, &mut clipboard, text);
            continue;
        }
        let Event::Key(key) = ev else {
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

/// Insert pasted text into the active input field and, if it landed there,
/// wipe the system clipboard so the pasted secret doesn't linger in it.
fn handle_paste(app: &mut App, clipboard: &mut Option<arboard::Clipboard>, text: &str) {
    if !app.paste(text) {
        return; // not in an input field — nothing was entered, leave clipboard alone
    }
    app.status = match clipboard.as_mut() {
        Some(cb) => match cb.clear() {
            Ok(()) => "pasted — clipboard cleared".to_string(),
            Err(e) => format!("pasted — could not clear clipboard: {e}"),
        },
        None => "pasted — clipboard unavailable to clear".to_string(),
    };
}

/// Encrypt and persist; on failure show the error in the footer instead of
/// tearing down the UI.
fn save(app: &mut App, session: &Session, path: &std::path::Path) {
    let data = app.vault.serialize();
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

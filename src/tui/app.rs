//! State machine for the interactive vault editor.

use crate::vault::{validate_key, EnvVault};
use std::collections::HashSet;
use zeroize::{Zeroize, Zeroizing};

/// What the UI is currently doing. Determines which keys are handled and which
/// overlay (if any) is drawn.
#[derive(PartialEq, Eq)]
pub enum Mode {
    /// Browsing the list of entries.
    Browse,
    /// Typing the key for a new entry.
    AddKey,
    /// Typing the value for the new entry (key already accepted).
    AddValue,
    /// Editing the value of the selected entry.
    EditValue,
    /// Confirming deletion of the selected entry.
    ConfirmDelete,
    /// Confirming quit while there are unsaved changes.
    ConfirmQuit,
}

pub struct App {
    pub vault: EnvVault,
    /// Display name for the vault (its file name), shown in the title bar.
    label: String,
    pub selected: usize,
    pub revealed: HashSet<usize>,
    pub dirty: bool,
    pub mode: Mode,
    /// Text buffer for the active input overlay.
    pub input: String,
    /// Key captured during the two-step add flow.
    pending_key: Option<String>,
    /// Transient one-line message shown in the footer.
    pub status: String,
    /// Set when the user wants to leave the event loop.
    pub should_quit: bool,
}

impl App {
    pub fn new(vault: EnvVault, label: String) -> Self {
        Self {
            vault,
            label,
            selected: 0,
            revealed: HashSet::new(),
            dirty: false,
            mode: Mode::Browse,
            // Pre-allocate so typing a secret rarely reallocates (a realloc
            // would leave an un-zeroized copy of the partial value behind).
            input: String::with_capacity(256),
            pending_key: None,
            status: String::new(),
            should_quit: false,
        }
    }

    fn set_status(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
    }

    /// Empty the input buffer, wiping its contents from memory (unlike
    /// `String::clear`, which leaves the bytes in the backing allocation).
    fn clear_input(&mut self) {
        self.input.zeroize();
    }

    pub fn is_revealed(&self, index: usize) -> bool {
        self.revealed.contains(&index)
    }

    pub fn vault_label(&self) -> &str {
        &self.label
    }

    // --- navigation -------------------------------------------------------

    pub fn select_next(&mut self) {
        if self.vault.len() > 1 {
            self.selected = (self.selected + 1).min(self.vault.len() - 1);
        }
    }

    pub fn select_prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    fn clamp_selection(&mut self) {
        if self.vault.is_empty() {
            self.selected = 0;
        } else if self.selected >= self.vault.len() {
            self.selected = self.vault.len() - 1;
        }
    }

    // --- entry actions ----------------------------------------------------

    pub fn begin_add(&mut self) {
        self.mode = Mode::AddKey;
        self.clear_input();
        self.pending_key = None;
        self.set_status("");
    }

    pub fn begin_edit(&mut self) {
        if self.vault.is_empty() {
            self.set_status("nothing to edit — press 'a' to add an entry");
            return;
        }
        // Seed the editor with the current value without leaving an
        // un-zeroized clone behind (plain `=` assignment would drop the old
        // input buffer without wiping it).
        self.clear_input();
        let value = Zeroizing::new(self.vault.entries()[self.selected].value.clone());
        self.input.push_str(&value);
        self.mode = Mode::EditValue;
        self.set_status("");
    }

    pub fn begin_delete(&mut self) {
        if self.vault.is_empty() {
            return;
        }
        self.mode = Mode::ConfirmDelete;
    }

    pub fn toggle_reveal(&mut self) {
        if self.vault.is_empty() {
            return;
        }
        if !self.revealed.remove(&self.selected) {
            self.revealed.insert(self.selected);
        }
    }

    pub fn confirm_delete(&mut self) {
        let removed = self.vault.entries()[self.selected].key.clone();
        self.vault.remove_at(self.selected);
        self.revealed.clear();
        self.clamp_selection();
        self.dirty = true;
        self.mode = Mode::Browse;
        self.set_status(format!("deleted {removed}"));
    }

    /// Confirm the current text input for whichever input mode is active.
    pub fn submit_input(&mut self) {
        match self.mode {
            Mode::AddKey => {
                // Accept either a bare key name (then prompt for the value) or
                // a full `KEY=VALUE` assignment typed in one go.
                if let Some((key, value)) = crate::vault::split_assignment(&self.input) {
                    let value = Zeroizing::new(value);
                    if let Err(e) = validate_key(&key) {
                        self.set_status(format!("invalid key: {e}"));
                        return;
                    }
                    let idx = self.vault.set(&key, &value);
                    self.selected = idx;
                    self.dirty = true;
                    self.set_status(format!("added {key}"));
                    self.clear_input();
                    self.mode = Mode::Browse;
                    return;
                }
                let key = self.input.trim().to_string();
                if let Err(e) = validate_key(&key) {
                    self.set_status(format!("invalid key: {e}"));
                    return;
                }
                if self.vault.contains(&key) {
                    self.set_status(format!("'{key}' already exists — editing its value"));
                }
                self.pending_key = Some(key);
                self.clear_input();
                self.mode = Mode::AddValue;
            }
            Mode::AddValue => {
                if let Some(key) = self.pending_key.take() {
                    let idx = self.vault.set(&key, &self.input);
                    self.selected = idx;
                    self.dirty = true;
                    self.set_status(format!("added {key}"));
                }
                self.clear_input();
                self.mode = Mode::Browse;
            }
            Mode::EditValue => {
                self.vault.set_value_at(self.selected, &self.input);
                self.dirty = true;
                self.set_status("value updated");
                self.clear_input();
                self.mode = Mode::Browse;
            }
            _ => {}
        }
    }

    pub fn cancel_input(&mut self) {
        self.clear_input();
        self.pending_key = None;
        self.mode = Mode::Browse;
        self.set_status("cancelled");
    }

    pub fn push_char(&mut self, c: char) {
        self.input.push(c);
    }

    /// Insert pasted text into the active input buffer. Newlines and carriage
    /// returns are dropped so a multi-line paste can't break the single-line
    /// vault format (or smuggle past the Enter handler). Returns true if the
    /// paste landed in an input field, so the caller knows to wipe the
    /// clipboard.
    pub fn paste(&mut self, text: &str) -> bool {
        if !matches!(self.mode, Mode::AddKey | Mode::AddValue | Mode::EditValue) {
            return false;
        }
        for c in text.chars().filter(|&c| c != '\n' && c != '\r') {
            self.input.push(c);
        }
        true
    }

    pub fn backspace(&mut self) {
        self.input.pop();
    }

    // --- save / quit ------------------------------------------------------

    /// Called by the event loop after a successful save.
    pub fn mark_saved(&mut self) {
        self.dirty = false;
        self.set_status("saved");
    }

    /// Request quit. If there are unsaved changes, route through the confirm
    /// dialog instead of leaving immediately.
    pub fn request_quit(&mut self) {
        if self.dirty {
            self.mode = Mode::ConfirmQuit;
        } else {
            self.should_quit = true;
        }
    }

    pub fn quit_discarding(&mut self) {
        self.should_quit = true;
    }

    pub fn cancel_quit(&mut self) {
        self.mode = Mode::Browse;
    }
}

impl Drop for App {
    /// Wipe any secret material still held in the UI state when the editor
    /// closes. (`vault` wipes itself via its own `ZeroizeOnDrop`.)
    fn drop(&mut self) {
        self.input.zeroize();
        self.status.zeroize();
        if let Some(k) = self.pending_key.as_mut() {
            k.zeroize();
        }
    }
}

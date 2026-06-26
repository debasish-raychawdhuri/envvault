//! In-memory model of the decrypted vault: an ordered list of `KEY=VALUE`
//! environment-variable entries, parsed from / serialized to a dotenv-style
//! text blob.

use anyhow::{bail, Result};

#[derive(Clone, Debug)]
pub struct Entry {
    pub key: String,
    pub value: String,
}

#[derive(Default)]
pub struct EnvVault {
    entries: Vec<Entry>,
}

impl EnvVault {
    /// Parse a dotenv-style blob. Blank lines and `#` comments are ignored.
    /// An optional `export ` prefix and surrounding quotes on the value are
    /// stripped so hand-written or imported `.env` files import cleanly.
    pub fn parse(text: &str) -> Self {
        let mut entries = Vec::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let key = k.trim().to_string();
            if key.is_empty() {
                continue;
            }
            let value = unquote(v.trim());
            entries.push(Entry { key, value });
        }
        Self { entries }
    }

    /// Serialize back to a dotenv-style blob (one `KEY=VALUE` per line). Values
    /// are quoted only when they would otherwise not round-trip cleanly.
    pub fn serialize(&self) -> String {
        let mut out = String::new();
        for e in &self.entries {
            out.push_str(&e.key);
            out.push('=');
            out.push_str(&quote_if_needed(&e.value));
            out.push('\n');
        }
        out
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn position(&self, key: &str) -> Option<usize> {
        self.entries.iter().position(|e| e.key == key)
    }

    /// Insert a new entry or update the value of an existing key (case
    /// sensitive). Returns the index of the affected entry.
    pub fn set(&mut self, key: &str, value: &str) -> usize {
        match self.position(key) {
            Some(i) => {
                self.entries[i].value = value.to_string();
                i
            }
            None => {
                self.entries.push(Entry {
                    key: key.to_string(),
                    value: value.to_string(),
                });
                self.entries.len() - 1
            }
        }
    }

    /// Update the value at a given index (used by the TUI editor).
    pub fn set_value_at(&mut self, index: usize, value: &str) {
        if let Some(e) = self.entries.get_mut(index) {
            e.value = value.to_string();
        }
    }

    pub fn remove_at(&mut self, index: usize) {
        if index < self.entries.len() {
            self.entries.remove(index);
        }
    }

    pub fn contains(&self, key: &str) -> bool {
        self.position(key).is_some()
    }
}

/// If `input` looks like a `KEY=VALUE` assignment, split it into the key
/// (trimmed) and value (with surrounding quotes stripped), like a dotenv line.
/// Returns `None` when there is no `=`.
pub fn split_assignment(input: &str) -> Option<(String, String)> {
    let (k, v) = input.split_once('=')?;
    Some((k.trim().to_string(), unquote(v.trim())))
}

/// Validate that a string is a usable environment-variable name:
/// `[A-Za-z_][A-Za-z0-9_]*`.
pub fn validate_key(key: &str) -> Result<()> {
    if key.is_empty() {
        bail!("key cannot be empty");
    }
    let mut chars = key.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphabetic() || first == '_') {
        bail!("key must start with a letter or underscore");
    }
    if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        bail!("key may only contain letters, digits, and underscores");
    }
    Ok(())
}

fn unquote(v: &str) -> String {
    let bytes = v.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        // Double-quoted: reverse the `\\` and `\"` escaping done on save.
        if first == b'"' && last == b'"' {
            let inner = &v[1..v.len() - 1];
            let mut out = String::with_capacity(inner.len());
            let mut chars = inner.chars();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    match chars.next() {
                        Some('\\') => out.push('\\'),
                        Some('"') => out.push('"'),
                        Some(other) => {
                            out.push('\\');
                            out.push(other);
                        }
                        None => out.push('\\'),
                    }
                } else {
                    out.push(c);
                }
            }
            return out;
        }
        // Single-quoted: literal contents.
        if first == b'\'' && last == b'\'' {
            return v[1..v.len() - 1].to_string();
        }
    }
    v.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_basic_entries() {
        let v = EnvVault::parse("FOO=bar\nBAZ=qux\n");
        assert_eq!(v.len(), 2);
        let v2 = EnvVault::parse(&v.serialize());
        assert_eq!(v2.entries()[0].key, "FOO");
        assert_eq!(v2.entries()[0].value, "bar");
        assert_eq!(v2.entries()[1].value, "qux");
    }

    #[test]
    fn ignores_comments_blanks_and_export() {
        let v = EnvVault::parse("# a comment\n\nexport API_KEY=sk-123\n");
        assert_eq!(v.len(), 1);
        assert_eq!(v.entries()[0].key, "API_KEY");
        assert_eq!(v.entries()[0].value, "sk-123");
    }

    #[test]
    fn round_trips_tricky_values() {
        // values with spaces, '#', quotes, backslashes, leading/trailing space
        for raw in [
            "value with spaces",
            "has#hash",
            "with\"quote",
            "back\\slash",
            " leading-and-trailing ",
            "",
        ] {
            let mut v = EnvVault::default();
            v.set("K", raw);
            let restored = EnvVault::parse(&v.serialize());
            assert_eq!(restored.entries()[0].value, raw, "failed for {raw:?}");
        }
    }

    #[test]
    fn set_updates_existing_key_in_place() {
        let mut v = EnvVault::parse("A=1\nB=2\n");
        let idx = v.set("A", "99");
        assert_eq!(idx, 0);
        assert_eq!(v.len(), 2);
        assert_eq!(v.entries()[0].value, "99");
    }

    #[test]
    fn key_validation() {
        assert!(validate_key("FOO_BAR1").is_ok());
        assert!(validate_key("_x").is_ok());
        assert!(validate_key("").is_err());
        assert!(validate_key("1abc").is_err());
        assert!(validate_key("has-dash").is_err());
        assert!(validate_key("has space").is_err());
    }
}

fn quote_if_needed(v: &str) -> String {
    let needs = v.is_empty()
        || v.starts_with(['"', '\'', ' '])
        || v.ends_with(' ')
        || v.contains('#')
        || v.contains('\n');
    if needs {
        // Escape backslashes and double quotes, wrap in double quotes.
        let escaped = v.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    } else {
        v.to_string()
    }
}

//! Precomputed identity/marker lookup table for every possible `mbr_val` (0-2047).
//!
//! Used by the full-`mbr_val`-space collision search (`search` without `--identity`) to
//! turn a found `mbr_val` back into a real, usable MBR identity/marker pair -- any identity
//! sharing the same `mbr_val` is functionally interchangeable for licensing purposes,
//! see `docs/reference/identity-reverse-search.md`.

use std::fs;
use std::path::Path;

/// Embedded copy of the checked-in `mbr-table.toml` (all 2048 entries). Self-heals a
/// missing, unreadable, or incomplete `--mbr-table` file: any `mbr_val` not covered by a
/// valid user-supplied entry falls back to this, so a sweep can never hit a gap.
const DEFAULT_TABLE_TOML: &str = include_str!("../mbr-table.toml");

/// Default filename checked in the current directory when `--mbr-table` isn't given.
const DEFAULT_TABLE_FILENAME: &str = "mbr-table.toml";

/// One validated `mbr_val -> identity/marker` entry.
struct MbrEntry {
    identity_hex: String,
    marker_hex: String,
}

/// Deserialize entries individually so one missing or mistyped field cannot discard
/// valid entries elsewhere in an otherwise well-formed TOML document.
#[derive(serde::Deserialize)]
struct TableFile {
    #[serde(default)]
    entry: Vec<toml::Value>,
}

#[derive(serde::Deserialize)]
struct TableEntry {
    mbr_val: u16,
    identity: String,
    marker: String,
}

/// Full 2048-entry lookup table, indexed directly by `mbr_val`.
pub struct MbrTable {
    entries: Vec<Option<MbrEntry>>,
}

impl MbrTable {
    /// Load the table. Resolution order: `path` if given, else `./mbr-table.toml` if it
    /// exists, else the embedded default alone. Only valid disk entries are overlaid on
    /// the embedded default; malformed TOML or invalid entries leave defaults intact.
    pub fn load(path: Option<&str>) -> MbrTable {
        let mut entries: Vec<Option<MbrEntry>> = (0..2048).map(|_| None).collect();
        fill_from_toml(&mut entries, DEFAULT_TABLE_TOML);

        let candidate_path = path.map(str::to_string).or_else(|| {
            Path::new(DEFAULT_TABLE_FILENAME)
                .exists()
                .then(|| DEFAULT_TABLE_FILENAME.to_string())
        });

        if let Some(p) = candidate_path {
            match fs::read_to_string(&p) {
                Ok(content) => fill_from_toml(&mut entries, &content),
                Err(e) => eprintln!(
                    "Warning: cannot read --mbr-table {}: {} (using embedded default)",
                    p, e
                ),
            }
        }

        let missing = entries.iter().filter(|e| e.is_none()).count();
        if missing > 0 {
            eprintln!(
                "Error: mbr-table is missing {} of 2048 entries even after falling back to \
                 the embedded default -- this should never happen",
                missing
            );
            std::process::exit(1);
        }

        MbrTable { entries }
    }

    /// Look up the identity/marker hex strings for a given `mbr_val` (0-2047).
    pub fn lookup(&self, mbr_val: u16) -> (&str, &str) {
        let e = self.entries[mbr_val as usize]
            .as_ref()
            .expect("mbr_val out of range or table incomplete");
        (&e.identity_hex, &e.marker_hex)
    }
}

/// Decode an exact-length ASCII hex field without accepting whitespace or separators.
fn decode_hex<const N: usize>(hex: &str) -> Option<[u8; N]> {
    if hex.len() != N * 2 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0u8; N];
    for (byte, pair) in bytes.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(bytes)
}

/// Validate all three fields together before allowing an entry to replace a default.
fn validate_entry(entry: TableEntry) -> Option<(usize, MbrEntry)> {
    if entry.mbr_val >= 2048 {
        return None;
    }
    let identity = decode_hex::<10>(&entry.identity)?;
    let marker = decode_hex::<2>(&entry.marker)?;
    if crate::targets::marker_from_identity(&identity) != marker
        || (u16::from_le_bytes(marker) & 0x7FF) != entry.mbr_val
    {
        return None;
    }
    Some((
        entry.mbr_val as usize,
        MbrEntry {
            identity_hex: entry.identity.to_ascii_uppercase(),
            marker_hex: entry.marker.to_ascii_uppercase(),
        },
    ))
}

/// Overlay valid `[[entry]]` records using real TOML parsing and exact serde field names.
/// Unknown metadata is ignored. Invalid records, including later duplicates, never
/// replace previously validated entries. Syntax errors leave the entire table unchanged.
fn fill_from_toml(entries: &mut [Option<MbrEntry>], content: &str) {
    let parsed: TableFile = match toml::from_str(content) {
        Ok(parsed) => parsed,
        Err(_) => {
            // Do not print the parser's source excerpt: it can contain user-supplied data.
            eprintln!("Warning: invalid mbr-table TOML (keeping existing entries)");
            return;
        }
    };

    for (index, value) in parsed.entry.into_iter().enumerate() {
        let valid = value.try_into().ok().and_then(validate_entry);
        if let Some((mbr_val, entry)) = valid {
            if let Some(slot) = entries.get_mut(mbr_val) {
                *slot = Some(entry);
                continue;
            }
        }
        eprintln!(
            "Warning: invalid mbr-table entry {} (keeping existing entry)",
            index + 1
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_default_is_complete() {
        let table = MbrTable::load(None);
        for mbr_val in 0u16..2048 {
            let (identity_hex, marker_hex) = table.lookup(mbr_val);
            assert_eq!(identity_hex.len(), 20, "mbr_val={}", mbr_val);
            assert_eq!(marker_hex.len(), 4, "mbr_val={}", mbr_val);
        }
    }

    #[test]
    fn test_missing_user_file_falls_back_to_default() {
        let table = MbrTable::load(Some("/nonexistent/path/mbr-table.toml"));
        let (identity_hex, _) = table.lookup(0);
        assert_eq!(identity_hex.len(), 20);
    }

    /// Adapted for the post-refactor `fill_from_toml`, which now requires each `[[entry]]`
    /// to pass `validate_entry` (identity/marker/mbr_val must be mutually consistent per
    /// `crate::targets::marker_from_identity`) instead of the old hand-rolled parser's
    /// accept-anything-well-formed behavior -- an arbitrary identity/marker pair like the
    /// original test used is no longer accepted, so this constructs a genuinely valid entry
    /// via the real formula before overlaying it.
    #[test]
    fn test_partial_user_file_fills_gaps_from_default() {
        let identity = [0x11u8; 10];
        let marker = crate::targets::marker_from_identity(&identity);
        let mbr_val = u16::from_le_bytes(marker) & 0x7FF;
        let identity_hex: String = identity.iter().map(|b| format!("{:02X}", b)).collect();
        let marker_hex: String = marker.iter().map(|b| format!("{:02X}", b)).collect();

        let partial = format!(
            "[[entry]]\nmbr_val = {}\nidentity = \"{}\"\nmarker = \"{}\"\n",
            mbr_val, identity_hex, marker_hex
        );
        let mut entries: Vec<Option<MbrEntry>> = (0..2048).map(|_| None).collect();
        fill_from_toml(&mut entries, DEFAULT_TABLE_TOML);
        fill_from_toml(&mut entries, &partial);

        assert_eq!(
            entries[mbr_val as usize].as_ref().unwrap().identity_hex,
            identity_hex
        );
        // Every other index must still be present from the default, untouched.
        assert!(entries[0].is_some());
        assert!(entries[2047].is_some());
    }

    /// New behavior introduced by the serde/toml rewrite (not present in the old hand-rolled
    /// parser): an `[[entry]]` whose identity/marker/mbr_val are mutually inconsistent must be
    /// rejected outright, leaving the previously-loaded (default) entry at that slot intact.
    #[test]
    fn test_invalid_user_entry_falls_back_to_default() {
        let bogus =
            "[[entry]]\nmbr_val = 5\nidentity = \"1111111111111111AAAA\"\nmarker = \"BEEF\"\n";
        let mut entries: Vec<Option<MbrEntry>> = (0..2048).map(|_| None).collect();
        fill_from_toml(&mut entries, DEFAULT_TABLE_TOML);
        let before = entries[5].as_ref().unwrap().identity_hex.clone();
        fill_from_toml(&mut entries, bogus);
        assert_eq!(
            entries[5].as_ref().unwrap().identity_hex,
            before,
            "invalid entry must not overwrite the default"
        );
    }
}

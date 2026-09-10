//! Precomputed identity/marker lookup table for every possible `mbr_val` (0-2047).
//!
//! Used by the full-`mbr_val`-space collision search (`search`/`generate serial` without
//! `--identity`) to turn a found `mbr_val` back into a real, usable MBR identity/marker
//! pair -- any identity sharing the same `mbr_val` is functionally interchangeable for
//! licensing purposes, see `docs/reference/identity-reverse-search.md`.

use std::fs;
use std::path::Path;

/// Embedded copy of the checked-in `mbr-table.toml` (all 2048 entries). Self-heals a
/// missing, unreadable, or incomplete `--mbr-table` file: any `mbr_val` not covered by the
/// user-supplied file falls back to this, so a sweep can never hit a gap.
const DEFAULT_TABLE_TOML: &str = include_str!("../mbr-table.toml");

/// Default filename checked next to `keys.toml` when `--mbr-table` isn't given.
const DEFAULT_TABLE_FILENAME: &str = "mbr-table.toml";

/// One `mbr_val -> identity/marker` entry.
struct MbrEntry {
    identity_hex: String,
    marker_hex: String,
}

/// Full 2048-entry lookup table, indexed directly by `mbr_val`.
pub struct MbrTable {
    entries: Vec<Option<MbrEntry>>,
}

impl MbrTable {
    /// Load the table. Resolution order: `path` if given, else `./mbr-table.toml` if it
    /// exists, else the embedded default alone. Whatever is loaded from disk is overlaid
    /// on top of the embedded default, so a partial/corrupt file never leaves a gap.
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

/// Parse `[[entry]]` blocks (`mbr_val`/`identity`/`marker` fields, same hand-rolled style as
/// `targets::load_from_file`) and fill in `entries` at each `mbr_val` found. Called first
/// with the embedded default, then optionally again with a user-supplied file so the
/// user's entries overlay the default.
fn fill_from_toml(entries: &mut [Option<MbrEntry>], content: &str) {
    fn flush(
        mbr_val: &mut Option<u16>,
        identity: &mut String,
        marker: &mut String,
        entries: &mut [Option<MbrEntry>],
    ) {
        if let Some(v) = mbr_val.take() {
            if (v as usize) < entries.len() {
                entries[v as usize] = Some(MbrEntry {
                    identity_hex: std::mem::take(identity),
                    marker_hex: std::mem::take(marker),
                });
            }
        }
        identity.clear();
        marker.clear();
    }

    let mut cur_mbr_val: Option<u16> = None;
    let mut cur_identity = String::new();
    let mut cur_marker = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[[entry]]" {
            flush(
                &mut cur_mbr_val,
                &mut cur_identity,
                &mut cur_marker,
                entries,
            );
        } else if let Some(rest) = trimmed.strip_prefix("mbr_val") {
            cur_mbr_val = rest
                .trim()
                .trim_start_matches('=')
                .trim()
                .parse::<u16>()
                .ok();
        } else if let Some(rest) = trimmed.strip_prefix("identity") {
            cur_identity = rest
                .trim()
                .trim_start_matches('=')
                .trim()
                .trim_matches('"')
                .to_string();
        } else if let Some(rest) = trimmed.strip_prefix("marker") {
            cur_marker = rest
                .trim()
                .trim_start_matches('=')
                .trim()
                .trim_matches('"')
                .to_string();
        }
    }
    flush(
        &mut cur_mbr_val,
        &mut cur_identity,
        &mut cur_marker,
        entries,
    );
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

    #[test]
    fn test_partial_user_file_fills_gaps_from_default() {
        let partial =
            "[[entry]]\nmbr_val = 5\nidentity = \"1111111111111111AAAA\"\nmarker = \"BEEF\"\n";
        let mut entries: Vec<Option<MbrEntry>> = (0..2048).map(|_| None).collect();
        fill_from_toml(&mut entries, DEFAULT_TABLE_TOML);
        fill_from_toml(&mut entries, partial);

        assert_eq!(
            entries[5].as_ref().unwrap().identity_hex,
            "1111111111111111AAAA"
        );
        // Every other index must still be present from the default, untouched.
        assert!(entries[0].is_some());
        assert!(entries[2047].is_some());
    }
}

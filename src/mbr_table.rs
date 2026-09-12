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
#[cfg_attr(test, derive(Clone, PartialEq, Eq))]
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
    for (byte, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
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

    fn embedded_entries() -> Vec<Option<MbrEntry>> {
        let mut entries = (0..2048).map(|_| None).collect::<Vec<_>>();
        fill_from_toml(&mut entries, DEFAULT_TABLE_TOML);
        entries
    }

    fn synthetic_entry() -> TableEntry {
        let identity = "1111111111111111AAAA";
        let marker = crate::targets::marker_from_identity(&decode_hex::<10>(identity).unwrap());
        TableEntry {
            mbr_val: u16::from_le_bytes(marker) & 0x7FF,
            identity: identity.to_string(),
            marker: format!("{:02X}{:02X}", marker[0], marker[1]),
        }
    }

    fn entry_toml(entry: &TableEntry) -> String {
        format!(
            "[[entry]]\nmbr_val = {}\nidentity = {:?}\nmarker = {:?}\n",
            entry.mbr_val, entry.identity, entry.marker
        )
    }

    #[test]
    fn test_embedded_default_is_complete_and_consistent() {
        // Inspect only the embedded data, never a working-directory override.
        let parsed: TableFile = toml::from_str(DEFAULT_TABLE_TOML).unwrap();
        assert_eq!(parsed.entry.len(), 2048);
        let table = MbrTable {
            entries: embedded_entries(),
        };
        for mbr_val in 0u16..2048 {
            let (identity_hex, marker_hex) = table.lookup(mbr_val);
            let identity = decode_hex::<10>(identity_hex).expect("valid embedded identity");
            let marker = decode_hex::<2>(marker_hex).expect("valid embedded marker");
            assert_eq!(crate::targets::marker_from_identity(&identity), marker);
            assert_eq!(u16::from_le_bytes(marker) & 0x7FF, mbr_val);
            let mix = u64::from(mbr_val) * crate::targets::MIX_MULTIPLIER;
            assert_eq!(
                crate::targets::mix_from_identity(&identity),
                (mix as u32, (mix >> 32) as u32)
            );
        }
    }

    #[test]
    fn test_missing_user_file_falls_back_to_default() {
        let table = MbrTable::load(Some("/nonexistent/path/mbr-table.toml"));
        assert!(table.entries == embedded_entries());
    }

    #[test]
    fn test_partial_user_file_fills_gaps_from_default() {
        let entry = synthetic_entry();
        let baseline = embedded_entries();
        let mut entries = baseline.clone();
        fill_from_toml(&mut entries, &entry_toml(&entry));
        for (index, actual) in entries.iter().enumerate() {
            if index == usize::from(entry.mbr_val) {
                let actual = actual.as_ref().unwrap();
                assert_eq!(actual.identity_hex, entry.identity);
                assert_eq!(actual.marker_hex, entry.marker);
            } else {
                assert!(actual == &baseline[index], "unexpected change at {index}");
            }
        }
    }

    #[test]
    fn test_invalid_entries_preserve_default() {
        let baseline = embedded_entries();
        let valid =
            "[[entry]]\nmbr_val = 189\nidentity = \"00000000000000000000\"\nmarker = \"BDE8\"\n";
        let cases = [
            (
                "missing identity",
                valid.replace("identity = \"00000000000000000000\"\n", ""),
            ),
            ("missing marker", valid.replace("marker = \"BDE8\"\n", "")),
            ("missing mbr_val", valid.replace("mbr_val = 189\n", "")),
            ("truncated block", "[[entry]]\nmbr_val = 189\n".to_string()),
            (
                "short identity",
                valid.replace("00000000000000000000", "00"),
            ),
            (
                "long identity",
                valid.replace("00000000000000000000", "0000000000000000000000"),
            ),
            (
                "nonhex identity",
                valid.replace("00000000000000000000", "0000000000000000000G"),
            ),
            (
                "unicode identity",
                valid.replace("00000000000000000000", "000000000000000000é"),
            ),
            ("short marker", valid.replace("BDE8", "BD")),
            ("long marker", valid.replace("BDE8", "BDE800")),
            ("nonhex marker", valid.replace("BDE8", "BDEZ")),
            (
                "wrong marker with same low bits",
                valid.replace("BDE8", "BD00"),
            ),
            ("wrong mbr_val", valid.replace("189", "190")),
            ("out-of-range mbr_val", valid.replace("189", "2048")),
            ("negative mbr_val", valid.replace("189", "-1")),
            ("overflow mbr_val", valid.replace("189", "65536")),
            ("mistyped mbr_val", valid.replace("189", "\"189\"")),
            (
                "mistyped identity",
                valid.replace("\"00000000000000000000\"", "false"),
            ),
            ("mistyped marker", valid.replace("\"BDE8\"", "false")),
        ];
        for (name, content) in cases {
            let mut entries = baseline.clone();
            fill_from_toml(&mut entries, &content);
            assert!(
                entries == baseline,
                "invalid overlay changed defaults: {name}"
            );
        }
    }

    #[test]
    fn test_malformed_toml_preserves_entire_table() {
        let baseline = embedded_entries();
        let valid = entry_toml(&synthetic_entry());
        for invalid in [
            "[[entry",
            "entry = 42",
            "entry = [{ mbr_val = 189, mbr_val = 190 }]",
        ] {
            let mut entries = baseline.clone();
            fill_from_toml(&mut entries, invalid);
            assert!(entries == baseline);
        }
        let mut entries = baseline.clone();
        fill_from_toml(&mut entries, &format!("{valid}\n[[entry"));
        assert!(
            entries == baseline,
            "syntax errors must not partially apply a file"
        );
    }

    #[test]
    fn test_invalid_records_do_not_discard_valid_neighbors() {
        let entry = synthetic_entry();
        let mut entries = embedded_entries();
        let content = format!(
            "[[entry]]\nmbr_val = 189\n\n{}\n[[entry]]\nmbr_val = {}\nidentity = false\nmarker = \"BEEF\"\n",
            entry_toml(&entry), entry.mbr_val
        );
        fill_from_toml(&mut entries, &content);
        let actual = entries[usize::from(entry.mbr_val)].as_ref().unwrap();
        assert_eq!(actual.identity_hex, entry.identity);
        assert_eq!(actual.marker_hex, entry.marker);
    }

    #[test]
    fn test_extra_fields_comments_and_lowercase_hex() {
        let entry = synthetic_entry();
        let mut entries = embedded_entries();
        let content = format!(
            "title = 'metadata'\n[[entry]] # header comment\nmbr_val = {} # number comment\nidentity = '{}' # identity comment\nmarker = '{}' # marker comment\nidentity_note = 'not an identity'\nmarker_note = 'not a marker'\nmbr_val_note = 'not a value'\n",
            entry.mbr_val,
            entry.identity.to_ascii_lowercase(),
            entry.marker.to_ascii_lowercase()
        );
        fill_from_toml(&mut entries, &content);
        let actual = entries[usize::from(entry.mbr_val)].as_ref().unwrap();
        assert_eq!(actual.identity_hex, entry.identity);
        assert_eq!(actual.marker_hex, entry.marker);
    }

    #[test]
    fn test_inline_array_of_tables() {
        let entry = synthetic_entry();
        let mut entries = embedded_entries();
        let content = format!(
            "entry = [{{ mbr_val = {}, identity = {:?}, marker = {:?} }}]",
            entry.mbr_val, entry.identity, entry.marker
        );
        fill_from_toml(&mut entries, &content);
        let actual = entries[usize::from(entry.mbr_val)].as_ref().unwrap();
        assert_eq!(actual.identity_hex, entry.identity);
        assert_eq!(actual.marker_hex, entry.marker);
    }
}

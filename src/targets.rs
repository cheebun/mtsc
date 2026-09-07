//! Collision search target management
//!
//! Loads known L6 signatures from an external `keys.toml`, allowing new keys to be added without recompilation.
//!
//! # Configuration format
//! ```toml
//! [[key]]
//! software_id = "XXXX-XXXX"
//! signature_hex = "..."
//! ```

use crate::software_id;
use std::fs;
use std::path::Path;

/// Collision search target
pub struct Target {
    /// SOFTWARE ID (e.g. "XXXX-XXXX")
    pub name: String,
    /// Required sid_lo to match (= target_lo ⊕ mix_lo)
    pub need_lo: u32,
    /// Required sid_hi to match (= (target_hi ⊕ mix_hi) & 0xFF)
    pub need_hi: u8,
    /// MBR signature hex (64 bytes, printed on a hit)
    pub signature_hex: String,
}

/// Fixed mix value for an all-zero MBR: mbr_val=0x0BD, mix=0x0BD × 0x3FF800F
const MBR_MIX: u64 = 0x0BD_u64 * 0x3FF800F;

/// Load targets from keys.toml; exits with error if not found or empty.
///
/// `mix` must be the *same* mix (lo, hi) that the caller will use to compute candidate
/// SOFTWARE IDs (`targets::mbr_mix()` for the standard identity, or
/// `targets::mix_from_identity(...)` for a custom one) -- `need_lo`/`need_hi` are only
/// meaningful relative to that specific mix. Passing a mismatched mix silently makes
/// every match check fail (or match the wrong candidates).
pub fn load_targets(config_path: Option<&str>, mix: (u32, u32)) -> Vec<Target> {
    let entries = config_path
        .and_then(load_from_file)
        .or_else(|| load_from_file("keys.toml"))
        .unwrap_or_default();

    if entries.is_empty() {
        eprintln!("Error: keys.toml not found or empty. Copy keys.example.toml to keys.toml and add your signatures.");
        std::process::exit(1);
    }

    eprintln!("Loaded {} keys from config", entries.len());
    entries_to_targets(&entries, mix)
}

/// Get the lo/hi components of the MBR mix
pub fn mbr_mix() -> (u32, u32) {
    (MBR_MIX as u32, (MBR_MIX >> 32) as u32)
}

/// Derive the raw, unmasked 16-bit value (`sha_val XOR chksum`) for a 10-byte MBR
/// identity seed (`0x100-0x109`).
///
/// This single 16-bit value is the source of *both* `mbr_val` (its low 11 bits, used for
/// the mix) *and* the MBR `marker` bytes at `0x10A-0x10B` (the full, unmasked value,
/// written little-endian) -- see `marker_from_identity()` and
/// `docs/identity-marker-formula.md`. They were never two independent fields: the
/// "standard" marker `BD E8` is simply what this formula produces for an all-zero
/// identity (`raw16 = 0xE8BD`, and `0xE8BD & 0x7FF == 0x0BD`).
fn raw16_from_identity(identity: &[u8; 10]) -> u16 {
    let sha_val = crate::sha256::hash_10(identity);
    let mut sum: u16 = 0;
    for chunk in identity.chunks_exact(2) {
        sum = sum.wrapping_add(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    let chksum = !sum;
    sha_val ^ chksum
}

/// Derive the mix (lo, hi) from a real, non-standard 10-byte MBR identity seed
/// (`0x100-0x109`), instead of assuming the standard all-zero identity.
///
/// Formula (see `docs/license-internals.md` §3.2, §3.6, reverse-engineered from and
/// cross-checked against the `keyman` binary):
/// ```text
/// raw16    = MikroTik_SHA256(identity)[0:2] as LE u16  XOR  NOT(sum of 5 LE u16 words of identity)
/// mbr_val  = raw16 & 0x7FF
/// mix      = mbr_val * 0x3FF800F
/// ```
pub fn mix_from_identity(identity: &[u8; 10]) -> (u32, u32) {
    let mbr_val = (raw16_from_identity(identity) as u64) & 0x7FF;
    let mix = mbr_val * 0x3FF800F;
    (mix as u32, (mix >> 32) as u32)
}

/// Derive the 2-byte MBR `marker` (`0x10A-0x10B`, little-endian) that must accompany a
/// given 10-byte identity seed for a real device (or a real-hardware-equivalent PVE/QEMU
/// activation) to accept the license -- confirmed via disassembly and, this session,
/// real-hardware round-trip activation in both directions: real captured `identity`s
/// correctly predict their recorded `marker` (5/5, two independently confirmed by a live
/// `nlevel` activation), and a `marker`-matching but otherwise unrelated `identity`
/// activates exactly like the standard all-zero identity it was *not* copied from. A
/// mismatched pair (right identity, wrong marker) reproducibly fails to activate -- see
/// `docs/identity-marker-formula.md`.
pub fn marker_from_identity(identity: &[u8; 10]) -> [u8; 2] {
    raw16_from_identity(identity).to_le_bytes()
}

// ---- Internal implementation ----

pub(crate) struct KeyEntry {
    pub(crate) software_id: String,
    #[allow(dead_code)] // read by tests that need the full entry, not just software_id
    pub(crate) signature_hex: String,
}

/// `pub(crate)` (not just an internal helper) so tests elsewhere in the crate can load raw
/// `keys.toml` entries and decode their *unmasked* SOFTWARE ID -- `load_targets`'s own
/// `Target.need_hi` bakes in a specific mix and masks to `u8`, which is wrong for code that
/// needs the target's raw (tv_lo, tv_hi) pair against multiple/no fixed mix (e.g. checking
/// feasibility across all 2048 possible `mbr_val` values).
pub(crate) fn load_from_file(path: &str) -> Option<Vec<KeyEntry>> {
    if !Path::new(path).exists() {
        return None;
    }

    let content = fs::read_to_string(path).ok()?;
    let mut entries = Vec::new();
    let mut current_sid = String::new();
    let mut current_sig = String::new();

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "[[key]]" {
            if !current_sid.is_empty() {
                entries.push(KeyEntry {
                    software_id: current_sid.clone(),
                    signature_hex: current_sig.clone(),
                });
            }
            current_sid.clear();
            current_sig.clear();
        } else if let Some(rest) = trimmed.strip_prefix("software_id") {
            current_sid = rest
                .trim()
                .trim_start_matches('=')
                .trim()
                .trim_matches('"')
                .to_string();
        } else if let Some(rest) = trimmed.strip_prefix("signature_hex") {
            current_sig = rest
                .trim()
                .trim_start_matches('=')
                .trim()
                .trim_matches('"')
                .to_string();
        }
    }

    if !current_sid.is_empty() {
        entries.push(KeyEntry {
            software_id: current_sid,
            signature_hex: current_sig,
        });
    }

    Some(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mix_from_identity_matches_standard_all_zero() {
        // The standard all-zero identity used by collision search must reduce to
        // the same fixed mix as mbr_mix()'s hardcoded MBR_MIX constant.
        let (lo, hi) = mix_from_identity(&[0u8; 10]);
        let (std_lo, std_hi) = mbr_mix();
        assert_eq!((lo, hi), (std_lo, std_hi));
    }

    #[test]
    fn test_mix_from_identity_deterministic() {
        let identity = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA];
        let a = mix_from_identity(&identity);
        let b = mix_from_identity(&identity);
        assert_eq!(a, b, "same identity must produce same mix");
    }

    #[test]
    fn test_mix_from_identity_differs_from_standard() {
        // A non-zero identity should (overwhelmingly likely) produce a different mix
        // than the standard all-zero one.
        let identity = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA];
        assert_ne!(mix_from_identity(&identity), mbr_mix());
    }

    #[test]
    fn test_marker_from_identity_matches_standard_all_zero() {
        // The all-zero identity's marker is the familiar "standard" BD E8 -- not an
        // independent convention, but this exact formula's output for this input.
        assert_eq!(marker_from_identity(&[0u8; 10]), [0xBD, 0xE8]);
    }

    #[test]
    fn test_marker_from_identity_matches_real_devices() {
        // docs/mbr-data.md real-hardware captures -- WUB2-EYCK and HCC0-4FJR are each
        // independently confirmed by a real `nlevel` activation (this session), not just
        // a formula match; ER1G-WVEL and ZJ3M-ESHW are formula-only cross-checks.
        let cases: [(&str, [u8; 2]); 4] = [
            (
                "13053023E906092F2175", // WUB2-EYCK
                [0xA3, 0x89],
            ),
            (
                "75437493726136326185", // HCC0-4FJR
                [0x33, 0x20],
            ),
            (
                "3836311F7DD5092F2175", // ER1G-WVEL
                [0xD3, 0x53],
            ),
            (
                "32836785814746803233", // ZJ3M-ESHW
                [0x75, 0x08],
            ),
        ];
        for (identity_hex, expected_marker) in cases {
            let mut identity = [0u8; 10];
            for (i, byte) in identity.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&identity_hex[i * 2..i * 2 + 2], 16).unwrap();
            }
            assert_eq!(
                marker_from_identity(&identity),
                expected_marker,
                "identity {identity_hex} marker mismatch"
            );
        }
    }

    #[test]
    fn test_marker_from_identity_low_11_bits_match_mix_from_identity() {
        // marker and mix_from_identity's mbr_val are derived from the exact same raw16
        // value -- marker is the full 16 bits, mbr_val is its low 11 bits. They must stay
        // consistent for any identity, not just the cases already spot-checked above.
        for identity in [
            [0u8; 10],
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA],
            [0x71, 0xD2, 0x33, 0x94, 0xF5, 0x56, 0xB7, 0x18, 0xAE, 0xA0],
        ] {
            let marker = marker_from_identity(&identity);
            let raw16 = u16::from_le_bytes(marker);
            let (mix_lo, mix_hi) = mix_from_identity(&identity);
            let expected_mix = ((raw16 as u64) & 0x7FF) * 0x3FF800F;
            assert_eq!(
                (mix_lo, mix_hi),
                (expected_mix as u32, (expected_mix >> 32) as u32)
            );
        }
    }
}

fn entries_to_targets(entries: &[KeyEntry], mix: (u32, u32)) -> Vec<Target> {
    let (mix_lo, mix_hi) = mix;

    entries
        .iter()
        .map(|e| {
            let tv = software_id::decode(&e.software_id)
                .unwrap_or_else(|e| panic!("invalid SOFTWARE ID in config: {}", e));
            Target {
                name: e.software_id.clone(),
                need_lo: (tv as u32) ^ mix_lo,
                need_hi: (((tv >> 32) as u32 ^ mix_hi) & 0xFF) as u8,
                signature_hex: e.signature_hex.clone(),
            }
        })
        .collect()
}

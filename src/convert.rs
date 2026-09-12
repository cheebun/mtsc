//! signature_hex ↔ Key text conversion
//!
//! Key text = MTBase64Encode(the 64 bytes of signature_hex)
//! signature_hex = hex representation of MTBase64Decode(Key text)

use crate::sha256_constants::ROUND_CONSTANTS;
use data_encoding::{BitOrder, Encoding, Specification, HEXLOWER_PERMISSIVE, HEXUPPER};
use std::sync::LazyLock;

/// MTBase64 character table (same alphabet as standard Base64, but LSB-first bit order)
const BASE64_TABLE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// MikroTik Base64: standard Base64 alphabet, LSB-first bit order (RFC 4648 is MSB-first, and
/// no mainstream crate's built-in Base64 encodings support LSB-first) -- see
/// `docs/reference/mtsc-cli-plan.md`'s "Replace hand-rolled MTBase64 with the `data-encoding`
/// crate" section for why `data_encoding::Specification` is the only fit found.
static MT_BASE64: LazyLock<Encoding> = LazyLock::new(|| {
    let mut spec = Specification::new();
    spec.symbols.push_str(BASE64_TABLE);
    spec.bit_order = BitOrder::LeastSignificantFirst;
    spec.padding = Some('=');
    spec.encoding().unwrap() // infallible for this fixed, hand-verified spec
});

const KEY_BEGIN_MARKER: &str = "-----BEGIN MIKROTIK SOFTWARE KEY------------";
const KEY_END_MARKER: &str = "-----END MIKROTIK SOFTWARE KEY--------------";

/// Convert a 64-byte signature (hex string) to Key text format. Single-line output (no
/// newlines anywhere) -- `key_text_to_signature` locates the BEGIN/END markers by substring
/// search rather than by line, so it accepts this format equally well whether embedded inline
/// (e.g. after a "License: " label) or pasted as a standalone block.
pub fn signature_to_key_text(signature_hex: &str) -> Result<String, String> {
    let sig_bytes = hex_decode(signature_hex)?;
    if sig_bytes.len() != 64 {
        return Err(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        ));
    }

    let encoded = MT_BASE64.encode(&sig_bytes);

    Ok(format!("{}{}{}", KEY_BEGIN_MARKER, encoded, KEY_END_MARKER))
}

/// Convert Key text to the hex string of a 64-byte signature. Accepts three input forms via one
/// uniform normalization pipeline (strip all whitespace, then strip the BEGIN/END marker
/// substrings if present -- whatever remains is the base64 payload):
/// 1. Traditional multi-line `.key` file format (markers/data each on their own line, any indent)
///    -- stripping whitespace collapses this to form 2.
/// 2. Single-line, `signature_to_key_text`'s own output (markers directly abutting the data)
///    -- stripping the marker substrings reduces this to form 3.
/// 3. Bare MTBase64 data with no BEGIN/END markers at all.
pub fn key_text_to_signature(key_text: &str) -> Result<String, String> {
    // Strip markers *before* stripping whitespace: the marker constants contain their own
    // internal single spaces ("BEGIN MIKROTIK SOFTWARE KEY"), so a whitespace-stripped-first
    // input would no longer contain a literal match for them.
    let without_markers = key_text
        .replace(KEY_BEGIN_MARKER, "")
        .replace(KEY_END_MARKER, "");
    let b64_data: String = without_markers
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    if b64_data.is_empty() {
        return Err("no key data found".to_string());
    }

    let decoded = MT_BASE64
        .decode(b64_data.as_bytes())
        .map_err(|e| format!("invalid MTBase64 data: {}", e))?;
    Ok(hex_encode(&decoded))
}

/// Metadata embedded in a signature's first 16 bytes: SOFTWARE ID, a version byte, and license level.
///
/// See `decode_metadata` for how this is extracted.
pub struct LicenseMetadata {
    pub software_id: String,
    /// Byte 6 of the decrypted block. Not labeled by the reference MTLic `ParseLic.py` --
    /// meaning unconfirmed, printed as-is.
    pub version_byte: u8,
    pub level: u8,
    /// Whether bytes 8..16 of the decrypted block are all zero, as expected for a well-formed
    /// signature. `false` means either this isn't a real signature or the decode is wrong.
    pub padding_ok: bool,
    /// Signature bytes 16..32 -- the EC-KCDSA nonce hash. See docs/license-internals.md §8.32.
    pub nonce_hash: String,
    /// Signature bytes 32..64 -- the EC-KCDSA signature scalar. See docs/license-internals.md §8.32.
    pub signature: String,
}

/// Decrypt the SOFTWARE ID / level metadata embedded in a signature's first 16 bytes.
///
/// Confirmed against the reference implementation (`MT_Transform` in MTLic's `MTTools.py`,
/// https://github.com/Ygnecz/MTLic): a signature's first 16 bytes, run through this transform,
/// decode to `SOFTWARE_ID(6B LE) || reserved(1B) || level(1B) || zero-padding(8B)`.
pub fn decode_metadata(signature_hex: &str) -> Result<LicenseMetadata, String> {
    let (block, nonce_hash, signature) = decode_verify_inputs(signature_hex)?;

    let software_id_val =
        u64::from_le_bytes(block[0..8].try_into().unwrap()) & 0x0000_FFFF_FFFF_FFFF;

    Ok(LicenseMetadata {
        software_id: crate::software_id::encode(software_id_val),
        version_byte: block[6],
        level: block[7],
        padding_ok: block[8..].iter().all(|&b| b == 0),
        nonce_hash: hex_encode(&nonce_hash),
        signature: hex_encode(&signature),
    })
}

/// (decoded payload block, nonce hash, signature scalar) -- see `decode_verify_inputs`.
pub(crate) type VerifyInputs = ([u8; 16], [u8; 16], [u8; 32]);

/// Split a 64-byte signature into its three EC-KCDSA-relevant parts: the `mt_transform`-
/// decrypted 16-byte payload block (SOFTWARE-ID/version/level/reserved), the 16-byte nonce
/// hash, and the 32-byte signature scalar. Shared by `decode_metadata` and
/// `curve25519::verify`'s callers so the ARX-decode logic exists in exactly one place.
pub(crate) fn decode_verify_inputs(signature_hex: &str) -> Result<VerifyInputs, String> {
    let sig_bytes = hex_decode(signature_hex)?;
    if sig_bytes.len() != 64 {
        return Err(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        ));
    }

    let mut block = [0u8; 16];
    block.copy_from_slice(&sig_bytes[0..16]);
    mt_transform(&mut block);

    let nonce_hash: [u8; 16] = sig_bytes[16..32].try_into().unwrap();
    let signature: [u8; 32] = sig_bytes[32..64].try_into().unwrap();
    Ok((block, nonce_hash, signature))
}

/// MikroTik's proprietary ARX block cipher, called `MT_Transform` in the MTLic reference
/// implementation. Decrypts (not encrypts) a signature's first 16 bytes into SOFTWARE ID/level
/// metadata -- see `decode_metadata`. Reuses this project's MikroTik SHA-256 round constants,
/// which are the same table `MT_Transform` uses (confirmed against MTLic's `MTTools.py`).
fn mt_transform(block: &mut [u8; 16]) {
    let mut s = [0u32; 4];
    for (w, chunk) in s.iter_mut().zip(block.as_chunks::<4>().0) {
        *w = u32::from_be_bytes(*chunk);
    }

    for i in 0..16 {
        let (p, q, r, t) = (i % 4, (i + 1) % 4, (i + 2) % 4, (i + 3) % 4);
        let k0 = ROUND_CONSTANTS[i * 4];
        let k1 = ROUND_CONSTANTS[i * 4 + 1];
        let k2 = ROUND_CONSTANTS[i * 4 + 2];
        let k3 = ROUND_CONSTANTS[i * 4 + 3];

        // `k & 0x0F` is always 0..=15, so `rotate_left` can never overflow.
        s[r] = s[r].wrapping_sub(s[p]).wrapping_sub(k0);
        s[t] = (s[p].rotate_left(k0 & 0x0F) ^ s[t]).wrapping_add(s[p]);

        s[q] = s[q].wrapping_sub(s[t]).wrapping_sub(k1);
        s[r] = (s[q].rotate_left(k1 & 0x0F) ^ s[r]).wrapping_add(s[q]);

        s[p] = s[p].wrapping_sub(s[r]).wrapping_sub(k2);
        s[q] = (s[r].rotate_left(k2 & 0x0F) ^ s[q]).wrapping_add(s[r]);

        s[t] = s[t].wrapping_sub(s[q]).wrapping_sub(k3);
        s[p] = (s[t].rotate_left(k3 & 0x0F) ^ s[p]).wrapping_add(s[t]);
    }

    for (chunk, w) in block.as_chunks_mut::<4>().0.iter_mut().zip(s.iter()) {
        chunk.copy_from_slice(&w.to_be_bytes());
    }
}

/// hex string → byte array. Accepts mixed-case input (matches this project's other hex call
/// sites, e.g. `main.rs`'s `--identity`), and trims surrounding whitespace since callers may
/// pass file contents with a trailing newline.
fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    HEXLOWER_PERMISSIVE
        .decode(hex.trim().as_bytes())
        .map_err(|e| format!("invalid hex: {}", e))
}

/// byte array → uppercase hex string
fn hex_encode(bytes: &[u8]) -> String {
    HEXUPPER.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Legacy hand-rolled MTBase64 (pre-`data_encoding` migration), kept test-only as a
    // fixture for the compatibility/regression checks below -- see
    // `docs/reference/mtsc-cli-plan.md`'s "Required before shipping" section for why both a
    // compatibility diff AND a negative/malformed-input corpus are needed, not just one. ----

    const LEGACY_BASE64_TABLE: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn legacy_mt_base64_encode(data: &[u8]) -> String {
        let mut encoded = String::new();
        let mut pending_bits = 0u32;

        for (i, &byte) in data.iter().enumerate() {
            if pending_bits == 0 {
                encoded.push(LEGACY_BASE64_TABLE[(byte & 0x3F) as usize] as char);
                pending_bits = 2;
            } else if pending_bits == 6 {
                encoded.push(LEGACY_BASE64_TABLE[(data[i - 1] >> 2) as usize] as char);
                encoded.push(LEGACY_BASE64_TABLE[(byte & 0x3F) as usize] as char);
                pending_bits = 2;
            } else {
                let index1 = data[i - 1] >> (8 - pending_bits);
                let index2 = (byte as u32) << pending_bits;
                encoded
                    .push(LEGACY_BASE64_TABLE[((index1 as u32 | index2) & 0x3F) as usize] as char);
                pending_bits += 2;
            }
        }

        if pending_bits != 0 {
            encoded.push(
                LEGACY_BASE64_TABLE[(data[data.len() - 1] >> (8 - pending_bits)) as usize] as char,
            );
        }

        while !encoded.len().is_multiple_of(4) {
            encoded.push('=');
        }

        encoded
    }

    /// Legacy decoder's actual behavior, preserved exactly (including its leniencies) so the
    /// negative-corpus tests below can assert against real old behavior, not a guess at it.
    /// Notably: strips `=` from *anywhere* in the input (no position/count check), and never
    /// checks trailing-bits canonicality.
    fn legacy_mt_base64_decode(data: &str) -> Result<Vec<u8>, String> {
        let bytes: Vec<u8> = data.bytes().filter(|&b| b != b'=').collect();

        let mut result = Vec::new();
        let mut pending_bits = 0u32;

        for (i, &byte) in bytes.iter().enumerate() {
            if pending_bits == 0 {
                pending_bits = 6;
            } else {
                let pos_prev = LEGACY_BASE64_TABLE
                    .iter()
                    .position(|&c| c == bytes[i - 1])
                    .ok_or_else(|| format!("invalid base64 char: {}", bytes[i - 1] as char))?;
                let pos_curr = LEGACY_BASE64_TABLE
                    .iter()
                    .position(|&c| c == byte)
                    .ok_or_else(|| format!("invalid base64 char: {}", byte as char))?;

                let value1 = pos_prev >> (6 - pending_bits);
                let value2 = pos_curr & ((1 << (8 - pending_bits)) - 1);
                let value = (value1 | (value2 << pending_bits)) as u8;
                result.push(value);
                pending_bits -= 2;
            }
        }

        Ok(result)
    }

    /// Compatibility diff (required before deleting the old decoder, per
    /// `mtsc-cli-plan.md`): every real signature this test module already carries -- both are
    /// real hardware-activation-confirmed signatures, not synthetic -- must decode to
    /// byte-identical results under the legacy and the new `data_encoding`-backed `MT_BASE64`.
    #[test]
    fn test_new_base64_matches_legacy_on_real_signatures() {
        let real_signatures = [
            // TI09-7WK3 (docs/license-internals.md §8.32)
            "E67A8F47AE86672FAE6D91DF19221453B34FE40E23F19E917107C449DDCB1D2061521816AD7730671B4CB226F1B0DB7448923C6297C49BDB3CCBF40AECBBCF0B",
            // VI8Q-E90F (docs/collision-database.md, confirmed L1 on real hardware)
            "FAF308BA3FFD4185308A8784244749EFFE7E4E65C14C01CD55D946506B47F636757F62106D114329104012DE7B44543F3444F0E724080873E3A20E11F5EF450E",
        ];
        for sig_hex in real_signatures {
            let sig_bytes = hex_decode(sig_hex).unwrap();
            let legacy_encoded = legacy_mt_base64_encode(&sig_bytes);
            let new_encoded = MT_BASE64.encode(&sig_bytes);
            assert_eq!(legacy_encoded, new_encoded, "encode mismatch for {sig_hex}");

            let legacy_decoded = legacy_mt_base64_decode(&legacy_encoded).unwrap();
            let new_decoded = MT_BASE64.decode(new_encoded.as_bytes()).unwrap();
            assert_eq!(legacy_decoded, new_decoded, "decode mismatch for {sig_hex}");
            assert_eq!(legacy_decoded, sig_bytes);
        }
    }

    /// Negative/malformed-input corpus (the actual security-relevant half of the migration,
    /// per `mtsc-cli-plan.md`'s security-review correction: a pure compatibility diff against
    /// only-valid inputs can't surface "new decoder silently accepts what the old one
    /// correctly rejected," because there was nothing for the old one to correctly reject in
    /// the first place -- it has none of these checks). Each case documents both decoders'
    /// actual behavior as a deliberate, recorded decision, not just "no mismatches found."
    #[test]
    fn test_base64_negative_corpus_documents_old_vs_new_behavior() {
        // Case 1: padding in the wrong position (`=` before the end). Legacy strips `=` from
        // anywhere with no position check at all, so it currently ACCEPTS this. The new
        // `data_encoding`-backed decoder validates padding structure and REJECTS it --  a
        // real, deliberate behavior tightening (closes an encoding-malleability class), not a
        // silent regression.
        let misplaced_padding = "mr=3jH5qhn9irtF53ZICFTN7Tk7wIx7ZkxdAxJ19ydASYShhFteHMntBTyaS8wuNdIJJPidJxbuNPLTvCsv7zLA==";
        assert!(
            legacy_mt_base64_decode(misplaced_padding).is_ok(),
            "legacy decoder is known to accept misplaced padding"
        );
        assert!(
            MT_BASE64.decode(misplaced_padding.as_bytes()).is_err(),
            "new decoder must reject misplaced padding (deliberate tightening)"
        );

        // Case 2: wrong padding count (one `=` too many for the input length). Same
        // accept(legacy)/reject(new) shape as case 1.
        let excess_padding = "mr3jH5qhn9irtF53ZICFTN7Tk7wIx7ZkxdAxJ19ydASYShhFteHMntBTyaS8wuNdIJJPidJxbuNPLTvCsv7zLA===";
        assert!(legacy_mt_base64_decode(excess_padding).is_ok());
        assert!(MT_BASE64.decode(excess_padding.as_bytes()).is_err());

        // Case 3: a character outside the base64 alphabet embedded mid-string. Both decoders
        // must reject this -- no behavior change here, just confirming neither silently
        // accepts garbage input.
        let invalid_char = "mr3jH5qhn9irtF53ZICFTN7Tk7wIx7ZkxdAxJ19ydASY!hhFteHMntBTyaS8wuNdIJJPidJxbuNPLTvCsv7zLA==";
        assert!(legacy_mt_base64_decode(invalid_char).is_err());
        assert!(MT_BASE64.decode(invalid_char.as_bytes()).is_err());

        // Case 4: non-canonical trailing bits. Base64's 6-bit symbols don't divide evenly
        // into 8-bit bytes, so the final symbol in a group can carry a few bits with no real
        // data behind them; a canonical encoder always zeros them. Legacy never checks this
        // (it has no `check_trailing_bits`-equivalent logic at all), so two different encoded
        // strings can legally decode to the same bytes under it. Build one: take a real
        // 2-byte-tail encoding and flip its last symbol to another one occupying the same
        // "real" bits but different trailing bits.
        let sig_bytes = hex_decode(
            "E67A8F47AE86672FAE6D91DF19221453B34FE40E23F19E917107C449DDCB1D2061521816AD7730671B4CB226F1B0DB7448923C6297C49BDB3CCBF40AECBBCF0B",
        )
        .unwrap();
        let canonical = legacy_mt_base64_encode(&sig_bytes);
        let mut chars: Vec<char> = canonical.chars().collect();
        let last_data_idx = chars.iter().rposition(|&c| c != '=').unwrap();
        let last_data_char = chars[last_data_idx];
        let last_data_pos = LEGACY_BASE64_TABLE
            .iter()
            .position(|&b| b as char == last_data_char)
            .unwrap();
        // Flip a high (non-data-carrying, for this tail width) bit of the last symbol's index
        // to get a different, non-canonical encoding of the identical underlying bytes.
        let flipped_pos = last_data_pos ^ 0x20;
        chars[last_data_idx] = LEGACY_BASE64_TABLE[flipped_pos] as char;
        let non_canonical: String = chars.into_iter().collect();
        assert_ne!(
            non_canonical, canonical,
            "sanity: flip must change the string"
        );

        let legacy_result = legacy_mt_base64_decode(&non_canonical);
        let new_result = MT_BASE64.decode(non_canonical.as_bytes());
        // Record whatever each decoder actually does -- this is the explicit "old does X, new
        // does Y" table the plan calls for, not an assumption. If the flipped bit happened to
        // fall in a position with no encodable-length interpretation for the new decoder, it
        // rejects; if it decodes, both must still be checked against each other, never just
        // assumed to agree.
        match (legacy_result, new_result) {
            (Ok(legacy_bytes), Ok(new_bytes)) => {
                // If the new decoder accepts it, it must decode to the exact same bytes as
                // the legacy one -- this would only fail if the two encodings genuinely
                // disagreed on which underlying bytes the non-canonical string represents.
                assert_eq!(
                    legacy_bytes, new_bytes,
                    "both decoders accepted the non-canonical input but disagreed on its bytes"
                );
            }
            (Ok(_), Err(_)) => {
                // Expected, common outcome: new decoder's stricter validation rejects a
                // non-canonical encoding the legacy one silently accepted -- a deliberate
                // tightening, documented here rather than discovered later.
            }
            (Err(_), Ok(_)) => panic!(
                "new decoder accepts an input the legacy decoder rejects -- unexpected loosening"
            ),
            (Err(_), Err(_)) => {
                // Also acceptable: the flip happened to also produce a shape the legacy
                // decoder's own (different) lookup logic couldn't resolve either.
            }
        }

        // Case 5: off-by-one lengths adjacent to the real 64-byte signature length (63/65
        // decoded bytes), through the full signature_to_key_text/key_text_to_signature path
        // where actual length validation happens (MTBase64 itself has no fixed-length
        // requirement -- length checking is `signature_to_key_text`'s job, downstream of the
        // base64 layer).
        let sig_63 = "AA".repeat(63);
        let sig_65 = "AA".repeat(65);
        assert!(
            signature_to_key_text(&sig_63).is_err(),
            "63 bytes must be rejected (not 64)"
        );
        assert!(
            signature_to_key_text(&sig_65).is_err(),
            "65 bytes must be rejected (not 64)"
        );
    }

    /// Compatibility diff against every real signature in the local `keys.toml`, per
    /// `mtsc-cli-plan.md`'s "Required before shipping" section -- the two hardcoded
    /// signatures in `test_new_base64_matches_legacy_on_real_signatures` are a start, but
    /// this is the actual "every real sample" check the plan calls for.
    ///
    /// `#[ignore]`: depends on `keys.toml` existing at the crate root at test-run time
    /// (private, gitignored -- not present in a fresh checkout or CI). Run explicitly with
    /// `cargo test --release -- --ignored` on a machine with a populated `keys.toml`.
    #[test]
    #[ignore]
    fn test_new_base64_matches_legacy_on_every_keys_toml_signature() {
        let targets = crate::targets::load_targets(Some("keys.toml"), (0, 0));
        assert!(
            !targets.is_empty(),
            "keys.toml must be present and non-empty"
        );

        for target in &targets {
            let sig_bytes = hex_decode(&target.signature_hex)
                .unwrap_or_else(|e| panic!("bad signature_hex for {}: {e}", target.name));
            let legacy_encoded = legacy_mt_base64_encode(&sig_bytes);
            let new_encoded = MT_BASE64.encode(&sig_bytes);
            assert_eq!(
                legacy_encoded, new_encoded,
                "encode mismatch for {}",
                target.name
            );

            let legacy_decoded = legacy_mt_base64_decode(&legacy_encoded).unwrap();
            let new_decoded = MT_BASE64.decode(new_encoded.as_bytes()).unwrap();
            assert_eq!(
                legacy_decoded, new_decoded,
                "decode mismatch for {}",
                target.name
            );
        }
    }

    #[test]
    fn test_roundtrip_synthetic() {
        // Synthetic 64-byte signature; verify sig→key→sig round-trips exactly.
        let sig: String = (0..64)
            .map(|i| format!("{:02X}", (i * 7 + 3) as u8))
            .collect();

        // sig → key
        let key = signature_to_key_text(&sig).unwrap();
        assert!(key.starts_with("-----BEGIN"), "key header missing");
        assert!(key.trim_end().ends_with("-----"), "key footer missing");

        // key → sig
        let back = key_text_to_signature(&key).unwrap();
        assert_eq!(back, sig, "sig↔key roundtrip mismatch");
    }

    #[test]
    fn test_key_text_three_input_forms_agree() {
        // TI09-7WK3's known-good signature (see docs/license-internals.md §8.32), exercised
        // through all three input forms `key_text_to_signature` must accept.
        let sig = "E67A8F47AE86672FAE6D91DF19221453B34FE40E23F19E917107C449DDCB1D2061521816AD7730671B4CB226F1B0DB7448923C6297C49BDB3CCBF40AECBBCF0B";

        // Form 1: single-line, this project's own signature_to_key_text output
        let single_line = signature_to_key_text(sig).unwrap();
        assert!(!single_line.contains('\n'), "expected single-line output");
        assert_eq!(key_text_to_signature(&single_line).unwrap(), sig);

        // Form 2: bare base64, no BEGIN/END markers at all
        let bare_b64 = "mr3jH5qhn9irtF53ZICFTN7Tk7wIx7ZkxdAxJ19ydASYShhFteHMntBTyaS8wuNdIJJPidJxbuNPLTvCsv7zLA==";
        assert_eq!(key_text_to_signature(bare_b64).unwrap(), sig);

        // Form 3: traditional multi-line, indented `.key` file format
        let multi_line = "  -----BEGIN MIKROTIK SOFTWARE KEY------------\n  mr3jH5qhn9irtF53ZICFTN7Tk7wIx7ZkxdAxJ19ydASY\n  ShhFteHMntBTyaS8wuNdIJJPidJxbuNPLTvCsv7zLA==\n  -----END MIKROTIK SOFTWARE KEY--------------";
        assert_eq!(key_text_to_signature(multi_line).unwrap(), sig);
    }

    #[test]
    fn test_decode_metadata_vi8q_e90f() {
        // VI8Q-E90F's signature hex, from docs/collision-database.md -- confirmed L1
        // (nlevel: 1) on real hardware. Also independently confirmed by decoding this
        // project's key-text form of the same signature against the reference MT_Transform.
        let sig = "FAF308BA3FFD4185308A8784244749EFFE7E4E65C14C01CD55D946506B47F636757F62106D114329104012DE7B44543F3444F0E724080873E3A20E11F5EF450E";
        let meta = decode_metadata(sig).unwrap();
        assert_eq!(meta.software_id, "VI8Q-E90F");
        assert_eq!(meta.level, 1);
        assert!(meta.padding_ok);
    }
}

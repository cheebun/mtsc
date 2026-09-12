//! signature_hex ↔ Key text conversion
//!
//! Key text = MTBase64Encode(the 64 bytes of signature_hex)
//! signature_hex = hex representation of MTBase64Decode(Key text)

use crate::sha256_constants::ROUND_CONSTANTS;

/// MTBase64 character table (same alphabet as standard Base64, but LSB-first bit order)
const BASE64_TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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

    let encoded = mt_base64_encode(&sig_bytes);

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

    let decoded = mt_base64_decode(&b64_data)?;
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

/// MikroTik Base64 encoding (LSB-first bit order)
fn mt_base64_encode(data: &[u8]) -> String {
    let mut encoded = String::new();
    let mut pending_bits = 0u32;

    for (i, &byte) in data.iter().enumerate() {
        if pending_bits == 0 {
            encoded.push(BASE64_TABLE[(byte & 0x3F) as usize] as char);
            pending_bits = 2;
        } else if pending_bits == 6 {
            encoded.push(BASE64_TABLE[(data[i - 1] >> 2) as usize] as char);
            encoded.push(BASE64_TABLE[(byte & 0x3F) as usize] as char);
            pending_bits = 2;
        } else {
            let index1 = data[i - 1] >> (8 - pending_bits);
            let index2 = (byte as u32) << pending_bits;
            encoded.push(BASE64_TABLE[((index1 as u32 | index2) & 0x3F) as usize] as char);
            pending_bits += 2;
        }
    }

    if pending_bits != 0 {
        encoded.push(BASE64_TABLE[(data[data.len() - 1] >> (8 - pending_bits)) as usize] as char);
    }

    // Padding
    while !encoded.len().is_multiple_of(4) {
        encoded.push('=');
    }

    encoded
}

/// MikroTik Base64 decoding (LSB-first bit order)
fn mt_base64_decode(data: &str) -> Result<Vec<u8>, String> {
    let bytes: Vec<u8> = data.bytes().filter(|&b| b != b'=').collect();

    let mut result = Vec::new();
    let mut pending_bits = 0u32;

    for (i, &byte) in bytes.iter().enumerate() {
        if pending_bits == 0 {
            pending_bits = 6;
        } else {
            let pos_prev = BASE64_TABLE
                .iter()
                .position(|&c| c == bytes[i - 1])
                .ok_or_else(|| format!("invalid base64 char: {}", bytes[i - 1] as char))?;
            let pos_curr = BASE64_TABLE
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

/// hex string → byte array
fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return Err("hex string must have even length".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at position {}: {}", i, e))
        })
        .collect()
}

/// byte array → uppercase hex string
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

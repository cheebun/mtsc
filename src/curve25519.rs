//! EC-KCDSA verification for `keyman`'s local license signatures, built on `curve25519-dalek`
//! (audited, standard Curve25519 field/point arithmetic) rather than hand-rolled bignum code.
//!
//! Curve: y^2 = x^3 + 486662*x^2 + x (Montgomery form) over GF(2^255-19). Verification
//! algorithm and the public key constant below were confirmed via independent disassembly of
//! `tools/bin/keyman_x86_7.23.2` (x86) and `keyman_arm32` -- see docs/license-internals.md §8.32.

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;

/// The `keyman` local-license-verification public key (X-coordinate only), independently
/// confirmed present via disassembly in both `keyman_x86_7.23.2` (x86) and `keyman_arm32` --
/// see docs/license-internals.md §8.32. NOT YET independently confirmed reachable from a
/// local `.key`-file-import code path on ARM (only confirmed on x86) -- see §8.32's open item.
pub const LICENSE_PUBLIC_KEY: [u8; 32] = [
    0x8E, 0x10, 0x67, 0xE4, 0x30, 0x5F, 0xCD, 0xC0, 0xCF, 0xBF, 0x95, 0xC1, 0x0F, 0x96, 0xE5, 0xDF,
    0xE8, 0xC4, 0x9A, 0xEF, 0x48, 0x6B, 0xD1, 0xA4, 0xE2, 0xE9, 0x6C, 0x27, 0xF0, 0x1E, 0x3E, 0x32,
];

/// MikroTik's custom SHA-256 (K-table + initial state), needed for the nonce-hash comparison
/// inside EC-KCDSA verification. See `crate::sha256_constants::ROUND_CONSTANTS` for the
/// K-table (shared with `convert::mt_transform`, confirmed against the reference implementation).
fn mikro_sha256(data: &[u8]) -> [u8; 32] {
    crate::sha256::mikro_sha256_digest(data)
}

/// `signature` is stored little-endian (byte 0 = least significant); `MontgomeryPoint::
/// mul_bits_be` wants the integer's bits **most**-significant-first. Reversing byte order
/// (LE -> MSB-byte-first) and iterating each byte from bit 7 down to bit 0 produces exactly
/// that big-endian bit stream.
fn be_bits_from_le_bytes(bytes: &[u8; 32]) -> impl Iterator<Item = bool> + '_ {
    bytes
        .iter()
        .rev()
        .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
}

/// EC-KCDSA verification, matching the algorithm confirmed in docs/license-internals.md §8.32
/// (`mikro_kcdsa_verify`): `data` is the 16-byte decrypted license payload (SOFTWARE-ID/
/// version/level/reserved), `nonce_hash` and `signature` are the trailing 16+32 bytes of the
/// 64-byte MBR/`.key` signature blob, and `public_key` is the curve X-coordinate (32 bytes).
///
/// Implementation note: the reference algorithm (`toyecc`, and this project's original
/// hand-written version) works directly in Montgomery-curve affine (x, y) coordinates, trying
/// both square-root branches of the public key's Y coordinate before adding two points. That
/// exact affine addition isn't exposed by `curve25519-dalek` (Montgomery points are
/// deliberately X-only). Instead: `public_key * signature`'s X coordinate is computed directly
/// via the Montgomery ladder (`mul_bits_be`, sign-independent -- see comment below), then
/// converted to Edwards form trying both Y signs (`to_edwards`), added to `G * data_hash` in
/// Edwards coordinates (where dalek's `mul_base_clamped` handles the standard X25519 clamping
/// this project's earlier hand-written version applied manually), and converted back to a
/// Montgomery X coordinate for the final hash comparison. This is mathematically equivalent to
/// the reference algorithm: for a Montgomery point P=(x,y) and its negation P'=(x,-y), scalar
/// multiplication satisfies `k*P' = -(k*P)` -- both share the same X coordinate -- so trying
/// both Y signs *after* the scalar multiplication (as done here) explores the same two
/// candidate final points as the reference's "try both Y roots of the public key *before*
/// multiplying" approach.
pub fn verify(
    data: &[u8],
    nonce_hash: &[u8; 16],
    signature: &[u8; 32],
    public_key: &[u8; 32],
) -> bool {
    let public_key_montgomery = MontgomeryPoint(*public_key);
    let term1_x_only = public_key_montgomery.mul_bits_be(be_bits_from_le_bytes(signature));

    let mut data_hash = mikro_sha256(data);
    for i in 0..16 {
        data_hash[8 + i] ^= nonce_hash[i];
    }
    // X25519-standard clamping -- also applied internally by `mul_base_clamped` below, but
    // kept here too (harmless: these bit ops are idempotent) to mirror the reference
    // algorithm's own explicit clamping step for clarity.
    data_hash[0] &= 0xF8;
    data_hash[31] &= 0x7F;
    data_hash[31] |= 0x40;

    let term2: EdwardsPoint = EdwardsPoint::mul_base_clamped(data_hash);

    for sign in [0u8, 1u8] {
        let term1 = match term1_x_only.to_edwards(sign) {
            Some(p) => p,
            None => continue, // this X coordinate/sign combination isn't a valid curve point
        };
        let sum = term1 + term2;
        let nonce_bytes = sum.to_montgomery().to_bytes();
        let recomputed = mikro_sha256(&nonce_bytes);
        if recomputed[..nonce_hash.len()] == nonce_hash[..] {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_our_known_good_ti09_7wk3_signature() {
        // TI09-7WK3's signature from keys.toml, already confirmed valid via real hardware
        // activation (§8.14) and independently confirmed to decode to the right SOFTWARE-ID/
        // level via the ARX cipher (docs/license-internals.md §8.32 step 1). This is the
        // decisive test: it must return `true`.
        let sig_hex = "E67A8F47AE86672FAE6D91DF19221453B34FE40E23F19E917107C449DDCB1D2061521816AD7730671B4CB226F1B0DB7448923C6297C49BDB3CCBF40AECBBCF0B";
        let (decoded_payload, nonce_hash, signature) =
            crate::convert::decode_verify_inputs(sig_hex).unwrap();

        assert!(
            verify(
                &decoded_payload,
                &nonce_hash,
                &signature,
                &LICENSE_PUBLIC_KEY
            ),
            "EC-KCDSA verify failed against a known-good, hardware-confirmed signature"
        );
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let sig_hex = "E67A8F47AE86672FAE6D91DF19221453B34FE40E23F19E917107C449DDCB1D2061521816AD7730671B4CB226F1B0DB7448923C6297C49BDB3CCBF40AECBBCF0B";
        let (decoded_payload, nonce_hash, mut signature) =
            crate::convert::decode_verify_inputs(sig_hex).unwrap();
        signature[0] ^= 0xFF; // flip a byte -- must no longer verify
        assert!(!verify(
            &decoded_payload,
            &nonce_hash,
            &signature,
            &LICENSE_PUBLIC_KEY
        ));
    }

    #[test]
    fn verify_rejects_wrong_public_key() {
        let sig_hex = "E67A8F47AE86672FAE6D91DF19221453B34FE40E23F19E917107C449DDCB1D2061521816AD7730671B4CB226F1B0DB7448923C6297C49BDB3CCBF40AECBBCF0B";
        let (decoded_payload, nonce_hash, signature) =
            crate::convert::decode_verify_inputs(sig_hex).unwrap();
        let mut wrong_key = LICENSE_PUBLIC_KEY;
        wrong_key[0] ^= 0xFF;
        assert!(!verify(
            &decoded_payload,
            &nonce_hash,
            &signature,
            &wrong_key
        ));
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let sig_hex = "E67A8F47AE86672FAE6D91DF19221453B34FE40E23F19E917107C449DDCB1D2061521816AD7730671B4CB226F1B0DB7448923C6297C49BDB3CCBF40AECBBCF0B";
        let (mut decoded_payload, nonce_hash, signature) =
            crate::convert::decode_verify_inputs(sig_hex).unwrap();
        decoded_payload[0] ^= 0xFF;
        assert!(!verify(
            &decoded_payload,
            &nonce_hash,
            &signature,
            &LICENSE_PUBLIC_KEY
        ));
    }
}

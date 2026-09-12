//! Four-way AArch64 NEON kernel for MikroTik's custom 40-byte SHA-256.
//!
//! Each u32 lane hashes an independent message, using vector boolean operations
//! and sigma functions rather than SHA2 instructions. A 16-vector circular
//! schedule fuses expansion with compression. The IV and round constants are
//! exclusively the shared MikroTik values, not standard SHA-256 constants.

#![cfg(target_arch = "aarch64")]

use std::arch::aarch64::*;

use crate::sha256_constants::{INITIAL_HASH_VALUES, ROUND_CONSTANTS};

/// Hash the first four 40-byte inputs into the first four `(sid_lo, sid_hi)` outputs.
///
/// Bytes 20..40 are supplied as five precomputed big-endian words in
/// `const_w5_9`. Their broadcasts, padding, and initial constant round sums are
/// reused across all four lanes. Additional inputs and outputs are untouched.
///
/// # Safety
///
/// The CPU must support AArch64 `neon`; this kernel performs no runtime feature
/// detection and does not require SHA2 or SME. Both slices must contain at least
/// four elements. Bytes 20..40 of all four inputs must be identical and encode
/// exactly `const_w5_9` as big-endian u32 words. No alignment beyond the slice
/// element types' natural alignment is required.
#[target_feature(enable = "neon")]
pub(crate) unsafe fn hash_batch(
    inputs: &[[u8; 40]],
    const_w5_9: &[u32; 5],
    outputs: &mut [(u32, u8)],
) {
    // SAFETY: The caller provides NEON and sufficient slice lengths. All vector
    // loads/stores below stay within four-word arrays and allow unaligned data.
    unsafe {
        let zero = vdupq_n_u32(0);
        let mut w = [zero; 16];
        for (word, slot) in w[..5].iter_mut().enumerate() {
            // Each lane needs the same big-endian word from a different input;
            // from_be_bytes makes this gather independent of native byte order.
            let offset = word * 4;
            let words: [u32; 4] = std::array::from_fn(|lane| {
                let input = inputs.get_unchecked(lane);
                u32::from_be_bytes([
                    input[offset],
                    input[offset + 1],
                    input[offset + 2],
                    input[offset + 3],
                ])
            });
            *slot = vld1q_u32(words.as_ptr());
        }
        for (slot, &word) in w[5..10].iter_mut().zip(const_w5_9) {
            *slot = vdupq_n_u32(word);
        }
        w[10] = vdupq_n_u32(0x8000_0000);
        // W[11..14] remain zero; W[15] is the big-endian bit length, 40 * 8.
        w[15] = vdupq_n_u32(40 * 8);

        // Precompute K + W for the constant rounds once per batch, not per lane.
        // Keep the raw W values in the ring for later message expansion.
        let common_wk: [uint32x4_t; 11] =
            std::array::from_fn(|i| vaddq_u32(w[i + 5], vdupq_n_u32(ROUND_CONSTANTS[i + 5])));
        let iv = INITIAL_HASH_VALUES.map(|word| vdupq_n_u32(word));
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = iv;

        // NEON shifts take immediate amounts; each u32 lane rotates independently.
        macro_rules! rotr {
            ($value:expr, $shift:literal) => {{
                let value = $value;
                vorrq_u32(
                    vshrq_n_u32::<$shift>(value),
                    vshlq_n_u32::<{ 32 - $shift }>(value),
                )
            }};
        }
        macro_rules! round {
            ($wk:expr) => {{
                let wk = $wk;
                let sigma1 = veorq_u32(veorq_u32(rotr!(e, 6), rotr!(e, 11)), rotr!(e, 25));
                // Bit-select implements Ch(e,f,g) = (e & f) ^ (!e & g).
                let ch = vbslq_u32(e, f, g);
                let t1 = vaddq_u32(vaddq_u32(h, sigma1), vaddq_u32(ch, wk));
                let sigma0 = veorq_u32(veorq_u32(rotr!(a, 2), rotr!(a, 13)), rotr!(a, 22));
                // Where a and b differ, c decides; otherwise b is the majority.
                let maj = vbslq_u32(veorq_u32(a, b), c, b);
                let t2 = vaddq_u32(sigma0, maj);
                h = g;
                g = f;
                f = e;
                e = vaddq_u32(d, t1);
                d = c;
                c = b;
                b = a;
                a = vaddq_u32(t1, t2);
            }};
        }

        for (word, &k) in w[..5].iter().zip(&ROUND_CONSTANTS[..5]) {
            round!(vaddq_u32(*word, vdupq_n_u32(k)));
        }
        for wk in common_wk {
            round!(wk);
        }
        for (round_index, &k) in ROUND_CONSTANTS.iter().enumerate().skip(16) {
            // Overwrite W[t-16] only after reading all recurrence inputs.
            let x = w[(round_index - 15) & 15];
            let y = w[(round_index - 2) & 15];
            let sigma0 = veorq_u32(veorq_u32(rotr!(x, 7), rotr!(x, 18)), vshrq_n_u32::<3>(x));
            let sigma1 = veorq_u32(veorq_u32(rotr!(y, 17), rotr!(y, 19)), vshrq_n_u32::<10>(y));
            let slot = round_index & 15;
            w[slot] = vaddq_u32(
                vaddq_u32(w[slot], sigma0),
                vaddq_u32(w[(round_index - 7) & 15], sigma1),
            );
            round!(vaddq_u32(w[slot], vdupq_n_u32(k)));
        }

        // Only the first two feedforward words contribute to SOFTWARE ID.
        a = vaddq_u32(a, iv[0]);
        b = vaddq_u32(b, iv[1]);
        let mut state0 = [0u32; 4];
        let mut state1 = [0u32; 4];
        vst1q_u32(state0.as_mut_ptr(), a);
        vst1q_u32(state1.as_mut_ptr(), b);
        for lane in 0..4 {
            // RouterOS interprets digest bytes 0..4 (BE state0) as LE u32, so
            // swap bytes. Digest byte 4 is the most significant byte of state1.
            *outputs.get_unchecked_mut(lane) =
                (state0[lane].swap_bytes(), (state1[lane] >> 24) as u8);
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sha256, sha256_scalar};

    fn supported() -> bool {
        let supported = std::arch::is_aarch64_feature_detected!("neon");
        if !supported {
            eprintln!("SKIP: AArch64 NEON is not supported on this CPU");
        }
        supported
    }

    fn constant_words(input: &[u8; 40]) -> [u32; 5] {
        // The kernel accepts numeric BE words, not native-endian tail loads.
        std::array::from_fn(|i| {
            let offset = 20 + 4 * i;
            u32::from_be_bytes(input[offset..offset + 4].try_into().unwrap())
        })
    }

    fn check_batch(inputs: &[[u8; 40]; 4]) {
        let words = constant_words(&inputs[0]);
        let sentinel = (0xdead_beef, 0xa5);
        // An extra input with a different tail must not be consumed.
        let mut larger_inputs = [[0xa5; 40]; 5];
        larger_inputs[..4].copy_from_slice(inputs);
        for exact_length in [true, false] {
            let mut outputs = [sentinel; 6];
            let input_slice = if exact_length {
                &inputs[..]
            } else {
                &larger_inputs[..]
            };
            let output_end = if exact_length { 5 } else { outputs.len() };
            // SAFETY: Tests gate NEON first; both slices have at least four
            // elements and their processed tails agree with the supplied words.
            unsafe { hash_batch(input_slice, &words, &mut outputs[1..output_end]) };
            for (lane, input) in inputs.iter().enumerate() {
                let expected = sha256::hash_40(input);
                assert_eq!(expected, sha256_scalar::hash_40(input));
                assert_eq!(outputs[lane + 1], expected, "lane={lane}");
            }
            assert_eq!(outputs[0], sentinel);
            assert_eq!(outputs[5], sentinel);
        }
    }

    fn random_byte(seed: &mut u64) -> u8 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        (*seed >> 32) as u8
    }

    #[test]
    fn test_neon_6g_known() {
        if !supported() {
            return;
        }
        let mut input = [0x20; 40];
        input[..20].copy_from_slice(b"00000000000000000001");
        input[20..36].copy_from_slice(b"VMware Virtual I");
        input[36..40].copy_from_slice(&0x1800u32.to_le_bytes());
        assert_eq!(sha256::hash_40(&input), (0x0b49_ec2e, 0x35));
        check_batch(&[input; 4]);
    }

    #[test]
    fn test_neon_distinct_lanes() {
        if !supported() {
            return;
        }
        let mut inputs = [[0x20; 40]; 4];
        for (lane, input) in inputs.iter_mut().enumerate() {
            input[..20].copy_from_slice(format!("{lane:020}").as_bytes());
            input[20..36].copy_from_slice(b"VMware Virtual I");
            input[36..40].copy_from_slice(&0x1800u32.to_le_bytes());
        }
        check_batch(&inputs);
    }

    #[test]
    fn test_neon_varied_tails_match_scalars() {
        if !supported() {
            return;
        }
        let models = [
            *b"VMware Virtual I",
            *b"ABCDEFGHIJKLMNOP",
            [0x20; 16],
            [0; 16],
            [0xff; 16],
        ];
        for model in models {
            for sectors in [0u32, 1, 0x1800, 0x1234_5678, u32::MAX] {
                let mut inputs = [[0; 40]; 4];
                for (lane, input) in inputs.iter_mut().enumerate() {
                    for (index, byte) in input[..20].iter_mut().enumerate() {
                        *byte = (index as u8).wrapping_mul(17).wrapping_add(lane as u8);
                    }
                    input[20..36].copy_from_slice(&model);
                    input[36..40].copy_from_slice(&sectors.to_le_bytes());
                }
                check_batch(&inputs);
            }
        }
    }

    #[test]
    fn test_neon_random_batches_match_scalars() {
        if !supported() {
            return;
        }
        let mut seed = 0xd42c_9618_eb37_05afu64;
        for case in 0..128 {
            let mut tail = [0; 20];
            for byte in &mut tail {
                *byte = random_byte(&mut seed);
            }
            let mut inputs = [[0; 40]; 4];
            for input in &mut inputs {
                for byte in &mut input[..20] {
                    *byte = match case {
                        0 => 0,
                        1 => 0xff,
                        _ => random_byte(&mut seed),
                    };
                }
                input[20..40].copy_from_slice(&tail);
            }
            check_batch(&inputs);
        }
    }
}

//! AArch64 SHA2-instruction kernels for MikroTik's custom 40-byte SHA-256.
//!
//! Each stream keeps its own state and four-vector circular message schedule.
//! Four-round groups are interleaved across 1, 2, or 4 independent streams; the
//! SHA2 instructions implement the round operations, not the IV or constants.
//! Those always come from `sha256_constants`, never the standard SHA-256 tables.

#![cfg(target_arch = "aarch64")]

use std::arch::aarch64::*;

use crate::sha256_constants::{INITIAL_HASH_VALUES, ROUND_CONSTANTS};

/// Hash the first `N` 40-byte inputs into the first `N` `(sid_lo, sid_hi)` outputs.
///
/// `N` is specialized for 1, 2, or 4 interleaved independent hashes. Bytes 20..40
/// are supplied as five precomputed big-endian words in `const_w5_9`, allowing
/// the common model/sector tail and padding to be reused across streams.
/// Additional inputs and output slots are left untouched.
///
/// # Safety
///
/// The CPU must support both AArch64 `neon` and `sha2`; this kernel performs no
/// runtime feature detection. `N` must be 1, 2, or 4, and both slices must contain
/// at least `N` elements. For every processed input, bytes 20..40 must be identical
/// and encode exactly `const_w5_9` as big-endian u32 words. No alignment beyond
/// the slice element types' natural alignment is required.
#[target_feature(enable = "neon,sha2")]
pub(crate) unsafe fn hash_batch<const N: usize>(
    inputs: &[[u8; 40]],
    const_w5_9: &[u32; 5],
    outputs: &mut [(u32, u8)],
) {
    // SAFETY: The caller supplies the required features and slice lengths. All
    // vector loads below stay within their arrays and permit unaligned addresses.
    unsafe {
        let zero = vdupq_n_u32(0);
        let iv_abcd = vld1q_u32(INITIAL_HASH_VALUES.as_ptr());
        let iv_efgh = vld1q_u32(INITIAL_HASH_VALUES.as_ptr().add(4));
        let mut abcd = [iv_abcd; N];
        let mut efgh = [iv_efgh; N];

        // W[4] varies; W[5..9] are already numeric big-endian message words.
        let w4_7 = [0, const_w5_9[0], const_w5_9[1], const_w5_9[2]];
        let w8_11 = [const_w5_9[3], const_w5_9[4], 0x8000_0000, 0];
        // One-block padding encodes the 40-byte message length as 320 bits.
        let w12_15 = [0, 0, 0, 40 * 8];
        let common = [
            zero,
            vld1q_u32(w4_7.as_ptr()),
            vld1q_u32(w8_11.as_ptr()),
            vld1q_u32(w12_15.as_ptr()),
        ];
        let mut w = [common; N];
        for (stream, schedule) in w.iter_mut().enumerate() {
            let input = inputs.get_unchecked(stream);
            let bytes = vld1q_u8(input.as_ptr());
            // SHA-256 parses message words big-endian. Reverse each loaded u32
            // on little-endian AArch64 (including Apple Silicon), not word order.
            #[cfg(target_endian = "little")]
            let bytes = vrev32q_u8(bytes);
            schedule[0] = vreinterpretq_u32_u8(bytes);
            let w4 = u32::from_be_bytes([input[16], input[17], input[18], input[19]]);
            schedule[1] = vsetq_lane_u32::<0>(w4, schedule[1]);
        }

        // Literal slots let each specialization retain a four-vector W[16]
        // ring instead of indexing a 64-word expanded schedule. Each group
        // advances every independent stream before any stream advances again.
        macro_rules! rounds4 {
            ($slot:literal, $round:expr, $expand:literal) => {{
                // The custom K vector is loaded once and reused by all streams.
                let k = vld1q_u32(ROUND_CONSTANTS.as_ptr().add($round));
                for stream in 0..N {
                    if $expand {
                        let partial = vsha256su0q_u32(w[stream][$slot], w[stream][($slot + 1) & 3]);
                        w[stream][$slot] = vsha256su1q_u32(
                            partial,
                            w[stream][($slot + 2) & 3],
                            w[stream][($slot + 3) & 3],
                        );
                    }
                    let wk = vaddq_u32(w[stream][$slot], k);
                    // SHA256H2 needs the OLD abcd, not SHA256H's updated result.
                    let old_abcd = abcd[stream];
                    abcd[stream] = vsha256hq_u32(old_abcd, efgh[stream], wk);
                    efgh[stream] = vsha256h2q_u32(efgh[stream], old_abcd, wk);
                }
            }};
        }

        rounds4!(0, 0, false);
        rounds4!(1, 4, false);
        rounds4!(2, 8, false);
        rounds4!(3, 12, false);
        for round in (16..64).step_by(16) {
            rounds4!(0, round, true);
            rounds4!(1, round + 4, true);
            rounds4!(2, round + 8, true);
            rounds4!(3, round + 12, true);
        }

        for (stream, state) in abcd.iter().enumerate() {
            // Only the first two feedforward words are needed for SOFTWARE ID.
            let state = vaddq_u32(*state, iv_abcd);
            let state0 = vgetq_lane_u32::<0>(state);
            let state1 = vgetq_lane_u32::<1>(state);
            // RouterOS reads the first four big-endian digest bytes as LE u32;
            // the fifth digest byte is the high byte of the second state word.
            *outputs.get_unchecked_mut(stream) = (state0.swap_bytes(), (state1 >> 24) as u8);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sha256, sha256_scalar};

    fn supported() -> bool {
        let supported = crate::sha256_cpu::arm_sha2_supported();
        if !supported {
            eprintln!("SKIP: AArch64 NEON + SHA2 are not supported on this CPU");
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

    fn check_width<const N: usize>(inputs: &[[u8; 40]; 4]) {
        let words = constant_words(&inputs[0]);
        let sentinel = (0xdead_beef, 0xa5);
        // Exercise both exact-length slices and a larger caller-owned buffer.
        for exact_length in [true, false] {
            let mut outputs = [sentinel; 6];
            let input_slice = if exact_length { &inputs[..N] } else { inputs };
            let output_end = if exact_length { N + 1 } else { outputs.len() };
            // SAFETY: Each test gates NEON + SHA2 first, uses N = 1/2/4, and
            // supplies sufficient slices with identical, correctly encoded tails.
            unsafe { hash_batch::<N>(input_slice, &words, &mut outputs[1..output_end]) };
            for (stream, input) in inputs.iter().enumerate().take(N) {
                let expected = sha256::hash_40(input);
                assert_eq!(expected, sha256_scalar::hash_40(input));
                assert_eq!(outputs[stream + 1], expected, "N={N}, stream={stream}");
            }
            assert_eq!(outputs[0], sentinel);
            assert!(outputs[N + 1..].iter().all(|&value| value == sentinel));
        }
    }

    fn check_all_widths(inputs: &[[u8; 40]; 4]) {
        check_width::<1>(inputs);
        check_width::<2>(inputs);
        check_width::<4>(inputs);
    }

    fn random_byte(seed: &mut u64) -> u8 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        (*seed >> 32) as u8
    }

    #[test]
    fn test_arm_6g_known_all_widths() {
        if !supported() {
            return;
        }
        let mut input = [0x20; 40];
        input[..20].copy_from_slice(b"00000000000000000001");
        input[20..36].copy_from_slice(b"VMware Virtual I");
        input[36..40].copy_from_slice(&0x1800u32.to_le_bytes());
        assert_eq!(sha256::hash_40(&input), (0x0b49_ec2e, 0x35));
        check_all_widths(&[input; 4]);
    }

    #[test]
    fn test_arm_distinct_streams() {
        if !supported() {
            return;
        }
        let mut inputs = [[0x20; 40]; 4];
        for (stream, input) in inputs.iter_mut().enumerate() {
            input[..20].copy_from_slice(format!("{stream:020}").as_bytes());
            input[20..36].copy_from_slice(b"VMware Virtual I");
            input[36..40].copy_from_slice(&0x1800u32.to_le_bytes());
        }
        check_all_widths(&inputs);
    }

    #[test]
    fn test_arm_varied_tails_match_scalars() {
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
                for (stream, input) in inputs.iter_mut().enumerate() {
                    for (index, byte) in input[..20].iter_mut().enumerate() {
                        *byte = (index as u8).wrapping_mul(17).wrapping_add(stream as u8);
                    }
                    input[20..36].copy_from_slice(&model);
                    input[36..40].copy_from_slice(&sectors.to_le_bytes());
                }
                check_all_widths(&inputs);
            }
        }
    }

    #[test]
    fn test_arm_random_batches_match_scalars() {
        if !supported() {
            return;
        }
        let mut seed = 0x8ab3_7c19_d526_40efu64;
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
            check_all_widths(&inputs);
        }
    }
}

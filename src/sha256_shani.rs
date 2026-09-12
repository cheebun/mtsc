//! SHA-NI backend for MikroTik's custom, single-block 40-byte SHA-256.
//!
//! Interleaves 1, 2, or 4 independent messages rather than chaining their states.
//! Each message keeps just four 128-bit vectors for the circular W[16] schedule.
//! SHA instructions implement the standard round/schedule operations, but receive
//! MikroTik's shared custom IV and round constants, never the standard SHA-256 K.
//! Only SHA, SSSE3, and SSE4.1 are required; this backend has no AVX dependency.

#![cfg(any(target_arch = "x86", target_arch = "x86_64"))]

#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

use crate::sha256_constants::{INITIAL_HASH_VALUES, ROUND_CONSTANTS};

/// Hash `N` independent 40-byte messages, writing `(sid_lo, sid_hi)` in input order.
///
/// Monomorphize with `N = 1`, `2`, or `4`. Two-round SHA instructions are issued
/// across buffers before returning to the same buffer, exposing independent
/// instruction chains. SHA256MSG1/SHA256MSG2 expand four words at a time in a
/// circular four-vector schedule per message. The five uniform tail words are
/// precomputed by the caller, and the single-block padding is fixed at 320 bits.
/// Returns `(state[0].swap_bytes(), (state[1] >> 24) as u8)` after feedforward,
/// following RouterOS's digest convention without any SOFTWARE ID business logic.
/// No feature detection, allocation, or partial-batch handling occurs here.
///
/// # Safety
///
/// The caller must ensure SHA, SSSE3, and SSE4.1 are available, `N` is 1, 2, or 4,
/// and `inputs.len() == outputs.len() == N`. Every input's bytes 20..40 must equal
/// the big-endian encodings of `const_w5_9`; these bytes are not read by the kernel.
/// The input and output slices need only their element types' normal alignment.
#[target_feature(enable = "sha,ssse3,sse4.1")]
pub(crate) unsafe fn hash_batch<const N: usize>(
    inputs: &[[u8; 40]],
    const_w5_9: &[u32; 5],
    outputs: &mut [(u32, u8)],
) {
    // SAFETY: The caller guarantees the target features and exact batch lengths.
    // Loads read at most the first 20 bytes of each message, all vector loads are
    // unaligned, and unchecked output accesses are limited to the N lanes.
    unsafe {
        let zero = _mm_setzero_si128();
        // x86 loads little-endian u32s; reverse bytes within each word to obtain
        // SHA-256's numeric big-endian message words, without reordering words.
        let bswap = _mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);
        // These are already numeric big-endian words and need no byte reversal.
        let w4_7_tail = _mm_setr_epi32(
            0,
            const_w5_9[0] as i32,
            const_w5_9[1] as i32,
            const_w5_9[2] as i32,
        );
        let w8_11 = _mm_setr_epi32(
            const_w5_9[3] as i32,
            const_w5_9[4] as i32,
            0x8000_0000u32 as i32,
            0,
        );
        // W[12..14] are zero; W[15] is the big-endian bit length, 40 * 8.
        let w12_15 = _mm_setr_epi32(0, 0, 0, 0x140);
        let mut schedule = [[zero; 4]; N];
        for (lane, w) in schedule.iter_mut().enumerate() {
            let input = inputs.get_unchecked(lane).as_ptr();
            w[0] = _mm_shuffle_epi8(_mm_loadu_si128(input.cast()), bswap);
            // Load only W[4], not any bytes from the caller-precomputed tail.
            let raw_w4 = _mm_cvtsi32_si128(input.add(16).cast::<i32>().read_unaligned());
            w[1] = _mm_or_si128(_mm_shuffle_epi8(raw_w4, bswap), w4_7_tail);
            w[2] = w8_11;
            w[3] = w12_15;
        }

        // SHA256RNDS2 uses ABEF/CDGH packed in high-to-low order, so the actual
        // low-to-high u32 lanes are [F,E,B,A] and [H,G,D,C]. This is lane packing,
        // NOT byte reversal: all state words remain native numeric u32 values.
        let initial_abef = _mm_setr_epi32(
            INITIAL_HASH_VALUES[5] as i32,
            INITIAL_HASH_VALUES[4] as i32,
            INITIAL_HASH_VALUES[1] as i32,
            INITIAL_HASH_VALUES[0] as i32,
        );
        let initial_cdgh = _mm_setr_epi32(
            INITIAL_HASH_VALUES[7] as i32,
            INITIAL_HASH_VALUES[6] as i32,
            INITIAL_HASH_VALUES[3] as i32,
            INITIAL_HASH_VALUES[2] as i32,
        );
        let mut abef = [initial_abef; N];
        let mut cdgh = [initial_cdgh; N];

        /// Expand/consume four words and interleave two round pairs across buffers.
        macro_rules! rounds4 {
            ($round:literal) => {{
                // Literal slots let the optimizer keep the four-vector ring in
                // registers; no W[64] expansion or run-time ring indexing is used.
                const SLOT: usize = ($round / 4) & 3;
                let constants = _mm_loadu_si128(ROUND_CONSTANTS.as_ptr().add($round).cast());
                let mut wk = [zero; N];
                for (w, message) in schedule.iter_mut().zip(&mut wk) {
                    if $round >= 16 {
                        // MSG1 adds sigma0(W[t-15..t-12]) to W[t-16..t-13].
                        let partial = _mm_sha256msg1_epu32(w[SLOT], w[(SLOT + 1) & 3]);
                        // PALIGNR forms W[t-7..t-4] from the two newest vectors.
                        let middle = _mm_alignr_epi8::<4>(w[(SLOT + 3) & 3], w[(SLOT + 2) & 3]);
                        // MSG2 adds sigma1 and resolves the two intra-vector
                        // dependencies on the newly generated W[t] and W[t+1].
                        w[SLOT] =
                            _mm_sha256msg2_epu32(_mm_add_epi32(partial, middle), w[(SLOT + 3) & 3]);
                    }
                    // K is MikroTik's custom K, loaded in round order. Keep W
                    // unmodified: subsequent schedule expansion must not see K.
                    *message = _mm_add_epi32(w[SLOT], constants);
                }
                for ((state_cdgh, &state_abef), &message) in cdgh.iter_mut().zip(&abef).zip(&wk) {
                    *state_cdgh = _mm_sha256rnds2_epu32(*state_cdgh, state_abef, message);
                }
                for ((state_abef, &state_cdgh), &message) in abef.iter_mut().zip(&cdgh).zip(&wk) {
                    // RNDS2 consumes the low two lanes; move W[t+2]+K[t+2]
                    // and W[t+3]+K[t+3] there for the second pair of rounds.
                    let next_pair = _mm_shuffle_epi32::<0x0e>(message);
                    *state_abef = _mm_sha256rnds2_epu32(*state_abef, state_cdgh, next_pair);
                }
            }};
        }

        rounds4!(0);
        rounds4!(4);
        rounds4!(8);
        rounds4!(12);
        rounds4!(16);
        rounds4!(20);
        rounds4!(24);
        rounds4!(28);
        rounds4!(32);
        rounds4!(36);
        rounds4!(40);
        rounds4!(44);
        rounds4!(48);
        rounds4!(52);
        rounds4!(56);
        rounds4!(60);

        for (lane, state_abef) in abef.into_iter().enumerate() {
            // Only A and B are needed, so CDGH feedforward can be omitted.
            let state = _mm_add_epi32(state_abef, initial_abef);
            let state0 = _mm_extract_epi32::<3>(state) as u32;
            let state1 = _mm_extract_epi32::<2>(state) as u32;
            // RouterOS reads the first four big-endian digest bytes little-endian,
            // hence swap_bytes; the fifth byte is the high byte of state[1].
            *outputs.get_unchecked_mut(lane) = (state0.swap_bytes(), (state1 >> 24) as u8);
        }
    }
}

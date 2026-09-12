//! Eight-way AVX2 backend for MikroTik's custom, single-block 40-byte SHA-256.
//!
//! Only the first 20 bytes vary between lanes. The caller supplies the remaining
//! five big-endian message words, selects this backend, and handles batch sizing.
//! The IV and round constants come exclusively from `sha256_constants`.

#![cfg(any(target_arch = "x86", target_arch = "x86_64"))]

#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

use crate::sha256_constants::{INITIAL_HASH_VALUES, ROUND_CONSTANTS};

/// Rotate every 32-bit lane right by an immediate amount.
macro_rules! rotr {
    ($x:expr, $n:literal) => {
        _mm256_or_si256(_mm256_srli_epi32($x, $n), _mm256_slli_epi32($x, 32 - $n))
    };
}

/// Compute SHA-256's large sigma zero independently in eight lanes.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn big_sigma0(x: __m256i) -> __m256i {
    _mm256_xor_si256(_mm256_xor_si256(rotr!(x, 2), rotr!(x, 13)), rotr!(x, 22))
}

/// Compute SHA-256's large sigma one independently in eight lanes.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn big_sigma1(x: __m256i) -> __m256i {
    _mm256_xor_si256(_mm256_xor_si256(rotr!(x, 6), rotr!(x, 11)), rotr!(x, 25))
}

/// Compute SHA-256's small sigma zero for the circular message schedule.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn small_sigma0(x: __m256i) -> __m256i {
    _mm256_xor_si256(
        _mm256_xor_si256(rotr!(x, 7), rotr!(x, 18)),
        _mm256_srli_epi32(x, 3),
    )
}

/// Compute SHA-256's small sigma one for the circular message schedule.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn small_sigma1(x: __m256i) -> __m256i {
    _mm256_xor_si256(
        _mm256_xor_si256(rotr!(x, 17), rotr!(x, 19)),
        _mm256_srli_epi32(x, 10),
    )
}

/// Hash exactly eight 40-byte messages, writing `(sid_lo, sid_hi)` in lane order.
///
/// Uses AVX2 gather/byte reversal for W[0..4], broadcasts the precomputed W[5..9],
/// and fuses expansion and compression using a circular W[16] (512 bytes).
/// Returns the RouterOS convention `(state[0].swap_bytes(), (state[1] >> 24) as u8)`
/// after feedforward, not a standard SHA-256 digest or a complete SOFTWARE ID.
/// No feature detection, allocation, or partial-batch handling occurs here.
///
/// # Safety
///
/// The caller must ensure AVX2 is available, `inputs.len() == 8`, and
/// `outputs.len() == 8`. For every input, bytes 20..40 must equal the big-endian
/// encodings of `const_w5_9`; those bytes are not read by the kernel. No alignment
/// beyond the slice element types' normal requirements is needed.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn hash_batch(
    inputs: &[[u8; 40]],
    const_w5_9: &[u32; 5],
    outputs: &mut [(u32, u8)],
) {
    // SAFETY: The caller supplies eight inputs/outputs and guarantees AVX2.
    // Gather reads only the first five words of each input; all stores are
    // unaligned or use the normal alignment of an output tuple.
    unsafe {
        // Each 128-bit half uses the same per-u32 byte reversal. x86 loads words
        // little-endian, but SHA-256 interprets the message bytes big-endian.
        let bswap = _mm256_setr_epi8(
            3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 3, 2, 1, 0, 7, 6, 5, 4, 11, 10,
            9, 8, 15, 14, 13, 12,
        );
        let strides = _mm256_setr_epi32(0, 40, 80, 120, 160, 200, 240, 280);
        let base = inputs.as_ptr().cast::<u8>();
        let mut w = [_mm256_setzero_si256(); 16];
        for (word_idx, word) in w[..5].iter_mut().enumerate() {
            let raw = _mm256_i32gather_epi32::<1>(base.add(word_idx * 4).cast::<i32>(), strides);
            *word = _mm256_shuffle_epi8(raw, bswap);
        }
        for (word, &constant) in w[5..10].iter_mut().zip(const_w5_9) {
            // Already numeric big-endian message words, so do not byte-swap.
            *word = _mm256_set1_epi32(constant as i32);
        }
        w[10] = _mm256_set1_epi32(0x8000_0000u32 as i32);
        // W[11..14] are zero; W[15] encodes the big-endian bit length, 40 * 8.
        w[15] = _mm256_set1_epi32(0x140);

        let mut a = _mm256_set1_epi32(INITIAL_HASH_VALUES[0] as i32);
        let mut b = _mm256_set1_epi32(INITIAL_HASH_VALUES[1] as i32);
        let mut c = _mm256_set1_epi32(INITIAL_HASH_VALUES[2] as i32);
        let mut d = _mm256_set1_epi32(INITIAL_HASH_VALUES[3] as i32);
        let mut e = _mm256_set1_epi32(INITIAL_HASH_VALUES[4] as i32);
        let mut f = _mm256_set1_epi32(INITIAL_HASH_VALUES[5] as i32);
        let mut g = _mm256_set1_epi32(INITIAL_HASH_VALUES[6] as i32);
        let mut h = _mm256_set1_epi32(INITIAL_HASH_VALUES[7] as i32);

        for (round, &constant) in ROUND_CONSTANTS.iter().enumerate() {
            let slot = round & 15;
            if round >= 16 {
                w[slot] = _mm256_add_epi32(
                    _mm256_add_epi32(w[slot], small_sigma0(w[(round - 15) & 15])),
                    _mm256_add_epi32(w[(round - 7) & 15], small_sigma1(w[(round - 2) & 15])),
                );
            }

            // Ch = g XOR (e AND (f XOR g)); Maj = (a AND b) OR (c AND (a OR b)).
            let ch = _mm256_xor_si256(g, _mm256_and_si256(e, _mm256_xor_si256(f, g)));
            let maj = _mm256_or_si256(
                _mm256_and_si256(a, b),
                _mm256_and_si256(c, _mm256_or_si256(a, b)),
            );
            let t1 = _mm256_add_epi32(
                _mm256_add_epi32(h, big_sigma1(e)),
                _mm256_add_epi32(
                    ch,
                    _mm256_add_epi32(w[slot], _mm256_set1_epi32(constant as i32)),
                ),
            );
            let t2 = _mm256_add_epi32(big_sigma0(a), maj);
            h = g;
            g = f;
            f = e;
            e = _mm256_add_epi32(d, t1);
            d = c;
            c = b;
            b = a;
            a = _mm256_add_epi32(t1, t2);
        }

        // Only these two feedforward words contribute to the requested output.
        a = _mm256_add_epi32(a, _mm256_set1_epi32(INITIAL_HASH_VALUES[0] as i32));
        b = _mm256_add_epi32(b, _mm256_set1_epi32(INITIAL_HASH_VALUES[1] as i32));
        let mut sid_lo = [0u32; 8];
        let mut state1 = [0u32; 8];
        // RouterOS reads the first four big-endian digest bytes little-endian:
        // a per-word byte reversal is exactly state[0].swap_bytes().
        _mm256_storeu_si256(sid_lo.as_mut_ptr().cast(), _mm256_shuffle_epi8(a, bswap));
        _mm256_storeu_si256(state1.as_mut_ptr().cast(), b);
        for (lane, (&sid_lo, &state1)) in sid_lo.iter().zip(&state1).enumerate() {
            // The fifth digest byte is the high (big-endian) byte of state[1].
            *outputs.get_unchecked_mut(lane) = (sid_lo, (state1 >> 24) as u8);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gate hardware execution without adding detection to the production kernel.
    fn supported() -> bool {
        let supported = is_x86_feature_detected!("avx2");
        if !supported {
            eprintln!("SKIP: AVX2 not supported on this CPU");
        }
        supported
    }

    /// Decode the uniform tail into the kernel's numeric big-endian words.
    fn constant_words(input: &[u8; 40]) -> [u32; 5] {
        std::array::from_fn(|i| {
            u32::from_be_bytes(input[20 + 4 * i..24 + 4 * i].try_into().unwrap())
        })
    }

    /// Generate deterministic pseudo-random test data without extra dependencies.
    fn next_random(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    /// Compare all eight lanes with both existing scalar implementations.
    fn check_batch(inputs: &[[u8; 40]; 8]) -> [(u32, u8); 8] {
        let mut outputs = [(0, 0); 8];
        // SAFETY: Tests call this only after feature detection, with exact batch
        // lengths and a common tail used to construct the precomputed words.
        unsafe { hash_batch(inputs, &constant_words(&inputs[0]), &mut outputs) };
        for (lane, (input, &output)) in inputs.iter().zip(&outputs).enumerate() {
            assert_eq!(output, crate::sha256::hash_40(input), "lane {lane}");
            assert_eq!(output, crate::sha256_scalar::hash_40(input), "lane {lane}");
        }
        outputs
    }

    /// Preserve the hardware-independent, known 6G VMware result and lane order.
    #[test]
    fn test_6g_known() {
        if !supported() {
            return;
        }
        let inputs = std::array::from_fn(|lane| {
            let mut input = [0x20; 40];
            input[..20].copy_from_slice(format!("{lane:020}").as_bytes());
            input[20..36].copy_from_slice(b"VMware Virtual I");
            input[36..40].copy_from_slice(&0x1800u32.to_le_bytes());
            input
        });
        assert_eq!(check_batch(&inputs)[1], (0x0B49EC2E, 0x35));
    }

    /// Exercise independent decimal serials with a shared model/sector tail.
    #[test]
    fn test_random_serials() {
        if !supported() {
            return;
        }
        let mut random = 0x6a09_e667_f3bc_c909;
        for _ in 0..128 {
            let inputs = std::array::from_fn(|_| {
                let mut input = [0u8; 40];
                for byte in &mut input[..20] {
                    *byte = b'0' + (next_random(&mut random) % 10) as u8;
                }
                input[20..36].copy_from_slice(b"VMware Virtual I");
                input[36..40].copy_from_slice(&0x1800u32.to_le_bytes());
                input
            });
            check_batch(&inputs);
        }
    }

    /// Vary uniform tails and binary prefixes, including zero/high-bit patterns.
    #[test]
    fn test_varied_uniform_tails() {
        if !supported() {
            return;
        }
        let mut random = 0xbb67_ae85_84ca_a73b;
        for case in 0..128 {
            let tail: [u8; 20] = std::array::from_fn(|i| match case {
                0 => 0,
                1 => 0xff,
                2 => 0x80,
                3 => i as u8,
                4 => {
                    if i % 2 == 0 {
                        0x55
                    } else {
                        0xaa
                    }
                }
                _ => next_random(&mut random) as u8,
            });
            let inputs = std::array::from_fn(|lane| {
                let mut input = [0u8; 40];
                for byte in &mut input[..20] {
                    *byte = match lane {
                        0 => 0,
                        1 => 0xff,
                        _ => next_random(&mut random) as u8,
                    };
                }
                input[20..].copy_from_slice(&tail);
                input
            });
            check_batch(&inputs);
        }
    }

    /// Accept unaligned input storage and leave neighboring output tuples alone.
    #[test]
    fn test_sliced_unaligned_buffers() {
        if !supported() {
            return;
        }
        #[repr(align(32))]
        struct Storage([u8; 1 + 8 * 40]);
        let mut storage = Storage([0; 1 + 8 * 40]);
        // SAFETY: Offset one is deliberately unaligned for SIMD, but [u8; 40]
        // has alignment one and the allocation contains eight complete inputs.
        let inputs = unsafe { &mut *storage.0.as_mut_ptr().add(1).cast::<[[u8; 40]; 8]>() };
        for (lane, input) in inputs.iter_mut().enumerate() {
            input[..20].fill(lane as u8);
            input[20..].fill(0xa5);
        }
        let sentinel = (0xdead_beef, 0xa7);
        let mut outputs = [sentinel; 10];
        // SAFETY: Features are detected and both slices have exactly eight lanes.
        unsafe { hash_batch(inputs, &constant_words(&inputs[0]), &mut outputs[1..9]) };
        assert_eq!(outputs[0], sentinel);
        assert_eq!(outputs[9], sentinel);
        for (input, &output) in inputs.iter().zip(&outputs[1..9]) {
            assert_eq!(output, crate::sha256::hash_40(input));
            assert_eq!(output, crate::sha256_scalar::hash_40(input));
        }
    }
}

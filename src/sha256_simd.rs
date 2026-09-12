//! AVX-512 SIMD implementation of MikroTik custom SHA-256
//!
//! Uses 512-bit registers to compute 16 SHA-256 lanes simultaneously,
//! with one instruction processing 16 independent u32 operations.
//!
//! Prerequisite: CPU supports AVX-512F + AVX-512BW (e.g. AMD Zen4 / Intel Ice Lake+).

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

use crate::sha256_constants::{INITIAL_HASH_VALUES, ROUND_CONSTANTS};

/// Result of the 16-way parallel SHA-256
pub struct SimdResult {
    /// 16 sid_lo values (source of the SOFTWARE ID low 32 bits)
    pub sid_lo: [u32; 16],
    /// 16 sid_hi values (source of the SOFTWARE ID high byte)
    pub sid_hi: [u8; 16],
}

/// SIMD rotate-right helper macro: the imm8 shift amount must be a literal, not a generic parameter.
macro_rules! rotr {
    ($x:expr, $n:literal) => {{
        _mm512_or_si512(_mm512_srli_epi32($x, $n), _mm512_slli_epi32($x, 32 - $n))
    }};
}

/// SHA-256 Σ0(a) = ROTR(a,2) ⊕ ROTR(a,13) ⊕ ROTR(a,22)
#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx512f")]
unsafe fn big_sigma0(a: __m512i) -> __m512i {
    _mm512_xor_si512(_mm512_xor_si512(rotr!(a, 2), rotr!(a, 13)), rotr!(a, 22))
}

/// SHA-256 Σ1(e) = ROTR(e,6) ⊕ ROTR(e,11) ⊕ ROTR(e,25)
#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx512f")]
unsafe fn big_sigma1(e: __m512i) -> __m512i {
    _mm512_xor_si512(_mm512_xor_si512(rotr!(e, 6), rotr!(e, 11)), rotr!(e, 25))
}

/// SHA-256 σ0(x) = ROTR(x,7) ⊕ ROTR(x,18) ⊕ (x >> 3)
#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx512f")]
unsafe fn small_sigma0(x: __m512i) -> __m512i {
    _mm512_xor_si512(
        _mm512_xor_si512(rotr!(x, 7), rotr!(x, 18)),
        _mm512_srli_epi32(x, 3),
    )
}

/// SHA-256 σ1(x) = ROTR(x,17) ⊕ ROTR(x,19) ⊕ (x >> 10)
#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx512f")]
unsafe fn small_sigma1(x: __m512i) -> __m512i {
    _mm512_xor_si512(
        _mm512_xor_si512(rotr!(x, 17), rotr!(x, 19)),
        _mm512_srli_epi32(x, 10),
    )
}

/// Ch(e,f,g) = (e & f) ^ (!e & g)  — ternarylogic 0xCA
#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx512f")]
unsafe fn ch(e: __m512i, f: __m512i, g: __m512i) -> __m512i {
    _mm512_ternarylogic_epi32(e, f, g, 0xCA)
}

/// Maj(a,b,c) = (a & b) ^ (a & c) ^ (b & c)  — ternarylogic 0xE8
#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx512f")]
unsafe fn maj(a: __m512i, b: __m512i, c: __m512i) -> __m512i {
    _mm512_ternarylogic_epi32(a, b, c, 0xE8)
}

/// Build the u32 byte-reversal shuffle mask ([3,2,1,0] within each 4-byte group)
///
/// Used for LE ↔ BE conversion; shared by `load_be_word_simd` and result extraction.
#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx512f", enable = "avx512bw")]
unsafe fn bswap_mask_epi32() -> __m512i {
    _mm512_set_epi8(
        12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11, 4, 5,
        6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8,
        9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3,
    )
}

/// Load 4 bytes from the given offset of all 16 inputs, convert big-endian to u32, and pack into __m512i.
///
/// Uses a SIMD byte shuffle instead of 16 scalar `u32::from_be_bytes` calls.
/// Note: `hash_40_x16` now uses `_mm512_i32gather_epi32`; this function is retained for testing.
#[cfg(all(test, target_arch = "x86_64"))]
#[inline]
#[target_feature(enable = "avx512f", enable = "avx512bw")]
unsafe fn load_be_word_simd(inputs: &[[u8; 40]; 16], offset: usize) -> __m512i {
    // Scalar-gather 16 LE u32s (x86 is always little-endian)
    let mut raw = [0u32; 16];
    for lane in 0..16 {
        raw[lane] = u32::from_le_bytes([
            inputs[lane][offset],
            inputs[lane][offset + 1],
            inputs[lane][offset + 2],
            inputs[lane][offset + 3],
        ]);
    }
    let v = _mm512_loadu_si512(raw.as_ptr() as *const __m512i);
    // SIMD byte-order reversal: LE → BE
    _mm512_shuffle_epi8(v, bswap_mask_epi32())
}

/// Precompute the W[5..9] constants (big-endian u32) corresponding to model + sector_val
///
/// Returns 5 u32 values for `hash_40_x16`, avoiding recomputation per batch.
#[cfg(test)]
fn precompute_constant_words(model_bytes: &[u8; 16], sv_bytes: &[u8; 4]) -> [u32; 5] {
    crate::sha256_backend::precompute_constant_words(model_bytes, sv_bytes)
}

/// Compute MikroTik custom SHA-256 on 16 groups of 40-byte inputs simultaneously.
///
/// Optimizations:
/// - W[0..4] uses `_mm512_i32gather_epi32` SIMD gather (replacing scalar loops)
/// - W[5..9] precomputed broadcast
/// - 16-element circular buffer fuses message schedule with compression (4KB → 1KB stack)
/// - bswap mask hoisted to function top for reuse
///
/// # Safety
///
/// The caller must ensure the CPU supports AVX-512F + AVX-512BW.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f", enable = "avx512bw")]
pub unsafe fn hash_40_x16(inputs: &[[u8; 40]; 16], const_w5_9: &[u32; 5]) -> SimdResult {
    // Shared bswap mask (L5: hoisted for reuse)
    let bswap = bswap_mask_epi32();

    // ---- Load message words W[0..15] into the circular buffer ----
    let mut w: [__m512i; 16] = [_mm512_setzero_si512(); 16];

    // W[0..4]: serial portion, SIMD gather + byte-order conversion (H3)
    let base_ptr = inputs.as_ptr() as *const u8;
    let stride_indices = _mm512_setr_epi32(
        0, 40, 80, 120, 160, 200, 240, 280, 320, 360, 400, 440, 480, 520, 560, 600,
    );
    for (word_idx, word) in w[..5].iter_mut().enumerate() {
        let offset_vec = _mm512_set1_epi32((word_idx * 4) as i32);
        let indices = _mm512_add_epi32(stride_indices, offset_vec);
        let gathered = _mm512_i32gather_epi32::<1>(indices, base_ptr as *const i32);
        *word = _mm512_shuffle_epi8(gathered, bswap);
    }

    // W[5..9]: constant broadcast
    for i in 0..5 {
        w[5 + i] = _mm512_set1_epi32(const_w5_9[i] as i32);
    }

    // W[10..15]: padding constants
    w[10] = _mm512_set1_epi32(0x80000000u32 as i32);
    // w[11..14] already zero-initialized
    w[15] = _mm512_set1_epi32(0x00000140);

    // ---- Initialize working variables (custom IV, broadcast to 16 lanes) ----
    let mut a = _mm512_set1_epi32(INITIAL_HASH_VALUES[0] as i32);
    let mut b = _mm512_set1_epi32(INITIAL_HASH_VALUES[1] as i32);
    let mut c = _mm512_set1_epi32(INITIAL_HASH_VALUES[2] as i32);
    let mut d = _mm512_set1_epi32(INITIAL_HASH_VALUES[3] as i32);
    let mut e = _mm512_set1_epi32(INITIAL_HASH_VALUES[4] as i32);
    let mut f = _mm512_set1_epi32(INITIAL_HASH_VALUES[5] as i32);
    let mut g = _mm512_set1_epi32(INITIAL_HASH_VALUES[6] as i32);
    let mut h = _mm512_set1_epi32(INITIAL_HASH_VALUES[7] as i32);

    // ---- Fused message schedule + 64 compression rounds (H4: circular buffer) ----
    for i in 0..64 {
        // i >= 16: compute W[i] in place, overwriting the consumed W[i-16]
        if i >= 16 {
            let s0 = small_sigma0(w[(i - 15) & 0xF]);
            let s1 = small_sigma1(w[(i - 2) & 0xF]);
            w[i & 0xF] = _mm512_add_epi32(
                _mm512_add_epi32(w[i & 0xF], s0),
                _mm512_add_epi32(w[(i - 7) & 0xF], s1),
            );
        }

        let sig1 = big_sigma1(e);
        let ch_val = ch(e, f, g);
        let ki = _mm512_set1_epi32(ROUND_CONSTANTS[i] as i32);
        let t1 = _mm512_add_epi32(
            _mm512_add_epi32(h, sig1),
            _mm512_add_epi32(_mm512_add_epi32(ch_val, ki), w[i & 0xF]),
        );

        let sig0 = big_sigma0(a);
        let maj_val = maj(a, b, c);
        let t2 = _mm512_add_epi32(sig0, maj_val);

        h = g;
        g = f;
        f = e;
        e = _mm512_add_epi32(d, t1);
        d = c;
        c = b;
        b = a;
        a = _mm512_add_epi32(t1, t2);
    }

    // ---- Add the initial vector (only a and b are needed) ----
    a = _mm512_add_epi32(a, _mm512_set1_epi32(INITIAL_HASH_VALUES[0] as i32));
    b = _mm512_add_epi32(b, _mm512_set1_epi32(INITIAL_HASH_VALUES[1] as i32));

    // ---- Extract results (SIMD byte reversal) ----
    let a_swapped = _mm512_shuffle_epi8(a, bswap);

    let mut sid_lo_vals = [0u32; 16];
    let mut b_vals = [0u32; 16];
    _mm512_storeu_si512(sid_lo_vals.as_mut_ptr() as *mut __m512i, a_swapped);
    _mm512_storeu_si512(b_vals.as_mut_ptr() as *mut __m512i, b);

    let mut result = SimdResult {
        sid_lo: sid_lo_vals,
        sid_hi: [0u8; 16],
    };

    for (sid_hi, b) in result.sid_hi.iter_mut().zip(b_vals) {
        *sid_hi = (b >> 24) as u8;
    }

    result
}

/// Runtime detection of AVX-512F + AVX-512BW support
pub fn is_avx512_supported() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512bw")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256_scalar;

    /// Verify that the SIMD version produces the same output as the scalar version
    #[test]
    fn test_simd_matches_scalar() {
        if !is_avx512_supported() {
            eprintln!("SKIP: AVX-512 not supported on this CPU");
            return;
        }

        let model = b"VMware Virtual I";
        let sv: u32 = 0x1800;
        let const_w = precompute_constant_words(model, &sv.to_le_bytes());

        let mut inputs = [[0x20u8; 40]; 16];
        let mut expected_lo = [0u32; 16];
        let mut expected_hi = [0u8; 16];

        for lane in 0..16 {
            let serial = format!("{:020}", lane);
            inputs[lane][..20].copy_from_slice(serial.as_bytes());
            inputs[lane][20..36].copy_from_slice(model);
            inputs[lane][36..40].copy_from_slice(&sv.to_le_bytes());

            let (lo, hi) =
                sha256_scalar::hash_40(<&[u8; 40]>::try_from(&inputs[lane][..]).unwrap());
            expected_lo[lane] = lo;
            expected_hi[lane] = hi;
        }

        let result = unsafe { hash_40_x16(&inputs, &const_w) };

        for lane in 0..16 {
            assert_eq!(
                result.sid_lo[lane], expected_lo[lane],
                "sid_lo mismatch at lane {}",
                lane
            );
            assert_eq!(
                result.sid_hi[lane], expected_hi[lane],
                "sid_hi mismatch at lane {}",
                lane
            );
        }
    }

    /// Verify the 6G VMware known value (lane 1 = serial "00000000000000000001")
    #[test]
    fn test_simd_6g_known() {
        if !is_avx512_supported() {
            eprintln!("SKIP: AVX-512 not supported on this CPU");
            return;
        }

        let model = b"VMware Virtual I";
        let sv_bytes = 0x1800u32.to_le_bytes();
        let const_w = precompute_constant_words(model, &sv_bytes);

        let mut inputs = [[0x20u8; 40]; 16];
        for (lane, input) in inputs.iter_mut().enumerate() {
            let serial = format!("{:020}", lane);
            input[..20].copy_from_slice(serial.as_bytes());
            input[20..36].copy_from_slice(model);
            input[36..40].copy_from_slice(&sv_bytes);
        }

        let result = unsafe { hash_40_x16(&inputs, &const_w) };
        assert_eq!(result.sid_lo[1], 0x0B49EC2E, "sid_lo mismatch for 6G");
        assert_eq!(result.sid_hi[1], 0x35, "sid_hi mismatch for 6G");
    }

    /// Verify SIMD byte-order conversion correctness
    #[test]
    fn test_load_be_word_simd() {
        if !is_avx512_supported() {
            eprintln!("SKIP: AVX-512 not supported on this CPU");
            return;
        }

        let mut inputs = [[0x20u8; 40]; 16];
        // Write known value [0x41, 0x42, 0x43, 0x44] = "ABCD" at lane 0 offset 0
        inputs[0][0] = 0x41;
        inputs[0][1] = 0x42;
        inputs[0][2] = 0x43;
        inputs[0][3] = 0x44;

        let result = unsafe { load_be_word_simd(&inputs, 0) };
        let mut vals = [0u32; 16];
        unsafe { _mm512_storeu_si512(vals.as_mut_ptr() as *mut __m512i, result) };

        // Big-endian "ABCD" = 0x41424344
        assert_eq!(vals[0], 0x41424344, "BE conversion mismatch");
    }
}

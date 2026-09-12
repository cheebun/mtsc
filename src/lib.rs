//! MikroTik SHA-256 calculation backends for fixed 40-byte inputs.

pub mod sha256;
#[cfg(target_arch = "aarch64")]
mod sha256_arm;
#[cfg(target_arch = "x86_64")]
mod sha256_avx2;
pub mod sha256_backend;
mod sha256_constants;
#[cfg(target_arch = "aarch64")]
mod sha256_cpu;
#[cfg(target_arch = "aarch64")]
mod sha256_neon;
#[cfg(target_arch = "x86_64")]
mod sha256_shani;
#[cfg(target_arch = "x86_64")]
mod sha256_simd;

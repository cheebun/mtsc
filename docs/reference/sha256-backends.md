# SHA-256 backends

The calculation library hashes the same 40-byte messages, with the same MikroTik
IV and K constants, as the original scalar and AVX-512 implementations. It is not
standard SHA-256 with standard constants. SOFTWARE ID encoding, target loading,
license conversion, and signature verification are unchanged.

## Kernels and batches

| Backend | Architecture | Messages per call | Required features |
|---|---|---:|---|
| Scalar | Portable | 1 | None |
| SHA-NI | x86_64 | 1, 2, 4 | SHA, SSSE3, SSE4.1; no AVX requirement |
| AVX2 | x86_64 | 8 | AVX2 plus OS vector-state support |
| AVX-512 | x86_64 | 16 | AVX-512F + AVX-512BW plus OS vector-state support |
| ARM SHA2 | aarch64 | 1, 2, 4 | NEON + SHA2 |
| NEON | aarch64 | 4 | NEON; no SHA2 or SME requirement |

SHA-NI/ARM SHA2 multi-buffer variants interleave independent hash states. They
are not successive blocks of one message. SHA instructions accept the custom IV
and round constants because those instructions implement round/schedule
operations, not the standard constant table.

AVX2 and NEON retain circular W[16] schedules. SHA-NI and ARM SHA2 use four
128-bit vectors for their circular W[16] schedules, with hardware message
expansion. AVX-512 retains its gather, byte-shuffle, ternary-logic, and circular
schedule implementation. All kernels reuse the shared suffix words W[5..9] and
fixed one-block padding. No SME is used.

## Dispatch and ownership

`HashEngine::supported()` checks CPU/OS support before constructing callable
engine values. Architecture-specific modules are excluded from other builds.
Unsafe intrinsic kernels remain private to the library; their required CPU
features are set per function rather than for the entire executable.

`HashEngine::auto_for_threads(threads)` performs scalar cross-checks, warms up
supported variants, and selects the highest median throughput from three short
calibration rounds using the requested concurrency. Each round rotates the order
of candidates. A `OnceLock` fixes the first selected engine for the process;
subsequent calls reuse it. `auto()` uses available logical parallelism. Search
calls `auto_for_threads` once before creating its permanent workers.

Calibration currently uses 10 ms warm-up and 3 × 30 ms per candidate, plus thread
startup and self-check overhead (typically around half a second for five
candidates). Temporary workers are all ready before timing starts. Failed thread
creation cancels/releases existing calibration workers instead of leaving them
blocked. CPU frequency, competing work, and scheduling can affect such a short
measurement: this is a startup heuristic, not a guarantee of the fastest
end-to-end search under all later loads. It measures hashing, not target lookup,
serial preparation, or console output.

`HashBatch` owns exactly the selected number of inputs and outputs. Its suffix
is initialized once, and only the 20-byte serial fields are mutable. This keeps
precomputed tail words consistent across every lane and backend. It allocates
only when constructed. `hash()` uses a validated function pointer without CPU
detection, dynamic backend matching, locks, calibration, or allocation.

The search loop uses backend-owned batch widths rather than assuming 16 lanes.
Candidate generation supports the default decimal alphabet and generic ordered
ASCII alphanumeric alphabets, with either left-symbol or right-space padding;
fixed-identity and full-`mbr_val` sweep modes share the selected hashing backend.
Every active result is checked and reported using its actual hashed serial.
Candidate indices are `u64`, and `--from` is measured in millions of candidates,
not individual MBR variants or the full mathematical `alphabet_len^20` space.
The benchmark's BCD workload remains a decimal preparation measurement, not a
benchmark of every alphabet/padding combination.

The existing scalar `hash_10`/short-digest operations and one-off `check` calls
remain scalar. This change targets the repeated fixed-40-byte calculation layer;
it does not change the algorithms or broaden the digest input-length contract.

## macOS generic CPU detection

On the tested M4/macOS 26.3.1, `hw.optional.AdvSIMD` is absent but
`hw.optional.neon`, `hw.optional.arm.FEAT_SHA1`, and
`hw.optional.arm.FEAT_SHA256` return `1`. Rust 1.94's Darwin runtime SHA2 detector
requires the first key and can therefore give a false negative in an explicit
`-C target-cpu=generic` build. The default Apple compilation target already
includes SHA2 and can mask this issue.

The cold detection layer first uses Rust's detector. On macOS only, it also
accepts positive SHA1 + SHA256 sysctls together with positive AdvSIMD or NEON.
Unknown keys, system-call errors, unexpected output sizes, and values other than
`1` never authorize a feature. This is a read-only capability query, not a CPU
model-name assumption. Linux and other AArch64 systems retain Rust's normal
detection path.

Reference: [Rust 1.94 Darwin AArch64 feature detection](https://github.com/rust-lang/rust/blob/1.94.0/library/std_detect/src/detect/os/darwin/aarch64.rs).

## Build and correctness tests

```bash
# Portable release build; each kernel has its own target_feature boundary
cargo build --release
cargo test
cargo test --release
cargo fmt --check
cargo clippy --lib -- -D warnings

# Explicit baseline AArch64 CPU: exercise runtime detection on the Mac
RUSTFLAGS='-C target-cpu=generic' CARGO_TARGET_DIR=target-generic cargo test --release

# Machine-local optimization only; do not distribute to older CPUs
RUSTFLAGS='-C target-cpu=native' cargo build --release
```

All supported engines are compared lane-by-lane with the original production
scalar and the independent backup scalar. Cases include the known 6G result,
random binary serials, decimal serials, varied model/sector tails, all-zero and
high-bit patterns, reused output storage, and output canaries. Unsupported
instruction sets are not executed. In particular, a test function reporting
`ok` after printing `SKIP` is not evidence of hardware validation.

## Reproducible benchmark

```bash
# Every supported backend, including hardware-SHA x1/x2/x4
cargo bench --bench hash_backends -- --threads 1 --seconds 1 --samples 5 --warmup 0.3

# Focus on 5800H SHA-NI vs AVX2
cargo bench --bench hash_backends -- --backend sha-ni --backend avx2 --threads 16 --seconds 1 --samples 5 --warmup 0.3

# Focus on M4 ARM SHA2 vs NEON
cargo bench --bench hash_backends -- --backend arm-sha2 --backend neon --threads 10 --seconds 1 --samples 5 --warmup 0.3

# Test an exact multi-buffer width
cargo bench --bench hash_backends -- --backend sha-ni --lanes 2 --threads 16

# Include BCD serial generation and thread stride, but not target lookup or I/O
cargo bench --bench hash_backends -- --mode serial --threads 16 --seconds 1 --samples 5 --warmup 0.3
```

The benchmark needs no key/license file. Unsupported explicitly requested
backends fail rather than silently falling back. `--lanes` selects an existing
specialization, not an arbitrary width. There is no throughput timing inside the
search hot path.

Every sample reports hashes/s, counting all active lanes. Each worker initializes
storage before a common start. Measurement lasts at least the requested duration;
the aggregate rate divides all completed hashes by the slowest worker's elapsed
time. Clock reads occur every 256 kernel calls, not every hash. Inputs and all
outputs cross `black_box` barriers to prevent elimination. Five rotating-order
samples report median/min/max; warm-up and self-check time are excluded.

`--mode hash` measures changing one input byte, actual batch dispatch, input
loading, compression, and output storage/observation. It is not an isolated
compression-instruction benchmark. `--mode serial` additionally includes the
search-style BCD preparation/stride, but excludes target matching, stop checks,
progress reporting, and license work. Neither number should be labeled full
application search throughput.

See the [measured 5800H and M4 performance summary](../benchmarks/README.md).
Generated logs and individual samples are not committed; rerun the benchmark
above to collect measurements on the current machine.

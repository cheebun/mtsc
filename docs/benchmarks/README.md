# SHA-256 backend performance

Measured on 2026-09-12 using a Ryzen 7 5800H workstation and an Apple M4 reached
through SSH. Results are **M hashes/s** (millions of hashes per second), medians
of five one-second samples after 0.3 seconds of warm-up per backend.

## Environment and method

- Ryzen 7 5800H: 8 cores / 16 logical processors, Windows x86_64 MSVC, existing
  High Performance power plan.
- Apple M4: 4 performance + 6 efficiency cores, macOS 26.3.1, AC power,
  low-power mode disabled.
- Both: Rust 1.94.0, LLVM 21.1.8, opt-level=3, LTO, default platform target;
  no `target-cpu=native`, fixed CPU frequency, affinity, or priority overrides.
- Forty-byte MikroTik SHA-256 input with a shared model/sector suffix. All
  active lanes are counted and outputs cross `black_box` barriers.
- Backend order rotates between samples; workers initialize before a common
  start, and timing checks occur every 256 calls.

`hash` includes dispatch, input loading, compression, output storage/observation,
and changing one serial byte. `serial` adds BCD serial preparation and the
search-style thread stride. Neither includes target lookup, stop checks,
progress output, or license work: these are **not full search throughput**.

## Ryzen 7 5800H

### Hash mode

| Backend | Batch | 1 worker | 8 workers | 16 workers |
|---|---:|---:|---:|---:|
| Scalar | 1 | 3.50 | 18.60 | 24.55 |
| SHA-NI | 1 | 19.30 | 110.84 | 153.75 |
| SHA-NI | 2 | 36.92 | 219.06 | **288.56** |
| SHA-NI | 4 | **39.22** | 219.60 | 283.16 |
| AVX2 | 8 | 21.85 | 120.85 | 151.07 |

### Serial preparation + hash

| Backend | Batch | 1 worker | 8 workers | 16 workers |
|---|---:|---:|---:|---:|
| Scalar | 1 | 3.24 | 17.22 | 21.76 |
| SHA-NI | 1 | 13.57 | 84.77 | 111.01 |
| SHA-NI | 2 | **21.81** | **108.56** | **130.25** |
| SHA-NI | 4 | 21.32 | 99.51 | 112.70 |
| AVX2 | 8 | 15.78 | 84.70 | 96.58 |

**Recommendation: SHA-NI multi-buffer.** Single-worker hash favors x4, about
1.80 times AVX2 x8; 16-worker hash favors x2, about 1.91 times AVX2 x8. Prefer
x2 for the measured serial-preparation workload. Eight-worker hash x2/x4 rates
are within 0.3%, not a meaningful winner. SHA-NI x1 is slower than AVX2 x8 in the
single-worker hash test, demonstrating why multi-buffer variants matter.

Windows results fluctuate on the running workstation. For example, 16-worker
serial-mode SHA-NI x2 ranged from 93.71 to 141.83 M/s, versus AVX2's 82.07 to
100.10 M/s. The median is not a guaranteed sustained rate.

## Apple M4

### Hash mode

| Backend | Batch | 1 worker | 4 workers | 10 workers |
|---|---:|---:|---:|---:|
| Scalar | 1 | 6.85 | 26.52 | 37.29 |
| ARM SHA2 | 1 | 70.71 | 252.86 | 263.83 |
| ARM SHA2 | 2 | **71.06** | **253.30** | 412.68 |
| ARM SHA2 | 4 | 70.80 | 252.44 | **460.96** |
| NEON | 4 | 16.37 | 61.89 | 111.11 |

### Serial preparation + hash

| Backend | Batch | 1 worker | 4 workers | 10 workers |
|---|---:|---:|---:|---:|
| Scalar | 1 | 6.47 | 24.69 | 33.27 |
| ARM SHA2 | 1 | 49.06 | 179.10 | 223.76 |
| ARM SHA2 | 2 | **55.77** | **208.52** | 250.11 |
| ARM SHA2 | 4 | 52.64 | 201.29 | **299.35** |
| NEON | 4 | 14.16 | 53.63 | 94.73 |

**Recommendation: ARM SHA2.** Single-worker SHA2 x2 is about 4.34 times NEON;
all ten cores favor SHA2 x4, about 4.15 times NEON in hash mode. Prefer x2 for
one/four-worker serial preparation and x4 for ten workers. SHA2 widths differ
by less than 0.6% for one-worker hashing, but ten-worker x4 measured
458.57–465.74 M/s versus x2's 408.87–435.10 M/s. No SME is used.

The four-worker result does not prove that all workers stayed on performance
cores. Heterogeneous-core scheduling is a reason to calibrate the actual worker
count rather than extrapolating from one core.

## Interpretation and verification

Startup selects the highest median in a short, thread-count-aware hash
calibration and caches the engine for the process. It consistently selected the
SHA-NI/ARM SHA2 families in these runs, but close hardware-SHA widths sometimes
changed order. It does not measure BCD preparation or target lookup and cannot
guarantee the best end-to-end search backend under every subsequent load.

- Windows debug/release: 84 test functions reported passing (19 library + 65
  CLI); three AVX-512 tests returned early because that CPU lacks AVX-512.
- Mac debug/release and explicit `target-cpu=generic` release: 85 tests passed
  (20 library + 65 CLI), including hardware execution of ARM SHA2 and NEON.
- Calculation-library Clippy with warnings denied and formatting checks passed
  on both hosts. Full-project Clippy retains unrelated preexisting warnings.
- AVX-512 remains compiled and has gated scalar-comparison tests, but no
  AVX-512-capable host was available for this measurement session. No AVX-512
  hardware performance or correctness claim is made.

Generated logs, individual samples, host inventories, temporary paths, and
lockfile snapshots are deliberately not stored in Git. The benchmark and unit
test source are retained so measurements can be reproduced.

## Reproduce

```bash
cargo bench --bench hash_backends -- --threads 1 --seconds 1 --samples 5 --warmup 0.3
cargo bench --bench hash_backends -- --backend sha-ni --backend avx2 --threads 16
cargo bench --bench hash_backends -- --backend arm-sha2 --backend neon --threads 10
cargo bench --bench hash_backends -- --mode serial --threads 16
```

See [backend design and test commands](../reference/sha256-backends.md).

# Historical SHA-256 backend performance

Measured on 2026-09-12 using a Ryzen 7 5800H workstation and an Apple M4 reached
through SSH. Results are **M hashes/s** (millions of hashes per second), medians
of five one-second samples after 0.3 seconds of warm-up per backend.

These are historical measurements. The standalone benchmark program used for
these runs is no longer included in the project.

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
single-worker hash measurement, demonstrating why multi-buffer variants matter.

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

- For these measurements, `HashEngine::self_check` compared supported engines
  with the production scalar implementation before calibration and timing.
- Calculation-library Clippy with warnings denied and formatting checks passed
  on both hosts. At measurement time, full-project Clippy still had unrelated
  preexisting warnings.
- AVX-512 remains compiled, but no AVX-512-capable host was available for this
  measurement session. No AVX-512 hardware performance or correctness claim
  is made.

Generated logs, individual samples, host inventories, temporary paths, and
lockfile snapshots are deliberately not stored in Git. The tables above preserve
the historical results, not a currently runnable benchmark suite.

See [current backend design and runtime verification](../reference/sha256-backends.md).

## Future optimization opportunities (not yet implemented)

Identified 2026-09-13 while reviewing PR #5's new SHA-256 backends. Neither item
below is about the hash function itself -- both are in the surrounding `search`
loop, which this doc's own tables explicitly exclude ("Neither includes target
lookup... not full search throughput", above). For the common case of running
`search` *without* `--identity` (full mbr_val-sweep mode, the default), these
likely matter more than which SHA-256 backend is selected:

1. **`sweep_check_match`'s per-candidate target scan is unvectorized scalar code
   and is the dominant cost in sweep mode, not the hash.** Every candidate (even
   ones produced 16-at-a-time by an AVX-512 hash batch) is checked against every
   loaded `keys.toml` target one at a time in a plain `for` loop
   (`required_mix`/`feasible_mbr_val`, both O(1) per target already -- see
   `src/targets.rs` -- but the O(num_targets) outer loop itself is not SIMD).
   Empirically, a real sweep-mode run against 1038 targets measured only
   ~2.1 M candidates/s even with the AVX-512 hash engine active -- far below
   what the hash alone can do (compare to the hash-only numbers above), because
   this scan dominates. `required_mix`'s XOR/combine and `feasible_mbr_val`'s
   64-bit multiply-and-compare are both vectorizable; batching either across
   multiple targets or across a whole 16-lane hash result before falling back
   to scalar per-hit confirmation is the most promising next step for sweep-mode
   throughput -- likely a bigger win than adding further hash backends, since
   fixed-`--identity` mode (which has a cheap O(1) `hi_lookup` pre-filter
   already) doesn't have this bottleneck at all.
2. **`increment_candidate`'s per-symbol carry step does an O(alphabet-length)
   linear `.position()` scan** to find a byte's index in the configured
   `--alphabet` (`src/main.rs`) -- cheap for the default 10-symbol alphabet, more
   noticeable for longer ones (e.g. the 36-symbol digit+letter alphabet). A
   precomputed 256-entry reverse lookup table (byte -> alphabet index, built
   once per `search` invocation, not per candidate) would make this O(1),
   mirroring the `sid_hi` lookup-table pattern already used elsewhere in this
   project. Not yet measured as a real bottleneck (a live A/B benchmark this
   session found no consistent difference between the default and a custom
   alphabet's overall throughput, likely because item 1 above dominates first),
   but it's a straightforward, low-risk fix if sweep-mode's cost is ever brought
   down enough for this to start showing up.

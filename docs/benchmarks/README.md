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
   this scan dominates.

   **Status (2026-09-13): investigated in depth via real `perf` profiling; not
   yet resolved.** Chronology, so the reasoning isn't re-derived from scratch:

   - Split `sweep_check_match` into a hot arithmetic-only scan pass and a cold
     MBR-lookup/verify/print pass that only runs for actual hits (previously
     interleaved in one loop), plus explicit `#[inline]` on
     `required_mix`/`feasible_mbr_val`. Correctness-preserving, zero
     regressions, but a live A/B (~2.0 M candidates/s before and after) showed
     **no measurable throughput improvement**.
   - **Real `perf record` profiling** (20s sweep run, real 1038-target
     `keys.toml`) explained why: **~75% of self-time is `required_mix`/
     `feasible_mbr_val`'s own arithmetic**, another **~16%** is slice-iterator/
     `Vec`-internal pointer bookkeeping immediately around that loop, and the
     **SHA-256 hash kernel is only ~2-3%** (AVX-512 x16 active). Confirmed via
     `objdump` that the scan loop is **not auto-vectorized** -- plain scalar
     GP-register instructions only, no `ymm`/`zmm`. Conclusion: further hash-
     backend work (more SIMD widths, etc.) cannot move sweep-mode throughput at
     all right now -- hashing was never the bottleneck. All effort belongs in
     the scan loop.
   - **Tried and reverted**: replaced the `.iter().enumerate()` loop with
     `mem::take`-owned-local-`Vec` plus `unsafe get_unchecked` indexing,
     targeting that ~16%. Re-profiled: the targeted cost (a slice-iterator
     pointer-equality check) dropped to ~0%, but an equivalent-or-larger cost
     reappeared as a loop-bound comparison plus `Vec`-pointer reads -- net
     effect was a wash, not an improvement. Reverted rather than keep `unsafe`
     code that adds review/maintenance cost for zero measured benefit.
   - **Considered and retracted: invert the scan into a `HashMap` lookup over
     the fixed 2048 `mbr_val` values** (since they map to a target-independent
     set of `(mix_lo, mix_hi)` pairs, decoupling per-candidate cost from
     `num_targets`). Retracted after estimating real costs from the profiling
     data: the current scan's arithmetic is pure-register ALU work at roughly
     ~0.36 ns/target (no memory latency, fully pipelined), while even a fast
     hash-map lookup costs on the order of 5-20 ns (hashing + probable cache
     miss on a scattered table). At 2048 lookups vs. 1038 arithmetic checks,
     this would very likely be a **~50x regression** at the current target
     count, not an improvement -- the break-even point is far higher than
     2048 targets (rough estimate: tens of thousands), not "once `keys.toml`
     exceeds 2048 entries" as originally guessed before real numbers were in
     hand. Not implemented.
   - **Two directions considered promising, neither attempted yet**:
     1. **SIMD across the candidate-lane axis, not the target axis**: a hash
        batch already produces N candidates' `(sid_lo, sid_hi)` together (16 for
        AVX-512) -- vectorize `required_mix`/`feasible_mbr_val` to check one
        target against all N already-batched candidates per SIMD op, instead of
        one candidate against all targets scalar-sequentially. Reuses existing
        batch layout (no target-array reshaping needed) at the cost of hand-
        written 64-bit-multiply-via-32-bit-halves intrinsics (no native 64x64
        multiply on AVX2/AVX-512 without IFMA), needing the same
        cross-validate-against-scalar rigor as the existing hash kernels before
        being trusted. A cheap sub-optimization noted for this path: the
        `candidate < 2048` rejection only needs the *high* bits of the 64-bit
        product, so a first-pass high-bits-only computation could skip the full
        multiply for the (overwhelming majority) rejected lanes.
     2. **SoA layout for `raw_targets`**: today's `tv_lo`/`tv_hi` are likely
        interleaved with `name`/`signature_hex` in one `RawTarget` struct --
        splitting the hot `tv_lo`/`tv_hi` fields into flat parallel arrays
        would shrink the scan's working set to ~1038 x 8 bytes (fits L1 cleanly)
        instead of touching whatever the full struct's stride is, and is close
        to a prerequisite for direction 1 above (SIMD wants contiguous,
        uniformly-typed data, not a strided/gather access pattern). Low risk,
        pure data-layout change, not yet attempted.
2. **`increment_candidate`'s per-symbol carry step does an O(alphabet-length)
   linear `.position()` scan** to find a byte's index in the (now fixed, base-36)
   `SEARCH_ALPHABET` (`src/main.rs`).

   **Status (2026-09-13): implemented.** Added `SEARCH_ALPHABET_REVERSE`, a
   compile-time-constructed 256-entry reverse lookup table (byte -> alphabet
   index), and a new `increment_search_candidate` fast path that uses it --
   O(1) per digit instead of scanning up to 36 entries. The generic
   `increment_candidate(buf, alphabet)` function is kept as-is (still used by
   this project's own tests against arbitrary alphabets) and now serves as the
   reference implementation the fast path is cross-validated against
   (`test_increment_search_candidate_matches_generic`, 200,000 consecutive
   steps, plus an explicit all-`Z` overflow-wrap test and a reverse-table
   correctness test). Not yet isolated in a benchmark -- item 1 above still
   likely dominates total scan cost, so this alone may not move overall
   throughput until item 1 is resolved.

# AGENTS.md

Machine-executable rules for all AI tools working on this Rust project.

## Project

`ros-serialgen` — RouterOS serial generator + key conversion CLI tool. Computes serials from an existing license (any level, L1-L6 -- the SOFTWARE ID computation and collision-search process don't depend on `nlevel`) via SOFTWARE ID collision search; custom model strings supported.

## Architecture

```
src/
├── main.rs              CLI entry (clap subcommands) + multi-threaded search logic + tests
├── sha256_constants.rs  Shared constants (ROUND_CONSTANTS + INITIAL_HASH_VALUES)
├── sha256.rs            MikroTik custom SHA-256 (scalar, production) + arbitrary-length digest
├── sha256_scalar.rs     Scalar SHA-256 backup (#[cfg(test)], for cross-validation)
├── sha256_simd.rs       AVX-512 SIMD 16-way parallel SHA-256
├── software_id.rs       Base-35 encode/decode + sector_val rounding
├── targets.rs           Load collision targets from keys.toml
├── convert.rs           signature_hex ↔ Key text conversion (MTBase64) + metadata decode
└── curve25519.rs        EC-KCDSA local license verification (curve25519-dalek-based, §8.32)

keys.toml                External key configuration (loaded at runtime, no recompile needed)
```

## Commands

```bash
# Search for collisions
ros-serialgen search --disk-size <N> --unit <g|m|k|b> --threads <threads> [--count <count>] [--from <from_M>] [--model <model>] [--keys <keys.toml>] [--identity <identity_hex>] [--bus <ide|scsi>]
  --disk-size  Disk size magnitude, paired with --unit
  --unit       Unit: g (gigabytes, default), m (megabytes), k (kilobytes), b (bytes) -- min size is 64M in any unit
  --threads    Thread count
  --count      Collision count (default 1, 0 = unlimited collection)
  --from       Resume from N million hashes (matches the M value in progress output)
  --model      Custom Model (default ROS<N><unit>, e.g. ROS100G, ROS128M)
  --keys       Specify keys.toml path
  --identity   Non-standard 20-hex-char MBR identity (0x100-0x109); default is the standard all-zero identity
  --bus        Disk bus: ide (default, covers ide0/sata0) or scsi (scsi0/virtio-scsi-pci)

# Verify a serial
ros-serialgen check --serial <value> --disk-size <N> --unit <g|m|k|b> [--model <model>] [--keys <keys.toml>] [--identity <identity_hex>] [--bus <ide|scsi>] [--license <license.key>]
  --license    Compare a .key file's (or raw signature_hex file's) embedded SOFTWARE ID against the one computed above

# Conversion (also prints SOFTWARE-ID/VERSION/LEVEL/NONCE-HASH/SIGNATURE/LICENSE-VALID metadata to stderr)
ros-serialgen sig2key <128-char-hex>     # signature → Key text
ros-serialgen key2sig <file.key>         # Key text → signature

# Algorithm self-check
ros-serialgen verify

# Shell completion (bash/zsh/fish/powershell/elvish)
ros-serialgen completions <shell>
```

## Build

```bash
RUSTFLAGS='-C target-cpu=native' cargo build --release   # AVX-512 optimal
cargo test          # 66+ unit tests (grows with new features -- see `cargo test` output for the exact count)
cargo clippy        # a handful of pre-existing lints (too-many-arguments on CLI-plumbing functions, etc.); no new categories from recent changes
cargo fmt --check   # format check
```

## Documentation Style

- Command-line examples in `docs/` and `AGENTS.md` use **long-form flags** (`--disk-size`, not `-s`) for readability -- short flags are fine in interactive/muscle-memory use but obscure meaning for a reader seeing the command cold.

## Private Data Handling

`keys.toml` is gitignored (never reaches the public repo), but chat/tool-output transcripts are a
separate leak surface. Entries marked `private = true` in `keys.toml` are under an explicit
disclosure restriction from the user (currently: the 99 real-hardware CCR1009 licenses imported
2026-09-07, plus `WUB2-EYCK`, `HCC0-4FJR`, `XU4M-NJ40`):

- Never paste their `identity`, `model`, `serial`, or `signature_hex` field values into a chat
  response or tool-call diff (Edit old_string/new_string included) — refer to them only by
  `software_id`.
- Entries **without** `private = true` are not covered by this restriction and may be discussed/
  quoted normally (as has been done throughout this project's docs/investigation notes).
- When adding a new `[[key]]` entry sourced from the user's own private license inventory (as
  opposed to a publicly-documented forum post etc.), default to `private = true` and follow the
  same non-disclosure handling above unless the user says otherwise.

## Code Rules

- Single source of constants: `sha256_constants.rs`, shared by all three SHA-256 implementations
- Consistent naming: `sid_lo`/`sid_hi` (not hash_lo/d4), `max_collisions` (not target_count)
- All public functions must have `///` doc comments
- SHA-256 implementations must annotate the reason for byte-order conversions
- New collision targets go into keys.toml configuration, never hardcoded in source
- No built-in default targets -- `load_targets` exits with an error if keys.toml is missing or empty
- Search results must self-verify (recompute the full SOFTWARE ID and print it)
- `decode()` returns `Result`, errors on invalid characters
- Production code must not use `assert!` (use `eprintln!` + `process::exit` instead)
- `cargo clippy` zero warnings (except `dead_code`)
- `cargo fmt` unified formatting

## Key Constants

```
MBR mix (10-zeros): mbr_val = 0x0BD, mix = 0x0BD × 0x3FF800F
SHA-256 IV: [0x5B653932, 0x7B145F8F, 0x71FFB291, 0x38EF925F, ...]
Base-35 table: "TN0BYX18S5HZ4IA67DGF3LPCJQRUK9MW2VE"
```

## SIMD Optimizations

- `_mm512_i32gather_epi32` replaces 16 scalar gathers (W[0..4] loading)
- Circular buffer W[16] fuses message schedule with compression (4KB→1KB stack)
- `_mm512_ternarylogic_epi32` single-instruction Ch(0xCA)/Maj(0xE8)
- `_mm512_shuffle_epi8` SIMD byte-order conversion
- bswap mask hoisted to function top for reuse
- BCD incremental counter + W[5..9] precomputation
- sid_hi lookup pre-filter (256-byte lookup table)

## Testing

- `sha256::tests::test_6g_known_hash` — 6G VMware known hash value
- `sha256_simd::tests::test_simd_matches_scalar` — SIMD vs scalar cross-validation
- `sha256_simd::tests::test_simd_6g_known` — SIMD 6G known value
- `software_id::tests::test_encode_decode_roundtrip` — encode/decode roundtrip
- `software_id::tests::test_decode_invalid_char` — invalid character error
- `software_id::tests::test_round_sectors` — 5 rounding verification cases
- `convert::tests::test_roundtrip_synthetic` — sig ↔ key conversion verification
- `main::tests` — disk size parsing/validation, write_serial, BCD, software_id, model, input_buf, check_match, E2E, identity parsing/mix resolution
- `targets::tests` — 3 tests covering `mix_from_identity` (matches standard for all-zero, deterministic, differs for non-zero)
- `curve25519::tests` — EC-KCDSA verify against `TI09-7WK3`'s real, hardware-activation-confirmed
  signature (must return `true`), plus rejection tests for a tampered signature/payload/wrong
  public key (must return `false`) -- see `docs/investigation/license-internals.md` §8.32

## Dependencies

- `clap` 4.x — CLI framework (derive mode)
- `clap_complete` 4.x — shell completion script generation (`completions` subcommand)
- `curve25519-dalek` 4.x — audited Curve25519 field/point arithmetic for EC-KCDSA local license
  verification (`LICENSE-VALID` output); see `docs/investigation/license-internals.md` §8.32 for why this one
  isn't hand-implemented
- SHA-256 and MTBase64 are hand-implemented (MikroTik-proprietary variants, no library
  equivalent exists to depend on)

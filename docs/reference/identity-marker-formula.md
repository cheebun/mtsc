# Identity → Marker Relationship

How the MBR `marker` bytes (`0x10A-0x10B`) are derived from the `identity` bytes (`0x100-0x109`) -- they are not an independent, freely-choosable field. Confirmed this session via ARM32 `keyman` disassembly (`docs/license-internals.md` §8.39) plus real-hardware-captured data (`docs/mbr-data.md`).

## Background

The 80-byte MBR license region breaks down as:

| Offset | Length | Field | Previously assumed |
|---|---|---|---|
| `0x100-0x109` | 10 bytes | `identity` | Free/writable seed, feeds `mix_from_identity()` |
| `0x10A-0x10B` | 2 bytes | `marker` | "Standard" constant `BD E8`, cosmetic/decorative |
| `0x10C-0x10F` | 4 bytes | reserved | Always `00000000` |
| `0x110-0x14F` | 64 bytes | signature | The EC-KCDSA-signed license blob |

This project's own collision search (`mtsc search`/`check -i`) always assumes the standard all-zero `identity`, which happens to produce `mbr_val = 0x0BD` and is written with the marker `BD E8`. Real hardware devices ship with non-zero `identity` bytes, and -- as this document establishes -- a **matching, non-standard `marker`** that is not `BD E8`.

## The formula

`targets.rs`'s existing `mix_from_identity()` (validated against `keyman`'s `0x17094`-equivalent function on both x86 and ARM32, see `docs/license-internals.md` §3.6 and §8.39) computes:

```text
sha_val  = MikroTik_SHA256(identity)[0:2] as LE u16
chksum   = NOT(sum of 5 LE u16 words of identity) & 0xFFFF
raw16    = sha_val XOR chksum                      <-- NEW: this is the marker
mbr_val  = raw16 & 0x7FF                            <-- existing: this is the mix input
mix      = mbr_val * 0x3FF800F
```

**The key correction this document adds**: `mix_from_identity()` already computes `raw16` internally as an intermediate step, then discards the upper 5 bits via `& 0x7FF` to get `mbr_val`. That discarded, *full* 16-bit `raw16` value -- not `mbr_val` -- is exactly the 2-byte `marker`, written little-endian:

```text
marker = raw16.to_bytes(2, 'little')
```

This is why the "standard" marker is `BD E8`: for an all-zero `identity`, `raw16 = 0xE8BD`, and `0xE8BD & 0x7FF = 0x0BD` -- both the familiar `mbr_val = 0x0BD` *and* the familiar `marker = BD E8` fall out of the exact same computation, on the exact same input. They were never two independent constants; `BD E8` just happens to be what this formula produces for the identity value (`0`) this project has always used.

## Reference implementation (Python, self-contained)

```python
def raw16_and_marker(identity: bytes) -> tuple[int, int, bytes]:
    """identity: exactly 10 bytes (0x100-0x109). Returns (raw16, mbr_val, marker_bytes)."""
    assert len(identity) == 10
    sha_val = mikro_sha256_10(identity)          # first 2 digest bytes, LE u16 -- see sha256.rs::hash_10
    s = 0
    for i in range(0, 10, 2):
        s = (s + (identity[i] | (identity[i + 1] << 8))) & 0xFFFF
    chksum = (~s) & 0xFFFF
    raw16 = sha_val ^ chksum
    mbr_val = raw16 & 0x7FF
    marker = raw16.to_bytes(2, "little")
    return raw16, mbr_val, marker
```

(`mikro_sha256_10` is `sha256.rs`'s `hash_10`: MikroTik-custom-SHA-256 over exactly the 10 `identity` bytes, first 2 output bytes read as a little-endian `u16` -- same convention as `sid_lo`'s byte order.)

## Verification against real data

Tested against every `identity` value currently on record in this project (`docs/mbr-data.md`'s real-hardware captures, plus this project's own standard/all-zero convention):

| Source | `identity` (hex) | Predicted `marker` | Recorded `marker` | Match |
|---|---|---|---|---|
| Standard (all-zero) convention | `00000000000000000000` | `BDE8` | `BDE8` | ✅ |
| `ER1G-WVEL` real device | `3836311F7DD5092F2175` | `D353` | `D353` | ✅ |
| `ZJ3M-ESHW` real device | `32836785814746803233` | `7508` | `7508` | ✅ |

[Two additional real-device rows for `WUB2-EYCK` and `HCC0-4FJR` have been removed per project policy -- see `AGENTS.md`.]

**All 3 of 3** remaining independent, real-world `identity` values reproduce their `marker` **exactly**, byte for byte, ruling out coincidence.

## Reverse direction: many identities share one marker, and they're interchangeable

`marker` is a pure function of `identity` (one `identity` -> exactly one `marker`, deterministic). The reverse is a many-to-one relationship: `identity` is 80 bits, `marker` is 16 bits, so by pigeonhole an average of `2^80 / 2^16 = 2^64` distinct identities produce any given `marker` value -- enumerable in bulk (fix any 8 bytes, brute-force the remaining 2 -- about a 1-in-65536 hit rate, found via direct search, no cryptanalysis needed), just not exhaustible.

**Confirmed by real activation that this many-to-one relationship is a genuine functional equivalence, not just a numerical curiosity.** A freshly brute-forced identity, `71D23394F556B718AEA0` -- sharing no bytes in common with the standard all-zero identity, found purely by searching for `raw16 = 0xE8BD` -- was written (with `marker=BDE8`) alongside `TI09-7WK3`'s own collision-search-derived serial/model (`00000000251582663387` / `SSD1G`, standard-identity convention, `docs/collision-database.md`) onto a fresh RouterOS 7.23.2 install (PVE VM 303, `ide0`). Result: `software-id: TI09-7WK3`, `nlevel: 6` -- identical to what the standard all-zero identity produces for the same serial/model/size, even though the two identities are byte-for-byte unrelated. This is the necessary consequence of `mix` depending only on `raw16 & 0x7FF`, not on `identity` itself -- confirmed empirically, not just derived on paper.

(Two earlier attempts at this same experiment gave misleading negative results, both from test-setup mistakes rather than the formula: reusing `TI09-7WK3`'s own real-device identity/marker from `docs/mbr-data.md` -- which is itself non-standard, not the all-zero convention -- as if it were "the standard case"; and shrinking an already-installed 42G qcow2 disk down to 1G, which corrupts the filesystem rather than testing anything about identity/marker. Neither is evidence against the formula; both are logged here so the same mistakes aren't repeated.)

## Implemented

`targets::marker_from_identity(identity: &[u8; 10]) -> [u8; 2]` (`src/targets.rs`) computes the marker from an identity, sharing its `raw16` derivation with `mix_from_identity()` via a private `raw16_from_identity()` helper -- the two are now guaranteed consistent by construction, not just by convention. `cmd_check`'s `MBR HEX` output (`src/main.rs`) uses this automatically whenever `-i`/`--identity` is a non-standard identity, replacing the old hardcoded `BDE800000000` and the "supply your own marker" warning with the actually-derived marker. Covered by 4 unit tests in `targets.rs` (standard all-zero case, all 4 real `mbr-data.md` captures, and a consistency check against `mix_from_identity`'s `mbr_val` for arbitrary identities) -- `cargo test` 70/70 passing.

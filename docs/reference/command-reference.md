# Command Reference

Every `mtsc` subcommand and flag, explained. Use this when you need to know exactly what a parameter does before running it.

For PVE/QEMU deployment commands (`qm`, `qemu-img`, `qemu-nbd`, `dd`, `lvcreate`, etc.), see the inline explanations in [deployment-guide.md](../guides/x86-install.md).

---

## `mtsc search`

```bash
mtsc search --disk-size 100 --unit g --threads 16 --count 0 --keys keys.toml
mtsc search --disk-size 128 --unit m --threads 16 --count 0 --keys keys.toml
```

| Flag | Long form | Meaning |
|---|---|---|
| `-s <N>` | `--disk-size <N>` | Disk size magnitude, paired with `-u`/`--unit`. Determines `sector_val` -- must match the disk you'll actually create. **Required.** |
| `-u <unit>` | `--unit <unit>` | Unit for `-s`: `g` (gigabytes, default), `m` (megabytes), `k` (kilobytes), or `b` (raw bytes). Case-insensitive. |
| `-t <N>` | `--threads <N>` | Number of search threads. Defaults to all available CPU cores if omitted. |
| `-m <name>` | `--model <name>` | Disk model string to search under. Defaults to `ROS<N><unit>` (e.g. `ROS100G`, `ROS128M`) if omitted. |
| `-k <path>` | `--keys <path>` | Path to `keys.toml`. Defaults to `./keys.toml` if omitted. |
| `-c <N>` | `--count <N>` | Number of collisions to find before stopping. `1` (default) stops at the first hit; `0` runs until interrupted (Ctrl+C), collecting every hit. |
| `-f <N>` | `--from <N>` | Resume the search from N million hashes in, matching the `M` value printed in progress output. Defaults to `0` (start from the beginning). |
| `-i <hex>` | `--identity <hex>` | Non-standard 20-hex-char MBR identity seed (`0x100-0x109`), e.g. captured from a real device. Defaults to the standard all-zero identity used by collision search if omitted. See [license-internals.md](../investigation/license-internals.md#36-marker-and-reserved-generated-from-identity-not-just-checked) for what this changes and why. |
| `-b <bus>` | `--bus <bus>` | Disk bus type: `ide` (default, verified against real hardware -- covers both `ide0` and `sata0`/AHCI, which use the identical encoding, §8.20) or `scsi` (`scsi0`/`virtio-scsi-pci` specifically -- forces `sector_val=0`; does **not** apply to `sata0`). See [license-internals.md §8](../investigation/license-internals.md#8-arm32-keyman-on-virtio-scsi-a-platform-specific-investigation) -- `scsi` mode's SOFTWARE ID computation and full end-to-end activation are both confirmed on x86_64 (§8.14, §8.18); on ARM64 a separate virtualization-detection issue can still prevent activation (§8.15-8.17). |

### Minimum disk size per unit

Each unit has a separate minimum, all equivalent to 64 MB, enforced at startup (the process exits with an error if violated):

| Unit | Minimum `-s` value |
|---|---|
| `g` | `1` (1 GB) |
| `m` | `64` (64 MB) |
| `k` | `65536` (64 MB in KB) |
| `b` | `67108864` (64 MB in bytes) |

Decimal sizes are not supported (`-s` is an integer) -- fractional GB values must be expressed in a smaller unit instead, e.g. `-s 1536 --unit m` for 1.5 GB. This avoids floating-point rounding errors in the byte-exact `sector_val` calculation.

Progress is logged every 10,000M (10 billion) hashes, e.g. `10000M hashes, 5s, 0 found`. At ~2000M hash/s (AVX-512) that's roughly every 5 seconds; at ~100M hash/s (scalar) roughly every 100 seconds.

## `mtsc check`

```bash
mtsc check --serial 00000000090681934458 --disk-size 24 --unit g --model cheerlon
```

| Flag | Long form | Meaning |
|---|---|---|
| `--serial <value>` | -- | The serial number to verify. **Required.** No short form (`-s` is reserved for disk size). Pure-digit serials are left-padded with `0` to 20 characters automatically (`--serial 1` == `--serial 00000000000000000001`), so leading zeros can be omitted; alphanumeric serials are used as-is (right-padded with spaces internally, not zeros). |
| `-s <N>` | `--disk-size <N>` | Disk size magnitude, paired with `-u`/`--unit`. **Required.** |
| `-u <unit>` | `--unit <unit>` | Unit for `-s`: `g` (gigabytes, default), `m` (megabytes), `k` (kilobytes), or `b` (raw bytes). Same minimums as `search` above. |
| `-m <name>` | `--model <name>` | Disk model string. Defaults to `ROS<N><unit>` if omitted. |
| `-k <path>` | `--keys <path>` | Path to `keys.toml`. Defaults to `./keys.toml` if omitted. |
| `-i <hex>` | `--identity <hex>` | Non-standard 20-hex-char MBR identity seed. Same meaning as `search`'s `-i` above. |
| `-b <bus>` | `--bus <bus>` | Disk bus type: `ide` (default) or `scsi`. Same meaning and caveats as `search`'s `-b` above. |

Prints the computed SOFTWARE ID, and if it matches a known signature, the License Key and MBR hex. When `-i` is given, the printed MBR hex uses that identity instead of the standard all-zero header -- but still assumes standard `BDE800000000` for marker/reserved, which is only correct if you know that's what the source device actually used (see the note above). The `keys.toml` match lookup (`✅ Matched signature: ...`) correctly accounts for `-i`'s mix when comparing.

## `mtsc sig2key <signature_hex>`

Positional argument: a 128-character hex string (64 bytes) -- the signature from the [Signature Table](../database/collision-database.md#signature-table). Prints the corresponding `-----BEGIN MIKROTIK SOFTWARE KEY-----...` block to stdout.

Also prints `SOFTWARE-ID`/`VERSION`/`LEVEL` to **stderr** (so stdout stays exactly the key text, safe to redirect or copy/paste as-is) -- decrypted from the signature's first 16 bytes, confirming what SOFTWARE ID and license level this signature actually corresponds to. See [license-internals.md §8.21](../investigation/license-internals.md#821-signature-metadata-decryption-mt_transform) for how this works.

## `mtsc key2sig <key_file>`

Positional argument: path to a `.key` file containing MikroTik key text. Prints the 128-character signature hex to stdout, and the same `SOFTWARE-ID`/`VERSION`/`LEVEL` metadata to stderr as `sig2key` above.

## `mtsc verify`

```bash
mtsc verify
```

No arguments, no `keys.toml` needed -- this is a self-contained sanity check, unrelated to real signatures or collision search.

Runs the full SOFTWARE ID pipeline (custom SHA-256 -> MBR mix XOR -> Base-35 encode) against two fixed, hardcoded (serial, model, sector_val) test vectors, then checks that the result round-trips correctly through `encode -> decode -> re-encode`. Also prints which hash engine is active (`AVX-512 x16` or `scalar`), so you can confirm SIMD acceleration is being used on the current machine.

Run this once after building, or after moving to a different machine/CPU, before trusting `search` output.

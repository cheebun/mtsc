# VMware Virtual IDE Hard Drive Collision Database

Collision results for model `"VMware Virtual IDE Hard Drive"` — PVE's **default** `ide0` model string when no custom `model=` is set. Truncates to 16 bytes for hashing (`VMware Virtual I`), so it is **not interchangeable** with any other model string, including the SATA default (see [vmware-sata-collision-database.md](vmware-sata-collision-database.md)). All entries use `--bus ide`.

---

| model | serial | size (MB/GB) | size (bytes) | software-id | identity | marker | verified |
|---|---|---|---|---|---|---|---|
| VMware Virtual IDE Hard Drive | `1` | 60M | `62914560` | ZJ3M-ESHW | `32836785814746803233` | `7508` | Y |
| VMware Virtual IDE Hard Drive | `1` | 2G | `2147483648` | ER1G-WVEL | `3836311F7DD5092F2175` | `D353` | Y |
| VMware Virtual IDE Hard Drive | `1` | 6G | `6442450944` | TI09-7WK3 | `00000000000000000000` | `BDE8` | Y |

Serial `1` (i.e. `00000000000000000001` — leading zeros are optional, `ros-serialgen check` left-pads pure-digit serials automatically) is PVE's default `serial=` value when none is set — the 6G row (standard identity) is the "do nothing, just create a default `ide0` disk" collision.

Each hit above was found by a full sweep of all 2048 possible `mbr_val` values against every current `keys.toml` target (116 targets), cross-validated by two independent algorithms -- brute-force sweep and direct feasibility check -- agreeing. The 60M row (`62,914,560` bytes) is below `ros-serialgen check`'s CLI-enforced 64M floor (the underlying hash computation has no such limit); computed directly against the compiled hash/sector_val functions.

Also swept with no collision found (same method, `--bus ide`): 128M, 256M, 512M, 1G, 4G, 8G, 10G, 12G, 16G, 18G, 20G, 24G, 32G, 48G, 64G.

`--bus scsi` forces `sector_val` to `0` regardless of disk size (see `docs/license-internals.md` §8.11-8.20), so its SOFTWARE ID is identical across every size tested; a single full 2048-`mbr_val` sweep confirms **no** collision against any current target on `--bus scsi`, at any size, under any identity.

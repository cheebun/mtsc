# VMware Virtual SATA Hard Drive Collision Database

Collision results for model `"VMware Virtual SATA Hard Drive"` — PVE's **default** `sata0` model string when no custom `model=` is set. Truncates to 16 bytes for hashing (`VMware Virtual S`), so it is **not interchangeable** with the IDE default (see [vmware-ide-collision-database.md](vmware-ide-collision-database.md)) even though `sata0` and `ide0` otherwise share the same SOFTWARE ID encoding — the truncated model bytes differ.

---

| model | serial | size (MB/GB) | size (bytes) | software-id | identity | marker | verified |
|---|---|---|---|---|---|---|---|
| VMware Virtual SATA Hard Drive | `1` | — | — | — (no collision) | — | — | Y |

Swept (both `--bus ide` and `--bus scsi`, full 2048-`mbr_val` sweep against all 116 `keys.toml` targets, cross-validated by two independent algorithms -- brute-force sweep and direct feasibility check -- agreeing): 60M, 128M, 256M, 512M, 1G, 2G, 4G, 6G, 8G, 10G, 12G, 16G, 18G, 20G, 24G, 32G, 48G, 64G. **No collision found at any size, on either bus, under any identity.**

The 60M row (`62,914,560` bytes) is below `ros-serialgen check`'s CLI-enforced 64M floor (the underlying hash computation has no such limit); computed directly against the compiled hash/sector_val functions.

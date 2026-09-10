# scsi0 (virtio-scsi-pci) Collision Database

`scsi0` uses a different SOFTWARE ID encoding than `ide0`/`sata0` (`sector_val` forced to `0`, disk size irrelevant) — see [license-internals.md §8](../investigation/license-internals.md#8-arm32-keyman-on-virtio-scsi-a-platform-specific-investigation). Not interchangeable with [collision-database.md](collision-database.md). Standard identity (`00000000000000000000`), marker `BDE8`, for every row below.

---

## Verified Collisions

| Model | Serial | SOFTWARE ID | Verified |
|---|---|---|---|
| `SSD1G` | `00000000430480281048` | C7CU-PGT9 | Y (x86_64) |
| `SSD1G` | `00000000497177721400` | G353-EXPG | SOFTWARE ID only (ARM64) |

## Search Seeds — model `RouterOS-SCSI`, 1G

```
mtsc search --bus scsi --disk-size 1 --unit g --threads 4 --count 0 --model RouterOS-SCSI
```

| Software ID | Serial |
|---|---|
| `G353-EXPG` | `00000000732771898506` |
| `G353-EXPG` | `00000000116343066768` |
| `ZJ3M-ESHW` | `00000000218936537727` |
| `ZJ3M-ESHW` | `00000000561637839619` |
| `TI09-7WK3` | `00000000207553959629` |
| `TI09-7WK3` | `00000002449708160223` |
| `ER1G-WVEL` | `00000000226304717975` |
| `ER1G-WVEL` | `00000005712982986483` |
| `J1WN-449W` | `00000001962189391819` |
| `J1WN-449W` | `00000006133223718227` |
| `C7CU-PGT9` | `00000000653876263836` |
| `C7CU-PGT9` | `00000003339795897629` |
| `VI8Q-E90F` | `00000002115358196563` |
| `VI8Q-E90F` | `00000003775015766362` |
| `4MZF-SFTR` | `00000002537190172372` |
| `4MZF-SFTR` | `00000001235997288334` |
| `HHJH-UFWL` | `00000001503494363320` |
| `HHJH-UFWL` | `00000003371916148532` |

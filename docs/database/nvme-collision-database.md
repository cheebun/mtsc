# NVMe Collision Database

Collision results for model `"QEMU NVMe Ctrl"`. Standard identity (`00000000000000000000`), marker `BDE8`, unless noted otherwise. Confirmed the same results activate on real NVMe hardware presenting this model string, not just IDE-bus VMs.

**Model is fixed, not a search parameter for this bus.** PVE does not expose a way to set a custom `model=` string for `virtio-nvme`/NVMe disks (unlike `ide0`/`scsi0`, where `qm set` accepts `model=`) — every NVMe disk PVE creates reports the QEMU-hardcoded string `QEMU NVMe Ctrl`. So for NVMe, only the **serial** is searchable; the model above is the only one that will ever apply on PVE.

---

## 1G

The command below explicitly preserves the table's zero-padded/all-zero-identity convention. `--bus nvme` uses the same rounding as the former `--bus ide` command. Default searches without `--identity`/`--pad` produce sweep results whose own identity/marker and serial padding must be preserved.

```
mtsc search --bus nvme --size 1 --unit g --threads 4 --count 0 --model 'QEMU NVMe Ctrl' --identity 00000000000000000000 --pad start
```

| Software ID | Serial |
|---|---|
| `VI8Q-E90F` | `00000006802717902310` |
| `VI8Q-E90F` | `00000000041736642193` |
| `HHJH-UFWL` | `00000001262187908137` |
| `HHJH-UFWL` | `00000001087767787445` |
| `4MZF-SFTR` | `00000007102386261129` |
| `4MZF-SFTR` | `00000000493301561156` |
| `ZJ3M-ESHW` | `00000000347997818233` |
| `ZJ3M-ESHW` | `00000000409308376516` |
| `TI09-7WK3` | `00000000311569085001` |
| `TI09-7WK3` | `00000000949585446218` |
| `G353-EXPG` | `00000000161033372282` |
| `G353-EXPG` | `00000000041827153346` |
| `ER1G-WVEL` | `00000002857256357983` |
| `ER1G-WVEL` | `00000005889160662890` |
| `C7CU-PGT9` | `00000007687693126209` |
| `C7CU-PGT9` | `00000001351598754779` |

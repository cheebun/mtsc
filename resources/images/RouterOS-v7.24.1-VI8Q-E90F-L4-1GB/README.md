# VI8Q-E90F (Level 4) — rebuilt verification VM (RouterOS 7.24.1)

PVE VM 107, built from scratch (fresh RouterOS 7.24.1 install, then MBR-patched) to reproduce the
`VI8Q-E90F` / Level 4 real-hardware signature documented in `RouterOS-v6.49.13-VI8Q-E90F-L4-1GB/`.
Not the original real device — that ran RouterOS 6.49.13.

## Files

| File | Size | What it is |
|---|---|---|
| `RouterOS-v7.24.1-VI8Q-E90F-L4-1GB.vma` | 26,172,416 bytes | Proxmox `vzdump` backup (plain `.vma`), `ide0` + `efidisk0`. Restore with `qmrestore`. |

## Scheme

```
Model: QEMU HARDDISK
Serial: QM00001
Size: 1,071,645,184 bytes
-----
Software ID: VI8Q-E90F
License level: 4
Router OS version: 7.24.1
-----
Identity (0x100-0x109): 50508089413009661362
Marker (0x10A-0x10B): 0362
Reserved (0x10C-0x10F): 00000000
Signature (0x110-0x14F): 499cb95a702360e33097972ea9bb12802d8a688393d21505a80817ee4192de00c390add584a873cc729a032207d36c4ac13816bb821760a523e76eb0e3ed8d0d
```

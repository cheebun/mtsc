# C7CU-PGT9 (Level 6, 64G)

A 64G RouterOS L6-licensed VM: official ISO install + manual MBR patch. Built on two RouterOS
versions, both confirmed working — **v7.24.1** (this directory's `.vma`, built via PVE automation)
and **v7.23.2** (the original manual walkthrough, `64G-ROS.md` below).

## Files

| File | Size | What it is |
|---|---|---|
| `RouterOS-v7.24.1-C7CU-PGT9-L6-64GB.vma` | 50,200,064 bytes | Proxmox `vzdump` backup (plain `.vma`) of the v7.24.1 build. Restore with `qmrestore`. |
| `64G-ROS.md` | 3,492 bytes | Walkthrough (Chinese) for the original v7.23.2 build. |
| `images/*.png` | — | Install/activation screenshots from the v7.23.2 build. |

## Scheme

```
Model: SSD64G2016
Serial: HYSSD-20160419B79028
Size: 64,023,257,088 bytes
-----
Software ID: C7CU-PGT9
License level: 6
Router OS version: 7.24.1
-----
Identity (0x100-0x109): 00000000000000000000
Marker (0x10A-0x10B): BDE8
Reserved (0x10C-0x10F): 00000000
Signature (0x110-0x14F): F4E11772DEEAED8AF43668DA5EBDAD0846B694FFE9E77EFAE77E11A6049E4303B0B09DCEF8D9A647D643D1BAD4AF13B9659CCB11A06D3A9080096634E4E88B07
```

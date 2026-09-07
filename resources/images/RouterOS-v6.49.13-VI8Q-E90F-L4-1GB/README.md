# VI8Q-E90F (Level 4) — real device disk captures

Two raw disk images from the same physical real x86 machine (reflashed SSD, reported in
[github.com/cheebun/ros-serialgen issue #1](https://github.com/cheebun/ros-serialgen/issues/1),
MurVlad), running RouterOS 6.49.13.


## Files

| File | Size | What it is |
|---|---|---|
| `mikrotik.img.zip` | 8,393,833 bytes | First 10MB of the disk (MBR + partition table). Decompress with `unzip`. |
| `PVE-RouterOS-L4-1066M-6.49.13.vma` | 73,441,280 bytes | Full VMA backup of the complete disk. Extract with `vma extract`. |

## Scheme

```
Model: QEMU HARDDISK
Serial: QM00001
Size: 1,071,645,184 bytes
-----
Software ID: VI8Q-E90F
License level: 4
Router OS version: 6.49.13
-----
Identity (0x100-0x109): 50508089413009661362
Marker (0x10A-0x10B): 0362
Reserved (0x10C-0x10F): 00000000
Signature (0x110-0x14F): 499cb95a702360e33097972ea9bb12802d8a688393d21505a80817ee4192de00c390add584a873cc729a032207d36c4ac13816bb821760a523e76eb0e3ed8d0d
```

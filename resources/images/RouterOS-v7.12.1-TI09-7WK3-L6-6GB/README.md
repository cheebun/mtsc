# TI09-7WK3 (Level 6, 6G) — default VMware IDE collision, clean image

PVE's default `ide0` model/serial collide with `TI09-7WK3` with zero extra configuration.

## Files

| File | Size | What it is |
|---|---|---|
| `RouterOS-v7.12.1-TI09-7WK3-L6-6GB.img.zip` | 28,411,067 bytes | Full raw disk image, pre-activated. Decompress with `unzip`. |
| `RouterOS-v7.12.1-TI09-7WK3-L6-6GB.vma` | 24,835,584 bytes | Proxmox `vzdump` backup (plain `.vma`) of the verification VM. Restore with `qmrestore`. |

## Boot notes — this image needs OVMF/UEFI

```bash
qm set <vmid> --bios ovmf
qm set <vmid> --efidisk0 local:<vmid>,efitype=4m,pre-enrolled-keys=0,size=1M
qm start <vmid>
```

## Scheme

```
Model: VMware Virtual IDE Hard Drive
Serial: 1
Size: 6G
-----
Software ID: TI09-7WK3
License level: 6
Router OS version: 7.12.1
-----
Identity (0x100-0x109): 00000000000000000000
Marker (0x10A-0x10B): BDE8
Reserved (0x10C-0x10F): 00000000
Signature (0x110-0x14F): E67A8F47AE86672FAE6D91DF19221453B34FE40E23F19E917107C449DDCB1D2061521816AD7730671B4CB226F1B0DB7448923C6297C49BDB3CCBF40AECBBCF0B
```


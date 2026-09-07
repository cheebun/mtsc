# TI09-7WK3 (Level 6, 42G) — custom-size collision, RouterOS v7.12.1


## Files

| File | Size | What it is |
|---|---|---|
| `RouterOS-v7.12.1-TI09-7WK3-L6-42GB.zip` | 23,512,172 bytes | Original files: `RouterOS7.12.1-42G.vmdk` (disk), `SSD42G.vmdk` (descriptor), `RouterOS7.12.1-42G.bat` (launch script), `OVMF.fd` (UEFI firmware). |
| `RouterOS-v7.12.1-TI09-7WK3-L6-42GB.vma` | 33,114,112 bytes | Proxmox `vzdump` backup (plain `.vma`) of the verification VM. Restore with `qmrestore`. |
| `winbox.png` | 361,919 bytes | Screenshot of a successful Winbox connection/activation. |

## Boot notes

The sparse VMDK (`SSD42G.vmdk` descriptor + `RouterOS7.12.1-42G.vmdk` extent) won't open directly
via `qemu-img info`/`convert` on modern QEMU (`Unsupported image type 'monolithicSparse'`) — but
the extent file alone opens fine (embedded VMDK header):

```bash
qemu-img convert -f vmdk -O raw RouterOS7.12.1-42G.vmdk out.raw
```

Boots under OVMF/UEFI.

## Scheme

```
Model: n4X7W6eSOxyxUhOd
Serial: G4HQT594JN8VLY0FGN9
Size: 42G
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

# vzdump VMID 101 "ros" — full backup of the 4MZF-SFTR real device

A Proxmox VMA backup, confirmed to be a full (non-wiped) capture of the same physical device as
`RouterOS-v7.13.3-4MZF-SFTR-L6-8GB/`.

## Files

| File | Size | What it is |
|---|---|---|
| `RouterOS-v7.13.3-4MZF-SFTR-L6-64GB.vma` | 36,315,136 bytes | Proxmox VMA backup, plain `.vma`. Restore with `qmrestore`. |

## Scheme

```
Model: SSD08G
Serial: HKHYPO14032703B0778
Size: 7,918,460,928 bytes
-----
Software ID: 4MZF-SFTR
License level: 6
Router OS version: 7.13.3
-----
Identity (0x100-0x109): 4806559509200345055A
Marker (0x10A-0x10B): 4442
Reserved (0x10C-0x10F): 00000000
Signature (0x110-0x14F): 080342D34683448A1C8E3952E5A5D315F1C5FB4E4EB419C94FB88170DF0290EE3F4DFB796ECA3034D93E934B3FC27169D6506C88F23FE508B26F83546C335A05
```

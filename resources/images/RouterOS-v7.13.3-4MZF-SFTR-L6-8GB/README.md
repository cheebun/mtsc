# 4MZF-SFTR (Level 6, 8G) — real device disk image

Full raw disk image from a real physical device, wiped/reset before capture (hence "noconfig"),
carrying a real, factory-issued MBR license.

## Files

| File | Size | What it is |
|---|---|---|
| `RouterOS-v7.13.3-4MZF-SFTR-L6-8GB.img.zip` | 100,090,524 bytes | Full raw disk image, real hardware. Mostly zero-filled. Decompress with `unzip`. |

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

# hap-ax-lite.bin — Identification Notes

SPI flash dump for a MikroTik hAP ax lite.

## File identification

- Size: 4,194,304 bytes (4 MiB) exactly
- `file`: ELF 32-bit LSB executable, ARM, EABI5, statically linked, no section header
- MD5: `080ad3b9bfd6866bbad998f8c50876d0`

Not region-mapped yet -- no structural analysis pass done on this dump.

## Device context

- Source: https://www.right.com.cn/forum/thread-8388061-1-5.html (poster gaohz521,
  2024-7-27) -- hardware specs confirmed present on that page, matching what was
  supplied directly:

| Field | Value |
|---|---|
| Product code | L41G-2axD |
| Architecture | ARM |
| CPU | IPQ-5010, 2 cores, 800 MHz |
| Switch chip | MT7531BE |
| RouterOS license level | 4 |
| Operating System | RouterOS v7 |
| RAM | 256 MB |
| Storage | 128 MB NAND |

Note from thread replies: the IPQ5010+MT7531BE combination is described as unusual for a
router (`lhn1324`, `g1325`); one reply (`dengdechao`) reports getting SPI-flash boot
working but couldn't complete a full flash due to a switch-chip mismatch on their unit --
relevant if attempting to reuse this dump on non-original hardware, similar to the
`chateau-pro-ax` caveat.

No verification-mechanism analysis has been done on this dump -- stored as raw reference
material only, same status as `resources/programmer-firmware/chateau-pro-ax/` and
`resources/programmer-firmware/hap-ax3/`.

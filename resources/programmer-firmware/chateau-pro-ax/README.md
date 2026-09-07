# GD25LQ32D_ChateauProAx.bin — Identification Notes

SPI flash dump for a MikroTik "Chateau Pro Ax" router, chip `GD25LQ32D` (32 Mbit / 4 MiB
SPI NOR flash).

## File identification

- Size: 4,194,304 bytes (4 MiB) exactly
- `file`: ELF 32-bit LSB executable, ARM, EABI5, statically linked, no section header
- MD5: `2c02ac8e7007339f549f7d569c0cccf9`

Not region-mapped (bootloader/rootfs/config-gap boundaries) yet -- unlike
`resources/programmer-firmware/hap-ac2/README.md`'s dump, this hasn't had a structural analysis pass.

## Device context

- Source: https://www.right.com.cn/forum/thread-8430900-1-3.html (poster shahiyuan,
  2025-06-06)
- Hardware: CPU Qualcomm IPQ8072A, RAM 512MB x2 = 1024MB, wireless spec matching an
  "AX3600" reference design (repurposed/rebranded hardware, not necessarily an
  official MikroTik-branded board -- see caveat below)

## Important caveat: newer-generation SPI verification mechanism, not directly portable

Per the source thread, this is a **newer-generation SPI firmware** whose license/
verification mechanism differs from the AX2-generation devices this project has
otherwise worked with -- the poster explicitly states it does not directly transplant
onto hardware that doesn't match the official spec (repurposed AX3600-chassis hardware
in particular). **This project has not reverse-engineered or confirmed the Chateau Pro
Ax verification mechanism** -- treat this dump as raw identification/reference material
only, not yet analyzed the way `keyman_x86`/`keyman_arm32` were for the ROS/CHR formulas
documented in `docs/investigation/license-internals.md` and
`docs/reference/chr-system-id-formula.md`.

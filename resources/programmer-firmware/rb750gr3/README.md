# RB750Gr3.bin — Identification Notes

Programmer/flash firmware dump for a MikroTik RB750Gr3.

## File identification

- Size: 16,777,216 bytes (16 MiB) exactly
- `file`: generic `data` -- unlike the ARM-based devices in this project's other
  `resources/` captures (`hap-ac2`, `hap-ac3`, `chateau-pro-ax`, `hap-ax3`,
  `hap-ax-lite`, all identified as ELF/ARM), this dump does **not** start with an ELF
  header. First 32 bytes: `0900 0010 0000 0000 0000 0000 0000 0000 0000 0000 00f0
  0000 0010 0000 0000 0100 0000 0200 0010 0000 00be 083c 2006 0835` -- consistent with
  a MIPS-based boot header (RB750 series historically uses Atheros/QCA MIPS SoCs, not
  ARM) rather than the ARM/IPQ-family SoCs of this project's other captures. Not
  independently confirmed.
- MD5: `f8e21e5e2dc65902d74c17496dad7818`

Not region-mapped -- no structural analysis pass done on this dump.

## Device context

- Source: https://www.right.com.cn/forum/thread-4053086-1-6.html (poster lhn1324,
  2020-09-28) -- device obtained secondhand ("从闲鱼收了一个"), no CPU/RAM/flash-chip
  part numbers given in the visible thread content, only the 16MB image size.
- Poster was investigating whether this firmware could be adapted to boot on a
  different device ("歌华链" / "Gehua chain router") via hardware modification --
  unresolved in the visible thread; a later reply (RB751G, NAND storage) was declined
  by the poster for lack of hardware.

## Notable finding: official free L1 licensing path (not this project's method)

Multiple replies in the thread asked how to handle licensing ("授权怎么解决？"). The
poster's answer describes MikroTik's own **official, legitimate** route, unrelated to
this project's collision-search/reverse-engineering approach:

1. Go to **mikrotik.com/client**, register/log in.
2. Use the **"Make a demo key"** feature, entering the device's **Software ID**.
3. This generates a genuine **L1-level license key**, sufficient for home/personal use
   per the poster ("家用足够了").
4. Import via command line or Winbox (System -> License).

Worth keeping in mind for any future device where only a basic/L1 license is needed --
MikroTik provides this for free through official channels, no reverse-engineering
required, though it's capped at L1 (this project's other work targets L4/L6 licenses
that aren't available through this free path).

No verification-mechanism analysis has been done on this dump itself -- stored as raw
reference material only, same status as the other undocumented captures in `resources/`.

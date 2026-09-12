# Reverse Identity Search: Deriving `identity` from a Known Target

How to go the *other* direction from `identity-marker-formula.md`'s "many identities
share one marker" observation: given a known real `serial`/`model`/`size` and a target
`SOFTWARE ID` you want to reproduce, find an `identity` that makes the combination hash
to that target -- without needing to brute-force `serial` the way `search`/
`generate serial` does. Explored and empirically verified 2026-09-03.

## Why this is cheap: only 2048 outcomes possible per fixed serial/model/size

```
sid_lo, sid_hi = mt_sha256(serial + model + sector_val)   -- fixed once serial/model/size are fixed
mix            = mbr_val * 0x3FF800F                       -- mbr_val is only 11 bits: 0-2047
final          = (sid_lo XOR mix_lo, (sid_hi|0x100) XOR mix_hi)
SOFTWARE_ID    = base35_encode(final)
```

> **Confirmed correct, with an important structural consequence (2026-09-07):** this
> `(sid_hi|0x100) XOR mix_hi` formula is real and hardware-confirmed -- a live VM boot
> (RouterOS 7.24.1, `serial=573214362`, non-standard identity `00000000000000000FF4`)
> computed the exact SOFTWARE ID this formula predicts. A same-day investigation briefly
> suspected this formula was wrong (based on `targets::entries_to_targets`'s `& 0xFF`
> masked comparison, which is a *different*, separately-buggy code path -- since fixed to
> match this formula's full-width semantics) and edited this note to say so; that edit was
> itself wrong and has been reverted.
>
> The real, structural consequence of the `|0x100`: since `(sid_hi|0x100)` always has bit
> 8 set and no bits above 8, and `mix_hi` (`mbr_val * 0x3FF800F >> 32`) is always < 32 (so
> it can only ever flip bits 0-4), a target's `tv_hi` must *already* have bit 8 set and no
> bits above 8 -- i.e. fall in `256..512` -- for *any* `mbr_val`/identity to ever produce
> it. This is fixed per target, not something a longer search or a different identity can
> work around. Empirically, 59 of 131 real `keys.toml` targets (45%) decode to a `tv_hi`
> outside that range and are therefore not reachable via this disk/MBR-based collision
> technique for *any* serial -- most such entries are router-hardware-identity licenses
> (e.g. the CCR1009 batch), not disk-based SOFTWARE IDs to begin with, so this reflects a
> different licensing mechanism rather than a gap in the technique. Confirmed the hard way:
> a sweep for `MGT2-L23Y` (`tv_hi=0x44`, outside the range) using an incorrectly-loosened
> feasibility check reported a false-positive hit (`mbr_val=468`); booting that exact
> combo on real hardware produced a different SOFTWARE ID (`ZTBI-ENJL`), not `MGT2-L23Y`,
> proving the loosened check wrong and this original formula right.

For a **fixed** `serial`/`model`/`size`, `sid_lo`/`sid_hi` never change -- the *only*
thing `identity` can do is pick one of `mbr_val`'s **2048** possible values, each
producing exactly one resulting SOFTWARE ID. So instead of an open-ended search, this
reduces to two cheap steps:

1. **Feasibility check (instant, no search):** decode the target SOFTWARE ID, XOR
   against the known `sid_lo`/`sid_hi` to get the *required* `mix`, then check whether
   that `mix` is an exact multiple of `0x3FF800F` with a quotient in `0..=2047`. If not,
   **no identity can produce this target for this exact serial/model/size** -- proven
   mathematically, not just "not found after searching."
2. **Identity recovery (cheap search, only if step 1 succeeds):** find any 10-byte
   `identity` whose `raw16_from_identity(identity) & 0x7FF` equals the required
   `mbr_val`. Any such identity works equally well -- they're functionally
   interchangeable per `identity-marker-formula.md`'s already-established "many-to-one"
   result.

## Empirical verification (2026-09-03)

### Confirmed: exactly 2048 distinct `mbr_val` values exist, no more, no fewer

Sequentially enumerated identity `0000000000000000000` upward (treating the 10-byte
identity as a plain counter). Result: **all 2048 distinct `mbr_val` values appeared
within the first 19,227 identities tried**, and no value ever fell outside `0..=2047`.
In the same run, 16,629 distinct full 16-bit `raw16`/marker values appeared out of a
possible 65,536 -- consistent with the coupon-collector expectation for a
well-distributed hash (`65536*(1-e^(-19227/65536)) ≈ 16,680`, close to the 16,629
observed), i.e. no structural bias detected.

**Practical consequence:** since one match is expected on average every 2048 tries, and
`P(no match within 65536 tries) ≈ e^-32 ≈ 1.3e-14`, searching **only the last 2 bytes**
of the identity (65,536 combinations, first 8 bytes fixed at zero) is sufficient in
practice -- never need to touch the full 80-bit space. At this project's documented
scalar hash throughput (~100M hash/s), 65,536 tries costs well under 1 millisecond;
finding the *first* match (expected ~2048 tries) costs on the order of microseconds.

### Reference table: `mbr_val` for all 256 "half-and-half" two-digit identities

Sanity-check data set -- also useful as memorable, easy-to-transcribe non-standard
identities if a distinct-but-simple value is ever wanted. Identity = 10 hex chars of
digit `A` followed by 10 hex chars of digit `B` (`AAAAAAAAAA` + `BBBBBBBBBB`), for every
ordered pair of hex digits (`16 x 16 = 256` combinations, including `A == B`, i.e. the
all-same-digit case, e.g. `00`/`11`/.../`FF`, on the diagonal). The `00` row
(`mbr_val = 189 = 0x0BD`) matching the already-established standard-identity constant is
a useful cross-check that this reverse-search math is implemented correctly.
**Not symmetric**: swapping the two halves (e.g. `1111111111`+`2222222222` vs.
`2222222222`+`1111111111`) gives a different `mbr_val`, since byte order matters to the
hash.

`Pair` = first-half digit + second-half digit. `Marker` verified directly against this
project's own `ros-serialgen check --identity <hex>` output for all 256 identities
(2026-09-07):

| Pair | Identity (20 hex chars) | Marker (LE) | `mbr_val` |
|---|---|---|---|
| 00 | `00000000000000000000` | `BDE8` | 189 |
| 01 | `00000000001111111111` | `7801` | 376 |
| 02 | `00000000002222222222` | `B2AF` | 1970 |
| 03 | `00000000003333333333` | `C0E2` | 704 |
| 04 | `00000000004444444444` | `F375` | 1523 |
| 05 | `00000000005555555555` | `40B0` | 64 |
| 06 | `00000000006666666666` | `F579` | 501 |
| 07 | `00000000007777777777` | `0666` | 1542 |
| 08 | `00000000008888888888` | `357F` | 1845 |
| 09 | `00000000009999999999` | `54A5` | 1364 |
| 0A | `0000000000AAAAAAAAAA` | `4958` | 73 |
| 0B | `0000000000BBBBBBBBBB` | `2692` | 550 |
| 0C | `0000000000CCCCCCCCCC` | `B88F` | 1976 |
| 0D | `0000000000DDDDDDDDDD` | `A7BD` | 1447 |
| 0E | `0000000000EEEEEEEEEE` | `9418` | 148 |
| 0F | `0000000000FFFFFFFFFF` | `BED5` | 1470 |
| 10 | `11111111110000000000` | `C5BD` | 1477 |
| 11 | `11111111111111111111` | `F78D` | 1527 |
| 12 | `11111111112222222222` | `F2AB` | 1010 |
| 13 | `11111111113333333333` | `43D6` | 1603 |
| 14 | `11111111114444444444` | `5DA1` | 349 |
| 15 | `11111111115555555555` | `99E3` | 921 |
| 16 | `11111111116666666666` | `9C8B` | 924 |
| 17 | `11111111117777777777` | `E219` | 482 |
| 18 | `11111111118888888888` | `6F9E` | 1647 |
| 19 | `11111111119999999999` | `CCCA` | 716 |
| 1A | `1111111111AAAAAAAAAA` | `D768` | 215 |
| 1B | `1111111111BBBBBBBBBB` | `C7F4` | 1223 |
| 1C | `1111111111CCCCCCCCCC` | `F789` | 503 |
| 1D | `1111111111DDDDDDDDDD` | `A30D` | 1443 |
| 1E | `1111111111EEEEEEEEEE` | `7370` | 115 |
| 1F | `1111111111FFFFFFFFFF` | `3707` | 1847 |
| 20 | `22222222220000000000` | `1583` | 789 |
| 21 | `22222222221111111111` | `5E52` | 606 |
| 22 | `22222222222222222222` | `3E70` | 62 |
| 23 | `22222222223333333333` | `CB48` | 203 |
| 24 | `22222222224444444444` | `D9F0` | 217 |
| 25 | `22222222225555555555` | `A0A4` | 1184 |
| 26 | `22222222226666666666` | `1620` | 22 |
| 27 | `22222222227777777777` | `1E61` | 286 |
| 28 | `22222222228888888888` | `E12B` | 993 |
| 29 | `22222222229999999999` | `13DC` | 1043 |
| 2A | `2222222222AAAAAAAAAA` | `CCA3` | 972 |
| 2B | `2222222222BBBBBBBBBB` | `58D8` | 88 |
| 2C | `2222222222CCCCCCCCCC` | `4337` | 1859 |
| 2D | `2222222222DDDDDDDDDD` | `9759` | 407 |
| 2E | `2222222222EEEEEEEEEE` | `2400` | 36 |
| 2F | `2222222222FFFFFFFFFF` | `85F4` | 1157 |
| 30 | `33333333330000000000` | `8607` | 1926 |
| 31 | `33333333331111111111` | `D8C9` | 472 |
| 32 | `33333333332222222222` | `8526` | 1669 |
| 33 | `33333333333333333333` | `F461` | 500 |
| 34 | `33333333334444444444` | `70E5` | 1392 |
| 35 | `33333333335555555555` | `4B2A` | 587 |
| 36 | `33333333336666666666` | `EF9A` | 751 |
| 37 | `33333333337777777777` | `D963` | 985 |
| 38 | `33333333338888888888` | `C32A` | 707 |
| 39 | `33333333339999999999` | `807E` | 1664 |
| 3A | `3333333333AAAAAAAAAA` | `9FB9` | 415 |
| 3B | `3333333333BBBBBBBBBB` | `61C8` | 97 |
| 3C | `3333333333CCCCCCCCCC` | `9AE2` | 666 |
| 3D | `3333333333DDDDDDDDDD` | `D095` | 1488 |
| 3E | `3333333333EEEEEEEEEE` | `587A` | 600 |
| 3F | `3333333333FFFFFFFFFF` | `961C` | 1174 |
| 40 | `44444444440000000000` | `418B` | 833 |
| 41 | `44444444441111111111` | `ADFB` | 941 |
| 42 | `44444444442222222222` | `4FA2` | 591 |
| 43 | `44444444443333333333` | `A1F9` | 417 |
| 44 | `44444444444444444444` | `4D87` | 1869 |
| 45 | `44444444445555555555` | `B583` | 949 |
| 46 | `44444444446666666666` | `4C5F` | 1868 |
| 47 | `44444444447777777777` | `52EE` | 1618 |
| 48 | `44444444448888888888` | `64F1` | 356 |
| 49 | `44444444449999999999` | `5E1B` | 862 |
| 4A | `4444444444AAAAAAAAAA` | `BA52` | 698 |
| 4B | `4444444444BBBBBBBBBB` | `52EA` | 594 |
| 4C | `4444444444CCCCCCCCCC` | `A6C3` | 934 |
| 4D | `4444444444DDDDDDDDDD` | `5F5E` | 1631 |
| 4E | `4444444444EEEEEEEEEE` | `D456` | 1748 |
| 4F | `4444444444FFFFFFFFFF` | `B413` | 948 |
| 50 | `55555555550000000000` | `75DF` | 1909 |
| 51 | `55555555551111111111` | `A1F2` | 673 |
| 52 | `55555555552222222222` | `8E12` | 654 |
| 53 | `55555555553333333333` | `9D0A` | 669 |
| 54 | `55555555554444444444` | `397C` | 1081 |
| 55 | `55555555555555555555` | `37A2` | 567 |
| 56 | `55555555556666666666` | `3821` | 312 |
| 57 | `55555555557777777777` | `9F38` | 159 |
| 58 | `55555555558888888888` | `FC2B` | 1020 |
| 59 | `55555555559999999999` | `8ACA` | 650 |
| 5A | `5555555555AAAAAAAAAA` | `F894` | 1272 |
| 5B | `5555555555BBBBBBBBBB` | `346C` | 1076 |
| 5C | `5555555555CCCCCCCCCC` | `C4FD` | 1476 |
| 5D | `5555555555DDDDDDDDDD` | `F6A5` | 1526 |
| 5E | `5555555555EEEEEEEEEE` | `C777` | 1991 |
| 5F | `5555555555FFFFFFFFFF` | `7702` | 631 |
| 60 | `66666666660000000000` | `BFE3` | 959 |
| 61 | `66666666661111111111` | `3554` | 1077 |
| 62 | `66666666662222222222` | `D9E4` | 1241 |
| 63 | `66666666663333333333` | `92A0` | 146 |
| 64 | `66666666664444444444` | `6545` | 1381 |
| 65 | `66666666665555555555` | `0C16` | 1548 |
| 66 | `66666666666666666666` | `0B51` | 267 |
| 67 | `66666666667777777777` | `E137` | 2017 |
| 68 | `66666666668888888888` | `3324` | 1075 |
| 69 | `66666666669999999999` | `253F` | 1829 |
| 6A | `6666666666AAAAAAAAAA` | `B9A8` | 185 |
| 6B | `6666666666BBBBBBBBBB` | `7DDF` | 1917 |
| 6C | `6666666666CCCCCCCCCC` | `717D` | 1393 |
| 6D | `6666666666DDDDDDDDDD` | `684B` | 872 |
| 6E | `6666666666EEEEEEEEEE` | `7E42` | 638 |
| 6F | `6666666666FFFFFFFFFF` | `C975` | 1481 |
| 70 | `77777777770000000000` | `67EA` | 615 |
| 71 | `77777777771111111111` | `0487` | 1796 |
| 72 | `77777777772222222222` | `63F5` | 1379 |
| 73 | `77777777773333333333` | `9CBC` | 1180 |
| 74 | `77777777774444444444` | `D029` | 464 |
| 75 | `77777777775555555555` | `63A3` | 867 |
| 76 | `77777777776666666666` | `D022` | 720 |
| 77 | `77777777777777777777` | `6BEC` | 1131 |
| 78 | `77777777778888888888` | `206D` | 1312 |
| 79 | `77777777779999999999` | `A3C1` | 419 |
| 7A | `7777777777AAAAAAAAAA` | `6EBF` | 1902 |
| 7B | `7777777777BBBBBBBBBB` | `7EF8` | 126 |
| 7C | `7777777777CCCCCCCCCC` | `945B` | 916 |
| 7D | `7777777777DDDDDDDDDD` | `9223` | 914 |
| 7E | `7777777777EEEEEEEEEE` | `FCFB` | 1020 |
| 7F | `7777777777FFFFFFFFFF` | `A02B` | 928 |
| 80 | `88888888880000000000` | `9A67` | 1946 |
| 81 | `88888888881111111111` | `3C71` | 316 |
| 82 | `88888888882222222222` | `A186` | 1697 |
| 83 | `88888888883333333333` | `0ED3` | 782 |
| 84 | `88888888884444444444` | `38DF` | 1848 |
| 85 | `88888888885555555555` | `F785` | 1527 |
| 86 | `88888888886666666666` | `4B53` | 843 |
| 87 | `88888888887777777777` | `C0E6` | 1728 |
| 88 | `88888888888888888888` | `3A7D` | 1338 |
| 89 | `88888888889999999999` | `5FFD` | 1375 |
| 8A | `8888888888AAAAAAAAAA` | `EEDA` | 750 |
| 8B | `8888888888BBBBBBBBBB` | `B529` | 437 |
| 8C | `8888888888CCCCCCCCCC` | `53B9` | 339 |
| 8D | `8888888888DDDDDDDDDD` | `480E` | 1608 |
| 8E | `8888888888EEEEEEEEEE` | `3D84` | 1085 |
| 8F | `8888888888FFFFFFFFFF` | `0AEC` | 1034 |
| 90 | `99999999990000000000` | `56D4` | 1110 |
| 91 | `99999999991111111111` | `9E45` | 1438 |
| 92 | `99999999992222222222` | `86A7` | 1926 |
| 93 | `99999999993333333333` | `640C` | 1124 |
| 94 | `99999999994444444444` | `7F68` | 127 |
| 95 | `99999999995555555555` | `552E` | 1621 |
| 96 | `99999999996666666666` | `780D` | 1400 |
| 97 | `99999999997777777777` | `E140` | 225 |
| 98 | `99999999998888888888` | `65E2` | 613 |
| 99 | `99999999999999999999` | `CF10` | 207 |
| 9A | `9999999999AAAAAAAAAA` | `3FB6` | 1599 |
| 9B | `9999999999BBBBBBBBBB` | `E459` | 484 |
| 9C | `9999999999CCCCCCCCCC` | `DBA1` | 475 |
| 9D | `9999999999DDDDDDDDDD` | `AFC5` | 1455 |
| 9E | `9999999999EEEEEEEEEE` | `7B02` | 635 |
| 9F | `9999999999FFFFFFFFFF` | `A793` | 935 |
| A0 | `AAAAAAAAAA0000000000` | `7059` | 368 |
| A1 | `AAAAAAAAAA1111111111` | `F8A7` | 2040 |
| A2 | `AAAAAAAAAA2222222222` | `1D18` | 29 |
| A3 | `AAAAAAAAAA3333333333` | `1063` | 784 |
| A4 | `AAAAAAAAAA4444444444` | `FB73` | 1019 |
| A5 | `AAAAAAAAAA5555555555` | `9839` | 408 |
| A6 | `AAAAAAAAAA6666666666` | `4AD9` | 330 |
| A7 | `AAAAAAAAAA7777777777` | `53A5` | 1363 |
| A8 | `AAAAAAAAAA8888888888` | `08D0` | 8 |
| A9 | `AAAAAAAAAA9999999999` | `5C11` | 348 |
| AA | `AAAAAAAAAAAAAAAAAAAA` | `9B8B` | 923 |
| AB | `AAAAAAAAAABBBBBBBBBB` | `3604` | 1078 |
| AC | `AAAAAAAAAACCCCCCCCCC` | `520D` | 1362 |
| AD | `AAAAAAAAAADDDDDDDDDD` | `BE9F` | 1982 |
| AE | `AAAAAAAAAAEEEEEEEEEE` | `567B` | 854 |
| AF | `AAAAAAAAAAFFFFFFFFFF` | `B939` | 441 |
| B0 | `BBBBBBBBBB0000000000` | `0721` | 263 |
| B1 | `BBBBBBBBBB1111111111` | `9230` | 146 |
| B2 | `BBBBBBBBBB2222222222` | `D3E5` | 1491 |
| B3 | `BBBBBBBBBB3333333333` | `DD8B` | 989 |
| B4 | `BBBBBBBBBB4444444444` | `975C` | 1175 |
| B5 | `BBBBBBBBBB5555555555` | `8195` | 1409 |
| B6 | `BBBBBBBBBB6666666666` | `4D40` | 77 |
| B7 | `BBBBBBBBBB7777777777` | `09DA` | 521 |
| B8 | `BBBBBBBBBB8888888888` | `EE63` | 1006 |
| B9 | `BBBBBBBBBB9999999999` | `7863` | 888 |
| BA | `BBBBBBBBBBAAAAAAAAAA` | `990D` | 1433 |
| BB | `BBBBBBBBBBBBBBBBBBBB` | `997B` | 921 |
| BC | `BBBBBBBBBBCCCCCCCCCC` | `B5ED` | 1461 |
| BD | `BBBBBBBBBBDDDDDDDDDD` | `3F1C` | 1087 |
| BE | `BBBBBBBBBBEEEEEEEEEE` | `19D9` | 281 |
| BF | `BBBBBBBBBBFFFFFFFFFF` | `7AC6` | 1658 |
| C0 | `CCCCCCCCCC0000000000` | `1A2A` | 538 |
| C1 | `CCCCCCCCCC1111111111` | `F0CA` | 752 |
| C2 | `CCCCCCCCCC2222222222` | `1851` | 280 |
| C3 | `CCCCCCCCCC3333333333` | `FCAC` | 1276 |
| C4 | `CCCCCCCCCC4444444444` | `D49C` | 1236 |
| C5 | `CCCCCCCCCC5555555555` | `A6AB` | 934 |
| C6 | `CCCCCCCCCC6666666666` | `DD8C` | 1245 |
| C7 | `CCCCCCCCCC7777777777` | `2723` | 807 |
| C8 | `CCCCCCCCCC8888888888` | `C1FC` | 1217 |
| C9 | `CCCCCCCCCC9999999999` | `F25B` | 1010 |
| CA | `CCCCCCCCCCAAAAAAAAAA` | `A3A2` | 675 |
| CB | `CCCCCCCCCCBBBBBBBBBB` | `3963` | 825 |
| CC | `CCCCCCCCCCCCCCCCCCCC` | `09CD` | 1289 |
| CD | `CCCCCCCCCCDDDDDDDDDD` | `9E5D` | 1438 |
| CE | `CCCCCCCCCCEEEEEEEEEE` | `CD0E` | 1741 |
| CF | `CCCCCCCCCCFFFFFFFFFF` | `6BCE` | 1643 |
| D0 | `DDDDDDDDDD0000000000` | `13CA` | 531 |
| D1 | `DDDDDDDDDD1111111111` | `1097` | 1808 |
| D2 | `DDDDDDDDDD2222222222` | `2CC2` | 556 |
| D3 | `DDDDDDDDDD3333333333` | `22CB` | 802 |
| D4 | `DDDDDDDDDD4444444444` | `BF96` | 1727 |
| D5 | `DDDDDDDDDD5555555555` | `1B8E` | 1563 |
| D6 | `DDDDDDDDDD6666666666` | `FEC3` | 1022 |
| D7 | `DDDDDDDDDD7777777777` | `0E3B` | 782 |
| D8 | `DDDDDDDDDD8888888888` | `B022` | 688 |
| D9 | `DDDDDDDDDD9999999999` | `3E0C` | 1086 |
| DA | `DDDDDDDDDDAAAAAAAAAA` | `379D` | 1335 |
| DB | `DDDDDDDDDDBBBBBBBBBB` | `C4AD` | 1476 |
| DC | `DDDDDDDDDDCCCCCCCCCC` | `592D` | 1369 |
| DD | `DDDDDDDDDDDDDDDDDDDD` | `A748` | 167 |
| DE | `DDDDDDDDDDEEEEEEEEEE` | `8F67` | 1935 |
| DF | `DDDDDDDDDDFFFFFFFFFF` | `AA17` | 1962 |
| E0 | `EEEEEEEEEE0000000000` | `9D7A` | 669 |
| E1 | `EEEEEEEEEE1111111111` | `1D81` | 285 |
| E2 | `EEEEEEEEEE2222222222` | `9B57` | 1947 |
| E3 | `EEEEEEEEEE3333333333` | `F13C` | 1265 |
| E4 | `EEEEEEEEEE4444444444` | `9617` | 1942 |
| E5 | `EEEEEEEEEE5555555555` | `60E6` | 1632 |
| E6 | `EEEEEEEEEE6666666666` | `68C9` | 360 |
| E7 | `EEEEEEEEEE7777777777` | `FA52` | 762 |
| E8 | `EEEEEEEEEE8888888888` | `85B8` | 133 |
| E9 | `EEEEEEEEEE9999999999` | `ADF9` | 429 |
| EA | `EEEEEEEEEEAAAAAAAAAA` | `DD8E` | 1757 |
| EB | `EEEEEEEEEEBBBBBBBBBB` | `745A` | 628 |
| EC | `EEEEEEEEEECCCCCCCCCC` | `B2CD` | 1458 |
| ED | `EEEEEEEEEEDDDDDDDDDD` | `802A` | 640 |
| EE | `EEEEEEEEEEEEEEEEEEEE` | `7195` | 1393 |
| EF | `EEEEEEEEEEFFFFFFFFFF` | `0947` | 1801 |
| F0 | `FFFFFFFFFF0000000000` | `4068` | 64 |
| F1 | `FFFFFFFFFF1111111111` | `6A2F` | 1898 |
| F2 | `FFFFFFFFFF2222222222` | `8452` | 644 |
| F3 | `FFFFFFFFFF3333333333` | `E3D4` | 1251 |
| F4 | `FFFFFFFFFF4444444444` | `7C91` | 380 |
| F5 | `FFFFFFFFFF5555555555` | `E262` | 738 |
| F6 | `FFFFFFFFFF6666666666` | `9B40` | 155 |
| F7 | `FFFFFFFFFF7777777777` | `87A6` | 1671 |
| F8 | `FFFFFFFFFF8888888888` | `4635` | 1350 |
| F9 | `FFFFFFFFFF9999999999` | `6EBF` | 1902 |
| FA | `FFFFFFFFFFAAAAAAAAAA` | `0FD3` | 783 |
| FB | `FFFFFFFFFFBBBBBBBBBB` | `82F9` | 386 |
| FC | `FFFFFFFFFFCCCCCCCCCC` | `5F13` | 863 |
| FD | `FFFFFFFFFFDDDDDDDDDD` | `152F` | 1813 |
| FE | `FFFFFFFFFFEEEEEEEEEE` | `8974` | 1161 |
| FF | `FFFFFFFFFFFFFFFFFFFF` | `79C3` | 889 |

### Live verification against a real device: `HHJH-UFWL`

Using the already-verified real device data for `HHJH-UFWL` (`serial=SZHYPO14090903D0164`,
`model=SSD32G`, `size=31675383808` bytes, real `identity=47110226688983991618` ->
`mbr_val=1786`, per `keys.toml`'s comment for this entry):

1. Confirmed `identity=47110226688983991618` -> `raw16=0x7EFA` (marker `FA7E`) ->
   `mbr_val=1786`, matching the real device.
2. Enumerated all identities in `0..65536` with `mbr_val=1786`: **27 matches found**
   (close to the 32 expected on average -- `65536/2048`).
3. Picked 6 of the 27 (`0000000000000000040c`, `000000000000000006c6`,
   `00000000000000002202`, `00000000000000002f48`, `000000000000000031bb`,
   `0000000000000000ee69`) and ran each through the real `ros-serialgen check` binary
   with the same serial/model/size. **All 6 reproduced `HHJH-UFWL` exactly**
   (`✅ Matched signature: HHJH-UFWL`) -- live confirmation with this project's actual
   tooling, not just the Python prototype, that any identity sharing the target
   `mbr_val` is fully interchangeable for licensing purposes.

## Proposed CLI feature: `mtsc generate identity`

Not yet implemented -- specification only, to fold into `docs/reference/mtsc-cli-plan.md`'s
still-open `generate identity` design question.

```
mtsc generate identity --serial <S> --model <M> --size <N> --unit <U> --bus <B> [--target <SOFTWARE-ID>] [--keys <path>] [--count <N>]
```

| Flag | Required? | Meaning |
|---|---|---|
| `--serial` `--model` `--size` `--unit` `--bus` | required | Same meaning as `check` -- the known real device parameters |
| `--target <SOFTWARE-ID>` | optional | If given: check feasibility and recover an identity for this one specific target. If omitted: enumerate all 2048 reachable IDs for the given serial/model/size and cross-check against every entry in `--keys` |
| `--keys <path>` | optional (default `./keys.toml`) | Only meaningful when `--target` is omitted -- what to cross-reference the 2048 candidates against |
| `--count <N>` | optional (default `1`) | With `--target`: how many distinct valid identities to return (`0` = exhaust all combinations in the searched 65,536-value window). Without `--target`: how many `keys.toml` matches to find among the 2048 candidates before stopping (`0` = check all 2048, report every match) |

No `--threads`/`--from` needed (unlike `generate serial`) -- the search space here is
small enough that this is effectively instant single-threaded, not a long-running
brute-force job.

**Design decisions already settled by the analysis above:**
- Search only the last 2 bytes of `identity` (first 8 fixed at zero) -- proven
  sufficient (`P(miss) ≈ 1.3e-14` within 65,536 tries), avoids ever needing to reason
  about the full, intractable 80-bit space.
- Every found identity is functionally equivalent to every other for the same target --
  no need to search for "the" identity a real device actually used, any one that
  satisfies the `mbr_val` constraint works identically for licensing purposes.
- Self-verification requirement (consistent with this project's existing rule for
  `search`): whatever identity is returned should be re-run through the same
  `check`-equivalent logic to confirm it reproduces the target exactly before being
  reported, not just trusted from the `mbr_val` arithmetic alone.

## Applied to the pending `NU4C-KK1L` case -- result: mathematically unreachable

Ran the feasibility check (§"Why this is cheap") directly against `NU4C-KK1L`
(`serial=075583791106`, `model="TOPSSD DiskOnModule"`, `size=255328256` bytes), using
real `sid_lo`/`sid_hi` values from `ros-serialgen check` (not reimplemented by hand) --
tried both bus assumptions:

| Bus | `sid_lo` / `sid_hi` | `required_mix` | Divisible by `0x3FF800F`? | Feasible? |
|---|---|---|---|---|
| `ide` | `0x8A0F87DF` / `0xFD` | 824817673895 | No (remainder 49813039) | **No** |
| `scsi` | `0x5C3DFC3B` / `0x29` | 89603218755 | No (remainder 56610570) | **No** |

**Neither bus assumption is feasible** -- proven, not just "not found after searching."
No identity, out of all `2^80` possible, can make this exact `serial`/`model`/`size`
combination hash to `NU4C-KK1L`, under either bus interpretation. This is strong
evidence the reported `serial`/`model`/`size` for this device (sourced from a 2011 forum
post, see `keys.toml`'s comment on this entry) is wrong, incomplete, or imprecisely
transcribed -- not that the device belongs in the "no local recomputation" category like
`XU4M-NJ40` (that would still allow local computation in principle, just not for *this*
specific input). Recorded in `memory/project_topssd_dom_identity_pending.md`.

**Still open:** which part of the reported disk info is actually wrong (exact model
string capitalization/spacing, exact byte count vs. the CHS-derived approximation used,
or something else entirely) -- not yet narrowed down. `W5EY-LHT9`'s equivalent check
(`serial=00000000000000000001`, `model="VMware Virtual IDE Hard Drive"`,
`size=1073479680` bytes) has not yet been run.

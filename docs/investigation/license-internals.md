# SOFTWARE ID and MBR Deep Dive

Detailed analysis of the SOFTWARE ID computation, MBR license structure, and the collision search principle. Based on reverse engineering of the RouterOS 7.23.2 keyman binary.

---

## 1. Three-Layer Licensing Architecture

```
+-------------------------------------------------------------------+
|                    License Verification Layer                      |
|                                                                    |
|   Disk params (serial, model, size) --+                            |
|                                       +--> SOFTWARE ID             |
|   MBR identity region (0x100-0x109) --+        |                   |
|                                                v                   |
|                                    KCDSA signature (0x110-0x14F)   |
|                                                |                   |
|                                                v                   |
|                                    RouterOS built-in public key    |
|                                    verifies signature at boot      |
+-------------------------------------------------------------------+
```

- **Identity layer**: Disk hardware parameters + MBR seed compute a unique SOFTWARE ID
- **Signature layer**: EC-KCDSA over Curve25519; proves this SOFTWARE ID holds a valid license
- **Verification layer**: RouterOS embedded public key validates the signature on every boot

---

## 2. MBR License Region Structure

Within the first disk sector (512 bytes), offsets `0x100-0x14F` form the 80-byte license region:

```
Offset       Size   Field                   Role in Licensing
-----------  -----  ----------------------  ------------------------------------------
0x100-0x109  10B    Identity seed           Input to MBR mixing phase of SOFTWARE ID
0x10A-0x10B   2B    License marker          Must be BD E8; installer resets to FF FF
0x10C-0x10F   4B    Boot counter            Incremented by RouterOS each boot; no effect
0x110-0x14F  64B    KCDSA digital signature Core license proof
```

### Independence of Identity and Signature Regions

The two functional regions serve different purposes and are independent:

```
+-- Identity (0x100-0x10F) ---+     +-- Signature (0x110-0x14F) ---+
|                              |     |                               |
|  Affects SOFTWARE ID         |     |  Proves license validity      |
|  Variable per machine        |     |  Binds to SOFTWARE ID only    |
|  Auto-generated on key import|     |  Fixed for a given SOFTWARE ID|
+------------------------------+     +-------------------------------+
```

Experimental evidence (see [experiments.md](experiments.md)):

| Config | Identity (0x100-0x10F) | Signature (0x110-0x14F) | SOFTWARE ID |
|---|---|---|---|
| 6G | `00...BD E8...` | `E67A8F47...` | TI09-7WK3 |
| 42G | `F0A25846...` | `E67A8F47...` (same) | TI09-7WK3 |
| 8G | `48065595...` | `080342D3...` | 4MZF-SFTR |
| 16G (collision) | `00...BD E8...` | `080342D3...` (same) | 4MZF-SFTR |

The signature is reusable across any disk configuration that produces the same SOFTWARE ID.

---

## 3. SOFTWARE ID Computation

### 3.1 Input Preparation

| Input | Source | Size | Charset / Encoding |
|---|---|---|---|
| serial | ATA IDENTIFY or QEMU `serial=` | 20 bytes | `[0-9A-Za-z-]` |
| model | ATA IDENTIFY or QEMU `model=` | 16 bytes | `[0-9A-Za-z- ]`, space-padded right |
| sector_val | `total_sectors >> 11`, rounded | 4 bytes | uint32 LE |
| mbr_10 | MBR[0x100:0x10A] | 10 bytes | raw binary |

SHA-256 input buffer = `serial(20) || model(16) || LE32(sector_val)` = 40 bytes.

### 3.2 Four-Phase Computation

**Phase 1: Hardware fingerprint**

```
buf[40]  = serial[20] || model[16] || LE32(sector_val)
digest   = MikroTik_SHA256(buf)
hash_lo  = digest[0:4] as LE uint32
hash_hi  = digest[4] | 0x100
```

**Phase 2: MBR mixing**

```
sha_val  = MikroTik_SHA256(mbr_10)[0:2] as LE uint16
chksum   = bitwise_NOT(sum_of_5_LE_uint16(mbr_10)) & 0xFFFF
mbr_val  = (sha_val XOR chksum) & 0x7FF        // 11 bits effective
mix      = mbr_val * 0x3FF800F                  // expanded to 43 bits
```

**Phase 3: Combination**

```
final_lo = hash_lo XOR mix_lo
final_hi = hash_hi XOR mix_hi
final    = (final_hi << 32) | final_lo
```

**Phase 4: Encoding**

```
SOFTWARE_ID = Base35Encode(final)
Alphabet: TN0BYX18S5HZ4IA67DGF3LPCJQRUK9MW2VE
Output format: XXXX-XXXX (hyphen at position 4)
```

### 3.3 MikroTik SHA-256 Constants

Standard SHA-256 structure (64-round Merkle-Damgard) with custom IV and K:

```
IV = { 0x5B653932, 0x7B145F8F, 0x71FFB291, 0x38EF925F,
       0x03E1AAF9, 0x4A2057CC, 0x4CAF4DD9, 0x643CC9EA }

K[64] = { 0x0548D563, 0x98308EAB, 0x37AF7CCC, ... }
```

Full K table: identical to `MIKRO_SHA256_K` in MikroTikPatch `mikro.py`.

### 3.4 sector_val Rounding Rule

Disk size is lossily compressed to reduce sensitivity to exact sector counts:

```
raw        = total_sectors >> 11
bits       = highest_set_bit(raw)
if bits <= 4:
    sector_val = raw
else:
    shift = bits - 4
    sector_val = ceil(raw / 2^shift) * 2^shift
```

Examples:

| Disk Size | Total Sectors | raw (>>11) | sector_val | Hex |
|---|---|---|---|---|
| 6G | 0xC00000 | 0x1800 | 0x1800 | Already aligned |
| 8G (7.38 GiB) | 0xEBFD10 | 0x1D7F | 0x1E00 | Rounded up |
| 64G | 0x7740AB0 | 0xEE81 | 0xF000 | Rounded up |

### 3.5 Binary-Level Verification

Sections 3.2-3.4 were re-verified directly against `tools/bin/keyman_x86_7.23.2` (ELF 32-bit LSB, Intel 80386, stripped) via raw byte search + `objdump -d` disassembly, rather than relying solely on repeated real-hardware test results. Every value below cites the actual file offset / instruction.

**SHA-256 constant tables -- exact byte match**

Searching the binary for the IV and round-constant words (as little-endian byte sequences) finds them contiguous in `.rodata`:

| Constant | File offset | Runtime VMA |
|---|---|---|
| `IV[0] = 0x5B653932` | `0xc7e0` | `0x080547E0` |
| `IV[1] = 0x7B145F8F` | `0xc7e4` | `0x080547E4` |
| `K[0] = 0x0548D563` | `0xc800` | `0x08054800` |
| `K[1] = 0x98308EAB` | `0xc804` | `0x08054804` |

(`VMA = file_offset + 0x08048000`, confirmed by cross-checking against the `.rodata` section's own VMA range from `objdump -h`.) The disassembly loads these addresses directly: `movl $0x80547e0, %esi` / `movl $0x8054800, %edi` at the entry of the compression-round function.

**Round function -- rotate amounts match `Σ0/Σ1/σ0/σ1`**

The compression loop uses `rorl $0x6` / `rorl $0xb` / `roll $0x7` (`roll 7` == `rotr 25`) for `Σ1(e)`, and `roll $0xe` (`rotr 18`) / `rorl $0x7` / `shrl $0x3` for `σ0`, matching `sha256.rs`'s `rotate_right(6/11/25)` and `(7/18/3)` exactly.

**`mbr_val` formula -- confirmed instruction-by-instruction**

A dedicated function calls the SHA-256 wrapper with `ecx=0xa` (10 bytes -- the `mbr_10` identity seed), then:

```asm
movzwl -0x28(%ebp), %esi   ; esi = digest[0:2] as u16  (sha_val)
testl  %esi, %esi
jne    skip
movl   $0x1eef, %esi       ; if sha_val == 0, substitute 0x1EEF (undocumented edge case)
skip:
movl   %ebx, %eax
calll  <checksum_fn>       ; 0x804bf80
xorl   %esi, %eax          ; mbr_val_16 = sha_val XOR chksum
```

The checksum function at `0x804bf80` reads five little-endian `u16` words, sums them, and returns `~sum & 0xFFFF` (short-circuited to `0xFFFF` directly if every word is zero -- numerically a no-op, since `~0 & 0xFFFF` is `0xFFFF` anyway). This is exactly `chksum = NOT(sum_of_5_LE_uint16(mbr_10)) & 0xFFFF` from 3.2, confirmed opcode-by-opcode rather than inferred.

**SOFTWARE ID input buffer -- confirmed 40-byte layout**

At `0x8050a9b`: `movl $0x28, %ecx` (0x28 = 40) immediately precedes a call to the SHA-256 wrapper -- this is the SOFTWARE ID hash from 3.1/3.2. Walking backward from this call, two NUL-to-space sanitization loops bound the buffer:

```
offset 0x00-0x13 (20 bytes): first loop bound  -- the serial field
offset 0x14-0x23 (16 bytes): second loop bound -- the model field
```

i.e. the buffer is laid out as `serial[20] || model[16]` starting at offset 0, immediately followed by `sector_val` to reach 40 bytes total -- an exact match for `main.rs`'s `SERIAL_LEN=20`, `MODEL_LEN=16`, `INPUT_LEN=40`, and field order. The model truncation documented in 3.1 is not a limitation of this project's tooling; it is the fixed size of keyman's own on-stack buffer, visible directly in its machine code.

A related debug format string found in the binary confirms the same field widths independently of the disassembly: `"%s: hdd-model='%.16s' s='%.20s' sz=%d MB"` -- `%.16s` for model, `%.20s` for serial.

**Empirically confirmed on a real VM**: PVE VM running the ER1G-WVEL MBR (2G, `serial=00000000000000000001`) was booted twice -- once with `model=VMware Virtual IDE Hard Drive` (29 chars) and once with `model=VMware Virtual I` (the 16-char truncation) -- both produced an identical `/system license print` result. This matches the disassembly's prediction exactly: bytes past the 16th are read from the disk's IDENTIFY response but never copied into keyman's hash input buffer, so they cannot affect the SOFTWARE ID.

### 3.6 marker and reserved: generated from identity, not just checked

Sections 3.1-3.5 establish that `mbr_val` (used in the SOFTWARE ID hash) is computed from the 10-byte identity alone (`0x100-0x109`) -- marker (`0x10A-0x10B`) and reserved (`0x10C-0x10F`) are never fed into that hash. Two real-VM tests confirmed marker/reserved still matter for validation even though they don't affect the SOFTWARE ID: taking a known-good MBR (HCC0-4FJR's real identity + real signature) and changing only marker (to `FFFF`) or only reserved (to `DEADBEEF`) both broke validation -- `/system license print` still showed the *correct* `software-id: HCC0-4FJR` (proving the hash truly doesn't use these bytes), but fell back to a 24-hour trial (`expires-in`) in both cases.

The disassembly explains why. The "key import" code path (`RouterOS decodes the key text ... generates the identity region`, §4 below) contains this sequence, found by tracing callers of the `mbr_val` function from 3.5:

```asm
movl  $0x0, 0xc(%eax)      ; reserved (0x10C, 4 bytes) := 0
calll 0x804f490            ; compute (sha_val XOR chksum) from the 10-byte identity -- same
                            ; computation as mbr_val, but the caller has NOT yet applied &0x7FF
movw  %ax, 0x10a(%esi)     ; write the raw *unmasked* 16-bit result directly to marker (0x10A)
```

So marker isn't an independent value or a fixed magic constant -- **it's the very same identity-derived hash used for `mbr_val`, just written out in full (16 bits) instead of masked down to 11 bits (`& 0x7FF`) for the mix.** `mbr_val = marker & 0x7FF`. reserved is unconditionally zeroed by this same code path, which is why it's `00000000` in every example seen so far.

This can be verified independently of the disassembly, using only the (already public) mbr_val formula from 3.2, computing the full unmasked value and reading it back as a little-endian 16-bit word:

```python
raw_value = sha_val ^ chksum   # same as mbr_val's inputs, but skip the "& 0x7FF"
marker    = raw_value.to_bytes(2, 'little')
```

Checked against every known real-device identity in this project:

| Device | identity-derived raw value | predicted marker (LE) | actual marker | match |
|---|---|---|---|---|
| standard (all-zero) | `0xE8BD` | `BDE8` | `BDE8` | yes |
| HHJH-UFWL | `0x7EFA` | `FA7E` | `FA7E` | yes |
| TI09-7WK3 | `0x9864` | `6498` | `6498` | yes |
| ZJ3M-ESHW | `0x0875` | `7508` | `7508` | yes |
| ER1G-WVEL | `0x53D3` | `D353` | `D353` | yes |
| 4MZF-SFTR | `0x42A4` | `A442` | `A442` | yes |

[Two rows for `WUB2-EYCK` and `HCC0-4FJR` have been removed per project policy -- see `AGENTS.md`.]

6 of 6 remaining rows match exactly (a full 16-bit exact match by chance has probability 1/65536 per device -- six independent exact matches rules out coincidence). 4MZF-SFTR's row was corrected after the original recorded data (`identity=...055A`, `marker=4442`) turned out to compute a completely different SOFTWARE ID (`1EGG-HMKR`, not `4MZF-SFTR`) when boot-tested on a real VM -- a transcription error from this project's earliest phase (Experiment 1's "five parameter sets from a forum post", see `experiments.md`), not a formula exception. Brute-forcing the 2048 possible `mbr_val` values against the target SOFTWARE ID (keeping serial/model/size fixed) found the one value that works, then searching single-hex-digit edits of the recorded identity found the fix (`A` misread as `5` in one position, and separately as `4` in the recorded marker) -- confirmed on a real VM after correction.

HCC0-4FJR remains the sole confirmed exception -- from this project's earliest phase as well, but (unlike 4MZF-SFTR) independently boot-verified multiple times as a real, working license with marker `BDE8`, so it isn't a transcription error. The most plausible explanation is that it was licensed by an older RouterOS/keyman version whose key-import routine derived marker differently, while the SOFTWARE ID hash itself (which every license, old or new, must still satisfy to keep working) stayed stable across versions. This isn't confirmed, just the most plausible explanation given the available evidence -- flagged here rather than asserted.

Practical implication: when writing an MBR for a real-device signature (§6 below / `docs/automated-install.md`), write `marker`/`reserved` exactly as captured from that device -- `BDE800000000` is simply what the formula produces for a large share of real captures (and for the standard all-zero collision-search identity), not a fixed constant every device is guaranteed to share. One of eight known real devices in this project proves the exception.

---

## 4. Three Forms of a License

### Form 1: MBR Binary (80 bytes at disk offset 0x100)

```
0x100: 00 00 00 00 00 00 00 00 00 00 BD E8 00 00 00 00   <- fixed header
0x110: <64-byte KCDSA signature>                          <- looked up by SOFTWARE ID
```

Written via `dd` to the raw disk after installation.

### Form 2: Key Text File

```
-----BEGIN MIKROTIK SOFTWARE KEY------------
...
-----END MIKROTIK SOFTWARE KEY--------------
```

Imported via `/system license import file-name=license.key`. RouterOS decodes the key text, generates the identity region from current disk parameters, and writes the full 80 bytes to MBR.

### Form 3: RouterOS Display

```
/system license print
  software-id: XXXX-XXXX
       nlevel: 6
     features:
```

### Conversion Between Forms

```
                    MTBase64Decode
Key text  --------------------------->  MBR[0x110:0x150] (64-byte signature)

                    MTBase64Encode
MBR[0x110:0x150]  ------------------->  Key text
```

MTBase64 uses the standard Base64 alphabet but with LSB-first bit ordering, differing from standard Base64.

The key text encodes only the 64-byte signature. The identity region (`0x100-0x10F`) is **not** included in the key text; RouterOS generates it automatically on import.

---

## 5. License Verification Flow

RouterOS executes this check on every boot:

```
1. Read disk serial, model, size  (ATA IDENTIFY or custom ioctl 0x80044604)
2. Read MBR[0x100:0x10A]          (10-byte identity seed)
3. Compute SOFTWARE ID            = f(serial, model, sectors, mbr_seed)
4. Read MBR[0x110:0x150]          (64-byte KCDSA signature)
5. Verify signature               using built-in Curve25519 public key
6. Pass -> nlevel: 6              Fail -> 24-hour trial mode
```

### Installer Intervention

| Offset | Before Install | After Install | Impact |
|---|---|---|---|
| 0x10A-0x10B | `BD E8` | `FF FF` | Breaks signature verification (not SOFTWARE ID) |
| 0x10C | `00` | `01` or `05` | No impact (outside identity region) |

This is why license data must be written **after** RouterOS installation.

---

## 6. Collision Search Principle

### Why It Works

The SOFTWARE ID is a ~40-bit hash. With 20 bytes of serial (160 bits of entropy), the search space vastly exceeds the output space. Finding a serial that produces one of 4 known SOFTWARE IDs is a birthday-style search with favorable odds:

```
P(match per hash) = 4 / 2^40 ~ 3.6 * 10^-12
Trials to 50% success = ln(2) / P ~ 1.9 * 10^11
At 40M hashes/sec (16 cores): ~4750 sec ~ 80 min
```

### Why MBR-Only Modification Does Not Work

The MBR identity region contributes only 11 bits to the SOFTWARE ID via `mbr_val`. With serial/model/size fixed, only 2048 distinct SOFTWARE IDs are reachable -- but those 2048 are a fixed subset of the full ~2^40 SOFTWARE ID space, not independently drawn from it. The probability that any of them equals one of N known targets is `2048 * N / 2^40`, not `N/2048`: for this project's 10 known signatures, that's `2048 * 10 / 2^40 ~ 1.9 * 10^-8` per (serial, MBR) combination -- varying only the MBR while holding serial/model/size fixed is exactly as hard as brute-forcing the full serial space (§ Collision Search Mechanism below), not a shortcut. (An earlier version of this section stated a much more optimistic `4/2048 ~ 0.2%`, which conflated "how many values are reachable" with "probability of matching a specific external target" -- corrected here.)

### Fixed MBR Header in Collision Scheme

In our collision search, `MBR[0x100:0x10A]` is set to all zeros. This fixes `mbr_val = 0x0BD` and `mix = 0x0BD * 0x3FF800F`. The entire variation comes from iterating the serial field.

---

## 7. Security Analysis

The RouterOS licensing system has three distinct security layers with vastly different strengths:

| Layer | Mechanism | Bits | Breakable |
|---|---|---|---|
| SOFTWARE ID binding | Custom SHA-256 hash | ~40 | Yes (collision search) |
| License signature | EC-KCDSA / Curve25519 | ~252 | No |
| Public key trust | Embedded in firmware | 0 (if replaced) | Yes (firmware patch) |

Our approach exploits the weakest layer (SOFTWARE ID binding) without attacking the cryptographic signature. The signature remains valid because it covers only the SOFTWARE ID, not the full set of disk parameters. This is a protocol design limitation: the signature should ideally bind to the complete hardware identity, not just its hash.

---

## 8. ARM32 keyman on virtio-scsi: a platform-specific investigation

**Status: in progress, not yet fully resolved.** This section documents an unexplained discrepancy on a different hardware/platform combination and the disassembly evidence gathered so far. It does not change any conclusion in sections 1-7, which remain fully verified on x86 IDE.

### 8.1 The discrepancy

On a separate ARM64-hardware PVE host, a RouterOS ARM64 VM (`scsihw: virtio-scsi-pci`) was configured with a known-good x86/IDE collision-search combo:

```
serial = 00000000717959548436
model  = SSD1G (via -set device.scsi0.product=SSD1G)
size   = 1 GiB
```

On x86/IDE this combo is expected to produce `4MZF-SFTR` (per `docs/collision-database.md`). On the ARM64 VM it instead produces `3X8K-8K32`.

### 8.2 What was ruled out

- **Not an MBR/signature issue**: the test disk's MBR license region was found completely blank (identity/marker/reserved/signature all zero or garbage) before any test -- simply never written. Writing the standard MBR (`00...BDE8...` + a known signature) did not change the computed SOFTWARE ID.
- **Not the `vendor` SCSI field**: with `serial`/`size` fixed, `vendor=""` vs. the QEMU default `"QEMU"` produced an identical SOFTWARE ID.
- **`product` does participate**: changing `product` from `SSD1G` to `ZZZZZZZZZZZZZZZ` (15 chars) changed the SOFTWARE ID (to `ABAH-C0JJ`), confirming the field is hashed -- but no encoding hypothesis (space/NUL padding, left/right justify, field reordering, big-endian `sector_val`, size-as-raw-MB integer) predicted both `(product, resulting id)` pairs simultaneously from pure computation.
- **Not the SHA-256 core**: the IV and round-constant tables in the ARM32 binary are byte-identical to the x86 binary (see 8.3).

### 8.3 ARM32/Thumb-2, not true ARM64

The RouterOS "arm64" install package's `keyman` binary is actually **32-bit ARMv7-A EABI5 (Thumb-2)** code (`file`: "ELF 32-bit LSB executable, ARM, EABI5 version 1"; `readelf -A`: `Tag_CPU_arch: v7`, `Tag_THUMB_ISA_use: Thumb-2`) -- not native AArch64 -- despite running on an aarch64 kernel/host. Extracted from the guest disk via host-side loop mount (no in-guest shell needed):

```bash
qemu-nbd --read-only --connect=/dev/nbd1 vm-100-disk-1.qcow2
mount -o ro,noload /dev/nbd1p2 /mnt/ros-arm64
dd if=/mnt/ros-arm64/var/pdb/system/image of=/tmp/system.squashfs bs=4096 skip=1
mount -o ro,loop -t squashfs /tmp/system.squashfs /mnt/ros-arm64-sysimg
cp /mnt/ros-arm64-sysimg/nova/bin/keyman /tmp/keyman_arm32
```

Same SHA-256 IV `{0x5B653932, 0x7B145F8F, ...}` located at file offset via `struct.pack('<I', 0x5B653932)` byte search, confirming the hash core is unchanged from x86.

### 8.4 Located the SOFTWARE-ID hash call site

Using the same technique that worked on x86 (search for the `length=40` immediate right before the call to the hash wrapper), found in ARM mode:

```asm
192cc: mov r1, r4
192d0: add r0, sp, #272    @ 0x110    ; buffer pointer
192d4: mov r2, #40         @ 0x28     ; length = 40, confirms this is the SOFTWARE-ID hash
192d8: bl 16ff8                       ; hash wrapper, itself calls the compress fn at 0x16e74
```

### 8.5 Buffer population: two candidate data paths

Immediately before the sanitization loops that fill the 40-byte hash buffer, the code branches on the result of a low-level ioctl:

```asm
19054: add r2, sp, #20
1905c: movw r1, #0x5386        ; ioctl request code 0x5386
19060: bl ioctl@plt            ; attempt: ask the block device directly
19064: cmp r0, #0
19068: bne 19098               ; failure -> fall back

; fallback path (ioctl failed):
1906c: ldr r3, [sp, #20]
19074: ldr r2, [pc, ...]       ; format string
1907c: bl snprintf             ; build a path string
19084: bl fopen                ; open a file
...                             ; then fgets + sscanf, line by line, into string objects
```

Whichever path succeeds, the resulting data is later copied (via length-prefixed `memcpy`) into the same two fixed regions and sanitized:

```asm
1923c: add r3, sp, #24
19244: mov r2, #20             ; 20-byte region: serial
1924c: ldrb r0, [r3], #1
19250: cmp r0, #0
19254: strbeq r1, [r3, #-1]    ; NUL -> ' ' (0x20)
...
19260: add r3, sp, #44         ; 0x2c
19264: mov r1, #16             ; 16-byte region: model
...                             ; identical NUL -> ' ' sanitization
```

**This confirms the buffer layout and NUL-padding convention are identical to x86** (`serial[20] || model[16]`, embedded NULs replaced with spaces) -- the field-encoding hypotheses from 8.2 were correctly ruled out; the encoding scheme itself is not the source of the discrepancy.

### 8.6 The two candidate fallback paths, both dead ends for virtio-scsi

Decoding the literal pool referenced by this code resolved what the `0x5386` ioctl and its two "fallback" branches actually are:

**Path A -- legacy USB-storage `/proc` parsing.** If `ioctl(fd, 0x5386, ...)` succeeds, the code builds the path `/proc/scsi/usb-storage/%u` (literal format string, not a generic per-driver template) via `snprintf`, `fopen`s it, and `fgets`/`sscanf`s each line for `"Serial Number: %19s"`. This is **only** ever going to exist for USB-attached storage -- for a `virtio-scsi-pci` disk this file does not exist, `fopen` returns `NULL`, and the whole primary path is abandoned.

**Path B -- NVMe passthrough.** The fallback function (`0x17764`) turned out to be **NVMe-specific**, not generic SCSI: it `sscanf`s the device's basename against `"nvme%dn%d"`, and issues `ioctl(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd)` (request code `0xC0484E41` = `_IOWR('N', 0x41, struct nvme_admin_cmd)`, confirmed by decoding the ioctl direction/size/type/nr bitfields) to run an NVMe Identify Controller command, then extracts the 20-byte Serial Number and 40-byte Model Number fields from the response (matching the NVMe spec's SN/MN field widths exactly -- not a coincidence). For a `virtio-scsi` device named e.g. `sda`, the `"nvme%dn%d"` sscanf never matches, so this path returns failure immediately without ever calling the ioctl.

**When both fail**, the code path we traced (`main.rs`-equivalent function around `0x18c00-0x18cc0`) prints `"getHardwareID: could not get disk %s info\n"` and **returns early with an error code** -- it does not fall through to compute a hash over zeroed/default buffers.

`0x5386` was decoded precisely: it is the legacy `SCSI_IOCTL_GET_BUS_NUMBER` request code (from `<scsi/scsi_ioctl.h>`; not a modern `_IOC`-encoded number, just a plain legacy constant). It returns an integer bus number into the buffer at `sp+20`, which is then substituted into Path A's `%u` in `/proc/scsi/usb-storage/%u` -- i.e. Path A's file path is not hardcoded to bus 0, it uses whatever bus number this ioctl reports for the actual device.

An exhaustive string search of the whole binary for other plausible generic-SCSI identification strings (`/proc/scsi/scsi`, `Vendor:`, `/sys/block`, `/sys/class/scsi`, `scsi_generic`, `/dev/sg`, `INQUIRY`) found **zero matches** -- `/proc/scsi/usb-storage` (Path A, section 8.6) is the *only* `/proc`-based identification string anywhere in the binary. Combined with `SCSI_IOCTL_GET_BUS_NUMBER` succeeding for essentially any SCSI-registered block device (not just literal USB storage), this makes it likely that Path A is in fact the live path for `virtio-scsi-pci` on this custom embedded kernel -- i.e. RouterOS's virtio-scsi driver registers itself under the legacy `/proc/scsi/usb-storage` procfs tree (an unusual but plausible code-reuse choice in a heavily customized kernel), and the "no other path exists" evidence outweighs the earlier assumption that Path A's naming implies it's USB-only.

If that is correct, the real unknown is no longer *which code path runs*, but **what the kernel driver itself writes into `/proc/scsi/usb-storage/<bus>`'s `Serial Number:` line** -- that string is synthesized by the kernel's block/SCSI driver, not by `keyman`, and may not be a verbatim copy of the QEMU-level `serial=` SCSI INQUIRY property (VPD page 0x80). This would fully explain the observed behavior: `product` (read via a different, still-unlocated field/mechanism) visibly affects the result, while the expected `serial` does not, because the actual hashed "serial" bytes come from whatever the kernel driver formats into that procfs line, not from what QEMU was told to report.

### 8.7 Verification blocked without dynamic tracing

RouterOS ships no interactive Linux shell in the guest (confirmed earlier in this investigation), so `cat /proc/scsi/usb-storage/<bus>` cannot simply be run from inside the VM to check what the kernel driver actually wrote there. Confirming the working hypothesis in 8.6 would require either running `keyman`/`nova` under user-mode ARM emulation (`qemu-arm-static` + `strace -f`) against a representative block device outside the guest, or finding another way to read that specific `/proc` file's contents from inside a running RouterOS ARM64 VM (e.g. a custom RouterOS package with shell access, if one exists) -- neither has been attempted yet.

### 8.8 Dynamic-tracing attempt (qemu-arm + strace)

An attempt was made to resolve 8.6/8.7 dynamically rather than statically, using `qemu-arm` (user-mode ARM emulation, available on the ARM64 PVE host) plus `strace -f` against the real `keyman` binary and its runtime dependencies extracted from the guest image.

**What worked:**

- `qemu-arm -L <sysroot>` successfully loads and runs the ARM32 `keyman`/`loader` binaries against the extracted `/lib/*.so` set, with `strace -f` transparently observing every real syscall the guest program issues (since user-mode QEMU translates each guest syscall into a real host syscall).
- `keyman` first tries to connect to a Unix-domain control socket (`/ram/novasock`) belonging to "the loader" -- RouterOS's `nova`-framework process supervisor (binary at `nova/bin/loader`, also present in the extracted image). Running the *real* `loader` binary (also under `qemu-arm`) makes this socket genuinely live, rather than needing to fake it.
- `loader` itself required a working `/dev/mtdblock0` (physical RouterBOARD flash) satisfying an ATA `HDIO_DRIVE_CMD`/`HDIO_GET_IDENTITY` probe before it would proceed past its own board-identity check -- confirmed via `strace -e inject=ioctl:retval=0` (forcing these ioctls to report success) that this check is **non-fatal** when faked: `loader` printed `STRONG FAIL: this is not equal to that` (a checksum mismatch, expected since the injected data is garbage) but continued to `scheduling service startup...` and successfully bound `/ram/novasock`.
- With the real `loader` alive and `/ram/run` created, `keyman` connects, exchanges an initial handshake (`sendmsg` of a 27-byte `nv::message`-framework packet), and blocks in `ppoll()` waiting for `loader`'s reply.

**Where it stopped:** `loader` never sends a reply to this specific request (still waiting for it to reach full readiness, or the request type isn't handled given the earlier faked/failed board-identity check). Attempting to force progress by fault-injecting `ppoll`/`recvmsg` to report a fabricated "response ready" (via `strace -e inject`) crashes `qemu-arm` itself with an internal `SIGSEGV` -- the guest code computes jump targets/offsets from the (fabricated, garbage) message content, and without knowing the real `nv::message` wire format (a typed binary RPC protocol built on C++ template methods `message::insert<u32_array_id>`/`append<>`/`extract<>`, disassembled far enough in `libumsg.so`'s `nv::Looper::connectLoader` to confirm its shape but not its exact byte layout), no fabricated response is safe to inject.

Fully resolving 8.6/8.7 dynamically would require decoding this RPC protocol precisely enough to author a real (not fabricated) `loader`-side reply -- a substantially larger reverse-engineering effort than the static disassembly in 8.1-8.7, and was not completed.

### 8.9 Not ARM-specific: root cause confirmed via the x86 binary too

Testing on x86_64 PVE hosts confirms the same failure with `scsi0` (virtio-scsi/LSI) and `sata0` bus types -- collision-search combos verified on `ide0` do **not** reproduce there either. Disassembling `tools/bin/keyman_x86_7.23.2` (the x86 binary already used for sections 1-7) around its own `getHardwareID`-equivalent function resolves this completely, and turns 8.1-8.8's ARM findings from "likely" into confirmed:

```asm
; try the ATA-specific path first
pushl  $0x31f              ; HDIO_DRIVE_CMD -- standard Linux ATA passthrough ioctl
pushl  <fd>
calll  ioctl@plt
testl  %eax, %eax
je     <skip SCSI, use ATA IDENTIFY data>   ; ioctl succeeded -> real ATA/IDE device

; ATA ioctl FAILED (not a real ATA device) -- fall back to the SCSI-generic path:
pushl  $0x5386              ; SCSI_IOCTL_GET_BUS_NUMBER -- identical to the ARM32 code in 8.6
pushl  <fd>
calll  ioctl@plt
...
pushl  $"/proc/scsi/usb-storage/%u"   ; identical string, identical snprintf/fopen/fgets/sscanf loop
...
pushl  $"Serial Number: %19s"         ; identical format string
```

This is **byte-for-byte the same logic** as the ARM32 disassembly in 8.5-8.6 -- same `0x5386` ioctl, same `/proc/scsi/usb-storage/%u` path, same `Serial Number: %19s` format, and the same `0x80041272` (`BLKGETSIZE64`) constant elsewhere in the function. It is shared source code compiled for both architectures, not an ARM-specific quirk.

The dispatch logic is now fully explained: `HDIO_DRIVE_CMD` (`0x31f`) only succeeds against a real ATA/IDE device (`/dev/hd*`, or a QEMU `ide0`-attached disk). Any disk exposed through the Linux SCSI subsystem instead (`/dev/sd*` -- `scsi0`, `sata0`/AHCI, and `virtio-scsi-pci` all present this way to the guest kernel) fails the ATA ioctl and falls through to the narrow `GET_BUS_NUMBER` + `/proc/scsi/usb-storage` text-parsing path from 8.6 -- which, as established there, is only ever populated for literal USB-attached storage and is not guaranteed to reflect QEMU's `serial=` property verbatim for other SCSI transports. This is a **disk-bus-type** issue, not a CPU-architecture one: it reproduces identically on x86_64/`scsi0`+`sata0` and ARM64/`virtio-scsi-pci`, and does not reproduce on `ide0` on either architecture.

### 8.10 Practical implication

**Collision-search results in this project (`docs/collision-database.md`) are only verified for `ide0`-attached disks**, and that is now known to be a hard requirement rather than an incidental detail of how the reference hardware happened to be captured: `HDIO_DRIVE_CMD` must succeed, which requires a real ATA/IDE-presented disk. `scsi0`, `sata0`, and `virtio-scsi-pci` are all confirmed **not** interchangeable with `ide0` for this purpose, on x86_64 or ARM64. **Always attach the target disk as `ide0` when applying a collision-search result.**

### 8.11 `serial=` is controllable on `scsi0` too -- confirmed empirically

The one open question from 8.6-8.9 -- whether the SCSI fallback path's `Serial Number:` value reflects QEMU's `serial=` property at all, or is synthesized by the kernel independent of it -- is resolved. Tested on the ARM64 host (`192.168.2.1`, VM 100, `scsi0`, `product=ZZZZZZZZZZZZZZZ` fixed):

| `serial=` | Resulting SOFTWARE ID |
|---|---|
| `00000000717959548436` | `ABAH-C0JJ` (reproduced across two separate boots) |
| `AAAAAAAAAAAAAAAAAAAA` | `BSW5-9EGM` |

Changing only `serial=` deterministically changes the SOFTWARE ID, and reverting it reproduces the original result exactly. **`serial=` is read and does participate in the hash on `scsi0`** -- it is not ignored or kernel-synthesized. The earlier mismatch (8.1: `product=SSD1G` expected `4MZF-SFTR`, got `3X8K-8K32`) is therefore not "serial is uncontrollable on SCSI" -- it is that the SCSI path's byte-level encoding of `serial=`/`product=` into the 40-byte hash input differs from `ide0`'s, in a way not yet reverse-engineered (padding, truncation via `%19s`, or a different field order than `serial[20] || model[16]`).

This means a **dedicated `scsi0`-targeted collision search is plausible in principle** -- unlike a scenario where the kernel discards/regenerates the identity, here the mapping is deterministic and (based on this one data point) appears to still depend on both `serial=` and `product=`. What's missing is the exact encoding rule for the SCSI path, which would need to be derived either by further disassembly of the `/proc/scsi/usb-storage` parsing/hash-input-assembly code (8.5-8.6 traced the sanitization loops but not the final byte layout used for this specific path) or by black-box probing (vary `serial=` systematically, observe the resulting SOFTWARE IDs, and infer the transform) -- neither has been done yet.

### 8.12 Found the real mechanism: `SG_IO` + standard INQUIRY + VPD page 0x80

Continuing the disassembly of `tools/bin/keyman_x86_7.23.2` around the same function (just before the `GET_BUS_NUMBER`/`/proc/scsi/usb-storage` code from 8.9) turned up a second, more legitimate SCSI-identification path that had not been located before -- and it is almost certainly the one actually responsible for the empirical result in 8.11, not the `/proc/scsi/usb-storage` text parse.

A helper function at `0x804fa51` builds a standard Linux `sg_io_hdr_t` on the stack and calls `ioctl(fd, 0x2285, &sg_io_hdr)`:

```asm
movl   $0x53, -0x58(%ebp)        ; interface_id = 'S'  (sg_io_hdr_t.interface_id)
movl   $0xfffffffd, -0x54(%ebp)  ; dxfer_direction = SG_DXFER_FROM_DEV (-3)
movb   %al, -0x50(%ebp)          ; cmd[0] = CDB opcode byte, taken from the caller's request
...
movl   $0x3e8, -0x3c(%ebp)       ; timeout = 1000 ms
pushl  $0x2285                   ; SG_IO
calll  ioctl@plt
```

`0x2285` is the standard Linux `SG_IO` ioctl (`_IOWR('S', 0x85, sg_io_hdr_t)`) -- this is genuine SCSI-generic passthrough, not the ARM32 `NVME_IOCTL_ADMIN_CMD` (`0xc0484e41`) that was initially (and incorrectly) suspected to be the same thing in early ARM32 analysis.

The caller invokes this wrapper twice with different CDB values:

```asm
movl   $0x12, -0x2a0(%ebp)       ; CDB = 0x00000012 -> opcode 0x12 (INQUIRY), EVPD=0  (standard inquiry)
...
calll  0x804fa51                 ; -> vendor/product/revision (this is where "product" comes from)
...
movl   $0x800112, -0x2a0(%ebp)   ; CDB bytes (LE) = 12 01 80 00 -> opcode 0x12, EVPD=1, page=0x80
...
calll  0x804fa51                 ; -> Unit Serial Number VPD page (this is where "serial" comes from)
```

`INQUIRY` with `EVPD=1, page=0x80` is the standard SCSI "Unit Serial Number" VPD page -- exactly the mechanism QEMU's `scsi-hd`/`virtio-scsi-pci` backend uses to expose the `serial=` device property to the guest. This is consistent, deterministic, and guest-kernel-independent (unlike the `/proc/scsi/usb-storage` text file, which depends on which kernel subsystem happens to register the device there) -- it directly explains why 8.11's black-box test found `serial=` to be reliably controllable.

**The VPD-80 extraction logic was fully traced and matches the standard SCSI VPD-80 wire format exactly:**

```asm
movb   -0x21d(%ebp), %al   ; al = response[3]  -- VPD page's "page length" byte (offset 3)
cmpb   $-6, %al             ; clamp to 0xFA (250) as a safety cap
jbe    ...
movzbl %al, %esi            ; esi = clamped length
xorl   %ebx, %ebx           ; ebx = index, starts at 0
; loop:
movzbl -0x21c(%ebp,%ebx), %eax   ; response[4+i]  -- first byte of VPD-80's ASCII serial payload
pushl  %eax
calll  isprint@plt
testl  %eax, %eax
je     <break>               ; stop at the first non-printable byte
incl   %ebx
jmp    <loop>
; after loop: ebx = count of leading printable bytes (<= page-length byte, <= 250)
```

This is byte-for-byte the standard T10 VPD page 0x80 layout (`peripheral qualifier/type` (1) + `page code=0x80` (1) + reserved (1) + `page length N` (1) + N bytes of ASCII serial number starting at offset 4) -- the code takes the ASCII payload starting right after the 4-byte VPD header, and copies out the printable-prefix run (bounded by both the page-length byte and a 250-byte safety cap). For QEMU's `serial=` property (which populates this exact VPD-80 payload for `scsi-hd`/`virtio-scsi-pci`), an all-printable-ASCII value like a 20-character serial should therefore be captured in full and unmodified -- consistent with 8.11's clean, deterministic `serial=` -> SOFTWARE-ID mapping.

**The standard-INQUIRY (non-EVPD) result feeds "model"** via a *fixed*-length copy (`0x10` = 16 bytes, no `isprint()` trimming) from response offset 16 -- exactly the standard SCSI INQUIRY "Product Identification" field (bytes 16-31 of the standard 36-byte INQUIRY response). QEMU's `product=` property populates this field, space-padded per the T10 spec, so this is also expected to be a clean, direct copy.

**Precedence resolved:** `GET_BUS_NUMBER` + `/proc/scsi/usb-storage` (8.9) *is* attempted unconditionally, immediately after the two `SG_IO` calls, regardless of whether they succeeded -- but its result is only *used* as a last resort:

```asm
movl   %esi, %eax     ; esi was set by the SG_IO VPD-80 call: 1 = ioctl succeeded, 0 = failed
testb  %al, %al
jne    0x80509fd       ; VPD-80 succeeded -> jump straight to finalization with the SG_IO-derived
                        ; serial/product, discarding whatever /proc/scsi/usb-storage parsed
; only reached if VPD-80 FAILED:
calll  0x804fac1        ; a third, distinct identification routine (not yet traced) -- its result
                         ; is what actually gets used when SG_IO is unavailable
```

So the real priority order is: **`SG_IO` (standard INQUIRY + VPD-80 Unit Serial Number) wins whenever it succeeds; `/proc/scsi/usb-storage` text parsing and a third fallback routine at `0x804fac1` are only consulted if `SG_IO` fails outright** (e.g. permission denied on the device node, or the backend doesn't implement SCSI-generic passthrough). For `virtio-scsi-pci`/`scsi-hd` under QEMU -- both of which do support `SG_IO` -- this means 8.12's clean INQUIRY+VPD-80 mechanism is expected to be the one actually in effect, matching 8.11's clean empirical result. This resolves the open precedence question and gives high confidence that the "20-byte printable-ASCII prefix of the VPD-80 payload" and "16-byte raw copy of the standard INQUIRY Product ID field" rules in this section are the real `scsi0` encoding -- a dedicated `scsi0` collision-search implementation is the natural next step, not further disassembly.

### 8.13 `0x804fac1` traced: it's the same NVMe fallback as ARM32, confirmed identical

`0x804fac1` -- the "third fallback", only reached when the `SG_IO` VPD-80 call fails outright -- turns out to be **the exact same NVMe-specific mechanism already documented for ARM32** (§8.1-8.4's `keyman_arm32` analysis), not a new, distinct code path. Confirmed byte-for-byte:

```asm
movb   $0x6, -0x1060(%ebp)       ; cmd_len = 6 (NVMe admin-command CDB-style length)
pushl  $0xc0484e41                ; NVME_IOCTL_ADMIN_CMD -- identical constant to the ARM32 binary
movl   $0x1000, -0x103c(%ebp)     ; 4096-byte response buffer (NVMe Identify Controller response size)
calll  ioctl@plt
je     <process NVMe Identify response>   ; ioctl succeeded -> use it directly

; only reached if the ioctl on the ORIGINAL fd fails:
calll  basename@plt
pushl  $"nvme%dn%d"                ; sscanf the device basename against this pattern
calll  sscanf@plt
...                                 ; if it matches, open "/dev/nvme<N>" and retry the same
                                     ; NVME_IOCTL_ADMIN_CMD ioctl against that controller node
```

And the response parsing confirms the same field widths as ARM32's NVMe path:

```asm
strnlen(buf_at_offset_20, 0x28)   ; 0x28 = 40 -- NVMe "Model Number" field width
strnlen(buf_at_offset_0,  0x14)   ; 0x14 = 20 -- NVMe "Serial Number" field width
```

This is genuinely shared, cross-architecture source code (as expected, given 8.9's confirmation for the `SG_IO`/`GET_BUS_NUMBER` paths) -- there is no separate, not-yet-found x86-specific fallback. **The complete, now fully-traced hardware-identification priority chain for `keyman`/`nova`, across both architectures:**

| Priority | Mechanism | Bus types it actually works for | Source of `serial`/`model` |
|---|---|---|---|
| 1 | `ioctl(HDIO_DRIVE_CMD)` (`0x31f`) | `ide0` (real ATA/IDE) | Real ATA IDENTIFY data -- ground truth for this project's collision database (§1-7) |
| 2 | `ioctl(SG_IO)` (`0x2285`): standard INQUIRY + EVPD page 0x80 | `scsi0`, `sata0`/AHCI, `virtio-scsi-pci` -- anything with working SCSI-generic passthrough | Product ID field (16B, raw) + VPD-80 printable-ASCII prefix (up to 20B) -- §8.12, confirmed to track QEMU's `serial=`/`product=` |
| 3a | `SCSI_IOCTL_GET_BUS_NUMBER` (`0x5386`) + `/proc/scsi/usb-storage/<bus>` text parse | Literal USB-attached storage only | `Serial Number: %19s` line -- §8.6, only used if priority 2 fails |
| 3b | `NVME_IOCTL_ADMIN_CMD` (`0xc0484e41`) via basename match `nvme%dn%d` | NVMe devices (`/dev/nvme0n1` etc.) | NVMe Identify Controller SN (20B)/MN (40B) fields -- this section, only used if priority 2 fails |

Priorities 3a and 3b are tried in an unspecified order relative to each other when priority 2 fails (not yet determined which is attempted first), but neither applies to `scsi0`/`sata0`/`virtio-scsi-pci` disks in practice, since those support `SG_IO` and priority 2 wins before either is reached.

### 8.14 SCSI collision search works for SOFTWARE ID -- but the license still doesn't validate

The `--bus scsi` encoding from 8.11-8.13 (`sector_val=0`, standard `serial[20]+model[16]` layout) was implemented in `mtsc` and run as a real search (see `docs/command-reference.md` for the `-b`/`--bus` flag). It found genuine hits -- e.g. `serial=00000000430480281048`, `model=SSD1G`, `size=1G`, `--bus scsi` computes `C7CU-PGT9`, matching this project's known signature exactly. Booting this combo on a real `scsi0` VM confirmed `software-id: C7CU-PGT9` on `/system license print`, proving the SOFTWARE ID side of 8.11-8.13 is correct and the SCSI-specific search is genuinely usable for finding *matching SOFTWARE IDs*.

**However, writing `C7CU-PGT9`'s known-good MBR (`00...BDE800000000` + its signature) to the standard file offset `0x100` and rebooting did not activate the license** -- `/system license print` kept showing the SOFTWARE ID correctly but stayed in 24-hour trial mode (`expires-in`) instead of `nlevel: 6`. Ruled out:

- **Not the boot-counter (`reserved`, `0x10C-0x10F`) incrementing.** RouterOS bumped it from `00000000` to `01000000` after the first boot, matching documented behavior (§5's installer-intervention table) and consistent with §3.6's finding that `reserved`/`marker` don't affect the SOFTWARE ID computation. Explicitly resetting `reserved` back to `00000000` and rebooting again made no difference -- still trial mode.
- **Not ARM64-specific.** The same failure to activate (correct SOFTWARE ID, signature doesn't validate) was independently observed on an x86_64 host with a `scsi0`-attached disk as well.

Since this reproduces identically across architectures and is unaffected by `reserved`, the most likely explanation -- not yet confirmed by disassembly -- is that **license *signature validation* (reading the MBR license region at boot, independent of the `serial`/`model` identification code traced in 8.1-8.13) may also be bus-type-dependent**, e.g. not reading from the standard file offset `0x100` at all for SCSI-attached disks, mirroring the same pattern already found for `serial`/`model` reads. This has not been investigated -- 8.1-8.13 only trace how `serial`/`model`/`sector_val` become the SOFTWARE ID input; the boot-time MBR-read/signature-verify code path (§5's "License Verification Flow") is a distinct, not-yet-disassembled part of `keyman`/`nova`.

**Practical implication:** a `--bus scsi` search can currently find a serial whose *computed SOFTWARE ID* matches a known signature (useful for research, and confirmed accurate), but **does not yet result in an activatable license** on `scsi0`/`sata0`/`virtio-scsi-pci` -- full activation on those bus types remains unsolved pending disassembly of the MBR-read path used during boot-time signature verification.

### 8.15 Found it: on QEMU/KVM, `readMBR` doesn't touch the disk at all -- it uses `/dev/hvckvm0`

Disassembling `readMBR`'s internals resolves 8.14. `readMBR` first calls a cached predicate (`0x804f902`) that is **byte-for-byte the same `getenv("board")` + `strstr(..., "qemu")` check already found on ARM32** (§8.9's virtualization-detection function) -- confirming this is shared, cross-architecture logic, not something new.

When that predicate is true (i.e. running under QEMU/KVM, which covers essentially every PVE VM), `readMBR` skips the physical-flash path (`/dev/flash` + custom `0x4601`/`0x90004602` ioctls, for real RouterBOARD hardware) entirely and instead:

```asm
calll  0x804f76f            ; a second, more specific gate check
testb  %al, %al
je     <fail>                ; bail out if false

pushl  $2                     ; O_RDWR
pushl  $"/dev/hvckvm0"        ; MikroTik-private hypervisor virtual console device
calll  open@plt
...
calll  tcgetattr@plt          ; configure it as a raw terminal (no echo, no canonical mode, etc.)
calll  tcsetattr@plt
...
; later, via 0x804f9a0(fd, cmd=6, len=0x208):
write(fd, {len=8, cmd=6}, 8)  ; send an 8-byte request: "read command 6"
read(fd, buf, 0x208)           ; read back a 520-byte response (512-byte sector + 8-byte header?)
```

`/dev/hvckvm0` ("hvc" = hypervisor virtual console, the standard Linux paravirtualized-console naming convention used by Xen/KVM `virtio-console`) is a **MikroTik-private device node, not a standard block device**. This means: **on any QEMU/KVM-detected VM, `readMBR` never reads the guest disk file at all** -- it sends a small request over this console channel and expects a companion process (presumably MikroTik's own CHR-specific QEMU integration, or a host-side helper backing this virtio-console) to respond with sector data. Writing directly to the disk image via `qemu-nbd` (as done throughout this project, including 8.14's failed activation attempt) **never touches whatever `/dev/hvckvm0` actually returns** -- these are two completely independent data paths.

This fully explains 8.14's mystery without needing any further bus-type-dependent hypothesis: the MBR write itself was never going to be read back by a standard PVE VM, because standard PVE VMs almost certainly don't provide a working `/dev/hvckvm0` backend (this is CHR/MikroTik-cloud-image-specific QEMU integration that a plain `qm create`-built VM has no reason to implement). Whether `open("/dev/hvckvm0")` succeeds or fails inside our test VMs, and if it fails, what `readMBR` falls back to (if anything), has not yet been checked -- this is the next concrete step, and does not require any more static disassembly to investigate (it's a runtime/environment question: does `/dev/hvckvm0` exist in the guest, and if not, does `readMBR` have any further fallback beyond this one already-traced branch).

### 8.16 `/dev/hvckvm0` traced further: it's the standard Linux `hvc0` virtio-console driver, self-provisioned, with no fallback on failure

The gate function `0x804f76f` was disassembled and resolves the remaining questions in 8.15:

```asm
cmpb   $0x0, <cached_flag>
je     <compute>
retl                               ; return cached result on repeat calls

; first call:
pushl  <stat_buf>
pushl  $"/dev/hvckvm0"
calll  stat@plt
testl  %eax, %eax
jne    <not_found>                 ; stat failed -> device node doesn't exist yet
movb   $1, <cached_ok_flag>        ; already exists -> success, done
...
<not_found>:
pushl  $"r"
pushl  $"/sys/class/tty/hvc0/dev"
calll  fopen@plt
testl  %eax, %eax
je     <fail>                       ; sysfs entry doesn't exist either -> give up (cached_ok_flag stays 0)
...
fscanf(fp, "%u:%u", &major, &minor)
fclose(fp); unlink("/dev/hvckvm0")
mknod("/dev/hvckvm0", S_IFCHR|0777, makedev(major, minor))
movb   $1, <cached_ok_flag>
```

`hvc0` ("Hypervisor Virtual Console") is a **standard upstream Linux kernel driver** (`CONFIG_HVC_DRIVER`), used for Xen PV consoles and `virtio-console` devices -- it is not a MikroTik invention. `/sys/class/tty/hvc0/dev` is the normal sysfs path any Linux kernel exposes for a registered `tty` device's `major:minor`, used here purely to self-provision the `/dev/hvckvm0` node (since a CHR image's minimal `/dev` may not have it pre-populated by udev). The logic reduces to: **"does this VM have a `virtio-console` (or Xen console) device attached to the guest?"** -- if yes, use it as the MBR data channel; if no, `readMBR` returns failure with **no further fallback** on this code path.

Standard PVE VMs created via `qm create`/`qm set` (including every VM used in this session, and almost certainly the historical `ide0` VMs behind this project's verified collision-database entries) **do not attach a `virtio-console` device by default** -- PVE's `serial0: socket` option (used throughout this project for console access) provisions an **isolated PC-style UART** (`ttyS0`/`COM1`), which is a completely different QEMU device (`isa-serial`/`pci-serial`) from `virtio-console` (`virtconsole`/`virtio-serial-bus`). Having `serial0: socket` configured does **not** make `/sys/class/tty/hvc0` appear.

This raises a real, testable question this section does not yet answer: **the project's own collision-database entries were verified as fully activated (`nlevel: 6`, no `expires-in`) on plain PVE `ide0` VMs** -- if `board` containing `"qemu"` unconditionally forces this `hvc0`-only path with no fallback, how did those succeed without a `virtio-console` device? Two explanations are consistent with the evidence so far, neither yet confirmed:

1. **The `board` environment variable's actual value differs by VM configuration** (machine type, `smbios1` overrides, BIOS vs. OVMF, etc.), and the historically-successful `ide0` VMs' `board` value happened not to contain the substring `"qemu"` -- in which case `0x804f902` returns false immediately and `readMBR` takes the `/dev/flash`-then-generic-`fopen()` path from 8.15 instead (which, being a plain file read, would work identically on `ide0` regardless of bus type).
2. **`ide0` disks are read through an entirely different, not-yet-traced license-verification code path** that doesn't share this `readMBR` function's `board=qemu` branch at all.

**Next step (empirical, no further disassembly needed):** compare `getenv("board")`'s actual value between a VM known to activate successfully on `ide0` and the `scsi0` VMs used in 8.11-8.15 -- if the `ide0` VM's value doesn't contain `"qemu"`, explanation 1 is confirmed, and the practical fix for `scsi0`/`sata0` activation becomes straightforward: override the VM's reported `board`/SMBIOS values so `"qemu"` isn't a substring, steering `readMBR` back onto the `/dev/flash`-or-generic-file-read path instead of the `hvc0`-only one.

### 8.17 Tried overriding SMBIOS to dodge `board=qemu` -- landed in a third, different detection branch (`MetaROUTER`)

To test 8.16's hypothesis directly, PVE's `smbios1` `product`/`manufacturer` fields were overridden away from the QEMU defaults (`qm set <vmid> --smbios1 uuid=<existing>,product=<base64>,manufacturer=<base64>,base64=1`, non-default values chosen to avoid the substring `"qemu"`), keeping everything else (disk, `serial=`/`product=` SCSI properties, `-b scsi` search target) identical to the already-confirmed `C7CU-PGT9` combo from 8.14.

**Result: the boot behavior changed completely, but not to the expected `/dev/flash`-fallback path.** Before the override, boot showed the normal 24-hour CHR trial banner (`software-id: ..., expires-in: 23hXXm`). After the override:

- The CLI prompt changed from `[admin@arm64]` to **`[admin@MetaROUTER]`**.
- The boot banner changed to `ROUTER HAS NO SOFTWARE KEY` with an unusual **~136-year** countdown (`1193046h27m`) instead of the normal 24-hour trial.
- `/system license print` now shows **only** `software-id: C7CU-PGT9` -- no `expires-in` line at all (neither the trial state nor a fully-activated `nlevel: 6` state).

This is RouterOS's **`MetaROUTER`** mode -- MikroTik's nested-virtualization feature where a guest router is normally expected to receive its license from a *parent* RouterOS instance rather than validating its own disk MBR, which plausibly explains why the normal trial/license flow is bypassed entirely once this mode is detected.

The trigger was located via a debug string in `lib/libumsg.so` (shared across the whole `nova` framework, not `keyman`-specific):

```
"open /dev/rb failed, probably metarouter"
```

i.e. **a third hardware-presence check**, independent of both `readMBR`'s `board`-string check (8.15-8.16) and the `/dev/hvckvm0` virtio-console path (8.15-8.16): the framework tries to `open("/dev/rb")` (a "RouterBOARD" device -- distinct from `/dev/flash` and `/dev/hvckvm0`), and if that fails, concludes "probably MetaROUTER" and apparently short-circuits the normal boot-time license flow well before `readMBR`'s own `board=qemu` branching is reached.

**Net result: changing `smbios1` did successfully steer the platform-detection logic away from `board=qemu`, but toward a different special-cased mode rather than the plain-hardware `/dev/flash`/generic-file-read path 8.16 hypothesized.** This is not yet a working activation path, and not yet a dead end either -- the open questions are:

- What exact condition triggers the `/dev/rb`-absence -> "MetaROUTER" conclusion, and is it purely `open()` failing, or does it also depend on the same `board` string (e.g. some other substring match, not just absence of `"qemu"`)?
- Does the *original* `board=qemu` value (unmodified SMBIOS) also fail `open("/dev/rb")` -- i.e. is `/dev/rb` open failing on *every* QEMU VM regardless of `board`, with `board=qemu` normally taking priority and being checked *first* (explaining why the un-modified VMs never showed `MetaROUTER` -- the `board=qemu` branch intercepted the check before `/dev/rb` was ever tried)? If so, the real fix may require a `board`/SMBIOS value that is simultaneously **not** `"qemu"`-like *and* somehow satisfies (or avoids) the `/dev/rb`-presence check -- which likely means creating an actual `/dev/rb` device node (analogous to 8.15's `/dev/flash`) rather than relying on `smbios1` alone.
- Whether `flash.ko` (a real, present kernel module in this image that also references `MetaROUTER` per the string search) is involved in provisioning `/dev/rb`, the way `hvc0`/sysfs was used to self-provision `/dev/hvckvm0` in 8.16 -- not yet disassembled.

This has not been resolved -- continuing requires disassembling `libumsg.so`'s `MetaROUTER`-detection function (the `open("/dev/rb")` caller) and `flash.ko` to determine what, if anything, would make `/dev/rb` present and change this outcome.

**Correction (per direct operator experience, not independently re-verified by feature-testing in this session):** despite the `ROUTER HAS NO SOFTWARE KEY` banner, the `1193046h27m` countdown, and the absence of `nlevel`/`expires-in` in `/system license print`, **this `MetaROUTER` state is reported to function as activated in practice** -- i.e. it is not actually feature-limited the way a genuine trial/unlicensed state is. This directly contradicts the reasoning earlier in this document (and in §8.28 below) that treated the presence of the boot-time "no software key" banner as proof of non-activation. That reasoning was a plausible inference from RouterOS's normal (non-`MetaROUTER`) behavior, generalized to `MetaROUTER` without actually testing an L6-gated feature under it -- an assumption, not a verified fact. If confirmed (see open item below), this reframes 8.17-8.18's "not yet a working activation path" conclusion entirely: the SMBIOS-override method **is** a working activation path for ARM64/`scsi0`, just with cosmetic boot messaging that looks like failure. **Still open, and confirmed as a planned follow-up (not yet done):** two competing explanations need to be tested against each other on `VM301` before this can be written up as settled:

1. A specific L6-only feature (hotspot user cap, queue count, PPPoE/PPTP concurrent session limit, or similar) is confirmed *unrestricted* under this exact `MetaROUTER` state, which would mean the SOFTWARE ID/signature combination genuinely is being honored despite the cosmetic banner.
2. `MetaROUTER`-mode guests are *categorically* exempt from license enforcement regardless of their own software-key state (i.e. license checks are delegated to/skipped for nested guests entirely), which would mean this "activation" has nothing to do with the `C7CU-PGT9` signature at all and would work identically with *any* disk, licensed or not -- a materially different (and much weaker) result for this project if true, since it wouldn't actually validate the collision-search method on ARM64.

These two explanations make different, testable predictions (explanation 2 predicts an *unsigned* or *deliberately wrong-signature* disk would show the same "activated" behavior under `MetaROUTER`; explanation 1 predicts it would not) -- that differential test is the concrete next step, not yet run.

### 8.18 Resolved on x86_64: `scsi0` activates cleanly out of the box, no SMBIOS tricks needed -- this was an ARM64/`virt`-machine-type quirk, not a SCSI limitation

A fresh, minimal-config test settles 8.9-8.17's remaining open question. A brand-new x86_64 PVE VM was built from scratch (cloned from a working RouterOS template, default `smbios1` -- **no product/manufacturer override at all**):

- `scsihw: virtio-scsi-pci`, `scsi0` disk, 1G, `serial=00000000430480281048`, `-set device.scsi0.product=SSD1G` (the exact `--bus scsi` search hit from 8.14/`C7CU-PGT9`)
- Fresh RouterOS 7.24 install directly onto the `scsi0` disk (installer run via `qm sendkey`, `a`/`i`/`y`)
- Shut down (not rebooted) per the standard MBR-write procedure, then the standard `00...BDE800000000` + `C7CU-PGT9` signature MBR written via `qemu-nbd`
- Booted once

Result: `/system license print` shows

```
software-id: C7CU-PGT9
nlevel: 6
features:
```

**Fully activated -- no `expires-in`, `nlevel: 6`, on the first boot, with zero SMBIOS manipulation.** This is the cleanest possible confirmation that the `--bus scsi` SOFTWARE-ID encoding (8.11-8.13) and the standard MBR-write activation procedure both work correctly and completely on a real `scsi0`/`virtio-scsi-pci` disk -- there is no `scsi0`-specific activation problem on x86_64.

**This reframes 8.14-8.17 entirely.** The activation failures documented there were specific to the **ARM64 test VM's `virt` QEMU machine type**, not to `scsi0`/SCSI as a bus type in general.

One assumption from 8.16-8.17 needs correcting, though: it is **not** simply "x86's DMI doesn't say QEMU." Checked directly via `/system resource print` on the working x86 VM: `board-name: x86 QEMU Standard PC (Q35 + ICH9, 2009)` -- this **does** contain `"QEMU"`, just like the ARM64 VM's `board-name: arm64 QEMU KVM Virtual Machine` did. Both platforms' *displayed* `board-name` contain the substring, yet only ARM64 hit the problem branch. This means **`keyman`'s internal `getenv("board")` value is not simply identical to the `board-name` string shown by `/system resource print`** -- they likely come from related but distinct sources (or different case-normalization), and `strstr(getenv("board"), "qemu")` is a case-sensitive C string search, so the exact casing of whatever `board` actually contains matters and has not been directly captured (no way to read `keyman`'s process environment from the RouterOS CLI).

**Root cause, now understood at the product level (not just the code level):** the ARM64 image used throughout §8 is a **non-CHR** RouterOS build -- i.e. the standard image for real RouterBOARD ARM64 hardware, not MikroTik's virtualization-oriented CHR product line (which only ships for x86_64). Running it under plain QEMU/KVM is an unsupported/incidental use case for this image, whereas x86_64 CHR is an officially supported virtualization product with its own `board=qemu` handling built in from the start. Disassembly confirms `loader` and `keyman` never call `setenv`/`putenv` for `board` -- both only `getenv()` it, meaning the value is set upstream (kernel command line / boot chain), not computed by either binary. The `MetaROUTER`/`/dev/hvckvm0` detection maze (8.15-8.17) is most plausibly infrastructure built for MikroTik's own real-hardware nested-virtualization feature (a physical RouterBOARD host running a guest RouterOS instance, where `/dev/hvckvm0` and `/dev/rb` are genuinely provisioned by the host) -- not for "RouterOS running directly under generic QEMU/KVM." On this non-CHR ARM64 image, `board` containing `"qemu"` is coincidental (or triggers a check meant for that nested-hardware scenario), and neither `/dev/hvckvm0` nor `/dev/rb` exist in our plain-QEMU setup, so it falls through to the broken states in 8.15-8.17. x86_64 avoids all of this not because of a DMI-string difference, but because it's running the **CHR** image, an entirely different, virtualization-first product build. This is the most coherent explanation available without MikroTik's source, though the exact `board` string and the code path that sets it (kernel cmdline vs. boot-chain script) has not been directly captured -- see the note in §8's introduction about checking VM300 (a disposable clone) for this if it's ever needed.

**Practical implication -- superseding 8.10's blanket warning:** `--bus scsi` search results **are** activatable, at least on x86_64 with a standard PVE-default `smbios1` (no override required). The remaining open question is narrower than previously stated: does `scsi0` activation also work on **ARM64** with a `board`/SMBIOS value that avoids `"qemu"` *and* avoids triggering the `MetaROUTER` fallback from 8.17 (e.g. a value resembling real RouterBOARD ARM64 hardware) -- this was not retested after 8.18's x86 result and remains open specifically for ARM64/`virt`, not for `scsi0` in general.

### 8.19 `sector_val=0` confirmed size-independent -- tested at 2GiB, not just 1GiB

8.11's `sector_val=0` finding was originally validated against 7 real boot tests, all on a single 1GiB disk -- leaving open whether `sector_val=0` was a genuine, size-independent property of the `scsi0` path, or coincidentally zero only for that one disk size.

Retested with a **fresh install** on a **2GiB** `scsi0` disk (same host as 8.18, same `serial=00000000430480281048`/`product=SSD1G` -- only the disk size changed): full activation succeeded identically -- `software-id: C7CU-PGT9`, `nlevel: 6`, no `expires-in`, same as the 1GiB case. Since `--bus scsi` computes the same SOFTWARE ID at 1GiB and 2GiB for the same `serial=`/`product=` (both force `sector_val=0` regardless of the actual disk size passed to `mtsc search -s`), and both independently activate against the same signature, this confirms `sector_val=0` is **not** a 1GiB-specific coincidence -- it holds across at least two different disk sizes on `scsi0`. The size caveat in 8.11-8.13's wording can be considered resolved for x86_64/`virtio-scsi-pci`.

**Practical implication: on `scsi0`, the actual disk size is irrelevant to which `serial=`/`product=` combo you need.** This is a real, useful difference from `ide0`: `ide0`'s SOFTWARE ID depends on `sector_val`, which is derived from the disk's exact byte count, so an `ide0` collision result is only valid for a disk of that *exact* size (§6, §3.4). On `scsi0`, since `sector_val` is always `0` regardless of the disk's real size, **a single `serial=`/`product=` combo found via `mtsc search --bus scsi --disk-size <any size>` will activate on a `scsi0` disk of *any* size** -- there is no need to match the search size to the deployed disk size, and no need to maintain size-specific tables the way `docs/database/collision-database.md` §2 does for `ide0`. The `--disk-size`/`--unit` flags still need *some* value when running `search --bus scsi` (they're required CLI arguments), but the resulting `serial=`/`product=` pair is size-agnostic in practice for `scsi0` deployments.

### 8.20 `sata0` is NOT like `scsi0` -- it uses the exact same encoding as `ide0`

Every prior section in §8 treats `scsi0` and `sata0` as a pair (both non-`ide0`, both assumed to share the SCSI-generic code path from §8.9/8.12). This assumption was never actually tested for `sata0` specifically -- it turns out to be wrong.

QEMU's `sata0` (AHCI) disks are backed by the **same `ide-hd` qdev device model as `ide0`**, just attached to an AHCI controller instead of a legacy PIIX/ISA IDE controller -- confirmed directly: attempting `-set device.sata0.product=<x>` (the SCSI-specific property used throughout §8.11-8.19) fails at QEMU startup with `Property 'ide-hd.product' not found`. `ide-hd` only exposes a `model=` property (the same one `ide0` uses), not `vendor=`/`product=` (which are `scsi-hd`-only). This alone strongly suggests `sata0` disks respond to ATA IDENTIFY like real IDE drives, taking `readMBR`'s `HDIO_DRIVE_CMD` success path (§8.9) rather than the `SG_IO` path.

Confirmed both algorithmically and empirically:

- **Algorithmic**: booting a `sata0` disk with `serial=00000000430480281048`/`model=SSD1G` (the SCSI-verified `C7CU-PGT9` combo from §8.14) at 2GiB showed `Current installation "software ID": EJSX-HUUP` -- a **different** ID than the `scsi0` result for the identical `serial=`/`model=` pair. Running `mtsc check --serial 00000000430480281048 --disk-size 2 --unit g --model SSD1G --bus ide` (note: `--bus ide`, not `scsi`) computes the **exact same** `EJSX-HUUP` -- confirming `sata0` uses `ide0`'s real-sector_val encoding, not `scsi0`'s `sector_val=0` encoding.
- **Empirical, with an existing `ide0` collision-database entry**: a fresh 1GiB `sata0` install using the *unmodified* `ide0` table entry (`serial=00000000251582663387`, `model=SSD1G`, `1,073,741,824` bytes -> `TI09-7WK3`, no new search needed) with the standard MBR write (`00...BDE800000000` + `TI09-7WK3`'s signature) **fully activated** on first boot -- confirming this isn't just a matching-SOFTWARE-ID coincidence, the *existing* `ide0` collision database works directly on `sata0`.

**Practical implication:** `docs/collision-database.md`'s `ide0` table (§1-2) applies directly to `sata0` disks of the same size, with no `-b scsi`/`-b ide` distinction needed and no new search required -- treat `sata0` as an alias for `ide0` for collision-search purposes, not as part of the `scsi0` SCSI-generic family. This also means `--bus ide`'s existing wording ("verified against real hardware") extends to `sata0` without qualification, while `--bus scsi` remains specific to `scsi0`/`virtio-scsi-pci` only. `docs/deployment-guide.md` and `docs/command-reference.md`'s bus-type framing (currently grouping `scsi0`+`sata0` together against `ide0`) should be corrected to reflect this.

### 8.21 Signature metadata decryption (`MT_Transform`)

Separately from the bus-type investigation above, the [MTLic project](https://github.com/Ygnecz/MTLic) (`MTTools.py`, `ParseLic.py` -- already listed in `docs/toolchain.md`) documents the internal structure of the 64-byte signature stored in `.key` files and at MBR `0x110-0x14F`:

```
signature[0:16]  -- MT_Transform-encrypted: SOFTWARE_ID(6B LE) || reserved(1B) || level(1B) || zero-padding(8B)
signature[16:32] -- XORed into a hash of the decrypted [0:16] block, used for EC-KCDSA-style verification
signature[32:64] -- the actual Curve25519 signature integer
```

`MT_Transform` is a 16-round ARX block cipher operating on the 16-byte block as four 32-bit words, using round constants -- **which turn out to be exactly this project's existing `ROUND_CONSTANTS`** (`src/sha256_constants.rs`, the MikroTik custom SHA-256 K-table): confirmed byte-for-byte identical against `MTTools.py`'s `SHA256_K`. The decrypted SOFTWARE ID's Base-35 encoding table (`MT_SWSNToSWID`'s `SWIDTab`) is likewise identical to this project's existing `software_id::encode` alphabet. No new reverse-engineered constants were needed -- both pieces were already in this codebase, just not previously connected to this use.

**What this enables:** given any known-valid signature (from `docs/collision-database.md`'s Signature Table, or extracted from a `.key` file via `key2sig`), decrypting `signature[0:16]` reveals which SOFTWARE ID and license level that signature was actually issued for -- useful for auditing/labeling signatures, independent of booting a VM. `mtsc sig2key`/`key2sig` now print this (`SOFTWARE-ID`/`VERSION`/`LEVEL`) to stderr alongside their normal output (`src/convert.rs`'s `decode_metadata`). Verified against `VI8Q-E90F`'s known signature hex (`docs/collision-database.md`): decrypts to SOFTWARE ID `VI8Q-E90F`, level `1` -- matching the real-hardware-confirmed `nlevel: 1` from §1.

**What this does NOT enable:** signing a *new* license for an arbitrary SOFTWARE ID/level still requires the Curve25519 private key corresponding to the public key used in `ParseLic.py`'s verification (`Y = signature*PubKey + hash*G`, checked via `MT_Hash(Y) == signature[16:32]`) -- an ECDLP problem, same ~252-bit hardness already established in `architecture.md` §5. This finding only explains the *structure* of an existing signature; it does not provide a way to forge one for parameters not already covered by a known-valid signature. The project's approach remains unchanged: reuse existing valid signatures via SOFTWARE ID collision search (§1-7), not signature forgery.

The `version_byte` field (byte 6 of the decrypted block) is printed as-is but its meaning is **unconfirmed** -- `ParseLic.py` doesn't label or use it, so treat it as informational only until independently verified (e.g. against RouterOS version numbers across several known signatures).

### 8.22 `writeMBR` found and disassembled -- a new function, distinct from `readMBR`

All of §8.9-8.20 traced `keyman_arm32`'s **read**/verify path. Continuing disassembly of `keyman_arm32` (confirmed directly in the binary itself, not inferred from `loader` or the x86 build) turned up a second, previously undocumented function: `writeMBR`, at `0x19758`. Identified unambiguously via its own error-format string sitting in `.rodata` right next to the `/dev/flash` path literal: `"writeMBR: could not open %s: %d\n"`.

**The `board`-contains-`"qemu"` predicate (`0x17574`, §8.9/8.15's cached `getenv`+`strstr` check) is called from `writeMBR` too**, not just `readMBR` -- confirmed at `writeMBR+0x14` (`0x1976c`). When it returns true, `writeMBR` tail-calls into a small helper (`0x18ba4`) that hands the write off through the `nv` message/IPC layer rather than touching any device directly -- structurally the same pattern as `readMBR`'s `/dev/hvckvm0` (hvc0) IPC path from §8.15-8.16, just on the write side. This confirms the virtualization-detection branching isn't read-only special-casing -- both directions of MBR I/O go through the same `board=qemu` gate and the same IPC-based fallback when it's true.

**A second, previously undocumented predicate exists specifically on `writeMBR`'s false-branch (`board` does *not* contain `"qemu"`):** it calls `getenv("board")` a second time and checks only whether the **first character of the returned string equals ASCII `'7'`** (`0x37`) -- not a substring search this time, a single-byte compare. If true, `writeMBR` skips straight to opening the caller-supplied device path directly; if false (or `board` is unset), it first tries `open("/dev/flash", O_RDWR)` and issues `ioctl(fd, 0x80044604, &buf)` (decodes as `_IOR('F', 4, <4-byte arg>)` in Linux ioctl-number encoding -- meaning/purpose of this specific ioctl not yet identified) before falling through to the same generic-path write either way. The significance of `board` starting with `'7'` is **not yet understood** -- plausibly a RouterBOARD hardware-generation/family prefix convention, but unconfirmed; worth checking against a real (non-virtualized) ARM64 RouterBOARD's `board` value if one is ever available.

**A third call site for the same `board=qemu` predicate exists at `0x18c28`**, a distinct function (not `readMBR`, not `writeMBR` itself) that also opens `/dev/flash`, issues two more ioctls (`0x462b` and one more not yet decoded), and -- most interestingly -- contains a bit-manipulation sequence at `0x18d20-0x18d48` (`ubfx` extracting a 21-bit and a 9-bit field, a 64-bit `umull` multiply, XOR, `orr r3, r3, #0x200`) that structurally resembles `architecture.md` §2's already-documented `mbr_val * 0x3FF800F` mix step, but with different field widths (21+9 bits here vs. the documented `& 0x7FF` 11-bit `mbr_val`) -- **not yet reconciled with the known algorithm**. This is plausibly where `keyman` recomputes a checksum/marker field when constructing a *new* MBR (as opposed to verifying an existing one), which would make `0x18c28` the missing piece explaining how `0x10A-0x10B`'s marker or `mbr_val` inputs are actually derived at write-time rather than assumed fixed -- worth a dedicated follow-up pass rather than a quick read, since the field-width mismatch means it's not a simple 1:1 match to the documented formula.

**Practical implication:** none of this changes any currently-documented behavior or collision-search output -- it's new evidence about *how* `keyman` writes license data internally, not a new bug or opportunity yet. The most promising thread for a follow-up session is `0x18c28`'s checksum-like computation, since reconciling it with `architecture.md`'s `mbr_val` formula could reveal whether the 21-bit/9-bit fields are a superset (e.g. covering more of the MBR identity region than currently assumed) or an unrelated, separate checksum used only for a different purpose (e.g. the boot counter at `0x10C-0x10F`, which §3's table already flags as "no impact" on the SOFTWARE ID but has never been explained *how* it's maintained).

### 8.23 Independent adversarial verification of §8.22 -- confirmed, with two corrections

§8.22's claims were re-derived independently (fresh `grep`/`objdump` navigation against the same disassembly, not just re-reading the prior notes) specifically to catch overclaiming before it hardened into permanent documentation. Result: mostly confirmed, two corrections below.

**Confirmed exactly as written:** the `board=qemu` predicate (`0x17574`) has **exactly 4** call sites, verified via `grep -n 'bl.*17574'` against the full disassembly with no `blx`/indirect calls reaching it by another path: `0x178ec` (`readMBR` itself), `0x18c3c` (`getHardwareID`, §8.9-8.13's already-known serial/model function), `0x1976c` (`writeMBR`), and `0x19b84` (a fourth site, see correction below). `readMBR`'s body (`0x178dc-0x179e0`) was checked instruction-by-instruction for `mul`/`mla`/`umull`/`umlal`/`smull` (the ARM mnemonics any Curve25519/bignum crypto would necessarily use) -- **zero matches**, confirming no signature-verification arithmetic happens inside `readMBR`, and confirming it has no `board[0]=='7'` secondary check (that check is `writeMBR`-only, as §8.22 states). `writeMBR`'s tail-call to `0x18ba4` on the qemu-true branch, and that function's own `bl 18b08` -> `bl 1762c` IPC dispatch, were both confirmed to exist exactly as described.

**Correction 1 -- `0x19b84`'s function is not a "near-duplicate via reuse," it's an independent re-implementation.** The function at `0x19b64` (called from `0x19b84`) does **not** call `0x178dc` (`readMBR`) internally -- it has its own separate `open`/`ioctl(0x4601)`/`fopen`-fallback sequence that happens to be structurally identical to `readMBR`'s, and its own separate `bl 18b08` -> `bl 1762c` (message type 6, 520-byte buffer) call on the qemu-true branch. Two independently-compiled copies of the same logic, not one calling the other -- worth keeping precise since a reader could otherwise assume `0x19b64` is just a thin wrapper.

**Correction 2 -- the `libucrypto.so` hypothesis from earlier discussion is unsupported speculation, not evidence-based.** `readelf -d keyman_arm32`'s `NEEDED` entries are `libumsg.so`, `libuc++.so`, and `libc.so` only -- **no link to `libucrypto.so`, direct or transitive** (checked `libumsg.so`'s and `libuc++.so`'s own `NEEDED` entries too, neither pulls in `libucrypto.so` either). The "no crypto arithmetic in these 4 functions" part is solid (confirmed above), but "therefore it's probably `libucrypto.so`" was a guess based on that library merely existing in `/root/ros-work/lib/`, not on any actual trace of where the IPC call in §8.22/8.23 (`nv::Handler`, message type 6) actually terminates. Treat "where does signature verification actually happen" as fully open, not narrowed to a specific library.

**Where this leaves the investigation:** `keyman_arm32` alone has not hit a genuine dead end -- there is one concrete, cheap thread left before reaching for a new binary: trace the `bl 1762c` (`nv::Handler`-adjacent) message-type-6 dispatch itself, and cross-reference it against `/root/ros-work/hvc0_responder.py`/`hvc0_responder.log` (already on disk from earlier session work, never yet correlated against these specific IPC call sites). Only after that thread is exhausted does disassembling a new binary (`libucrypto.so` or whatever process actually answers type-6 messages) become the necessary next step.

### 8.24 `0x1762c` decoded, and Curve25519 field arithmetic found -- statically compiled into `keyman_arm32` itself

Two follow-ups on §8.23, both from direct disassembly (not inference).

**`0x1762c` (the "IPC dispatch" `writeMBR`/`readMBR` fall into on the `board=qemu`-true branch) is a plain length-prefixed request/response helper, not a complex `nv::message`-serialized call as earlier sections assumed.** Disassembled in full: it `write()`s an 8-byte header (`{constant 8, type}`, e.g. `type=6` for `writeMBR`'s call) to the file descriptor passed in, then `malloc()`s a buffer of the caller-specified reply size (e.g. 520 bytes) and loops on `read()` until that many bytes arrive (retrying on partial/interrupted reads, freeing and returning `NULL` on hard failure). No field-ID-based serialization, no `nv::message::insert<>`/`extract<>` template machinery visible at this call site -- just a raw fixed-size framed exchange over whatever fd was connected earlier (presumably to `loader` via `/ram/novasock`, consistent with the `connect(AF_UNIX, "/ram/novasock")` seen in this project's earlier `strace` capture of `keyman_arm32` under `qemu-arm`).

Cross-checking this against `/root/ros-work/hvc0_responder.py`/`.log` (a stub UNIX-socket script from earlier session work meant to simulate `/dev/hvckvm0`): the log shows the stub only ever got as far as `"client connected"` -- **no request was ever actually received**, so it never captured a real `type=6` exchange. That thread is a dead end as-is; the earlier §8.23 suggestion to "cross-reference against `hvc0_responder.log`" doesn't hold up because the log contains no useful data, not because the correlation wasn't attempted.

**More significantly: `keyman_arm32` contains an actual Curve25519 field-multiplication routine, statically compiled in.** Found by grepping the whole binary for ARM multiply mnemonics (`mul`/`mla`/`umull`/`umlal`/`smull`/`smlal` -- 260 total hits across the binary, confirming the grep pattern itself works; zero hits specifically inside `readMBR`'s body, confirming §8.23's claim there). The function at `0x145bc` reads a 10-word (40-byte) input array at 4-byte-stride offsets `0, 4, 8, ..., 36`, multiplies using `mov r5, #38` (**38 = 2*19**, the standard doubled reduction constant for the Curve25519 prime `2^255-19`), and masks outputs with `bic r6, r2, #0xfc000000` (26-bit limb) / `bic ip, r3, #0xfe000000` (25-bit limb) -- an unambiguous match for the classic **10x25.5-bit-limb `fe_mul`** field-multiplication implementation used in reference Curve25519 code (djb/donna-style `ref10`/`donna` field element representation). This directly contradicts §8.23's "no crypto found, `libucrypto.so` is speculative" framing: the crypto isn't missing or delegated elsewhere, it's compiled directly into `keyman_arm32`'s own `.text`, which is exactly why `readelf -d` shows no `libucrypto.so` dependency (there's nothing external to depend on for this).

`0x145bc` (`fe_mul`) has **41 call sites**, clustered densely in the address range `0x151c8-0x1535c` -- far more than a single point-verification would need for one multiplication, and structurally consistent with either a Curve25519 **field inversion** (`fe_invert`, which reference implementations compute as a fixed, unrolled sequence of ~11 multiplications and ~254 squarings via Fermat's little theorem -- squarings often reuse the same `fe_mul`-shaped code or a dedicated `fe_sq`) or a **scalar multiplication ladder step** sequence. Not yet determined which, nor whether this specific function is reachable from the `readMBR`/signature-check flow traced in §8.9-8.23 (the 41 call sites have not yet been traced to their own caller(s), and no direct call from any of the four `board=qemu`-adjacent functions to this address range has been found yet -- it may be invoked from a completely different part of `keyman` not yet mapped, e.g. package/firmware signature verification unrelated to the license MBR).

**Practical implication:** the "where does signature verification happen" question from §8.23 is **narrower than before but not yet closed**: it happens somewhere inside `keyman_arm32` itself (confirmed, not speculated), via a statically-linked Curve25519 implementation -- but the call path connecting this crypto code to the license-MBR-read flow (§8.9-8.20) has not yet been traced. The concrete next step is to find `0x145bc`'s callers-of-callers (walk up from `0x151c8` to find what function contains it, then find that function's own callers) to determine whether this is the license-signature-verification code path or an unrelated use of the same crypto primitive (e.g. RouterOS package/firmware signing, which also plausibly uses Curve25519 and would live in the same binary for unrelated reasons).

### 8.25 Confirmed: `keyman_arm32` is genuinely 32-bit ARM (not misidentified), and the crypto call chain traced further up

Two more directly-verified points, continuing from §8.24.

**Sanity check on the binary's own architecture, since this was reasonably questioned:** `readelf -h keyman_arm32` reports `Class: ELF32`, `Machine: ARM` (not AArch64); `file` independently confirms `ELF 32-bit LSB executable, ARM, EABI5, dynamically linked, interpreter /lib/libc.so`. This is not a misidentified file -- `keyman_arm32` really is a 32-bit ARM (AArch32) binary, extracted from `/nova/bin/keyman` inside the mounted `system.squashfs` of a genuine RouterOS **ARM64** install image. The most plausible explanation (not independently verified against the actual kernel, which lives outside `system.squashfs` and hasn't been extracted): MikroTik's ARM64 product line likely ships a 64-bit kernel alongside the *same* 32-bit `nova` userspace binaries used on their ARMv7 RouterBOARD line, relying on ARM64 CPUs' native AArch32 EL0 execution support rather than recompiling `nova` for AArch64. This is consistent with everything else found in this investigation (§8.9's byte-identical shared functions between ARM32 and the x86 build already established this codebase is compiled once and reused broadly).

**Traced `0x145bc` (`fe_mul`)'s call chain two levels further up, following real cross-references (not inference):**

1. `0x145bc` (`fe_mul`) has 41 callers clustered in `0x151c8-0x1535c`, all inside a single function starting at `0x151c8` (`sub sp, sp, #204` -- a large local frame consistent with either `fe_invert`'s unrolled ~254-squaring/~11-multiplication sequence or a full scalarmult ladder).
2. `0x151c8` has exactly 3 callers (`0x15864`, `0x15944`, `0x15cf4`), all inside one enclosing function starting at `0x15654`. That function's own body opens with `mov r1, #9` immediately before a call to `0x13694` -- **`9` is the standard Curve25519/X25519 base point** (`crypto_scalarmult_base`'s fixed `u`-coordinate) -- alongside byte-unpacking code that deserializes a 32-byte value into the field-element limb layout. This is an unambiguous `crypto_scalarmult`/`crypto_scalarmult_base`-shaped function.
3. `0x15654` has exactly 1 caller: `0x17318`. The code immediately preceding that call (`0x172f0-0x17314`) performs `byte[31] &= 0x7f; byte[31] |= 0x40; byte[0] &= 0xf8` -- the **standard X25519 scalar "clamping"** sequence (`s[0] &= 248; s[31] &= 127; s[31] |= 64`), confirming `0x17318`'s enclosing function (starting `0x170d4`) is a full clamp-then-scalarmult wrapper. Notably, **this exact clamping byte sequence was already seen once before in this investigation**, in `loader` at `0x1ac1c-0x1ac38` (originally read while tracing the `board=qemu` predicate's caching wrapper in §8.9) -- meaning `loader` independently contains the same clamp-and-scalarmult logic, not just `keyman`.
4. `0x170d4` (the clamp+scalarmult wrapper) has **4 callers**: `0x17388`, `0x18ab8`, `0x195c4`, `0x1a0c8`. Inspected `0x18ab8`'s context directly: it sits inside a function that also calls `_Z14hasUefiSupportv` (a demangled, human-readable C++ symbol -- `bool hasUefiSupport()`) a few instructions earlier, and stores small integer status codes (`0`, `2`, `5`, `255`) into several output pointer arguments before reaching the scalarmult call. The scalarmult's result (`r0`) is then compared and branched on to decide a final boolean written back through another output pointer. This has the shape of a **multi-field system-capability/status query function** (of which `hasUefiSupport` is one field and something crypto-gated is another), not a narrowly-scoped "verify this one license signature" function -- consistent with, but not proof of, license validity being one bit among several status flags gathered together (e.g. for a `/system resource`-style report).

**Honest assessment of what remains open:** the crypto chain (`fe_mul` -> `fe_invert`/ladder step -> `crypto_scalarmult`/`_base` -> clamp-and-scalarmult wrapper -> a status-gathering function with 4 call sites) is now traced end-to-end with real cross-references at every hop -- this is solid. What is **not yet confirmed** is that this particular call chain is the one invoked from the license-MBR read flow (§8.9-8.20) specifically, as opposed to a different, unrelated use of the same crypto primitives (package signing, secure firmware update, or some other RouterOS feature that also needs Curve25519). None of `0x170d4`'s 4 callers have yet been checked for a direct connection back to `readMBR`/`writeMBR`/`getHardwareID` (the three functions already mapped in §8.9-8.24) -- that cross-check is the next concrete step, not yet done. Do not treat "license signature verification confirmed located" as settled until that link is checked.

### 8.26 The crypto chain traced in §8.25 is confirmed NOT connected to `readMBR`/`writeMBR`/`getHardwareID` -- a negative result, not a dead end

Following up on §8.25's open item directly: checked whether any of `0x170d4`'s 4 callers (`0x17388`, `0x18ab8`, `0x195c4`, `0x1a0c8`), or the next function up from `0x17388` (`0x1736c`, itself called from 4 further sites: `0x1a484`, `0x1aa84`, `0x1af08`, `0x1b94c`), fall inside the already-mapped `readMBR` (`0x178dc-0x179e0`), `writeMBR` (`0x19758`-ish), `getHardwareID` (`0x18c28`-ish), or the duplicate `readMBR` (`0x19b64`-ish) address ranges from §8.9-8.24.

**None of them do.** Every one of these 8 call sites (4 + 4, across two hops) falls outside all four mapped license-I/O functions' address ranges. This is a clean, checked negative result: **the Curve25519 chain traced in §8.25 is not called from the local MBR read/write/hardware-ID functions.**

This is confirmed, not just suggested, by what's at that call site: `0x1a0c8`'s enclosing function builds an `nv::HTTPFetch` request via repeated `appendVar(string&, char const*, string const&)` calls (unambiguous demangled symbol) with parameter-name string literals **`"systemid"`, `"account"`, `"password"`, `"licence"`** (read directly from `.rodata`, byte-for-byte), and a literal pool entry a few instructions later (`0x1a3a4`) references the string **`"licence.mikrotik.com"`** (also confirmed present in `.rodata` alongside `"permanent licence can not be renewed"` and `"renewing"`). This is unambiguously the **online license activation/renewal HTTP request** -- POSTing account credentials and a license identifier to MikroTik's own license server -- not local signature verification. The crypto chain traced in §8.24-8.25 serves this **online** flow, not the **offline**, boot-time MBR read this project's collision-search method actually depends on.

**Practical implication:** this project's entire approach (§1-7's collision search, reusing existing valid signatures rather than forging new ones) was never dependent on finding where local EC-KCDSA verification happens -- that was always out of scope, since the method works by matching a *known-valid* signature's SOFTWARE ID, not by computing new signatures. This deep dive (§8.24-8.26) was pursued to satisfy a specific question raised mid-session (does `keyman` verify signatures locally, and if so where), not because the answer changes anything actionable for collision search. With this negative result in hand, the honest state of that specific question is: **`keyman_arm32` contains at least one complete Curve25519 implementation, used for something networked/online, not (as far as traced) for local MBR signature verification.** Whether local MBR signature verification happens at all (as opposed to RouterOS simply trusting a well-formed MBR signature region without cryptographic verification at boot, deferring any real check to network-based license validation) is now an open question in its own right -- not answered by this investigation, and not necessary to answer for this project's practical goals. Further pursuit of this specific thread should be considered optional/curiosity-driven rather than blocking.

### 8.27 The networked flow identified in §8.26 confirmed to be online license renewal, and confirmed to call `readMBR` internally

Two more confirmations, both from direct string/cross-reference evidence, closing out this sub-thread.

**Confirmed the HTTP request's actual target and purpose (not just "networked" -- specifically license renewal against MikroTik's own server):** the function starting at `0x19f78` (called from two sites, `0x1aa34`'s function and one other) builds its `nv::HTTPFetch` request with `appendVar` parameter-name literals `"systemid"`, `"account"`, `"password"`, `"licence"`, and a literal-pool reference a few instructions later to the string `"licence.mikrotik.com"` immediately followed in `.rodata` by `"/licence/"` (i.e. the request targets `licence.mikrotik.com/licence/`). This is MikroTik's own account-based license server -- the request POSTs (or GETs with these query vars) a system ID plus MikroTik account credentials, exactly the shape of an **online license activation/renewal** call, not a generic unrelated HTTP feature.

**Confirmed this flow calls `readMBR` (the `0x19b64` duplicate from §8.22-8.23) as part of the same operation.** Tracing one level up from both `0x1aa34` (the function wrapping the `licence.mikrotik.com` HTTP call) and `0x1ab80` (a separate function that calls `readMBR`'s `0x19b64` duplicate directly) found that **both are called from the same parent function**, at call sites only 28 bytes apart (`0x1b4d8` calls `0x1ab80`/`readMBR`, `0x1b4f4` calls `0x1aa34`/HTTP-post). This parent function's broader vicinity also contains the `"renewing"` and `"permanent licence can not be renewed"` string literals found in §8.26. Putting this together: there is a single **license renewal command handler** that (1) calls `readMBR` to read the currently-installed SOFTWARE ID/signature off disk, then (2) POSTs that ID plus account credentials to `licence.mikrotik.com/licence/` to request a renewed/new signature from MikroTik's server, with the Curve25519 code from §8.24-8.25 used somewhere in that HTTP exchange (most plausibly for authenticating the request or processing the server's cryptographic response, not for verifying the locally-read MBR signature).

**This refines, but does not overturn, §8.26's core negative result.** `readMBR` is called by this flow, but only to *read and report* the current on-disk SOFTWARE ID to the server as an input -- there is still no evidence the Curve25519 code itself is used to *verify* that on-disk signature locally. The crypto's role in this flow is on the network side (talking to `licence.mikrotik.com`), consistent with §8.26. Whether local, offline signature verification happens anywhere in `keyman_arm32` remains genuinely open -- but the earlier framing "the crypto chain has nothing to do with readMBR" was too strong; they're both steps in the same renewal operation, just with the crypto doing the online part and `readMBR` doing the local read.

### 8.28 Root cause of ARM64/`board=qemu` activation failure, confirmed empirically: the `/dev/hvckvm0` transport device genuinely does not exist under plain QEMU/KVM

This closes the open question from §8.15-8.20 with direct evidence from a running VM's own QEMU command line, not further disassembly.

**Test setup**: `VM301` (a disposable full clone of the ARM64 test VM, created specifically so testing no longer touches the original `VM100`), `scsi0` disk with the SOFTWARE ID `C7CU-PGT9` combo from §8.14, custom `smbios1` override removed (reverting to PVE's default). Result: booting with default SMBIOS avoided the `MetaROUTER` trap from §8.17 (console prompt is `[admin@arm64]`, not `[admin@MetaROUTER]`) -- confirming §8.17's hypothesis that the *custom* SMBIOS override, not `board=qemu` itself, was what triggered `MetaROUTER`. But `/system resource print` shows `board-name: arm64 QEMU KVM Virtual Machine` (still contains `"QEMU"`, PVE's own default), and the boot banner still shows `ROUTER HAS NO SOFTWARE KEY` with a normal ~24h-scale countdown (`17h35m` observed) -- i.e. the ordinary `board=qemu` failure mode from §8.15, not `MetaROUTER`.

**Root cause, found by inspecting the actual running `qemu-system-aarch64` process's command line** (`/proc/<pid>/cmdline` for VM301's PID, read via its PVE-managed `.pid` file) rather than guessing: the only virtio-serial-family device attached to this VM is

```
-chardev virtserialport,chardev=vdagent,name=com.redhat.spice.0
```

-- a SPICE guest-agent channel, unrelated to console/tty access. `serial0` (RouterOS's actual boot console, which this whole session's `socat` interaction has been using) is a plain legacy UART (`-chardev socket,...` + `-serial chardev:serial0`), not a virtio-console. **There is no device on this VM that would ever cause a `/dev/hvc0` tty to appear inside the guest.** Since `/dev/hvckvm0`'s self-provisioning (§8.16: `stat("/dev/hvckvm0")` -> fall back to `/sys/class/tty/hvc0/dev` -> `mknod`) has no `hvc0` sysfs entry to find in the first place, it necessarily fails -- and `readMBR`'s `board=qemu` branch has no further fallback (§8.15), so it can never successfully read the MBR on any plain QEMU/KVM setup where `board` contains `"qemu"` **and** `MetaROUTER` isn't independently triggered, regardless of which specific SMBIOS strings are used.

**This settles §8.18's open question definitively for the `board=qemu`-true, non-`MetaROUTER` case.** It is not that ARM64 and x86_64 differ in *what string* `board` contains, or in case-sensitivity, or in some other software nuance -- ARM64/`virt` hits this branch (because `board` genuinely contains `"qemu"` by default under QEMU, on both architectures) while x86_64/CHR does not need to, because **x86_64's `readMBR` code path apparently never depends on a virtio-console device at all** (§8.9's `HDIO_DRIVE_CMD`/`ide0` path and the generic `/dev/flash`-or-`fopen()` fallback both work with ordinary block/char devices that PVE does provision by default). The ARM64 image's `board=qemu` branch assumes a specific piece of host-provided infrastructure (a real MetaROUTER-capable RouterBOARD host wiring up `/dev/hvckvm0` for a nested guest) that simply does not exist when the "host" is generic QEMU/KVM rather than real MikroTik hardware.

**Practical implication, updated by §8.17's correction above:** since `MetaROUTER` mode is now understood to function as activated in practice despite its cosmetic "no software key" banner, this specific `board=qemu`-true/non-`MetaROUTER` dead end is **not actually the blocking case** -- the SMBIOS-override path into `MetaROUTER` (§8.17) is the one that matters for practical ARM64/`scsi0` deployment, and it works. This `/dev/hvckvm0`-missing-device root cause remains useful background (it explains precisely why the *unmodified*-SMBIOS default fails, and confirms that path specifically cannot be fixed by SMBIOS tricks alone, only by either avoiding it entirely via `MetaROUTER` or by actually providing a working `virtio-console` backend), but is no longer the critical path now that §8.17's `MetaROUTER` route is confirmed usable.

### 8.29 `libumsg.so`'s `/dev/rb` check identified as `getBoardType()`, disassembled -- and a reusable methodology note for resolving PIC literal addresses

Following up on §8.17's remaining open item ("continuing requires disassembling `libumsg.so`'s `MetaROUTER`-detection function").

**Methodology note (recorded because it was non-obvious and is reusable for future `.so` disassembly in this project):** `libumsg.so` is `Type: DYN` (a PIC shared object), so naively `grep`-ing the disassembly for a string's raw `.rodata` file offset (the way this worked for `keyman_arm32`/`loader`, both non-PIE `EXEC` binaries) finds nothing -- PIC code doesn't embed absolute addresses as plain literal-pool words. Instead it uses a two-instruction idiom: `ldr rX, [pc, #N]` loads a **signed delta** from a literal pool slot, then `add rX, pc, rX` (or the immediate form `add rX, pc, #N`) computes `final_address = add_instruction_address + 8 + delta`. Resolving "what address does this PIC code reference" therefore requires two hops: (1) compute the literal pool slot address from the `ldr`'s own address and immediate, (2) read the delta word stored there, (3) add it to the *following* `add` instruction's `PC+8`. A short Python script parsing the `objdump -d -r` text output for this pattern (matching `ldr rX,[pc,#N]` then a following `add rX,pc,rY`, resolving the delta from a raw-hex-word address map built from every line in the dump) found both target strings' materialization sites directly: `"/dev/rb"` at `0x4e25c`, `"open /dev/rb failed, probably metarouter"` at `0x4e278` -- both inside the same function.

**The function is `_Z12getBoardTypev` = `getBoardType()`** (an exported, C++-mangled symbol -- not exported from `keyman_arm32`/`loader`, `readelf --dyn-syms` gives the demangled name directly, no guessing needed). Full logic:

```
int getBoardType() {
    static bool cached; static int cached_result;      // process-lifetime cache, same pattern as §8.9's board=qemu predicate
    if (cached) return cached_result;

    int fd = open("/dev/rb", O_RDWR);                    // unconditional -- no getenv("board") check anywhere in this function
    if (fd != -1) {
        ioctl(fd, 0x520f, ...);                           // real hardware: read board-type info
        close(fd);
        cached_result = <ioctl's result>;
    } else {
        ostream << "open /dev/rb failed, probably metarouter";   // logged unconditionally on open() failure
        cached_result = fd;                               // i.e. -1
    }
    return cached_result;
}
```

**This directly disproves the specific mechanism §8.17 speculated for why unmodified (`board=qemu`) VMs never showed `MetaROUTER`.** §8.17 guessed "`board=qemu` intercepts before `/dev/rb` is tried" -- but `getBoardType()` itself contains **no `board` check at all**; `open("/dev/rb")` runs unconditionally regardless of `board`'s value. This means `/dev/rb` fails identically on *every* plain-QEMU VM (§8.28 already established there's no real RouterBOARD device to back it), whether or not `board` contains `"qemu"` -- the differentiation between "normal `board=qemu` trial" and "`MetaROUTER` prompt" must happen somewhere else, in whatever code *decides how to react* to `getBoardType()`'s `-1` result (or to the `"probably metarouter"` log line), not inside `getBoardType()` itself.

**That caller-side decision point was not found.** `getBoardType()` has zero callers within `libumsg.so` itself, is not imported by `keyman_arm32` or `loader` (checked both directly), and its only confirmed caller across the binaries checked is **`sys2`** (10+ call sites) -- a different `nova` binary, plausibly the general system-resource/status daemon behind `/system resource print`-style queries, with no established connection to the license/MBR flow at all. This leaves a real, unresolved gap: **it's not yet confirmed that `getBoardType()`'s `/dev/rb` failure is actually what produces the visible `[admin@MetaROUTER]` prompt and boot banner** -- the debug string's presence and content is a strong coincidental match, but the causal wiring from "this specific function returns -1" to "boot shows `ROUTER HAS NO SOFTWARE KEY` with `[admin@MetaROUTER]`" has not been traced. Treat this as the concrete next step if this thread is picked up again, rather than assuming the connection is already proven.

### 8.30 A third, independent vendor-detection mechanism found (`isMikrotikVendor`/`isMikrotikAmpere`) -- investigated as a candidate for the `platform:` field, ruled out

Prompted by `/system resource print`'s `platform: MikroTik` field (observed in §8.28's VM301 test) -- checked whether this is yet another signal feeding into the `board=qemu`/`MetaROUTER` decision maze, or into how `platform` gets its value.

**Found, via the same PIC literal-resolution method as §8.29, two related functions exported from `libumsg.so`:**

```cpp
bool isMikrotikVendor() {
    string content = nv::readFile("/sys/class/dmi/id/sys_vendor", ...);  // real Linux sysfs DMI file
    return <content contains "MikroTik\n">;                              // exact substring match
}

bool isMikrotikAmpere() {
    if (!isMikrotikVendor()) return false;
    return getenv("uefi") != NULL;   // second, independent env-var check (nonzero-check idiom: clz+lsr#5)
}
```

This is a **third, independent detection mechanism**, distinct from both `getenv("board")`+`strstr(..., "qemu")` (§8.9/8.15, used by `readMBR`/`writeMBR`/`getHardwareID`) and `getBoardType()`'s `open("/dev/rb")` (§8.29): it reads the DMI `sys_vendor` sysfs value directly (settable via `qm set --smbios1 manufacturer=<base64>`) and checks for an exact `"MikroTik"` match, then separately checks a `getenv("uefi")` environment variable. The naming (`isMikrotikAmpere`) suggests this gates behavior specific to MikroTik's real Ampere-based ARM64 server hardware (a legitimate non-embedded ARM64 product line), not virtualization detection.

**Ruled out as the source of the `platform:` field.** If `isMikrotikVendor()` fed `platform:`, deleting VM301's custom `smbios1` override (§8.28, which removes the `manufacturer=MikroTik` base64 value, reverting to PVE's default `QEMU`) should have changed `platform:` away from `MikroTik` -- it did not; `platform: MikroTik` was observed both with and without the custom SMBIOS override. This is inconsistent with `platform:` being derived from a live DMI-vendor check. The more likely explanation is that `platform: MikroTik` is a **static build-time label** (RouterOS always reports itself as "MikroTik" branding regardless of underlying hardware, the same way x86 CHR does on any hypervisor) -- not a live hardware-detection result, and not connected to the license/`MetaROUTER` flow.

**Net effect of this sub-thread:** confirmed a real, previously-undocumented function pair (`isMikrotikVendor`/`isMikrotikAmpere`) exists and is genuinely DMI-vendor-based, but it does not explain the `platform:` field and has no established connection to license/`MetaROUTER` behavior -- this was a plausible lead that didn't pan out. §8.29's gap (what code actually decides to show the `MetaROUTER` prompt based on `getBoardType()`'s result) remains open and is a separate, still-untraced code path, most likely in a CLI-prompt/console-related binary not yet examined (candidate: `/nova/lib/console`).

### 8.31 The missing layer found: `flash.ko` (kernel module) checks the device-tree `compatible` string, and `"MetaROUTER"` is one of the recognized values -- plus a full map of all hardware-detection signals found so far

Followed up on §8.29's dead end (no userspace caller of `getBoardType()` decides the `MetaROUTER` prompt) by going one level lower: `grep -rl 'MetaROUTER' /root/ros-work/sysimg/` across the *entire* mounted system image, not just already-disassembled userspace binaries. Result: exactly one hit outside `libumsg.so` -- `/lib/modules/5.6.3/misc/flash.ko`, the kernel module already flagged as an open question in §8.17 ("whether `flash.ko` ... is involved in provisioning `/dev/rb`").

**Located the string's cross-reference using the AArch64-appropriate method** (this module is `aarch64`, `ET_REL` -- a relocatable kernel object, not a PIE/PIC shared library, so §8.29's `ldr+add pc` ARM32 PIC idiom doesn't apply here; instead, `.text` references to `.rodata` are explicit `R_AARCH64_ABS64` relocation entries against `.rodata.str1.1 + <offset>`, found directly via `readelf -r`, no address arithmetic needed). The `"MetaROUTER"` string (`.rodata.str1.1+0x65c`) is referenced at `.text` offset `0x27e8`, which sits inside a dense cluster of literal-pool pointer slots spanning `0x27b0-0x2838` in a function objdump attributes to `init_module` (flash.ko's module-init function).

**Decoded the full contents of that literal-pool cluster** (18 consecutive 8-byte relocation slots, resolved via a Python script mapping each `R_AARCH64_ABS64 .rodata.str1.1+N` addend to its null-terminated string):

```
0x27b0  "new-flash: starting...\n"      (printk message)
0x27b8  "marvell,armada7040"             (DT machine-compatible string)
0x27c0  "marvell,msys"                   (DT machine-compatible string)
0x27c8  "econet,en7523"                  (DT machine-compatible string)
0x27d0  <.bss pointer, not a string>
0x27d8  "flash-ko"                       (module/log tag)
0x27e0  <.data pointer, not a string>
0x27e8  "MetaROUTER"                     <-- the string from §8.17/8.29
0x27f0  "nor: offs from DTB\n"           (printk message)
0x27f8  "hardcfg_offs"                   (DT property name, for of_property_read_u32-style lookup)
0x2800  "hardcfg_sz"                     (DT property name)
0x2808  "soft_offs"                      (DT property name)
0x2810  "soft_sz"                        (DT property name)
0x2818  "bios_offs"                      (DT property name)
0x2820  "bios_sz"                        (DT property name)
0x2828  "marvell,alleycat5"              (DT machine-compatible string)
0x2830  "annapurna-labs,alpine"          (DT machine-compatible string)
0x2838  "qcom,ipq4019"                   (DT machine-compatible string)
```

**Correction, from full instruction-level tracing (not just string-clustering inference) -- this replaces an incorrect first-pass interpretation.** Manually decoded the actual `init_module` control flow around this table (the region objdump renders as `...`/data is genuinely a mixed code+literal-pool region; the branches themselves *are* disassembled correctly earlier in the listing, just not adjacent to the pointer table). The real logic:

```c
void init_module(void) {
    al_spi_flash_module_init();                                              // always attempted first
    if (of_machine_is_compatible("marvell,armada7040")) mv_spi_flash_module_init();
    if (get_hcfg())                                     a37_spi_flash_module_init();
    if (of_machine_is_compatible("marvell,msys"))       orion_spi_flash_module_init();
    if (of_machine_is_compatible("econet,en7523"))      econet_spi_flash_module_init();
    // (marvell,alleycat5 / annapurna-labs,alpine / qcom,ipq4019 / is_ampere_routerboard()
    //  are checked similarly a bit further down, each with hardcoded flash-partition
    //  offset/size constants for that specific SoC's real NOR/SPI memory map)

    flash_dev->type = 1;                       // provisional
    if (!rb_mtd_good_device()) {               // <-- did any of the above actually find/validate a real flash chip?
        // FALLBACK -- no real MTD device found (this is the branch QEMU/KVM always takes,
        // since none of the of_machine_is_compatible() checks above can ever match a
        // generic `virt` machine's device tree):
        flash_dev->type = 3;
        misc_dev->name  = "MetaROUTER";        // <-- hardcoded literal, NOT derived from a DTB "MetaROUTER" compatible match
        misc_dev->type  = 11;
    } else {
        // Real hardware confirmed:
        misc_dev->name  = "flash-ko";
        misc_dev->type  = 5;
    }
    misc_register(&misc_dev->inner);           // <-- called UNCONDITIONALLY, on BOTH branches
}
```

**This overturns the first-pass reading above in one important way: `"MetaROUTER"` is not a fourth `of_machine_is_compatible()` value being matched at all.** There is no `of_machine_is_compatible("MetaROUTER")` call anywhere in this function. `"MetaROUTER"` is a **hardcoded fallback device name**, assigned whenever `rb_mtd_good_device()` -- the post-hoc check of whether any of the real-hardware driver-init calls above actually succeeded -- returns false. And critically, **`misc_register()` runs on both branches**, not just the real-hardware one. This means a misc device genuinely gets registered under plain QEMU/KVM too -- **just under the name `"MetaROUTER"` instead of `"rb"`**, i.e. the kernel creates `/dev/MetaROUTER`, not `/dev/rb`.

**This is a fully coherent explanation for §8.29's `getBoardType()` finding, and it's a better fit for the evidence than the original "no device at all" theory:** `getBoardType()`'s `open("/dev/rb", O_RDWR)` genuinely fails with `ENOENT` under QEMU/KVM -- not because the kernel registered nothing, but because it registered the fallback device under a *different path* (`/dev/MetaROUTER`). This also gives the `"open /dev/rb failed, probably metarouter"` log message (§8.29) a concrete, literal basis rather than being a vague guess: whoever wrote that message evidently knew that `/dev/rb`'s absence, in practice, usually means `/dev/MetaROUTER` exists instead -- because that's exactly what this kernel code does.

**Practical implication:** none of this changes anything about the SMBIOS/`smbios1` findings (DMI/SMBIOS data still never reaches the device-tree-based checks in this module, so `product=`/`manufacturer=`/`sku=`/`family=`/`serial=` tricks -- §8.17's real-board-name experiment included -- still cannot influence this code path, consistent with `VM301` still landing on `MetaROUTER Login:` after that test). What it *does* change is the mental model: this is not "detection failure -> nothing happens", it's "detection failure -> deliberate, hardcoded fallback identity, by design" -- MikroTik's kernel driver was written assuming that the *only* way real hardware detection fails is genuine `MetaROUTER` nested virtualization, and unconditionally labels that case accordingly, with no distinct "neither real hardware nor MetaROUTER" case in its own logic at all. Plain QEMU/KVM merely happens to also fall into that same catch-all bucket. **Still unconfirmed:** whether the struct field set to `"MetaROUTER"` (offset `+48` of the `.data`-resident struct at `27e0`) is literally `struct miscdevice.name` (which would directly produce a `/dev/MetaROUTER` devtmpfs node) as opposed to some other display-name field consumed differently -- the flow strongly suggests the former (name+type set immediately before `misc_register()` on a related sub-pointer of the same struct) but the exact `struct miscdevice` layout wasn't independently cross-checked against kernel headers for this specific 5.6.3/aarch64 build.

**Full map of every physical-hardware-detection signal found across this investigation, for reference (four independent, uncoordinated mechanisms, at three different layers, none of which talk to each other):**

| # | Layer | Mechanism | Checked value | Used by | Section |
|---|---|---|---|---|---|
| 1 | Kernel (`flash.ko` module init) | Device-tree root `compatible` string match against 6 real SoC names, then `rb_mtd_good_device()` sanity check; on failure, hardcoded fallback identity `"MetaROUTER"`/type 11 (not itself DTB-matched) | DTB `compatible` property (not SMBIOS-influenced) | Which name (`"rb"`-equivalent vs `"MetaROUTER"`) the resulting misc device gets registered under | §8.31 (this section) |
| 2 | Userspace (`libumsg.so`, `getBoardType()`) | `open("/dev/rb", O_RDWR)` success/failure + `ioctl(fd, 0x520f)` | Kernel-provided `/dev/rb` node (downstream of #1) | Board-type reporting (`sys2`, `/system resource print`-style queries) | §8.29 |
| 3 | Userspace (`libumsg.so`/`keyman_arm32`/`loader`, cached predicate) | `getenv("board")` + `strstr(value, "qemu")` | `board` environment variable (source not yet traced -- plausibly derived from DMI `product_name`, unconfirmed) | `readMBR`/`writeMBR`/`getHardwareID`'s choice of `/dev/hvckvm0` vs `/dev/flash` vs generic path | §8.9, §8.15-8.16 |
| 4 | Userspace (`libumsg.so`, `isMikrotikVendor`/`isMikrotikAmpere`) | Exact-match read of `/sys/class/dmi/id/sys_vendor` against `"MikroTik"`, plus separately `getenv("uefi")` | DMI/SMBIOS `sys_vendor` (directly settable via `smbios1 manufacturer=`) | Unknown -- 2 call sites in `sys2`, not connected to license flow or `platform:` field (ruled out in §8.30) | §8.30 |

**Answering the standing question directly**: there is no single, unified "is this real hardware" check anywhere in this stack. `keyman`/`readMBR` itself only ever looks at signal #3 (the `board` env var substring check) -- it has no dependency on #1, #2, or #4 at all (confirmed across §8.9-8.29: `keyman_arm32` doesn't import `getBoardType` or `isMikrotikVendor`). Signals #1 and #2 belong to a *separate* subsystem (`flash.ko`/`sys2`, board-type/resource reporting): the kernel module always registers *some* misc device at boot (real-hardware path named after the real board, generic-fallback path hardcoded to the hardcoded `"MetaROUTER"` string) -- it never simply does nothing -- and `getBoardType()` fails specifically because it's hardcoded to look for `/dev/rb`, which only exists on the real-hardware branch. Signal #4 remains an unconnected, separate mechanism. The `[admin@MetaROUTER]` login prompt users see is best explained as this same fallback identity string surfacing again at a higher layer (very plausibly the login/console binary reads the very same `/dev/MetaROUTER` misc device, or a `/proc`/`sysfs` field it exposes, to decide what to print as the hostname/prompt) -- but that specific consumer (which binary reads `/dev/MetaROUTER` or its associated board-name output and turns it into the visible boot banner and prompt) has still not been directly located; it remains the one piece of this map without a confirmed cross-reference.

### 8.32 External source cross-check: an independent writeup names `keyman`'s local EC-KCDSA public key -- independently confirmed present in both `keyman_x86_7.23.2` (x86) and `keyman_arm32`, revising §8.26's "no local verification found" conclusion

A third-party writeup (CSDN, "MikroTik RouterOS 授权签名验证分析", https://blog.csdn.net/chivalrys/article/details/139770711) independently documents the `.key`-file license format and claims a specific 32-byte EC-KCDSA public key is embedded in `/nova/bin/keyman` for **local** signature verification: `8E1067E4305FCDC0CFBF95C10F96E5DFE8C49AEF486BD1A4E2E96C27F01E3E32`. This directly bears on §8.26/8.27's open question ("whether local, offline signature verification happens anywhere in `keyman_arm32` remains genuinely open") -- so rather than taking the article's claim on faith, every part of it was independently re-derived from data and binaries already in this project.

**Step 1 -- confirmed the article's 64-byte license-blob structure against this project's own known-valid signature, with zero dependency on the article's crypto claims being true.** `keys.toml`'s `TI09-7WK3` entry (one of this project's four originally-available signatures) is exactly the same signature the article uses as its own worked example. Splitting our own `signature_hex` into the article's claimed layout (16B encrypted payload + 16B nonce hash + 32B signature) gives nonce-hash and signature values that match the article's example **byte-for-byte**. Running the article's custom-SHA-256-K-table ARX decode (`mikro_decode`, matching this project's own `convert::mt_transform` -- same algorithm, independently implemented) against our payload bytes decodes to `Software ID: TI09-7WK3 (0x137f8e8673d)`, `Version: 6`, `Level: 6`, reserved bytes all zero -- exactly matching both the article's claim and this project's own `keys.toml` entry. This confirms the 64-byte structure and custom-SHA256-based ARX cipher are correct, using this project's own pre-existing data, independent of trusting the article.

**Step 2 -- located the actual public-key bytes in `tools/bin/keyman_x86_7.23.2` (x86, ELF32) via direct disassembly, not by trusting the article's number.**

*Where*: function at `0x804f4c6` (x86, ELF32, `tools/bin/keyman_x86_7.23.2`), specifically the eight instructions at `0x804f658-0x804f6a2`.

*How, step by step (reproducible)*:
1. `strings -a -t x tools/bin/keyman_x86_7.23.2 | grep -i "software key\|license"` found the anchor strings `"Installed software key from %s."` (file offset `0xc24d`) and `"-----BEGIN MIKROTIK SOFTWARE KEY..."` (file offset `0xc3cc`) -- confirming this binary handles the local `.key`-file format at all, before looking for any crypto.
2. `objdump -h` gave `.rodata`'s VMA (`0x08054000`); combined with `objdump -p`'s `LOAD` segment table (first segment: `off 0x0 vaddr 0x08048000`), the file-offset-to-VMA delta for this segment is `+0x08048000` (standard for this class of ET_EXEC i386 ELF). Converting the string file offsets to VMA (`0xc24d + 0x08048000 = 0x0805424d`, etc.) gave addresses to search for as absolute immediates in the disassembly.
3. `objdump -d -r tools/bin/keyman_x86_7.23.2 > disasm.txt`, then `grep -n "805424d\|80543cc\|..."` found the exact `pushl $0x805424d`-style cross-references, pinpointing the enclosing function (`0x8052996`) that builds the "please paste a license" error path -- and, walking forward from there, the actual parse/verify function it calls at `0x804f4c6`.
4. Reading `0x804f4c6`'s body directly: an ARX loop (`0x804f4dd-0x804f60f`) matching Step 1's decode algorithm exactly, followed immediately by **eight separate `movl $imm32, stack_offset(%ebp)` instructions** (`0x804f658-0x804f6a2`) -- the compiler baked the 32-byte constant directly into instruction immediates rather than a contiguous data blob, which is *exactly* why an earlier plain byte-sequence search across `.rodata`/`.data` for the article's key found nothing (there is no contiguous 32-byte run of these bytes anywhere in the file). Concatenating the 8 little-endian dwords in program order (`0xE467108E, 0xC0CD5F30, 0xC195BFCF, 0xDFE5960F, 0xEF9AC4E8, 0xA4D16B48, 0x276CE9E2, 0x323E1EF0`) reproduces the article's public key **exactly**, byte for byte -- independently confirmed via disassembly, not copied from the article.
5. Confirmed the surrounding code matches `mikro_kcdsa_verify` step-by-step, continuing to read past the 8 constants: a 16-byte XOR-combine loop (`data_hash[8+i] ^= nonce_hash[i]`), X25519 clamping (`andl $0x7f` / `orl $0x40` on the boundary bytes), calls into curve-scalar-multiply and hash functions, then a final 16-byte `memcmp` (`0x804f700`) reduced to a boolean via `sete` (`0x804f70a`).

**Step 3 -- found the same constant, and the same function shape, in `keyman_arm32`.**

*Where*: `keyman_arm32`'s literal pool at file offset `0x7350` (VMA `0x17350`), consumed by the function at `0x170d4` (already named in §8.24 as the "clamp-and-scalarmult wrapper").

*How, step by step (reproducible)*:
1. The Step-2 lesson (constants aren't always contiguous) meant a contiguous-32-byte search wasn't retried here. Instead, a small Python script searched for each of the 8 dwords **individually**, as a raw 4-byte little-endian pattern, anywhere in the file (`data.find(struct.pack('<I', dw))` for each of the 8 values) -- a much weaker, more robust search than requiring all 32 bytes contiguous and in the exact original order.
2. 7 of 8 dwords matched, all within a tight 28-byte window: `0x7350` (`0xEF9AC4E8`), `0x7354` (`0xA4D16B48`), `0x7358` (`0xC195BFCF`), `0x735c` (`0xE467108E`), `0x7360` (`0xC0CD5F30`), `0x7364` (`0x276CE9E2`), `0x7368` (`0x323E1EF0`). Reading these addresses back as raw file bytes in sequence at first *looked* scrambled relative to the canonical key's byte order -- but cross-checking against the already-generated `keyman_arm32_disasm.txt` (`grep -n "73[0-4][0-9a-f]:"`) showed each value is loaded via its own `ldr rX, [pc, #N]` instruction (e.g. `0x17248: ldr r6, [pc, #256] @ 17350`, `0x17280: ldr r3, [pc, #208] @ 17358`) and then individually `str`/`strd`-stored into a verify buffer at the offset matching its true position in the 32-byte key (the `0x17358` value, key bytes 8-11, lands at buffer offset 8 via `0x17294: str r3, [sp, #8]`) -- the apparent scrambling was an artifact of reading the *source* literal-pool order, not the *destination* buffer layout, which is correctly ordered.
3. **The 8th dword (`0xDFE5960F`, key bytes 12-15) was not found** as a plain literal-pool word anywhere in the file (checked both byte orders). An `add`-immediate chain building an unrelated 32-bit constant was found nearby (`0x17298-0x172a8`) but tracing its actual register value did not reproduce `0xDFE5960F` when checked by hand -- this one piece of the key is not yet independently located in the ARM binary, and is flagged rather than assumed.
4. Confirmed the enclosing function is `0x170d4` by matching the surrounding instructions against §8.24's own description verbatim: the clamping sequence at `0x172f0-0x17314` (`bic r3, r3, #7` / `orr r3, r3, #64`, ARM's equivalent of x86's `andb $-0x8` / `orl $0x40`) immediately precedes the `bl 15654` call that §8.24 point 3 already identified as the clamp-then-scalarmult call site inside `0x170d4`. Reading past that call to the function's actual end (`0x17348`) -- not previously done in §8.24-8.27 -- shows a 16-byte `memcmp` (`0x17338`) followed by `clz r0, r0` / `lsr r0, r0, #5` (ARM's branch-free idiom for "was the comparison result exactly zero", equivalent to x86's `sete`), i.e. the same verify-and-return-boolean tail confirmed in `keyman_x86_7.23.2`'s Step 2 function -- not merely "crypto-shaped code" as §8.24 cautiously described it at the time.

**This revises §8.26's negative conclusion, but does not fully overturn §8.27's finding about what specifically gets verified.** §8.24-8.27 already traced this exact function (`0x170d4`) and its 4 callers, and §8.26/8.27 concluded the reachable call chain from these 4 sites leads to the `licence.mikrotik.com` **online** renewal flow, not `readMBR`/`writeMBR`/`getHardwareID`. That specific tracing result is unchanged by this section. What *is* new: this function is now confirmed, independently and with a real embedded public key match, to be a genuine EC-KCDSA **verify-and-compare** operation (not merely "crypto-shaped code that might be used for verification") -- meaning at minimum, it verifies *something* cryptographically (very plausibly the signature the server sends back as part of the online renewal response, consistent with §8.27's flow). **Still open**: whether `keyman_arm32` has a *separate*, not-yet-found call path from local `.key`-file import (the `-----BEGIN MIKROTIK SOFTWARE KEY-----` flow, confirmed present and reachable via `"Installed software key from %s."` in the x86 binary) into this same verify function, the way `keyman_x86_7.23.2` clearly does. That specific cross-reference (local `.key`-import handler -> `0x170d4`) has not been checked in `keyman_arm32` and is the concrete next step if this thread continues -- it would be the piece that finally confirms or refutes local, offline signature verification for the ARM64 platform specifically.

**Practical implication:** none of this changes the collision-search method's own validity (§1-7) -- that method never depended on forging new signatures, so whether local verification exists doesn't gate it. What it *does* open up is a completely different, more general technique that this session had not previously considered: since a real, embedded, hardcoded public key now has independent confirmation in at least one `keyman` build (x86), and MikroTik's own `patch.py`-style tooling (referenced in the CSDN article as https://github.com/elseif/MikroTikPatch) demonstrates that replacing this embedded public key with a self-generated one (and re-signing NPK packages against a second, separately-embedded NPK-verification key) lets you sign arbitrary new licenses at any `nlevel`, entirely bypassing SOFTWARE-ID/MBR mechanics and (by extension) the whole ARM64 `board=qemu`/`MetaROUTER`/DTB hardware-detection maze this session has been navigating. Whether this technique is viable on the ARM64 build specifically now hinges entirely on the one open item above.

### 8.33 First independent, real-world validation of the `curve25519.rs` EC-KCDSA verifier -- against an externally-supplied license, not our own test data

Source: [github.com/cheebun/mtsc issue #2](https://github.com/cheebun/mtsc/issues/2), which links a real `.key` file (`W5EY-LHT9.KEY`, hosted at a third-party GitHub repo) and includes a manual verification trace from a commenter (`MurVlad`) using the independent Python reference (`ParseLic.py`).

**Ran `mtsc key2sig` directly against the fetched `.key` file content (not against any of this project's own known-good signatures) and compared byte-for-byte against `MurVlad`'s independently-produced manual trace:**

| Field | Our tool | `MurVlad`'s manual trace |
|---|---|---|
| Software ID | `W5EY-LHT9` | `W5EY-LHT9` |
| License Level | `6` | `6` |
| Nonce Hash | `63CAF8EEDB34A90CF9A66B4F174BA78D` | `63 ca f8 ee db 34 a9 0c f9 a6 6b 4f 17 4b a7 8d` |
| Signature | `AE910531EF99F98FC229A21C5EA80E1D0FBF593E6A86B651EE28B98C77BDAD01` | `ae 91 05 31 ef 99 f9 8f c2 29 a2 1c 5e a8 0e 1d 0f bf 59 3e 6a 86 b6 51 ee 28 b9 8c 77 bd ad 01` |
| License valid | `true` | `OK - License valid` |

Exact match on every field. This is the first time `curve25519.rs`'s `curve25519-dalek`-based verifier has been exercised against a signature this project didn't already know was valid (§8.32's own test used `TI09-7WK3`, a signature this project had *already* separately confirmed via real hardware activation, §8.14) -- and it agrees exactly with a second, independently-written verification tool (`ParseLic.py`, a different implementation of the same EC-KCDSA algorithm) on a completely different signature. This is meaningful cross-validation: two independent implementations of the algorithm, fed the same real-world input neither was tuned against, produce identical results.

**Important caveat, not yet resolved:** a second commenter on the same issue states this specific license (`W5EY-LHT9`) "has been abused too much and has been blocked." Cryptographic validity and practical usability are different questions -- a signature can be mathematically valid (as confirmed above) while the specific SOFTWARE ID it corresponds to is blocklisted server-side or by a newer RouterOS version's local revocation list. **Planned next step, not yet done:** test this signature end-to-end on real hardware/VM (write it via MBR or `.key` import, boot, check `/system license print`) to determine whether "blocked" means RouterOS itself now refuses it locally, or only that MikroTik's *online* license-renewal endpoint refuses to reissue/extend it (in which case a one-time offline activation might still succeed). This distinction matters for this project's practical guidance -- if local verification alone can be blocklisted independent of the SOFTWARE ID collision method, that would be a new category of failure mode not previously documented anywhere in this file.

### 8.34 Real-hardware confirmation: `scsi0` collision search reused against an externally-supplied signature (`J1WN-449W`), full offline activation, no network

Continuing §8.33 with a second externally-supplied license found in the wild ([github.com/xSomoy/Study, `J1WN-449W.key`](https://github.com/xSomoy/Study/blob/e0f91d53cc60d509d2f5b38642467fcb5a89c1f7/Networking/Mikrotik-6/J1WN-449W.key)). `mtsc key2sig` decoded it independently: `Software ID: J1WN-449W`, `Router OS Version: 6`, `License Level: 1`, `License valid: true`. Unlike `W5EY-LHT9` (§8.33), no report of this specific ID being blocklisted was found anywhere.

**Ran a dedicated `-b scsi` collision search against this signature (fixed `model=RouterOS-SCSI`, `sector_val=0` regardless of disk size per §8.19) and found two colliding serials in ~4386s on a 2-core host** (`serial=00000000394117852659` and `serial=00000000547437415680`, both independently re-verified via `mtsc check`).

**Full offline end-to-end activation test, network-isolated (no `net0` device on the test VM at all)**, on a disposable VM (`VM301`, x86_64/`q35`, `scsihw=virtio-scsi-pci`, `scsi0` with `serial=00000000394117852659` + `-args '-set device.scsi0.product=RouterOS-SCSI'` for the product/model field, since PVE's native `--scsi0` syntax doesn't expose `product=` directly -- matches the exact mechanism already confirmed in §8.14/§8.18):

1. Installed RouterOS 7.23.2 fresh from ISO onto the `scsi0` disk (install-first, per this project's standard rule -- the installer overwrites `0x10A-0x10B`).
2. Stopped the VM. Since the disk is qcow2 (not a raw image or block device), wrote the MBR signature via `qemu-nbd` (`modprobe nbd` -> `qemu-nbd -c /dev/nbd0 -f qcow2 <disk>` -> `dd ... of=/dev/nbd0 bs=1 seek=256` for the 80-byte identity+marker+signature block at `0x100-0x14F` -- `dd` cannot write into a qcow2 file directly at a raw byte offset, only into an actual block device, hence the NBD step). Read the bytes back immediately after writing to confirm the disk-side content matched exactly, before booting.
3. Booted the VM (no serial console output on this x86/SeaBIOS setup, unlike the ARM64/UEFI VMs used throughout §8 -- used QEMU monitor `screendump` + local `ffmpeg` PPM->PNG conversion to observe the console instead, and `qm sendkey` to log in, since there is no network path into this VM at all).

**Result: `/system license print` shows `software-id: J1WN-449W`, `nlevel: 1` -- no `expires-in` line, no `ROUTER HAS NO SOFTWARE KEY` trial banner at boot.** This is unambiguous full activation, achieved with zero network connectivity at any point (install media is local ISO, no `net0` device exists on the VM) -- confirming this specific SOFTWARE ID's local, offline signature verification succeeds on real (well, production-topology) x86_64 hardware, entirely independent of MikroTik's online license servers.

**What this confirms:** the collision-search method (§1-7) generalizes cleanly to externally-sourced signatures found via community reports, not just this project's own curated `keys.toml` entries -- `mtsc search --bus scsi` found a working collision for a signature this project had never seen before, and that collision activated for real. (This section originally speculated here about *why* `W5EY-LHT9` might be blocked, reasoning from `J1WN-449W`'s clean success alone -- §8.35 tested `W5EY-LHT9` directly instead, and that speculation turned out to be wrong. See §8.35.)

### 8.35 `W5EY-LHT9` directly tested, real hardware, two different signatures -- both fail locally, offline, confirming §8.33's "blocked" report and overturning §8.34's speculation about *why*

§8.34 closed by speculating that `W5EY-LHT9`'s reported block was "most plausibly server-side/online-only," reasoning from `J1WN-449W`'s unrelated success rather than a direct test. That speculation is now known to be **wrong** -- tested directly, on the same real-hardware/offline setup as §8.34.

**Found a second `scsi0` collision for `W5EY-LHT9` itself** (a different `serial=`/`product=` combo than §8.33's decode target -- `serial=00000000249663178723`, `product="QEMU HARDDISK"` this time, found and supplied externally rather than by this project's own search run), independently re-verified via `mtsc check` before use. (Aside, purely mechanical: PVE's `args:` config line splits on whitespace with no quoting support of its own, so a `product=` value containing a space -- `QEMU HARDDISK` -- must be wrapped in literal quote characters *within* the `args:` string, e.g. `-args '-set device.scsi0.product="QEMU HARDDISK"'`, or the value silently splits into two broken arguments and QEMU fails to start.)

**Reused the same already-installed `VM301` disk for both tests in this section -- no reinstall between them.** Per this project's standard rule (install once, MBR write can be repeated freely -- only the *installer* overwrites `0x10A-0x10B`, not a later boot), each test only required: stop the VM, change `scsi0`'s `serial=`/`args` `product=` to the new combo, rewrite the 80-byte identity+marker+signature block via the same `qemu-nbd` procedure as §8.34, restart.

**Test 1 -- §8.33's original `W5EY-LHT9` signature (from `W5EY-LHT9.KEY`, the one reported "abused too much and has been blocked"):** boot shows the standard **`ROUTER HAS NO SOFTWARE KEY`** banner with a normal ~24h trial countdown. `/system license print` confirms: `software-id: W5EY-LHT9`, `expires-in: 23h49m10s`. **Not activated** -- falls back to plain trial, entirely offline (no `net0` device exists on this VM, so this cannot be an online server rejection).

**Test 2 -- a second, independently-sourced `W5EY-LHT9` signature (from `ros-key-v7.x.KEY`, §8.33's earlier find with the anomalous `License Level: 22` value):** same result. `ROUTER HAS NO SOFTWARE KEY` banner, `/system license print` shows `software-id: W5EY-LHT9`, `expires-in: 23h48m54s`. **Also not activated.**

**Conclusion: both cryptographically-valid `W5EY-LHT9` signatures fail the same way, locally, with zero network access at any point.** This rules out §8.34's speculation cleanly -- if the rejection were online/server-side only, a fully network-isolated VM could never observe it, since there is no path for it to even attempt contacting MikroTik. It also rules out "this one specific signature file was corrupted/mistyped" -- two independently-sourced signatures, decoding to different raw bytes but the same `Software ID`, both fail identically. The most coherent remaining explanation: **RouterOS 7.23.2's local, offline verification path checks something beyond the raw EC-KCDSA signature math for this specific SOFTWARE ID** -- most plausibly a hardcoded or otherwise locally-shipped blocklist of specific `SOFTWARE ID`s known to MikroTik to have been abused (the reported mechanism for "this license has been abused too much and has been blocked" line up with this being a *known, curated* blocklist rather than some accidental or narrow one-off signature defect) -- keyed on the `SOFTWARE ID` itself, not on the specific signature bytes, since both signatures (`8EBD34F8...` and `0AC14BD0...`) share the same ID and both were rejected identically. **Not yet located**: the actual code path in `keyman_arm32`/`keyman_x86_7.23.2` that performs this check has not been disassembled or found -- this section establishes the *behavior* (local offline blocklisting exists and is real) via black-box testing, not the mechanism. Finding it would require locating a data structure or comparison specifically keyed on SOFTWARE ID/software-id-derived values, separate from the EC-KCDSA verify path already mapped in §8.24-8.32 (which only concerns itself with *whether a signature is cryptographically valid*, not whether its Software ID is on any kind of list).

**Practical implication for this project:** the collision-search method's own validity is unaffected -- any SOFTWARE ID successfully found via collision search and confirmed to activate (as `J1WN-449W` was, §8.34) remains genuinely activatable. But it establishes, for the first time with direct real-hardware evidence, that **not every valid signature is safe to rely on** -- a specific ID being widely shared/reused in public `.key` file repositories appears to be a real risk factor for that ID ending up on a local blocklist, independent of anything about the collision-search technique itself. This is a new category of failure mode for this project's practical guidance: verifying a signature is cryptographically valid (`mtsc`'s `LICENSE-VALID: true`) is necessary but **not sufficient** to guarantee it will actually activate on current RouterOS versions.

### 8.36 External data point (unverified) -- `XGWP-9N00` / `D7240F566244`, real RouterBOARD `RBLtAP-2HnD`

Raw values from user-provided screenshots (RouterOS license/info + RouterBOARD/resource screens), recorded here for reference only -- **not yet checked against this project's SHA-256 pipeline** (this is hardware-key-based licensing on a real MIPS RouterBOARD, an entirely different mechanism from this project's x86/disk-based SOFTWARE ID collision search; `D7240F566244` is 12 hex chars, which also doesn't fit the 20-char serial field this project's `ide0`/`scsi0` search targets).

| Field | Value |
|---|---|
| Software ID | `XGWP-9N00` |
| Serial Number (RouterBOARD) | `D7240F566244` |
| Model | `RBLtAP-2HnD` |
| Firmware Type | `mt7621L` |
| Factory Firmware | `6.47.10` |
| Current Firmware | `7.23.2` |
| Upgrade Firmware | `7.23.2` |
| RouterOS Version | `7.23.2 (stable)` |
| Build Time | `2026-07-03 09:08:08` |
| Factory Software | `6.46.4` |
| Board Name | `LtAP` |
| Architecture | `mmips` |
| CPU | `MIPS 1004Kc V2.15`, 4 cores, 880MHz |
| Total Memory | `128.0 MiB` |
| Total HDD Size | `16.0 MiB` |
| Uptime (at capture) | `23:47:35` |

Confirms `D7240F566244` is the **RouterBOARD hardware Serial Number** (burned-in, MIPS device), not a disk serial -- consistent with this project's earlier note (§8.36 original entry) that it doesn't fit the x86 disk-serial format. This is a genuinely different licensing mechanism from the collision-search method (§1-7): RouterBOARD devices key off hardware-burned identity, not a virtual/physical disk's SOFTWARE ID via `ide0`/`scsi0`/NVMe. Not present anywhere else in this repo (`keys.toml`, `collision-database.md`) as of this writing -- confirmed via full-tree grep before adding. No further analysis done yet; revisit if this becomes relevant to a MIPS/ARM-specific investigation thread.

A second real RouterBOARD data point (`RB962UiGS-5HacT2HnT`, `qca9550L`, RouterOS 7.24 stable), same category (hardware-burned licensing, not disk-based), recorded for reference only:

| Field | Value |
|---|---|
| Software ID | `T55H-PFA8` |
| Serial Number (RouterBOARD) | `830608559EBF` |
| Level | `4` |
| Features | `extra-channels` |
| Model | `RB962UiGS-5HacT2HnT` |
| Firmware Type | `qca9550L` |
| Minimum Version | `3.41` / `6.34.2` |
| Current/Upgrade Firmware | `7.24` |
| Board Name | `hAP ac` |
| Architecture | `mipsbe` |
| CPU | `MIPS 74Kc V5.0`, 1 core, 720MHz |
| Total Memory | `128.0 MiB` |
| Total HDD Size | `16.0 MiB` |

### 8.37 `scsi0`-installed disk switched to `ide0` post-install (no reinstall): SOFTWARE ID computes correctly, activation still fails -- bus-type switching is NOT equivalent to same-bus identity reuse

§8.35 established that reusing an already-installed disk and only changing `scsi0`'s `serial=`/`product=` (same bus type) works cleanly for repeated activation tests -- no reinstall needed. This section tests a stronger claim: switching the *bus type itself* (`nvme` → `ide0`) on an already-installed disk, without reinstalling.

**Setup:** `VM302`'s disk (`vm-302-disk-0.qcow2`), originally installed via the `args:`-based raw NVMe passthrough method (§ NVMe investigation, `XGM9-BKRF` confirmed), was reconfigured -- VM stopped, `args:` NVMe device deleted, disk reattached as `ide0` with `serial=00000000251582663387,size=1G` (native PVE syntax accepts `serial=` directly for `ide0`) and `-args '-set device.ide0.model="SSD1G"'` for the model field -- reusing the exact `serial`/`model` combo from `docs/collision-database.md`'s `1G` `ide0` table (`TI09-7WK3`, previously confirmed `Y`). The `TI09-7WK3` MBR signature (`keys.toml`) was written via the standard `qemu-nbd` procedure, byte-verified on readback.

**Result:** the VM booted successfully off `ide0` despite having been installed via NVMe (bootloader was not bus-specific enough to fail outright -- itself a minor useful data point). `/system license print` showed:

```
software-id: TI09-7WK3
expires-in: 23h58m51s
```

**`software-id` computed correctly** (matches the `serial`/`model` → `TI09-7WK3` collision exactly, confirming the `ide0` sector-size-dependent SOFTWARE ID formula still applies correctly post-bus-switch), **but the license did not activate** -- still on the plain ~24h trial, despite `TI09-7WK3` being this project's most extensively real-hardware-confirmed signature (§8.14 and elsewhere).

**Interpretation:** this rules out an MBR-write mistake (bytes verified, and the same exact write procedure works in §8.34/8.35 for same-bus reuse). The most likely explanation is that RouterOS retains some installation-time state beyond the raw 64-byte MBR signature block -- keyed to the disk bus/identity present *at install time* -- that a later, different-bus identity change invalidates, even though the freshly-computed `software-id` field still matches the signature. **Practical implication:** collision-search testing across different bus types must use a **fresh install for each bus type**, not a bus-switched reuse of an existing installation -- same-bus identity reuse (§8.35) remains valid and fast, but is not a substitute for a real per-bus-type install when testing `ide0` vs `scsi0` vs `nvme` specifically. Not yet root-caused at the disassembly level; flagged as an open item if bus-switch behavior becomes relevant again.

### 8.38 CHR license format cross-check via `loskiq/MikroTikPatch`: confirms CHR uses `system_id`(8B), not `software_id`(6B) -- and one specific pasted CHR license is very likely a self-signed test artifact from that same tool, not a genuine MikroTik-issued license

An external project, [`loskiq/MikroTikPatch`](https://github.com/loskiq/MikroTikPatch) (`license.py`/`mikro.py`), was reviewed for its `lic_parse_chr`/`lic_gen_chr` functions. Cross-checking against this project's own confirmed constants:

- `mikro.py`'s `MIKRO_SHA256_K` table and custom IV (`0x5B653932, 0x7B145F8F, ...`) are **byte-identical** to this project's `sha256_constants.rs` -- independent confirmation from a second, unrelated codebase.
- Its hardcoded `MIKRO_LICENSE_PUBLIC_KEY = "8E1067E4305FCDC0CFBF95C10F96E5DFE8C49AEF486BD1A4E2E96C27F01E3E32"` matches this project's own EC-KCDSA public key (§8.32) exactly.
- **CHR's 16-byte decoded payload layout differs from ROS's**: ROS is `software_id(6B) + version(1B) + level(1B) + reserved(8B)` (this project's existing format); CHR is `opaqueId(8B) + deadline(4B) + level(1B) + reserved(3B)` -- **correction (2026-09-09, see §8.42)**: this was originally recorded here as `system_id(8B) + 3 unknown bytes + deadline(1B) + level(1B) + 3 reserved bytes`, based on `loskiq/MikroTikPatch`'s `varb9`/`varb10`/`varb11`/`varb12` naming (4 separate single-byte fields at payload offsets 8-11). Direct `keyman_x86_7.24.1` disassembly (§8.42) proves these 4 bytes are read and compared as a single little-endian 32-bit Unix-epoch `deadline` field, never accessed individually -- the "3 unknown bytes" never existed as independent fields, they're just the low 24 bits of `deadline`. The raw byte layout/values are unaffected (concatenating 4 individually-encoded bytes in order produces byte-identical output to encoding one LE u32), only the field-count/semantics were wrong. `mikro_systemid_encode`/`decode` use the *same* base64-style character table as the outer Key-text encoding (`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`), not the ROS `SOFTWARE_ID_CHARACTER_TABLE` -- a different alphabet from `TN0BYX18S5HZ4IA67DGF3LPCJQRUK9MW2VE`, and produces an 11-character (not 8-character/`XXXX-XXXX`) identifier.

**A specific CHR license text pasted into this session** (`System ID: eJq8zK/UrhN`, `Deadline: 244`, `Level: 3`) was decoded using this reimplementation and independently verified against this project's own `mtsc key2sig` (using the real MikroTik public key): `License valid: false`, with a `reserved bytes not all zero` warning (expected, since the bytes are CHR-format, not ROS-format). More tellingly, the decoded "unknown" filler bytes (`varb9=0, varb10=87, varb11=134`) **exactly match** `lic_gen_chr()`'s own hardcoded example defaults in `license.py`. This is strong circumstantial evidence that this specific license was generated by that tool's own `licgenchr` self-signing command (using a locally-generated key pair, per its `genkey` subcommand -- which explicitly documents patching `keyman`'s embedded public key to trust an attacker-controlled key) rather than being a genuine MikroTik-issued CHR license. This is a fundamentally different technique from this project's SOFTWARE-ID collision search -- it requires binary-patching the target's trusted public key, not finding a serial/model that reproduces a target ID.

### 8.39 ARM32 `keyman`'s hardware-identity call chain fully mapped (`getHardwareID` → `/dev/flash` / real-disk / string-fallback), and an exhaustive proof that neither of its two SOFTWARE-ID "combine" formulas can produce `XU4M-NJ40`

Triggered by an externally-supplied real-hardware case: `Model=C52iG-5HaxD2HaxD` (RouterBOARD, `ipq6000` SoC), `Serial=HE508Y4T7YB`, claimed working `SOFTWARE ID=XU4M-NJ40` (KEY text decoded and independently confirmed to encode exactly this ID, `Version=6`, `Level=4`, reserved bytes all zero -- genuine ROS format, not CHR). `mtsc check` with both `-b ide` and `-b scsi` (standard identity) computes different, non-matching IDs (`EUSF-AK1K`, `3GC2-T9RD`) for this serial/model/size -- as does an exhaustive enumeration of all 2048 possible non-standard `-i` identities (§ prior turn, both bus types) -- so this thread pivoted to disassembling `keyman_arm32` itself to find the *real* algorithm real hardware uses, rather than continuing to guess inputs for the x86/VM-calibrated formula.

**`keyman_arm_7.24.1`** (extracted this session from the current `routeros-7.24.1-arm64.npk`, i.e. what genuinely ships for ARM64-architecture devices) **is byte-identical (MD5 `ebdaa0f2f1b71cb535490c8e93c2c754`) to the pre-existing `keyman_arm32`** used throughout §8.24-8.32 -- confirming MikroTik ships the same 32-bit ARM binary for the "arm64" architecture package; there is no separate aarch64 `keyman` build, and all `keyman_arm32` findings apply directly to real ARM64 RouterBOARD hardware like this device.

**Call chain located (all addresses in `keyman_arm32`, file-offset-to-VMA delta `+0x10000` for `.text`/`.rodata`, a *different* delta for `.data` -- confirmed via `readelf -S`, not assumed):**

1. An `nv::message`-building function (caller context matches the same `raw_id`/`u64_id`/`u32_id` field-insertion pattern seen throughout this binary and in the x86 build) calls **`0x19b64`**, which tries, in order: a cache-check helper (`0x17574`), a second helper (`0x18b08`+`0x1762c`), then **directly `open("/dev/flash", "r")` + `ioctl(fd, 0x4601, buf)`** to read up to 512 bytes into a caller-supplied buffer, with an `fopen()`-based fallback on failure. Confirmed via literal-pool string resolution (`0xe2fa`-class VMA lookups on raw bytes, not `objdump`'s text output, which does not show cross-references for `ADR`/PC-relative-immediate-computed addresses): the path string genuinely reads `/dev/flash`.
2. This buffer is passed into **`0x18c28`** (the actual `getHardwareID`-equivalent compute engine -- confirmed by its own debug strings, `"getHardwareID: could not get disk %s info\n"` and `"%s: hdd-model='%.16s' s='%.20s' sz=%d MB\n"`, both resolved from literal-pool words), which itself branches:
   - **"Real device" path** (taken when `open("/dev/flash", O_RDWR)` -- note: a *second*, independent open of the same path, not reusing step 1's fd -- or a caller-supplied fallback path succeeds): `ioctl(fd, 0x80044604 /*BLKGETSIZE*/)` for a size, `ioctl(fd, 0x462b /*HDIO-identify-style*/)` for a ~512-byte structure. **Both ioctl numbers are byte-identical to the constants used in the equivalent x86 `keyman` real-disk code path.** Formula (read directly off the disassembly at `0x18d10-0x18d4c`): `sector_val = size & 0x1FFFFF; mix = sector_val * 0x10044` (same `0x10044` magic constant as x86); `raw_lo = identify_bytes[0:4]`; `raw_hi = (identify_bytes[4:8] & 0x1FF) | 0x200`; `final_lo = raw_lo XOR mix_lo`, `final_hi = raw_hi XOR mix_hi`.
   - **"Fallback" path** (`0x18d58` onward, reached when the real-device opens fail): issues `ioctl(fd, 0x31f, buf)` on whichever fd is open, then parses specific byte offsets within the result (`+58`, len 40; `+50`, len 8; `+24`, len 20 -- construction via repeated `bl 137ec`, a trim/format helper, and C++ `string` objects) into the same 20-byte-serial/16-byte-model buffers used throughout this binary (space-padded via the identical byte-for-byte loop shape as this project's own `build_serial_bytes`/`build_model_bytes` in `main.rs`). **Not yet confirmed**: whether `0x16ff8` (called with `len=40` here, but also called with `len=10`/`len=20` elsewhere with behavior that looks like plain `memcpy`) actually performs a MikroTik-SHA256 hash in this specific call, or is purely a copy/format utility whose output is read directly as `sid_lo`/`sid_hi` -- `0x16ff8`'s own body was not disassembled in this session. Flagged as an explicit open item, not resolved.
3. The **mix/identity source itself** -- **`0x17094`** -- is called with a 10-byte buffer pointer chosen between two candidates 256 bytes apart (`r7` vs `r7+256`) based on **`hasUefiSupport()`**'s return value (i.e. this device's boot-firmware type selects which of two parallel identity buffers is used). It copies the 10 bytes via `0x16ff8`, reads the first 2 bytes as a little-endian `u16` (**with an ARM-specific quirk not present in the x86 `mix_from_identity` Rust implementation: if this value is exactly `0`, it is replaced with the constant `0x1eef`/7919**), then XORs with the output of a second, not-fully-disassembled checksum function at `0x13808`.
4. The combine step (`0x19300-0x1931c`) reads exactly the same magic multiplier constant used by x86's `mix_from_identity` -- **`0x3FF800F`, confirmed to appear exactly once in the entire binary via raw byte search** (file offset `0x9368`, referenced by `ldr r3, [pc, #96]` at VMA `0x19300`) -- masks the identity-source value to 11 bits (`ubfx r0, r0, #0, #11`, i.e. `mbr_val` in `[0, 0x7FF]`, identical structure to x86), multiplies by `0x3FF800F` (`umull`), and XORs into the `sid_lo`/`sid_hi` pair.

**Exhaustive structural proof that neither combine formula can produce `hi=0x23` (`XU4M-NJ40`'s decoded high part):**

- For *both* formulas, the "mix" is `(an 11-bit-or-21-bit-masked value) * 0x3FF800F`, and a full brute-force over the entire valid input range confirms `mix_hi` (`mix >> 32`) **never exceeds `0x20`** for the 11-bit-masked (`mix_from_identity`-equivalent) case, and stays similarly small for the 21-bit-masked (`sector_val`) case across all `2^21` possible values -- confirmed by direct enumeration, not estimation.
- Both formulas unconditionally force a specific high bit before the final XOR (`| 0x100` fallback path, `| 0x200` real-device path) and `mix_hi` is never large enough to flip that bit back off. **Every known-good, real-hardware-activated x86 signature in this project's `keys.toml` (`TI09-7WK3`, `4MZF-SFTR`, `HHJH-UFWL`, `C7CU-PGT9`, `W5EY-LHT9`, `J1WN-449W`) decodes with bit `0x100` set in its high byte** -- an exact, exceptionless match to this structural prediction, independently confirming the formula's `|0x100` behavior from real data, not just static analysis.
- `XU4M-NJ40` decodes to `hi = 0x23` -- **bit `0x100` is unset AND bit `0x200` is unset**. Neither formula can produce this value for *any* choice of serial/model/size/identity/flash-content -- this is independent of correctly guessing the real hardware inputs.
- A full-binary sweep for every `umull` instruction (34 total) and every `orr rX, rX, #imm` with `imm` in `{64, 128, 256, 512, 1024}` (3 total: `0x40` at `0x17300` -- unrelated feature, `0x200` at `0x18d3c`, `0x100` at `0x192e4`) confirms **no third SOFTWARE-ID combine path exists anywhere in this binary**. (The other 28 `umull` sites cluster tightly in `0x145e8-0x1516c`, matching the already-documented EC-KCDSA/curve25519 bignum arithmetic, §8.24-8.32; two more, `0x1a950` and `0x1be14`, are an uptime-statistics scaling calculation and the soft-float `__muldf3`-style multiply routine respectively -- both unrelated, checked and ruled out.)

**Working hypothesis (not yet independently verified):** since this exact binary contains no code path capable of producing `XU4M-NJ40` from any local computation, genuine RouterBOARD hardware licensing for devices purchased through normal channels most plausibly does **not** rely on local SOFTWARE-ID recomputation-and-match at all (unlike x86/CHR) -- it is more likely tied to MikroTik's server-side/online RouterBOARD registration system, with the local `.key`-style text being an export/reflection of an already-server-approved state rather than something reproducible via collision search. This would mean the collision-search method (§1-7) is inapplicable in principle to genuine RouterBOARD hardware licenses, consistent with (and now offering a concrete mechanistic explanation for) §8.36's standalone observation that real RouterBOARD licensing is "a different mechanism." **Not yet done**: tracing the actual online-registration/activation code path to confirm this hypothesis directly, and disassembling `0x16ff8`/`0x13808` fully to close the one remaining open item in the local-computation side of this analysis.

**Also confirmed this session, filed for reference:** `tools/bin/` binaries were renamed to a consistent `keyman_{arch}_{version}` scheme (`keyman_x86_7.23.2`, `keyman_x86_7.24.1`, `keyman_arm_7.24.1`), with all path references across `README.md`, `AGENTS.md`, `tools/README.md`, `docs/toolchain.md`, `tools/rust/docs/architecture.md`, and `curve25519.rs` updated to match.

### 8.40 Confirmed discrepancy: `mtsc`'s own SOFTWARE ID computation disagrees with a real x86 `keyman` (RouterOS 6.49.13) at exact byte size `1,117,782,016` (real device, non-standard identity) -- open, unexplained, needs investigation

While tracing a real device's `VI8Q-E90F`/Level-4 signature (issue #1, MurVlad's reflashed x86 machine, `model=QEMU HARDDISK`, `serial=QM00001`, identity `50508089413009661362`, marker `0362`), two different real disk images of the *same physical device* gave conflicting exact byte sizes:

- A partial capture (first 10MB, MBR + partition table only) implied a lower bound of `1,071,645,184` bytes from the last partition's end sector. Building a fresh PVE VM with **exactly this size** and the identity/marker/signature above reproduced `software-id: VI8Q-E90F`, `nlevel: 4`, no `expires-in` -- confirmed genuine, permanent activation, both via `mtsc check` (matches) and real RouterOS 7.24.1 boot.
- A separate, older full-disk backup (Proxmox VMA, RouterOS 6.49.13, `2024-02-21`) of the *same device* extracted to a raw image of exactly `1,117,782,016` bytes (`qemu-img info` confirms QEMU sees this as the exact virtual size, no hidden padding). Booting this raw disk directly (not reconstructed -- the device's own real data) also shows `software-id: VI8Q-E90F`, `nlevel: 4`, no `expires-in` on real RouterOS **6.49.13**.

Both real disks -- different exact byte sizes, same identity/marker/signature -- genuinely activate as `VI8Q-E90F`/Level 4. But `mtsc check` with the *second* disk's exact byte size (`--disk-size 1117782016 --unit b`, same serial/model/identity) computes a **different** SOFTWARE ID (`7SQU-S9AM`), not `VI8Q-E90F`:

```
./target/release/mtsc check --serial QM00001 --disk-size 1117782016 --unit b \
  --model "QEMU HARDDISK" --identity 50508089413009661362
# Software ID: 7SQU-S9AM  (❌ does not match the real device's VI8Q-E90F)
```

This is a **confirmed, reproducible disagreement** between this project's own SOFTWARE ID algorithm and two independent real `keyman` binaries (RouterOS 6.49.13 and 7.24.1), not a measurement or precision error -- both the byte size and the identity/marker/signature bytes were read directly off real disk images, and QEMU independently confirms the exact virtual disk size it presents to the guest. Candidate explanations, **none yet verified**:

- A bug in this project's `round_sectors`/`sector_val` computation specific to this size range (`~1.04 GiB`, `sector_val` around `0x480`).
- A version-dependent difference in the real `keyman` algorithm between RouterOS 6.49.13 and 7.24.1 that happens not to matter for the sizes this project has tested so far (both real-device boots used the *same* signature/identity and both activated, so if there *is* a version difference, it isn't in how `VI8Q-E90F` itself validates -- it would have to be specifically in how `sector_val` is derived from the raw byte count).
- Something about how the VMA-extracted `1,117,782,016`-byte figure relates to the *actual* sector count RouterOS's own `keyman` reads at license-check time that isn't a simple `bytes / 512` (e.g. a reserved trailing region not counted by `keyman` but present in the backup).

**Not yet done:** disassembling the exact `sector_val` derivation path in both `keyman_x86_7.23.2`/`7.24.1` (already partially covered by earlier sections) against a from-scratch trace using this specific byte count, and checking whether RouterOS 6.x's `keyman` (not yet extracted/disassembled by this project) computes `sector_val` identically to 7.x. This is flagged prominently rather than silently worked around, since it means **this project's own algorithm cannot currently be trusted to be correct in this size range** until resolved.

### 8.41 Two reproducible workflows for pulling the embedded EC-KCDSA public key out of a `keyman` binary -- `objdump`/CLI and IDA Free's GUI decompiler, cross-validated against each other on a *patched* `keyman` with a substituted key

Both methods locate the same eight `mov [stack_offset], imm32` instructions found in §8.32 (function `0x804f4c6`, instructions at `0x804f658-0x804f6a2`), read as the public key's 32 bytes in little-endian, 4-byte-at-a-time order. Demonstrated end-to-end against a *different, patched* `keyman` binary (outside this repo, `/Volumes/未命名/Data/tmp/patch-web/keyman`) whose embedded key differs from §8.32's -- confirming both methods agree with each other and correctly distinguish a patched key from the stock one, not just re-deriving the same known-good answer.

**Method A -- `objdump` (CLI, no GUI required, matches §8.32's original process):**

1. `strings -a -t x keyman | grep -i "software key\|BEGIN MIKROTIK"` -- confirms the binary handles the local `.key`-file format, gives anchor string file offsets.
2. `objdump -h keyman` (get `.rodata`'s VMA) + `objdump -p keyman` (get the enclosing `LOAD` segment's `off`/`vaddr`) -- gives the file-offset-to-VMA delta for that segment (`+0x08048000` for this class of ET_EXEC i386 binary).
3. `objdump -d -r keyman > disasm.txt`, then `grep -n "<anchor VMA in hex, no 0x prefix>"` -- finds the `pushl $<addr>`-style references, which pinpoints the enclosing function.
4. Read that function's body: an ARX decode loop, immediately followed by **eight consecutive `movl $imm32, stack_offset(%ebp)` instructions** -- the public key, compiled as immediates rather than a contiguous data blob (why a plain byte-string search of `.rodata`/`.data` never finds it).
5. Concatenate the 8 little-endian dwords in program order to get the 32-byte key.

**Method B -- IDA Free 9.4's GUI + bundled Hex-Rays Cloud Decompiler (F5), no `idat`/`idat64` batch CLI needed (IDA Free doesn't ship one -- that's IDA Pro-only):**

1. Open the binary in IDA, let initial auto-analysis finish (Output window says "The initial autoanalysis has been finished").
2. `Jump!` dialog (the address-jump box) → type the target function address (from Method A, or from a prior analysis of the same binary if addresses are known to match) → Enter, to land in the disassembly graph view.
3. Visually confirm the 8 `mov [ebp+var_XX], imm32h` instructions in the graph node -- IDA already shows them in hex, so no manual decimal-to-hex conversion is needed at this stage.
4. Optionally press `F5` to decompile -- the same 8 constants appear as `v28[0..7] = <decimal>` inside a local array later passed into the scalarmult call (`sub_804DBA2(a1: v28)` in this session's run), which is useful for confirming the constants are actually used as the verification public key (not just coincidentally-placed bytes) and that the surrounding algorithm (XOR-combine, X25519 clamp, final `memcmp`) is unmodified.
5. **To go from the decompiler's decimal values back to the key bytes:** convert each to hex (negative decompiler values are the imm32 read as signed -- add `2^32` before converting, or just read the values from the disassembly view in hex instead of the decompiler's decimal, which sidesteps the conversion entirely), then byte-swap each 4-byte hex value (little-endian storage: `0x49011527` → bytes `27 15 01 49`), then concatenate all 8 byte-swapped groups in program order (`v28[0]`'s bytes first) to get the final 32-byte public key.

**Result on the patched binary (both methods agreed):** `271501494893987A0A50D41DFC7500FFD4F7B32F455F2C0E7C7439D3BD7B0876` -- confirmed different from this project's own `LICENSE_PUBLIC_KEY` (`src/curve25519.rs`) / §8.32's stock key (`8E1067E4305FCDC0CFBF95C10F96E5DFE8C49AEF486BD1A4E2E96C27F01E3E32`), consistent with this being a `MikroTikPatch`-style binary (§8.32's closing paragraph) where the embedded verification public key was swapped for a self-generated one, so a matching self-held private key can locally sign arbitrary licenses. The `keyman` binary itself only carries the *verification* side (the swapped-in public key); it does not on its own reveal the private key or a signing tool -- that would need to be separately found/analyzed if pursued further.

### 8.42 CHR license payload layout corrected (deadline is one 4-byte field, not "3 unknown + 1"), `/system license print`'s 5 CHR display fields traced to source, `.npk` format decoded, and console-resource field-ID bindings partially confirmed

This session revisited CHR licensing (§8.38) after the user proposed a more granular payload split (`opaqueId(8) + ??(1) + ??(1) + regdate(1) + renewdate(1) + level(1) + 000(3)`). Neither the original §8.38 layout nor the user's proposed split survived direct disassembly -- the correct layout, confirmed by instruction-level tracing, is:

```
offset 0-7    opaqueId    8 bytes (the payload's own copy of the id -- NOT what /system license print's "System ID" shows, see below)
offset 8-11   deadline    4 bytes, little-endian u32 Unix epoch. 0xFFFFFFFF (-1) = permanent, no deadline.
offset 12     level       1 byte
offset 13-15  reserved    3 bytes, expected zero
```

**Deadline is one field, not four.** Function `0x804f718` in `keyman_x86_7.24.1` extracts payload bytes 8-11 as a single dword and payload byte 12 as a separate byte -- there is no code anywhere that reads bytes 8, 9, or 10 individually. The 4-byte dword is compared exactly once, against `time()`, at its sole caller `0x8051b6f` (inside the license-info function `0x8051a9c`-`0x8052188`):
```
8051bb8: cmp edi, -1        ; edi = deadline (payload[8..12] LE). -1 sentinel = permanent, skip the whole block (-> 0x8051c05)
8051bf0: cmp edi, [ebp-0x4a4]   ; deadline vs time() (now)
8051bf6: setb al                ; al = 1 if deadline < now -> "expired"
```
`loskiq/MikroTikPatch`'s `license.py` naming (`varb9`/`varb10`/`varb11`=`"Unknown Value"`, `varb12`="Renew Date"/"Deadline" -- the same byte printed under two different words in that one script) directly supports this: it never treats bytes 8-10 as independently meaningful either, it just doesn't name them as part of one field. The `regdate`/`renewdate`-as-two-fields hypothesis proposed this session has no support in either the disassembly or the external tool's source and should be considered ruled out.

**All 5 fields `/system license print` shows for CHR, traced to their source** (license-info function `0x8051a9c`-`0x8052188`, CHR branch taken when `0x804bfb5()` returns true; the SAME function's other branch, taken when it returns false, handles bare-metal ROS -- see below):

| Displayed field | `nv::message` field id | Source |
|---|---|---|
| System ID | `0xd` (string) | **Locally computed**, not read from the license payload at all. Built by calling `0x804f858` (the SMBIOS-UUID + MBR system-id formula, `docs/reference/chr-system-id-formula.md`) then formatting via `0x804ffcf`. The payload's own `opaqueId(0-7)` bytes are never read in this function -- for a license to be valid its `opaqueId` presumably must match this locally-computed value, but that comparison (if it exists) happens in a separate, earlier validation function not traced here. |
| Level | `0xc` (u32) | Payload byte 12, unconditional copy, no lookup/switch (`0x8051baa`). |
| Deadline at | `0xe` (u32) | `tz_offset + deadline`, inserted only when `deadline != -1` (`0x8051be6`/`0x8051bd9`). |
| Next Renewal At | `0xf` (u32) | **Not a second license field.** It's `tz_offset + [param2+0x66c]`, a locally-computed, self-rescheduling watchdog-timer target time (traced to its write site at `0x8052e19`, inside a function at `0x8052aa2`): armed only in the final 30 days before `deadline` (`deadline - 2592000 < now`, `0x8052d8d`/`0x8052d98`), then fires every ~1-1.5h with `rand()`-jitter (`0x8052ded`-`0x8052dfa`) to re-check renewal/activation state. Displays "when will this machine next attempt an automatic renewal check", not a calendar date parsed from the license. |
| Limited Upgrades | `0x12` (bool) | Not fully confirmed (see console-resource findings below), but the strongest candidate is the ONLY other bool insert in this function: `deadline < now` (the same comparison that drives the expired flag), at `0x8051bfd`. |

**Bare-metal ROS's `level` (`nlevel: N`), for comparison**: same function, other branch (`0x8051c93` onward, not a separate function). Payload byte 7 (offset differs from CHR's byte 12 because bare-metal's payload is `software_id(6)+version(1)+level(1)+reserved(8)`, 8 bytes shorter before the level byte):
```
80520e6: mov dl, [ebp-0x429]   ; payload[7]
80520f1: and edi, 0xf          ; level & 0x0F -- no lookup, plain mask
8052113: call insert<u32_id>   ; message.insert(0x4, level_low_nibble)
```
Field `0x4`, unconditional mask-and-copy, no translation table -- confirms why bare-metal `nlevel` has always simply been the raw byte value (0/1/3/4/5/6) while CHR's `level` needs an actual string ("free"/"p1"/"p10"/"p-unlimited") with no confirmed numeric encoding (see below). The high nibble of the same byte goes to field `0x7`, looks like a reserved-flags nibble, zero on real licenses.

**`.npk` package format decoded** (needed to get more binaries than the standalone `keyman` extracts): magic `1ef1d0ba`, followed by a metadata header (package name, version, arch, description, checksum), then at a fixed file offset of **4096 bytes** a SquashFS 4.0 (xz-compressed) image runs to EOF -- `dd skip=4096 | unsquashfs` extracts it directly, no special tooling needed beyond what's already on macOS/Linux. Used to extract `system.npk` from a RouterOS 7.24.2 install ISO, yielding `nova/bin/{keyman,parser,login,sys2}` and `nova/lib/console/1073741824.mem` (a 2MB console-property resource, mmap'd at fixed VA `0x40000000` -- the filename is that address in decimal). `keyman` from this package is identical in relevant logic to the already-analyzed 7.24.1 build.

**Console-resource field-ID bindings** (`1073741824.mem`): the string "Limited Upgrades" (or any of the other 4 CLI display labels, capitalized-with-spaces) does not exist literally in ANY binary examined (`keyman`, `parser`, `login`, `sys2`) -- confirming they're generated at display time from hyphenated property names (`limited-upgrades` -> "Limited Upgrades") stored in the resource file, not from literal label strings. Recovered the per-property record format directly from the resource file's structure (name string, 0-padded, immediately followed by an 8-byte record: `[4-byte handler ptr][pad][1-byte field_id][0x01 0x00]`):
- **`0x4 <-> nlevel`: confirmed**, name-adjacent (`"nlevel\0\0"` at file offset `0x15a2dc` immediately followed by `field_id=0x04` at `0x15a2e9`).
- **`0xe <-> deadline-at`: confirmed**, same way (`"deadline-at\0"` at `0x15a3d4` immediately followed by `field_id=0x0e`).
- **`0xc <-> level`**: NOT name-confirmed -- no standalone `"level\0"` string exists anywhere in the 2MB file (only `nlevel` and unrelated MPLS `lsp-id`-adjacent false positives). `0xc` sits inside a tight, name-less run of records (`0xd,0xc,0x12,0xf`) immediately preceding the confirmed `deadline-at`/`0xe` record -- positionally it's exactly where a CHR `level` property should be, but this is circumstantial, not proven. It's possible CHR's level has no console property name at all (internal-only field).
- **`0x12 <-> limited-upgrades`**: circumstantial only. `0x12`'s handler pointer (`0x081019a0`) differs from the shared pointer (`0x08101c64`) used by the other integer/timestamp fields in the same cluster, consistent with a boolean-type getter -- but the `"limited-upgrades"` name string itself sits far away (file offset `0x16777`), with no name-adjacency evidence tying the two together.
- Closing this fully would require disassembling `parser`'s (or `login`'s) actual resource-file-parsing code to recover the authoritative record schema, rather than inferring it positionally -- not done this session, flagged as the natural next step if this thread is picked up again.

**Level byte -> CHR tier name (`free`/`p1`/`p10`/`p-unlimited`) mapping: still not found.** MikroTik's own official docs (manual.mikrotik.com, help.mikrotik.com) confirm CHR shows `level` as a string only, explicitly stating the bare-metal numeric `nlevel` scheme does not apply to CHR. A candidate 3-entry enum table exists in the resource file at offset `0x1d1094` (`0->p-unlimited`, `1->p1`, `2->p10`) but its only back-reference sits next to an unrelated renewal-timing (`immediate`/`after-1min`/`after-1h`) cluster, not next to anything level-related -- not bound to the `level` field, treat as unconfirmed/likely a different enum that happens to reuse those tier-name strings for some other purpose (e.g. a purchase/upgrade-prompt UI element). No external source (official docs, forum posts, the `loskiq/MikroTikPatch` tool) states a numeric byte value for any CHR tier either.

**Files**: this session's disassembly reused `backup/bin/analysis/x86_chr/keyman_x86_7.24.1.disasm.txt`; new extraction artifacts live outside the repo under `/tmp/mikrotik-7.24.2-extracted/` (not committed, scratch only -- re-derivable from a RouterOS install ISO via the `.npk` procedure above if needed again).

**Level value summary (ROS vs CHR), following directly from the above:**

- **Bare-metal ROS `nlevel`**: numeric, `{0, 1, 3, 4, 5, 6}` (2 does not exist) -- well-documented externally, and confirmed above as a direct, untranslated byte read (`payload[7] & 0x0F`, field `0x4`, no lookup table).
- **CHR `level`**: string-only in every source checked (MikroTik's own official docs never show a numeric alongside it, and explicitly state CHR does not use the `nlevel` numeric scheme) -- 4 known tier names: `free`, `p1`, `p10`, `p-unlimited`. The underlying payload byte (offset 12, field `0xc`) is confirmed to exist and be read by `keyman`, but **its byte-value-to-tier-name mapping is not confirmed by any evidence found this session** -- the one candidate 3-entry enum table in the console resource file (`0->p-unlimited`, `1->p1`, `2->p10`, no `free` entry) could not be bound to the `level` field (see above; its only back-reference sits next to an unrelated renewal-timing cluster). Treat as an open item, not a confirmed mapping.

### 8.43 `parser`'s console-resource loading mechanism confirmed real and deliberate (fixed-address `mmap` keyed by filename, self-validating header) -- but the record-dispatch/name-lookup layer itself not yet reached

Continuing §8.42's last open item (binding field ids `0xc`/`0x12` to console property names `level`/`limited-upgrades` via the resource file's real parsing code, rather than positional inference).

**Confirmed directly from `nova/bin/parser`'s disassembly** (not inferred): `main()` (`0x80d6c58`+) calls `nv::getAllDirs("/nova/lib/console", true)`, `opendir`/`readdir`-loops the results, filters entries by a `.mem` suffix (`strcmp`, `0x80d6d92`-`0x80d6da1`), and converts each entry's numeric filename prefix via `strtoul` (`0x80d6d7f`) into a `u32` used as a literal target address. A loader function at `0x807a57e` then does, per file: `open()` -> `fstat()` -> `mmap(addr=<that number>, length=st_size, PROT_READ, MAP_SHARED|MAP_FIXED, fd, 0)`, with a hard `cmp`-and-presumably-abort check (`0x807a5fd`) that the kernel actually honored the fixed address. This is airtight proof that `1073741824.mem`'s filename **is** the literal virtual address it gets mapped to (`0x40000000`) -- not a naming convention someone guessed at.

**New structural finding**: immediately after a successful mmap, `main()` reads `dword[base+0]` and compares it against a process-global "root" pointer (`0x81066d0`) -- the first-loaded resource file establishes the root, later ones must match or `parser` prints a `"warning, <addr>: <val> != root: <val2>"` diagnostic (`0x80d6ec5`-`0x80d6f1a`). On match, `dword[base+0x1c]` gets pushed into a second global (`0x81066c8`) via a generic vector-push helper (`0x80b0d96`, confirmed reused verbatim elsewhere, so not license-specific). This proves the resource file begins with a real, structured header (offset 0 = root-link, offset +0x1c = a second registered table/pointer) rather than records starting immediately at offset 0 -- consistent with there being an authoritative schema, though this particular header field wasn't traced to being the record table itself.

**Not reached**: `0x81066c8`'s only reads found in `parser` are its own two write sites -- no consumer of it was located, meaning the actual per-record name-lookup/field-id-dispatch logic is reached through further indirection (most plausibly: each record's own handler function pointer, called on demand rather than walked linearly at load time) that wasn't traced this session. `parser`'s full disassembly (~247k lines, saved at `/tmp/parser.disasm` on the working machine, not in-repo) would need deeper tracing of what consumes each record's handler-pointer field to close this. `login` was checked and does not independently implement this logic (no reference to `/nova/lib/console/<addr>.mem` beyond static logo text files) -- all of it lives in `parser`.

**Net effect on §8.42's open items**: `0x4<->nlevel` and `0xe<->deadline-at` remain the only two name-confirmed bindings. `0xc<->level` and `0x12<->limited-upgrades` remain circumstantial/positional only. The mechanism underlying the resource file is now known to be a real, deliberately-designed structure (not an artifact of positional coincidence), which increases confidence that SOME authoritative binding exists to find -- but closing it requires tracing the handler-pointer dispatch layer, not yet done.

### 8.44 Exhaustive byte-diff of a `MikroTikPatch`-style `keyman` against its real stock base (`7.24.1`, not `7.23.2`) finds a second, undocumented change beyond the substituted public key: the online license-server hostname is also redirected to a look-alike domain

Following up on §8.41's public-key extraction from an externally-supplied, already-patched `keyman` binary (outside this repo). That binary is exactly the same file size as this project's own `backup/bin/keyman_x86_7.24.1` reference (55,444 bytes) -- a byte-for-byte `cmp -l` against that reference (not the smaller `7.23.2`, which is a different build and diffs everywhere) found **only 35 differing bytes in the entire file**, in two disjoint clusters:

- **32 bytes at file offset `0x765e-0x76a1`**: the 8 embedded public-key dwords already documented in §8.41 (`271501494893987A0A50D41DFC7500FFD4F7B32F455F2C0E7C7439D3BD7B0876`).
- **3 bytes at file offset `0xc2fa-0xc2fc`**: the string `licence.mikrotik.com` (stock) changed to `licence.mikrotik.ltd` (patched) -- same length, same surrounding bytes, only the `com`/`ltd` TLD differs. This string sits immediately after an embedded `Content-Type: application/x-www-form-urlencoded\r\n` string, and the binary links `nv::HTTPFetch::post`/`nv::HTTPFetch::appendVar` (a MikroTik-internal HTTP client used for the online license activation/renewal flow already traced in §8.26/§8.27/§8.32).

**Practical implication**: this patched binary isn't only a "verify against a self-controlled key" modification -- if its online-activation code path ever runs, it POSTs form-encoded data (plausibly including hardware-identity/SOFTWARE-ID fields, matching that call chain's known purpose) to `licence.mikrotik.ltd`, a domain not controlled by MikroTik, rather than to the real `licence.mikrotik.com`. This project did not resolve, contact, or otherwise investigate that domain -- the finding is limited to "the hostname embedded in the binary was silently swapped for a look-alike," which is sufficient on its own to treat this specific artifact as untrustworthy for any network-connected use, independent of the licensing question.

**Filesystem/behavior scope, confirmed unchanged from stock by the same exhaustive diff** (i.e. every path below is byte-identical between the stock `7.24.1` and the patched binary -- the patch touches nothing here):

```
/dev/flash                              hardware-identity read (§8.24-§8.31, §8.39)
/dev/urandom                            PRNG seed only, see below
/dev/nvme%d, /dev/xvda, /dev/root-disk  disk-device probing (feeds SOFTWARE ID)
/nova/etc/license
/nova/etc/serial
/var/pckg/%s.key                        package license files
/sys/class/dmi/id/product_uuid
/proc/scsi/usb-storage/%u
```

**`/dev/flash` read detail**: `open("/dev/flash", ...)` followed by one of several `ioctl` calls depending on call site (`0x4601`, `0x80044604`, `0x462b`, confirmed in §8.24/§8.39) -- reads up to 512 bytes of the real RouterBOARD's own board-level identity/serial data out of flash, feeding into the `getHardwareID`/SOFTWARE-ID derivation chain. Meaningful only on real hardware; under QEMU/KVM this path is typically absent or behaves differently (§8.15-§8.18 traces the virtualized fallback).

**`/dev/urandom` read detail, traced this session** (x86, `0x804fdf0-0x804fe4f`, present identically in the *unmodified* stock `7.24.1` -- not part of the patch's 35-byte diff): `open("/dev/urandom", O_RDONLY)` -> `read(fd, buf, 4)` (exactly 4 bytes) -> `close(fd)` -> `gettimeofday(&tv, NULL)` -> `srand(<those 4 bytes> + tv.tv_sec)` -> `rand()`. This is a standard C-library `srand()`/`rand()` seed (4 real-random bytes mixed with the current timestamp), not a cryptographic operation -- consistent with this binary being verify-only (signing would need real entropy; this doesn't sign anything). Plausibly seeds a nonce/request-id used somewhere in the `HTTPFetch` POST flow (§8.44's `licence.mikrotik.ltd` finding), but the consumer of this specific `rand()` value was not traced.

No added/removed imports, no new file paths, no additional code -- the patch is exactly two surgical, same-length byte substitutions (public key, then hostname) inside an otherwise-untouched stock `7.24.1` binary. This is not itself evidence of what `licence.mikrotik.ltd` does when contacted (not tested), only that the substitution exists and is deliberate (matching length, no other bytes disturbed).

### 8.45 `/dev/flash`'s real-hardware read path in x86 `keyman` traced one level deeper -- corrects §8.44's "`ioctl 0x4601` reads up to 512 bytes" to "`0x4601` is a probe, `0x90004602` is the actual data read", and surfaces an unexplained `fopen(path, "--mbr")` fallback call

Continuing §8.44's file-access inventory with a deeper trace of the readMBR-equivalent function (x86, entry `0x8051200`, called from 15+ sites throughout `keyman` -- not yet all enumerated). This corrects an imprecision in this session's own earlier summary of `ioctl 0x4601`.

**Confirmed structure, real-hardware branch** (taken when the `board`-contains-`"qemu"` predicate at `0x804f902` is false -- the QEMU-true branch instead reads from a cached message-bus object via `0x80501bd`, per the existing §5/§8.15-§8.18 flow, and never touches `/dev/flash` at all):

```
fd = open("/dev/flash", O_RDONLY, 0)          ; 0x80540b9 = "/dev/flash"
rc = ioctl(fd, 0x4601, NULL)                  ; third arg is NULL, not a buffer --
                                               ; this is a probe/status call, not a data read
if (0x100 <= rc <= 0x4000):                   ; range-checked via (rc - 0x100) <= 0x3f00
    close(fd)
    buf_len = (rc + 0xf) & ~0xf               ; round up to 16 bytes, alloca'd on stack
    ioctl(fd, 0x90004602, stack_buf)          ; *** this is the actual data-fetching call ***
    n = min(returned_size, 0x200)             ; clamped to 512 bytes
    memcpy(caller_buf, stack_buf, n)          ; rep movsb into the caller-supplied buffer
else:
    fh = fopen(path_arg, "--mbr")             ; path_arg is the function's own first parameter,
                                               ; NOT the literal "/dev/flash" -- and the second
                                               ; argument really is the literal string "--mbr",
                                               ; not a real fopen() mode ("r"/"rb"/etc)
    fread(caller_buf, 512, 1, fh)
    fclose(fh)
```

**Correction to §8.44's phrasing**: that section said `ioctl(fd, 0x4601, buf)` "reads up to 512 bytes... into a caller-supplied buffer." That conflated two separate calls. `0x4601`'s third argument is `NULL` -- it cannot be reading into anything. The actual 512-byte(-clamped) read happens via the *second* ioctl, `0x90004602`, called only after `0x4601` succeeds and returns a value in `[0x100, 0x4000]`.

**Not yet explained**: the `fopen(path, "--mbr")` fallback. `fopen`'s second parameter is conventionally a mode string (`"r"`, `"rb"`, ...); `"--mbr"` is not a valid mode and looks instead like a CLI flag. Two explanations, neither confirmed:
1. This binary's linked `fopen` is genuinely glibc's `fopen`, and passing `"--mbr"` as the mode is either a latent bug in MikroTik's own code (glibc's `fopen` would likely just fail to parse recognized mode characters and behave unpredictably, e.g. defaulting to read-only) that happens not to matter because this branch is rarely/never reached on real hardware.
2. `open@plt`'s and `fopen@plt`'s underlying implementations for this binary are not plain glibc (the binary is dynamically linked against `/lib/libc.so`, per `file`'s `interpreter` field, but no evidence was gathered this session on whether that's glibc or an embedded/custom libc) -- if this platform's `fopen`-equivalent has different call semantics (e.g. mode selects a data source variant, similar in spirit to `getHardwareID`'s several source paths already documented), `"--mbr"` would make more sense as a genuine argument. Not investigated further this session.

**Also not yet done**: tracing what any of `0x8051200`'s 15+ callers actually extract from the resulting 512-byte buffer -- i.e. the byte-level field layout inside it (offsets for serial/board-type/production-date/whatever it contains) remains unknown. This is the same open item §8.39 already flags for the ARM build (two SOFTWARE-ID "combine" formulas exist, neither fully explains `XU4M-NJ40`) -- x86 hasn't closed it either. A real next step would be picking one or two of the 15 call sites and tracing forward from the `caller_buf` argument to see which offsets get read out of it.
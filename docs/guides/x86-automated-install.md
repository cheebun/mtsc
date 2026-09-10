# Automated RouterOS Installation via `qm sendkey`

Drive the RouterOS installer non-interactively from the PVE host shell, with no VNC/console viewer needed. **Primarily written for AI agents** (or any script/session with only shell/SSH access and no way to see a console screen) driving VM creation end-to-end — e.g. verifying a new collision entry without a human at a console. For manual, console-driven installation by a human, see [x86-install.md](x86-install.md) instead.

---

## Why `qm sendkey`

`qm sendkey <vmid> <key>` injects a single keystroke into the VM's virtual keyboard, the same as if you typed it in the PVE noVNC console. Chaining these calls drives the RouterOS text installer without ever opening a console viewer -- useful when working entirely over SSH to the PVE host.

**Limitation**: it's a one-way, blind interface. There is no way to read the screen back through `sendkey`; timing between steps must be estimated (see the sleeps below), and if the installer is in an unexpected state the sequence will silently do the wrong thing. Treat it as a best-effort automation, not a guaranteed one -- verify the outcome afterward (e.g. via MBR read-back or `/system license print`).

## Key names

`qm sendkey` uses QEMU's QKeyCode names, not raw characters:

| Key | QKeyCode |
|---|---|
| Enter | `ret` |
| Space | `spc` |
| Arrow down | `down` |
| Letters/digits | the character itself, e.g. `a`, `i`, `y` |

## Full sequence

Assumes the VM was created and booted with the ISO attached (`--ide2 local:iso/<file>,media=cdrom --boot order=ide2`) per [deployment-guide.md](x86-install.md).

```bash
VMID=302

# 1. Wait for the ISO to finish UEFI boot into the installer menu, then confirm
sleep 45
qm sendkey ${VMID} ret

# 2. Wait for the package selection screen to load
sleep 60

# 3a. Select package(s). Move the cursor with `down`/`up`, toggle the
#     highlighted package with `spc` -- repeat down/spc for each additional
#     package you want (selecting one package or several both work the same
#     way). Example: toggle the package two entries down from the default
#     cursor position (e.g. "container"):
qm sendkey ${VMID} down
qm sendkey ${VMID} down
qm sendkey ${VMID} spc

# 3b. Start the install -- send this as its own step, after package
#     selection is done (don't fold it into the same call as 3a: `i` starts
#     the install immediately, so any `down`/`spc` you meant to send first
#     needs to have already landed):
qm sendkey ${VMID} i

# 4. Confirm the "all data will be erased" warning
sleep 3
qm sendkey ${VMID} y

# 5. Wait for installation to finish, then acknowledge the reboot prompt
sleep 40
qm sendkey ${VMID} ret
```

After this, RouterOS reboots. If the VM's boot order still lists the CD-ROM first, it will boot back into the installer -- remove the ISO and fix the boot order immediately after step 5:

```bash
qm set ${VMID} --delete ide2
qm set ${VMID} --boot order=ide0
```

A clean `qm stop` / `qm start` cycle after this is more reliable than waiting for RouterOS's own reboot to pick up the corrected boot order:

```bash
qm stop ${VMID} --skiplock
sleep 3
qm start ${VMID}
```

## `scsi0`/`virtio-scsi-pci` variant

Everything above works identically for a `scsi0`-attached disk -- the installer's `sendkey` sequence doesn't care about disk bus type. Differences vs. the `ide0` examples above:

- Use `mtsc search`/`check --bus scsi` to get a `serial=`/`product=` combo (not `--model=`/`--serial=` from an `ide0` search -- see [license-internals.md §8](../investigation/license-internals.md#8-arm32-keyman-on-virtio-scsi-a-platform-specific-investigation) for why they're not interchangeable).
- VM config: `--scsihw virtio-scsi-pci`, `--scsi0 local:<vmid>/vm-<vmid>-disk-1.qcow2,serial=<serial>,size=<any size>` (disk size is irrelevant on `scsi0` -- `sector_val` is always `0` regardless of actual disk size, confirmed at both 1GiB and 2GiB), plus `--args '-set device.scsi0.product=<product>'` (no `vendor=` override needed -- it was confirmed to never participate in the hash computation).
- The MBR write step (below) is unchanged -- same offset (`0x100`), same header format, same signature encoding, regardless of bus type.
- Confirmed to fully activate (`nlevel: 6`, no `expires-in`) end-to-end on x86_64 with a fresh install and standard PVE-default `smbios1` -- no special SMBIOS configuration required.

## Verifying the result without console access

Since `sendkey` can't read the screen, and typing multi-line commands (network config, key import) character-by-character via `sendkey` is slow and error-prone, prefer the **MBR write method** to activate the license instead of console-based key import -- it requires the VM to be stopped, not a live console session:

```bash
qm stop ${VMID} --skiplock
sleep 2

modprobe nbd max_part=8
qemu-nbd --connect=/dev/nbd0 /var/lib/vz/images/${VMID}/vm-${VMID}-disk-1.qcow2
sleep 1

echo -n "00000000000000000000BDE800000000<signature-hex>" | xxd -r -p | dd of=/dev/nbd0 bs=1 seek=256 count=80 conv=notrunc

# Verify before disconnecting
hexdump -C -s 0x100 -n 80 /dev/nbd0

qemu-nbd --disconnect /dev/nbd0
qm start ${VMID}
```

See [command-reference.md](../reference/command-reference.md) for what each part of the `dd` command does.

To confirm activation, either check the console visually (`/system license print`, expect `nlevel: 6`), or -- if network is configured -- watch for the VM's MAC address to appear in the PVE host's neighbor table once it's reachable:

```bash
ip neigh show | grep -i <vm-mac-address>
```

---

## Lesson: real hardware disk sizes are not always round GB values

When registering a collision entry that came from a real physical disk (not a `ROS<N>G` virtual disk created for collision search), the **actual byte count matters**, not the nominal advertised size. Several existing entries in [collision-database.md](../database/collision-database.md) already reflect this:

| Model | Nominal | Actual bytes |
|---|---|---|
| `SSD08G` | 8G | `7,918,460,928` |
| `SSD32G` | 32G | `31,675,383,808` |
| `SSD64G2016` | 64G | `64,023,257,088` |
| `SSD16G` | 16G | `15,905,849,344` |

Creating the verification disk with the nominal power-of-2 size (e.g. `17179869184` for "16G") instead of the real device's actual byte count (`15905849344`) produces a **different `sector_val`**, and therefore a different computed SOFTWARE ID -- the collision will not reproduce. Always use the exact byte count the original device reported, not `<N> * 1024^3`.

---

## Lesson: signatures captured from real hardware need that hardware's identity bytes too

This project's own collision search always assumes a fixed, all-zero MBR identity region (`0x100-0x109`), giving a fixed `mbr_val = 0x0BD` and thus a fixed mix. Every serial `mtsc search` finds is specifically brute-forced to work with *that* fixed mix -- so writing the standard header (`00000000000000000000BDE800000000` + signature) always reproduces the correct SOFTWARE ID for those results.

**This does not hold for signatures extracted from a real physical device.** A real device's MBR identity bytes are whatever it shipped with -- not all-zero -- so its `mbr_val` (and therefore its mix) is different from the collision-search convention. The device's serial + model + disk size were only ever hashed against *that* device's own mix to produce its SOFTWARE ID.

This is not a new discovery -- it's exactly what [experiments.md](../investigation/experiments.md) Experiment 3 already documented from the earliest phase of this project: an original device's non-standard identity bytes stop matching the moment they're zeroed out. It's easy to lose sight of this once `mtsc search` -- which always assumes the fixed all-zero convention -- becomes the primary daily workflow.

Writing the *real* signature with the *standard* all-zero header, using that same serial/model/size, computes a **different** SOFTWARE ID than the one the signature was issued for -- the license import will appear to succeed (SOFTWARE ID and signature both look well-formed) but RouterOS falls back to a 24-hour trial (`expires-in` present, no permanent `nlevel: 6`), because the signature doesn't cryptographically validate for the SOFTWARE ID your disk actually computed.

**Fix**: when reproducing a signature captured from a real device, write the MBR identity bytes exactly as they were on that device, not the standard all-zero header:

```bash
# Standard collision-search header (works only for search results using the fixed mix)
HEADER="00000000000000000000BDE800000000"

# Real-device header: <original identity bytes (10 bytes)><BD E8><4 zero bytes>
HEADER="<original-10-byte-identity-hex>BDE800000000"

echo -n "${HEADER}<signature-hex>" | xxd -r -p | dd of=<disk> bs=1 seek=256 count=80 conv=notrunc
```

| | Collision search results | Real-device-captured signatures |
|---|---|---|
| Identity bytes (`0x100-0x109`) | Fixed all-zero | The original device's actual bytes |
| `mbr_val` / mix | Fixed `0x0BD` | Device-specific |
| Serial | Brute-forced for the fixed mix | The device's own serial, tied to its own mix |
| MBR header to write | Standard `00...BDE8...` | `<original identity>BDE8...` |

The `0x10A-0x10B` marker (`BD E8`) and the `0x10C-0x10F` reserved bytes are unaffected -- only `0x100-0x109` needs to match the source device.

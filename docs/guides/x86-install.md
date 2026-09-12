# PVE RouterOS VM Deployment Guide

Complete reference for creating, licensing, and troubleshooting a RouterOS x86 VM on Proxmox VE.

For a streamlined walkthrough, see [quick-start.md](../quick-start.md).

---

## Prerequisites

- Proxmox VE 8.x or 9.x
- RouterOS x86 ISO uploaded to PVE (Datacenter > Storage > ISO Images > Upload)
- A collision entry for your disk size from the [collision table](../database/collision-database.md)
- SSH access to the PVE host

> **Note**: Commands below use `100` as an example VM ID. Replace it with a VMID that is free on your PVE host -- check with `qm list` first.

---

## 1. VM Creation

### CLI Method (Recommended)

```bash
qm create 100 \
  --name ros100 \
  --machine q35 \
  --bios ovmf \
  --efidisk0 local:0,efitype=4m,pre-enrolled-keys=0,size=4M \
  --vga std \
  --cpu host \
  --cores 2 \
  --memory 2048 \
  --net0 virtio,bridge=vmbr0 \
  --scsihw virtio-scsi-single \
  --ostype l26 \
  --agent 0
```

### Web UI Method

PVE Web UI > Create VM:

| Setting | Value |
|---|---|
| VM ID | As needed |
| Name | e.g. `RouterOS-100G` |
| OS Type | Linux, 6.x - 2.6 Kernel |
| ISO Image | Uploaded RouterOS ISO |
| BIOS | **OVMF (UEFI)** |
| EFI Storage | local-lvm, check **Add EFI Disk** |
| Machine | q35 or i440fx |
| CPU | 1+ cores |
| Memory | 256 MB minimum |
| Disk | Any (will be replaced) |
| Network | virtio, bridged |

**Do not start the VM after creation.**

---

## 2. Disk Creation and Attachment

The disk size must match the collision table entry **exactly** (in bytes). The procedure differs by storage backend -- check which one you're using with `pvesm status`.

**This project's collision database (§1-7, `docs/collision-database.md`) is verified against `ide0` -- and, confirmed identical, `sata0`.** `keyman` computes the SOFTWARE ID differently depending on how the disk is presented to the guest kernel: `ide0` and `sata0`/AHCI both use real ATA IDENTIFY data (`sata0`'s QEMU device is `ide-hd`, the same device model as `ide0`, just on an AHCI controller) and are therefore interchangeable for collision-search purposes -- an `ide0` table entry activates on a same-size `sata0` disk with no changes. `scsi0`/`virtio-scsi-pci` is the outlier: it uses SCSI INQUIRY + VPD page 0x80, a genuinely different encoding (see [license-internals.md §8](../investigation/license-internals.md#8-arm32-keyman-on-virtio-scsi-a-platform-specific-investigation)). **A `serial=`/`model=` combo verified for `ide0`/`sata0` will not produce the same SOFTWARE ID on `scsi0`, and vice versa** -- use `mtsc`'s `--bus` flag matched to the target: `ide` covers `ide0` and `sata0`, `scsi` covers `scsi0`, and `nvme` uses the same size-dependent rounding as `ide`. For `--bus scsi`, `--size` can be omitted, but then `--model` is required.

`--bus scsi` search results **have been confirmed activatable end-to-end** on x86_64 (`scsi0`/`virtio-scsi-pci`, fresh install, standard PVE-default `smbios1`, no special configuration needed -- §8.18). On ARM64 (`virt` machine type specifically), the same disk-bus difference additionally interacts with a separate QEMU/KVM-virtualization-detection code path in `keyman` that can prevent the MBR signature from validating even when the SOFTWARE ID is correct (§8.15-8.17, unresolved for that platform) -- if targeting ARM64 + `scsi0`, verify activation on real hardware before relying on it.

### Backend A: Directory Storage (e.g. `local`, qcow2 files)

Example uses the 6G collision (`6442450944` bytes, model `ROS6G`); substitute the byte count for your disk size from the [collision table](../database/collision-database.md).

```bash
# Remove any default disk
qm set 100 --delete scsi0 2>/dev/null

# Create qcow2 with exact size
mkdir -p /var/lib/vz/images/100
qemu-img create -f qcow2 /var/lib/vz/images/100/vm-100-disk-1.qcow2 6442450944
```

### Backend B: LVM Storage (e.g. `local-lvm`)

`qm set --ide0 local-lvm:<GB>` only accepts whole gigabytes and cannot express the exact byte count most collisions require. Create the logical volume manually instead.

Find the volume group backing your storage first:

```bash
pvesm status              # confirm the storage type (lvmthin / lvm)
vgs                       # list volume groups, e.g. "pve"
lvs pve                   # list logical volumes, confirm thin pool name (e.g. "data")
```

**Thin-provisioned pool** (default `local-lvm`, pool `pve/data`):

```bash
lvcreate -T pve/data -V 6442450944B -n vm-100-disk-0
```

**Plain (thick) LVM volume group** (replace `pve` with your VG name from `vgs`):

```bash
lvcreate -L 6442450944B -n vm-100-disk-0 pve
```

Both create a block device at `/dev/pve/vm-100-disk-0` (adjust the path for your VG name). Verify the exact size:

```bash
blockdev --getsize64 /dev/pve/vm-100-disk-0
```

> If the LVM extent size rounds the volume up beyond the required byte count, the collision will not match. Precise byte-level sizing is only guaranteed on thin pools and directory (qcow2) storage; thick LVM is constrained to the VG's physical extent size (commonly 4 MiB) and may not hit an exact match for arbitrary collision entries.

### Attach Disk

Use `qm set` to attach the disk with the serial and model from your collision entry. Reference the disk by its storage-relative path:

```bash
# Directory storage
qm set 100 --ide0 local:100/vm-100-disk-1.qcow2,model=ROS6G,serial=00000000401012206606

# LVM storage (volume already created above)
qm set 100 --ide0 local-lvm:vm-100-disk-0,model=ROS6G,serial=00000000401012206606
```

### Model Names Containing Spaces

PVE's property-string parser (used by `qm set`) rejects literal spaces and shell quoting -- `model="VMware Virtual IDE Hard Drive"` fails with `invalid format - format error`. Use URL encoding (`%20`) instead:

```bash
qm set 100 --ide0 local:100/vm-100-disk-1.qcow2,model=VMware%20Virtual%20IDE%20Hard%20Drive,serial=00000000000000000001
```

PVE decodes `%20` back to a literal space before generating the underlying QEMU `-device` argument. Verify both sides:

```bash
# Confirm the encoded value is stored as-is in the VM config
qm config 100 | grep ide0

# Confirm QEMU decoded it to a real space (look for "model = ..." in the ide0 qdev block)
qm monitor 100
(qemu) info qtree
```

---

## 3. Installation

1. Start the VM and open the console (Web UI or `qm terminal`)
2. Press `a` to select all optional packages
3. Press `i` to install
4. Press `y` to confirm disk format
5. After installation completes, **shut down the VM** -- do not reboot

> **Critical**: The RouterOS installer overwrites MBR bytes `0x10A-0x10B` (sets them to `FF FF`). License data must be written **after** installation. See [experiments.md](../investigation/experiments.md) Experiment 2 for details.

---

## 4. License Activation

### Method A: MBR Write (Recommended)

Requires the VM to be shut down. Look up the signature for your SOFTWARE ID from the table below.

Example uses the C7CU-PGT9 signature and the older all-zero identity/BDE8 marker; substitute the row for your own SOFTWARE ID from the [Signature Table](../database/collision-database.md#signature-table).

**Search compatibility:** current `mtsc search` defaults to all 2048 `mbr_val` values and `--pad end` (right spaces). For a new result, preserve its printed serial and write its output **identity and marker**, not the fixed header in these examples. Recheck with `mtsc check --serial <serial> --size <N> --unit <g|m|k|b> --model <model> --identity <identity-from-search>` and the matching `--bus`; `check` without `--identity` still means all zeros. Short numeric serials show zero- and space-padding results separately. To search under this guide's original convention, add `--identity 00000000000000000000 --pad start` and keep the full 20-digit serial in the VM configuration.

**Directory storage (qcow2)** -- mount via `qemu-nbd` first:

```bash
modprobe nbd max_part=8
qemu-nbd --connect=/dev/nbd0 /var/lib/vz/images/100/vm-100-disk-1.qcow2
sleep 1

echo -n "00000000000000000000BDE800000000F4E11772DEEAED8AF43668DA5EBDAD0846B694FFE9E77EFAE77E11A6049E4303B0B09DCEF8D9A647D643D1BAD4AF13B9659CCB11A06D3A9080096634E4E88B07" | xxd -r -p | dd of=/dev/nbd0 bs=1 seek=256 count=80 conv=notrunc

# Verify
hexdump -C -s 0x100 -n 80 /dev/nbd0

qemu-nbd --disconnect /dev/nbd0
```

**LVM storage** -- the logical volume is already a block device, write directly (no `qemu-nbd` needed):

```bash
echo -n "00000000000000000000BDE800000000F4E11772DEEAED8AF43668DA5EBDAD0846B694FFE9E77EFAE77E11A6049E4303B0B09DCEF8D9A647D643D1BAD4AF13B9659CCB11A06D3A9080096634E4E88B07" | xxd -r -p | dd of=/dev/pve/vm-100-disk-0 bs=1 seek=256 count=80 conv=notrunc

# Verify
hexdump -C -s 0x100 -n 80 /dev/pve/vm-100-disk-0
```

Verification checklist:
- `0x100-0x109`: identity from the matching result (all zeros only for this example)
- `0x10A-0x10B`: marker from the matching result (`bd e8` only for this example)
- `0x10C-0x10F`: all zeros
- `0x110-0x14F`: matches the signature for your SOFTWARE ID

### Method B: Key Import (Online)

No shutdown required. The VM can be running after installation.

**Generate the key text and prepare the HTTP server on the PVE host:**

Generate the key text on demand from the signature hex in the [Signature Table](../database/collision-database.md#signature-table) below:

```bash
mtsc sig2key <signature-hex-from-table-above>
```

This outputs a unified stdout report with metadata, MBR signature hex, and a `License:` key-text field. Copy only the complete `-----BEGIN MIKROTIK SOFTWARE KEY-----...-----END...-----` block, without the label or metadata; do not redirect the whole report into a `.key` file.

```bash
mkdir -p /tmp/serve
cat > /tmp/serve/license.key << 'EOF'
<paste the output of mtsc sig2key for the corresponding SOFTWARE ID>
EOF
cd /tmp/serve && python3 -m http.server 8080 &
ip addr add 10.255.255.1/24 dev vmbr0 2>/dev/null
```

**In the RouterOS console:**

```
/ip address add address=10.255.255.2/24 interface=ether1
/tool fetch url="http://10.255.255.1:8080/license.key" dst-path=license.key
/system license import file-name=license.key
```

When prompted `Reboot? [y/N]:`, enter `y`.

> **Warning**: The file **must** have the `.key` extension. Using `.txt` causes `no new key found`.

### Method C: Console Direct Import

Generate the key text from the signature hex in the [Signature Table](../database/collision-database.md#signature-table) below, then paste only the complete `BEGIN`/`END` key block (not the `License:` label, metadata, or MBR hex) directly in the RouterOS console:

```bash
mtsc sig2key <signature-hex-from-table-above>
```

```
/system/license/import "-----BEGIN MIKROTIK SOFTWARE KEY------------
...
-----END MIKROTIK SOFTWARE KEY--------------"
```

Enter `y` to reboot when prompted.

---

## 5. Boot Configuration

For the MBR method, remove the CD-ROM and set boot order before starting:

```bash
qm set 100 --delete ide2
qm set 100 --boot order=ide0
qm start 100
```

The Key import method reboots automatically.

---

## 6. Verification

In the RouterOS console:

```
/system license print
```

Expected output:

```
  software-id: XXXX-XXXX
       nlevel: 6
     features:
```

`nlevel: 6` confirms L6 license activation.

---

## Troubleshooting

### VM Boots Into Installer Instead of RouterOS

The CD-ROM is still in the boot order:

```bash
qm set 100 --delete ide2
qm set 100 --boot order=ide0
```

### `ROUTER HAS NO SOFTWARE KEY`

License data missing or mismatched. Verify:

1. Serial and model match the collision table exactly
2. MBR identity and marker match the result (`BD E8` only for the all-zero identity example, not a universal marker; installer-written `FF FF` is not the expected license marker)
3. MBR was written **after** installation (the installer overwrites these bytes)
4. The signature at `0x110-0x14F` corresponds to the correct SOFTWARE ID

### SOFTWARE ID Does Not Match Expected Value

- Model or serial does not exactly match the collision table entry -- check with `qm config 100`
- Model contains spaces -- `qm set --ide0` does not reliably pass them; pick a space-free model when searching for a collision instead
- Disk size not exact -- confirm with `blockdev --getsize64 <device>` (LVM) or `qemu-img info` (qcow2); thick LVM volumes are rounded to the VG's physical extent size and may not land on an exact collision entry
- Confirm storage backend with `pvesm status` before assuming the qcow2 path is correct -- `local-lvm` disks are raw block devices, not files

### Key Import Returns `no new key found`

- File extension must be `.key`, not `.txt`
- The SOFTWARE ID displayed by RouterOS must match the SOFTWARE ID that the key was signed for
- Fall back to the MBR write method if the issue persists

### Migrating the VM to Another PVE Node

- Disk serial/model are stored in the VM config (`ide0:` line) and migrate automatically with it
- Do not convert qcow2 to raw format (changes disk geometry)

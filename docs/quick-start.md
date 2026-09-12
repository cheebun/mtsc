# Quick Start: Licensed RouterOS VM in 10 Minutes

Deploy a licensed RouterOS virtual machine on Proxmox VE using a pre-computed collision. The examples below use L6 signatures, but the technique works identically for any license level (L1-L6).

---

## Prerequisites

- Proxmox VE 8.x or 9.x host with SSH access
- RouterOS x86 ISO uploaded to PVE storage ([download](https://mikrotik.com/download))
- `mtsc` binary built (`cargo build --release`)

> **Note**: Commands below use `100` as an example VM ID. Replace it with a VMID that is free on your PVE host -- check with `qm list` first.

---

## Step 1: Look Up a Collision

Pick your disk size from the table below. For sizes not listed, see the [full collision table](database/collision-database.md).

| Disk Size | Bytes | Serial | Model | SOFTWARE ID |
|---|---|---|---|---|
| 128M | 134,217,728 | `00000000545657840722` | `ROS128M` | 4MZF-SFTR |
| 1G | 1,073,741,824 | `00000000251582663387` | `SSD1G` | TI09-7WK3 |
| 6G | 6,442,450,944 | `00000000401012206606` | `ROS6G` | C7CU-PGT9 |
| 8G | 8,589,934,592 | `00000000106987476296` | `ROS8G` | 4MZF-SFTR |
| 16G | 17,179,869,184 | `00000000202155543391` | `ROS16G` | 4MZF-SFTR |
| 32G | 34,359,738,368 | `00000000031682233604` | `ROS32G` | TI09-7WK3 |
| 48G | 51,539,607,552 | `00000000398318370243` | `ROS48G` | TI09-7WK3 |
| 64G | 68,719,476,736 | `00000000350481748276` | `ROS64G` | C7CU-PGT9 |
| 100G | 107,374,182,400 | `00000000418756277141` | `ROS100G` | 4MZF-SFTR |
| 128G | 137,438,953,472 | `00000000311309782924` | `ROS128G` | 4MZF-SFTR |
| 256G | 274,877,906,944 | `00000000031811615027` | `ROS256G` | 4MZF-SFTR |
| 512G | 549,755,813,888 | `00000000037935077152` | `ROS512G` | TI09-7WK3 |

All entries above use space-free model names, so no `%20` encoding is needed.

The table and fixed MBR header in this walkthrough use the older **20-digit zero-padded serial + all-zero identity** convention. For unlisted sizes, the following command preserves that convention (see [command-reference.md](reference/command-reference.md); sub-1GiB sizes use `--unit m/k/b`, minimum 64MiB):

```bash
mtsc search --disk-size <N> --unit <g|m|k|b> --threads <threads> --count 0 --keys keys.toml --identity 00000000000000000000 --pad start
```

For the current defaults, omit `--identity` and `--pad`: search covers all 2048 `mbr_val` values per candidate and right-pads the natural serial with spaces. **Use the output serial, identity, and marker together**; replace Step 5's entire MBR hex with the matching result rather than reusing its all-zero/BDE8 header. Recheck with `mtsc check --serial <serial> --disk-size <N> --unit <g|m|k|b> --model <model> --identity <identity-from-search>`; `check` otherwise defaults to all-zero identity and shows both padding variants for short numeric serials.

---

## Step 2: Create VM

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

Alternatively, create via Web UI: OS Type = Linux 6.x, BIOS = OVMF (UEFI), check Add EFI Disk. Do not start the VM yet.

---

## Step 3: Create Exact-Size Disk and Attach

Example uses the 6G collision (`6442450944` bytes, model `ROS6G`, serial `00000000401012206606`); substitute your own values from the [collision table](#step-1-look-up-a-collision).

```bash
mkdir -p /var/lib/vz/images/100
qemu-img create -f qcow2 /var/lib/vz/images/100/vm-100-disk-1.qcow2 6442450944
```

Attach with serial and model:

```bash
qm set 100 --ide0 local:100/vm-100-disk-1.qcow2,model=ROS6G,serial=00000000401012206606
```

> If your model contains spaces (e.g. `VMware Virtual IDE Hard Drive`), URL-encode them as `%20` -- see [deployment-guide.md](guides/x86-install.md#model-names-containing-spaces).

---

## Step 4: Install RouterOS

1. Attach the ISO: `qm set 100 --ide2 local:iso/<RouterOS_ISO>,media=cdrom --boot order=ide2`
2. Start VM, open console
3. Press `a` (select all packages), `i` (install), `y` (confirm format)
4. After installation completes, **shut down the VM** (do not reboot)

---

## Step 5: Write MBR License

Look up the signature for your SOFTWARE ID in the [Signature Table](database/collision-database.md#signature-table). Example below uses the C7CU-PGT9 signature, matching the 6G collision used throughout this walkthrough; substitute your own row.

```bash
modprobe nbd max_part=8
qemu-nbd --connect=/dev/nbd0 /var/lib/vz/images/100/vm-100-disk-1.qcow2
sleep 1

echo -n "00000000000000000000BDE800000000F4E11772DEEAED8AF43668DA5EBDAD0846B694FFE9E77EFAE77E11A6049E4303B0B09DCEF8D9A647D643D1BAD4AF13B9659CCB11A06D3A9080096634E4E88B07" | xxd -r -p | dd of=/dev/nbd0 bs=1 seek=256 count=80 conv=notrunc

hexdump -C --disk-size 0x100 -n 80 /dev/nbd0
qemu-nbd --disconnect /dev/nbd0
```

Verify this example's `0x10A-0x10B` reads `bd e8`; `0x110` onward must match the signature. For a new sweep result, verify `0x100-0x109` and `0x10A-0x10B` against its output identity and marker instead.

---

## Step 6: Boot and Verify

```bash
qm set 100 --delete ide2
qm set 100 --boot order=ide0
qm start 100
```

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

`nlevel` should match the license level of the SOFTWARE ID you used (`6` for this walkthrough's example).

---

## Alternative: Key Import Method

Instead of writing the MBR offline, you can import a key file while RouterOS is running. No shutdown required after installation.

Generate the key text from the signature hex for your SOFTWARE ID (see the [Signature Table](database/collision-database.md#signature-table)):

```bash
mtsc sig2key <signature-hex-from-table>
```

This prints metadata, MBR signature hex, and a `License:` field on stdout. Copy **only the complete `-----BEGIN MIKROTIK SOFTWARE KEY-----...-----END...-----` block**, without the `License:` label or metadata, into the key file on the PVE host; do not redirect the entire command output as a `.key` file:

```bash
mkdir -p /tmp/serve
cat > /tmp/serve/license.key << 'EOF'
<paste the output of mtsc sig2key here>
EOF
cd /tmp/serve && python3 --model http.server 8080 &
ip addr add 10.255.255.1/24 dev vmbr0 2>/dev/null
```

In the RouterOS console:

```
/ip address add address=10.255.255.2/24 interface=ether1
/tool fetch url="http://10.255.255.1:8080/license.key" dst-path=license.key
/system license import file-name=license.key
```

Enter `y` when prompted to reboot.

> The file **must** have the `.key` extension. `.txt` will fail silently.

See [deployment-guide.md](guides/x86-install.md) for the full signature table and detailed import instructions.

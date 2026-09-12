# Toolchain Reference

Tools, dependencies, and operational commands used in this project.

---

## External Projects

| Project | URL | Used For |
|---|---|---|
| MikroTikPatch | https://github.com/elseif/MikroTikPatch | Custom SHA-256 constants (IV, K), MTBase64, KCDSA implementation in `mikro.py`; `keygen_x86` binary analysis |
| MTLic | https://github.com/Ygnecz/MTLic | License file parser, `MT_Transform`/`MT_TransformRev` encrypt/decrypt, MTBase64 encode/decode |

---

## mtsc (This Project)

Rust-based collision search tool with portable scalar and CPU-selected SHA-NI, AVX2, AVX-512, ARM SHA2, and NEON backends. Startup calibration selects a supported backend once for the requested thread count; candidate generation and both identity modes retain backend-owned batch sizes. See [SHA-256 backends](sha256-backends.md).

### Build

```bash
# Portable release: runtime detection/calibration selects supported kernels
cargo build --release

# Optional machine-local optimization; do not distribute to older CPUs
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

The Cargo package, library, and binary are named `mtsc`; the local executable is `target/release/mtsc` (`target/release/mtsc.exe` on Windows). The GitHub repository is `cheebun/mtsc` (renamed from `ros-serialgen` alongside the package).

### Search

`--size` is a magnitude paired with `--unit` (`g`/`m`/`k`/`b`, default `g`, powers of 1024). Minimum supplied size is 64MiB. `--bus nvme` uses IDE's rounding; `--bus scsi` forces `sector_val=0` and can omit size if `--model` is explicit.

Default search sweeps all 2048 `mbr_val` values and uses `--pad end` (right spaces), so deploy each result's serial, identity, and marker together. Add `--identity 00000000000000000000 --pad start` for the old fixed-identity, zero-padded convention. Candidates are always drawn from a fixed base-36 alphabet (digits then uppercase letters) -- there is no `--alphabet` flag. `--from` counts millions of `u64` candidate indices; keep all search parameters unchanged when resuming. See [command-reference.md](command-reference.md).

```bash
# Search for a collision at a given disk size
mtsc search --size <N> --unit <g|m|k|b> --threads <threads> --count 0 --keys keys.toml

# Sub-1GB sizes
mtsc search --size 128 --unit m --threads <threads> --count 0 --keys keys.toml

# Resume from checkpoint
mtsc search --size <N> --unit <g|m|k|b> --threads <threads> --count 0 --from <progress_M> --keys keys.toml

# Background execution
nohup mtsc search --size <N> --unit <g|m|k|b> --threads <threads> --count 0 --keys keys.toml \
  > /tmp/results.txt 2> /tmp/progress.txt &
```

### Verify

```bash
mtsc check --serial <Serial> --size <N> --unit <g|m|k|b> --model <model> --identity <identity-from-search>
```

`check` defaults to all-zero identity if omitted, not a sweep. It prints both zero- and space-padding variants for a short numeric serial, but only once if the resulting 20-byte input is identical.

### Build checks and runtime self-check

```bash
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo fmt --check
mtsc verify
```

`verify` runs the production algorithm self-check without a key/license file.

---

## PVE Operation Reference

### VM Lifecycle

| Command | Purpose |
|---|---|
| `qm create <VMID> ...` | Create VM |
| `qm set <VMID> --ide0 ...` | Attach disk with serial/model |
| `qm set <VMID> --delete <device>` | Remove disk or CD-ROM |
| `qm config <VMID>` | View VM configuration |
| `qm start/stop/destroy <VMID>` | VM lifecycle control |

### Disk Operations

| Command | Purpose |
|---|---|
| `qemu-img create -f qcow2 <path> <bytes>` | Create exact-size qcow2 disk |
| `modprobe nbd max_part=8` | Load NBD kernel module |
| `qemu-nbd --connect=/dev/nbd0 <qcow2>` | Mount qcow2 as block device |
| `dd of=/dev/nbd0 bs=1 seek=256 count=80` | Write 80-byte MBR license data |
| `hexdump -C -s 0x100 -n 80 /dev/nbd0` | Verify MBR license region |
| `qemu-nbd --disconnect /dev/nbd0` | Disconnect block device |

---

## Reverse Engineering

### keyman Extraction from RouterOS

```bash
# Extract squashfs from RouterOS image (NPK format)
dd if=/rw/pdb/system/image of=/tmp/routeros.squashfs bs=1 skip=4096
unsquashfs -d /tmp/squashfs_edit /tmp/routeros.squashfs
cp /tmp/squashfs_edit/nova/bin/keyman /tmp/keyman
```

### keyman Analysis

```bash
# Run keyman via chroot on PVE
mount --bind /dev /tmp/ros_chroot/dev
ln -s /dev/sda /tmp/ros_chroot/dev/root-disk
chroot /tmp/ros_chroot /bin/qemu-i386-static -strace /nova/bin/keyman --software-id
```

Key findings:
- keyman reads disk serial/model via `ioctl(HDIO_DRIVE_CMD, ATA_CMD_ID_ATA)`
- RouterOS custom ioctl `0x80044604` takes priority over HDIO
- keyman resides in squashfs (read-only); cannot be replaced without firmware modification
- RouterOS 7.23.2 has closed the devel backdoor

---

## C Brute-Force Bug Fix History

| Version | Bug | Fix |
|---|---|---|
| bf3 | `snprintf` null terminator overwrote first byte of model | Used tmp buffer + `memcpy` |
| bf4 | SHA-256 output byte order wrong (stored LE, should be read BE then LE) | Corrected to BE output, LE read |
| bf5 | MBR mix value hardcoded wrong (`0x1EEF` default, not actual) | Computed actual `sha_val=0x1742`, `mbr_val=0x0BD` |
| bf6 | Search space assumed wrong MBR header | Discovered key import bypasses the MBR header issue |

The C tool has been superseded by mtsc (Rust, startup-selected multi-architecture CPU backends).

---

## Key Experimental Findings

| Experiment | Finding |
|---|---|
| VM 920 vs 921 | Installer overwrites `0x10A-0x10B` (`BD E8` -> `FF FF`) |
| VM 916 (16G) | Disk size affects SOFTWARE ID |
| Differential analysis | Both serial and model participate; no ATA byte swap |
| 6G vs 42G signatures | Signature binds to SOFTWARE ID, not disk parameters |
| `.txt` vs `.key` import | Only `.key` extension is accepted |
| MBR write vs key import | Both activate L6; key import is simpler |

See [experiments.md](../investigation/experiments.md) for full details.

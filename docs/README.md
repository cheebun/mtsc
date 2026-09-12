# Documentation Index

This directory is organized by what you're trying to do, not by when a page was written.

## Start here

- **[quick-start.md](quick-start.md)** — deploy a licensed RouterOS VM in 10 minutes using a pre-computed collision.

## guides/ — step-by-step walkthroughs

- **[x86-install.md](guides/x86-install.md)** — full manual PVE deployment reference (VM creation, disk backends, MBR write vs Key import, model names with spaces).
- **[x86-automated-install.md](guides/x86-automated-install.md)** — drive the RouterOS installer non-interactively via `qm sendkey`, for AI agents/scripts with no console access.
- **[nanopi-r5s-install.md](guides/nanopi-r5s-install.md)** — ARM64 install on a NanoPi R5S PVE host (no IDE/SATA bus workaround).

## reference/ — algorithm and command reference

- **[architecture.md](reference/architecture.md)** — algorithm overview and security analysis.
- **[sha256-backends.md](reference/sha256-backends.md)** — CPU detection, native batch sizes, correctness tests, and benchmark commands.
- **[benchmark results](benchmarks/README.md)** — measured Ryzen 7 5800H and Apple M4 performance and reproduction commands.
- **[identity-marker-formula.md](reference/identity-marker-formula.md)** — how MBR `marker` bytes derive from `identity` bytes.
- **[command-reference.md](reference/command-reference.md)** — every `mtsc` subcommand and flag explained.
- **[toolchain.md](reference/toolchain.md)** — external projects, in-house tools, and PVE operations used in this project.

## database/ — verified collision data

- **[collision-database.md](database/collision-database.md)** — verified SOFTWARE ID / serial / model combinations (`ide0`/`sata0` and `scsi0`).
- **[mbr-data.md](database/mbr-data.md)** — real-device MBR captures with non-standard identity/marker bytes (raw source data — do not edit).
- **[nvme-collision-database.md](database/nvme-collision-database.md)** — collision search seeds for QEMU's NVMe controller model string, by disk size.
- **[scsi-collision-database.md](database/scsi-collision-database.md)** — verified `scsi0` collisions plus search seeds for the `RouterOS-SCSI` model.
- **[vmware-ide-collision-database.md](database/vmware-ide-collision-database.md)** — collisions for PVE's default `ide0` model string.
- **[vmware-sata-collision-database.md](database/vmware-sata-collision-database.md)** — collisions for PVE's default `sata0` model string.

## investigation/ — reverse-engineering notes and experiment log

- **[license-internals.md](investigation/license-internals.md)** — SOFTWARE ID / MBR deep dive, based on `keyman` disassembly.
- **[arm-reverse-engineering.md](investigation/arm-reverse-engineering.md)** — ARM32 `keyman` disassembly notes.
- **[experiments.md](investigation/experiments.md)** — verification experiment log.

---

Restricted-signature policy (`WUB2-EYCK`, `HCC0-4FJR`, `XU4M-NJ40`): see the root `AGENTS.md`.

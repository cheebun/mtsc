//! RouterOS L6 Serial Generator — computes serials from existing licenses + key conversion tool
//!
//! Supports AVX-512 SIMD acceleration: computes 16 SHA-256 hashes per batch,
//! auto-detected at runtime with fallback to the scalar implementation.

mod convert;
mod curve25519;
mod mbr_table;
mod sha256;
mod sha256_constants;
#[cfg(test)]
mod sha256_scalar;
mod sha256_simd;
mod software_id;
mod targets;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

// ---- Constants ----

/// Space padding byte in SHA-256 input (RouterOS convention)
const SPACE_PADDING: u8 = 0x20;
/// Serial field length (20-digit decimal ASCII)
const SERIAL_LEN: usize = 20;
/// Model field length (16 bytes, space-padded)
const MODEL_LEN: usize = 16;
/// Total SHA-256 input length: serial(20) + model(16) + sector_val(4)
const INPUT_LEN: usize = SERIAL_LEN + MODEL_LEN + 4;
/// Number of lanes computed in parallel per SIMD batch
const SIMD_LANES: usize = 16;
/// Progress report interval (every 10,000M = 10 billion hashes)
const PROGRESS_INTERVAL: u64 = 10_000_000_000;

// ---- CLI definition ----

#[derive(Parser)]
#[command(name = "ros-serialgen")]
#[command(about = "RouterOS L6 Serial Generator — collision search & key conversion")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Search collision serial for a disk size
    Search {
        /// Disk size magnitude (paired with --unit). Required for --bus ide/nvme; optional
        /// (and ignored) for --bus scsi, where sector_val is always forced to 0.
        #[arg(short = 's', long = "disk-size")]
        disk_size: Option<u64>,
        /// Disk size unit: g (gigabytes, default), m (megabytes), k (kilobytes), or b (bytes)
        #[arg(short = 'u', long, value_enum, ignore_case = true, default_value = "g")]
        unit: SizeUnit,
        /// Thread count
        #[arg(short, long)]
        threads: Option<usize>,
        /// Model name (default: ROS<size><unit>, e.g. ROS100G, ROS128M)
        #[arg(short, long)]
        model: Option<String>,
        /// keys.toml path
        #[arg(short, long)]
        keys: Option<String>,
        /// Number of collisions to find (default: 1, 0 = unlimited)
        #[arg(short = 'c', long, default_value = "1")]
        count: usize,
        /// Start from N million hashes (resume from progress output)
        #[arg(short = 'f', long, default_value = "0")]
        from: u64,
        /// Non-standard 20-hex-char MBR identity seed (0x100-0x109), e.g. from a real
        /// device's captured MBR. Default: sweep all 2048 possible mbr_val values per
        /// candidate serial instead of a single fixed identity (see --mbr-table).
        #[arg(short = 'i', long)]
        identity: Option<String>,
        /// Disk bus type: ide (default, verified against real hardware -- also covers
        /// sata0/AHCI, which uses the identical encoding), nvme (same sector_val rounding
        /// as ide), or scsi (scsi0/virtio-scsi-pci specifically, NOT sata0 -- forces
        /// sector_val=0; see docs/license-internals.md §8.11-8.20; end-to-end activation
        /// confirmed on x86_64, §8.18).
        #[arg(
            short = 'b',
            long,
            value_enum,
            ignore_case = true,
            default_value = "ide"
        )]
        bus: BusType,
        /// Path to the mbr_val -> identity/marker lookup table, used only when --identity is
        /// NOT given (full mbr_val sweep mode). Default: ./mbr-table.toml if present,
        /// otherwise an embedded complete table. Any mbr_val missing from this file is
        /// filled in from the embedded default, so an incomplete file is never a hard error.
        #[arg(long = "mbr-table")]
        mbr_table: Option<String>,
        /// How numeric candidate serials are padded to 20 bytes: zero (default, left-pad
        /// with '0', e.g. "123" -> "00000000000000000123") or space (right-pad with spaces
        /// using the natural digit count, e.g. "123" -> "123                 "). Real disks
        /// don't always zero-pad a short numeric serial (confirmed on real hardware: QEMU's
        /// scsi0 `serial=` property is written verbatim, not zero-padded, so a disk with a
        /// short numeric serial may actually be space-padded by the controller instead) --
        /// use this to search under that alternate assumption.
        #[arg(
            long = "serial-pad",
            value_enum,
            ignore_case = true,
            default_value = "zero"
        )]
        serial_pad: SerialPad,
    },
    /// Convert signature_hex to Key text
    Sig2key {
        /// 128-char hex string (64 bytes)
        signature_hex: String,
    },
    /// Convert Key text to signature_hex -- accepts either a path to a .key file, or the
    /// key text itself (any of the three forms `key_text_to_signature` accepts) as a literal
    /// string argument
    Key2sig {
        /// Path to a .key file, or the key text itself as a literal string (may start with
        /// "-----BEGIN..."; allow_hyphen_values lets this be passed without a `--` separator)
        #[arg(allow_hyphen_values = true)]
        key_file_or_text: String,
    },
    /// Verify SOFTWARE ID computation with known test vectors
    Verify,
    /// Check a serial against known signatures
    Check {
        /// Serial number (20-digit string)
        #[arg(long)]
        serial: String,
        /// Disk size magnitude (paired with --unit). Required for --bus ide/nvme; optional
        /// (and ignored) for --bus scsi, where sector_val is always forced to 0.
        #[arg(short = 's', long = "disk-size")]
        disk_size: Option<u64>,
        /// Disk size unit: g (gigabytes, default), m (megabytes), k (kilobytes), or b (bytes)
        #[arg(short = 'u', long, value_enum, ignore_case = true, default_value = "g")]
        unit: SizeUnit,
        /// Model name (default: ROS<size><unit>, e.g. ROS100G, ROS128M, ROS67108864B)
        #[arg(short, long)]
        model: Option<String>,
        /// keys.toml path
        #[arg(short, long)]
        keys: Option<String>,
        /// Non-standard 20-hex-char MBR identity seed (0x100-0x109), e.g. from a real
        /// device's captured MBR. Default: standard all-zero identity used by collision search.
        #[arg(short = 'i', long)]
        identity: Option<String>,
        /// Disk bus type: ide (default, verified against real hardware -- also covers
        /// sata0/AHCI, which uses the identical encoding), nvme (same sector_val rounding
        /// as ide), or scsi (scsi0/virtio-scsi-pci specifically, NOT sata0 -- forces
        /// sector_val=0; see docs/license-internals.md §8.11-8.20; end-to-end activation
        /// confirmed on x86_64, §8.18).
        #[arg(
            short = 'b',
            long,
            value_enum,
            ignore_case = true,
            default_value = "ide"
        )]
        bus: BusType,
        /// Path to a .key license file (or a raw 128-char signature_hex file) to compare
        /// against the SOFTWARE ID computed from serial/model/disk-size/identity/bus above.
        #[arg(short = 'l', long)]
        license: Option<String>,
    },
    /// Generate a shell completion script (bash/zsh/fish/powershell/elvish) and print it to stdout
    Completions {
        /// Target shell
        shell: Shell,
    },
}

/// Disk bus type -- see `docs/license-internals.md` §8 for why this matters.
///
/// `keyman` uses entirely different code paths to read serial/model depending on how the
/// disk is presented to the guest kernel. `sata0`/AHCI disks use QEMU's `ide-hd` device --
/// the same device model as real `ide0` -- and are confirmed to use the identical encoding
/// (§8.20), so `Ide` covers both. `Scsi` covers `scsi0`/`virtio-scsi-pci` specifically
/// (SCSI INQUIRY + VPD page 0x80, sector_val forced to 0) -- confirmed correct and fully
/// activatable end-to-end on x86_64 (§8.14, §8.18-8.19); on ARM64 a separate
/// virtualization-detection issue in `keyman` can still block activation (§8.15-8.17).
#[derive(Clone, Copy, clap::ValueEnum, PartialEq, Eq)]
enum BusType {
    /// Real ATA/IDE-presented disk (QEMU `ide0`), or `sata0`/AHCI (confirmed identical
    /// encoding, §8.20). Standard, verified encoding.
    Ide,
    /// SCSI-subsystem-presented disk (`scsi0`/`virtio-scsi-pci` -- NOT `sata0`, which uses
    /// `Ide`'s encoding instead, §8.20). Forces sector_val=0 -- see §8.11-8.19.
    Scsi,
    /// NVMe-presented disk. Uses the identical sector_val rounding as `Ide` (disk size
    /// matters, standard rounding rule) -- distinct from `Scsi`, which forces sector_val=0.
    Nvme,
}

impl BusType {
    /// Whether disk size is meaningless for this bus (sector_val is forced to a fixed
    /// value regardless of size) -- currently only `Scsi`.
    fn size_irrelevant(self) -> bool {
        matches!(self, BusType::Scsi)
    }
}

/// How a numeric candidate serial is padded to `SERIAL_LEN` bytes during `search`.
/// See `zero_padded_to_space_padded` for the space-padding transform.
#[derive(Clone, Copy, clap::ValueEnum, PartialEq, Eq)]
enum SerialPad {
    /// Left-pad with '0' (default, current/original behavior).
    Zero,
    /// Right-pad with spaces, using the candidate's natural digit count (no leading zeros).
    Space,
}

/// Disk size unit, paired with the `--disk-size` magnitude
#[derive(Clone, Copy, clap::ValueEnum)]
enum SizeUnit {
    /// Gigabytes (1024^3 bytes)
    G,
    /// Megabytes (1024^2 bytes)
    M,
    /// Kilobytes (1024^1 bytes)
    K,
    /// Raw bytes
    B,
}

impl SizeUnit {
    /// Number of bytes in one unit
    fn bytes_per_unit(self) -> u64 {
        match self {
            SizeUnit::G => 1024 * 1024 * 1024,
            SizeUnit::M => 1024 * 1024,
            SizeUnit::K => 1024,
            SizeUnit::B => 1,
        }
    }

    /// Uppercase letter used in size labels (e.g. "128M", "100G", "65536K", "67108864B") and default model names
    fn label_char(self) -> char {
        match self {
            SizeUnit::G => 'G',
            SizeUnit::M => 'M',
            SizeUnit::K => 'K',
            SizeUnit::B => 'B',
        }
    }

    /// Minimum allowed magnitude for this unit -- all equivalent to 64M
    fn min_magnitude(self) -> u64 {
        match self {
            SizeUnit::G => 1,
            SizeUnit::M => 64,
            SizeUnit::K => 64 * 1024,
            SizeUnit::B => 64 * 1024 * 1024,
        }
    }
}

/// Reject disk sizes below the minimum for their unit (all equivalent to 64M). Exits the process on violation.
fn validate_disk_size(magnitude: u64, unit: SizeUnit) {
    let min = unit.min_magnitude();
    if magnitude < min {
        eprintln!(
            "Error: disk size {}{} is below the minimum for unit '{}' (must be >= {}{})",
            magnitude,
            unit.label_char(),
            unit.label_char(),
            min,
            unit.label_char()
        );
        std::process::exit(1);
    }
}

/// Compute exact disk size in bytes and a display label (e.g. "128M", "100G", "65536K", "67108864B")
fn disk_size_bytes_and_label(magnitude: u64, unit: SizeUnit) -> (u64, String) {
    let bytes = magnitude * unit.bytes_per_unit();
    let label = format!("{}{}", magnitude, unit.label_char());
    (bytes, label)
}

/// Resolve `--disk-size`/`--unit` against the selected bus, enforcing that they're required
/// for buses where disk size actually affects sector_val (ide/nvme) while remaining optional
/// (and ignored) for buses where it doesn't (scsi -- sector_val is always forced to 0).
/// Exits the process if disk_size is missing on a bus that needs it.
fn resolve_disk_size(disk_size: Option<u64>, unit: SizeUnit, bus: BusType) -> (u64, String) {
    match disk_size {
        Some(magnitude) => {
            validate_disk_size(magnitude, unit);
            disk_size_bytes_and_label(magnitude, unit)
        }
        None if bus.size_irrelevant() => (0, "N/A (scsi, size ignored)".to_string()),
        None => {
            eprintln!(
                "Error: --disk-size is required for --bus ide/nvme (only optional for --bus scsi)"
            );
            std::process::exit(1);
        }
    }
}

/// Parse a 20-hex-char `--identity` argument into the 10-byte MBR identity seed.
/// Exits the process on malformed input (wrong length or non-hex characters).
fn parse_identity_hex(s: &str) -> [u8; 10] {
    if s.len() != 20 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        eprintln!(
            "Error: --identity must be exactly 20 hex characters (10 bytes), got '{}' ({} chars)",
            s,
            s.len()
        );
        std::process::exit(1);
    }
    let mut out = [0u8; 10];
    for i in 0..10 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

/// Resolve the mix to use: either derived from a custom `--identity`, or the standard
/// all-zero-identity mix used by collision search.
fn resolve_mix(identity: Option<&str>) -> (u32, u32) {
    match identity {
        Some(hex) => targets::mix_from_identity(&parse_identity_hex(hex)),
        None => targets::mbr_mix(),
    }
}

// ---- Search context ----

/// Context shared across search threads (avoids excessive parameters)
struct SearchContext {
    model_bytes: [u8; MODEL_LEN],
    sv_bytes: [u8; 4],
    targets: Arc<Vec<targets::Target>>,
    /// `Some` only in full-mbr_val-sweep mode (no `--identity` given); `targets` above is
    /// left empty in that case. See `sweep_check_match`.
    raw_targets: Option<Arc<Vec<targets::RawTarget>>>,
    /// `Some` only in full-mbr_val-sweep mode -- pairs with `raw_targets`.
    mbr_table: Option<Arc<mbr_table::MbrTable>>,
    /// How numeric candidate serials are padded to `SERIAL_LEN` bytes -- see `SerialPad`.
    serial_pad: SerialPad,
    mix_lo: u32,
    mix_hi: u32,
    max_collisions: usize,
    stop: Arc<AtomicBool>,
    found_count: Arc<AtomicUsize>,
    start: Instant,
}

// ---- Common utility functions ----

/// Compute the SOFTWARE ID string from sid_lo + sid_hi
///
/// Eliminates duplicate logic in check_match / cmd_check / cmd_verify.
fn compute_software_id(sid_lo: u32, sid_hi: u8, mix_lo: u32, mix_hi: u32) -> String {
    let final_lo = sid_lo ^ mix_lo;
    let final_hi = ((sid_hi as u32) | 0x100) ^ mix_hi;
    software_id::encode(((final_hi as u64) << 32) | (final_lo as u64))
}

/// Write a u64 as 20-byte ASCII decimal (zero-padded), avoiding format! heap allocation
#[inline(always)]
fn write_serial(buf: &mut [u8; SERIAL_LEN], mut n: u64) {
    for i in (0..SERIAL_LEN).rev() {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
}

/// Increment the BCD buffer by 1 (only modifies the changed low digits)
///
/// Silently wraps to zero on all-9s overflow (requires 10^20 iterations, unreachable in practice).
#[inline(always)]
fn increment_bcd(buf: &mut [u8; SERIAL_LEN]) {
    for i in (0..SERIAL_LEN).rev() {
        if buf[i] < b'9' {
            buf[i] += 1;
            return;
        }
        buf[i] = b'0';
    }
}

/// Convert a zero-padded 20-byte numeric serial (as produced by `write_serial`/
/// `increment_bcd`) into its space-padded equivalent: strip the leading zeros (keeping at
/// least one digit for value 0), left-justify, and right-pad with spaces to fill the rest.
/// E.g. `"00000000000000000123"` -> `"123                 "`.
#[inline(always)]
fn zero_padded_to_space_padded(buf: &[u8; SERIAL_LEN]) -> [u8; SERIAL_LEN] {
    let first_nonzero = buf
        .iter()
        .position(|&b| b != b'0')
        .unwrap_or(SERIAL_LEN - 1);
    let mut out = [SPACE_PADDING; SERIAL_LEN];
    let sig_len = SERIAL_LEN - first_nonzero;
    out[..sig_len].copy_from_slice(&buf[first_nonzero..]);
    out
}

/// Valid Serial characters: `[0-9A-Za-z-]`
fn is_valid_serial(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Valid Model characters: `[0-9A-Za-z- ]` (including space)
fn is_valid_model(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b' ')
}

/// Build the serial byte array (20 bytes)
///
/// - Pure digits: left-pad with '0' (e.g. `"123"` → `"00000000000000000123"`)
/// - Contains letters: right-pad with spaces (e.g. `"ABCD"` → `"ABCD                "`)
fn build_serial_bytes(serial: &str) -> [u8; SERIAL_LEN] {
    let sb = serial.as_bytes();
    if !is_valid_serial(serial) {
        eprintln!("Warning: serial '{}' contains invalid characters", serial);
    }
    if sb.len() > SERIAL_LEN {
        eprintln!(
            "Warning: serial '{}' truncated to {} bytes",
            serial, SERIAL_LEN
        );
    }
    // `.all()` on an empty slice is vacuously true; treat empty as non-numeric so it
    // takes the space-padding branch below, matching keyman's zero-fill-then-pad
    // behavior for an empty disk serial (see the test above for disassembly evidence).
    let is_numeric = !sb.is_empty() && sb.iter().all(|b| b.is_ascii_digit());
    if is_numeric {
        // Pure digits: left-pad with '0'
        let mut bytes = [b'0'; SERIAL_LEN];
        let copy_len = sb.len().min(SERIAL_LEN);
        let offset = SERIAL_LEN - copy_len;
        bytes[offset..].copy_from_slice(&sb[..copy_len]);
        bytes
    } else {
        // Alphanumeric: right-pad with spaces
        let mut bytes = [SPACE_PADDING; SERIAL_LEN];
        let copy_len = sb.len().min(SERIAL_LEN);
        bytes[..copy_len].copy_from_slice(&sb[..copy_len]);
        bytes
    }
}

/// Build the model byte array (space-padded to 16 bytes)
fn build_model_bytes(model: &str) -> [u8; MODEL_LEN] {
    let mut bytes = [SPACE_PADDING; MODEL_LEN];
    let mb = model.as_bytes();
    if !is_valid_model(model) {
        eprintln!("Warning: model '{}' contains invalid characters", model);
    }
    if mb.len() > MODEL_LEN {
        eprintln!(
            "Warning: model '{}' truncated to {} bytes",
            model, MODEL_LEN
        );
    }
    let copy_len = mb.len().min(MODEL_LEN);
    bytes[..copy_len].copy_from_slice(&mb[..copy_len]);
    bytes
}

/// Convert an exact disk size in bytes to sector_val
fn disk_bytes_to_sector_val(total_bytes: u64) -> u32 {
    software_id::round_sectors((total_bytes / 512 >> 11) as u32)
}

/// Resolve sector_val for the given bus type.
///
/// `ide` uses the standard, real-hardware-verified rounding rule (`disk_bytes_to_sector_val`).
/// `scsi` forces `sector_val=0` regardless of disk size -- confirmed against 7 real boot tests
/// on a single 1GiB ARM64 VM (docs/license-internals.md §8.11-8.13), not yet verified at other
/// disk sizes.
fn sector_val_for_bus(bus: BusType, total_bytes: u64) -> u32 {
    match bus {
        BusType::Ide | BusType::Nvme => disk_bytes_to_sector_val(total_bytes),
        BusType::Scsi => 0,
    }
}

/// Build the SHA-256 input buffer (serial + model + sector_val)
fn build_input_buf(
    serial: &[u8; SERIAL_LEN],
    model_bytes: &[u8; MODEL_LEN],
    sv_bytes: &[u8; 4],
) -> [u8; INPUT_LEN] {
    let mut buf = [SPACE_PADDING; INPUT_LEN];
    buf[..SERIAL_LEN].copy_from_slice(serial);
    buf[SERIAL_LEN..SERIAL_LEN + MODEL_LEN].copy_from_slice(model_bytes);
    buf[SERIAL_LEN + MODEL_LEN..].copy_from_slice(sv_bytes);
    buf
}

// ---- Main entry ----

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Search {
            disk_size,
            unit,
            threads,
            model,
            keys,
            count,
            from,
            identity,
            bus,
            mbr_table,
            serial_pad,
        } => cmd_search(
            disk_size, unit, threads, model, keys, count, from, identity, bus, mbr_table,
            serial_pad,
        ),
        Commands::Sig2key { signature_hex } => cmd_sig2key(&signature_hex),
        Commands::Key2sig { key_file_or_text } => cmd_key2sig(&key_file_or_text),
        Commands::Verify => cmd_verify(),
        Commands::Check {
            serial,
            disk_size,
            unit,
            model,
            keys,
            identity,
            bus,
            license,
        } => cmd_check(
            &serial, disk_size, unit, model, keys, identity, bus, license,
        ),
        Commands::Completions { shell } => {
            generate(
                shell,
                &mut Cli::command(),
                "ros-serialgen",
                &mut io::stdout(),
            );
        }
    }
}

// ---- search command ----

/// Execute the collision search
fn cmd_search(
    disk_size: Option<u64>,
    unit: SizeUnit,
    threads: Option<usize>,
    model: Option<String>,
    keys: Option<String>,
    count: usize,
    from: u64,
    identity: Option<String>,
    bus: BusType,
    mbr_table_path: Option<String>,
    serial_pad: SerialPad,
) {
    let (total_bytes, size_label) = resolve_disk_size(disk_size, unit, bus);
    let sector_val = sector_val_for_bus(bus, total_bytes);
    let model = model.unwrap_or_else(|| format!("ROS{}", size_label));
    let num_threads = threads.unwrap_or_else(|| {
        thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    });
    let use_simd = sha256_simd::is_avx512_supported();
    let start_serial = from * 1_000_000;

    verify_6g();

    // No --identity given: sweep all 2048 mbr_val values per candidate serial instead of a
    // single fixed identity (decided 2026-09-07, see docs/reference/mtsc-cli-plan.md).
    let sweep_mode = identity.is_none();

    let ctx = if sweep_mode {
        let raw_targets = targets::load_raw_targets(keys.as_deref());
        let table = mbr_table::MbrTable::load(mbr_table_path.as_deref());

        print_sweep_search_banner(
            &size_label,
            &model,
            sector_val,
            num_threads,
            &raw_targets,
            count,
            start_serial,
            use_simd,
            bus,
            serial_pad,
        );

        Arc::new(SearchContext {
            model_bytes: build_model_bytes(&model),
            sv_bytes: sector_val.to_le_bytes(),
            targets: Arc::new(Vec::new()),
            raw_targets: Some(Arc::new(raw_targets)),
            mbr_table: Some(Arc::new(table)),
            serial_pad,
            mix_lo: 0,
            mix_hi: 0,
            max_collisions: count,
            stop: Arc::new(AtomicBool::new(false)),
            found_count: Arc::new(AtomicUsize::new(0)),
            start: Instant::now(),
        })
    } else {
        let (mix_lo, mix_hi) = resolve_mix(identity.as_deref());
        let fixed_targets = targets::load_targets(keys.as_deref(), (mix_lo, mix_hi));

        print_search_banner(
            &size_label,
            &model,
            sector_val,
            num_threads,
            &fixed_targets,
            count,
            start_serial,
            use_simd,
            identity.as_deref(),
            bus,
            serial_pad,
        );

        Arc::new(SearchContext {
            model_bytes: build_model_bytes(&model),
            sv_bytes: sector_val.to_le_bytes(),
            targets: Arc::new(fixed_targets),
            raw_targets: None,
            mbr_table: None,
            serial_pad,
            mix_lo,
            mix_hi,
            max_collisions: count,
            stop: Arc::new(AtomicBool::new(false)),
            found_count: Arc::new(AtomicUsize::new(0)),
            start: Instant::now(),
        })
    };

    let handles: Vec<_> = (0..num_threads)
        .map(|tid| {
            let ctx = Arc::clone(&ctx);
            thread::spawn(move || {
                if use_simd {
                    unsafe { search_simd(tid, num_threads, start_serial, &ctx) };
                } else {
                    search_scalar(tid, num_threads, start_serial, &ctx);
                }
            })
        })
        .collect();

    for h in handles {
        let _ = h.join();
    }

    let total = ctx.found_count.load(Ordering::Relaxed);
    println!(
        "\nDone. {} collisions found in {}s",
        total,
        ctx.start.elapsed().as_secs()
    );
}

/// Print search startup info
fn print_search_banner(
    disk_label: &str,
    model: &str,
    sector_val: u32,
    num_threads: usize,
    targets: &[targets::Target],
    count: usize,
    start_serial: u64,
    use_simd: bool,
    identity: Option<&str>,
    bus: BusType,
    serial_pad: SerialPad,
) {
    let mode_str = if count == 0 {
        "unlimited".to_string()
    } else {
        format!("find {}", count)
    };
    let engine = if use_simd { "AVX-512 x16" } else { "scalar" };

    println!("=== RouterOS L6 Serial Generator ===");
    println!(
        "Disk: {}  Model: {}  SV: 0x{:X}",
        disk_label, model, sector_val
    );
    match bus {
        BusType::Ide => {
            println!("Bus: ide (verified against real hardware; also covers sata0/AHCI)")
        }
        BusType::Nvme => {
            println!("Bus: nvme (same sector_val rounding as ide)")
        }
        BusType::Scsi => {
            println!("Bus: scsi (scsi0/virtio-scsi-pci only, NOT sata0; sector_val forced to 0)");
            println!("  WARNING: this encoding is validated against 7 real boot tests on a single");
            println!(
                "  1GiB ARM64 VM only (docs/license-internals.md §8.11-8.13). sector_val=0 has"
            );
            println!("  not been confirmed at other disk sizes -- verify any hit on real hardware");
            println!("  before relying on it.");
        }
    }
    match identity {
        Some(hex) => println!(
            "Identity: {} (custom, non-standard mix)",
            hex.to_uppercase()
        ),
        None => println!("Identity: 00000000000000000000 (standard, all-zero mix)"),
    }
    match serial_pad {
        SerialPad::Zero => println!("Serial pad: zero (left-pad with '0', default)"),
        SerialPad::Space => {
            println!("Serial pad: space (right-pad with spaces, natural digit count)")
        }
    }
    println!(
        "Threads: {}  Targets: {}  Mode: {}  Engine: {}",
        num_threads,
        targets.len(),
        mode_str,
        engine
    );
    if start_serial > 0 {
        println!(
            "Start: {}M (serial {})",
            start_serial / 1_000_000,
            start_serial
        );
    }
    println!();

    for t in targets {
        println!(
            "  {} need_lo=0x{:08X} need_hi=0x{:03X}",
            t.name, t.need_lo, t.need_hi
        );
    }
    println!("\nSearching...\n");
}

/// Print search startup info for full-mbr_val-sweep mode (no fixed `--identity`)
fn print_sweep_search_banner(
    disk_label: &str,
    model: &str,
    sector_val: u32,
    num_threads: usize,
    targets: &[targets::RawTarget],
    count: usize,
    start_serial: u64,
    use_simd: bool,
    bus: BusType,
    serial_pad: SerialPad,
) {
    let mode_str = if count == 0 {
        "unlimited".to_string()
    } else {
        format!("find {}", count)
    };
    let engine = if use_simd { "AVX-512 x16" } else { "scalar" };

    println!("=== RouterOS L6 Serial Generator (mbr_val full-space sweep) ===");
    println!(
        "Disk: {}  Model: {}  SV: 0x{:X}",
        disk_label, model, sector_val
    );
    match bus {
        BusType::Ide => {
            println!("Bus: ide (verified against real hardware; also covers sata0/AHCI)")
        }
        BusType::Nvme => println!("Bus: nvme (same sector_val rounding as ide)"),
        BusType::Scsi => {
            println!("Bus: scsi (scsi0/virtio-scsi-pci only, NOT sata0; sector_val forced to 0)")
        }
    }
    println!(
        "Identity: sweeping all 2048 mbr_val values per candidate serial (no fixed --identity)"
    );
    match serial_pad {
        SerialPad::Zero => println!("Serial pad: zero (left-pad with '0', default)"),
        SerialPad::Space => {
            println!("Serial pad: space (right-pad with spaces, natural digit count)")
        }
    }
    println!(
        "Threads: {}  Targets: {}  Mode: {}  Engine: {}",
        num_threads,
        targets.len(),
        mode_str,
        engine
    );
    if start_serial > 0 {
        println!(
            "Start: {}M (serial {})",
            start_serial / 1_000_000,
            start_serial
        );
    }
    println!();

    for t in targets {
        println!(
            "  {} tv_lo=0x{:08X} tv_hi=0x{:02X}",
            t.name, t.tv_lo, t.tv_hi
        );
    }
    println!("\nSearching...\n");
}

// ---- Search engines ----

/// Scalar search (no SIMD, computes one hash at a time)
fn search_scalar(tid: usize, num_threads: usize, start_serial: u64, ctx: &SearchContext) {
    let mut buf = build_input_buf(&[b'0'; SERIAL_LEN], &ctx.model_bytes, &ctx.sv_bytes);
    let step = num_threads as u64;
    let mut i: u64 = start_serial + tid as u64;

    let sweep_mode = ctx.raw_targets.is_some();

    // sid_hi pre-filter table: only effective in fixed-mix mode. With a full mbr_val sweep
    // the effective mix varies per candidate, so sid_hi alone can't reject most of them --
    // skip building/using it entirely in sweep mode (see sweep_check_match). Indexed by
    // the full `(sid_hi|0x100)` value (always in 256..512, see `Target::need_hi`'s doc
    // comment) -- targets whose `need_hi` falls outside `0..512` can never match under
    // this fixed mix and are simply never marked, not an error.
    let mut hi_lookup = [false; 512];
    if !sweep_mode {
        for t in ctx.targets.iter() {
            if (t.need_hi as usize) < hi_lookup.len() {
                hi_lookup[t.need_hi as usize] = true;
            }
        }
    }

    loop {
        if ctx.stop.load(Ordering::Relaxed) {
            return;
        }

        let mut serial_buf = [b'0'; SERIAL_LEN];
        write_serial(&mut serial_buf, i);
        if ctx.serial_pad == SerialPad::Space {
            serial_buf = zero_padded_to_space_padded(&serial_buf);
        }
        buf[..SERIAL_LEN].copy_from_slice(&serial_buf);
        let (sid_lo, sid_hi) = sha256::hash_40(&buf);

        if sweep_mode {
            sweep_check_match(i, sid_lo, sid_hi, ctx);
        } else if hi_lookup[(sid_hi as usize) | 0x100] {
            check_match(i, sid_lo, sid_hi, ctx);
        }

        i += step;

        if tid == 0 && (i / PROGRESS_INTERVAL) != ((i - step) / PROGRESS_INTERVAL) {
            report_progress(i, &ctx.start, &ctx.found_count);
        }
    }
}

/// Non-x86_64 stub: `sha256_simd::is_avx512_supported()` always returns `false` there, so
/// `cmd_search` never takes the `use_simd` branch that calls this -- exists only so the
/// crate compiles for non-x86_64 targets (e.g. Apple Silicon), which always use the scalar
/// engine.
///
/// # Safety
///
/// Never actually unsafe to call (it just panics), but keeps the same signature/safety
/// contract as the real x86_64 implementation for the call site that doesn't branch on
/// target_arch.
#[cfg(not(target_arch = "x86_64"))]
unsafe fn search_simd(_tid: usize, _num_threads: usize, _start_serial: u64, _ctx: &SearchContext) {
    unreachable!("search_simd has no non-x86_64 implementation; use_simd must be false here");
}

/// AVX-512 SIMD search (computes 16 serials in parallel per batch)
///
/// # Safety
///
/// The caller must ensure the CPU supports AVX-512F.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f", enable = "avx512bw")]
unsafe fn search_simd(tid: usize, num_threads: usize, start_serial: u64, ctx: &SearchContext) {
    let batch = SIMD_LANES as u64;
    let step = (num_threads as u64) * batch;
    let mut base: u64 = start_serial + (tid as u64) * batch;

    // W[5..9] precomputation: model + sector_val are constant, compute once
    let const_w = sha256_simd::precompute_constant_words(&ctx.model_bytes, &ctx.sv_bytes);

    // Pre-fill model + sector_val for all 16 inputs (once, outside the loop)
    let mut inputs = [[SPACE_PADDING; INPUT_LEN]; SIMD_LANES];
    for lane in 0..SIMD_LANES {
        inputs[lane][SERIAL_LEN..SERIAL_LEN + MODEL_LEN].copy_from_slice(&ctx.model_bytes);
        inputs[lane][SERIAL_LEN + MODEL_LEN..].copy_from_slice(&ctx.sv_bytes);
    }

    // BCD counter
    let mut base_serial = [b'0'; SERIAL_LEN];
    write_serial(&mut base_serial, base);

    let sweep_mode = ctx.raw_targets.is_some();

    // sid_hi pre-filter table: only effective in fixed-mix mode (see search_scalar).
    let mut hi_lookup = [false; 512];
    if !sweep_mode {
        for t in ctx.targets.iter() {
            if (t.need_hi as usize) < hi_lookup.len() {
                hi_lookup[t.need_hi as usize] = true;
            }
        }
    }

    loop {
        if ctx.stop.load(Ordering::Relaxed) {
            return;
        }

        // Generate 16 consecutive serials via BCD
        let mut serials = [0u64; SIMD_LANES];
        let mut lane_serial = base_serial;
        for lane in 0..SIMD_LANES {
            serials[lane] = base + lane as u64;
            let bytes = if ctx.serial_pad == SerialPad::Space {
                zero_padded_to_space_padded(&lane_serial)
            } else {
                lane_serial
            };
            inputs[lane][..SERIAL_LEN].copy_from_slice(&bytes);
            increment_bcd(&mut lane_serial);
        }

        // 16-way parallel SHA-256
        let result = sha256_simd::hash_40_x16(&inputs, &const_w);

        // Check each lane for a match
        for lane in 0..SIMD_LANES {
            if sweep_mode {
                sweep_check_match(serials[lane], result.sid_lo[lane], result.sid_hi[lane], ctx);
            } else if hi_lookup[(result.sid_hi[lane] as usize) | 0x100] {
                check_match(serials[lane], result.sid_lo[lane], result.sid_hi[lane], ctx);
            }
        }

        base += step;
        // BCD stepping is faster than 20 divisions (step is usually < 256)
        if step <= 256 {
            for _ in 0..step {
                increment_bcd(&mut base_serial);
            }
        } else {
            write_serial(&mut base_serial, base);
        }

        if tid == 0 && (base / PROGRESS_INTERVAL) != ((base - step) / PROGRESS_INTERVAL) {
            report_progress(base, &ctx.start, &ctx.found_count);
        }
    }
}

/// Check whether a hash result matches any target (only formats serial on a hit)
fn check_match(serial_num: u64, sid_lo: u32, sid_hi: u8, ctx: &SearchContext) {
    for t in ctx.targets.iter() {
        if ((sid_hi as u32) | 0x100) == t.need_hi && sid_lo == t.need_lo {
            let n = ctx.found_count.fetch_add(1, Ordering::Relaxed) + 1;
            let sid = compute_software_id(sid_lo, sid_hi, ctx.mix_lo, ctx.mix_hi);

            let mut sbuf = [b'0'; SERIAL_LEN];
            write_serial(&mut sbuf, serial_num);
            if ctx.serial_pad == SerialPad::Space {
                sbuf = zero_padded_to_space_padded(&sbuf);
            }
            let serial_str = std::str::from_utf8(&sbuf).unwrap();

            println!(
                "FOUND [{}] serial={} target={} verified={}",
                n, serial_str, t.name, sid
            );

            if ctx.max_collisions > 0 && n >= ctx.max_collisions {
                ctx.stop.store(true, Ordering::Relaxed);
            }
        }
    }
}

/// Check a hash result against every raw target across the full mbr_val space (0-2047) --
/// used when `search` is run without `--identity`. Unlike `check_match`'s single-fixed-mix
/// comparison, this can find a hit for any mbr_val, not just the one a fixed identity bakes in.
///
/// TODO: reports every feasible target for this serial rather than stopping at the first
/// (decided 2026-09-07) -- change to first-match-wins if multi-target hits per serial turn
/// out noisy in practice. At current target counts this is astronomically rare either way.
fn sweep_check_match(serial_num: u64, sid_lo: u32, sid_hi: u8, ctx: &SearchContext) {
    let raw_targets = ctx
        .raw_targets
        .as_ref()
        .expect("sweep_check_match requires SearchContext::raw_targets");
    let mbr_table = ctx
        .mbr_table
        .as_ref()
        .expect("sweep_check_match requires SearchContext::mbr_table");

    for t in raw_targets.iter() {
        let required = targets::required_mix(sid_lo, sid_hi, t.tv_lo, t.tv_hi);
        if let Some(mbr_val) = targets::feasible_mbr_val(required) {
            let n = ctx.found_count.fetch_add(1, Ordering::Relaxed) + 1;

            let mut sbuf = [b'0'; SERIAL_LEN];
            write_serial(&mut sbuf, serial_num);
            if ctx.serial_pad == SerialPad::Space {
                sbuf = zero_padded_to_space_padded(&sbuf);
            }
            let serial_str = std::str::from_utf8(&sbuf).unwrap();
            let (identity_hex, marker_hex) = mbr_table.lookup(mbr_val);

            println!(
                "FOUND [{}] serial={} target={} mbr_val={} identity={} marker={}",
                n, serial_str, t.name, mbr_val, identity_hex, marker_hex
            );

            if ctx.max_collisions > 0 && n >= ctx.max_collisions {
                ctx.stop.store(true, Ordering::Relaxed);
            }
        }
    }
}

/// Print progress to stderr
fn report_progress(hashes: u64, start: &Instant, found_count: &AtomicUsize) {
    let elapsed = start.elapsed().as_secs();
    let fc = found_count.load(Ordering::Relaxed);
    eprintln!("{}M hashes, {}s, {} found", hashes / 1_000_000, elapsed, fc);
}

// ---- Other commands ----

/// Convert a signature hex to License Key text
fn cmd_sig2key(hex: &str) {
    print_metadata(hex);
}

/// Convert Key text to signature hex. `input` is treated as a file path if it names an
/// existing file; otherwise it's treated as the key text itself (any of the three forms
/// `key_text_to_signature` accepts -- see `convert.rs`).
fn cmd_key2sig(input: &str) {
    let content = if std::path::Path::new(input).is_file() {
        match std::fs::read_to_string(input) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Cannot read {}: {}", input, e);
                return;
            }
        }
    } else {
        input.to_string()
    };

    match convert::key_text_to_signature(&content) {
        Ok(sig) => print_metadata(&sig),
        Err(e) => eprintln!("Error: {}", e),
    }
}

/// Print a signature's full metadata to stdout: decoded fields, the raw MBR hex blob, and the
/// equivalent `.key` file text -- everything derivable from a 64-byte signature, in one unified
/// layout, regardless of whether the caller started from hex (`sig2key`) or a `.key` file
/// (`key2sig`). Field labels/format match the reference `MTLic`-style parser output (see
/// docs/license-internals.md §8.32).
///
/// `MBR Signature (hex)` is the full 64-byte blob (payload+nonce+signature) as written to MBR
/// 0x110-0x14F -- distinct from the `Signature:` field above it, which is only the trailing
/// 32-byte EC-KCDSA signature scalar (bytes 32..64 of this same blob).
fn print_metadata(signature_hex: &str) {
    match convert::decode_metadata(signature_hex) {
        Ok(m) => {
            println!("  Software ID: {}", m.software_id);
            println!("  Router OS Version: {}", m.version_byte);
            println!("  License Level: {}", m.level);
            println!("  Nonce Hash: {}", m.nonce_hash);
            println!("  Signature: {}", m.signature);

            let valid = match convert::decode_verify_inputs(signature_hex) {
                Ok((payload, nonce_hash, signature)) => Some(curve25519::verify(
                    &payload,
                    &nonce_hash,
                    &signature,
                    &curve25519::LICENSE_PUBLIC_KEY,
                )),
                Err(_) => None,
            };
            match valid {
                Some(v) => println!("  License valid: {}", v),
                None => println!("  License valid: (could not run EC-KCDSA verification)"),
            }

            if !m.padding_ok {
                eprintln!(
                    "  Warning: reserved bytes not all zero -- this may not be a valid signature"
                );
            }
        }
        Err(e) => eprintln!("(could not decode license metadata: {})", e),
    }

    println!("-----");
    println!("  MBR Signature (hex): {}", signature_hex);

    println!("-----");
    match convert::signature_to_key_text(signature_hex) {
        Ok(key_text) => println!("  License: {}", key_text),
        Err(e) => eprintln!("Error: {}", e),
    }
}

/// Check whether a given serial matches a known signature
fn cmd_check(
    serial: &str,
    disk_size: Option<u64>,
    unit: SizeUnit,
    model: Option<String>,
    keys: Option<String>,
    identity: Option<String>,
    bus: BusType,
    license: Option<String>,
) {
    let (total_bytes, size_label) = resolve_disk_size(disk_size, unit, bus);
    let sector_val = sector_val_for_bus(bus, total_bytes);
    let model = model.unwrap_or_else(|| format!("ROS{}", size_label));
    let (mix_lo, mix_hi) = resolve_mix(identity.as_deref());
    let search_targets = targets::load_targets(keys.as_deref(), (mix_lo, mix_hi));

    let serial_bytes = build_serial_bytes(serial);
    let serial_display = std::str::from_utf8(&serial_bytes).unwrap_or(serial);
    let model_bytes = build_model_bytes(&model);
    let buf = build_input_buf(&serial_bytes, &model_bytes, &sector_val.to_le_bytes());

    let (sid_lo, sid_hi) = sha256::hash_40(&buf);
    let sid = compute_software_id(sid_lo, sid_hi, mix_lo, mix_hi);

    let identity_hex = identity
        .as_deref()
        .map(|s| s.to_uppercase())
        .unwrap_or_else(|| "00000000000000000000".to_string());

    let marker = identity
        .as_deref()
        .map(|hex| targets::marker_from_identity(&parse_identity_hex(hex)))
        .unwrap_or([0xBD, 0xE8]);
    let marker_hex = format!("{:02X}{:02X}", marker[0], marker[1]);

    println!("=== Check ===");
    println!("Serial: {}", serial_display);
    println!("Model:  {}", model);
    println!("Disk:   {} (SV: 0x{:X})", size_label, sector_val);
    match bus {
        BusType::Ide => println!("Bus:    ide (verified against real hardware; also covers sata0/AHCI)"),
        BusType::Nvme => println!("Bus:    nvme (same sector_val rounding as ide)"),
        BusType::Scsi => println!("Bus:    scsi (scsi0/virtio-scsi-pci only, NOT sata0; sector_val forced to 0 -- see docs/license-internals.md §8.11-8.20)"),
    }
    println!("-----------");
    println!("Identity: {}", identity_hex);
    println!("Marker: {}", marker_hex);
    println!("-----------");
    println!("Software ID: {}", sid);

    if let Some(path) = license.as_deref() {
        compare_license_software_id(path, &sid);
    }

    let matched = search_targets
        .iter()
        .find(|t| ((sid_hi as u32) | 0x100) == t.need_hi && sid_lo == t.need_lo);

    if let Some(t) = matched {
        println!("\n✅ Matched signature: {}", t.name);
        if t.signature_hex.len() >= 128 {
            println!(
                "   Signature: {}...{}",
                &t.signature_hex[..16],
                &t.signature_hex[112..]
            );
        } else {
            println!("   Signature: {}", t.signature_hex);
        }

        if let Ok(key_text) = convert::signature_to_key_text(&t.signature_hex) {
            println!("\n   LICENSE KEY:");
            for line in key_text.lines() {
                println!("   {}", line);
            }
        }

        println!(
            "\n   MBR HEX:\n   {}{}00000000{}",
            identity_hex, marker_hex, t.signature_hex
        );
    } else {
        println!("\n❌ No match found");
        println!("   sid_lo=0x{:08X} sid_hi=0x{:02X}", sid_lo, sid_hi);
    }
}

/// Read a license file (either `.key` text or a raw 128-char signature_hex file), decode its
/// embedded SOFTWARE ID, and compare it against the SOFTWARE ID computed from `check`'s
/// serial/model/disk-size/identity/bus inputs.
fn compare_license_software_id(path: &str, computed_sid: &str) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("\nError: cannot read license file {}: {}", path, e);
            return;
        }
    };

    let sig_hex = if content.contains("BEGIN MIKROTIK") {
        match convert::key_text_to_signature(&content) {
            Ok(sig) => sig,
            Err(e) => {
                eprintln!("\nError: cannot parse {} as a .key file: {}", path, e);
                return;
            }
        }
    } else {
        content.trim().to_string()
    };

    match convert::decode_metadata(&sig_hex) {
        Ok(m) => {
            println!("\n=== License comparison ({}) ===", path);
            println!("License SOFTWARE-ID: {}", m.software_id);
            println!("Computed SOFTWARE-ID: {}", computed_sid);
            if m.software_id == computed_sid {
                println!(
                    "✅ MATCH -- this license's SOFTWARE ID matches the given disk parameters"
                );
            } else {
                println!("❌ NO MATCH -- this license was issued for a different SOFTWARE ID");
            }
        }
        Err(e) => eprintln!("\nError: could not decode SOFTWARE-ID from {}: {}", path, e),
    }
}

/// Verify SHA-256 + SOFTWARE ID algorithms (self-consistency check)
fn cmd_verify() {
    let (mix_lo, mix_hi) = targets::mbr_mix();
    let cases = [
        ("00000000000000000001", "VMware Virtual I", 0x1800u32),
        ("00000000202155543391", "ROS16G          ", 0x4000),
    ];
    let engine = if sha256_simd::is_avx512_supported() {
        "AVX-512 x16"
    } else {
        "scalar"
    };

    println!("=== Verify (engine: {}) ===", engine);
    for (ser, model_str, sv) in &cases {
        let mut serial_bytes = [b'0'; SERIAL_LEN];
        serial_bytes[..ser.len().min(SERIAL_LEN)]
            .copy_from_slice(&ser.as_bytes()[..ser.len().min(SERIAL_LEN)]);
        let mut model_bytes = [SPACE_PADDING; MODEL_LEN];
        model_bytes.copy_from_slice(&model_str.as_bytes()[..MODEL_LEN]);
        let buf = build_input_buf(&serial_bytes, &model_bytes, &sv.to_le_bytes());

        let (sid_lo, sid_hi) = sha256::hash_40(&buf);
        let sid = compute_software_id(sid_lo, sid_hi, mix_lo, mix_hi);
        // Self-consistency: encode → decode → re-encode must round-trip
        let ok = match software_id::decode(&sid) {
            Ok(v) if software_id::encode(v) == sid => "OK",
            _ => "FAIL",
        };
        println!("  {} → {} [{}]", &ser[..8], sid, ok);
    }
}

/// Startup self-check: verify the 6G VMware known hash value
fn verify_6g() {
    let mut serial_bytes = [b'0'; SERIAL_LEN];
    serial_bytes[..20].copy_from_slice(b"00000000000000000001");
    let model_bytes = *b"VMware Virtual I";
    let buf = build_input_buf(&serial_bytes, &model_bytes, &0x1800u32.to_le_bytes());

    let (sid_lo, sid_hi) = sha256::hash_40(&buf);
    if sid_lo != 0x0B49EC2E || sid_hi != 0x35 {
        eprintln!(
            "FATAL: SHA-256 self-check failed! sid_lo=0x{:08X} sid_hi=0x{:02X}",
            sid_lo, sid_hi
        );
        std::process::exit(1);
    }
}

// ---- Tests ----

#[cfg(test)]
mod tests {
    use super::*;

    // ---- SizeUnit::min_magnitude ----

    #[test]
    fn test_min_magnitude_gb_is_1() {
        assert_eq!(SizeUnit::G.min_magnitude(), 1);
    }

    #[test]
    fn test_min_magnitude_mb_is_64() {
        assert_eq!(SizeUnit::M.min_magnitude(), 64);
    }

    #[test]
    fn test_min_magnitude_bytes_is_64mb_in_bytes() {
        assert_eq!(SizeUnit::B.min_magnitude(), 64 * 1024 * 1024);
    }

    // ---- sector_val_for_bus ----

    #[test]
    fn test_sector_val_for_bus_ide_matches_standard_rounding() {
        let total_bytes = 6 * 1024 * 1024 * 1024u64; // 6G, matches the known 0x1800 test vector
        assert_eq!(sector_val_for_bus(BusType::Ide, total_bytes), 0x1800);
    }

    #[test]
    fn test_sector_val_for_bus_scsi_is_always_zero() {
        // Confirmed via 7 real boot tests on a 1GiB ARM64 VM (docs §8.11-8.13) -- scsi mode
        // forces sector_val=0 regardless of disk size.
        for total_bytes in [
            1 * 1024 * 1024 * 1024u64,
            6 * 1024 * 1024 * 1024,
            100 * 1024 * 1024 * 1024,
        ] {
            assert_eq!(sector_val_for_bus(BusType::Scsi, total_bytes), 0);
        }
    }

    // ---- disk_size_bytes_and_label ----

    #[test]
    fn test_disk_size_gb() {
        let (bytes, label) = disk_size_bytes_and_label(100, SizeUnit::G);
        assert_eq!(bytes, 100 * 1024 * 1024 * 1024);
        assert_eq!(label, "100G");
    }

    #[test]
    fn test_disk_size_mb_128() {
        let (bytes, label) = disk_size_bytes_and_label(128, SizeUnit::M);
        assert_eq!(bytes, 128 * 1024 * 1024);
        assert_eq!(label, "128M");
    }

    #[test]
    fn test_disk_size_mb_256_512() {
        assert_eq!(
            disk_size_bytes_and_label(256, SizeUnit::M).0,
            256 * 1024 * 1024
        );
        assert_eq!(
            disk_size_bytes_and_label(512, SizeUnit::M).0,
            512 * 1024 * 1024
        );
    }

    #[test]
    fn test_disk_size_mb_vs_gb_distinct() {
        let (mb_bytes, _) = disk_size_bytes_and_label(1, SizeUnit::M);
        let (gb_bytes, _) = disk_size_bytes_and_label(1, SizeUnit::G);
        assert_eq!(gb_bytes, mb_bytes * 1024);
    }

    #[test]
    fn test_disk_size_bytes_unit_passthrough() {
        // For SizeUnit::B, magnitude IS the byte count (bytes_per_unit == 1)
        let (bytes, label) = disk_size_bytes_and_label(67_108_864, SizeUnit::B);
        assert_eq!(bytes, 67_108_864);
        assert_eq!(label, "67108864B");
    }

    #[test]
    fn test_disk_size_bytes_matches_equivalent_mb() {
        let (bytes_via_b, _) = disk_size_bytes_and_label(134_217_728, SizeUnit::B);
        let (bytes_via_m, _) = disk_size_bytes_and_label(128, SizeUnit::M);
        assert_eq!(bytes_via_b, bytes_via_m);
    }

    #[test]
    fn test_disk_size_kb() {
        let (bytes, label) = disk_size_bytes_and_label(65_536, SizeUnit::K);
        assert_eq!(bytes, 65_536 * 1024);
        assert_eq!(label, "65536K");
    }

    #[test]
    fn test_disk_size_kb_matches_equivalent_mb() {
        let (bytes_via_k, _) = disk_size_bytes_and_label(131_072, SizeUnit::K);
        let (bytes_via_m, _) = disk_size_bytes_and_label(128, SizeUnit::M);
        assert_eq!(bytes_via_k, bytes_via_m);
    }

    #[test]
    fn test_min_magnitude_kb_is_64mb_in_kb() {
        assert_eq!(SizeUnit::K.min_magnitude(), 64 * 1024);
    }

    // ---- write_serial ----

    #[test]
    fn test_write_serial_zero() {
        let mut buf = [0u8; SERIAL_LEN];
        write_serial(&mut buf, 0);
        assert_eq!(&buf, b"00000000000000000000");
    }

    #[test]
    fn test_write_serial_one() {
        let mut buf = [0u8; SERIAL_LEN];
        write_serial(&mut buf, 1);
        assert_eq!(&buf, b"00000000000000000001");
    }

    #[test]
    fn test_write_serial_known_6g() {
        let mut buf = [0u8; SERIAL_LEN];
        write_serial(&mut buf, 401012206606);
        assert_eq!(&buf, b"00000000401012206606");
    }

    #[test]
    fn test_write_serial_large() {
        let mut buf = [0u8; SERIAL_LEN];
        write_serial(&mut buf, 6145996160994);
        assert_eq!(&buf, b"00000006145996160994");
    }

    #[test]
    fn test_write_serial_max_u64() {
        let mut buf = [0u8; SERIAL_LEN];
        write_serial(&mut buf, u64::MAX);
        assert_eq!(&buf, b"18446744073709551615");
    }

    // ---- zero_padded_to_space_padded ----

    #[test]
    fn test_zero_padded_to_space_padded_zero() {
        let mut buf = [0u8; SERIAL_LEN];
        write_serial(&mut buf, 0);
        let out = zero_padded_to_space_padded(&buf);
        assert_eq!(&out, b"0                   ");
    }

    #[test]
    fn test_zero_padded_to_space_padded_short() {
        let mut buf = [0u8; SERIAL_LEN];
        write_serial(&mut buf, 123);
        let out = zero_padded_to_space_padded(&buf);
        assert_eq!(&out, b"123                 ");
    }

    #[test]
    fn test_zero_padded_to_space_padded_matches_earlier_real_disk_case() {
        // The exact scenario this feature was requested for: serial=25828501 on a real
        // disk was observed to NOT be zero-padded by the controller (a short zero-padded
        // vs. unpadded serial produced different SOFTWARE IDs when boot-tested on a real
        // VM this session) -- confirming what the space-padded form should look like.
        let mut buf = [0u8; SERIAL_LEN];
        write_serial(&mut buf, 25828501);
        let out = zero_padded_to_space_padded(&buf);
        assert_eq!(&out, b"25828501            ");
    }

    #[test]
    fn test_zero_padded_to_space_padded_full_length_no_zeros_stripped() {
        // A 20-digit value with no leading zeros: nothing to strip, output == input.
        let mut buf = [0u8; SERIAL_LEN];
        write_serial(&mut buf, u64::MAX); // "18446744073709551615", 20 digits, leads with '1'
        let out = zero_padded_to_space_padded(&buf);
        assert_eq!(&out, &buf);
    }

    #[test]
    fn test_zero_padded_to_space_padded_leading_zero_digit_preserved() {
        // A significant digit that happens to be '0' (not a leading-zero pad byte) must
        // survive -- only the *leading* run of zero pad bytes is stripped.
        let buf = *b"00000000000000010203";
        let out = zero_padded_to_space_padded(&buf);
        assert_eq!(&out, b"10203               ");
    }

    // ---- increment_bcd ----

    #[test]
    fn test_increment_bcd_simple() {
        let mut buf = *b"00000000000000000000";
        increment_bcd(&mut buf);
        assert_eq!(&buf, b"00000000000000000001");
    }

    #[test]
    fn test_increment_bcd_carry() {
        let mut buf = *b"00000000000000000009";
        increment_bcd(&mut buf);
        assert_eq!(&buf, b"00000000000000000010");
    }

    #[test]
    fn test_increment_bcd_multi_carry() {
        let mut buf = *b"00000000000000000099";
        increment_bcd(&mut buf);
        assert_eq!(&buf, b"00000000000000000100");
    }

    #[test]
    fn test_increment_bcd_all_nines() {
        let mut buf = *b"00000000000000009999";
        increment_bcd(&mut buf);
        assert_eq!(&buf, b"00000000000000010000");
    }

    #[test]
    fn test_increment_bcd_consistency_with_write_serial() {
        let base: u64 = 999_999_999_990;
        let mut bcd_buf = [0u8; SERIAL_LEN];
        write_serial(&mut bcd_buf, base);

        for i in 1..=16u64 {
            increment_bcd(&mut bcd_buf);
            let mut expected = [0u8; SERIAL_LEN];
            write_serial(&mut expected, base + i);
            assert_eq!(bcd_buf, expected, "BCD mismatch at base+{}", i);
        }
    }

    // ---- mbr_val search strategy cross-validation (Approach A vs Approach B) ----
    //
    // Two independent ways to find, for a fixed serial/model/size, which `mbr_val`
    // (0..2048) reproduces a target SOFTWARE ID when `--identity` isn't fixed:
    //
    //   Approach A ("sweep"): for each candidate, try all 2048 `mbr_val` values and
    //   compare the resulting (final_lo, final_hi) against the target's raw values.
    //   O(2048) per candidate.
    //
    //   Approach B ("feasibility check", per docs/reference/identity-reverse-search.md):
    //   for each candidate, XOR its sid_lo/sid_hi against the target directly to get the
    //   *required* mix, then check it's an exact multiple of 0x3FF800F with a quotient in
    //   0..=2047. O(1) per candidate (per target) -- no sweep needed.
    //
    // Both must find exactly the same hits. This test builds a small synthetic search
    // space with a known "needle" (a specific candidate/mbr_val pair guaranteed to hit),
    // runs both approaches over it, and asserts their hit sets agree exactly -- the same
    // cross-validation-by-independent-implementation pattern this project already uses
    // for SIMD vs. scalar SHA-256 (`test_simd_matches_scalar`).
    #[test]
    fn test_mbr_val_sweep_vs_feasibility_check_agree() {
        const N_CANDIDATES: usize = 2000;
        const NEEDLE_IDX: usize = 777;
        const NEEDLE_MBR_VAL: u32 = 555;
        const MIX_MULTIPLIER: u64 = 0x3FF800F;

        // Fixed model/disk-size context, same shape as a real `search` run.
        let model_bytes = build_model_bytes("ROS1G");
        let sector_val = disk_bytes_to_sector_val(1_073_741_824); // 1G
        let sv_bytes = sector_val.to_le_bytes();

        // Generate N_CANDIDATES consecutive serials (BCD increment, same as the real
        // search loop) and their (sid_lo, sid_hi) hashes.
        let mut serial_buf = [b'0'; SERIAL_LEN];
        let mut candidates: Vec<(u32, u8)> = Vec::with_capacity(N_CANDIDATES);
        for _ in 0..N_CANDIDATES {
            let buf = build_input_buf(&serial_buf, &model_bytes, &sv_bytes);
            candidates.push(sha256::hash_40(&buf));
            increment_bcd(&mut serial_buf);
        }

        // Plant the needle: the target is whatever SOFTWARE ID candidate NEEDLE_IDX
        // produces under NEEDLE_MBR_VAL. Computed directly (not via encode/decode --
        // those have their own tests) as the raw (target_lo, target_hi) pair, matching
        // `compute_software_id`'s real, hardware-confirmed formula (full width,
        // `(sid_hi|0x100) XOR mix_hi` -- see targets::required_mix's doc comment,
        // 2026-09-07 real-VM confirmation).
        let (needle_sid_lo, needle_sid_hi) = candidates[NEEDLE_IDX];
        let needle_mix = (NEEDLE_MBR_VAL as u64) * MIX_MULTIPLIER;
        let needle_mix_lo = needle_mix as u32;
        let needle_mix_hi = (needle_mix >> 32) as u32;
        let target_lo = needle_sid_lo ^ needle_mix_lo;
        let target_hi = ((needle_sid_hi as u32) | 0x100) ^ needle_mix_hi;

        // Approach A: sweep all 2048 mbr_val per candidate.
        let mut hits_a: Vec<(usize, u32)> = Vec::new();
        for (i, &(sid_lo, sid_hi)) in candidates.iter().enumerate() {
            for mbr_val in 0u32..2048 {
                let mix = (mbr_val as u64) * MIX_MULTIPLIER;
                let mix_lo = mix as u32;
                let mix_hi = (mix >> 32) as u32;
                let final_lo = sid_lo ^ mix_lo;
                let final_hi = ((sid_hi as u32) | 0x100) ^ mix_hi;
                if final_lo == target_lo && final_hi == target_hi {
                    hits_a.push((i, mbr_val));
                }
            }
        }

        // Approach B: feasibility check per candidate, no sweep.
        let mut hits_b: Vec<(usize, u32)> = Vec::new();
        for (i, &(sid_lo, sid_hi)) in candidates.iter().enumerate() {
            let required_mix_lo = sid_lo ^ target_lo;
            let required_mix_hi = ((sid_hi as u32) | 0x100) ^ target_hi;
            let required_mix = (required_mix_lo as u64) | ((required_mix_hi as u64) << 32);
            if required_mix % MIX_MULTIPLIER == 0 {
                let mbr_val = required_mix / MIX_MULTIPLIER;
                if mbr_val < 2048 {
                    hits_b.push((i, mbr_val as u32));
                }
            }
        }

        assert!(
            hits_a.contains(&(NEEDLE_IDX, NEEDLE_MBR_VAL)),
            "planted needle must be found by approach A"
        );
        assert!(
            hits_b.contains(&(NEEDLE_IDX, NEEDLE_MBR_VAL)),
            "planted needle must be found by approach B"
        );
        assert_eq!(
            hits_a, hits_b,
            "sweep (A) and feasibility-check (B) must find exactly the same hits"
        );
    }

    /// Real-disk, all-`keys.toml`-targets version of the A-vs-B cross-check above: for a
    /// specific real serial/model/size, sweep all 2048 `mbr_val` (Approach A) against
    /// *every* entry in `keys.toml` and separately run the feasibility check (Approach B)
    /// against every entry, then assert the two full hit sets agree exactly -- not just a
    /// single planted needle this time, the complete result for this disk.
    ///
    /// `#[ignore]`: depends on `keys.toml` existing at the crate root at test-run time
    /// (gitignored, not present in a fresh clone/CI) -- run explicitly with
    /// `cargo test -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn test_real_disk_all_targets_sweep_vs_feasibility_check_agree() {
        const MIX_MULTIPLIER: u64 = 0x3FF800F;

        let serial = "1";
        let model = "VMware Virtual SATA Hard Drive";
        let sizes: [(&str, u64); 18] = [
            ("60M", 62_914_560),
            ("128M", 128 * 1024 * 1024),
            ("256M", 256 * 1024 * 1024),
            ("512M", 512 * 1024 * 1024),
            ("1G", 1024 * 1024 * 1024),
            ("2G", 2 * 1024 * 1024 * 1024),
            ("4G", 4 * 1024 * 1024 * 1024),
            ("6G", 6 * 1024 * 1024 * 1024),
            ("8G", 8 * 1024 * 1024 * 1024),
            ("10G", 10 * 1024 * 1024 * 1024),
            ("12G", 12 * 1024 * 1024 * 1024),
            ("16G", 16 * 1024 * 1024 * 1024),
            ("18G", 18 * 1024 * 1024 * 1024),
            ("20G", 20 * 1024 * 1024 * 1024),
            ("24G", 24 * 1024 * 1024 * 1024),
            ("32G", 32 * 1024 * 1024 * 1024),
            ("48G", 48 * 1024 * 1024 * 1024),
            ("64G", 64 * 1024 * 1024 * 1024),
        ];

        let entries = targets::load_from_file("keys.toml").expect("keys.toml must be present");
        assert!(!entries.is_empty(), "keys.toml must not be empty");

        // Raw (unmasked) (name, tv_lo, tv_hi) per target -- NOT run through
        // `entries_to_targets`, which bakes in one fixed mix and masks tv_hi to u8.
        let raw_targets: Vec<(String, u32, u32)> = entries
            .iter()
            .map(|e| {
                let tv = software_id::decode(&e.software_id)
                    .unwrap_or_else(|err| panic!("invalid SOFTWARE ID {}: {}", e.software_id, err));
                (e.software_id.clone(), tv as u32, (tv >> 32) as u32)
            })
            .collect();

        for (size_label, total_bytes) in sizes {
            for (bus, bus_label) in [(BusType::Ide, "Ide"), (BusType::Scsi, "Scsi")] {
                let sector_val = sector_val_for_bus(bus, total_bytes);
                let serial_bytes = build_serial_bytes(serial);
                let model_bytes = build_model_bytes(model);
                let buf = build_input_buf(&serial_bytes, &model_bytes, &sector_val.to_le_bytes());
                let (sid_lo, sid_hi) = sha256::hash_40(&buf);

                // Approach A: sweep all 2048 mbr_val, check against every target. Matches
                // `compute_software_id`'s real, hardware-confirmed full-width formula
                // (`(sid_hi|0x100) XOR mix_hi`, see targets::required_mix's doc comment,
                // 2026-09-07).
                let mut hits_a: Vec<(String, u32)> = Vec::new();
                for mbr_val in 0u32..2048 {
                    let mix = (mbr_val as u64) * MIX_MULTIPLIER;
                    let mix_lo = mix as u32;
                    let mix_hi = (mix >> 32) as u32;
                    let final_lo = sid_lo ^ mix_lo;
                    let final_hi = ((sid_hi as u32) | 0x100) ^ mix_hi;
                    for (name, tv_lo, tv_hi) in &raw_targets {
                        if final_lo == *tv_lo && final_hi == *tv_hi {
                            hits_a.push((name.clone(), mbr_val));
                        }
                    }
                }

                // Approach B: feasibility check per target, no sweep.
                let mut hits_b: Vec<(String, u32)> = Vec::new();
                for (name, tv_lo, tv_hi) in &raw_targets {
                    let required_mix_lo = sid_lo ^ tv_lo;
                    let required_mix_hi = ((sid_hi as u32) | 0x100) ^ tv_hi;
                    let required_mix = (required_mix_lo as u64) | ((required_mix_hi as u64) << 32);
                    if required_mix % MIX_MULTIPLIER == 0 {
                        let mbr_val = required_mix / MIX_MULTIPLIER;
                        if mbr_val < 2048 {
                            hits_b.push((name.clone(), mbr_val as u32));
                        }
                    }
                }
                hits_a.sort();
                hits_b.sort();

                eprintln!(
                    "[{size_label} bytes={total_bytes} {bus_label}] sid_lo=0x{sid_lo:08X} sid_hi=0x{sid_hi:02X} -- {} keys.toml targets checked",
                    raw_targets.len()
                );
                eprintln!("[{size_label} {bus_label}] Approach A hits: {hits_a:?}");
                eprintln!("[{size_label} {bus_label}] Approach B hits: {hits_b:?}");

                assert_eq!(
                    hits_a, hits_b,
                    "[{size_label} {bus_label}] sweep (A) and feasibility-check (B) must find exactly the same hits for every keys.toml target"
                );
            }
        }
    }

    // ---- compute_software_id ----

    #[test]
    fn test_compute_software_id_6g_vmware() {
        let (mix_lo, mix_hi) = targets::mbr_mix();
        let sid = compute_software_id(0x0B49EC2E, 0x35, mix_lo, mix_hi);
        // Self-consistency: result must be a valid SOFTWARE ID that round-trips
        assert_eq!(sid.len(), 9);
        assert_eq!(sid.chars().nth(4), Some('-'));
        let v = software_id::decode(&sid).expect("decode computed sid");
        assert_eq!(software_id::encode(v), sid);
    }

    #[test]
    fn test_compute_software_id_deterministic() {
        let (mix_lo, mix_hi) = targets::mbr_mix();
        let a = compute_software_id(0xAABBCCDD, 0xEE, mix_lo, mix_hi);
        let b = compute_software_id(0xAABBCCDD, 0xEE, mix_lo, mix_hi);
        assert_eq!(a, b, "same input must produce same output");
    }

    // ---- build_model_bytes ----

    #[test]
    fn test_build_model_bytes_short() {
        let bytes = build_model_bytes("ROS6G");
        assert_eq!(&bytes[..5], b"ROS6G");
        assert_eq!(bytes[5], SPACE_PADDING);
        assert_eq!(bytes[15], SPACE_PADDING);
    }

    #[test]
    fn test_build_model_bytes_exact() {
        let bytes = build_model_bytes("VMware Virtual I");
        assert_eq!(&bytes, b"VMware Virtual I");
    }

    // ---- build_serial_bytes ----

    #[test]
    fn test_build_serial_bytes_numeric_short() {
        let bytes = build_serial_bytes("123");
        assert_eq!(&bytes, b"00000000000000000123");
    }

    #[test]
    fn test_build_serial_bytes_numeric_full() {
        let bytes = build_serial_bytes("00000000350481748276");
        assert_eq!(&bytes, b"00000000350481748276");
    }

    #[test]
    fn test_build_serial_bytes_alpha_exact() {
        // 19-char alphanumeric serial: right-padded with one trailing space to fill SERIAL_LEN (20)
        let bytes = build_serial_bytes("G4HQT594JN8VLY0FGN9");
        assert_eq!(&bytes, b"G4HQT594JN8VLY0FGN9 ");
    }

    #[test]
    fn test_build_serial_bytes_alpha_short() {
        let bytes = build_serial_bytes("SZHYPO14090903D0164");
        // 19 chars + 1 space padding on right
        assert_eq!(&bytes[..19], b"SZHYPO14090903D0164");
        assert_eq!(bytes[19], SPACE_PADDING);
    }

    #[test]
    fn test_build_serial_bytes_with_hyphen() {
        let bytes = build_serial_bytes("HYSSD-20160419B7902");
        assert_eq!(&bytes[..19], b"HYSSD-20160419B7902");
        assert_eq!(bytes[19], SPACE_PADDING);
    }

    #[test]
    fn test_build_serial_bytes_empty_matches_keyman_space_padding() {
        // keyman zero-fills its 20-byte serial buffer before reading the disk, then
        // sweeps the whole buffer turning every zero byte into a space -- an empty
        // (zero-length) serial therefore becomes 20 ASCII spaces, not 20 '0' chars.
        // Confirmed via keyman_x86_7.24.1 disassembly (zero-fill at 0x8050411-0x805041e,
        // pad loop at 0x8050a1e-0x8050a29, which never special-cases length 0).
        let bytes = build_serial_bytes("");
        assert_eq!(&bytes, &[SPACE_PADDING; SERIAL_LEN]);
    }

    // ---- parse_identity_hex / resolve_mix ----

    #[test]
    fn test_parse_identity_hex_exact_20() {
        let bytes = parse_identity_hex("0011223344556677AABB");
        assert_eq!(
            bytes,
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xAA, 0xBB]
        );
    }

    #[test]
    fn test_parse_identity_hex_lowercase() {
        let bytes = parse_identity_hex("0011223344556677aabb");
        assert_eq!(
            bytes,
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xAA, 0xBB]
        );
    }

    #[test]
    fn test_resolve_mix_none_matches_standard() {
        assert_eq!(resolve_mix(None), targets::mbr_mix());
    }

    #[test]
    fn test_resolve_mix_custom_matches_targets_fn() {
        let hex = "0011223344556677AABB";
        assert_eq!(
            resolve_mix(Some(hex)),
            targets::mix_from_identity(&parse_identity_hex(hex))
        );
    }

    // ---- is_valid_serial / is_valid_model ----

    #[test]
    fn test_is_valid_serial() {
        assert!(is_valid_serial("00000000350481748276"));
        assert!(is_valid_serial("G4HQT594JN8VLY0FGN9"));
        assert!(is_valid_serial("HYSSD-20160419B79028"));
        assert!(!is_valid_serial("hello world")); // space invalid
        assert!(!is_valid_serial("test@#$"));
    }

    #[test]
    fn test_is_valid_model() {
        assert!(is_valid_model("VMware Virtual I"));
        assert!(is_valid_model("ROS128G"));
        assert!(is_valid_model("cheerlon"));
        assert!(!is_valid_model("test@model"));
    }

    // ---- build_input_buf ----

    #[test]
    fn test_build_input_buf_layout() {
        let serial = *b"00000000000000000001";
        let model = *b"VMware Virtual I";
        let sv = 0x1800u32.to_le_bytes();
        let buf = build_input_buf(&serial, &model, &sv);

        assert_eq!(buf.len(), INPUT_LEN);
        assert_eq!(&buf[..SERIAL_LEN], b"00000000000000000001");
        assert_eq!(
            &buf[SERIAL_LEN..SERIAL_LEN + MODEL_LEN],
            b"VMware Virtual I"
        );
        assert_eq!(&buf[SERIAL_LEN + MODEL_LEN..], &sv);
    }

    // ---- check_match ----

    fn make_test_ctx(targets: Vec<targets::Target>) -> SearchContext {
        let (mix_lo, mix_hi) = targets::mbr_mix();
        SearchContext {
            model_bytes: [SPACE_PADDING; MODEL_LEN],
            sv_bytes: [0; 4],
            targets: Arc::new(targets),
            raw_targets: None,
            mbr_table: None,
            serial_pad: SerialPad::Zero,
            mix_lo,
            mix_hi,
            max_collisions: 0,
            stop: Arc::new(AtomicBool::new(false)),
            found_count: Arc::new(AtomicUsize::new(0)),
            start: Instant::now(),
        }
    }

    fn make_fake_target() -> targets::Target {
        targets::Target {
            need_lo: 0x0B49EC2E,
            need_hi: 0x135, // 0x35 | 0x100 -- full-width need_hi, see Target::need_hi's doc
            name: "TEST-0001".to_string(),
            signature_hex: "AA".repeat(64),
        }
    }

    #[test]
    fn test_check_match_hit() {
        let ctx = make_test_ctx(vec![make_fake_target()]);

        check_match(1, 0x0B49EC2E, 0x35, &ctx);
        assert_eq!(ctx.found_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_check_match_miss() {
        let ctx = make_test_ctx(vec![make_fake_target()]);

        check_match(999, 0xDEADBEEF, 0xFF, &ctx);
        assert_eq!(ctx.found_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_check_match_sid_hi_only_miss() {
        let ctx = make_test_ctx(vec![make_fake_target()]);

        check_match(999, 0x0B49EC2E, 0x99, &ctx);
        assert_eq!(ctx.found_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_search_scalar_finds_space_padded_target() {
        let model_bytes = [SPACE_PADDING; MODEL_LEN];
        let sv_bytes = [0u8; 4];

        // Plant a target at serial=7 using SPACE padding ("7" + 19 spaces), not the
        // default zero padding.
        let mut zero_buf = [b'0'; SERIAL_LEN];
        write_serial(&mut zero_buf, 7);
        let space_buf = zero_padded_to_space_padded(&zero_buf);
        let buf = build_input_buf(&space_buf, &model_bytes, &sv_bytes);
        let (sid_lo, sid_hi) = sha256::hash_40(&buf);

        let need_lo = sid_lo;
        let need_hi = (sid_hi as u32) | 0x100;
        let make_target = || targets::Target {
            need_lo,
            need_hi,
            name: "SPACE-TEST".to_string(),
            signature_hex: "00".repeat(64),
        };

        // With --serial-pad space, search_scalar must find it at serial index 7.
        let mut ctx = make_test_ctx(vec![make_target()]);
        ctx.serial_pad = SerialPad::Space;
        ctx.max_collisions = 1;
        ctx.model_bytes = model_bytes;
        ctx.sv_bytes = sv_bytes;
        search_scalar(0, 1, 0, &ctx);
        assert_eq!(ctx.found_count.load(Ordering::Relaxed), 1);
        assert!(ctx.stop.load(Ordering::Relaxed));

        // The same target's hash must NOT be produced by the default zero-padded serial=7
        // ("00000000000000000007") -- confirms the two padding modes genuinely diverge.
        let zero_input_buf = build_input_buf(&zero_buf, &model_bytes, &sv_bytes);
        let (zero_sid_lo, zero_sid_hi) = sha256::hash_40(&zero_input_buf);
        assert!(zero_sid_lo != need_lo || ((zero_sid_hi as u32) | 0x100) != need_hi);
    }

    #[test]
    fn test_check_match_stops_at_target_count() {
        let mut ctx = make_test_ctx(vec![targets::Target {
            need_lo: 0xAAAAAAAA,
            need_hi: 0x1BB, // 0xBB | 0x100
            name: "TEST".to_string(),
            signature_hex: "00".repeat(64),
        }]);
        ctx.max_collisions = 1;

        check_match(0, 0xAAAAAAAA, 0xBB, &ctx);
        assert!(ctx.stop.load(Ordering::Relaxed));
    }

    // ---- End-to-end SOFTWARE ID ----

    #[test]
    fn test_end_to_end_6g_vmware() {
        let serial = *b"00000000000000000001";
        let model = *b"VMware Virtual I";
        let buf = build_input_buf(&serial, &model, &0x1800u32.to_le_bytes());

        let (sid_lo, sid_hi) = sha256::hash_40(&buf);
        let (mix_lo, mix_hi) = targets::mbr_mix();
        let sid = compute_software_id(sid_lo, sid_hi, mix_lo, mix_hi);
        // Self-consistency: computed SOFTWARE ID must encode/decode round-trip
        let v = software_id::decode(&sid).expect("decode computed sid");
        assert_eq!(software_id::encode(v), sid);
    }

    #[test]
    fn test_end_to_end_16g() {
        let serial = *b"00000000202155543391";
        let model_bytes = build_model_bytes("ROS16G");
        let buf = build_input_buf(&serial, &model_bytes, &0x4000u32.to_le_bytes());

        let (sid_lo, sid_hi) = sha256::hash_40(&buf);
        let (mix_lo, mix_hi) = targets::mbr_mix();
        let sid = compute_software_id(sid_lo, sid_hi, mix_lo, mix_hi);
        let v = software_id::decode(&sid).expect("decode computed sid");
        assert_eq!(software_id::encode(v), sid);
    }

    // ---- precompute_constant_words ----

    #[test]
    fn test_precompute_constant_words() {
        let model = b"VMware Virtual I";
        let sv_bytes = 0x1800u32.to_le_bytes();
        let words = sha256_simd::precompute_constant_words(model, &sv_bytes);

        assert_eq!(words[0], u32::from_be_bytes([b'V', b'M', b'w', b'a']));
        assert_eq!(words[1], u32::from_be_bytes([b'r', b'e', b' ', b'V']));
        assert_eq!(words[2], u32::from_be_bytes([b'i', b'r', b't', b'u']));
        assert_eq!(words[3], u32::from_be_bytes([b'a', b'l', b' ', b'I']));
        assert_eq!(words[4], u32::from_be_bytes([0x00, 0x18, 0x00, 0x00]));
    }
}

//! RouterOS L6 Serial Generator — computes serials from existing licenses + key conversion tool
//!
//! Selects a CPU-supported SHA-256 backend once at startup; each backend owns
//! its batch size, with portable scalar calculation retained as the reference.

mod convert;
mod curve25519;
mod sha256_constants;
use ros_serialgen::sha256;
#[cfg(test)]
use ros_serialgen::sha256_backend::precompute_constant_words;
use ros_serialgen::sha256_backend::{HashBatch, HashEngine};
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
        /// Disk size magnitude (paired with --unit)
        #[arg(short = 's', long = "disk-size")]
        disk_size: u64,
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
        /// device's captured MBR. Default: standard all-zero identity used by collision search.
        #[arg(short = 'i', long)]
        identity: Option<String>,
        /// Disk bus type: ide (default, verified against real hardware -- also covers
        /// sata0/AHCI, which uses the identical encoding) or scsi (scsi0/virtio-scsi-pci
        /// specifically, NOT sata0 -- forces sector_val=0; see docs/license-internals.md
        /// §8.11-8.20; end-to-end activation confirmed on x86_64, §8.18).
        #[arg(
            short = 'b',
            long,
            value_enum,
            ignore_case = true,
            default_value = "ide"
        )]
        bus: BusType,
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
        /// Disk size magnitude (paired with --unit)
        #[arg(short = 's', long = "disk-size")]
        disk_size: u64,
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
        /// sata0/AHCI, which uses the identical encoding) or scsi (scsi0/virtio-scsi-pci
        /// specifically, NOT sata0 -- forces sector_val=0; see docs/license-internals.md
        /// §8.11-8.20; end-to-end activation confirmed on x86_64, §8.18).
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
    let is_numeric = sb.iter().all(|b| b.is_ascii_digit());
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
        BusType::Ide => disk_bytes_to_sector_val(total_bytes),
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
        } => cmd_search(
            disk_size, unit, threads, model, keys, count, from, identity, bus,
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
    disk_size: u64,
    unit: SizeUnit,
    threads: Option<usize>,
    model: Option<String>,
    keys: Option<String>,
    count: usize,
    from: u64,
    identity: Option<String>,
    bus: BusType,
) {
    validate_disk_size(disk_size, unit);
    let (total_bytes, size_label) = disk_size_bytes_and_label(disk_size, unit);
    let sector_val = sector_val_for_bus(bus, total_bytes);
    let model = model.unwrap_or_else(|| format!("ROS{}", size_label));
    let num_threads = threads.unwrap_or_else(|| {
        thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    });
    let (mix_lo, mix_hi) = resolve_mix(identity.as_deref());
    let raw_targets = targets::load_targets(keys.as_deref(), (mix_lo, mix_hi));
    let engine = HashEngine::auto_for_threads(num_threads).unwrap_or_else(|error| {
        eprintln!("FATAL: {error}");
        std::process::exit(1);
    });
    let start_serial = from * 1_000_000;

    verify_6g(&raw_targets);
    print_search_banner(
        &size_label,
        &model,
        sector_val,
        num_threads,
        &raw_targets,
        count,
        start_serial,
        engine,
        identity.as_deref(),
        bus,
    );

    let ctx = Arc::new(SearchContext {
        model_bytes: build_model_bytes(&model),
        sv_bytes: sector_val.to_le_bytes(),
        targets: Arc::new(raw_targets),
        mix_lo,
        mix_hi,
        max_collisions: count,
        stop: Arc::new(AtomicBool::new(false)),
        found_count: Arc::new(AtomicUsize::new(0)),
        start: Instant::now(),
    });

    let handles: Vec<_> = (0..num_threads)
        .map(|tid| {
            let ctx = Arc::clone(&ctx);
            thread::spawn(move || {
                search_batch(tid, num_threads, start_serial, &ctx, engine);
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
    engine: HashEngine,
    identity: Option<&str>,
    bus: BusType,
) {
    let mode_str = if count == 0 {
        "unlimited".to_string()
    } else {
        format!("find {}", count)
    };

    println!("=== RouterOS L6 Serial Generator ===");
    println!(
        "Disk: {}  Model: {}  SV: 0x{:X}",
        disk_label, model, sector_val
    );
    match bus {
        BusType::Ide => {
            println!("Bus: ide (verified against real hardware; also covers sata0/AHCI)")
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
            "  {} need_lo=0x{:08X} need_hi=0x{:02X}",
            t.name, t.need_lo, t.need_hi
        );
    }
    println!("\nSearching...\n");
}

// ---- Search engines ----

/// Search with a previously selected backend and its native batch size.
fn search_batch(
    tid: usize,
    num_threads: usize,
    start_serial: u64,
    ctx: &SearchContext,
    engine: HashEngine,
) {
    let mut hashes = HashBatch::new(engine, &ctx.model_bytes, &ctx.sv_bytes);
    let batch = hashes.len() as u64;
    let step = (num_threads as u64) * batch;
    let mut base: u64 = start_serial.wrapping_add((tid as u64) * batch);

    // BCD counter
    let mut base_serial = [b'0'; SERIAL_LEN];
    write_serial(&mut base_serial, base);

    // sid_hi pre-filter table: most batches have no match.
    let mut hi_lookup = [false; 256];
    for t in ctx.targets.iter() {
        hi_lookup[t.need_hi as usize] = true;
    }

    loop {
        if ctx.stop.load(Ordering::Relaxed) {
            return;
        }

        let mut lane_serial = base_serial;
        for lane in 0..hashes.len() {
            hashes.serial_mut(lane).copy_from_slice(&lane_serial);
            if base.wrapping_add(lane as u64) == u64::MAX {
                lane_serial.fill(b'0');
            } else {
                increment_bcd(&mut lane_serial);
            }
        }

        hashes.hash();

        for (lane, &(sid_lo, sid_hi)) in hashes.outputs().iter().enumerate() {
            if hi_lookup[sid_hi as usize] {
                check_match(base.wrapping_add(lane as u64), sid_lo, sid_hi, ctx);
            }
        }

        let previous_base = base;
        base = base.wrapping_add(step);
        // Keep decimal and numeric counters identical even when u64 wraps.
        if step <= 256 && base >= previous_base {
            for _ in 0..step {
                increment_bcd(&mut base_serial);
            }
        } else {
            write_serial(&mut base_serial, base);
        }

        if tid == 0 && (base / PROGRESS_INTERVAL) != (previous_base / PROGRESS_INTERVAL) {
            report_progress(base, &ctx.start, &ctx.found_count);
        }
    }
}

/// Check whether a hash result matches any target (only formats serial on a hit)
fn check_match(serial_num: u64, sid_lo: u32, sid_hi: u8, ctx: &SearchContext) {
    for t in ctx.targets.iter() {
        if sid_hi == t.need_hi && sid_lo == t.need_lo {
            let n = ctx.found_count.fetch_add(1, Ordering::Relaxed) + 1;
            let sid = compute_software_id(sid_lo, sid_hi, ctx.mix_lo, ctx.mix_hi);

            let mut sbuf = [0u8; SERIAL_LEN];
            write_serial(&mut sbuf, serial_num);
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
    disk_size: u64,
    unit: SizeUnit,
    model: Option<String>,
    keys: Option<String>,
    identity: Option<String>,
    bus: BusType,
    license: Option<String>,
) {
    validate_disk_size(disk_size, unit);
    let (total_bytes, size_label) = disk_size_bytes_and_label(disk_size, unit);
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
        .find(|t| sid_hi == t.need_hi && sid_lo == t.need_lo);

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
    let engine = HashEngine::auto().unwrap_or_else(|error| {
        eprintln!("FATAL: {error}");
        std::process::exit(1);
    });

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
fn verify_6g(targets: &[targets::Target]) {
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
    if let Some(t) = targets
        .iter()
        .find(|t| t.need_lo == sid_lo && t.need_hi == sid_hi)
    {
        let _ = t; // hash matches a configured target; nothing further to check
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
            need_hi: 0x35,
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
    fn test_check_match_stops_at_target_count() {
        let mut ctx = make_test_ctx(vec![targets::Target {
            need_lo: 0xAAAAAAAA,
            need_hi: 0xBB,
            name: "TEST".to_string(),
            signature_hex: "00".repeat(64),
        }]);
        ctx.max_collisions = 1;

        check_match(0, 0xAAAAAAAA, 0xBB, &ctx);
        assert!(ctx.stop.load(Ordering::Relaxed));
    }

    #[test]
    fn test_search_batch_all_backends_and_thread_offsets() {
        for engine in HashEngine::supported() {
            for num_threads in [1, 3, 257] {
                for tid in [0, num_threads - 1] {
                    for start_serial in [9_999_999_990_u64, u64::MAX - 2] {
                        for batch_index in [0, 3] {
                            let offset = ((batch_index * num_threads + tid) * engine.batch_size()
                                + engine.batch_size()
                                - 1) as u64;
                            let serial_num = start_serial.wrapping_add(offset);
                            let mut serial = [0; SERIAL_LEN];
                            write_serial(&mut serial, serial_num);
                            let model = *b"VMware Virtual I";
                            let sv = 0x1800u32.to_le_bytes();
                            let (sid_lo, sid_hi) =
                                sha256::hash_40(&build_input_buf(&serial, &model, &sv));
                            let mut ctx = make_test_ctx(vec![targets::Target {
                                need_lo: sid_lo,
                                need_hi: sid_hi,
                                name: "synthetic backend regression".to_string(),
                                signature_hex: String::new(),
                            }]);
                            ctx.model_bytes = model;
                            ctx.sv_bytes = sv;
                            ctx.max_collisions = 1;
                            let ctx = Arc::new(ctx);
                            let worker_ctx = Arc::clone(&ctx);
                            let (done_tx, done_rx) = std::sync::mpsc::channel();
                            let worker = thread::spawn(move || {
                                search_batch(tid, num_threads, start_serial, &worker_ctx, engine);
                                let _ = done_tx.send(());
                            });
                            let done = done_rx.recv_timeout(std::time::Duration::from_secs(3));
                            ctx.stop.store(true, Ordering::Relaxed);
                            worker.join().unwrap();
                            assert!(
                                done.is_ok(),
                                "{engine}: search mapping did not reach expected target"
                            );
                            assert_eq!(ctx.found_count.load(Ordering::Relaxed), 1, "{engine}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_search_batch_honors_preexisting_stop() {
        for engine in HashEngine::supported() {
            let ctx = make_test_ctx(vec![]);
            ctx.stop.store(true, Ordering::Relaxed);
            search_batch(0, 1, 0, &ctx, engine);
            assert_eq!(ctx.found_count.load(Ordering::Relaxed), 0);
        }
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
        let words = precompute_constant_words(model, &sv_bytes);

        assert_eq!(words[0], u32::from_be_bytes([b'V', b'M', b'w', b'a']));
        assert_eq!(words[1], u32::from_be_bytes([b'r', b'e', b' ', b'V']));
        assert_eq!(words[2], u32::from_be_bytes([b'i', b'r', b't', b'u']));
        assert_eq!(words[3], u32::from_be_bytes([b'a', b'l', b' ', b'I']));
        assert_eq!(words[4], u32::from_be_bytes([0x00, 0x18, 0x00, 0x00]));
    }
}

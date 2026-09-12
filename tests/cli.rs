use std::fs::{self, File};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new(sid: &str) -> Self {
        let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("mtsc-cli-{}-{id}", std::process::id()));
        fs::create_dir(&path).unwrap();
        fs::write(
            path.join("keys.toml"),
            format!("[[key]]\nsoftware_id = \"{sid}\"\n"),
        )
        .unwrap();
        Self(path)
    }

    fn run(&self, args: &[&str]) -> Output {
        let stdout_path = self.0.join("stdout.txt");
        let stderr_path = self.0.join("stderr.txt");
        let mut child = Command::new(env!("CARGO_BIN_EXE_mtsc"))
            .args(args)
            .current_dir(&self.0)
            .stdin(Stdio::null())
            .stdout(File::create(&stdout_path).unwrap())
            .stderr(File::create(&stderr_path).unwrap())
            .spawn()
            .unwrap();
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if started.elapsed() > Duration::from_secs(30) {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "mtsc {args:?} timed out\nstdout: {}\nstderr: {}",
                    fs::read_to_string(&stdout_path).unwrap(),
                    fs::read_to_string(&stderr_path).unwrap()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        Output {
            status,
            stdout: fs::read(stdout_path).unwrap(),
            stderr: fs::read(stderr_path).unwrap(),
        }
    }

    fn success(&self, args: &[&str]) -> String {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "mtsc {args:?}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn expected_sid(serial: &[u8; 20], sector_val: u32) -> String {
    let mut input = [b' '; 40];
    input[..20].copy_from_slice(serial);
    input[20..28].copy_from_slice(b"TestDisk");
    input[36..40].copy_from_slice(&sector_val.to_le_bytes());
    let (lo, hi) = mtsc::sha256::hash_40(&input);
    let mix = 0xBD_u64 * 0x3FF800F;
    let mut value = (u64::from(lo) | ((u64::from(hi) | 0x100) << 32)) ^ mix;
    let table = b"TN0BYX18S5HZ4IA67DGF3LPCJQRUK9MW2VE";
    let mut sid = String::new();
    for digit in 0..8 {
        if digit == 4 {
            sid.push('-');
        }
        sid.push(table[(value % 35) as usize] as char);
        value /= 35;
    }
    sid
}

#[test]
fn mtsc_name_version_help_and_completions() {
    let fixture = Fixture::new("TTTT-TTTT");
    assert_eq!(
        fixture.success(&["--version"]).trim(),
        concat!("mtsc ", env!("CARGO_PKG_VERSION"))
    );
    let help = fixture.success(&["search", "--help"]);
    assert!(help.contains("mtsc search") || help.contains("mtsc.exe search"));
    for flag in ["--pad", "--alphabet", "--mbr-table", "--identity"] {
        assert!(help.contains(flag), "missing {flag}");
    }
    let completion = fixture.success(&["completions", "bash"]);
    assert!(completion.contains("mtsc"));
    assert!(!completion.contains("ros-serialgen"));
    assert!(fixture.success(&["verify"]).contains("OK"));
}

#[test]
fn check_both_padding_variants_with_legacy_sid_only_config() {
    let sid = expected_sid(b"00000000000000000123", 0x1800);
    let fixture = Fixture::new(&sid);
    let output = fixture.success(&[
        "check",
        "--serial",
        "123",
        "--disk-size",
        "6",
        "--model",
        "TestDisk",
    ]);
    assert!(output.contains("Serial (zero-padded): 00000000000000000123"));
    assert!(output.contains("Serial (space-padded): 123"));
    assert_eq!(output.matches("Software ID:").count(), 2);
    assert!(output.contains(&format!("Software ID: {sid}")));
    assert!(output.contains(&format!("Matched signature: {sid}")));

    for serial in ["00000000000000000123", "abc", ""] {
        let output = fixture.success(&[
            "check",
            "--serial",
            serial,
            "--disk-size",
            "6",
            "--model",
            "TestDisk",
        ]);
        assert_eq!(output.matches("Software ID:").count(), 1, "{serial:?}");
    }
}

#[test]
fn legacy_fixed_identity_search_self_verifies() {
    let sid = expected_sid(b"00000000000000000000", 0x1800);
    let fixture = Fixture::new(&sid);
    let output = fixture.success(&[
        "search",
        "--disk-size",
        "6",
        "--model",
        "TestDisk",
        "--threads",
        "1",
        "--identity",
        "00000000000000000000",
        "--pad",
        "start",
    ]);
    assert!(output.contains("FOUND [1] serial=00000000000000000000"));
    assert!(output.contains(&format!("target={sid} verified={sid}")));
}

#[test]
fn default_sweep_uses_space_padding_and_validated_table() {
    let mut serial = [b' '; 20];
    serial[0] = b'0';
    let sid = expected_sid(&serial, 0x1800);
    let fixture = Fixture::new(&sid);
    fs::write(
        fixture.0.join("mbr-table.toml"),
        "[[entry]]\nmbr_val = 189\nidentity = \"00000000000000000000\"\nmarker = \"BDE8\" # valid override\n",
    )
    .unwrap();
    let args = [
        "search",
        "--disk-size",
        "6",
        "--model",
        "TestDisk",
        "--threads",
        "1",
    ];
    let output = fixture.success(&args);
    assert!(output.contains(&format!(
        "FOUND [1] serial={} target=",
        std::str::from_utf8(&serial).unwrap()
    )));
    assert!(output.contains("mbr_val=189 identity=00000000000000000000 marker=BDE8"));
    assert!(output.contains(&format!("verified={sid}")));

    fs::write(
        fixture.0.join("mbr-table.toml"),
        "[[entry]]\nmbr_val = 189\n",
    )
    .unwrap();
    let fallback = fixture.success(&args);
    assert!(fallback.contains(&format!("verified={sid}")));
    assert!(!fallback.contains("identity= marker="));
}

#[test]
fn custom_alphabet_fixed_search_preserves_zero_symbol() {
    for pad in ["start", "end"] {
        let mut serial = [b'A'; 20];
        if pad == "end" {
            serial[1..].fill(b' ');
        }
        let sid = expected_sid(&serial, 0x1800);
        let fixture = Fixture::new(&sid);
        let output = fixture.success(&[
            "search",
            "--disk-size",
            "6",
            "--model",
            "TestDisk",
            "--threads",
            "1",
            "--identity",
            "00000000000000000000",
            "--alphabet",
            "A0B",
            "--pad",
            pad,
        ]);
        assert!(output.contains(&format!("target={sid} verified={sid}")));
        assert!(output.contains(&format!(
            "serial={} target=",
            std::str::from_utf8(&serial).unwrap()
        )));
    }
}

#[test]
fn bus_and_invalid_search_arguments_fail_clearly() {
    let sid = expected_sid(b"00000000000000000123", 0);
    let fixture = Fixture::new(&sid);
    let scsi = fixture.success(&[
        "check",
        "--serial",
        "00000000000000000123",
        "--bus",
        "scsi",
        "--model",
        "TestDisk",
    ]);
    assert!(scsi.contains("SV: 0x0"));
    assert!(scsi.contains(&format!("Software ID: {sid}")));
    let output = fixture.run(&["check", "--serial", "123", "--bus", "scsi"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--model"));
    let output = fixture.run(&["check", "--serial", "123", "--bus", "nvme"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--disk-size"));

    for invalid in [
        ["--threads", "0"],
        ["--from", "18446744073709551615"],
        ["--alphabet", "001"],
        ["--alphabet", "0"],
        ["--alphabet", "0!"],
    ] {
        let output = fixture.run(&[
            "search",
            "--disk-size",
            "6",
            "--model",
            "TestDisk",
            invalid[0],
            invalid[1],
        ]);
        assert!(!output.status.success(), "{invalid:?}");
    }
}

#[test]
fn conversion_accepts_literal_key_and_preserves_report_format() {
    let fixture = Fixture::new("TTTT-TTTT");
    let hex = "00".repeat(64);
    let report = fixture.success(&["sig2key", &hex]);
    assert!(report.contains(&format!("MBR Signature (hex): {hex}")));
    let start = report
        .find("-----BEGIN MIKROTIK SOFTWARE KEY------------")
        .unwrap();
    let end_marker = "-----END MIKROTIK SOFTWARE KEY--------------";
    let end = report.find(end_marker).unwrap() + end_marker.len();
    let key = &report[start..end];
    let literal = fixture.success(&["key2sig", key]);
    fs::write(fixture.0.join("synthetic.key"), key).unwrap();
    let from_file = fixture.success(&["key2sig", "synthetic.key"]);
    assert_eq!(literal, from_file);
    assert!(literal.contains(&format!("MBR Signature (hex): {hex}")));
    assert!(literal.contains("License valid: false"));
}

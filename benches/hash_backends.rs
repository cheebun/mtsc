//! Reproducible fixed-input SHA-256 throughput benchmark, independent of licenses.

use clap::{Parser, ValueEnum};
use ros_serialgen::sha256_backend::{HashBackend, HashBatch, HashEngine};
use std::hint::black_box;
use std::sync::{mpsc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    /// Kernel dispatch, changing one serial byte, and observing all outputs.
    Hash,
    /// Consecutive BCD serial preparation and hashing (no target lookup or I/O).
    Serial,
}

#[derive(Parser)]
#[command(about = "MikroTik 40-byte SHA-256 backend throughput; no license data needed")]
struct Args {
    /// Only benchmark these backends; omit to test every supported implementation.
    #[arg(long, value_enum)]
    backend: Vec<HashBackend>,
    /// Restrict native batch size (hardware SHA offers 1, 2, and 4).
    #[arg(long)]
    lanes: Option<usize>,
    /// Concurrent workers, identical for each backend.
    #[arg(long, default_value = "1")]
    threads: usize,
    /// Measured seconds per sample, excluding warm-up.
    #[arg(long, default_value = "1")]
    seconds: f64,
    /// Number of measured samples (median, minimum and maximum reported).
    #[arg(long, default_value = "5")]
    samples: usize,
    /// Work included in the timing.
    #[arg(long, value_enum, default_value = "hash")]
    mode: Mode,
    /// Warm-up seconds per backend, before measured rounds.
    #[arg(long, default_value = "0.2")]
    warmup: f64,
}

fn increment_bcd(serial: &mut [u8; 20]) {
    for byte in serial.iter_mut().rev() {
        if *byte < b'9' {
            *byte += 1;
            return;
        }
        *byte = b'0';
    }
}

fn measure(
    engine: HashEngine,
    threads: usize,
    duration: Duration,
    mode: Mode,
) -> Result<f64, String> {
    let (ready_tx, ready_rx) = mpsc::channel();
    // An open gate with no start time cancels workers without timing any work.
    let gate = (Mutex::new((false, None::<Instant>)), Condvar::new());
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        let mut failure = None;
        for tid in 0..threads {
            let ready = ready_tx.clone();
            let gate = &gate;
            match std::thread::Builder::new().spawn_scoped(scope, move || {
                let mut batch =
                    HashBatch::new(engine, b"VMware Virtual I", &0x1800u32.to_le_bytes());
                let serial = format!("{:020}", tid * engine.batch_size());
                let mut base_serial: [u8; 20] = serial.as_bytes().try_into().unwrap();
                let step = threads * engine.batch_size();
                let mut base = (tid * engine.batch_size()) as u64;
                for lane in 0..batch.len() {
                    batch.serial_mut(lane).copy_from_slice(&base_serial);
                    increment_bcd(&mut base_serial);
                }
                base_serial.copy_from_slice(serial.as_bytes());
                let _ = ready.send(());
                // Let the receiver detect an initialization panic in another worker.
                drop(ready);
                let (lock, wake) = gate;
                let state = wake
                    .wait_while(lock.lock().unwrap(), |state| !state.0)
                    .unwrap();
                let start = state.1;
                drop(state);
                let Some(start) = start else {
                    return (0, 0.0);
                };
                let mut calls = 0_u64;
                loop {
                    for _ in 0..256 {
                        match mode {
                            Mode::Hash => batch.serial_mut(0)[19] = calls as u8,
                            Mode::Serial => {
                                let mut lane_serial = base_serial;
                                for lane in 0..batch.len() {
                                    batch.serial_mut(lane).copy_from_slice(&lane_serial);
                                    if base.wrapping_add(lane as u64) == u64::MAX {
                                        lane_serial.fill(b'0');
                                    } else {
                                        increment_bcd(&mut lane_serial);
                                    }
                                }
                            }
                        }
                        black_box(&mut batch).hash();
                        black_box(batch.outputs());
                        if matches!(mode, Mode::Serial) {
                            let previous_base = base;
                            base = base.wrapping_add(step as u64);
                            if step <= 256 && base >= previous_base {
                                for _ in 0..step {
                                    increment_bcd(&mut base_serial);
                                }
                            } else {
                                let mut value = base;
                                for byte in base_serial.iter_mut().rev() {
                                    *byte = b'0' + (value % 10) as u8;
                                    value /= 10;
                                }
                            }
                        }
                        calls += 1;
                    }
                    if start.elapsed() >= duration {
                        break;
                    }
                }
                (calls * batch.len() as u64, start.elapsed().as_secs_f64())
            }) {
                Ok(handle) => handles.push(handle),
                Err(error) => {
                    failure = Some(format!(
                        "cannot create benchmark worker {} of {threads}: {error}",
                        tid + 1
                    ));
                    break;
                }
            }
        }
        drop(ready_tx);
        if failure.is_none() {
            for _ in 0..threads {
                if ready_rx.recv().is_err() {
                    failure = Some("benchmark worker did not initialize".to_string());
                    break;
                }
            }
        }
        let start = if failure.is_none() {
            Some(Instant::now())
        } else {
            None
        };
        *gate.0.lock().unwrap() = (true, start);
        gate.1.notify_all();
        let mut hashes = 0_u64;
        let mut elapsed = 0.0_f64;
        // Join every worker, including failed ones, before leaving the scope.
        for handle in handles {
            match handle.join() {
                Ok((count, seconds)) => {
                    hashes += count;
                    elapsed = elapsed.max(seconds);
                }
                Err(_) => {
                    failure.get_or_insert_with(|| "benchmark worker panicked".to_string());
                }
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(hashes as f64 / elapsed),
        }
    })
}

fn main() {
    // cargo bench forwards --bench to harness=false executables.
    let args = Args::parse_from(std::env::args_os().filter(|s| s != "--bench"));
    if args.threads == 0
        || args.threads > 1024
        || args.samples == 0
        || !args.seconds.is_finite()
        || !(0.01..=3600.0).contains(&args.seconds)
        || !args.warmup.is_finite()
        || !(0.01..=3600.0).contains(&args.warmup)
    {
        eprintln!("Error: threads must be 1..1024, samples > 0, seconds/warmup 0.01..3600");
        std::process::exit(2);
    }
    let supported = HashEngine::supported();
    for backend in &args.backend {
        if !supported.iter().any(|e| e.backend() == *backend) {
            eprintln!("Error: {backend} is unsupported on this CPU/OS");
            std::process::exit(2);
        }
    }
    let engines: Vec<_> = supported
        .into_iter()
        .filter(|e| {
            (args.backend.is_empty() || args.backend.contains(&e.backend()))
                && args.lanes.is_none_or(|lanes| e.batch_size() == lanes)
        })
        .collect();
    if engines.is_empty() {
        eprintln!("Error: no supported backend matches the requested batch size");
        std::process::exit(2);
    }
    println!(
        "# arch={} os={} debug_assertions={} mode={:?} threads={} seconds={} samples={} warmup={}",
        std::env::consts::ARCH,
        std::env::consts::OS,
        cfg!(debug_assertions),
        args.mode,
        args.threads,
        args.seconds,
        args.samples,
        args.warmup
    );
    println!("# 40-byte custom SHA-256, shared 20-byte suffix; all active lanes observed");
    let duration = Duration::from_secs_f64(args.seconds);
    for engine in &engines {
        engine.self_check().unwrap_or_else(|error| {
            eprintln!("FATAL: {engine}: {error}");
            std::process::exit(1);
        });
        measure(
            *engine,
            args.threads,
            Duration::from_secs_f64(args.warmup),
            args.mode,
        )
        .unwrap_or_else(|error| {
            eprintln!("FATAL: {engine}: warm-up failed: {error}");
            std::process::exit(1);
        });
    }
    println!("backend,batch_size,threads,sample,hashes_per_second");
    let mut rates = vec![Vec::new(); engines.len()];
    for sample in 0..args.samples {
        for offset in 0..engines.len() {
            // Rotate execution order to reduce systematic warm-up/thermal bias.
            let i = (offset + sample) % engines.len();
            let engine = engines[i];
            let rate = measure(engine, args.threads, duration, args.mode).unwrap_or_else(|error| {
                eprintln!("FATAL: {engine}: sample {} failed: {error}", sample + 1);
                std::process::exit(1);
            });
            rates[i].push(rate);
            println!(
                "{},{},{},{},{:.0}",
                engine.backend(),
                engine.batch_size(),
                args.threads,
                sample + 1,
                rate
            );
        }
    }
    println!("# summary: backend,batch_size,threads,median_hashes_per_second,min,max");
    for (engine, rates) in engines.iter().zip(&mut rates) {
        rates.sort_by(f64::total_cmp);
        let middle = rates.len() / 2;
        let median = if rates.len() % 2 == 0 {
            (rates[middle - 1] + rates[middle]) / 2.0
        } else {
            rates[middle]
        };
        println!(
            "# {},{},{},{:.0},{:.0},{:.0}",
            engine.backend(),
            engine.batch_size(),
            args.threads,
            median,
            rates[0],
            rates[rates.len() - 1]
        );
    }
    let selected = HashEngine::auto_for_threads(args.threads).unwrap_or_else(|error| {
        eprintln!("FATAL: startup calibration failed: {error}");
        std::process::exit(1);
    });
    println!("# startup_auto={selected}");
}

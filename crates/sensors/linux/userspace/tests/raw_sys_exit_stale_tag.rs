//! Live regression test for #694: a thread-group leader blocked in `accept()` while
//! another thread `execve()`s must not have the new image's first syscall misrouted
//! into a bogus `SocketAccept` from the stale `PENDING_SYSCALL_EXIT` tag.
//!
//! Needs real `CAP_BPF`/`CAP_PERFMON` (root) and a kernel the raw dispatcher attaches
//! on — not run by default. `sudo -E ~/.cargo/bin/cargo test -p sensor-linux --release
//! -- --ignored raw_sys_exit --nocapture`.
//!
//! `LinuxSensor` only exists for `target_os = "linux"` (`sensor-linux`'s own
//! `lib.rs`): gated the same way so `cargo test --workspace` still builds an
//! empty test binary here on Windows/macOS instead of failing to resolve it.
#![cfg(target_os = "linux")]

use std::{
    path::PathBuf,
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};

use schema::Event;
use schema::sensor::{EventSink, Sensor};

struct Collector(Arc<Mutex<Vec<Event>>>);

impl EventSink for Collector {
    fn on_event(&self, event: Event) {
        self.0.lock().unwrap().push(event);
    }
}

/// Compiles the standalone repro binary (no cargo project: a raw `extern "C" execve`
/// binding plus std, so plain `rustc` is enough) into a temp dir, once.
fn build_repro() -> PathBuf {
    let src =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/raw_sys_exit_repro.rs");
    let out = std::env::temp_dir().join("raw_sys_exit_repro_bin");
    // `rustc` bare is not reliably on PATH under `sudo` — same toolchain `cargo` itself
    // runs from, so locate it the same way: next to the running test binary's own
    // compiler, via `rustc` resolved from `RUSTC` if set, falling back to `rustc` on
    // PATH and finally the common rustup shim location.
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        let candidate = format!("{home}/.cargo/bin/rustc");
        if PathBuf::from(&candidate).exists() {
            candidate
        } else {
            "rustc".into()
        }
    });
    let status = Command::new(rustc)
        .args(["-O", "-o"])
        .arg(&out)
        .arg(&src)
        .status()
        .expect("rustc");
    assert!(status.success(), "failed to compile the repro binary");
    out
}

#[test]
#[ignore = "needs root (CAP_BPF/CAP_PERFMON) and a live kernel; see module doc"]
fn a_new_image_after_an_execve_from_a_blocked_accept_thread_produces_no_bogus_socket_accept() {
    let repro = build_repro();

    let events = Arc::new(Mutex::new(Vec::new()));
    let sink_events = Arc::clone(&events);
    std::thread::spawn(move || {
        let mut sensor = sensor_linux::LinuxSensor::new();
        if let Err(e) = sensor.run(Box::new(Collector(sink_events))) {
            eprintln!("sensor run ended: {e}");
        }
    });
    // Let the sensor finish attaching before the scenario runs.
    std::thread::sleep(Duration::from_millis(1500));

    let mut child = Command::new(&repro).spawn().expect("spawn repro");
    let pid = child.id();
    eprintln!("repro child pid={pid}");
    let status = child.wait().expect("wait repro");
    assert!(status.success(), "repro binary exited non-zero: {status:?}");

    // Give the ring buffer a moment to drain the trailing events.
    std::thread::sleep(Duration::from_millis(500));

    let seen = events.lock().unwrap();
    let bogus: Vec<&Event> = seen
        .iter()
        .filter(|e| e.meta().pid == pid && matches!(e, Event::SocketAccept(_)))
        .collect();
    assert!(
        bogus.is_empty(),
        "pid={pid} never had a real accept() return (nothing ever connected to its \
         listener) — any SocketAccept for it is the stale PENDING_SYSCALL_EXIT tag \
         misrouting the re-exec'd image's first syscall exit: {bogus:?}"
    );
}

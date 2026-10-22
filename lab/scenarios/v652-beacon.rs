// Standalone beacon for lab/validate-652.sh's scenarios B and C: a compiled binary under a
// trusted path (`/usr/libexec/v652-beacon`), run as a systemd unit's `ExecStart` so its main
// process is this binary with ppid 1 — the case `policy::service_main_path_is_trusted` is meant
// to protect, as opposed to a shell or interpreter, which it excludes on purpose (#755).
//
// No cargo project: `rustc -O` compiles this file alone, same as the scenario it replaces needed
// no build step either. Single dependency-free std binary, deliberately as dumb as the `bash -c`
// loop it replaces: attempt a TCP connect to 127.0.0.1:4444 every second, up to 90 times, same
// shape BAYES judges in the real beacon rule.

use std::net::TcpStream;
use std::thread::sleep;
use std::time::Duration;

fn main() {
    for _ in 0..90 {
        let _ = TcpStream::connect("127.0.0.1:4444");
        sleep(Duration::from_secs(1));
    }
}

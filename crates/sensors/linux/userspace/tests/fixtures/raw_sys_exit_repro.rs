// Standalone repro for #694: a thread-group leader blocked in accept() while another
// thread execve()s. Compiled directly with `rustc` (no cargo project needed) — just
// std + a raw extern "C" execve binding.
use std::env;
use std::ffi::CString;
use std::net::TcpListener;
use std::os::raw::{c_char, c_int};
use std::ptr;

unsafe extern "C" {
    fn execve(path: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> c_int;
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("post-exec") {
        // Re-exec'd process: one ordinary, returning syscall (write, via println!) that
        // #694's bug would misroute as the stale accept() return.
        println!("post-exec-marker-write");
        return;
    }

    let exe = env::current_exe().expect("current_exe");
    let t2 = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(300));
        let path = CString::new(exe.to_str().unwrap()).unwrap();
        let arg0 = path.clone();
        let arg1 = CString::new("post-exec").unwrap();
        let argv: [*const c_char; 3] = [arg0.as_ptr(), arg1.as_ptr(), ptr::null()];
        let envp: [*const c_char; 1] = [ptr::null()];
        unsafe {
            execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
        }
        eprintln!("execve failed: {}", std::io::Error::last_os_error());
        std::process::exit(1);
    });

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    eprintln!("repro: leader thread blocking in accept() on {:?}", listener.local_addr());
    let _ = listener.accept(); // blocks; this thread is killed by thread 2's successful execve

    // Unreachable on the success path (this thread dies on exec).
    t2.join().unwrap();
}

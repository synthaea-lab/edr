# lab/provisioning — Provider-Neutral VM Setup

Provisioning scripts shared by every virtualization harness. A harness (Vagrant,
Hyper-V, Proxmox, cloud instances, ...) is only responsible for creating a machine and
running these scripts in it — the toolchain and lab setup live here, once.

| Script | Purpose |
| --- | --- |
| `linux-toolchain.sh` | Per-family toolchain (apt / dnf+CRB, rustup stable+nightly, bpf-linker, bindgen-cli, aya-tool), with the LLVM-major alignment the eBPF build needs |
| `windows-toolchain.ps1` | Rust toolchain (rustup, stable-msvc) + Visual Studio Build Tools (MSVC linker + Windows SDK) for the ETW/Event Log/SCM sensors — see #22 |
| `agent-install.ps1` | Installs an already-built agent + watchdog (+ rules/sigma, rules/yara content, installed under the agent's `storage.state_dir\content`, see `-StateDir`) into a Windows lab VM for scenario runs, optionally registering the watchdog service — see #22 |
| `agent-install.sh` (planned) | Linux equivalent, for a replay-only machine (`fedora-41`/`rocky-9` in ../MATRIX.md) that receives a binary built elsewhere instead of building itself |

Scripts take no harness-specific assumptions: plain bash/PowerShell, idempotent,
runnable over ssh/winrm/cloud-init user data.

## Windows toolchain vs. Linux toolchain

Unlike eBPF, the Windows sensors (`sensor-windows`/ETW via `ferrisetw`,
`sensor-windows-eventlog`, and `watchdog`'s SCM integration via `windows-service`) are
pure-Rust FFI bindings against DLLs Windows already ships — no LLVM-version alignment
dance. The one thing Rust itself doesn't provide on Windows is the MSVC linker and
Windows SDK import libraries, which `windows-toolchain.ps1` gets from a Visual Studio
Build Tools install (the C++ workload). No nightly toolchain is needed on Windows —
that's a Linux/aya-only requirement.

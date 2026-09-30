# lab/vagrant — Vagrant Harness (QEMU / Apple Silicon)

One of possibly several virtualization harnesses for the lab (see `../README.md`).
Implements the machine matrix from `../MATRIX.md`; each VM runs the shared
provisioning from `../provisioning/`. For Windows hosts running Hyper-V, see
`../vagrant-hyperv/`.

## Host setup (macOS / Apple Silicon)

- **QEMU**: `brew install qemu`
- **Vagrant** + the QEMU provider plugin: `vagrant plugin install vagrant-qemu`
- Windows boxes are **amd64** (VirtualBox / Hyper-V): unusable under QEMU on Apple
  Silicon — run them on an x86 host instead (see below).

## Host setup (Windows / x86, VirtualBox) — Alpine row only

The `alpine319` machine is amd64, same as the Windows boxes — unusable under QEMU
on Apple Silicon. Unlike them it's a Linux guest, so it doesn't need
`../vagrant-hyperv/`'s Hyper-V provider either: it runs directly on VirtualBox,
which a Windows lab machine already needs for other work.

- **VirtualBox** (any recent 7.x) + **Vagrant**: `winget install Hashicorp.Vagrant`
- Neither installer adds itself to `PATH` reliably on Windows — open a fresh shell
  (or add `C:\Program Files\Vagrant\bin` yourself) before the commands below.

```
cd lab\vagrant
vagrant up alpine319 --provider virtualbox
vagrant ssh alpine319
vagrant destroy -f alpine319   # rollback = destroy + up
```

`generic/alpine319` (3.19/6.6) is the newest Alpine Vagrant Cloud publishes with a
virtualbox/amd64 provider — not the 3.24/6.18 `../MATRIX.md` and issue #123 were
manually validated against, but this row exists to prove musl/BusyBox toolchain
portability, not kernel-version drift (that's the `arch` row's job). Provisioning
is `../provisioning/alpine-toolchain.sh`; verified end to end on this box — build,
`agent status` (5/5 eBPF programs accepted by the verifier), and the full
`lab/scenarios/beacon.sh` walking-skeleton (T1071/T1041 alert fires as expected).

## Usage (Linux machines)

```bash
cd lab/vagrant
vagrant up                 # primary machine (ubuntu2404) only
vagrant up debian13        # any machine from the matrix
vagrant ssh ubuntu2404
vagrant status
vagrant rsync ubuntu2404   # re-push the repo after host-side changes
```

Each Linux machine has a dedicated host SSH port (50022, 50122, …) — the QEMU plugin
does not auto-allocate, and distinct ports let several machines run in parallel.

The repository root is rsynced one-way into each VM at `/synthaea` (excluding `.git/`,
`target/`, `old/`, ML venv/datasets). Build inside the VM:

```bash
vagrant ssh ubuntu2404 -c 'cd /synthaea && cargo build --release -p agent'
```

Provisioning installs the family packages, rustup (stable + nightly + rust-src),
bpf-linker (with the LLVM-major alignment), bindgen-cli, and aya-tool — see
`../provisioning/linux-toolchain.sh`. On `fedora41`/`rocky9` no recent-enough LLVM is
available: provisioning continues with a warning and those VMs are replay-only.

## Usage (Windows machines, #22)

Requires an x86 host with VirtualBox or Hyper-V (`autostart: false` — bring one up
explicitly):

```bash
cd lab/vagrant
vagrant up win11
vagrant provision win11      # re-run windows-toolchain.ps1 (idempotent)
```

Provisioning (`../provisioning/windows-toolchain.ps1`) installs rustup (stable-msvc)
and, if not already present, Visual Studio Build Tools with the C++ workload and the
Windows 11 SDK — the MSVC linker and import libraries the ETW/Event Log/SCM sensors
link against. No nightly toolchain and no LLVM-alignment step: `windows-sys`,
`ferrisetw`, and `windows-service` are pure-Rust bindings against DLLs Windows already
ships.

There is no rsync-equivalent synced folder wired up for winrm yet — get the source
onto the VM (winrm file copy, a shared drive, or building on one machine and shipping
the binary to the others), then:

```powershell
cargo build --release -p agent -p watchdog
```

To stage a build (from this VM or another) for a scenario run without rebuilding —
useful once one Windows machine has built and the others just need to run —
`../provisioning/agent-install.ps1` copies the binaries (+ `rules/sigma`,
`rules/yara` if present, under `-StateDir` (default `C:\ProgramData\Synthaea\state`, which must match `storage.state_dir` in `agent.toml`) as `content\rules\...`) into place and can optionally register the watchdog service:

```powershell
.\agent-install.ps1 -SourceDir target\release -InstallService
```

### Operator notes (real-machine validation, #223)

A few things that only show up running this on an actual Windows box, not on
static review — found end to end on a vanilla Windows 11 VM:

- **Execution policy.** Windows 11 defaults to `Restricted`, so
  `windows-toolchain.ps1` refuses to run at all (`UnauthorizedAccess:
  PSSecurityException`). Either invoke it with the policy bypassed for that
  one process:
  ```powershell
  powershell -ExecutionPolicy Bypass -File windows-toolchain.ps1
  ```
  or, in an already-open session:
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
  ```
- **Capturing the output to a log file** — don't pipe through `Tee-Object`
  (`.\windows-toolchain.ps1 *>&1 | Tee-Object -FilePath log.txt`). The
  script's `$ErrorActionPreference = 'Stop'` treats `rustup-init`'s routine
  stderr warning (`installing msvc toolchain without its prerequisites`) as
  fatal and aborts the run - not a real failure, just how PowerShell handles
  stderr under redirection. `Start-Transcript` doesn't redirect stderr, so
  it captures the same output without that side effect:
  ```powershell
  Start-Transcript -Path log.txt
  .\windows-toolchain.ps1
  Stop-Transcript
  ```
- **A second Rust toolchain gets installed on the first build.** This script
  always installs `stable-msvc`, but the repo pins a specific version at the
  root via `rust-toolchain.toml`. The first `cargo build` after provisioning
  makes rustup silently fetch and install that pinned version too (~150MB,
  ~2 extra minutes) - expected rustup behavior given the two don't
  necessarily match, not a bug in this script, but worth knowing before it
  looks like the build is doing something unexpected.

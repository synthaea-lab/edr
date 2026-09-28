# RUNBOOK — PR #155 validation (issue #152 argv + #53 lineage non-regression)

Runs the Debian-family x86_64 rows of `../MATRIX.md` on this Hyper-V harness:
`ubuntu2204` (5.15 — strictest verifier) and `debian12` (6.1). One VM at a time
on a 16 GB host. The 6.8 / 6.12 rows have no ready Hyper-V box — see
[README.md](README.md) "Missing boxes".

All `vagrant` commands run from an **elevated PowerShell** in this directory.

---

## 0. Once per host

```powershell
cd lab\vagrant-hyperv
.\bootstrap.ps1            # Hyper-V feature + admin group + Vagrant + Default Switch
. .\helpers.ps1           # dot-source the vprep/vup/vssh/... shortcuts
```

`helpers.ps1` is re-dot-sourced every session; `bootstrap.ps1` is one-time.

---

## 1. Full cycle for one machine

Replace `MACHINE` with `ubuntu2204` **or** `debian12`.

```powershell
. .\helpers.ps1
vprep                                  # wsl --shutdown + rsync check + free-RAM warning
vup MACHINE                            # ~5 min: boot + provisioning (rust + bpf-linker); answer "1" at the switch prompt

# DNS on the Default Switch is flaky. Ubuntu has the systemd-resolved 127.0.0.53
# stub; on the generic/debian12 box /etc/resolv.conf is sometimes absent entirely.
# Drop any symlink and pin public resolvers — works on both:
vssh MACHINE 'test -L /etc/resolv.conf && sudo rm -f /etc/resolv.conf; printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" | sudo tee /etc/resolv.conf >/dev/null'
vssh MACHINE 'getent hosts static.rust-lang.org >/dev/null && echo "DNS ok"'

# the repo is already at /synthaea (rsynced at boot); run the validator in place.
# first run on a fresh VM is a cold build — several minutes, no output until done.
vssh MACHINE 'bash /synthaea/lab/validate-155.sh'
```

Expected tail: `[PASS] kernel <x> — argv (#152/#155) + lineage (#53)`.

```powershell
vhalt MACHINE            # or `vagrant destroy -f MACHINE` to free the disk too
```

Then repeat block **1** with the other `MACHINE`.

---

## 2. After a host-side code change

`vup` rsyncs once at boot; to re-push without destroying the VM:

```powershell
vsync MACHINE
vssh MACHINE 'bash /synthaea/lab/validate-155.sh'
```

Uncommitted host changes are included — `vsync` sends the working tree, not `HEAD`.

---

## 3. Manual debugging (validator failed, want to watch it live)

```powershell
# toolchain sanity in one shot
vssh MACHINE 'bash /synthaea/lab/diag.sh'

# lint gate (same checks as CI, without spending the CI budget)
vssh MACHINE 'bash /synthaea/lab/lint.sh'

# eBPF probe build alone, full output
vssh MACHINE 'cd /synthaea && cargo build --release -p sensor-linux 2>&1 | tail -40'

# DNS / NAT
vssh MACHINE 'ping -c2 static.crates.io; resolvectl status'
```

If the Default Switch NAT is dead (build can't resolve `static.crates.io`),
from an elevated host PowerShell:

```powershell
Get-NetAdapter 'vEthernet (Default Switch)' | Restart-NetAdapter
Restart-Service hns
# and drop any host VPN (WireGuard/OpenVPN) for the duration of the lab
```

Classic eBPF build failures (see `../provisioning/linux-toolchain.sh`):

| Symptom | Fix |
| --- | --- |
| `built without embedded eBPF probes` — bpf-linker missing (download failed at provisioning, script continued with `[warn]`) | `vagrant provision MACHINE` (retries 3x now, and busts the stale build) |
| `rust-src` missing from the probe toolchain | `vssh MACHINE 'rustup component add rust-src --toolchain "$(cat /synthaea/ebpf-toolchain.txt)"'` |
| `Unknown attribute kind … Producer LLVM NN … Reader LLVM MM` | bump `BPF_LINKER_VERSION` in the provisioner, or pin an older nightly in `ebpf-toolchain.txt` |

---

## 4. Known traps

- **`vagrant ssh -c "…"` mangles complex snippets.** PowerShell's native-arg
  parser breaks embedded quotes / `$(...)` / leading-dash tokens before vagrant
  sees them. `helpers.ps1` routes every remote command through `Invoke-LabRemote`
  (base64 in, `base64 -d | bash` in the guest) — use `vssh`, not a raw
  `vagrant ssh -c`.
- **CRLF.** Handled by `/.gitattributes` (`*.sh eol=lf`) — scripts reach the VM
  as LF. If you add a `.sh` on a machine with a broken git config, check
  `file lab/…/x.sh` before blaming the sensor.
- **Truncated scenario console.** PowerShell drops interleaved stdout; trust the
  `grep` on the `--alerts` / `--events` files, not the screen. `validate-155.sh`
  already asserts on the files.
- **Pre-created `--alerts` / `--events` files** owned by a non-root host user →
  the agent's `open()` fails with EACCES. Let the agent (root) create them.
- **RAM.** VMs use Dynamic Memory (1 GB startup, 4 GB ceiling). `vhalt` the
  finished machine and `wsl --shutdown` before starting the next.

---

## 5. 6.8 / 6.12 — no ready Hyper-V box

`ubuntu2404` (6.8) and `debian13` (6.12): neither `generic/*` nor `bento/*`
ships a Hyper-V box. Options (see [README.md](README.md) "Missing boxes"):

- add `"ubuntu2404" => { box: "boxen/ubuntu-24.04" }` to `LINUX_MACHINES` in
  the [Vagrantfile](Vagrantfile) (third-party box, low download count — your call);
- build one from the official cloud image (`qemu-img convert -O vhdx` + a
  `vagrant` user + the insecure key + `vagrant box add`) — ~an evening;
- or delegate those two rows to the arm64 `../vagrant` harness.

5.15 is the strictest verifier of the four, so `ubuntu2204` + `debian12` catch
most kernel-portability regressions on their own.

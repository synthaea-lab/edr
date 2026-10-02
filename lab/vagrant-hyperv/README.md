# lab/vagrant-hyperv — Hyper-V Harness

One of the lab's virtualization harnesses (see `../README.md`). Sibling of
`../vagrant` (QEMU on Apple Silicon) for **Windows hosts with Hyper-V**. Same
machine matrix (`../MATRIX.md`), same provisioning
(`../provisioning/linux-toolchain.sh`).

Scope: the **Debian-family x86_64** rows. The `aarch64` dimension where issue #53
was originally found needs an arm64 host (the `../vagrant` harness).

| Machine | Kernel | Proves | Box |
| --- | --- | --- | --- |
| `ubuntu2204` (primary) | 5.15 | oldest supported LTS — strictest verifier | `generic/ubuntu2204` |
| `debian12` | 6.1 | Debian stable | `generic/debian12` |
| `ubuntu2404` | 6.8 | current Ubuntu LTS | `jtarpley/ubuntu2404_base` — see [Community boxes](#community-boxes-68--612) |
| `debian13` | 6.12 | Debian trixie | `shekeriev/debian-13` — see [Community boxes](#community-boxes-68--612) |
| `fedora41` | 6.11 GA / 6.17 updated | RPM family, SELinux enforcing | `jtarpley/fedora41_base` — see [`fedora41`](#fedora41--jtarpleyfedora41_base-40-gb-lvm) |

## Host setup — once, ELEVATED PowerShell

```powershell
cd lab\vagrant-hyperv
.\bootstrap.ps1
```

Enables Hyper-V (may need a reboot — re-run after), adds you to *Hyper-V
Administrators* (log out/in once), installs Vagrant, checks the Default Switch.

The Hyper-V provider **requires an elevated shell** for every `vagrant` command
that touches a VM (`up`, `halt`, `ssh`, `destroy`, `rsync`).

## Usage

```powershell
$env:VAGRANT_HYPERV_SWITCH = "Default Switch"   # skip the interactive switch prompt
vagrant up ubuntu2204 --provider hyperv          # ~5 min boot + provisioning
vagrant rsync ubuntu2204                          # re-push the repo after host-side edits
vagrant ssh ubuntu2204
vagrant destroy -f ubuntu2204                     # rollback = destroy + up
```

The repo root is rsynced one-way to `/synthaea` (needs an `rsync` on the host —
Git for Windows ships one at `C:\Program Files\Git\usr\bin\rsync.exe`, or
`winget install cwRsync`). RAM: the boxes use Hyper-V Dynamic Memory, 2 GB
startup up to 4 GB — bring one machine up at a time, and `wsl --shutdown` first
(`helpers.ps1` `vprep` does this). If `vagrant up` still dies with `0x800705AA`
("Ressources système insuffisantes" / cannot allocate RAM), the host has under
~2.5 GB free — close a browser/IDE and retry.

Don't count on the balloon for the build: these guests report a memory demand
well below what they use, so Hyper-V often leaves them at the startup amount
while they swap, even with GBs free on the host. The `build-host-setup`
provisioner (inline in the `Vagrantfile`) covers that on every box: a 4 GB
swapfile, `vm.swappiness = 60` and `CARGO_BUILD_JOBS=2`. Before it, rustc was
OOM-killed at 1 GB on both `ubuntu2404` and `debian13`.

## Build + test in the VM

```powershell
vagrant ssh ubuntu2204 -c 'cd /synthaea && source ~/.cargo/env && cargo build --release -p agent'
vagrant ssh ubuntu2204 -c 'cd /synthaea && sudo ./target/release/agent status'   # verifier check, every program in TRACEPOINTS
# scenario: agent in one shell, scenario in another
vagrant ssh ubuntu2204 -c 'cd /synthaea && sudo env RUST_LOG=sensor_linux=info ./target/release/agent run --alerts /tmp/a --events /tmp/e &  sleep 4;  bash lab/scenarios/beacon.sh;  sleep 2;  sudo pkill -f "agent run";  grep T1071 /tmp/a'
```

The agent refuses to start without `/etc/synthaea/agent.toml` (ADR-0013). On a
fresh VM install the committed template first:
`sudo install -D -m 0644 crates/config/data/default-agent.toml /etc/synthaea/agent.toml`
(or `cli config init` once #417 is merged).

Let the agent create the `--alerts` / `--events` files (a host-user-owned
pre-created file makes its `open()` fail with EACCES). Use `sudo env VAR=...`,
not `sudo VAR=... cmd` — the default sudoers env policy drops the latter.

## Community boxes (6.8 / 6.12)

`generic/*` stops at 5.15/6.1 and `bento/*` dropped Hyper-V, so the 6.8 and 6.12
rows use community boxes that ship a Hyper-V provider. Both were validated on
2026-09-24 (26/26 programs through the verifier, `argv.sh` + `lineage.sh` —
see #415/#416). Neither is turnkey. The fixes below are the exact ones used,
applied over `vagrant ssh` after the first `up`.

**Tip — no elevation needed after `up`.** Only `up`/`halt`/`destroy` need the
elevated shell. Once a VM runs, plain SSH with the key Vagrant generated works
from any shell:
`ssh -i .vagrant/machines/<machine>/hyperv/private_key vagrant@<ip>`, where
`<ip>` comes from `(Get-VM synthaea-<machine> | Get-VMNetworkAdapter).IPAddresses`
(see the `ubuntu2404` note below for when that comes back empty).

### `ubuntu2404` — `jtarpley/ubuntu2404_base` (40 GB disk, LVM)

1. **It boots the Azure kernel (6.17), not 6.8.** `uname -r` shows
   `6.17.x-azure`, so without this fix the run validates the wrong row. Pin the
   generic 6.8 kernel (already installed) and reboot:

   ```bash
   C=$(sudo cat /boot/grub/grub.cfg)
   E=$(echo "$C" | awk -F"'" "/menuentry .*6.8.0-[0-9]*-generic'/ && !/recovery/ {print \$2; exit}")
   S=$(echo "$C" | awk -F"'" '/submenu /{print $2; exit}')
   sudo sed -i 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT=saved/' /etc/default/grub
   sudo update-grub && sudo grub-set-default "$S>$E" && sudo systemctl reboot
   ```

   Under the generic kernel, Hyper-V no longer reports the guest IP (the KVP
   daemon came with the Azure kernel). Find it from the MAC instead:
   `Get-NetNeighbor -LinkLayerAddress (Get-VM synthaea-ubuntu2404 | Get-VMNetworkAdapter).MacAddress`
   (format the MAC as `00-15-5d-…`).
2. **`/home` is a 1 GB LVM volume and swap takes 8 GB**, so rustup
   (`~/.rustup`) fills `/home` during provisioning (`No space left on device`).
   Reclaim the swap:

   ```bash
   sudo swapoff /dev/vg_ubuntu/swap && sudo lvreduce -f -y -L 1G /dev/vg_ubuntu/swap
   sudo mkswap /dev/vg_ubuntu/swap && sudo swapon -a
   sudo lvextend -r -L +4G /dev/vg_ubuntu/home
   sudo lvextend -r -l +100%FREE /dev/vg_ubuntu/root
   ```

3. **`vm.swappiness = 0` in `/etc/sysctl.conf`.** With ~1 GB of RAM the
   release build's LTO step gets OOM-killed (`signal: 9`) while swap sits
   unused. The `build-host-setup` provisioner now resets it to 60. It also adds
   the 4 GB swapfile, but only when `/` has 8 GB free, which this box has only
   after step 2. Once step 2 is done, re-run it:
   `vagrant provision ubuntu2404 --provision-with build-host-setup`.
4. Then re-run the provisioning (`bash /synthaea/lab/provisioning/linux-toolchain.sh`)
   if the first `up` died on the disk, and check that `bpf-linker --version`
   works. Otherwise `sensor-linux` builds **without** embedded probes and
   `agent status` fails with "built without embedded eBPF probes".

### `debian13` — `shekeriev/debian-13` (32 GB disk, single partition)

Disk is fine as shipped. The 1.7 GB of swap is not enough on its own, but the
`build-host-setup` provisioner adds a 4 GB swapfile. What's missing:

- **No `rsync` in the guest**, so `/synthaea` never gets populated. Either
  `sudo apt-get install -y rsync` then `vagrant rsync debian13`, or stream the
  tree over SSH:
  `git archive HEAD | ssh … 'sudo mkdir -p /synthaea && sudo chown vagrant: /synthaea && tar -xf - -C /synthaea'`.
- Provisioning therefore never ran either. Run it by hand:
  `bash /synthaea/lab/provisioning/linux-toolchain.sh`.
- No `sysctl` binary (`procps` not installed). Read `/proc/sys/vm/*` directly
  if needed.

### `fedora41` — `jtarpley/fedora41_base` (40 GB LVM)

Validated 2026-09-30: builds natively (Fedora ships clang/LLVM 19, `linux-toolchain.sh`
fetches the prebuilt `bpf-linker`), 51/51 programs pass the verifier, `lineage.sh`
3/3 and `argv.sh` fire, with SELinux **Enforcing**. That run was started from an SSH
shell, i.e. in an unconfined domain, so it says nothing about the SELinux policy; the
packaged service is what exercises it (below). What to know:

- **The kernel is not 6.11.** The box is already updated (`6.17.7-100.fc41`); it
  uses the `__data_loc` `sched_process_fork` layout, like Alpine 6.18. `uname -r`
  after `up` says which row you are validating.
- **The disk is many small logical volumes**: `/` has ~6 GB free after the LLVM
  packages, `/home` under 1 GB (rustup dies with "No space left on device"), `/var`
  ~9 GB. The `prep` provisioner (`FEDORA_PREP` in the `Vagrantfile`) links
  `~/.cargo` and `~/.rustup` into `/var/synthaea` and sets `CARGO_TARGET_DIR` there.
  A release build of the agent (~7.5 min at 2 vCPU-equivalent) fits in the ~9 GB;
  it leaves ~4 GB.
- Run the scenarios against `$CARGO_TARGET_DIR/release/agent`
  (`/var/synthaea/target/release/agent`), not `target/release/agent`.
- **Where SELinux denials are.** `auditd` is not running on this box, so
  `ausearch` reads a missing `/var/log/audit/audit.log` and always answers "no
  matches" (an earlier "0 AVC" claim measured with it was wrong). Denials are in the
  journal: `sudo journalctl _TRANSPORT=audit | grep AVC`.
- **The packaged systemd unit does not start the agent on this row.** Installing the
  files the way `synthaea-agent.spec.template` does and starting the real unit under
  Enforcing, four defects stack, each hiding the next:
  1. `ExecStartPre` tries `ln -sf ... /usr/bin/synthaea-ctl` under `ProtectSystem=strict`
     (read-only `/usr`): `Read-only file system`, the unit never starts. The `.deb`
     `postinst` creates that link, the RPM spec does not.
  2. The binaries under `/var/lib/synthaea` are labelled `var_lib_t`; `init_t` is
     denied `execute`, `execute_no_trans` and `map` on them (`status=203/EXEC`,
     `Permission denied`). `chcon -R -t bin_t /var/lib/synthaea/bootstrap` fixes it
     (the service then runs as `unconfined_service_t`, no denial). A real fix labels
     it with `semanage fcontext` so `restorecon` and the updater's `versions/vN` agree.
  3. The unit runs the agent as the unprivileged `synthaea` user with
     `NoNewPrivileges` and no `AmbientCapabilities`, so it cannot load eBPF, falls back
     to the audit socket, gets `EPERM` (`audit socket open: netlink socket error: 1`)
     and exits 1. With `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE` and
     `CAP_DAC_READ_SEARCH` ambient, the eBPF sensor and the BPF-LSM hook attach
     (conntrack still needs `CAP_NET_ADMIN`).
  4. The watchdog starts the agent with `--alerts` only and forces its working
     directory to the binary's folder (`/var/lib/synthaea/bootstrap`, root-owned), so
     the agent's default relative `events.jsonl` fails with `Permission denied`; its
     output goes to `/var/tmp/synthaea-agent.log`, which `PrivateTmp=true` hides from
     the host (`nsenter -t <watchdog pid> -m -- cat /var/tmp/synthaea-agent.log`).
  Defect 1 is RPM-specific and 2 is SELinux-specific; 3 and 4 come from the unit and
  the watchdog, not from the distro, so they should hit the `.deb` too (not tested here).

### Check the tracepoint layout on every new row

`sched_process_fork`'s record layout differs across kernels (#415). 5.15, 6.1,
6.8 and 6.12 all use the inline `char[16]` comm, and Alpine 6.18 and Fedora 6.17 use
`__data_loc`. Since #416 the agent reads it from tracefs at load, but a new row
should still record it:
`sudo cat /sys/kernel/tracing/events/sched/sched_process_fork/format`.

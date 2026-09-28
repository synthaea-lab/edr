# lab/driver — minifilter test-signing workflow (ADR-0012)

Scripts for the driver's lab loop: one test-signing VirtualBox VM per
developer, separate from the demo VM, never the host (ADR-0012 Acceptance).
VirtualBox rather than Hyper-V because some team hosts run Windows 11 Home.
VMware Workstation works too: skip `new-driver-vm.ps1`, turn Secure Boot off in
the VM settings (Options > Advanced), share the repository with the guest, and pass
`-Vmx <path to the .vmx>` to `snapshot-driver-vm.ps1`. The guest scripts accept
either hypervisor and find the certificate and package next to themselves, so
run them from the shared folder (`\\vmware-host\Shared Folders\<share>\lab\driver\...`).

| Script | Runs on | Does |
| --- | --- | --- |
| `new-test-cert.ps1` | host | Creates (or reuses) your self-signed code-signing certificate in `CurrentUser\My`; exports the public part to `target\driver\cert\` |
| `new-driver-vm.ps1` | host | Creates the VM: Windows 11, EFI, TPM 2.0, Secure Boot off, COM1 on `\\.\pipe\<vm>-kd`, repo shared read-only as `\\VBoxSvr\synthaea`, unattended install with Guest Additions |
| `prepare-driver-vm.ps1` | guest, elevated, once | Trusts the certificate, `testsigning on`, kernel debugging on COM1, DbgPrint visible, kernel dump kept, optional Driver Verifier |
| `snapshot-driver-vm.ps1` | host | `-Take <label>` (live, timestamped), `-Restore <label>` (latest match), `-List` |
| `sign-driver.ps1` | host | Copies the built `.sys`/`.inf` to `target\driver\package`, signs the `.sys`, builds and signs the catalog when the WDK's `inf2cat` is there |
| `driver-load-unload.ps1` | guest, elevated | Milestone 1 check, replayed at the demo: install from the INF, `fltmc load`, listed, `fltmc unload`, gone |

## Once

```powershell
# host
.\lab\driver\new-test-cert.ps1
.\lab\driver\new-driver-vm.ps1 -IsoPath $env:USERPROFILE\Downloads\Win11_25H2_French_x64_v2.iso -BaseFolder E:\VMs
# guest (elevated), after the unattended install finishes
powershell -ExecutionPolicy Bypass -File \\VBoxSvr\synthaea\lab\driver\prepare-driver-vm.ps1
Restart-Computer
# host
.\lab\driver\snapshot-driver-vm.ps1 -Take clean
```

## Each driver build

```powershell
# host
.\lab\driver\sign-driver.ps1 -DriverDir <build output with the .sys and .inf>
.\lab\driver\snapshot-driver-vm.ps1 -Take pre-load
# guest (elevated)
powershell -ExecutionPolicy Bypass -File \\VBoxSvr\synthaea\lab\driver\driver-load-unload.ps1
# host, if the guest bluescreened or the filter wedged
.\lab\driver\snapshot-driver-vm.ps1 -Restore pre-load
```

Kernel debugger from the host: `windbg -k com:pipe,port=\\.\pipe\<vm>-kd,resets=0,reconnect`.
A bugcheck leaves `%SystemRoot%\MEMORY.DMP` in the guest (no auto-reboot).

The test certificate only works where it is trusted **and** test-signing is
on. Production signing (attestation, ELAM/PPL) is MVI-gated and out of scope
here (ADR-0012, #39).

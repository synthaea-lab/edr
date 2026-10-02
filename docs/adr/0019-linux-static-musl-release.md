# ADR-0019: Ship the Linux agent as a static musl binary

- **Status**: accepted
- **Date**: 2026-09-30

## Context

The prebuilt ONNX Runtime archive selected by `ml/dynamic-onnx` requires glibc
2.38 and libstdc++ from GCC 13. The agent therefore fails to link or load on
Ubuntu 22.04, Debian 12, and Rocky 9, which are in the Linux lab matrix (#456).
Building ONNX Runtime from source on the oldest glibc host would still need a
newer C++ toolchain. The Alpine lab has already produced a static musl agent
with source-built ONNX Runtime that runs in all three distributions' userlands.

## Decision

Build the x86-64 Linux `agent`, `watchdog`, and `cli` on Alpine as static musl
executables. Production builds disable the development `dynamic-onnx` feature
and link ONNX Runtime from the source-built static archives, preserving ADR-0002.
The `.deb` and `.rpm` packaging steps consume these exact binaries; they do not
rebuild Rust code on the packaging host. Packaging rejects ELF files with a
program interpreter or a shared-library dependency, and verifies the binaries
inside the resulting package. Release builds also require embedded eBPF probes.

## Consequences

- One set of x86-64 binaries can be packaged for the supported glibc
  distributions without inheriting the build host's glibc or libstdc++ floor.
- Alpine and source-built ONNX Runtime become release build dependencies. The
  build is slower and needs a controlled, reproducible toolchain.
- musl hostname lookup does not use glibc NSS modules. Endpoint enrollment
  with nonstandard NSS-only names needs an explicit lab check.
- Container userland checks do not prove kernel compatibility. Ubuntu 22.04
  on kernel 5.15 and Rocky 9 on kernel 5.14 still require real-kernel smoke
  tests, including eBPF attachment, event flow, and ML scoring, before #456
  can close.

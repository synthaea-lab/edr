#!/usr/bin/env bash
# Build the three Linux release binaries on Alpine against source-built ONNX Runtime.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "commit tracked changes before building release binaries" >&2
    exit 1
fi

if [ "$(uname -m)" != x86_64 ] || ! grep -q '^ID=alpine$' /etc/os-release; then
    echo "build-musl.sh must run on x86-64 Alpine (the validated musl build host)" >&2
    exit 1
fi
: "${ORT_LIB_LOCATION:?build ONNX Runtime on Alpine and set ORT_LIB_LOCATION first}"
if [ ! -d "$ORT_LIB_LOCATION" ]; then
    echo "ORT_LIB_LOCATION does not exist: $ORT_LIB_LOCATION" >&2
    exit 1
fi
for tool in cargo rustup bpf-linker readelf; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing build tool: $tool" >&2
        exit 1
    }
done

target=x86_64-unknown-linux-musl
if ! rustup target list --installed | grep -qx "$target"; then
    echo "install the Rust target first: rustup target add $target" >&2
    exit 1
fi

# The ort-sys static library list omits libraries produced by ONNX Runtime.
eval "$(./lab/provisioning/ort-static-link-flags.sh)"
cargo test -p ml --release --target "$target" --no-default-features
cargo build --release --target "$target" --no-default-features \
    -p agent -p watchdog -p cli

binary_dir="$REPO_ROOT/target/$target/release"
./packaging/linux/check-static-elf.sh \
    "$binary_dir/agent" "$binary_dir/watchdog" "$binary_dir/cli"
for name in agent watchdog cli; do
    "$binary_dir/$name" --help >/dev/null
done

# sensor-linux silently builds a probe-less variant when bpf-linker is absent.
# A release artifact must contain the probes, including the uprobe sensor.
for crate in sensor-linux sensor-linux-uprobes; do
    probe=$(find "$binary_dir/build" -path "*/${crate}-*/out/sensor-linux-ebpf" \
        -type f -print -quit)
    if [ -z "$probe" ]; then
        echo "missing embedded eBPF probe from $crate build" >&2
        exit 1
    fi
done

git rev-parse HEAD > "$binary_dir/synthaea-source-revision"
echo "Release binaries ready in $binary_dir"

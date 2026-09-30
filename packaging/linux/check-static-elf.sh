#!/usr/bin/env bash
# Refuse Linux release artifacts that would need the build host's glibc or libstdc++.
set -euo pipefail

export LC_ALL=C

if [ "$#" -eq 0 ]; then
    echo "usage: $0 ELF_BINARY [...]" >&2
    exit 2
fi

command -v readelf >/dev/null 2>&1 || {
    echo "readelf is required to check release binaries" >&2
    exit 2
}

for binary in "$@"; do
    if [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
        echo "missing executable: $binary" >&2
        exit 1
    fi
    header=$(readelf -h "$binary") || {
        echo "not an ELF binary: $binary" >&2
        exit 1
    }
    if ! grep -q 'Machine:.*Advanced Micro Devices X86-64' <<< "$header"; then
        echo "not an x86-64 ELF binary: $binary" >&2
        exit 1
    fi
    if readelf -l "$binary" | grep -q 'INTERP'; then
        echo "binary has a runtime loader (PT_INTERP): $binary" >&2
        exit 1
    fi
    if readelf -d "$binary" | grep -q '(NEEDED)'; then
        echo "binary has shared-library dependencies (DT_NEEDED): $binary" >&2
        exit 1
    fi
    echo "static x86-64 ELF: $binary"
done

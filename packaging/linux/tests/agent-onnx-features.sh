#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

target=x86_64-unknown-linux-musl
release_features=$(cargo tree -p agent --no-default-features -e features \
    -i ort --target "$target")
if grep -Fq 'ort feature "download-binaries"' <<< "$release_features"; then
    echo "release agent still downloads a prebuilt ONNX Runtime" >&2
    exit 1
fi

dev_features=$(cargo tree -p agent -e features -i ort --target "$target")
if ! grep -Fq 'ort feature "download-binaries"' <<< "$dev_features"; then
    echo "development agent lost its default ONNX Runtime setup" >&2
    exit 1
fi

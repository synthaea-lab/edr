#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
checker="$REPO_ROOT/packaging/linux/check-static-elf.sh"
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT

printf 'int main(void) { return 0; }\n' > "$stage/main.c"
printf '#include <stdio.h>\nvoid call_libc(void) { puts("linked"); }\n' > "$stage/shared.c"
cc "$stage/main.c" -o "$stage/dynamic"
cc -static "$stage/main.c" -o "$stage/static"
cc -static-pie "$stage/main.c" -o "$stage/static-pie"
cc -shared -fPIC "$stage/shared.c" -o "$stage/shared"
chmod +x "$stage/shared"

bash "$checker" "$stage/static"
bash "$checker" "$stage/static-pie"
if bash "$checker" "$stage/dynamic"; then
    echo "dynamic executable passed the release guard" >&2
    exit 1
fi
if bash "$checker" "$stage/shared"; then
    echo "shared-library dependency passed the release guard" >&2
    exit 1
fi
if bash "$checker" "$stage/missing"; then
    echo "missing executable passed the release guard" >&2
    exit 1
fi

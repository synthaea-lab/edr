#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

echo "==> Packaging static musl Synthaea binaries as a .deb"
command -v dpkg-deb >/dev/null 2>&1 || {
    echo "dpkg-deb is required to inspect the package payload" >&2
    exit 1
}

target=x86_64-unknown-linux-musl
binary_dir="$REPO_ROOT/target/$target/release"
if [ ! -f "$binary_dir/synthaea-source-revision" ] || \
    [ "$(cat "$binary_dir/synthaea-source-revision")" != "$(git rev-parse HEAD)" ]; then
    echo "musl binaries were not built from this source revision" >&2
    exit 1
fi
./packaging/linux/check-static-elf.sh \
    "$binary_dir/agent" "$binary_dir/watchdog" "$binary_dir/cli"

# Install cargo-deb if needed
if ! command -v cargo-deb &> /dev/null; then
    echo "cargo-deb not found. Installing..."
    cargo install cargo-deb --locked
fi

# cargo-deb translates the target/release asset prefix in watchdog/Cargo.toml
# to the musl target directory when --target is specified.
version=$(awk -F '"' '/^version = / { print $2; exit }' watchdog/Cargo.toml)
deb_file="$REPO_ROOT/target/debian/synthaea-agent_${version}-1_amd64.deb"
mkdir -p "$(dirname "$deb_file")"
cargo deb -p watchdog --target "$target" --no-build --no-strip \
    --output "$deb_file"

# Inspect the actual payload, not just the inputs: no host-built binary may slip
# into the package through a stale asset path or a future cargo-deb change.
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
dpkg-deb -x "$deb_file" "$stage"
for name in agent watchdog cli; do
    packaged="$stage/var/lib/synthaea/bootstrap/$name"
    ./packaging/linux/check-static-elf.sh "$packaged"
    cmp "$binary_dir/$name" "$packaged"
done

# Output
echo ""
echo "==> Package created: $deb_file"
echo ""
echo "Package contents:"
dpkg-deb -c "$deb_file"

# Lintian check (optional)
if command -v lintian &> /dev/null; then
    echo ""
    echo "Running lintian checks..."
    lintian "$deb_file" || true
fi

echo ""
echo "==> Installation command:"
echo "    sudo dpkg -i $deb_file"
echo "    sudo apt-get install -f"

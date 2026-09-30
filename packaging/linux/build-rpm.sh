#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

echo "==> Packaging static musl Synthaea binaries as an .rpm"
for tool in rpmbuild rpm2cpio cpio rpm; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "missing RPM packaging tool: $tool" >&2
    exit 1
  }
done

target=x86_64-unknown-linux-musl
binary_dir="$REPO_ROOT/target/$target/release"
if [ ! -f "$binary_dir/synthaea-source-revision" ] || \
  [ "$(cat "$binary_dir/synthaea-source-revision")" != "$(git rev-parse HEAD)" ]; then
  echo "musl binaries were not built from this source revision" >&2
  exit 1
fi
./packaging/linux/check-static-elf.sh \
  "$binary_dir/agent" "$binary_dir/watchdog" "$binary_dir/cli"

# Setup RPM build environment
RPMBUILD_DIR="$REPO_ROOT/target/rpmbuild"
mkdir -p "$RPMBUILD_DIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Extract version
VERSION=$(grep -m1 '^version' agent/Cargo.toml | cut -d'"' -f2)
WATCHDOG_VERSION=$(grep -m1 '^version' watchdog/Cargo.toml | cut -d'"' -f2)
if [ "$VERSION" != "$WATCHDOG_VERSION" ]; then
  echo "agent and watchdog package versions differ" >&2
  exit 1
fi
echo "Version: $VERSION"

# Package the exact binaries built on Alpine; rpmbuild must not rebuild against
# the packaging host's libc or silently select target/release.
echo "Creating package input tarball..."
tar czf "$RPMBUILD_DIR/SOURCES/synthaea-agent-$VERSION.tar.gz" \
  --transform "s,^,synthaea-agent-$VERSION/," \
  "target/$target/release/agent" \
  "target/$target/release/watchdog" \
  "target/$target/release/cli" \
  packaging/linux/systemd/ LICENSE README.md

# Copy spec file
cp packaging/linux/rpm/synthaea-agent.spec.template \
   "$RPMBUILD_DIR/SPECS/synthaea-agent.spec"

# Build RPM
echo "Building RPM..."
rpmbuild -bb \
  --define "_topdir $RPMBUILD_DIR" \
  --define "_version $VERSION" \
  "$RPMBUILD_DIR/SPECS/synthaea-agent.spec"

RPM_PATH=$(find "$RPMBUILD_DIR/RPMS" -name "synthaea-agent-${VERSION}-*.x86_64.rpm" -print -quit)
if [ -z "$RPM_PATH" ]; then
  echo "rpmbuild produced no synthaea-agent RPM" >&2
  exit 1
fi

stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
rpm2cpio "$RPM_PATH" | (cd "$stage" && cpio -id --quiet)
for name in agent watchdog cli; do
  packaged="$stage/var/lib/synthaea/bootstrap/$name"
  ./packaging/linux/check-static-elf.sh "$packaged"
  cmp "$binary_dir/$name" "$packaged"
done
echo ""
echo "==> RPM built: $RPM_PATH"

# Copy to output
mkdir -p "$REPO_ROOT/packaging/output"
cp "$RPM_PATH" "$REPO_ROOT/packaging/output/"

echo ""
echo "Package contents:"
rpm -qpl "$RPM_PATH"

echo ""
echo "==> Installation command:"
echo "    sudo dnf install $(basename "$RPM_PATH")"

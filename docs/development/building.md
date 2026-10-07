# Building

Workspace layout, what `cargo build --workspace` covers, and how each platform sensor and
the eBPF probes are built explicitly.

## ML Crate (ONNX Runtime)

The `ml` crate requires ONNX Runtime statically linked per ADR-0002. The workspace `ort` dependency has `default-features = false` to enforce static linking.

**Development builds:** By default, the ml crate will attempt to link against system-provided onnxruntime libraries if `ORT_LIB_LOCATION` is not set. For development, you can either:
1. Set up static linking (recommended for production-like builds)
2. Skip building the ml crate: `cargo build --workspace --exclude ml`

**Static linking setup (required for production builds):**

```bash
# 1. Build onnxruntime from source
./lab/provisioning/build-onnxruntime-static.sh

# 2. Set environment variable
export ORT_LIB_LOCATION="$PWD/onnxruntime/build/Linux/Release"

# 3. Generate static link flags
eval "$(./lab/provisioning/ort-static-link-flags.sh)"

# 4. Build normally
cargo build --release
```

See `crates/ml/README.md` and `lab/provisioning/onnxruntime-static-build.md` for detailed instructions.

**Platform support:**
- Linux (Ubuntu 24.04+): Fully supported
- Windows (MSVC): supported for the `ml` crate, CPU only; see `lab/provisioning/onnxruntime-static-build.md` (issue #337)
- macOS: Not yet implemented (issue #110)

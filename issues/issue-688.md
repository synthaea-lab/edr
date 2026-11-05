# Issue #688: T1204.002 signature gate — verify the image that ran

**Branch:** `feat/688-verify-running-image`
**Status:** Implemented in code and unit tests; lab run (rename-and-replace inside the
enrichment latency) not done yet.

## Summary

Part 1 (file identity in the enrich cache key, one handle for hash/verify/identify)
shipped in #794. This change is part 2: the gate compares the identity of the file it
verified with the identity of the image at exec time, and alerts "not verified" otherwise.

The issue named the minifilter's process-creation path as the identity source; there is
none (Windows exec events come from the userland ETW sensor, and `SynthaeaFilter.c` has no
process-notify callback). Decision: capture in the ETW ProcessStart callback now; a kernel
callback is the follow-up that closes the exec → callback window.

## Files Changed
- `crates/schema/src/lib.rs` — `ExecEvent::image_file_id`; `SCHEMA_VERSION` 57 → 58
  (`tests/fixtures/v58/`, new `exec_image_file_id` golden)
- `crates/enrich/src/lib.rs` — `path_identity`, `FileEnrichment::file_id`
- `crates/sensors/windows/etw/src/{providers,winapi,lib}.rs` — records the identity at exec with its own FFI (`image_file_id`, `identity_token`): sensor crates may depend on `schema` only, so it cannot call `enrich`; a Windows agent test pins the two formats together
- `crates/rules/src/signature_gate.rs` — `SignatureGatedAlert::unconfirmed_image`
- `agent/src/enrich_queue.rs` — `image_confirmed`, applied to the gated alert
- `docs/sensors/sources.md`, `docs/detection/download-provenance.md`

## Not validated here
- Windows build of the ETW change (no Windows target on the dev host).
- `agent` tests (the host cannot link it: no libstdc++), only `cargo check`/clippy.
- Lab: rename-and-replace within the enrichment latency must raise T1204.002.

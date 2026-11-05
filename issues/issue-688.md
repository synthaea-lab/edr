# Issue #688: T1204.002 signature gate — verify the image that ran

**Branch:** `feat/688-verify-running-image`
**Status:** Implemented in code and unit tests. On a Windows 11 host at `793c5ad3` (2026-11-05,
reported by Jihair54 on #688): both Windows-only agent tests pass, and the lab "Done when" passes.
Only the kernel process-creation callback is left.

## Summary

Part 1 (file identity in the enrich cache key, one handle for hash/verify/identify)
shipped in #794. This change is part 2: the gate compares the identity of the file it
verified with the identity of the image at exec time, and alerts "not verified" otherwise.

The issue named the minifilter's process-creation path as the identity source; there is
none (Windows exec events come from the userland ETW sensor, and `SynthaeaFilter.c` has no
process-notify callback). Decision: capture in the ETW ProcessStart callback now; a kernel
callback is the follow-up that closes the exec → callback window.

## Files Changed
- `crates/schema/src/lib.rs` — `ExecEvent::image_file_id`; `SCHEMA_VERSION` 58 → 59
  (`tests/fixtures/v59/`, new `exec_image_file_id` golden)
- `crates/enrich/src/lib.rs` — `path_identity`, `FileEnrichment::file_id`
- `crates/sensors/windows/etw/src/{providers,winapi,lib}.rs` — records the identity at exec with its own FFI (`image_file_id`, `identity_token`): sensor crates may depend on `schema` only, so it cannot call `enrich`; a Windows agent test pins the two formats together
- `crates/rules/src/signature_gate.rs` — `SignatureGatedAlert::unconfirmed_image`
- `agent/src/enrich_queue.rs` — `image_confirmed`, applied to the gated alert
- `docs/sensors/sources.md`, `docs/detection/download-provenance.md`

## Not validated at implementation time (`d7f72d7a`)
This is the history of the first change; the Windows items were done on 2026-11-05, see the Status review below.
- Windows build of the ETW change (no Windows target on the dev host): covered by CI, and run on a Windows 11 host on 2026-11-05.
- `agent` tests (the host cannot link it: no libstdc++), only `cargo check`/clippy. The two Windows-only tests passed on a Windows 11 host on 2026-11-05.
- Lab: rename-and-replace within the enrichment latency must raise T1204.002. Done on 2026-11-05: it did.

## Status review (2026-11-05, read against `main`, nothing run on a VM)

The issue's two comments (2026-10-22, 2026-10-27) predate d7f72d7a (2026-10-29), which
built the exec-time identity after all (`ExecEvent::image_file_id`, v59, ETW sensor). They
read "ExecEvent has no such field": that is no longer true. Defect 2 (#794) and defect 1
(Windows, userland capture) are both in code. Nothing in code was left that could be
validated without a Windows host, so this review changes documentation only; the Windows host
results of the same day are in the table below.

Why Linux and macOS need no code today: the gate only silences on
`ImageSignature::chain_verified`, which is `cfg!(windows)` in `agent/src/sink.rs`. Elsewhere
a `Valid` never silences T1204.002 ("signed, chain not verified on this platform"), so a
swapped file cannot hide the alert and `image_file_id` stays `None`. `IDENTITY_CAPTURED`
in `agent/src/enrich_queue.rs` is `cfg!(windows)` for the same reason.

### Per-OS split of what remains

| OS | Needed | Needs a probe / VM |
|----|--------|--------------------|
| Windows | **Verified on a Windows 11 host (10.0.26300, NTFS) at `793c5ad3`, 2026-11-05.** The two Windows-only agent tests (`the_sensor_and_enrichment_agree_on_a_files_identity`, `a_valid_signature_of_a_file_that_is_not_the_image_that_ran_still_alerts`) ran and passed, with no skip ([comment](https://github.com/synthaea-lab/edr/issues/688#issuecomment-6655239026); the swap is simulated through the sink, no ETW session). The lab "Done when" passed: a live rename-and-replace with the ETW sensor attached raised T1204.002 "file differs from the image that ran", and the ETW `image_file_id` matched the moved-aside image, not the signed file at the path ([comment](https://github.com/synthaea-lab/edr/issues/688#issuecomment-6655603005); debug build, one run). Still open: measure the exec -> ETW delivery window (no issue tracks it; it could sit on #1037), and the airtight fix, a kernel process-creation callback in the minifilter (#1037; #136, #853 and #857 are the minifilter's delete/rename work, not this). | Windows VM + CI (kernel callback only) |
| macOS | Only if a chain-verified verdict is ever allowed to silence the gate there (today it cannot: ad-hoc signatures count as `Valid`). Then the ES exec message carries the image's `stat` (`es_file_t.stat`, device + inode): read it in `endpoint-security/src/normalize.rs` into `image_file_id` in the `{dev:016x}:{ino:032x}` format of `enrich::path_identity`, and flip `IDENTITY_CAPTURED`. Not verified: ES field availability on the deployment target, and device number encoding versus `stat(2)` from userland. | macOS host |
| Linux | Same condition (no chain-verified signature check exists on Linux). The audit PATH record gives `dev`/`inode` of the executed file; eBPF could read the exec'd inode in the probe. Which of the two is exact for an exec through a symlink or an overlayfs container, and whether audit `dev=` (major:minor) maps to `st_dev`, is unverified. | Linux VM (audit and eBPF paths) |

No schema change is needed for any row: `image_file_id` is a free-form identity token.

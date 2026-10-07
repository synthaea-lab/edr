# macOS Sensor

`EndpointSecurity` client design, AUTH vs NOTIFY events, entitlement requirements, and
inline prevention capabilities. Implementation: `crates/sensors/macos/endpoint-security`
(`sensor-macos`, issue #32).

## Client design

`libEndpointSecurity` hands events to an Objective-C block as `es_message_t` — a
version-gated union of ~100 event structs whose layout shifts per SDK release.
The sensor therefore never touches that layout from Rust: a small C shim
(`shim/es_shim.c`, compiled by the crate's `build.rs` against the host SDK's own
headers) subscribes, flattens each handled message into a stable plain-C struct,
and calls back into Rust. Field access is checked by the C compiler against
Apple's headers at build time — ABI drift becomes a compile error on the next
SDK, not silent corruption.

From there the path is the same shape as the Windows ETW sensor: an owned raw
model (`raw.rs`) and a pure normalization layer (`normalize.rs`), both
cross-platform and unit-tested on any host; only the FFI + client lifecycle are
macOS-gated.

## AUTH vs NOTIFY

The sensor subscribes **NOTIFY-only**. AUTH events (inline allow/deny with a
deadline) are the platform's blocking mechanism — that belongs to the response
milestone (M6) and needs the verdict model first, same sequencing as Linux LSM
blocking (#91). Nothing in the shim's design changes for AUTH beyond responding
within the deadline; the subscription set is one array away.

## Subscription set and volume discipline

| ES event | Normalized as | Note |
| --- | --- | --- |
| `NOTIFY_EXEC` | `Event::Exec` | argv via `es_exec_arg`, parent lineage from the pre-exec image, kernel code-signing state (`CS_VALID`, signing/team id, platform-binary bit) mapped to `signature` at the source |
| `NOTIFY_OPEN` | `Event::FileOpen` | kernel `fflag` (`FREAD`/`FWRITE`) translated to POSIX `O_*` so `schema::has_write_intent` works unchanged |
| `NOTIFY_CREATE` | `Event::FileOpen` (`O_CREAT\|O_WRONLY`) | |
| `NOTIFY_RENAME` | `Event::FileRename` | ransomware rename signal |
| `NOTIFY_UNLINK` | `Event::FileDelete` | |
| `NOTIFY_MMAP` | `Event::FileOpen` (`O_RDWR`) | forwarded **only** for `PROT_WRITE` + `MAP_SHARED` (mutates the file); dyld's read-only/private mapping torrent is dropped in the shim |
| `NOTIFY_BTM_LAUNCH_ITEM_ADD` | `Event::FileOpen` + `FLAG_PERSISTENCE_BTM_ARTIFACT` | macOS 13+; registration-time launch-item fact, the macOS sibling of Windows 7045 — see `rules::check_btm_launch_item_persistence` |
| `NOTIFY_OPENSSH_LOGIN` / `LOGIN_LOGIN` / `LW_SESSION_LOGIN` | `Event::Auth` (ADR-0005 shared shape) | #96, macOS 13+; SSH carries the source address when it is a literal |
| `NOTIFY_SETEXTATTR` | `Event::FileQuarantine` | #96; forwarded **only** for `com.apple.quarantine`, with the quarantine string and `kMDItemWhereFroms` URLs read back via `getxattr` at event time (best-effort: a raced read leaves them `None`, the mark itself still reports) |
| `NOTIFY_MOUNT`/`UNMOUNT` | `Event::Mount` | #96; DMG delivery / USB staging / evidence-destroying unmounts |
| `NOTIFY_SIGNAL` | `Event::Signal` | #96; forwarded **only** when the target is an ES client (the agent, other security tools) — the tamper subset; meta is the sender |
| `NOTIFY_XPC_CONNECT` | `Event::XpcConnect` | #96, macOS 14+; high-volume — rules match sensitive service names, never per-event |

The agent's own process is muted (`es_mute_process` on the self audit token) so
spool/alert writes don't feed back into the pipeline.

Download provenance is the network→file link: a `FileQuarantine` event's
`origin_url` joins the later exec of the same path on a case — the macOS
mark-of-the-web (`docs/sensors/sources.md`, cross-platform note).

Credentials in the recorded URLs (userinfo, fragment, secret-named query
values such as a pre-signed link's signature) are redacted by the agent before
anything stores or sends the event (#440, ADR-0018).

## Persistence coverage

Two deliberately distinct signals:

1. **Path writes** — a plist dropped into `LaunchAgents`/`LaunchDaemons`,
   `/etc/periodic/`, `/var/at/tabs/`, or a shell rc file is an ordinary
   write-intent `FileOpen` caught by `rules::check_persistence_write`'s path
   patterns (no flag involved).
2. **BTM registration** — Background Task Management emits
   `BTM_LAUNCH_ITEM_ADD` when an item is *registered*, whatever the path taken
   (plist drop, `SMAppService`, MDM), with the instigating process and the
   resolved payload executable. This is the deterministic signal; it also
   catches registrations that never touch a watched directory.

## Entitlement requirements (and the dev-signing path)

An ES client only starts when all three hold, and `es_new_client` reports which
one failed — `sensor-macos` maps each to its fix:

| `es_new_client` result | Fix |
| --- | --- |
| `ERR_NOT_PRIVILEGED` | run as root |
| `ERR_NOT_PERMITTED` | grant the binary Full Disk Access (System Settings → Privacy & Security → Full Disk Access) — TCC gates ES clients behind it |
| `ERR_NOT_ENTITLED` | the binary must be signed with `com.apple.developer.endpoint-security.client` |

**Production**: the entitlement is restricted — it requires an Apple Developer
ID with the Endpoint Security entitlement granted by Apple
(<https://developer.apple.com/system-extensions/>, request form; approval is per
team and takes weeks). The signed agent then runs on any Mac with the user's
one-time TCC approval. This is a packaging concern (`packaging/macos`, M7), not
a code one.

**Development, on a lab machine you control**: the entitlement check can be
relaxed instead of waiting for Apple —

1. Boot into recovery (hold power on Apple Silicon), open Terminal, and run
   `csrutil disable`, **and** set the AMFI boot-arg:
   `nvram boot-args="amfi_get_out_of_my_way=1"`. Both are required: with SIP
   off, `amfid` still rejects ad-hoc restricted entitlements — verified live
   on a SIP-enabled dev Mac (2026-09-22), where the kill is amfid's
   `"The file is adhoc signed but contains restricted entitlements"`
   (AppleMobileFileIntegrity error -424, SIGKILL at exec, **before** TCC —
   no Privacy & Security toggle can approve it). Lab machines/VMs only —
   never a daily driver.
2. Ad-hoc sign the agent with the entitlement:

   ```sh
   cat > es.entitlements <<'EOF'
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0"><dict>
       <key>com.apple.developer.endpoint-security.client</key><true/>
   </dict></plist>
   EOF
   codesign --force --options runtime \
       --entitlements es.entitlements \
       --sign - target/debug/agent
   ```

3. Grant the binary Full Disk Access, then `sudo target/debug/agent run`.

A macOS VM (UTM/Tart) is the recommended lab shape — same posture as the
Windows ETW validation VM.

## Unified-log tail (`sensor-macos-unifiedlog`, issue #95)

The supplementary source for what ES does not carry, tailing
`log stream --style ndjson` under a strict OR-of-three predicate (the daemon
filters before anything reaches the agent), with an exact-message classifier
and a counted sliding-window shed behind it:

| Source | Normalized as | Live-validated |
| --- | --- | --- |
| `sudo` outcome lines | `Event::Auth` (same mapping semantics as `sensor-linux-journal`) | ✔ failed attempt → `Auth`/failure (this repo's dev Mac, 2026-09-22) |
| tccd `AUTHREQ_CTX` + `AUTHREQ_RESULT` (joined on tccd's msgID by a bounded, counted joiner) | `Event::TccDecision` | ✔ FDA preflight denial → joined `TccDecision`/denied |
| syspolicyd `GK evaluateScanResult` | `Event::GatekeeperVerdict` | format pinned from live capture; verdict-code raw/uninterpreted |

Two documented redactions in the public log stream: syspolicyd hash-redacts
file paths (installing Apple's private-data logging profile reveals them — a
lab option, not assumed), and tccd redacts the requesting client identity on
the parsed records, so `TccDecisionEvent::client` is `None` today. Gatekeeper
events carry `team_id`/`signing_id` as the join keys toward their exec event.

Gatekeeper coverage nuance (observed live, macOS 26, 2026-09-22): syspolicyd
only writes `GK evaluateScanResult` for **Mach-O/bundle** scans — assessing a
quarantined *shell script* (e.g. via `spctl --assess`) logs `GK performScan`
alone, so script-only assessments produce no verdict event. Executing a
quarantined Mach-O produced the full verdict, ad-hoc `signing_id` included.
Widening to `performScan` would add a scan-started signal without a verdict —
deliberately not done until a rule needs it.

The message formats are undocumented; the crate's unit tests pin verbatim
live captures and are the tripwire for an OS release changing one.

## NetworkExtension sensor (`sensor-macos-network-extension`, issue #33)

The network/DNS visibility ES does not carry. Apple only runs
`NEFilterDataProvider`/`NEDNSProxyProvider` inside a Swift system extension,
so the sensor is a **seam**: the extension (`extension/` in the crate,
type-checked by `swiftc` against the SDK) extracts pid/path from each flow's
audit token and writes versioned NDJSON over a Unix socket in the shared
app-group container; the Rust crate listens, and normalizes into **existing**
schema shapes — `Connect` (what the BEACON rule keys on), `NetworkFlow`
(byte counts at flow close), `DnsQuery` (domain↔process join, RCODE in
`status`). No schema change. Records from a mismatched extension version are
skipped and counted, never guessed at.

Packaging, entitlements (both restricted, same Apple request as ES), and the
user/MDM approval flow: `packaging/macos/README.md`. The beacon-scenario lab
validation rides the packaged extension.

## Socket-table snapshots (`sensor-macos-sockets`, issue #358)

The entitlement-free source: a libproc walk (C shim against the SDK's own
`proc_info` headers — `socket_fdinfo` layout never transcribed into Rust)
snapshots every visible TCP socket with direct attribution (pid, real ppid,
uid/gid, executable path — richer than the Linux inode join). Listeners map
to `Event::ListenPort` on a 10s poll; the agent seeds the LISTENER-DRIFT
baseline from one startup snapshot, so boot-time services are baseline, not
findings. Unprivileged it sees the caller's own scope; as root, the whole
table. Established sockets are snapshotted but deliberately not emitted —
the NE flow stream (#33) is the connection source. Live-validated in the
default test suite: the crate's integration tests bind a real listener and
require the walk to find and normalize it.

## Fork/exit and process-tree state

`NOTIFY_FORK`/`NOTIFY_EXIT` are not subscribed: `schema` has no fork/exit
variants (the Linux sensor doesn't emit them either), and nothing in the
current detection set consumes them. They become interesting for pid-lifetime
state (pid-reuse hygiene in the correlator); subscribe them when that consumer
exists.

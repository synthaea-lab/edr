# Event Schema

The internal event model (process, file, network, registry, ...), normalization rules per
platform, schema versioning, and export formats.

## The model

`crates/schema` (`schema::Event` and friends) is the platform boundary described in its own
crate docs: every sensor normalizes its platform's native representation into these types;
the rule engine, correlator, and ML feature extractors consume only this shape, never a
sensor's internal one. Its public API is semi-frozen — additive changes (new optional
fields, new `Event` variants) are preferred over reshaping what already exists, because
every workspace crate depends on it.

## Detection sources

`schema::detection::DetectionSource` names the engine behind a detection and carries
enough identity to reproduce the verdict. It is serialized as an internally tagged
object (`"engine": "rule" | "sigma" | "ml" | "correlator" | "yara" | "ioc"`), so a
consumer switches on `source.engine`; the control plane's zod union
(`server/lib/detection-payload.ts`) mirrors it and must grow with it.

`Ioc` (#60, v52) is an on-device indicator match: `kind` (`sha256`, `sha1`, `md5`, `ip`,
`domain`), the matched `indicator` in the feed's canonical form (lowercase hex, textual
address, lowercase name without a trailing dot), the `feed` that supplied it, the
`feed_version` of the signed indicator set loaded when the match fired, and an optional
upstream `reference`. The schema only carries these strings and the `IocKind` enum; the
matcher and the indicator-set format live in `crates/intel` and do not leak into the
event model. Feed provenance is part of the detection so a retracted or expired feed can be
traced to every detection it produced.

## Versioning contract (issue #114)

`schema::SCHEMA_VERSION` bumps on **every** serialization-visible change to the model — no
exception for changes that are non-breaking on the Rust side. A change is visible in one of
three ways, and all three bump the version the same way:

1. **A new optional field** on an existing type — e.g. `EventMeta::container`
   (`Option<ContainerContext>`, #169, v9 → v10). `#[serde(default, skip_serializing_if)]`
   makes this a no-op for a Rust reader on an old payload, and the field is invisible in
   JSON when absent. It still bumps: a non-Rust consumer (the control-plane server, a SIEM
   export) that snapshots the field set it deserializes sees a shape that didn't exist
   before v10, even though nothing broke.
2. **A new `Event` (or `DetectionSource`, etc.) variant** — e.g. `Event::Auth` (#94, v12 →
   v13). `Event` is `#[non_exhaustive]`, so existing Rust `match` arms already have a
   wildcard and don't need to change. It still bumps: a consumer keying on the `"type"` tag
   value now has a value it has never seen, the same "new shape" concern as case 1 — even
   though old data still deserializes fine under the new type (`tests/v1_compat.rs` pins
   exactly this: `tests/fixtures/v1/*.json`, frozen forever, still parse as the current
   `Event`).
3. **A removal, rename, or type change** to an existing field or variant — breaking outright
   for any reader, old or new. Bumps for the obvious reason.

Cases 1 and 2 cost nothing to bump (the version is a "this shape is new" signal, not a
compatibility gate — nothing stops an old payload from parsing under a newer schema) and
buys every consumer, Rust or not, an honest answer to "did this field/variant exist yet".
Not bumping for additive changes would quietly hide that answer from anyone who isn't
reading this crate's Rust source.

Every bump adds a **full** `tests/fixtures/v<N>/` snapshot (every golden fixture as it
serializes today, not only the ones that changed) and never edits an existing version's
fixture files — `v1` through `v13` all still exist on disk, exactly as `SCHEMA_VERSION`
found them at the time. `tests/golden.rs` exercises the current version; `tests/v1_compat.rs`
is the standing proof that the oldest frozen data still deserializes under the current
types.

### What does *not* bump `SCHEMA_VERSION`

Reusing bits inside a field that already exists is not a new shape. `FileOpenEvent::flags`
gained `FLAG_PERSISTENCE_ARTIFACT`/`FLAG_PERSISTENCE_TASK_ARTIFACT`/
`FLAG_PERSISTENCE_ACCOUNT_ARTIFACT` (Windows persistence detections marking an existing
`u32` field with a high bit) without a version bump — the field's type and presence are
unchanged, only the *meaning* of specific values within it grew. See
`docs/adr/0004-windows-persistence-detection-via-eventlog-polling.md` for the full rationale
and its known limitation (a bit-flag convention doesn't scale to a real `Persistence` event
family, which would be a case-2 change if it lands).

### Not the same contract as a sensor's own wire ABI

`SCHEMA_VERSION` governs `crates/schema`'s public JSON model only. A sensor's internal
wire format between its own privileged and userspace halves is a separate, unrelated
versioning scheme — e.g. `sensor-linux-wire::WIRE_VERSION`, a build-time tripwire
(`assert!(wire::WIRE_VERSION == N)`) that only fails the Linux sensor's own build if the
eBPF-side struct layout and userspace's understanding of it drift. Adding a
kernel-captured `cgroup_id` field to that wire struct (#204) bumped `WIRE_VERSION` 3 → 4
and touched no fixture directory here, because nothing changed in what `schema::Event`
serializes to a consumer — the sensor still normalizes to the same `EventMeta.container`
shape it always did, just resolved more reliably internally.

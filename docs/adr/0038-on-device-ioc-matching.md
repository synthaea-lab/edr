# ADR-0038: On-device IOC matching: an exact set behind a filter, indicators of attack stay content

- **Status**: proposed
- **Date**: 2026-10-26

Issue #60. This records what `crates/intel` builds and what it leaves open. The first slice is
hashes and addresses; the amendment under "### 6. Domains" (status **proposed**, pending the
owner's decision) adds domains.
The number is the next free one on `main` at the time of writing; #969 also names an ADR-0037,
so renumber on merge if another lands first.

## Context

Indicator sets (file hashes, IP addresses, domains) must be matched on the device, against
`enrich` output on exec and write and against connect events, without a round trip per event and
without unbounded memory: a public feed lists millions of hashes. Matches are detections and
feed the correlator like any other source.

Two things were already fixed before this ADR: sets ship as signed content through the canary
rings (ADR-0016), and behavioural indicators (IOA) are not a new engine, because `rules`, `sigma`
and the correlator already express them.

## Decision

### 1. Indicators of attack are not matched here

A server-side pipeline converts an IOA feed into rule or Sigma content, which ships and is
evaluated like any other. `crates/intel` stays about membership of atomic indicators. This is the
record #60 asks for; the pipeline itself is not built.

### 2. The exact tier decides; a Bloom filter only saves work

An indicator set is sorted arrays (a 32-byte digest or a 128-bit address, with a 16-bit feed id),
searched by binary search. In front of each array sits a Bloom filter (10 bits per indicator,
7 positions, about 1% false positives). A "no" from the filter is final; a "maybe" is always
confirmed by the array. A false positive therefore costs one search and can never be a detection.
The false-positive count is a counter, so the filter's cost on a real fleet is observable.

The filter is in memory only and has no byte layout to keep stable. It is not shared with the
common-set snapshot reader (`crates/ml/src/features/common_set.rs`, ADR-0033): that one parses a
server-written format and uses a "maybe" as weak evidence, and it lives in `ml`, which a detection
leaf should not depend on.

### 3. The memory budget is enforced at build time, and a set is refused whole

`SetBuilder` takes a budget in bytes (default 64 MiB, **provisional**, sized for a few million
hashes and not measured on a fleet). Once the set it would build no longer fits, further
indicators are refused and counted, and `build` fails. A set is never silently truncated: a
partial feed is coverage nobody asked for, and the agent keeps the set it has. While building, the
builder holds up to the same entries again as the finished set.

### 4. Reload swaps one pointer

`Intel` holds the current set in an `Arc` behind a lock held only for the swap. A lookup in flight
finishes on the set it started with; the next lookup sees the new one. There is no half-loaded
state and no restart. Counters belong to a set, so they restart at a reload.

### 5. Provenance and normalisation

A match reports the feed that listed the indicator (the lowest id when several do), which the
future `DetectionSource::Ioc` carries. An IPv4-mapped IPv6 address is the IPv4 address on both
sides, judged on the canonical form. A loopback or unspecified address is never an indicator
(listing `127.0.0.1` would alert on every local connection); it is counted as rejected. A bad line
in a feed is counted and skipped, so one malformed line does not discard the feed.

### 6. Domains (amendment, proposed)

**A listed domain matches itself and every name beneath it.** `evil.example` flags `evil.example`,
`www.evil.example` and `a.b.evil.example`, on a label boundary only: `notevil.example` and
`evil.example.org` do not match, and a suffix is never a substring that starts inside a label. A
listed `c2.evil.example` does not cover its parent.

Why suffix and not exact only. What a feed lists is a registered or operator-controlled domain;
what the endpoint resolves is a name beneath it, often one the attacker generates per victim (DGA
and DNS-tunnelling labels, per-campaign hosts). Exact-only matching would make a feed of domains
miss most of the traffic it was published for, and a feed author who wants a single host lists
that host. The cost is blast radius: a wrongly listed parent flags every name under it. That is
bounded by the rules below and by the server-side pipeline, not by the device.

**Normalisation, applied identically to a listed name and to a queried one**, because the
two must agree on what a name *is*:

- ASCII-lowercase, and drop one trailing dot (the root). A second dot is an empty label.
- Labels are 1 to 63 bytes, the name at most 253 bytes (RFC 1035), characters `a-z 0-9 - _`
  only, no hyphen at either edge of a label. `_` is kept because real DNS names carry it
  (`_dmarc`, service records) and refusing it would make a feed unable to list such a host.
- **No Unicode.** DNS carries an internationalised name as punycode (`xn--`), which is plain ASCII
  and compared as written. The engine does not convert: a non-ASCII indicator is rejected and
  counted so the feed author fixes the feed, and a non-ASCII query matches nothing. This avoids
  an IDNA dependency and its version-dependent mapping rules; it assumes the DNS sensors report
  the wire form, which is what they read.
- An all-numeric last label is refused, which is how an IPv4 literal (`203.0.113.7`) looks; an
  address belongs under `ip:`. A name that fails any rule matches nothing and is never an error
  on the lookup path.

**Too broad to be an indicator, with no dependency.** A single label (`com`, `localhost`) is
refused (`DomainTooBroad`), so `com` can never flag a whole TLD. This is a floor, and it is not
enough: `co.uk` has two labels and is a public suffix, so listing it would flag every `*.co.uk`.
Telling those apart needs the public-suffix list, which the device does not embed: it is a
dependency or a vendored file that changes monthly and would have to ship through the same signed
channel as the sets. Decision: the **server-side pipeline** checks every domain against the
public-suffix list before it enters a set (it is the place that can carry the dependency and
reject or quarantine the feed), and the device enforces the minimal rule above. The residual
risk is a bad set that passed the pipeline; it is limited by the canary rings, not by the engine.
A per-feed hit counter on the server would show such a feed flagging far too much; the device
does not report per-feed hits yet.

**Bounded lookup cost.** A listed domain has 2 to 8 labels (`DomainTooDeep` beyond that, refused
at load rather than silently unmatchable). A lookup probes the queried name's label suffixes of 2
to 8 labels: at most 7 filter checks and binary searches, whatever the name's length (a 253-byte
name has up to 127 labels and still costs 7), no allocation. Each probe goes through the Bloom
filter first; the exact tier decides. When several listed suffixes match, the lowest feed id wins,
as for the other kinds. The counters count a lookup once.

**Memory.** The exact tier holds the name as a boxed string; a name is charged its length plus
a fixed per-entry overhead (24 bytes for the string header and feed, 16 assumed for the
allocator) and one Bloom filter shared by all domains. `estimated_bytes_with_domains` takes the
count and the total name bytes so the budget check stays exact before anything is allocated.

**Not decided here.** Wildcard syntax (`*.evil.example`) and exact-only entries: a feed that
needs "this host but not its children" has no way to say so, and we do not guess a syntax before
a real feed asks. The agent wiring (which DNS events feed `lookup_domain`) belongs to the
sensors that produce them.

## Delivery: an `ioc` content type

Sets travel as signed content (ADR-0016) under a fourth content type, `ioc`: `ioc/<feed>.txt` and an
optional `ioc/VERSION`. **No agent change is needed**: `crates/updater` keeps `type` as a plain string and
the agent applies an entry by its path, so a signed `ioc/<feed>.txt` is written to
`<content_root>/ioc/`, the directory the agent's IOC loader already reads. The manifest schema version
does not change, and an agent that predates the loader stores the files and ignores them.

Because the agent chooses by path and never by type, **the server pins the pairing at publish**
(`iocEntryError`, `server/lib/content-publish.ts`): only an `ioc` entry may sit under `ioc/` (a `rule`
named `ioc/x.txt` would otherwise load as a feed), an `ioc` entry must be a feed or the version file, and a
feed must be one the device loads whole: every line a valid indicator under the device's own rules, no
listed public suffix. The device skips a bad line without a word, so this is the only place anyone is told.
Withdrawing a feed is a corrective release without the entry (ADR-0032): the file is removed and the set
unloads at the next reload.

Not decided here: who may publish an `ioc` entry (today, whoever may publish any content), and whether a
feed needs a per-tenant switch before it reaches a host.

## Not decided, not built

- **CIDR ranges, indicator expiry, and a confidence per indicator.**
- **File-write hashes.** The agent matches exec image hashes, connect and `NetworkFlow` addresses and DNS
  queries (`docs/detection/ioc-matching.md`); `FileWriteEvent` carries a descriptor and a byte count, no
  path and no hash, so nothing is matched on writes until a sensor reports one.
- **Behaviour when the enrichment worker falls behind.** No shedding is defined for the hash lookup.
- **Signing the sets in production** (blocked on #753) and most of the **server-side feed pipeline**: the
  builder (normalise, dedup, device rules, public-suffix gate) and a CSV source exist, see
  `docs/detection/ioc-matching.md`; STIX/TAXII, MISP, expiry, per-tenant enablement and a step that
  builds a feed and puts it in a release do not.
- **Calibration** of the 64 MiB budget and the filter sizing against a fleet. The lab run with a seeded
  indicator #60 asked for was done on 2026-10-26 (three indicators, three findings), which says nothing
  about the budget.

## Consequences

- Hash, address and domain matching can be unit-tested and fuzzed with no sensor, no schema change and no
  lab.
- A feed that is too large is a visible failure at load, not a slow memory leak.
- The filter's false-positive rate and the budget are calibration constants to revisit with fleet
  data.

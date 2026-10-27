# ADR-0038: On-device IOC matching: an exact set behind a filter, indicators of attack stay content

- **Status**: proposed
- **Date**: 2026-10-26

Issue #60. This records what the first slice builds (`crates/intel`) and what it leaves open.
The number is the next free one on `main` at the time of writing; #969 also names an ADR-0037,
so renumber on merge if another lands first.

## Context

Indicator sets (file hashes, IP addresses, later domains) must be matched on the device, against
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

## Not decided, not built

- **Domains.** Whether a listed domain matches its subdomains, and how the DNS telemetry (and its
  case and trailing-dot forms) is normalised, change what an indicator means and need their own
  decision.
- **CIDR ranges, indicator expiry, and a confidence per indicator.**
- **The schema variant `DetectionSource::Ioc`** (indicator and feed provenance, with fixtures).
- **Wiring into the agent**: where hash matching sits on the exec and write path, and the shed
  behaviour when it falls behind.
- **Signed delivery** of sets (ADR-0016; blocked in production on #753) and the **server-side feed
  pipeline** (STIX/TAXII, MISP, CSV, dedup, expiry, per-tenant enablement).
- A lab run with a seeded indicator, which #60's "done when" asks for.

## Consequences

- Hash and address matching can be unit-tested and fuzzed with no sensor, no schema change and no
  lab.
- A feed that is too large is a visible failure at load, not a slow memory leak.
- The filter's false-positive rate and the budget are calibration constants to revisit with fleet
  data.

# IOC matching (issue #60, ADR-0038)

`crates/intel` matches file hashes (SHA-256), IP addresses and domains against a loaded indicator
set. This is the engine only: it is not yet wired into the agent and loads no signed content (see
"Not decided, not built" in ADR-0038).

## Building a set

`SetBuilder::new(budget)`, then `add_sha256`, `add_ip` or `add_lines(feed, text)`, then `build`.
Line format, one indicator per line, blank lines and `#` comments ignored:

```
sha256:<64 hex digits, either case>
ip:<IPv4 or IPv6 address>
domain:<DNS name, 2 to 8 labels, ASCII>
```

A line that is neither is counted in `LoadReport::rejected` and skipped. A CIDR range and a loopback or
unspecified address are rejected, and so is a domain that is not a valid DNS name (see below). `build` fails with `BudgetExceeded` if any
indicator did not fit; the set is refused whole.

## Querying

`IndicatorSet::lookup_sha256`, `lookup_sha256_hex` (as `enrich` reports a hash), `lookup_ip` and
`lookup_domain` return a `Match { kind, feed }`. `Intel` holds the set in force and `load` replaces it while
lookups run.

## Domains

A listed domain matches itself and every name beneath it, on a label boundary: `evil.example`
flags `www.evil.example` but not `notevil.example`. A listed subdomain does not cover its parent.
Case and one trailing dot are ignored on both sides. Rejected at load (counted in
`LoadReport::rejected`): a single label (`com`), more than 8 labels, an empty label, a label over
63 bytes or a name over 253, characters other than `a-z 0-9 - _`, a hyphen at a label edge, an
all-numeric last label (an IP literal, list it as `ip:`) and non-ASCII text. An internationalised
name is listed and queried as punycode (`xn--...`); the engine does not convert.

A lookup is at most 7 filter checks and searches (suffixes of 2 to 8 labels) whatever the name's
length, with no allocation; a name that is not valid DNS matches nothing. When several listed
suffixes match, the lowest feed id is reported. The two-label floor does not stop a public suffix
such as `co.uk`: the server-side pipeline must check domains against the public-suffix list
before they enter a set, because the device carries no such list (ADR-0038, section 6).

## Observability

`IndicatorSet::stats()`: lookups, lookups the filter rejected, lookups the filter passed and the
exact tier refused (the filter's cost), and confirmed hits. `memory_bytes()` is what the set
occupies, against `estimated_bytes(sha256_count, ip_count)`, or `estimated_bytes_with_domains` when domains
are listed (a name costs its length plus a fixed overhead). A domain lookup counts once in the
stats: a filter negative when no probe passed the filter (an invalid name included), a false
positive when one did and none was confirmed.

## Calibration

The default budget (64 MiB) and the filter sizing (10 bits per indicator, 7 positions, about 1%)
are provisional: set from arithmetic and a synthetic test (100,000 absent hashes against 20,000
listed, under 3% false positives), not from a fleet.

## In the agent (`agent/src/ioc.rs`, `DetectionSink`)

Feeds are files in `<content_root>/ioc/`: each `*.txt` is one feed, named by its file stem and
written in the line format above; an optional `VERSION` file (first line) names the release they
came from, `unversioned` without one. Feed ids follow the sorted file names, so two agents with
the same files agree on which feed wins an overlap. Names and versions are trimmed, stripped of
control characters and cut at 64 characters, because they travel in every detection.
**Nothing delivers these files yet:** signed delivery through the content manifest waits on the
production signing keys (#753), so today a feed is a file somebody put there.

Loaded at startup and on `reload_content` (IPC `ReloadContent`): a present directory replaces the
set, an absent one unloads it, an unreadable or over-budget one keeps the previous set (logged).
The set and its feed names are swapped together.

Where it matches:

| Event | Where | Indicator | Severity |
|---|---|---|---|
| `Exec` | the enrichment worker, once the image hash is known | SHA-256 | High |
| `Connect` | the capture thread (a Bloom probe and a binary search) | destination address | Medium |

A match becomes a `DetectionSource::Ioc` detection with the indicator in its normalised form
(lowercase hex, canonical address), the feed name and the feed version. It carries the label
`IOC` where other engines carry a technique, and no ATT&CK technique: an indicator says a thing
is known bad, not which tactic it served. It enters the verdict and the alert log like any other
finding and never kills or quarantines.

The same indicator raises one finding per 10 minutes (**provisional**); a repeat inside that
window is counted (`IocStats::cooled_down`) and dropped, so a hash run in a loop or an address
polled every second is one finding. The cooldown remembers 4,096 indicators, least recently seen
forgotten first.

Not wired: file writes, `NetworkFlow`, and the health-beacon counters (`IocStats` exists, nothing
reports it yet).

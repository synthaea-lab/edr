# IOC matching (issue #60, ADR-0038)

`crates/intel` matches file hashes (SHA-256), IP addresses and domains against a loaded indicator
set. The agent loads feed files from its content root and raises a detection on a match (see "In the
agent" below); no signed delivery of those files exists yet, and ADR-0038 ("Not decided, not built")
lists what is still open.

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
Delivery is a signed content release carrying `ioc/<feed>.txt` entries of type `ioc` (ADR-0038,
"Delivery"); the agent needs nothing new for it. **Nothing builds and publishes such a release yet**, and
signing it in production waits on the production keys (#753): a feed reaches a host through a release an
operator signs by hand (test key in the lab), or is a file somebody put there.

Verified in the lab on 2026-10-29 (Fedora 43, kernel 7.2.9, agent built from `main` `609cd1d8`, control
plane run from the same tree, **public test key only**): release 1 of ring `prod` with `ioc/lab-feed.txt`
(an exec hash, an address, a domain) and `ioc/VERSION` was staged under `storage/artifacts/<sha256>`, signed
with `release-tool sign --kind content --test-key` and published with `POST /api/content/release`. A running
agent ran `agent apply-content-manifest --allow-test-key`: `applied release 1 (2 entries fetched, 0 removed)`,
`notified the running agent`, and its log shows `ioc: indicator set loaded` with the version
`2026-10-29.signed`. Before the delivery the same exec, connections and lookups raised no IOC finding; after
it the exec hash and the domain each raised one on the test traffic (a listed binary run twice, a lookup of
a name under the listed domain), carrying that feed name and version, and the unlisted domain and address
stayed silent. **The address case was exercised only through the agent's own connection:** the listed address
was the control plane's, the finding came from the `apply-content-manifest` process connecting to it, and the
test loop's connections then fell inside the cooldown. So the run shows that a delivered address indicator
is loaded and matches, not that a listed address a test process connects to raises a finding; that needs
another run with a listed address that is not the control plane. The same run showed the agent alerting on its
own control-plane connection (#1061). The publish step refused, with 422, a `rule` entry under `ioc/`, an
`ioc` entry outside `ioc/` and a feed with an invalid line. Not covered: a delivery to an agent that is not
running, the production key path, and the file-write hash (above, still not wired).

Loaded at startup and on `reload_content` (IPC `ReloadContent`): a present directory replaces the
set, an absent one unloads it, an unreadable or over-budget one keeps the previous set (logged).
The set and its feed names are swapped together.

Where it matches:

| Event | Where | Indicator | Severity |
|---|---|---|---|
| `Exec` | the enrichment worker, once the image hash is known | SHA-256 | High |
| `Connect` | the capture thread (a Bloom probe and a binary search) | destination address | Medium |
| `DnsQuery` | the capture thread (at most 7 probes) | the queried name, any status | Medium |

A match becomes a `DetectionSource::Ioc` detection with the indicator in its normalised form
(lowercase hex, canonical address, and for a domain the *listed* domain that matched, not the
subdomain the host asked for), the feed name and the feed version. It carries the label
`IOC` where other engines carry a technique, and no ATT&CK technique: an indicator says a thing
is known bad, not which tactic it served. It enters the verdict and the alert log like any other
finding and never kills or quarantines.

The same indicator raises one finding per 10 minutes (**provisional**); a repeat inside that
window is counted (`IocStats::cooled_down`) and dropped, so a hash run in a loop or an address
polled every second is one finding. The cooldown remembers 4,096 indicators, least recently seen
forgotten first.

A `NetworkFlow` peer address is checked like a connect destination: conntrack reports every live
flow on each poll, and the cooldown makes that one finding.

The health beacon reports `ioc_indicators` (indicators in force, a gauge), `ioc_findings` and
`ioc_cooled_down`, so the server can tell a host with no feed from one with a feed and no match. The
console's fleet health page shows them in an "IOC feed" column (`docs/architecture/control-plane.md`).

Not wired: file writes (`FileWriteEvent` carries a descriptor and a byte count, no path and no
hash, so there is nothing to match until a sensor reports one).

## Server side: building a feed (`server/lib/ioc-feed.ts`)

`buildFeed({ feed, text, isPublicSuffix, defaultKind })` turns the text of one source into the
`ioc/<feed>.txt` an agent loads: `kind:value` lines, normalised as the device normalises them,
de-duplicated and sorted, so the same input always gives the same bytes and the same hash. It
applies the device's own load rules (hash length, loopback and unspecified addresses, IPv4-mapped
IPv6 canonicalised, domain syntax and 2 to 8 labels, ASCII only) and returns a reason per rejected
line (`rejected`, bounded to 100 by default, with `rejectedTotal` always exact). One bad line never
discards a feed. `versionFile` writes the one-line `ioc/VERSION`, `isValidFeedName` guards the file
stem.

The check the device cannot make is here: a listed domain must not be a public suffix (`co.uk`
would flag a whole country, since a listed domain covers its subdomains). The suffix list is a
dependency the module does not carry: the caller passes `isPublicSuffix`, and **without one every
domain is refused** (`public_suffix_unchecked`) rather than published unchecked. Hashes and
addresses are unaffected.

`server/lib/public-suffix.ts` is the `isPublicSuffix` to pass: `tldts` (pinned at 7.4.18, MIT, one
transitive package), private suffixes such as `github.io` and `blogspot.com` counted, so a listed
`github.io` is refused and `attacker.github.io` is not.

`server/tests/fixtures/ioc-feed-golden.txt` is checked on both sides: the server test asserts the
builder produces it from `ioc-feed-input.txt`, and `crates/intel/tests/feed_golden.rs` asserts the
engine takes every line of it unchanged.

### A CSV source (`server/lib/ioc-csv.ts`)

`buildFeedFromCsv({ feed, csv, valueColumn, typeColumn?, defaultKind?, hasHeader?, isPublicSuffix })`
reads a feed published as CSV (RFC 4180: quoted fields, `""` for a quote, CRLF or LF, a newline inside
quotes, a byte-order mark) and passes its rows to the same builder core, so a CSV feed gets the same
normalisation, device rules and public-suffix gate, and gives the same bytes (and hash) as the plain
`kind:value` text for the same indicators. `server/tests/fixtures/ioc-csv-input.csv` produces
`ioc-feed-golden.txt` byte for byte.

- **Columns** are named by header (case-insensitive) or, with `hasHeader: false`, by 0-based index. A
  column that is not there throws: it is a mistake in the configuration, not in the data.
- **Kind**: from `typeColumn` (`sha256`, `sha-256`, `ip`, `ipv4`, `ipv6`, `ip-src`, `ip-dst`, `domain`,
  `fqdn`, `hostname`; case-insensitive), else `defaultKind`. A kind the engine does not match (`md5`, `url`)
  or none at all is rejected as `unknown_kind`. A `kind:` prefix inside the value does not override it.
- **A bad row never discards the feed.** A row with the wrong number of fields is `bad_csv`; every
  rejection carries the line its record *starts* on, which a quoted newline makes different from the
  record's index. A quote that is never closed swallows the rest of the text, so it is one `bad_csv`
  rejection at its record and the records before it are kept.
- A line starting with `#` and a blank line are skipped, as in the plain format. A header that itself
  starts with `#` is therefore skipped too: address the columns by index with `hasHeader: false`.
- A quote in the middle of an unquoted field is kept as text (lenient on input; the output is always
  normalised).

### Publishing (`ioc` content type)

A feed is published as an `ioc` entry of a content release (`ContentType` has `ioc`): the file as
`ioc/<feed>.txt` and, optionally, `ioc/VERSION`. At publish (`POST /api/content/release`) the server refuses
the release when the type and the path disagree or a feed has a line the device would skip. See ADR-0038,
"Delivery", for why the pairing is checked on the server.

Not built: the other sources (STIX/TAXII, MISP), expiry, per-tenant enablement, a step that turns a source
into a release (nothing calls `buildFeed` outside this check yet), and production signing (#753).

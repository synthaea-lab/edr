# IOC matching (issue #60, ADR-0038)

`crates/intel` matches file hashes (SHA-256) and IP addresses against a loaded indicator set.
This is the engine only: it is not yet wired into the agent, has no schema variant and loads no
signed content (see "Not built" in ADR-0038).

## Building a set

`SetBuilder::new(budget)`, then `add_sha256`, `add_ip` or `add_lines(feed, text)`, then `build`.
Line format, one indicator per line, blank lines and `#` comments ignored:

```
sha256:<64 hex digits, either case>
ip:<IPv4 or IPv6 address>
```

A line that is neither is counted in `LoadReport::rejected` and skipped. A CIDR range, a domain
and a loopback or unspecified address are rejected. `build` fails with `BudgetExceeded` if any
indicator did not fit; the set is refused whole.

## Querying

`IndicatorSet::lookup_sha256`, `lookup_sha256_hex` (as `enrich` reports a hash) and `lookup_ip`
return a `Match { kind, feed }`. `Intel` holds the set in force and `load` replaces it while
lookups run.

## Observability

`IndicatorSet::stats()`: lookups, lookups the filter rejected, lookups the filter passed and the
exact tier refused (the filter's cost), and confirmed hits. `memory_bytes()` is what the set
occupies, against `estimated_bytes(sha256_count, ip_count)`.

## Calibration

The default budget (64 MiB) and the filter sizing (10 bits per indicator, 7 positions, about 1%)
are provisional: set from arithmetic and a synthetic test (100,000 absent hashes against 20,000
listed, under 3% false positives), not from a fleet.

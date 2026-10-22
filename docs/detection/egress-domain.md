# Egress to storage and paste services (EGRESS-DOMAIN, #380)

The T1567 line of the Collection and Exfiltration pack (#380). One stateful rule in
`crates/rules` (`RuleState::on_dns_query` and `RuleState::check_egress_volume`, the domain table in
`egressdomain.rs`) and two Sigma rules over curl command lines.

## What the rule joins

EGRESS-VOLUME (T1041/T1048) sums the bytes a process name sends to one public address and alerts at
512 MiB in ten minutes. EGRESS-DOMAIN reads the **same sum** with a lower threshold when the
destination is a storage or paste service:

1. A DNS lookup (`DnsQueryEvent`) of a listed name, by pid P, that resolved to address A is
   remembered as (P, A) for one hour.
2. A conntrack flow (`NetworkFlowEvent`) of pid P to address A is volume. When the sum for that
   (process name, address) reaches **25 MiB** in ten minutes, the alert names the technique of the class
   (T1567.002 cloud storage and file sharing, T1567.003 paste and text sharing) and the domain.

The class comes from the name the process asked for, never from the address it connected to: a service
shares its addresses with every other site behind the same CDN, and an address says nothing alone. So the
join key is the pid *and* its own lookup. A lookup by another pid, a failed or empty one, an address of a
different answer, a sighting older than an hour, and one recorded for another incarnation of a recycled pid
(`process_generation`) all join nothing. The first poll of a flow is a baseline and adds nothing, as for
EGRESS-VOLUME.

## It is dormant on a default host

Two things must be on, and neither is by default:

- `net.netfilter.nf_conntrack_acct=1`, or `bytes_sent` is `None` and no volume exists (the same condition as
  EGRESS-VOLUME).
- A DNS source. On Linux it is the `getaddrinfo` uprobe, opt-in (`UprobesConfig::with_dns_enabled`), and it
  records **only the first address** of the answer, so a connection to a second one is not joined. Windows has
  DNS (the DNS-Client provider lists every address) but no volume (#138). macOS has both gated on the network
  extension (#351). So today the rule can only fire on a Linux host that enabled both.

Without a lookup, the only finding is the generic EGRESS-VOLUME one at 512 MiB. `Event::DnsQuery` now reaches
the rule state in `agent::DetectionSink`; it did not before.

## Provisional

25 MiB, ten minutes, one hour and the domain lists are **starting points**. No capture of ordinary uploads
exists. Raise the threshold before narrowing the lists. Medium, like the volume rule. One alert per window per
(process name, address), kept apart from the generic alert so one does not hide the other. State is bounded
(`BoundedMap`, the sightings and the sums).

## False positives, assessed

Reasoned, **not measured on a live host.**

- **Expected to fire:** a sync client (Dropbox, `rclone`, `rsync` to a bucket) or a backup tool that sends more
  than 25 MiB to a storage service: that is its job. An administrator's deliberate upload.
- **Excluded, on evidence only:** a browser (`chrome`, `chromium`, `firefox`, `brave`, `msedge`, `opera`,
  `vivaldi`) whose exec-time image sits at a trusted system path. A `chrome` run from `/tmp` is **not**
  excluded, and a browser installed as a Snap or Flatpak (outside the system directories) alerts on its own
  uploads, a known false positive.
- **Webhooks are not classified** (`discord.com/api/webhooks`, T1567.004): the name is the host of the whole
  chat service, and only the URL path tells a webhook, which DNS does not carry.

## The Sigma rules

`curl_upload_to_cloud_storage` (Linux) gained the storage and file-sharing names and the `-F`/`--form` and
`@file` upload shapes; `curl_upload_to_paste_service` is new (T1567.003). Both see only a command line: an
attempt, not a byte, and not `nc termbin.com 9999 < file`, whose file is a redirection. Regional S3 endpoints
(`s3.<region>.amazonaws.com`) cannot be written as an edge wildcard, so only the DNS rule classifies them. The
`@file` and form shapes widen the rule: an API client that posts a JSON file to Dropbox or SharePoint matches.
The **Windows** `curl_upload_to_cloud_storage` rule was not widened and keeps its five names: the two lists
should be brought in step in a follow-up.

## Tests

`crates/rules/src/tests/egressdomain.rs` (the join, the threshold, the window, the pid and generation keys,
the browser gate, the bounded history), the unit tests of the classifier in `egressdomain.rs`, the content test
`the_storage_and_paste_rules_cover_each_listed_domain_and_upload_shape` in `crates/sigma/tests/content.rs`, and
one in `agent/src/sink.rs` that a lookup and a flow, fed through the sink, reach `alerts.ndjson`.

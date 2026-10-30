import { describe, expect, it } from "vitest";
import { buildFeedFromStix } from "@/lib/ioc-stix";
import { buildFeed } from "@/lib/ioc-feed";
import { buildIocStage } from "@/lib/ioc-stage";

const HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
const NOW = new Date("2026-10-30T12:00:00Z");
const suffixes = new Set(["com", "co.uk"]);
const isPublicSuffix = (name: string) => suffixes.has(name);

const indicator = (pattern: string, extra: object = {}) => ({
  type: "indicator",
  spec_version: "2.1",
  id: "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  pattern,
  pattern_type: "stix",
  valid_from: "2026-01-01T00:00:00Z",
  ...extra,
});
const bundle = (...objects: object[]) => JSON.stringify({ type: "bundle", id: "bundle--1", objects });
const build = (json: string, extra: object = {}) =>
  buildFeedFromStix({ feed: "lab", json, now: NOW, isPublicSuffix, ...extra });

describe("buildFeedFromStix", () => {
  it("builds the same file as the plain feed for the same indicators", () => {
    const json = bundle(
      indicator(`[file:hashes.'SHA-256' = '${HASH}']`),
      indicator("[ipv4-addr:value = '203.0.113.9']"),
      indicator("[domain-name:value = 'Evil.Example.Org']"),
    );
    const plain = buildFeed({
      feed: "lab",
      text: `sha256:${HASH}\nip:203.0.113.9\ndomain:evil.example.org\n`,
      isPublicSuffix,
    });
    const stix = build(json);
    expect(stix.text).toBe(plain.text);
    expect(stix.sha256).toBe(plain.sha256);
    expect(stix.counts).toEqual({ sha256: 1, ip: 1, domain: 1, total: 3 });
    expect(stix.rejectedTotal).toBe(0);
  });

  it("reads an IPv6 address and a TAXII envelope without a type", () => {
    const json = JSON.stringify({ objects: [indicator("[ipv6-addr:value = '2001:DB8::1']")] });
    expect(build(json).text).toBe("ip:2001:db8::1\n");
  });

  it("ignores objects that are not indicators and does not count them", () => {
    const r = build(bundle({ type: "malware", id: "malware--1", name: "x" }, indicator("[ipv4-addr:value = '203.0.113.9']")));
    expect(r.read).toBe(1);
    expect(r.text).toBe("ip:203.0.113.9\n");
  });

  it("refuses a compound or non-equality pattern instead of reading half of it", () => {
    const patterns = [
      `[ipv4-addr:value = '203.0.113.9' OR ipv4-addr:value = '203.0.113.10']`,
      `[ipv4-addr:value = '203.0.113.9'] FOLLOWEDBY [domain-name:value = 'evil.example.org']`,
      `[domain-name:value IN ('a.example.org', 'b.example.org')]`,
      `[domain-name:value LIKE '%.example.org']`,
      `[ipv4-addr:value = '203.0.113.9'] WITHIN 5 SECONDS`,
      `[file:name = 'evil.exe']`,
      `[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']`,
      `[ipv4-addr:value = '203.0.113.0/24']`,
      `[ipv4-addr:value != '203.0.113.9']`,
    ];
    const r = build(bundle(...patterns.map((p) => indicator(p))));
    expect(r.counts.total).toBe(0);
    expect(r.rejected.map((x) => x.reason)).toEqual(patterns.map(() => "unsupported_pattern"));
  });

  it("refuses another pattern language", () => {
    const r = build(bundle(indicator("rule x { condition: true }", { pattern_type: "yara" })));
    expect(r.rejected[0].reason).toBe("unsupported_pattern");
  });

  it("applies lifetime at the instant it is given", () => {
    const r = build(
      bundle(
        indicator("[ipv4-addr:value = '203.0.113.1']", { revoked: true }),
        indicator("[ipv4-addr:value = '203.0.113.2']", { valid_until: "2026-10-30T11:59:59Z" }),
        indicator("[ipv4-addr:value = '203.0.113.3']", { valid_until: "2026-10-30T12:00:00Z" }),
        indicator("[ipv4-addr:value = '203.0.113.4']", { valid_from: "2026-10-30T12:00:01Z" }),
        indicator("[ipv4-addr:value = '203.0.113.5']", { valid_until: "2026-10-30T12:00:01Z" }),
        indicator("[ipv4-addr:value = '203.0.113.6']", { revoked: false }),
      ),
    );
    expect(r.rejected.map((x) => x.reason)).toEqual(["revoked", "expired", "expired", "not_yet_valid"]);
    expect(r.text).toBe("ip:203.0.113.5\nip:203.0.113.6\n");
    const later = build(bundle(indicator("[ipv4-addr:value = '203.0.113.5']", { valid_until: "2026-10-30T12:00:01Z" })), {
      now: new Date("2026-10-30T12:00:02Z"),
    });
    expect(later.counts.total).toBe(0);
  });

  it("rejects an unreadable timestamp or a missing pattern as bad_stix", () => {
    const r = build(
      bundle(
        indicator("[ipv4-addr:value = '203.0.113.1']", { valid_until: "soon" }),
        { type: "indicator", id: "indicator--2" },
      ),
    );
    expect(r.rejected.map((x) => x.reason)).toEqual(["bad_stix", "bad_stix"]);
  });

  it("applies the device rules and the public-suffix gate to the values", () => {
    const r = build(
      bundle(
        indicator("[ipv4-addr:value = '127.0.0.1']"),
        indicator("[domain-name:value = 'co.uk']"),
        indicator("[file:hashes.'SHA-256' = 'abc']"),
      ),
    );
    expect(r.rejected.map((x) => x.reason)).toEqual(["unusable_address", "public_suffix", "bad_hash"]);
  });

  it("numbers a rejection by the object's position in the bundle", () => {
    const r = build(bundle({ type: "malware", id: "malware--1" }, indicator("[file:name = 'x']")));
    expect(r.rejected[0].line).toBe(2);
  });

  it("unescapes the two STIX escapes and refuses what is left odd", () => {
    const r = build(bundle(indicator("[domain-name:value = 'a\\'b.example.org']")));
    expect(r.rejected[0].reason).toBe("bad_domain");
  });

  it("drops duplicates across indicators", () => {
    const r = build(bundle(indicator("[ipv4-addr:value = '203.0.113.9']"), indicator("[ipv4-addr:value = '203.0.113.9']")));
    expect(r.counts.total).toBe(1);
    expect(r.duplicates).toBe(1);
  });

  it("throws for input that is not a bundle", () => {
    expect(() => build("not json")).toThrow(RangeError);
    expect(() => build("[]")).toThrow(RangeError);
    expect(() => build(JSON.stringify({ type: "bundle" }))).toThrow(RangeError);
    expect(() => build(JSON.stringify({ type: "report", objects: [] }))).toThrow(RangeError);
    expect(() => build(bundle(), { feed: "Bad Name" })).toThrow(RangeError);
  });
});

describe("buildIocStage with a STIX source", () => {
  it("stages the feed and reports the lifetime rejections", () => {
    const json = bundle(
      indicator("[ipv4-addr:value = '203.0.113.9']"),
      indicator("[ipv4-addr:value = '203.0.113.10']", { valid_until: "2026-01-02T00:00:00Z" }),
    );
    const r = buildIocStage({ feed: "lab", source: { format: "stix", json }, now: NOW });
    if (!r.ok) throw new Error(r.error);
    expect(r.artifacts[0].bytes.toString()).toBe("ip:203.0.113.9\n");
    expect(r.report.rejected.map((x) => x.reason)).toEqual(["expired"]);
  });

  it("refuses a bundle whose indicators have all expired rather than unload the set", () => {
    const json = bundle(indicator("[ipv4-addr:value = '203.0.113.9']", { valid_until: "2026-01-02T00:00:00Z" }));
    const r = buildIocStage({ feed: "lab", source: { format: "stix", json }, now: NOW });
    expect(r.ok).toBe(false);
  });

  it("says a non-bundle is the caller's mistake", () => {
    const r = buildIocStage({ feed: "lab", source: { format: "stix", json: "<html>error</html>" }, now: NOW });
    expect(r).toEqual({ ok: false, error: "the source is not JSON" });
  });
});

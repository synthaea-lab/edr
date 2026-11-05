import { describe, expect, it } from "vitest";
import { createHash } from "crypto";
import { readFileSync } from "fs";
import path from "path";
import {
  buildFeed,
  isValidFeedName,
  normalizeAddress,
  normalizeDomain,
  versionFile,
} from "@/lib/ioc-feed";

const HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
const suffixes = new Set(["com", "co.uk", "blogspot.com"]);
const isPublicSuffix = (name: string) => suffixes.has(name);

const build = (text: string, extra: object = {}) => buildFeed({ feed: "lab", text, isPublicSuffix, ...extra });

describe("normalizeDomain", () => {
  it("lowercases and drops one trailing dot", () => {
    expect(normalizeDomain("Evil.Example.COM.")).toEqual({ ok: true, name: "evil.example.com" });
  });

  it("refuses what the device refuses", () => {
    const reason = (name: string) => {
      const r = normalizeDomain(name);
      return r.ok ? "ok" : r.reason;
    };
    expect(reason("localhost")).toBe("domain_too_broad");
    expect(reason("a.b.c.d.e.f.g.h.i")).toBe("domain_too_deep");
    expect(reason("a.b.c.d.e.f.g.h")).toBe("ok");
    expect(reason("bücher.example")).toBe("non_ascii_domain");
    expect(reason("\u212A.com")).toBe("non_ascii_domain"); // KELVIN SIGN lowercases to ASCII "k"
    expect(reason("evil.\u212A.com")).toBe("non_ascii_domain");
    expect(reason("\u0130.example.com")).toBe("non_ascii_domain"); // dotted capital I
    expect(reason("-a.example.com")).toBe("bad_domain");
    expect(reason("a-.example.com")).toBe("bad_domain");
    expect(reason("a..example.com")).toBe("bad_domain");
    expect(reason("a b.example.com")).toBe("bad_domain");
    expect(reason("1.2.3.4")).toBe("bad_domain");
    expect(reason(`${"a".repeat(64)}.example.com`)).toBe("bad_domain");
    expect(reason(`${"a".repeat(63)}.example.com`)).toBe("ok");
    expect(reason(`${"a.".repeat(125)}com`)).toBe("domain_too_deep"); // 253 bytes, 126 labels
    expect(reason(`${"a.".repeat(126)}com`)).toBe("bad_domain"); // 255 bytes
    expect(reason("_dmarc.example.com")).toBe("ok");
    expect(reason("xn--bcher-kva.example")).toBe("ok");
  });
});

describe("normalizeAddress", () => {
  const norm = (a: string) => {
    const r = normalizeAddress(a);
    return r.ok ? r.address : r.reason;
  };
  it("accepts and canonicalises", () => {
    expect(norm("203.0.113.9")).toBe("203.0.113.9");
    expect(norm("2001:DB8:0:0:0:0:0:1")).toBe("2001:db8::1");
    expect(norm("2001:db8:0:1:0:0:0:1")).toBe("2001:db8:0:1::1");
    expect(norm("::ffff:203.0.113.9")).toBe("203.0.113.9");
    expect(norm("::ffff:cb00:7109")).toBe("203.0.113.9");
  });
  it("refuses a scoped IPv6 address rather than widening it", () => {
    for (const a of ["fe80::1%eth0", "fe80::1%3", "2001:db8::1%eth0", "::ffff:203.0.113.9%eth0"]) {
      expect(norm(a), a).toBe("bad_address");
    }
    expect(norm("fe80::1")).toBe("fe80::1");
  });
  it("refuses loopback, unspecified (also IPv4-mapped) and garbage", () => {
    for (const a of ["127.0.0.1", "127.9.9.9", "0.0.0.0", "::1", "::", "::ffff:127.0.0.1", "::ffff:0.0.0.0"]) {
      expect(norm(a), a).toBe("unusable_address");
    }
    for (const a of ["", "999.1.1.1", "1.2.3", "example.com", "1.2.3.4/24", "0x7f.1"]) {
      expect(norm(a), a).toBe("bad_address");
    }
  });
});

describe("buildFeed", () => {
  it("builds the agent's file: normalised, sorted, de-duplicated", () => {
    const result = build(
      [
        "# a comment",
        "",
        `sha256:${HASH.toUpperCase()}`,
        `sha256:${HASH}`,
        "ip:203.0.113.9",
        "ip:::ffff:203.0.113.9",
        "domain:Evil.Example.Org.",
        "domain:evil.example.org",
      ].join("\r\n"),
    );
    expect(result.text).toBe(`domain:evil.example.org\nip:203.0.113.9\nsha256:${HASH}\n`);
    expect(result.counts).toEqual({ sha256: 1, ip: 1, domain: 1, total: 3 });
    expect(result.read).toBe(6);
    expect(result.duplicates).toBe(3);
    expect(result.rejectedTotal).toBe(0);
    expect(result.sha256).toBe(createHash("sha256").update(result.text).digest("hex"));
  });

  it("is deterministic whatever the order of the input", () => {
    const a = build("ip:203.0.113.9\ndomain:a.example.org\nip:198.51.100.1\n");
    const b = build("ip:198.51.100.1\ndomain:a.example.org\nip:203.0.113.9\n");
    expect(a.text).toBe(b.text);
    expect(a.sha256).toBe(b.sha256);
  });

  it("counts and lists a bad line without discarding the feed", () => {
    const result = build(
      ["ip:203.0.113.9", "sha256:abc", "ip:127.0.0.1", "nonsense", "domain:localhost", "ip:198.51.100.1"].join("\n"),
    );
    expect(result.counts.total).toBe(2);
    expect(result.rejectedTotal).toBe(4);
    expect(result.rejected.map((r) => [r.line, r.reason])).toEqual([
      [2, "bad_hash"],
      [3, "unusable_address"],
      [4, "unknown_kind"],
      [5, "domain_too_broad"],
    ]);
  });

  it("refuses a listed domain that is a public suffix, but not one under it", () => {
    const result = build("domain:co.uk\ndomain:blogspot.com\ndomain:evil.co.uk\ndomain:x.blogspot.com\n");
    expect(result.text).toBe("domain:evil.co.uk\ndomain:x.blogspot.com\n");
    expect(result.rejected.map((r) => r.reason)).toEqual(["public_suffix", "public_suffix"]);
  });

  it("refuses every domain when no suffix check is given, and still takes hashes and addresses", () => {
    const result = buildFeed({ feed: "lab", text: `domain:evil.example.org\nip:203.0.113.9\nsha256:${HASH}\n` });
    expect(result.counts).toEqual({ sha256: 1, ip: 1, domain: 0, total: 2 });
    expect(result.rejected).toEqual([{ line: 1, reason: "public_suffix_unchecked", value: "evil.example.org" }]);
  });

  it("takes bare values under a default kind, and an explicit prefix wins", () => {
    const result = build(`${HASH}\nip:203.0.113.9\n`, { defaultKind: "sha256" });
    expect(result.text).toBe(`ip:203.0.113.9\nsha256:${HASH}\n`);
    expect(build(HASH).rejected[0].reason).toBe("unknown_kind");
  });

  it("an empty or all-rejected feed is an empty file, not an error", () => {
    expect(build("# nothing\n").text).toBe("");
    expect(build("junk\n").counts.total).toBe(0);
  });

  it("bounds the rejection list but counts every rejection, and cuts long values", () => {
    const text = Array.from({ length: 250 }, (_, i) => `ip:bad${i}`).join("\n") + `\nip:${"9".repeat(200)}`;
    const result = build(text);
    expect(result.rejectedTotal).toBe(251);
    expect(result.rejected).toHaveLength(100);
    expect(build(text, { maxRejectedListed: 3 }).rejected).toHaveLength(3);
    expect(build(`ip:${"9".repeat(200)}`).rejected[0].value).toHaveLength(80);
  });

  it("refuses a bad feed name and an oversized source", () => {
    for (const feed of ["", "A", "../x", "a/b", ".hidden", "a..b", "x.", "a b", "é", "a".repeat(65)]) {
      expect(() => buildFeed({ feed, text: "" }), feed).toThrow(RangeError);
    }
    expect(() => buildFeed({ feed: "lab", text: "x".repeat(64 * 1024 * 1024 + 1) })).toThrow(RangeError);
  });
});

describe("isValidFeedName / versionFile", () => {
  it("accepts usual names", () => {
    for (const n of ["abuse.ch", "misp_prod", "feed-1", "a", "9lives"]) expect(isValidFeedName(n), n).toBe(true);
  });
  it("writes a one-line version and refuses an unprintable or long one", () => {
    expect(versionFile("2026-10-26.1")).toBe("2026-10-26.1\n");
    for (const v of ["", "a b", "a\nb", "é", "v".repeat(65)]) expect(() => versionFile(v), v).toThrow(RangeError);
  });
});

describe("the file the agent loads", () => {
  it("matches the golden file, which the Rust engine loads with no rejection", () => {
    const dir = path.join(__dirname, "..", "fixtures");
    const input = readFileSync(path.join(dir, "ioc-feed-input.txt"), "utf8");
    const golden = readFileSync(path.join(dir, "ioc-feed-golden.txt"), "utf8");
    const result = buildFeed({ feed: "golden", text: input, isPublicSuffix });
    expect(result.text).toBe(golden);
    expect(result.rejectedTotal).toBe(3); // 127.0.0.1, localhost, nine labels
  });
});

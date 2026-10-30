import { describe, expect, it } from "vitest";
import { buildFeedFromMisp } from "@/lib/ioc-misp";
import { buildFeed } from "@/lib/ioc-feed";
import { buildIocStage } from "@/lib/ioc-stage";

const HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
const suffixes = new Set(["com", "co.uk"]);
const isPublicSuffix = (name: string) => suffixes.has(name);

const attr = (type: string, value: string, extra: object = {}) => ({ type, value, to_ids: true, ...extra });
const event = (attributes: object[], objects: object[] = []) => ({ Event: { id: "1", Attribute: attributes, Object: objects } });
const build = (doc: unknown, extra: object = {}) =>
  buildFeedFromMisp({ feed: "lab", json: JSON.stringify(doc), isPublicSuffix, ...extra });

describe("buildFeedFromMisp", () => {
  it("builds the same file as the plain feed for the same indicators", () => {
    const r = build(
      event([attr("sha256", HASH), attr("ip-dst", "203.0.113.9"), attr("domain", "Evil.Example.Org"), attr("hostname", "c2.example.net")]),
    );
    const plain = buildFeed({
      feed: "lab",
      text: `sha256:${HASH}\nip:203.0.113.9\ndomain:evil.example.org\ndomain:c2.example.net\n`,
      isPublicSuffix,
    });
    expect(r.text).toBe(plain.text);
    expect(r.sha256).toBe(plain.sha256);
    expect(r.rejectedTotal).toBe(0);
  });

  it("reads restSearch envelopes, a bare event and several events", () => {
    const one = event([attr("ip-src", "203.0.113.9")]);
    expect(build({ response: [one] }).text).toBe("ip:203.0.113.9\n");
    expect(build(one.Event).text).toBe("ip:203.0.113.9\n");
    const two = build({ response: [one, event([attr("ip-src", "203.0.113.10")])] });
    expect(two.text).toBe("ip:203.0.113.10\nip:203.0.113.9\n");
  });

  it("reads the attributes of objects, in order after the event's own", () => {
    const r = build(event([attr("md5", "d41d8cd98f00b204e9800998ecf8427e")], [{ Attribute: [attr("ip-src", "203.0.113.9"), attr("sha1", "x")] }]));
    expect(r.text).toBe("ip:203.0.113.9\n");
    expect(r.rejected.map((x) => [x.line, x.reason])).toEqual([
      [1, "unknown_kind"],
      [3, "unknown_kind"],
    ]);
  });

  it("refuses an attribute that is not flagged for detection, in either boolean spelling", () => {
    const r = build(
      event([
        attr("ip-src", "203.0.113.1", { to_ids: false }),
        attr("ip-src", "203.0.113.2", { to_ids: "0" }),
        attr("ip-src", "203.0.113.3", { to_ids: undefined }),
        attr("ip-src", "203.0.113.4", { to_ids: "1" }),
        attr("ip-src", "203.0.113.5", { to_ids: 1 }),
      ]),
    );
    expect(r.rejected.map((x) => x.reason)).toEqual(["not_for_detection", "not_for_detection", "not_for_detection"]);
    expect(r.text).toBe("ip:203.0.113.4\nip:203.0.113.5\n");
  });

  it("refuses a deleted attribute", () => {
    const r = build(event([attr("ip-src", "203.0.113.1", { deleted: true }), attr("ip-src", "203.0.113.2", { deleted: "0" })]));
    expect(r.rejected.map((x) => x.reason)).toEqual(["deleted"]);
    expect(r.text).toBe("ip:203.0.113.2\n");
  });

  it("refuses the attributes of a deleted object", () => {
    // MISP soft-deletes an object as a whole: its attributes need not be flagged one by one.
    const r = build(
      event(
        [],
        [
          { name: "domain-ip", deleted: true, Attribute: [attr("domain", "gone.example.org")] },
          { name: "domain-ip", deleted: "0", Attribute: [attr("domain", "kept.example.org")] },
        ],
      ),
    );
    expect(r.rejected.map((x) => x.reason)).toEqual(["deleted"]);
    expect(r.text).toBe("domain:kept.example.org\n");
  });

  it("never splits a composite type", () => {
    const r = build(
      event([attr("ip-src|port", "203.0.113.9|443"), attr("filename|sha256", `evil.exe|${HASH}`), attr("domain|ip", "evil.example.org|203.0.113.9")]),
    );
    expect(r.counts.total).toBe(0);
    expect(r.rejected.map((x) => x.reason)).toEqual(["unknown_kind", "unknown_kind", "unknown_kind"]);
  });

  it("applies the device rules and the public-suffix gate to the values", () => {
    const r = build(event([attr("ip-src", "10.0.0.0/8"), attr("ip-src", "127.0.0.1"), attr("domain", "co.uk"), attr("sha256", "abc")]));
    expect(r.rejected.map((x) => x.reason)).toEqual(["bad_address", "unusable_address", "public_suffix", "bad_hash"]);
  });

  it("rejects a malformed attribute without discarding the feed", () => {
    const r = build(event([{ type: "ip-src" }, "x" as unknown as object, attr("ip-src", "203.0.113.9")]));
    expect(r.rejected.map((x) => x.reason)).toEqual(["bad_misp", "bad_misp"]);
    expect(r.text).toBe("ip:203.0.113.9\n");
  });

  it("throws for input that holds no event", () => {
    expect(() => build("a string")).toThrow(RangeError);
    expect(() => buildFeedFromMisp({ feed: "lab", json: "not json" })).toThrow(RangeError);
    expect(() => build({})).toThrow(RangeError);
    expect(() => build({ response: [] })).toThrow(RangeError);
    expect(() => build(event([]), { feed: "Bad Name" })).toThrow(RangeError);
  });
});

describe("buildIocStage with a MISP source", () => {
  it("stages the feed and reports what was refused", () => {
    const json = JSON.stringify(event([attr("ip-src", "203.0.113.9"), attr("ip-src", "203.0.113.10", { to_ids: false })]));
    const r = buildIocStage({ feed: "lab", source: { format: "misp", json } });
    if (!r.ok) throw new Error(r.error);
    expect(r.artifacts[0].bytes.toString()).toBe("ip:203.0.113.9\n");
    expect(r.report.rejected.map((x) => x.reason)).toEqual(["not_for_detection"]);
  });

  it("refuses an export with no detection indicator rather than unload the set", () => {
    const json = JSON.stringify(event([attr("ip-src", "203.0.113.9", { to_ids: false })]));
    expect(buildIocStage({ feed: "lab", source: { format: "misp", json } }).ok).toBe(false);
  });
});

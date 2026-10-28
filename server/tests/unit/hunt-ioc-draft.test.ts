import { describe, expect, it } from "vitest";
import { readFileSync } from "fs";
import path from "path";
import { parseGraduationRequest, type GraduationDetection, type GraduationHunt } from "@/lib/hunt-graduation";
import { draftIocSetFromHunt, graduationKind, parseIocGraduationRequest } from "@/lib/hunt-ioc-draft";

const SHA_A = "a".repeat(64);
const SHA_B = "0123456789abcdef".repeat(4);

const det = (id: string, event: unknown): GraduationDetection => ({ id, technique: "T1105", severity: "high", event });
const exec = (sha256: unknown) => ({ type: "exec", image_path: "/tmp/x", cmdline: "x", sha256 });
const connect = (daddr: unknown, type = "connect") => ({ type, daddr, dport: 443 });

const hunt: GraduationHunt = {
  id: "h-1",
  name: "Dropper callbacks",
  description: null,
  version: 3,
  query: { version: 1, lastHours: 168 },
};

function ok(result: ReturnType<typeof draftIocSetFromHunt>) {
  if (!result.ok) throw new Error(`expected a draft, got ${JSON.stringify(result.problems)}`);
  return result;
}

describe("draftIocSetFromHunt", () => {
  it("lists the hashes and addresses the matches carry, in the engine's line format", () => {
    const { files, todo } = ok(
      draftIocSetFromHunt(hunt, [
        det("1", exec(SHA_B.toUpperCase())),
        det("2", connect("203.0.113.9")),
        det("3", exec(SHA_A)),
        det("4", connect("2001:DB8::1", "network_flow")),
      ])
    );
    expect(files).toHaveLength(1);
    expect(files[0].path).toBe("rules/ioc/dropper_callbacks.txt");
    const lines = files[0].content.split("\n").filter((l) => l !== "" && !l.startsWith("#"));
    expect(lines).toEqual([`sha256:${SHA_B}`, `sha256:${SHA_A}`, "ip:2001:db8::1", "ip:203.0.113.9"]);
    expect(files[0].content).toContain("# DRAFT graduated from hunt h-1 (query version 3)");
    expect(todo.join(" ")).toMatch(/not a verdict/);
    expect(todo.join(" ")).toMatch(/#753/);
  });

  it("lists an indicator once however many detections carry it, and an IPv4-mapped address as IPv4", () => {
    const { files } = ok(
      draftIocSetFromHunt(hunt, [
        det("1", exec(SHA_A)),
        det("2", exec(SHA_A)),
        det("3", connect("203.0.113.9")),
        det("4", connect("::ffff:203.0.113.9")),
      ])
    );
    const lines = files[0].content.split("\n").filter((l) => l !== "" && !l.startsWith("#"));
    expect(lines).toEqual([`sha256:${SHA_A}`, "ip:203.0.113.9"]);
  });

  it("leaves out what the engine refuses and says so", () => {
    const { files, todo } = ok(
      draftIocSetFromHunt(hunt, [
        det("1", connect("203.0.113.9")),
        det("2", connect("127.0.0.1")),
        det("3", connect("127.9.9.9")),
        det("4", connect("0.0.0.0")),
        det("5", connect("::1")),
        det("6", connect("::")),
        det("7", connect("::ffff:127.0.0.1")),
        det("8", connect("fe80::1%eth0")),
        det("9", connect("not an address")),
        det("10", exec("abc")),
      ])
    );
    expect(files[0].content).not.toMatch(/127\.|::1|0\.0\.0\.0|%|abc/);
    expect(todo.join(" ")).toMatch(/6 loopback or unspecified addresses/);
    expect(todo.join(" ")).toMatch(/3 values were left out/);
  });

  it("drafts the queried domains, lowercased, once, after the addresses", () => {
    const { files, todo } = ok(
      draftIocSetFromHunt(hunt, [
        det("1", { type: "dns_query", query: "C2.Evil.example.com." }),
        det("2", { type: "dns_query", query: "c2.evil.example.com" }),
        det("3", { type: "dns_query", query: "a.evil.example" }),
        det("4", connect("203.0.113.9")),
      ])
    );
    const lines = files[0].content.split("\n").filter((l) => l !== "" && !l.startsWith("#"));
    expect(lines).toEqual(["ip:203.0.113.9", "domain:a.evil.example", "domain:c2.evil.example.com"]);
    expect(todo.join(" ")).toMatch(/every name beneath it/);
  });

  it("leaves out a public suffix, a name the feed builder refuses, and counts them", () => {
    const { files, todo } = ok(
      draftIocSetFromHunt(hunt, [
        det("1", exec(SHA_A)),
        det("2", { type: "dns_query", query: "co.uk" }),
        det("3", { type: "dns_query", query: "blogspot.com" }),
        det("4", { type: "dns_query", query: "localhost" }),
        det("5", { type: "dns_query", query: "\u212A.example.com" }), // KELVIN SIGN
        det("6", { type: "dns_query", query: "1.2.3.4" }),
        det("7", { type: "dns_query" }),
        det("8", { type: "dns_query", query: "evil.co.uk" }),
      ])
    );
    const lines = files[0].content.split("\n").filter((l) => l !== "" && !l.startsWith("#"));
    expect(lines).toEqual([`sha256:${SHA_A}`, "domain:evil.co.uk"]);
    expect(todo.join(" ")).toMatch(/2 DNS queries were left out because the name is a public suffix/);
    expect(todo.join(" ")).toMatch(/4 values were left out/);
  });

  it("refuses when no match carries an indicator, naming what was skipped", () => {
    const result = draftIocSetFromHunt(hunt, [
      det("1", { type: "dns_query", query: "co.uk" }),
      det("2", exec(undefined)),
      det("3", connect("127.0.0.1")),
      det("4", null),
    ]);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.problems[0]).toMatch(/SHA-256/);
    expect(result.problems[0]).toMatch(/1 DNS queries for a public suffix/);
    expect(result.problems[0]).toMatch(/1 loopback/);
  });

  it("does not put the hunt's name in a comment, where a line break would start a new line", () => {
    const { files } = ok(draftIocSetFromHunt({ ...hunt, name: "x\nsha256:" + "b".repeat(64) }, [det("1", exec(SHA_A))]));
    expect(files[0].content.match(/sha256:/g)).toHaveLength(1);
    expect(files[0].path).toMatch(/^rules\/ioc\/[a-z0-9_]+\.txt$/);
  });

  it("is the file the intel crate loads (the same fixture is loaded by crates/intel/tests/draft_golden.rs)", () => {
    const golden = readFileSync(path.join(__dirname, "../fixtures/ioc-draft-golden.txt"), "utf8");
    const { files } = ok(
      draftIocSetFromHunt(hunt, [
        det("1", exec(SHA_B)),
        det("2", exec(SHA_A)),
        det("3", connect("203.0.113.9")),
        det("4", connect("2001:db8::1", "network_flow")),
        det("5", connect("127.0.0.1")),
        det("6", { type: "dns_query", query: "C2.Evil.example." }),
        det("7", { type: "dns_query", query: "a.evil.example" }),
        det("8", { type: "dns_query", query: "co.uk" }),
      ])
    );
    expect(files[0].content).toBe(golden);
  });
});

describe("graduationKind and parseIocGraduationRequest", () => {
  it("defaults to the Sigma draft, so a body without kind keeps working", () => {
    expect(graduationKind({ platform: "linux" })).toBe("sigma");
    expect(graduationKind({ kind: "sigma", platform: "linux" })).toBe("sigma");
    expect(graduationKind({ kind: "ioc" })).toBe("ioc");
    expect(graduationKind(null)).toBe("sigma");
    expect(() => graduationKind({ kind: "yara" })).toThrow('kind must be "sigma" or "ioc"');
  });

  it("takes a Sigma body that names its kind, and an IOC body that names nothing else", () => {
    expect(parseGraduationRequest({ kind: "sigma", platform: "macos" })).toEqual({ platform: "macos" });
    expect(() => parseIocGraduationRequest({ kind: "ioc" })).not.toThrow();
    expect(() => parseIocGraduationRequest({ kind: "ioc", platform: "linux" })).toThrow('unknown field "platform"');
    expect(() => parseIocGraduationRequest({ kind: "ioc", negative: {} })).toThrow('unknown field "negative"');
    expect(() => parseIocGraduationRequest([])).toThrow("body must be an object");
  });
});

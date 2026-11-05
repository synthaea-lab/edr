import { describe, expect, it } from "vitest";
import { readFileSync } from "fs";
import path from "path";
import { buildFeedFromCsv, parseCsv } from "@/lib/ioc-csv";
import { buildFeed } from "@/lib/ioc-feed";

const HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
const suffixes = new Set(["com", "co.uk"]);
const isPublicSuffix = (name: string) => suffixes.has(name);

const build = (csv: string, extra: object = {}) =>
  buildFeedFromCsv({ feed: "lab", csv, valueColumn: "indicator", typeColumn: "type", isPublicSuffix, ...extra });

describe("parseCsv", () => {
  it("reads RFC 4180 quoting: commas, doubled quotes and newlines inside a field", () => {
    const { records } = parseCsv('a,"b,c","d ""e"" f","g\nh"\n1,2,3,4\n');
    expect(records.map((r) => r.fields)).toEqual([
      ["a", "b,c", 'd "e" f', "g\nh"],
      ["1", "2", "3", "4"],
    ]);
  });

  it("numbers a record by the line it starts on, across a quoted newline", () => {
    const { records } = parseCsv('x\n"a\nb"\nz\n');
    expect(records.map((r) => r.line)).toEqual([1, 2, 4]);
  });

  it("accepts CRLF, a missing final newline and a byte-order mark; skips blank and comment lines", () => {
    const { records } = parseCsv("﻿# note\r\na,b\r\n\r\nc,d");
    expect(records.map((r) => r.fields)).toEqual([
      ["a", "b"],
      ["c", "d"],
    ]);
  });

  it("keeps an empty trailing field and does not treat # inside a record as a comment", () => {
    const { records } = parseCsv("a,#b,\n");
    expect(records[0].fields).toEqual(["a", "#b", ""]);
  });

  it("reports an unterminated quote and keeps the records before it", () => {
    const { records, fault } = parseCsv('a,b\nc,"d\ne,f\n');
    expect(records.map((r) => r.fields)).toEqual([["a", "b"]]);
    expect(fault?.line).toBe(2);
  });
});

describe("buildFeedFromCsv", () => {
  it("builds the same file as the plain feed for the same indicators", () => {
    const csv = `indicator,type\n${HASH},sha256\n203.0.113.9,ip\nevil.example.org,domain\n`;
    const plain = buildFeed({ feed: "lab", text: `sha256:${HASH}\nip:203.0.113.9\ndomain:evil.example.org\n`, isPublicSuffix });
    const result = build(csv);
    expect(result.text).toBe(plain.text);
    expect(result.sha256).toBe(plain.sha256);
  });

  it("finds columns by header name, in any order and any case", () => {
    const result = build(`Type,Note,INDICATOR\nip,x,203.0.113.9\n`);
    expect(result.text).toBe("ip:203.0.113.9\n");
  });

  it("addresses columns by index when there is no header", () => {
    const result = buildFeedFromCsv({
      feed: "lab",
      csv: "203.0.113.9,ip\n198.51.100.1,ip\n",
      hasHeader: false,
      valueColumn: 0,
      typeColumn: 1,
    });
    expect(result.text).toBe("ip:198.51.100.1\nip:203.0.113.9\n");
  });

  it("uses defaultKind when there is no kind column", () => {
    const result = buildFeedFromCsv({ feed: "lab", csv: `hash\n${HASH}\n`, valueColumn: "hash", defaultKind: "sha256" });
    expect(result.text).toBe(`sha256:${HASH}\n`);
  });

  it("refuses a row with no kind at all", () => {
    const result = buildFeedFromCsv({ feed: "lab", csv: "v\n203.0.113.9\n", valueColumn: "v" });
    expect(result.text).toBe("");
    expect(result.rejected).toEqual([{ line: 2, reason: "unknown_kind", value: "203.0.113.9" }]);
  });

  it("refuses a kind the engine does not match (md5), with the line it is on", () => {
    const result = build(`indicator,type\nd41d8cd98f00b204e9800998ecf8427e,md5\n203.0.113.9,ip\n`);
    expect(result.text).toBe("ip:203.0.113.9\n");
    expect(result.rejected).toEqual([{ line: 2, reason: "unknown_kind", value: "md5" }]);
  });

  it("counts a short or long row as bad_csv without dropping the others", () => {
    const result = build(`indicator,type\n203.0.113.9\n198.51.100.1,ip,extra\n192.0.2.1,ip\n`);
    expect(result.text).toBe("ip:192.0.2.1\n");
    expect(result.rejected.map((r) => [r.line, r.reason])).toEqual([
      [2, "bad_csv"],
      [3, "bad_csv"],
    ]);
    expect(result.rejectedTotal).toBe(2);
  });

  it("cannot be made to list a second indicator from one field", () => {
    // A quoted newline must stay inside one value, which the builder then refuses whole.
    const result = build(`indicator,type\n"203.0.113.9\ndomain:evil.example.org",ip\n`);
    expect(result.text).toBe("");
    expect(result.rejected[0].reason).toBe("bad_address");
  });

  it("does not let a value's own prefix change its kind", () => {
    const result = build(`indicator,type\ndomain:evil.example.org,ip\n`);
    expect(result.text).toBe("");
  });

  it("applies the public-suffix gate and fails closed without a checker", () => {
    expect(build(`indicator,type\nco.uk,domain\n`).rejected[0].reason).toBe("public_suffix");
    const open = buildFeedFromCsv({ feed: "lab", csv: `indicator,type\nevil.example.org,domain\n`, valueColumn: "indicator", typeColumn: "type" });
    expect(open.rejected[0].reason).toBe("public_suffix_unchecked");
  });

  it("keeps what an unterminated quote did not swallow, and lists the fault", () => {
    const result = build(`indicator,type\n203.0.113.9,ip\n"198.51.100.1,ip\n192.0.2.1,ip\n`);
    expect(result.text).toBe("ip:203.0.113.9\n");
    expect(result.rejected.map((r) => [r.line, r.reason])).toEqual([[3, "bad_csv"]]);
  });

  it("throws on a column that is not in the header, an index with no header, or no header at all", () => {
    expect(() => build(`a,b\n1,2\n`)).toThrow(RangeError);
    expect(() => buildFeedFromCsv({ feed: "lab", csv: "1,2\n", hasHeader: false, valueColumn: "x" })).toThrow(RangeError);
    expect(() => buildFeedFromCsv({ feed: "lab", csv: "", valueColumn: "x" })).toThrow(RangeError);
    expect(() => build("indicator,type\n", { feed: "../x" })).toThrow(RangeError);
  });

  it("matches the golden file, which the Rust engine loads with no rejection", () => {
    const dir = path.join(__dirname, "..", "fixtures");
    const csv = readFileSync(path.join(dir, "ioc-csv-input.csv"), "utf8");
    const golden = readFileSync(path.join(dir, "ioc-feed-golden.txt"), "utf8");
    const result = buildFeedFromCsv({ feed: "golden", csv, valueColumn: "indicator", typeColumn: "type", isPublicSuffix });
    expect(result.text).toBe(golden);
    expect(result.rejected.map((r) => r.reason).sort()).toEqual(["domain_too_broad", "unusable_address"]);
  });
});

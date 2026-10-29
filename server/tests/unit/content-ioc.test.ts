import { describe, expect, it } from "vitest";
import { iocEntryError } from "@/lib/content-publish";
import { ContentType } from "@/lib/content-manifest";

const HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
const feed = (text: string) => Buffer.from(text);
const err = (path: string, type: string, text = "") => iocEntryError({ path, type }, feed(text));

describe("the ioc content type", () => {
  it("is one of the types a manifest may carry", () => {
    expect(ContentType.parse("ioc")).toBe("ioc");
    expect(() => ContentType.parse("yara")).toThrow();
  });
});

describe("iocEntryError: the type and the path must agree, because the agent loads by path", () => {
  it("leaves every other entry alone", () => {
    expect(err("rules/a.sigma", "rule", "title: x\n")).toBeNull();
    expect(err("models/m.pkl", "model", "\x00\x01")).toBeNull();
    expect(err("policy/p.json", "policy", "{}")).toBeNull();
    // `ioc` as a name that merely starts with the letters is not the directory.
    expect(err("iocs/a.txt", "rule", "x")).toBeNull();
  });

  it("refuses an entry under ioc/ that is not an ioc entry: the agent would load it as a feed", () => {
    expect(err("ioc/evil.txt", "rule", `sha256:${HASH}\n`)).toContain("only an entry of type \"ioc\"");
    expect(err("ioc/VERSION", "policy", "v1\n")).toContain("only an entry of type \"ioc\"");
  });

  it("refuses an ioc entry outside ioc/", () => {
    expect(err("rules/feed.txt", "ioc", `sha256:${HASH}\n`)).toContain("not under ioc/");
    expect(err("xioc/feed.txt", "ioc", `sha256:${HASH}\n`)).toContain("not under ioc/");
  });

  it("accepts a feed and a version file", () => {
    expect(err("ioc/lab.txt", "ioc", `sha256:${HASH}\nip:203.0.113.9\ndomain:evil.example.org\n`)).toBeNull();
    expect(err("ioc/VERSION", "ioc", "2026-10-28\n")).toBeNull();
    expect(err("ioc/VERSION", "ioc", "2026-10-28")).toBeNull();
  });

  it("accepts an empty feed, which unloads nothing and matches nothing", () => {
    expect(err("ioc/empty.txt", "ioc", "")).toBeNull();
  });

  it("accepts a feed the builder itself produced, comments and all", () => {
    expect(err("ioc/lab.txt", "ioc", `# curated\n\nsha256:${HASH}\n`)).toBeNull();
  });

  it("refuses a name that is not a feed: wrong extension, nesting, a name the agent would refuse", () => {
    expect(err("ioc/lab.csv", "ioc", "")).toContain("is not a feed");
    expect(err("ioc/sub/lab.txt", "ioc", "")).toContain("is not a feed");
    expect(err("ioc/.txt", "ioc", "")).toContain("is not a feed");
    expect(err("ioc/Lab.txt", "ioc", "")).toContain("is not a feed");
    expect(err("ioc/ioc", "ioc", "")).toContain("is not a feed");
  });

  it("refuses a version file that is not one short printable line", () => {
    expect(err("ioc/VERSION", "ioc", "")).toContain("one line");
    expect(err("ioc/VERSION", "ioc", "a\nb\n")).toContain("one line");
    expect(err("ioc/VERSION", "ioc", "a b\n")).toContain("one line");
    expect(err("ioc/VERSION", "ioc", `${"v".repeat(65)}\n`)).toContain("one line");
    expect(err("ioc/VERSION", "ioc", `${"v".repeat(64)}\n`)).toBeNull();
  });

  it("refuses a feed with a line the device would skip, naming the first", () => {
    const message = err("ioc/lab.txt", "ioc", `sha256:${HASH}\nip:127.0.0.1\nsha256:zz\n`);
    expect(message).toContain("2 line(s)");
    expect(message).toContain("line 2: unusable_address");
  });

  it("refuses a line with no kind, which the device does not read", () => {
    expect(err("ioc/lab.txt", "ioc", `${HASH}\n`)).toContain("unknown_kind");
  });

  it("refuses a listed public suffix, which would flag a whole registry", () => {
    expect(err("ioc/lab.txt", "ioc", "domain:co.uk\n")).toContain("public_suffix");
    expect(err("ioc/lab.txt", "ioc", "domain:evil.co.uk\n")).toBeNull();
  });

  it("refuses a feed that is not UTF-8 text rather than reading it as one", () => {
    expect(iocEntryError({ path: "ioc/lab.txt", type: "ioc" }, Buffer.from([0xff, 0xfe, 0x00]))).not.toBeNull();
  });
});

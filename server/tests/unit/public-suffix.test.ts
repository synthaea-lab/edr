import { describe, expect, it } from "vitest";
import { isPublicSuffix } from "@/lib/public-suffix";
import { buildFeed } from "@/lib/ioc-feed";

describe("isPublicSuffix", () => {
  it("is true for ICANN suffixes and for private ones", () => {
    for (const name of ["com", "co.uk", "org.uk", "github.io", "blogspot.com", "s3.amazonaws.com"]) {
      expect(isPublicSuffix(name), name).toBe(true);
    }
  });

  it("is false for a name under a suffix, at any depth", () => {
    for (const name of ["evil.com", "evil.co.uk", "x.evil.co.uk", "attacker.github.io", "a.blogspot.com"]) {
      expect(isPublicSuffix(name), name).toBe(false);
    }
  });

  it("is false for a name the list does not know", () => {
    expect(isPublicSuffix("evil.invalid-tld-for-test")).toBe(false);
  });

  it("gates the feed builder", () => {
    const result = buildFeed({
      feed: "lab",
      text: "domain:co.uk\ndomain:github.io\ndomain:evil.co.uk\ndomain:attacker.github.io\n",
      isPublicSuffix,
    });
    expect(result.text).toBe("domain:attacker.github.io\ndomain:evil.co.uk\n");
    expect(result.rejected.map((r) => r.reason)).toEqual(["public_suffix", "public_suffix"]);
  });
});

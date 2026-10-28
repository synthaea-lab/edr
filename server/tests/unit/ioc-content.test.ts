import { describe, expect, it } from "vitest";
import { existsSync, readdirSync, readFileSync } from "fs";
import path from "path";
import { buildFeed, isValidFeedName } from "@/lib/ioc-feed";
import { isPublicSuffix } from "@/lib/public-suffix";

/**
 * Content check for `rules/ioc/` (#934, ADR-0038): every `*.txt` there is one feed, and it must be
 * a file the feed builder would publish as it stands. The builder's rules are the device's plus the
 * public-suffix check only the server can make, so this is the check the engine's own loader
 * (`crates/intel/tests/content.rs`) cannot do. Vacuous while the directory is empty.
 */
const IOC_DIR = path.join(__dirname, "../../../rules/ioc");

/** The problems with one feed file; empty when it is fit to ship. */
export function iocFileProblems(fileName: string, text: string): string[] {
  const problems: string[] = [];
  const stem = fileName.replace(/\.txt$/, "");
  if (!fileName.endsWith(".txt") || !isValidFeedName(stem)) {
    problems.push(`${fileName}: the file name must be a feed name (lowercase letters, digits, . _ -) plus .txt`);
  }
  const feed = buildFeed({ feed: isValidFeedName(stem) ? stem : "feed", text, isPublicSuffix });
  for (const r of feed.rejected) problems.push(`${fileName}:${r.line}: ${r.reason}: ${r.value}`);
  if (feed.rejectedTotal > feed.rejected.length) {
    problems.push(`${fileName}: ${feed.rejectedTotal - feed.rejected.length} more rejected lines`);
  }
  if (feed.duplicates > 0) problems.push(`${fileName}: ${feed.duplicates} duplicate indicators`);
  if (feed.read === 0) problems.push(`${fileName}: no indicator (an empty feed is a file to delete)`);
  return problems;
}

describe("iocFileProblems", () => {
  const SHA = "a".repeat(64);

  it("accepts a clean feed with comments", () => {
    expect(iocFileProblems("dropper.txt", `# draft\nsha256:${SHA}\nip:203.0.113.9\ndomain:c2.evil.example\n`)).toEqual([]);
  });

  it("refuses a public suffix, a bad line, a duplicate, an empty file and a bad file name", () => {
    const text = `domain:co.uk\nsha256:abc\nip:203.0.113.9\nip:203.0.113.9\n`;
    const problems = iocFileProblems("dropper.txt", text).join("\n");
    expect(problems).toMatch(/dropper\.txt:1: public_suffix: co\.uk/);
    expect(problems).toMatch(/dropper\.txt:2: bad_hash/);
    expect(problems).toMatch(/1 duplicate/);
    expect(iocFileProblems("empty.txt", "# nothing\n").join()).toMatch(/no indicator/);
    expect(iocFileProblems("Bad Name.txt", `sha256:${SHA}\n`).join()).toMatch(/file name/);
    expect(iocFileProblems("feed.csv", `sha256:${SHA}\n`).join()).toMatch(/file name/);
  });
});

describe("rules/ioc", () => {
  const files = existsSync(IOC_DIR) ? readdirSync(IOC_DIR).filter((f) => f !== "README.md") : [];

  it("has every feed file fit to ship", () => {
    const problems = files.flatMap((file) => iocFileProblems(file, readFileSync(path.join(IOC_DIR, file), "utf8")));
    expect(problems).toEqual([]);
  });
});

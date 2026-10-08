import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Next compiles `instrumentation.ts` for the Node AND the Edge runtime. The Edge one cannot
 * resolve `node:` modules, and when it fails the whole server stops answering (every route
 * returned 500, found in the lab run of #81, 2026-10-08). The unit tests never go through
 * Next's bundler, so this pins the two rules that keep the Edge bundle clean.
 */
const root = join(__dirname, "..", "..");
const entry = readFileSync(join(root, "instrumentation.ts"), "utf8");

describe("instrumentation.ts", () => {
  it("imports nothing at the top level: the Edge bundle would resolve it", () => {
    expect(entry).not.toMatch(/^\s*import\s/m);
  });

  it("loads the Node-only code only inside a positive NEXT_RUNTIME === nodejs check", () => {
    // An early `return` is not enough: the import after it is still resolved for Edge.
    expect(entry).toMatch(
      /if \(process\.env\.NEXT_RUNTIME === "nodejs"\) \{[\s\S]*?import\("\.\/instrumentation-node"\)/
    );
    expect(entry).not.toMatch(/NEXT_RUNTIME !== "nodejs"/);
  });

  it("keeps the Node-only modules out of instrumentation.ts itself", () => {
    expect(entry).not.toMatch(/@\/lib\/(decoy|prisma)|node:crypto/);
  });
});

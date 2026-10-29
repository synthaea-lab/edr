import { describe, expect, it } from "vitest";
import { DEFAULT_SNAPSHOT_PARAMS, guardFailure } from "@/lib/snapshot-publish";

const params = { ...DEFAULT_SNAPSHOT_PARAMS, minHostsCovered: 5, minEntryFraction: 0.5 };
const at = (s: number) => new Date(s * 1000);
const prev = { builtAt: at(1000), hostsCovered: 10, entryCount: 100 };
const build = { hostsCovered: 10, entryCount: 100, builtAt: 2000 };

describe("guardFailure (ADR-0033 decision 3)", () => {
  it("lets a healthy build through, with or without a previous one", () => {
    expect(guardFailure(params, build, null)).toBeNull();
    expect(guardFailure(params, build, prev)).toBeNull();
  });

  it("refuses a tenant with too few reporting hosts", () => {
    expect(guardFailure(params, { ...build, hostsCovered: 4 }, null)).toMatch(/only 4 hosts/);
    expect(guardFailure(params, { ...build, hostsCovered: 5 }, null)).toBeNull();
  });

  it("refuses a build that is not later than the one in force: the agent would refuse it", () => {
    expect(guardFailure(params, { ...build, builtAt: 1000 }, prev)).toMatch(/not later/);
    expect(guardFailure(params, { ...build, builtAt: 999 }, prev)).toMatch(/not later/);
    expect(guardFailure(params, { ...build, builtAt: 1001 }, prev)).toBeNull();
  });

  it("refuses a truncated build, unless the hosts covered fell too", () => {
    expect(guardFailure(params, { ...build, entryCount: 49 }, prev)).toMatch(/truncated/);
    expect(guardFailure(params, { ...build, entryCount: 50 }, prev)).toBeNull();
    // Fewer hosts reporting explains fewer common hashes.
    expect(guardFailure(params, { ...build, entryCount: 10, hostsCovered: 7 }, prev)).toBeNull();
  });

  it("compares with the previous snapshot only when there is one", () => {
    expect(guardFailure(params, { ...build, entryCount: 0 }, null)).toBeNull();
  });
});

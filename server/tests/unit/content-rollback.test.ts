import { describe, it, expect } from "vitest";
import { correctiveReleaseAdvice } from "@/lib/content-rollback";

describe("correctiveReleaseAdvice", () => {
  it("numbers the corrective release above every release of the ring and names the one to restore", () => {
    // Releases 2, 3 and 4 exist; 4 was rolled back to 2. Agents on 4 stay on 4 until a
    // release numbered above 4 carries release 2's content.
    const advice = correctiveReleaseAdvice(4, 2);
    expect(advice.releaseVersion).toBe(5);
    expect(advice.restoreVersion).toBe(2);
    expect(advice.note).toContain("numbered exactly 5");
    expect(advice.note).toContain("release 2's content");
    expect(advice.note).toContain("release-tool roll-forward");
  });

  it("says plainly that agents that already applied the release keep it", () => {
    expect(correctiveReleaseAdvice(7, 6).note).toContain("never goes to a lower release number");
  });
});

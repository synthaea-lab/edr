import { describe, it, expect } from "vitest";
import { notifyState, transitionFor } from "@/lib/notify/host-transitions";

describe("notifyState", () => {
  it("folds no_beacon into healthy: an alive host with no health says nothing", () => {
    expect(notifyState("no_beacon")).toBe("healthy");
    expect(notifyState("healthy")).toBe("healthy");
    expect(notifyState("degraded")).toBe("degraded");
    expect(notifyState("silent")).toBe("silent");
  });
});

describe("transitionFor", () => {
  it("records a first evaluation without a message", () => {
    for (const s of ["healthy", "degraded", "silent"] as const) {
      expect(transitionFor(null, s)).toEqual({ kind: "baseline" });
    }
  });

  it("says nothing while the state does not change", () => {
    for (const s of ["healthy", "degraded", "silent"] as const) {
      expect(transitionFor(s, s)).toEqual({ kind: "none" });
    }
  });

  it("names a change by what it became", () => {
    expect(transitionFor("healthy", "degraded")).toEqual({ kind: "event", event: "host.degraded" });
    expect(transitionFor("silent", "degraded")).toEqual({ kind: "event", event: "host.degraded" });
    expect(transitionFor("healthy", "silent")).toEqual({ kind: "event", event: "host.silent" });
    expect(transitionFor("degraded", "silent")).toEqual({ kind: "event", event: "host.silent" });
    expect(transitionFor("degraded", "healthy")).toEqual({ kind: "event", event: "host.recovered" });
    expect(transitionFor("silent", "healthy")).toEqual({ kind: "event", event: "host.recovered" });
  });
});

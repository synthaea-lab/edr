import { describe, expect, it } from "vitest";
import {
  FLEET_JOIN_WINDOW_MS,
  type FleetDetection,
  joinDetections,
  joinKeys,
  MAX_AGENTS_PER_ENTITY,
} from "@/lib/fleet-case";

const SHA = "a".repeat(64);
const OTHER_SHA = "b".repeat(64);
const T0 = new Date("2026-10-20T10:00:00Z");
const minutes = (n: number) => new Date(T0.getTime() + n * 60_000);

const exec = (sha256: string = SHA) => ({
  type: "exec",
  meta: { pid: 100, ppid: 1, comm: "curl", timestamp_ns: 1 },
  image_path: "/tmp/payload",
  sha256,
});
const session = (user: string) => ({ type: "session", target_user: user, meta: {} });

let seq = 0;
function detection(
  agentId: string,
  event: unknown,
  at: Date = T0,
  severity = "high"
): FleetDetection {
  return { id: `d${++seq}`, agentId, timestamp: at, severity, event };
}

describe("joinKeys", () => {
  it("an exec with a hash is keyed by the hash, lower-cased", () => {
    expect(joinKeys("a1", exec(SHA.toUpperCase()), T0)).toEqual([{ kind: "sha256", key: SHA }]);
  });

  it("an exec with no hash gives no key: a path alone is not an entity worth joining hosts on", () => {
    const event = { ...exec(), sha256: undefined };
    expect(joinKeys("a1", event, T0)).toEqual([]);
  });

  it("a session is keyed by its user, lower-cased", () => {
    expect(joinKeys("a1", session("Alice"), T0)).toEqual([{ kind: "identity", key: "alice" }]);
  });

  it.each(["root", "SYSTEM", "NT AUTHORITY\\SYSTEM", "Administrator", "nobody"])(
    "the generic account %s gives no key: every host has it",
    (user) => {
      expect(joinKeys("a1", session(user), T0)).toEqual([]);
    }
  );

  it.each([null, "text", 12, {}, { type: "exec" }, { type: "unknown", sha256: SHA }])(
    "an event of an unknown shape (%j) gives nothing and no error",
    (event) => {
      expect(joinKeys("a1", event, T0)).toEqual([]);
    }
  );
});

describe("joinDetections", () => {
  it("joins detections of two agents that carry the same hash", () => {
    const a = detection("a1", exec());
    const b = detection("a2", exec(), minutes(5));

    const groups = joinDetections([a, b]);

    expect(groups).toHaveLength(1);
    expect(groups[0].agentIds).toEqual(["a1", "a2"]);
    expect(groups[0].detectionIds.sort()).toEqual([a.id, b.id].sort());
    expect(groups[0].entities).toEqual([{ kind: "sha256", key: SHA }]);
  });

  it("does not join two detections of one agent: that is a host case, not a fleet case", () => {
    expect(joinDetections([detection("a1", exec()), detection("a1", exec(), minutes(1))])).toEqual([]);
  });

  it("does not join different hashes", () => {
    expect(joinDetections([detection("a1", exec()), detection("a2", exec(OTHER_SHA))])).toEqual([]);
  });

  it("joins on a shared identity too", () => {
    const groups = joinDetections([
      detection("a1", session("mallory")),
      detection("a2", session("Mallory"), minutes(3)),
    ]);

    expect(groups).toHaveLength(1);
    expect(groups[0].entities).toEqual([{ kind: "identity", key: "mallory" }]);
  });

  it("one group when two entities connect the same agents, and when a third agent bridges two groups", () => {
    const groups = joinDetections([
      detection("a1", exec()),
      detection("a2", exec(), minutes(1)),
      detection("a2", session("mallory"), minutes(2)),
      detection("a3", session("mallory"), minutes(3)),
    ]);

    expect(groups).toHaveLength(1);
    expect(groups[0].agentIds).toEqual(["a1", "a2", "a3"]);
    expect(groups[0].entities).toEqual([
      { kind: "identity", key: "mallory" },
      { kind: "sha256", key: SHA },
    ]);
  });

  it("keeps unrelated groups apart", () => {
    const groups = joinDetections([
      detection("a1", exec()),
      detection("a2", exec(), minutes(1)),
      detection("a3", exec(OTHER_SHA)),
      detection("a4", exec(OTHER_SHA), minutes(1)),
    ]);

    expect(groups).toHaveLength(2);
    expect(groups.map((g) => g.agentIds)).toEqual([["a1", "a2"], ["a3", "a4"]]);
  });

  it("takes the highest severity, and the first and last time of the group", () => {
    const [group] = joinDetections([
      detection("a1", exec(), minutes(0), "medium"),
      detection("a2", exec(), minutes(9), "critical"),
      detection("a3", exec(), minutes(4), "low"),
    ]);

    expect(group.severity).toBe("critical");
    expect(group.firstAt).toEqual(minutes(0));
    expect(group.lastAt).toEqual(minutes(9));
  });

  describe("the window", () => {
    it("does not join two sightings of the same entity further apart than the window", () => {
      const late = new Date(T0.getTime() + FLEET_JOIN_WINDOW_MS + 1);
      expect(joinDetections([detection("a1", exec()), detection("a2", exec(), late)])).toEqual([]);
    });

    it("joins them at exactly the window: the bound is inclusive", () => {
      const edge = new Date(T0.getTime() + FLEET_JOIN_WINDOW_MS);
      expect(joinDetections([detection("a1", exec()), detection("a2", exec(), edge)])).toHaveLength(1);
    });

    it("a chain of sightings each within the window of the next is one group, however long", () => {
      const step = FLEET_JOIN_WINDOW_MS - 1;
      const groups = joinDetections([
        detection("a1", exec(), new Date(T0.getTime())),
        detection("a2", exec(), new Date(T0.getTime() + step)),
        detection("a3", exec(), new Date(T0.getTime() + 2 * step)),
      ]);
      expect(groups).toHaveLength(1);
      expect(groups[0].agentIds).toEqual(["a1", "a2", "a3"]);
    });
  });

  describe("an entity that is everywhere", () => {
    const fleet = (n: number) =>
      Array.from({ length: n }, (_, i) => detection(`agent-${String(i).padStart(3, "0")}`, exec(), minutes(i % 5)));

    it("joins up to the cap", () => {
      const [group] = joinDetections(fleet(MAX_AGENTS_PER_ENTITY));
      expect(group.agentIds).toHaveLength(MAX_AGENTS_PER_ENTITY);
    });

    it("joins nothing past the cap: a hash on that many hosts is software, not an intrusion, and one decoy hash must not link the whole fleet", () => {
      expect(joinDetections(fleet(MAX_AGENTS_PER_ENTITY + 1))).toEqual([]);
    });

    it("the cap does not stop other entities from joining", () => {
      const groups = joinDetections([
        ...fleet(MAX_AGENTS_PER_ENTITY + 1),
        detection("x1", exec(OTHER_SHA)),
        detection("x2", exec(OTHER_SHA), minutes(1)),
      ]);
      expect(groups).toHaveLength(1);
      expect(groups[0].entities).toEqual([{ kind: "sha256", key: OTHER_SHA }]);
    });
  });

  it("gives the same groups whatever the order of the input", () => {
    const input = [
      detection("a1", exec(), minutes(0)),
      detection("a2", exec(), minutes(1)),
      detection("a2", session("mallory"), minutes(2)),
      detection("a3", session("mallory"), minutes(3)),
      detection("a4", exec(OTHER_SHA)),
      detection("a5", exec(OTHER_SHA), minutes(2)),
    ];
    const forward = joinDetections(input);

    expect(joinDetections([...input].reverse())).toEqual(forward);
    expect(joinDetections([input[3], input[0], input[5], input[2], input[4], input[1]])).toEqual(forward);
  });

  it("detections that carry no entity are ignored", () => {
    expect(joinDetections([detection("a1", { test: "data" }), detection("a2", { test: "data" })])).toEqual([]);
  });
});

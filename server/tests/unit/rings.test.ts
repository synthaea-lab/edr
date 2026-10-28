import { describe, expect, it, vi } from "vitest";
import { loadRings } from "@/lib/rings";
import { FLEET_PAGE_SIZE } from "@/lib/fleet";

const NOW = new Date("2026-10-01T12:00:00Z");
const release = (releaseVersion: number, status: string) => ({
  releaseVersion,
  status,
  releasedAt: new Date("2026-09-30T00:00:00Z"),
});

/** A stub db: `releases` per ring, newest first; agents already shaped like Prisma rows. */
function stubDb(
  releases: Record<string, ReturnType<typeof release>[]>,
  agents: {
    ring: string;
    lastSeen: Date;
    sensors?: { name: string; silent: boolean }[];
    lossObservedAt?: Date;
  }[]
) {
  return {
    agent: {
      findMany: vi.fn().mockResolvedValue(
        agents.map((a, i) => ({
          id: `a${i}`,
          hostname: `h${i}`,
          ring: a.ring,
          version: "0.1.0",
          lastSeen: a.lastSeen,
          health: a.sensors
            ? {
                beaconAt: NOW,
                agentVersion: "0.1.0",
                spoolBytes: BigInt(0),
                spoolDropped: BigInt(0),
                enrichDropped: BigInt(0),
                lossObservedAt: a.lossObservedAt ?? null,
                sensors: a.sensors.map((s) => ({ ...s, pulse_count: 1 })),
              }
            : null,
        }))
      ),
    },
    contentRelease: {
      findFirst: vi.fn(
        ({ where }: { where: { ring: string; status?: string; releaseVersion?: { lt: number } } }) =>
          Promise.resolve(
            (releases[where.ring] ?? []).find(
              (r) =>
                (!where.status || r.status === where.status) &&
                (!where.releaseVersion || r.releaseVersion < where.releaseVersion.lt)
            ) ?? null
          )
      ),
    },
  };
}

describe("loadRings (issue #83)", () => {
  it("shows a halted newest release and offers no content until resume or rollback", async () => {
    const db = stubDb({ canary_0: [release(5, "halted"), release(4, "active")] }, []);
    const { rings } = await loadRings(db as never, "t1", NOW);
    const ring = rings.find((r) => r.ring === "canary_0");
    expect(ring).toMatchObject({ rollout: "halted", latestVersion: 5, servedVersion: null });
  });

  it("reports a ring with no release, and one whose every release was rolled back", async () => {
    const db = stubDb({ canary_1: [release(2, "rolled_back")] }, []);
    const { rings } = await loadRings(db as never, "t1", NOW);
    expect(rings.find((r) => r.ring === "canary_0")).toMatchObject({
      rollout: "no_release",
      latestVersion: null,
      servedVersion: null,
    });
    expect(rings.find((r) => r.ring === "canary_1")).toMatchObject({
      rollout: "rolled_back",
      latestVersion: 2,
      servedVersion: null,
    });
  });

  it("says whether a serving or halted ring has an earlier release to roll back to, and nothing else does", async () => {
    const db = stubDb(
      {
        canary_0: [release(2, "active"), release(1, "rolled_back")],
        canary_1: [release(1, "active")],
        canary_2: [release(3, "halted"), release(2, "active")],
        prod: [release(2, "rolled_back"), release(1, "active")],
      },
      []
    );
    const { rings } = await loadRings(db as never, "t1", NOW);
    const has = (ring: string) => rings.find((r) => r.ring === ring)?.hasEarlierRelease;
    expect(has("canary_0")).toBe(true); // an earlier release of any status is a target, as in the route
    expect(has("canary_1")).toBe(false); // a single release
    expect(has("canary_2")).toBe(true);
    expect(has("prod")).toBe(false); // already rolled back: nothing to offer
    const empty = await loadRings(stubDb({}, []) as never, "t1", NOW);
    expect(empty.rings.every((r) => r.hasEarlierRelease === false)).toBe(true);
  });

  it("counts each ring's agents by health status and keeps the rings apart", async () => {
    const recent = new Date(NOW.getTime() - 1000);
    const old = new Date(NOW.getTime() - 3_600_000);
    const db = stubDb({ prod: [release(1, "active")] }, [
      { ring: "prod", lastSeen: recent, sensors: [{ name: "s", silent: false }] },
      { ring: "prod", lastSeen: recent, sensors: [{ name: "s", silent: true }] },
      { ring: "prod", lastSeen: old },
      { ring: "canary_0", lastSeen: recent },
    ]);
    const { rings } = await loadRings(db as never, "t1", NOW);
    const prod = rings.find((r) => r.ring === "prod");
    expect(prod).toMatchObject({ rollout: "serving", agents: 3 });
    expect(prod?.byStatus).toEqual({ healthy: 1, degraded: 1, silent: 1, no_beacon: 0 });
    expect(rings.find((r) => r.ring === "canary_0")?.agents).toBe(1);
  });

  it("counts a host that lost telemetry recently as degraded in its ring (#83)", async () => {
    const recent = new Date(NOW.getTime() - 1000);
    const db = stubDb({}, [
      { ring: "prod", lastSeen: recent, sensors: [{ name: "s", silent: false }] },
      {
        ring: "prod",
        lastSeen: recent,
        sensors: [{ name: "s", silent: false }],
        lossObservedAt: new Date(NOW.getTime() - 60_000),
      },
    ]);
    const { rings } = await loadRings(db as never, "t1", NOW);
    expect(rings.find((r) => r.ring === "prod")?.byStatus).toEqual({
      healthy: 1,
      degraded: 1,
      silent: 0,
      no_beacon: 0,
    });
  });

  it("says when the agent counts cover only one page of the fleet", async () => {
    const agents = Array.from({ length: FLEET_PAGE_SIZE }, () => ({ ring: "prod", lastSeen: NOW }));
    const { truncated } = await loadRings(stubDb({}, agents) as never, "t1", NOW);
    expect(truncated).toBe(true);
    expect((await loadRings(stubDb({}, []) as never, "t1", NOW)).truncated).toBe(false);
  });
});

import { describe, expect, it } from "vitest";
import { beaconTime, parseHeartbeatBody } from "@/lib/health-beacon";
import { SILENCE_THRESHOLD_MS, fleetStatus, sensorsOf } from "@/lib/fleet-health";

const beacon = (over: Record<string, unknown> = {}) => ({
  timestamp_ns: 1_790_000_000_000_000_000,
  agent_version: "0.1.0",
  sensors: [{ name: "linux-ebpf", pulse_count: 10, silent: false }],
  spool_bytes: 0,
  spool_dropped: 0,
  enrich_dropped: 0,
  ...over,
});

describe("parseHeartbeatBody", () => {
  it("reads the beacon the agent posts inside { agent_id, beacon }", () => {
    const parsed = parseHeartbeatBody({ agent_id: "a1", beacon: beacon() });
    expect(parsed?.sensors[0].name).toBe("linux-ebpf");
    expect(parsed && beaconTime(parsed).toISOString()).toBe("2026-09-21T14:13:20.000Z");
  });

  it("returns null for a body with no usable beacon instead of throwing", () => {
    for (const body of [null, "x", 7, {}, { beacon: null }, { beacon: { timestamp_ns: 1 } }]) {
      expect(parseHeartbeatBody(body)).toBeNull();
    }
  });

  it("refuses a beacon that would store unbounded or nonsensical data", () => {
    const many = Array.from({ length: 65 }, (_, i) => ({ name: `s${i}`, pulse_count: 0, silent: false }));
    expect(parseHeartbeatBody({ beacon: beacon({ sensors: many }) })).toBeNull();
    expect(parseHeartbeatBody({ beacon: beacon({ spool_bytes: -1 }) })).toBeNull();
    expect(parseHeartbeatBody({ beacon: beacon({ enrich_dropped: 1.5 }) })).toBeNull();
    expect(parseHeartbeatBody({ beacon: beacon({ agent_version: "v".repeat(129) }) })).toBeNull();
  });
});

describe("fleetStatus", () => {
  const now = new Date("2026-10-01T12:00:00Z");
  const seen = (msAgo: number) => ({ lastSeen: new Date(now.getTime() - msAgo) });
  const sensor = (silent: boolean) => ({ name: "linux-ebpf", pulse_count: 1, silent });

  it("calls an agent with a silent sensor degraded, not healthy", () => {
    expect(fleetStatus(seen(1000), { sensors: [sensor(false), sensor(true)] }, now)).toBe("degraded");
    expect(fleetStatus(seen(1000), { sensors: [sensor(false)] }, now)).toBe("healthy");
  });

  it("calls an agent that stopped heartbeating silent even if its last beacon looked fine", () => {
    expect(fleetStatus(seen(SILENCE_THRESHOLD_MS + 1), { sensors: [sensor(false)] }, now)).toBe("silent");
    expect(fleetStatus(seen(SILENCE_THRESHOLD_MS), { sensors: [sensor(false)] }, now)).toBe("healthy");
  });

  it("separates an agent that never sent a beacon from a healthy one", () => {
    expect(fleetStatus(seen(1000), null, now)).toBe("no_beacon");
  });
});

describe("sensorsOf", () => {
  it("keeps well-formed sensors and drops the rest of a row written by another version", () => {
    expect(
      sensorsOf([{ name: "a", pulse_count: 3, silent: true }, { name: 5 }, null, "x"])
    ).toEqual([{ name: "a", pulse_count: 3, silent: true }]);
    expect(sensorsOf("not an array")).toEqual([]);
  });
});

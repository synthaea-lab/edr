import { describe, expect, it } from "vitest";
import { beaconTime, parseHeartbeatBody } from "@/lib/health-beacon";
import {
  LOSS_WINDOW_MS,
  SILENCE_THRESHOLD_MS,
  fleetStatus,
  nextLossObservedAt,
  sensorsOf,
} from "@/lib/fleet-health";

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

  it("reads the rarity evidence counters, and counts them as zero for an agent that predates them", () => {
    const withCounters = parseHeartbeatBody({
      beacon: beacon({ rarity_applied: 7, rarity_withheld: 11, rarity_unapplied: 2 }),
    });
    expect([withCounters?.rarity_applied, withCounters?.rarity_withheld, withCounters?.rarity_unapplied]).toEqual([7, 11, 2]);

    // `beacon()` carries none: an older agent's beacon must still be stored, as zeros.
    const old = parseHeartbeatBody({ beacon: beacon() });
    expect([old?.rarity_applied, old?.rarity_withheld, old?.rarity_unapplied]).toEqual([0, 0, 0]);
  });

  it("reads the watchdog, tamper and eviction counters, and counts them as zero for an agent that predates them (#863)", () => {
    const withCounters = parseHeartbeatBody({
      beacon: beacon({
        watchdog_restarts: 3,
        tamper_events: 5,
        parent_image_evicted_live: 13,
        parent_image_evicted_dead: 209000,
      }),
    });
    expect([
      withCounters?.watchdog_restarts,
      withCounters?.tamper_events,
      withCounters?.parent_image_evicted_live,
      withCounters?.parent_image_evicted_dead,
    ]).toEqual([3, 5, 13, 209000]);

    const old = parseHeartbeatBody({ beacon: beacon() });
    expect([old?.watchdog_restarts, old?.tamper_events, old?.parent_image_evicted_live, old?.parent_image_evicted_dead]).toEqual([0, 0, 0, 0]);
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
    expect(parseHeartbeatBody({ beacon: beacon({ rarity_applied: -1 }) })).toBeNull();
    expect(parseHeartbeatBody({ beacon: beacon({ rarity_withheld: 0.5 }) })).toBeNull();
    expect(parseHeartbeatBody({ beacon: beacon({ rarity_unapplied: "3" }) })).toBeNull();
    for (const field of ["watchdog_restarts", "tamper_events", "parent_image_evicted_live", "parent_image_evicted_dead"]) {
      expect(parseHeartbeatBody({ beacon: beacon({ [field]: -1 }) }), `${field} -1`).toBeNull();
      expect(parseHeartbeatBody({ beacon: beacon({ [field]: 0.5 }) }), `${field} 0.5`).toBeNull();
      expect(parseHeartbeatBody({ beacon: beacon({ [field]: "3" }) }), `${field} "3"`).toBeNull();
    }
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

describe("fleetStatus and recent telemetry loss (#83)", () => {
  const now = new Date("2026-10-01T12:00:00Z");
  const seen = { lastSeen: new Date(now.getTime() - 1000) };
  const ok = [{ name: "linux-ebpf", pulse_count: 1, silent: false }];
  const lostAgo = (ms: number) => new Date(now.getTime() - ms);

  it("calls a host degraded while it lost telemetry within the window, and healthy after", () => {
    expect(fleetStatus(seen, { sensors: ok, lossObservedAt: lostAgo(1000) }, now)).toBe("degraded");
    expect(fleetStatus(seen, { sensors: ok, lossObservedAt: lostAgo(LOSS_WINDOW_MS - 1) }, now)).toBe("degraded");
    expect(fleetStatus(seen, { sensors: ok, lossObservedAt: lostAgo(LOSS_WINDOW_MS) }, now)).toBe("healthy");
  });

  it("leaves a host that never lost anything, or whose beacon has no loss field, healthy", () => {
    expect(fleetStatus(seen, { sensors: ok, lossObservedAt: null }, now)).toBe("healthy");
    expect(fleetStatus(seen, { sensors: ok }, now)).toBe("healthy");
  });

  it("keeps silent and no_beacon ahead of loss, and loss does not hide a silent sensor", () => {
    const stale = { lastSeen: new Date(now.getTime() - SILENCE_THRESHOLD_MS - 1) };
    expect(fleetStatus(stale, { sensors: ok, lossObservedAt: lostAgo(1000) }, now)).toBe("silent");
    expect(fleetStatus(seen, null, now)).toBe("no_beacon");
    expect(
      fleetStatus(seen, { sensors: [{ name: "s", pulse_count: 1, silent: true }], lossObservedAt: null }, now)
    ).toBe("degraded");
  });
});

describe("nextLossObservedAt (#83)", () => {
  const T0 = 1_790_000_000_000_000_000;
  const beacon = (over: Record<string, number> = {}) => ({
    timestamp_ns: T0 + 30_000_000_000,
    spool_dropped: 0,
    enrich_dropped: 0,
    ...over,
  });
  const stored = (over: Record<string, unknown> = {}) => ({
    beaconAt: new Date(T0 / 1_000_000),
    spoolDropped: BigInt(0),
    enrichDropped: BigInt(0),
    lossObservedAt: null as Date | null,
    ...over,
  });
  const received = new Date("2026-10-01T12:00:00Z");
  const earlier = new Date("2026-10-01T11:00:00Z");

  it("never counts the first beacon of an agent as loss, whatever its counters say", () => {
    expect(nextLossObservedAt(null, beacon({ spool_dropped: 5, enrich_dropped: 9 }), received)).toEqual({
      stale: false,
      lossObservedAt: null,
    });
  });

  it("stamps the receive time when either loss counter rose", () => {
    expect(nextLossObservedAt(stored(), beacon({ spool_dropped: 1 }), received).lossObservedAt).toEqual(received);
    expect(nextLossObservedAt(stored(), beacon({ enrich_dropped: 3 }), received).lossObservedAt).toEqual(received);
    // One counter falling does not cancel the other rising.
    expect(
      nextLossObservedAt(stored({ spoolDropped: BigInt(9) }), beacon({ spool_dropped: 0, enrich_dropped: 2 }), received)
        .lossObservedAt
    ).toEqual(received);
  });

  it("keeps what it had when nothing rose, including after an agent restart reset the counters", () => {
    expect(nextLossObservedAt(stored({ lossObservedAt: earlier }), beacon(), received).lossObservedAt).toEqual(earlier);
    const restarted = nextLossObservedAt(
      stored({ spoolDropped: BigInt(4096), enrichDropped: BigInt(7560), lossObservedAt: earlier }),
      beacon({ spool_dropped: 0, enrich_dropped: 0 }),
      received
    );
    expect(restarted).toEqual({ stale: false, lossObservedAt: earlier });
    expect(nextLossObservedAt(stored(), beacon(), received).lossObservedAt).toBeNull();
  });

  it("flags a beacon older than the stored one, so its lower counters are not stored", () => {
    expect(nextLossObservedAt(stored(), beacon({ timestamp_ns: T0 - 1_000_000_000 }), received).stale).toBe(true);
    // The same instant is a replay or a coarse clock, not an older beacon: same counters, no loss.
    expect(nextLossObservedAt(stored(), beacon({ timestamp_ns: T0 }), received).stale).toBe(false);
    expect(nextLossObservedAt(stored(), beacon({ timestamp_ns: T0 + 1_000_000 }), received).stale).toBe(false);
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

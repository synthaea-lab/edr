/** Matches the silent-agent cron: no heartbeat for this long means silent. */
export const SILENCE_THRESHOLD_MS = 5 * 60 * 1000;

/** How long after a loss counter last rose a host still counts as degraded for it (#83). */
export const LOSS_WINDOW_MS = 10 * 60 * 1000;

export type FleetStatus = "silent" | "degraded" | "healthy" | "no_beacon";

export type SensorState = { name: string; pulse_count: number; silent: boolean };

/**
 * One agent's place on the dashboard, worst first: `silent` (no heartbeat),
 * `degraded` (heartbeating, but a sensor reports silent, or it lost telemetry within
 * [`LOSS_WINDOW_MS`]: see [`nextLossObservedAt`]), `no_beacon` (alive, but never sent
 * health: an older agent, or one whose beacons are rejected), else `healthy`. A silent
 * agent's last beacon is stale, so its sensors are not reported as the reason.
 */
export function fleetStatus(
  agent: { lastSeen: Date },
  health: { sensors: SensorState[]; lossObservedAt?: Date | null } | null,
  now: Date
): FleetStatus {
  if (now.getTime() - agent.lastSeen.getTime() > SILENCE_THRESHOLD_MS) return "silent";
  if (!health) return "no_beacon";
  return health.sensors.some((s) => s.silent) || lostRecently(health.lossObservedAt, now)
    ? "degraded"
    : "healthy";
}

/** Whether `lossObservedAt` is within [`LOSS_WINDOW_MS`] of `now`. */
export function lostRecently(lossObservedAt: Date | null | undefined, now: Date): boolean {
  return !!lossObservedAt && now.getTime() - lossObservedAt.getTime() < LOSS_WINDOW_MS;
}

/** What `agent_health` holds about an agent's last beacon, as far as loss detection reads it. */
export type StoredLoss = {
  beaconAt: Date;
  spoolDropped: bigint;
  enrichDropped: bigint;
  lossObservedAt: Date | null;
};

/**
 * The loss stamp after a beacon arrives (#83). The agent's loss counters (`spool_dropped`,
 * `enrich_dropped`) are cumulative since it started and the server keeps only the latest beacon,
 * so a recent loss is told by a counter *rising* between two beacons, stamped with the server's
 * receive time (not the agent's clock, which can be skewed).
 *
 * - The first beacon of an agent is never loss: it has nothing to compare with, and a row
 *   missing for another reason (a reset database) must not flag a healthy host.
 * - A counter that fell is an agent restart, not loss, and neither sets nor clears the stamp.
 * - A beacon older than the stored one is `stale`: the caller must not store it, or its lower
 *   counters would make the next real beacon look like a rise.
 * - Only the two loss counters count; the rarity evidence counters are information about a
 *   feature, not lost telemetry.
 */
export function nextLossObservedAt(
  previous: StoredLoss | null,
  beacon: { timestamp_ns: number; spool_dropped: number; enrich_dropped: number },
  receivedAt: Date
): { stale: boolean; lossObservedAt: Date | null } {
  if (!previous) return { stale: false, lossObservedAt: null };
  if (Math.floor(beacon.timestamp_ns / 1_000_000) < previous.beaconAt.getTime()) {
    return { stale: true, lossObservedAt: previous.lossObservedAt };
  }
  const rose =
    BigInt(beacon.spool_dropped) > previous.spoolDropped ||
    BigInt(beacon.enrich_dropped) > previous.enrichDropped;
  return { stale: false, lossObservedAt: rose ? receivedAt : previous.lossObservedAt };
}

/** Sensors from stored JSON, tolerating a row written by a different version. */
export function sensorsOf(json: unknown): SensorState[] {
  if (!Array.isArray(json)) return [];
  return json.flatMap((s) =>
    s && typeof s.name === "string" && typeof s.silent === "boolean"
      ? [{ name: s.name, pulse_count: Number(s.pulse_count) || 0, silent: s.silent }]
      : []
  );
}

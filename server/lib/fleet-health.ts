/** Matches the silent-agent cron: no heartbeat for this long means silent. */
export const SILENCE_THRESHOLD_MS = 5 * 60 * 1000;

export type FleetStatus = "silent" | "degraded" | "healthy" | "no_beacon";

export type SensorState = { name: string; pulse_count: number; silent: boolean };

/**
 * One agent's place on the dashboard, worst first: `silent` (no heartbeat),
 * `degraded` (heartbeating, but a sensor reports silent), `no_beacon` (alive,
 * but never sent health: an older agent, or one whose beacons are rejected),
 * else `healthy`. A silent agent's last beacon is stale, so its sensors are
 * not reported as the reason.
 */
export function fleetStatus(
  agent: { lastSeen: Date },
  health: { sensors: SensorState[] } | null,
  now: Date
): FleetStatus {
  if (now.getTime() - agent.lastSeen.getTime() > SILENCE_THRESHOLD_MS) return "silent";
  if (!health) return "no_beacon";
  return health.sensors.some((s) => s.silent) ? "degraded" : "healthy";
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

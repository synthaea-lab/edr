import { z } from "zod";

/** More sensors than any platform loads; bounds what one beacon can store. */
const MAX_SENSORS = 64;
const MAX_NAME = 128;

const counter = z.number().int().nonnegative().finite();

/**
 * One serialized `schema::HealthBeacon` (what `transport` posts as
 * `{ agent_id, beacon }`). Counters are `u64` on the agent; JSON numbers hold
 * them exactly up to 2^53, far beyond any real spool or drop count.
 */
export const HealthBeacon = z.object({
  timestamp_ns: counter,
  agent_version: z.string().max(MAX_NAME),
  sensors: z
    .array(
      z.object({
        name: z.string().min(1).max(MAX_NAME),
        pulse_count: counter,
        silent: z.boolean(),
      })
    )
    .max(MAX_SENSORS),
  spool_bytes: counter,
  spool_dropped: counter,
  enrich_dropped: counter,
});
export type HealthBeacon = z.infer<typeof HealthBeacon>;

/**
 * The beacon inside a heartbeat request body, or `null` when the body is not
 * one. A heartbeat without a usable beacon is still a heartbeat (liveness
 * matters more than telemetry), so callers ignore `null` rather than reject.
 */
export function parseHeartbeatBody(body: unknown): HealthBeacon | null {
  if (typeof body !== "object" || body === null) return null;
  const parsed = HealthBeacon.safeParse((body as Record<string, unknown>).beacon);
  return parsed.success ? parsed.data : null;
}

/** The agent's `timestamp_ns` as a Date (millisecond precision). */
export function beaconTime(beacon: HealthBeacon): Date {
  return new Date(Math.floor(beacon.timestamp_ns / 1_000_000));
}

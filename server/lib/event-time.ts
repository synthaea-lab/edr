/** One day: an agent clock further ahead than this is treated as unset rather than believed. */
export const MAX_CLOCK_SKEW_MS = 24 * 60 * 60 * 1000;

/**
 * When an event happened, from its `meta.timestamp_ns`. A missing, non-numeric,
 * non-positive or far-future stamp becomes `now`: an enrolled agent with a bad
 * clock must not be able to backdate or postdate a sighting and so bend
 * "first seen on the fleet", nor choose the day partition its event lands in.
 */
export function eventTime(event: Record<string, unknown>, now: Date): Date {
  const meta = event.meta;
  const ns =
    typeof meta === "object" && meta !== null
      ? (meta as Record<string, unknown>).timestamp_ns
      : undefined;
  if (typeof ns !== "number" || !Number.isFinite(ns) || ns <= 0) return now;
  const at = new Date(Math.floor(ns / 1_000_000));
  return at.getTime() > now.getTime() + MAX_CLOCK_SKEW_MS ? now : at;
}

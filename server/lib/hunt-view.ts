import { HuntValidationError, parseHuntQuery } from "@/lib/hunt";

/**
 * What the console shows of a saved hunt (#61). Pure functions over what the database
 * holds, so the pages stay thin and the wording is tested without rendering anything.
 */

/**
 * A run whose row says it has not finished is "running" for this long after it started
 * (the search itself is capped well below it), and "interrupted" after: the server that
 * started it died, and nothing will finish it.
 */
export const RUNNING_GRACE_MS = 30_000;

/** The query in one line: "last 7 days · T1059, T1003 · high, critical · 2 hosts · text “mimikatz”". */
export function describeQuery(query: unknown): string {
  let parsed;
  try {
    parsed = parseHuntQuery(query);
  } catch (error) {
    if (error instanceof HuntValidationError) return "stored query no longer valid";
    throw error;
  }
  const parts = [parsed.lastHours % 24 === 0 ? `last ${parsed.lastHours / 24} d` : `last ${parsed.lastHours} h`];
  if (parsed.techniques?.length) parts.push(parsed.techniques.join(", "));
  if (parsed.severities?.length) parts.push(parsed.severities.join(", "));
  if (parsed.agentIds?.length) parts.push(`${parsed.agentIds.length} host${parsed.agentIds.length === 1 ? "" : "s"}`);
  if (parsed.text) parts.push(`text “${parsed.text}”`);
  return parts.join(" · ");
}

/** "manual only", "every 15 min", "every 2 h", "every day", with "paused" when the hunt is inactive. */
export function describeSchedule(scheduleMinutes: number | null, active: boolean): string {
  if (scheduleMinutes === null) return "manual only";
  let every: string;
  if (scheduleMinutes % 1440 === 0) every = scheduleMinutes === 1440 ? "every day" : `every ${scheduleMinutes / 1440} d`;
  else if (scheduleMinutes % 60 === 0) every = `every ${scheduleMinutes / 60} h`;
  else every = `every ${scheduleMinutes} min`;
  return active ? every : `${every}, paused`;
}

export type RunState = "running" | "ok" | "failed" | "interrupted";

export type RunLike = { startedAt: Date; finishedAt: Date | null; error: string | null };

/** `finishedAt` null is a run in flight, or one that never finished; an `error` is a failed run. */
export function runState(run: RunLike, now: Date): RunState {
  if (run.error) return "failed";
  if (run.finishedAt) return "ok";
  return now.getTime() - run.startedAt.getTime() < RUNNING_GRACE_MS ? "running" : "interrupted";
}

/** "2026-10-15 14:03 UTC": a fixed zone, so the page reads the same wherever it is opened. */
export function formatTime(date: Date): string {
  return `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

/** How long a finished run took ("0.4 s", "12 s"), or null while it has not finished. */
export function formatDuration(run: RunLike): string | null {
  if (!run.finishedAt) return null;
  const ms = Math.max(0, run.finishedAt.getTime() - run.startedAt.getTime());
  return ms < 10_000 ? `${(ms / 1000).toFixed(1)} s` : `${Math.round(ms / 1000)} s`;
}

/**
 * What the "Run now" button tells the user about the answer of `POST /api/hunts/[id]/run`:
 * null when the run completed, a sentence otherwise. The API answers 200 for a run that
 * failed (its `error` is set), 429 when the tenant used its runs for the minute.
 */
export function runResponseMessage(status: number, body: unknown): string | null {
  const record = typeof body === "object" && body !== null ? (body as Record<string, unknown>) : {};
  if (status >= 200 && status < 300) {
    const run = record.run as { error?: unknown } | undefined;
    return typeof run?.error === "string" && run.error ? `The run failed: ${run.error}` : null;
  }
  if (typeof record.error === "string" && record.error) return record.error;
  return `Request failed with status ${status}`;
}

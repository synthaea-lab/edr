import {
  HuntValidationError,
  MAX_SCHEDULE_MINUTES,
  MIN_SCHEDULE_MINUTES,
  parseHuntQuery,
  type HuntQuery,
} from "@/lib/hunt";

export type HuntInput = {
  name?: string;
  description?: string | null;
  query?: HuntQuery;
  /** `null` clears the schedule (manual only). */
  scheduleMinutes?: number | null;
  active?: boolean;
};

const NAME_MAX = 120;
const DESCRIPTION_MAX = 2000;

/**
 * Validates a create or update body. `partial` (update) allows every field to be
 * absent; a create needs `name` and `query`. Throws `HuntValidationError`.
 */
export function parseHuntInput(body: unknown, partial: boolean): HuntInput {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new HuntValidationError("body must be an object");
  }
  const raw = body as Record<string, unknown>;
  const allowed = ["name", "description", "query", "scheduleMinutes", "active"];
  for (const key of Object.keys(raw)) {
    if (!allowed.includes(key)) throw new HuntValidationError(`unknown field "${key}"`);
  }
  const input: HuntInput = {};

  if (raw.name !== undefined || !partial) {
    if (typeof raw.name !== "string" || raw.name.trim().length < 1 || raw.name.trim().length > NAME_MAX) {
      throw new HuntValidationError(`name must be 1 to ${NAME_MAX} characters`);
    }
    input.name = raw.name.trim();
  }
  if (raw.description !== undefined) {
    if (raw.description !== null && (typeof raw.description !== "string" || raw.description.length > DESCRIPTION_MAX)) {
      throw new HuntValidationError(`description must be a string of at most ${DESCRIPTION_MAX} characters`);
    }
    input.description = raw.description as string | null;
  }
  if (raw.query !== undefined || !partial) {
    input.query = parseHuntQuery(raw.query);
  }
  if (raw.scheduleMinutes !== undefined) {
    const m = raw.scheduleMinutes;
    if (m !== null && (!Number.isInteger(m) || (m as number) < MIN_SCHEDULE_MINUTES || (m as number) > MAX_SCHEDULE_MINUTES)) {
      throw new HuntValidationError(
        `scheduleMinutes must be null or an integer from ${MIN_SCHEDULE_MINUTES} to ${MAX_SCHEDULE_MINUTES}`
      );
    }
    input.scheduleMinutes = m as number | null;
  }
  if (raw.active !== undefined) {
    if (typeof raw.active !== "boolean") throw new HuntValidationError("active must be a boolean");
    input.active = raw.active;
  }
  return input;
}

/** True when two normalized queries are the same, whatever the key order they were sent in. */
export function sameQuery(a: HuntQuery, b: HuntQuery): boolean {
  const norm = (q: HuntQuery) =>
    JSON.stringify({
      ...q,
      techniques: q.techniques ? [...q.techniques].sort() : undefined,
      severities: q.severities ? [...q.severities].sort() : undefined,
      agentIds: q.agentIds ? [...q.agentIds].sort() : undefined,
    });
  return norm(a) === norm(b);
}

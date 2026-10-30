import { HuntValidationError, stringList } from "@/lib/hunt";

/**
 * The query of the hunt `events` source: the raw event archive (the telemetry lake, issue #77,
 * ADR-0041), searched through `queryLake` (issue #933, ADR-0025 point 10).
 *
 * Like `HuntQuery` and `CaseQuery` it is structured, never SQL, validated on every use, and refuses
 * unknown fields. It carries no tenant: the tenant is the session's and is given to the search by
 * the server, so there is no field, and no code path, through which a request names another one.
 *
 * Pure (no Prisma, no file access), like `lib/hunt.ts`: parsing is shared with client code.
 */

export const EVENT_QUERY_VERSION = 1;
/** Longest window, in UTC days: the lake's default retention (ADR-0041), and a hunt's own ceiling (90 days). */
export const MAX_EVENT_WINDOW_DAYS = 90;
/** Event types one query may name. */
export const MAX_EVENT_TYPES = 20;
/** Longest value of an equality filter; the writer bounds the typed columns to the same length. */
export const MAX_FILTER_LENGTH = 1024;

/** The typed columns a filter can test, as `queryLake` names them. */
export const EVENT_FILTERS = ["agentId", "comm", "path", "imagePath", "daddr", "query", "sha256"] as const;
export type EventFilterName = (typeof EVENT_FILTERS)[number];

export type EventQuery = {
  kind: "events";
  version: typeof EVENT_QUERY_VERSION;
  /** The last N UTC days including today (`1` is today only). The window is whole days: the archive is partitioned by day. */
  lastDays: number;
  /** Event types (the lake's `type=` segment, `[a-z][a-z0-9_]{0,63}`). Absent: every type. */
  types?: string[];
  /** Exact matches on typed columns, all of which must hold. `sha256` is 64 hex digits. */
  where?: Partial<Record<EventFilterName, string>>;
};

const TYPE_RE = /^[a-z][a-z0-9_]{0,63}$/;
const SHA256_RE = /^[0-9a-f]{64}$/i;

function fail(message: string): never {
  throw new HuntValidationError(message);
}

/** Validates untrusted JSON as an `EventQuery` and returns it normalized; throws `HuntValidationError`. */
export function parseEventQuery(input: unknown): EventQuery {
  if (typeof input !== "object" || input === null || Array.isArray(input)) fail("query must be an object");
  const raw = input as Record<string, unknown>;
  const allowed = new Set(["kind", "version", "lastDays", "types", "where"]);
  for (const key of Object.keys(raw)) if (!allowed.has(key)) fail(`unknown query field "${key}"`);
  if (raw.kind !== "events") fail('query.kind must be "events"');
  if (raw.version !== EVENT_QUERY_VERSION) fail(`query.version must be ${EVENT_QUERY_VERSION}`);
  const lastDays = raw.lastDays;
  if (!Number.isInteger(lastDays) || (lastDays as number) < 1 || (lastDays as number) > MAX_EVENT_WINDOW_DAYS) {
    fail(`query.lastDays must be an integer from 1 to ${MAX_EVENT_WINDOW_DAYS}`);
  }
  const query: EventQuery = { kind: "events", version: EVENT_QUERY_VERSION, lastDays: lastDays as number };
  if (raw.types !== undefined) {
    const list = stringList(raw.types, "types", MAX_EVENT_TYPES);
    for (const t of list) if (!TYPE_RE.test(t)) fail(`"${t}" is not an event type (lowercase letters, digits and underscores)`);
    query.types = Array.from(new Set(list));
  }
  if (raw.where !== undefined) {
    const where = raw.where;
    if (typeof where !== "object" || where === null || Array.isArray(where)) fail("query.where must be an object");
    const out: Partial<Record<EventFilterName, string>> = {};
    for (const [name, value] of Object.entries(where as Record<string, unknown>)) {
      if (!(EVENT_FILTERS as readonly string[]).includes(name)) fail(`unknown filter "${name}"`);
      if (typeof value !== "string" || value.length === 0 || value.length > MAX_FILTER_LENGTH) {
        fail(`query.where.${name} must be a string of 1 to ${MAX_FILTER_LENGTH} characters`);
      }
      if (name === "sha256" && !SHA256_RE.test(value)) fail("query.where.sha256 must be 64 hexadecimal digits");
      out[name as EventFilterName] = name === "sha256" ? value.toLowerCase() : value;
    }
    if (Object.keys(out).length > 0) query.where = out;
  }
  return query;
}

const DAY_MS = 86_400_000;

/** The first and last UTC day (`YYYY-MM-DD`, both included) of a query as of `now`. */
export function eventWindow(query: EventQuery, now: Date): { from: string; to: string } {
  const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  return {
    from: new Date(today - (query.lastDays - 1) * DAY_MS).toISOString().slice(0, 10),
    to: new Date(today).toISOString().slice(0, 10),
  };
}

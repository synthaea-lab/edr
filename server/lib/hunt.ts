import { Prisma, type PrismaClient } from "@prisma/client";

/**
 * Saved hunts (issue #61, ADR-0025).
 *
 * A hunt's `query` is a structured `HuntQuery`, never SQL. It is validated on every
 * write and compiled to parameterized SQL here, scoped to one tenant, so a hunt cannot
 * name a table, a column or another tenant. Slice 1 searches the detection store only;
 * the raw event archive (`server/datalake`) is a later `version` of the query.
 *
 * Client components import this file (the form, `lib/hunt-view.ts`), so it must not reach
 * server-only code: running a hunt and recording its history live in `lib/hunt-runner.ts`,
 * which reaches the notification outbox (`node:crypto`). `tests/unit/client-bundle-imports.test.ts`
 * enforces it (#926).
 */

export const HUNT_QUERY_VERSION = 1;
export const SEVERITIES = ["low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Longest window a hunt may look back, in hours (90 days). */
export const MAX_WINDOW_HOURS = 24 * 90;
/** `text` bounds: a shorter needle matches nearly everything, a longer one is not a hunt. */
export const MIN_TEXT_LENGTH = 3;
export const MAX_TEXT_LENGTH = 256;
export const MAX_TECHNIQUES = 20;
export const MAX_AGENT_IDS = 50;
/** Newest matching detection ids a run keeps. */
export const HUNT_SAMPLE_SIZE = 100;
/** Runs kept per hunt; older ones are pruned by the cron. */
export const HUNT_RUNS_KEPT = 100;
/** A run that takes longer than this is cancelled by Postgres and recorded as failed. */
export const HUNT_STATEMENT_TIMEOUT_MS = 10_000;
/**
 * How long Prisma keeps the run's interactive transaction open: longer than the statement
 * timeout, so Postgres cancels a slow search itself. Prisma closes an interactive
 * transaction after 5 s by default, which would end a 10 s search with "Transaction already
 * closed" before the statement timeout could fire.
 */
export const HUNT_TRANSACTION_TIMEOUT_MS = HUNT_STATEMENT_TIMEOUT_MS + 2_000;
/** Runs a tenant may start per minute, manual and scheduled together. */
export const MAX_RUNS_PER_TENANT_PER_MINUTE = 20;
/** Shortest schedule (minutes) and longest (a week). */
export const MIN_SCHEDULE_MINUTES = 5;
export const MAX_SCHEDULE_MINUTES = 7 * 24 * 60;

export type HuntQuery = {
  version: typeof HUNT_QUERY_VERSION;
  /** Look back this many hours from the run's start, so a scheduled hunt keeps meaning "recently". */
  lastHours: number;
  /** ATT&CK ids: `T1059` matches `T1059` and every `T1059.xxx`; `T1059.001` only itself. */
  techniques?: string[];
  severities?: Severity[];
  agentIds?: string[];
  /** Case-insensitive substring of the detection's stored event JSON. */
  text?: string;
};

export const TECHNIQUE_RE = /^T\d{4}(\.\d{3})?$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class HuntValidationError extends Error {}

function fail(message: string): never {
  throw new HuntValidationError(message);
}

/** Validates untrusted JSON as a `HuntQuery` and returns it normalized; throws `HuntValidationError`. */
export function parseHuntQuery(input: unknown): HuntQuery {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    fail("query must be an object");
  }
  const raw = input as Record<string, unknown>;
  const allowed = new Set(["version", "lastHours", "techniques", "severities", "agentIds", "text"]);
  for (const key of Object.keys(raw)) {
    if (!allowed.has(key)) fail(`unknown query field "${key}"`);
  }
  if (raw.version !== HUNT_QUERY_VERSION) fail(`query.version must be ${HUNT_QUERY_VERSION}`);
  const lastHours = raw.lastHours;
  if (!Number.isInteger(lastHours) || (lastHours as number) < 1 || (lastHours as number) > MAX_WINDOW_HOURS) {
    fail(`query.lastHours must be an integer from 1 to ${MAX_WINDOW_HOURS}`);
  }
  const query: HuntQuery = { version: HUNT_QUERY_VERSION, lastHours: lastHours as number };

  if (raw.techniques !== undefined) {
    const list = stringList(raw.techniques, "techniques", MAX_TECHNIQUES);
    for (const t of list) if (!TECHNIQUE_RE.test(t)) fail(`"${t}" is not an ATT&CK technique id (T1059 or T1059.001)`);
    query.techniques = Array.from(new Set(list));
  }
  if (raw.severities !== undefined) {
    const list = stringList(raw.severities, "severities", SEVERITIES.length);
    for (const s of list) if (!(SEVERITIES as readonly string[]).includes(s)) fail(`"${s}" is not a severity`);
    query.severities = Array.from(new Set(list)) as Severity[];
  }
  if (raw.agentIds !== undefined) {
    const list = stringList(raw.agentIds, "agentIds", MAX_AGENT_IDS);
    for (const id of list) if (!UUID_RE.test(id)) fail(`"${id}" is not an agent id`);
    query.agentIds = Array.from(new Set(list));
  }
  if (raw.text !== undefined) {
    if (typeof raw.text !== "string") fail("query.text must be a string");
    const text = raw.text.trim();
    if (text.length < MIN_TEXT_LENGTH || text.length > MAX_TEXT_LENGTH) {
      fail(`query.text must be ${MIN_TEXT_LENGTH} to ${MAX_TEXT_LENGTH} characters`);
    }
    query.text = text;
  }
  return query;
}

export function stringList(value: unknown, field: string, max: number): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > max) {
    fail(`query.${field} must be a list of 1 to ${max} strings`);
  }
  const list = value as unknown[];
  for (const item of list) if (typeof item !== "string") fail(`query.${field} must contain only strings`);
  return list as string[];
}

/** Escapes `\`, `%` and `_` so `text` is matched literally by `ILIKE ... ESCAPE '\'`. */
export function escapeLike(text: string): string {
  return text.replace(/[\\%_]/g, (c) => `\\${c}`);
}

/** The WHERE conditions of a query, always including the tenant and the window. */
export function huntConditions(tenantId: string, query: HuntQuery, now: Date): Prisma.Sql[] {
  const since = new Date(now.getTime() - query.lastHours * 3_600_000);
  const conditions = [Prisma.sql`tenant_id = ${tenantId}`, Prisma.sql`"timestamp" >= ${since}`];
  if (query.techniques) {
    const clauses = query.techniques.map((t) =>
      t.includes(".")
        ? Prisma.sql`technique = ${t}`
        : Prisma.sql`(technique = ${t} OR technique LIKE ${t + ".%"})`
    );
    conditions.push(Prisma.sql`(${Prisma.join(clauses, " OR ")})`);
  }
  if (query.severities) conditions.push(Prisma.sql`severity IN (${Prisma.join(query.severities)})`);
  if (query.agentIds) conditions.push(Prisma.sql`agent_id IN (${Prisma.join(query.agentIds)})`);
  if (query.text) {
    conditions.push(Prisma.sql`event::text ILIKE ${"%" + escapeLike(query.text) + "%"} ESCAPE '\\'`);
  }
  return conditions;
}

export type HuntResult = { matchCount: number; newMatchCount: number; sample: string[] };

/**
 * Runs `query` for `tenantId` as of `now`. `newSince` (the previous run's start, or null
 * on the first run) bounds what counts as a new match: detections ingested after it.
 * Runs inside a transaction with a statement timeout, so a costly text search is
 * cancelled instead of holding the database.
 */
export async function executeHunt(
  prisma: PrismaClient,
  tenantId: string,
  query: HuntQuery,
  now: Date,
  newSince: Date | null,
  options: ExecuteOptions = {}
): Promise<HuntResult> {
  const where = Prisma.join(huntConditions(tenantId, query, now), " AND ");
  const statementTimeoutMs = options.statementTimeoutMs ?? HUNT_STATEMENT_TIMEOUT_MS;
  return prisma.$transaction(
    async (tx) => {
      await tx.$executeRawUnsafe(`SET LOCAL statement_timeout = ${statementTimeoutMs}`);
      await options.beforeQuery?.(tx);
      const [{ total, fresh }] = await tx.$queryRaw<{ total: bigint; fresh: bigint }[]>(
        newSince
          ? Prisma.sql`SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE created_at > ${newSince}) AS fresh FROM detections WHERE ${where}`
          : Prisma.sql`SELECT COUNT(*) AS total, COUNT(*) AS fresh FROM detections WHERE ${where}`
      );
      const rows = await tx.$queryRaw<{ id: string }[]>(
        Prisma.sql`SELECT id FROM detections WHERE ${where} ORDER BY "timestamp" DESC, id LIMIT ${HUNT_SAMPLE_SIZE}`
      );
      return { matchCount: Number(total), newMatchCount: Number(fresh), sample: rows.map((r) => r.id) };
    },
    { timeout: statementTimeoutMs + (HUNT_TRANSACTION_TIMEOUT_MS - HUNT_STATEMENT_TIMEOUT_MS) }
  );
}

/** Test seams: a shorter statement timeout, and SQL to run first (a `pg_sleep` to force a slow search). */
export type ExecuteOptions = {
  statementTimeoutMs?: number;
  beforeQuery?: (tx: Prisma.TransactionClient) => Promise<unknown>;
};

/**
 * What a failed run stores and the API returns. Only messages this module wrote are
 * passed through; anything else (a Prisma or driver error can carry table names and
 * connection details) becomes a generic line and goes to the server log instead.
 */
export function describeRunError(error: unknown): string {
  if (error instanceof HuntValidationError) return error.message;
  const text = error instanceof Error ? error.message : "";
  if (/statement timeout/i.test(text)) return "the search exceeded its time limit and was cancelled";
  return "the run failed (see the server log)";
}

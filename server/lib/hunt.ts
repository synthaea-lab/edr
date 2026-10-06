import { Prisma, type PrismaClient } from "@prisma/client";

/**
 * Saved hunts (issue #61, ADR-0025).
 *
 * A hunt's `query` is a structured `HuntQuery`, never SQL. It is validated on every
 * write and compiled to parameterized SQL here, scoped to one tenant, so a hunt cannot
 * name a table, a column or another tenant. Slice 1 searches the detection store only;
 * the raw event archive (`server/datalake`) is a later `version` of the query.
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
/** A run that takes longer than this is cancelled and recorded as failed. */
export const HUNT_STATEMENT_TIMEOUT_MS = 10_000;
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

const TECHNIQUE_RE = /^T\d{4}(\.\d{3})?$/;
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

function stringList(value: unknown, field: string, max: number): string[] {
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
  newSince: Date | null
): Promise<HuntResult> {
  const where = Prisma.join(huntConditions(tenantId, query, now), " AND ");
  return prisma.$transaction(async (tx) => {
    await tx.$executeRawUnsafe(`SET LOCAL statement_timeout = ${HUNT_STATEMENT_TIMEOUT_MS}`);
    const [{ total, fresh }] = await tx.$queryRaw<{ total: bigint; fresh: bigint }[]>(
      newSince
        ? Prisma.sql`SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE created_at > ${newSince}) AS fresh FROM detections WHERE ${where}`
        : Prisma.sql`SELECT COUNT(*) AS total, COUNT(*) AS fresh FROM detections WHERE ${where}`
    );
    const rows = await tx.$queryRaw<{ id: string }[]>(
      Prisma.sql`SELECT id FROM detections WHERE ${where} ORDER BY "timestamp" DESC, id LIMIT ${HUNT_SAMPLE_SIZE}`
    );
    return { matchCount: Number(total), newMatchCount: Number(fresh), sample: rows.map((r) => r.id) };
  });
}

export type RunTrigger = "manual" | "schedule";

/**
 * Runs a hunt and appends its HuntRun. A failing query (timeout, database error) is
 * recorded on the run, not thrown: the history says the hunt could not run, which is
 * itself worth knowing on a schedule.
 */
export async function runHunt(
  prisma: PrismaClient,
  hunt: { id: string; tenantId: string; version: number; query: unknown },
  trigger: RunTrigger,
  now: Date = new Date()
) {
  const previous = await prisma.huntRun.findFirst({
    where: { huntId: hunt.id, tenantId: hunt.tenantId, error: null },
    orderBy: { startedAt: "desc" },
    select: { startedAt: true },
  });
  const base = {
    huntId: hunt.id,
    tenantId: hunt.tenantId,
    startedAt: now,
    queryVersion: hunt.version,
    query: (hunt.query ?? {}) as Prisma.InputJsonValue,
    trigger,
  };
  try {
    // Validated here, inside the try, so one hunt whose stored query no longer parses
    // is a failed run in its history and not an error that stops the cron's batch.
    const query = parseHuntQuery(hunt.query);
    const result = await executeHunt(prisma, hunt.tenantId, query, now, previous?.startedAt ?? null);
    return prisma.huntRun.create({
      data: {
        ...base,
        finishedAt: new Date(),
        matchCount: result.matchCount,
        newMatchCount: result.newMatchCount,
        sampleDetectionIds: result.sample,
      },
    });
  } catch (error) {
    console.error("Hunt run failed:", hunt.id, error);
    return prisma.huntRun.create({
      data: {
        ...base,
        finishedAt: new Date(),
        sampleDetectionIds: [],
        error: error instanceof Error ? error.message.slice(0, 500) : "run failed",
      },
    });
  }
}

/** Active scheduled hunts whose last run (any outcome) is older than their schedule, or that never ran. */
export async function dueHunts(prisma: PrismaClient, now: Date = new Date()) {
  const scheduled = await prisma.hunt.findMany({
    where: { active: true, scheduleMinutes: { not: null } },
    orderBy: { createdAt: "asc" },
  });
  const due = [];
  for (const hunt of scheduled) {
    const last = await prisma.huntRun.findFirst({
      where: { huntId: hunt.id },
      orderBy: { startedAt: "desc" },
      select: { startedAt: true },
    });
    const intervalMs = (hunt.scheduleMinutes as number) * 60_000;
    if (!last || now.getTime() - last.startedAt.getTime() >= intervalMs) due.push(hunt);
  }
  return due;
}

/** Deletes all but the newest `keep` runs of every hunt; returns how many went. */
export async function pruneHuntRuns(prisma: PrismaClient, keep: number = HUNT_RUNS_KEPT): Promise<number> {
  const result = await prisma.$executeRaw`
    DELETE FROM hunt_runs WHERE id IN (
      SELECT id FROM (
        SELECT id, ROW_NUMBER() OVER (PARTITION BY hunt_id ORDER BY started_at DESC, id) AS rn
        FROM hunt_runs
      ) ranked WHERE rn > ${keep}
    )`;
  return Number(result);
}

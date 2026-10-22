import { Prisma, type PrismaClient } from "@prisma/client";
import {
  HUNT_STATEMENT_TIMEOUT_MS,
  HUNT_TRANSACTION_TIMEOUT_MS,
  HuntValidationError,
  MAX_TECHNIQUES,
  MAX_TEXT_LENGTH,
  MAX_WINDOW_HOURS,
  MIN_TEXT_LENGTH,
  SEVERITIES,
  TECHNIQUE_RE,
  escapeLike,
  huntConditions,
  parseHuntQuery,
  stringList,
  type HuntQuery,
  type Severity,
} from "@/lib/hunt";

/**
 * Ad-hoc search over the detection and case store (#61, ADR-0025).
 *
 * The same structured, tenant-scoped queries as a saved hunt, run once and read back as rows
 * instead of counts: an analyst can look at what a hunt matches before saving it, and at what a
 * saved hunt matches now. Read-only. Both sources are Postgres tables; the raw event archive
 * (`server/datalake`, #77) is not built and is not searched.
 */

/** Rows per page. */
export const SEARCH_PAGE_SIZE = 50;
/** Searches a tenant may have in flight, across every server instance (see `searchWithinLimit`). */
export const MAX_CONCURRENT_SEARCHES_PER_TENANT = 2;
/** Longest `title` a row carries. */
const TITLE_MAX = 200;

export const CASE_STATUSES = ["open", "investigating", "resolved", "false_positive"] as const;
export type CaseStatus = (typeof CASE_STATUSES)[number];
export const CASE_QUERY_VERSION = 1;

/** A query over cases: the window is on the case's creation time. */
export type CaseQuery = {
  kind: "cases";
  version: typeof CASE_QUERY_VERSION;
  lastHours: number;
  severities?: Severity[];
  statuses?: CaseStatus[];
  /** Cases with at least one detection of these ATT&CK ids (`T1059` also matches `T1059.xxx`). */
  techniques?: string[];
  /** Case-insensitive substring of the title or the description. */
  text?: string;
};

export type SearchRequest =
  | { source: "detections"; query: HuntQuery; cursor?: string }
  | { source: "cases"; query: CaseQuery; cursor?: string };

export type DetectionRow = {
  id: string;
  timestamp: string;
  technique: string;
  severity: string;
  agentId: string;
  caseId: string | null;
  caseTitle: string | null;
  /**
   * The detection's rule title when its `meta` has one (`parseDetectionPayload` stores a structured
   * detection's `title` there, and its first triggering event in `event`); never anything read from
   * the event.
   */
  title: string | null;
};

export type CaseRow = {
  id: string;
  title: string;
  severity: string;
  status: string;
  createdAt: string;
  detectionCount: number;
};

export type SearchPage =
  | { source: "detections"; rows: DetectionRow[]; nextCursor: string | null; total: number | null }
  | { source: "cases"; rows: CaseRow[]; nextCursor: string | null; total: number | null };

function fail(message: string): never {
  throw new HuntValidationError(message);
}

/** Validates untrusted JSON as a `CaseQuery` and returns it normalized; throws `HuntValidationError`. */
export function parseCaseQuery(input: unknown): CaseQuery {
  if (typeof input !== "object" || input === null || Array.isArray(input)) fail("query must be an object");
  const raw = input as Record<string, unknown>;
  const allowed = new Set(["kind", "version", "lastHours", "severities", "statuses", "techniques", "text"]);
  for (const key of Object.keys(raw)) if (!allowed.has(key)) fail(`unknown query field "${key}"`);
  if (raw.kind !== "cases") fail('query.kind must be "cases"');
  if (raw.version !== CASE_QUERY_VERSION) fail(`query.version must be ${CASE_QUERY_VERSION}`);
  const lastHours = raw.lastHours;
  if (!Number.isInteger(lastHours) || (lastHours as number) < 1 || (lastHours as number) > MAX_WINDOW_HOURS) {
    fail(`query.lastHours must be an integer from 1 to ${MAX_WINDOW_HOURS}`);
  }
  const query: CaseQuery = { kind: "cases", version: CASE_QUERY_VERSION, lastHours: lastHours as number };
  if (raw.severities !== undefined) {
    const list = stringList(raw.severities, "severities", SEVERITIES.length);
    for (const s of list) if (!(SEVERITIES as readonly string[]).includes(s)) fail(`"${s}" is not a severity`);
    query.severities = Array.from(new Set(list)) as Severity[];
  }
  if (raw.statuses !== undefined) {
    const list = stringList(raw.statuses, "statuses", CASE_STATUSES.length);
    for (const s of list) if (!(CASE_STATUSES as readonly string[]).includes(s)) fail(`"${s}" is not a case status`);
    query.statuses = Array.from(new Set(list)) as CaseStatus[];
  }
  if (raw.techniques !== undefined) {
    const list = stringList(raw.techniques, "techniques", MAX_TECHNIQUES);
    for (const t of list) if (!TECHNIQUE_RE.test(t)) fail(`"${t}" is not an ATT&CK technique id (T1059 or T1059.001)`);
    query.techniques = Array.from(new Set(list));
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

/** Validates the body of `POST /api/hunts/search`; throws `HuntValidationError`. */
export function parseSearchRequest(body: unknown): SearchRequest {
  if (typeof body !== "object" || body === null || Array.isArray(body)) fail("body must be an object");
  const raw = body as Record<string, unknown>;
  for (const key of Object.keys(raw)) if (!["source", "query", "cursor"].includes(key)) fail(`unknown field "${key}"`);
  const source = raw.source ?? "detections";
  if (source !== "detections" && source !== "cases") fail('source must be "detections" or "cases"');
  let cursor: string | undefined;
  if (raw.cursor !== undefined && raw.cursor !== null) {
    if (typeof raw.cursor !== "string") fail("cursor must be a string");
    decodeCursor(raw.cursor);
    cursor = raw.cursor;
  }
  return source === "cases"
    ? { source, query: parseCaseQuery(raw.query), cursor }
    : { source, query: parseHuntQuery(raw.query), cursor };
}

const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** A page boundary: the last row's time and id, opaque to the client. */
export function encodeCursor(at: Date, id: string): string {
  return Buffer.from(`${at.toISOString()}|${id}`, "utf8").toString("base64url");
}

/** Throws `HuntValidationError` for anything `encodeCursor` could not have produced. */
export function decodeCursor(cursor: string): { at: Date; id: string } {
  let text: string;
  try {
    text = Buffer.from(cursor, "base64url").toString("utf8");
  } catch {
    return fail("cursor is not valid");
  }
  const [iso, id, extra] = text.split("|");
  if (extra !== undefined || !iso || !id || !ISO_RE.test(iso) || !ID_RE.test(id)) fail("cursor is not valid");
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) fail("cursor is not valid");
  return { at, id };
}

function techniqueClause(column: Prisma.Sql, technique: string): Prisma.Sql {
  return technique.includes(".")
    ? Prisma.sql`${column} = ${technique}`
    : Prisma.sql`(${column} = ${technique} OR ${column} LIKE ${technique + ".%"})`;
}

/** The WHERE conditions of a case query, always including the tenant and the window. */
export function caseConditions(tenantId: string, query: CaseQuery, now: Date): Prisma.Sql[] {
  const since = new Date(now.getTime() - query.lastHours * 3_600_000);
  const conditions = [Prisma.sql`c.tenant_id = ${tenantId}`, Prisma.sql`c.created_at >= ${since}`];
  if (query.severities) conditions.push(Prisma.sql`c.severity IN (${Prisma.join(query.severities)})`);
  if (query.statuses) conditions.push(Prisma.sql`c.status IN (${Prisma.join(query.statuses)})`);
  if (query.techniques) {
    const clauses = query.techniques.map((t) => techniqueClause(Prisma.sql`d.technique`, t));
    conditions.push(
      Prisma.sql`EXISTS (SELECT 1 FROM detections d WHERE d.case_id = c.id AND d.tenant_id = ${tenantId} AND (${Prisma.join(clauses, " OR ")}))`
    );
  }
  if (query.text) {
    const like = "%" + escapeLike(query.text) + "%";
    conditions.push(Prisma.sql`(c.title ILIKE ${like} ESCAPE '\\' OR c.description ILIKE ${like} ESCAPE '\\')`);
  }
  return conditions;
}

/** Test seams, as for `executeHunt`: a shorter statement timeout, and SQL to run first. */
export type SearchOptions = {
  statementTimeoutMs?: number;
  beforeQuery?: (tx: Prisma.TransactionClient) => Promise<unknown>;
};

export type SearchOutcome = { status: "ok"; page: SearchPage } | { status: "busy" };

/**
 * Runs one page of a search for `tenantId` as of `now`, inside a transaction with the hunt
 * statement timeout, so a costly `text` scan is cancelled instead of holding the database.
 *
 * A tenant may have `MAX_CONCURRENT_SEARCHES_PER_TENANT` searches in flight: each takes one of that
 * many transaction-scoped advisory locks without waiting, and a search that finds none free is
 * `busy` (the API answers 429). The lock lives in Postgres, so the bound holds across server
 * instances, and it frees itself when the transaction ends, however it ends. The count of the
 * first page is part of the same search, not a second one.
 */
export async function searchWithinLimit(
  prisma: PrismaClient,
  tenantId: string,
  request: SearchRequest,
  now: Date = new Date(),
  options: SearchOptions = {}
): Promise<SearchOutcome> {
  const statementTimeoutMs = options.statementTimeoutMs ?? HUNT_STATEMENT_TIMEOUT_MS;
  const after = request.cursor ? decodeCursor(request.cursor) : null;
  return prisma.$transaction(
    async (tx) => {
      await tx.$executeRawUnsafe(`SET LOCAL statement_timeout = ${statementTimeoutMs}`);
      // Prisma stores DateTime as a UTC timestamp without time zone. Bind dates against
      // that same clock even when the PostgreSQL session uses another time zone.
      await tx.$executeRawUnsafe("SET LOCAL TIME ZONE 'UTC'");
      let admitted = false;
      for (let slot = 0; slot < MAX_CONCURRENT_SEARCHES_PER_TENANT && !admitted; slot++) {
        const [{ ok }] = await tx.$queryRaw<{ ok: boolean }[]>(
          Prisma.sql`SELECT pg_try_advisory_xact_lock(hashtext(${`hunt_search:${tenantId}:${slot}`})) AS ok`
        );
        admitted = ok;
      }
      if (!admitted) return { status: "busy" } as const;
      await options.beforeQuery?.(tx);
      const page =
        request.source === "detections"
          ? await detectionPage(tx, tenantId, request.query, now, after)
          : await casePage(tx, tenantId, request.query, now, after);
      return { status: "ok", page } as const;
    },
    { timeout: statementTimeoutMs + (HUNT_TRANSACTION_TIMEOUT_MS - HUNT_STATEMENT_TIMEOUT_MS) }
  );
}

type Cursor = { at: Date; id: string } | null;

async function detectionPage(
  tx: Prisma.TransactionClient,
  tenantId: string,
  query: HuntQuery,
  now: Date,
  after: Cursor
): Promise<SearchPage> {
  const where = Prisma.join(huntConditions(tenantId, query, now), " AND ");
  let total: number | null = null;
  if (!after) {
    const [{ count }] = await tx.$queryRaw<{ count: bigint }[]>(
      Prisma.sql`SELECT COUNT(*) AS count FROM detections WHERE ${where}`
    );
    total = Number(count);
  }
  const keyset = after ? Prisma.sql` AND ("timestamp", id) < (${after.at}, ${after.id})` : Prisma.empty;
  const found = await tx.$queryRaw<
    { id: string; timestamp: Date; technique: string; severity: string; agentId: string; caseId: string | null; title: unknown }[]
  >(Prisma.sql`
    SELECT id, "timestamp", technique, severity, agent_id AS "agentId", case_id AS "caseId",
           CASE WHEN jsonb_typeof(meta::jsonb -> 'title') = 'string' THEN meta::jsonb ->> 'title' END AS title
    FROM detections WHERE ${where}${keyset}
    ORDER BY "timestamp" DESC, id DESC LIMIT ${SEARCH_PAGE_SIZE + 1}
  `);
  const more = found.length > SEARCH_PAGE_SIZE;
  const rows = found.slice(0, SEARCH_PAGE_SIZE);
  const caseIds = Array.from(new Set(rows.map((r) => r.caseId).filter((id): id is string => id !== null)));
  const cases = caseIds.length
    ? await tx.case.findMany({ where: { id: { in: caseIds }, tenantId }, select: { id: true, title: true } })
    : [];
  const titles = new Map(cases.map((c) => [c.id, c.title]));
  const last = rows[rows.length - 1];
  return {
    source: "detections",
    total,
    nextCursor: more && last ? encodeCursor(last.timestamp, last.id) : null,
    rows: rows.map((r) => ({
      id: r.id,
      timestamp: r.timestamp.toISOString(),
      technique: r.technique,
      severity: r.severity,
      agentId: r.agentId,
      caseId: r.caseId,
      caseTitle: r.caseId ? (titles.get(r.caseId) ?? null) : null,
      title: typeof r.title === "string" && r.title ? r.title.slice(0, TITLE_MAX) : null,
    })),
  };
}

async function casePage(
  tx: Prisma.TransactionClient,
  tenantId: string,
  query: CaseQuery,
  now: Date,
  after: Cursor
): Promise<SearchPage> {
  const where = Prisma.join(caseConditions(tenantId, query, now), " AND ");
  let total: number | null = null;
  if (!after) {
    const [{ count }] = await tx.$queryRaw<{ count: bigint }[]>(
      Prisma.sql`SELECT COUNT(*) AS count FROM cases c WHERE ${where}`
    );
    total = Number(count);
  }
  const keyset = after ? Prisma.sql` AND (c.created_at, c.id) < (${after.at}, ${after.id})` : Prisma.empty;
  const found = await tx.$queryRaw<
    { id: string; title: string; severity: string; status: string; createdAt: Date; detectionCount: bigint }[]
  >(Prisma.sql`
    SELECT c.id, c.title, c.severity, c.status, c.created_at AS "createdAt",
           (SELECT COUNT(*) FROM detections d WHERE d.case_id = c.id AND d.tenant_id = ${tenantId}) AS "detectionCount"
    FROM cases c WHERE ${where}${keyset}
    ORDER BY c.created_at DESC, c.id DESC LIMIT ${SEARCH_PAGE_SIZE + 1}
  `);
  const more = found.length > SEARCH_PAGE_SIZE;
  const rows = found.slice(0, SEARCH_PAGE_SIZE);
  const last = rows[rows.length - 1];
  return {
    source: "cases",
    total,
    nextCursor: more && last ? encodeCursor(last.createdAt, last.id) : null,
    rows: rows.map((r) => ({
      id: r.id,
      title: r.title,
      severity: r.severity,
      status: r.status,
      createdAt: r.createdAt.toISOString(),
      detectionCount: Number(r.detectionCount),
    })),
  };
}

/** The HTTP status and message a failed search maps to; only messages this module wrote reach the client. */
export function searchFailure(error: unknown): { status: number; message: string } {
  if (error instanceof HuntValidationError) return { status: 400, message: error.message };
  const text = error instanceof Error ? error.message : "";
  if (/statement timeout/i.test(text)) {
    return { status: 504, message: "the search exceeded its time limit and was cancelled" };
  }
  return { status: 500, message: "Internal server error" };
}

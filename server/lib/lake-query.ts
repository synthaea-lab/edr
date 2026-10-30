/**
 * Reads events back out of the telemetry lake (issue #77, ADR-0041, decision 4).
 *
 * A structured query, not SQL: a tenant, a range of UTC days, optionally event types and equality
 * filters on the typed columns, a row limit. It lists the tenant's prefix, keeps the files whose
 * `date=` and `type=` segments fit (partition pruning is the path), reads those with `hyparquet`
 * (pure JavaScript, so it runs in the server's Alpine image, where DuckDB's Node bindings have no
 * build, ADR-0041 "Findings") and filters the rows.
 *
 * **Tenant isolation is structural, in two layers that do not depend on each other.** The only
 * listing is `tenant=<id>/` for an id that passes a closed character set, and every key the listing
 * returns is parsed against the full layout and refused unless its tenant segment is that id, so a
 * store that answered a wider prefix, or a stray key, reads nothing. There is no query language for a
 * compiler bug to widen.
 *
 * It is bounded the way a search must be: at most {@link MAX_RANGE_DAYS} days, {@link MAX_FILES}
 * files read, {@link MAX_ROWS} rows returned, and a result says when it was cut. The cost is a scan
 * of every file in range: this is the engine for a hunt over days on one tenant, not for the fleet's
 * volume. DuckDB stays the planned engine for that (not measured, ADR "Measurements owed"); the
 * result shape is what a hunt layer consumes, so the engine can change under it.
 *
 * Rows come back oldest first (by `ts`, then by file), or newest first with `order: "desc"`, and carry `event`, the event's source text as
 * ingest received it, never re-serialised.
 */

import { parquetReadObjects } from "hyparquet";
import type { LakeReader } from "@/lib/lake-store";

export const MAX_RANGE_DAYS = 366;
export const MAX_FILES = 2000;
export const DEFAULT_ROWS = 100;
export const MAX_ROWS = 1000;

/** The typed columns a query can test for equality, as the writer names them in the file. */
const EQUALITY_COLUMNS = {
  agentId: "agent_id",
  comm: "comm",
  path: "path",
  imagePath: "image_path",
  daddr: "daddr",
  query: "query",
  sha256: "sha256",
} as const;

export type LakeFilterName = keyof typeof EQUALITY_COLUMNS;

export interface LakeQuery {
  tenantId: string;
  /** First and last UTC day, `YYYY-MM-DD`, both included. */
  from: string;
  to: string;
  /** Event types (the `type=` segment). Absent: every type. */
  types?: string[];
  /** Exact matches, all of which must hold. `sha256` is compared in lowercase. */
  where?: Partial<Record<LakeFilterName, string>>;
  limit?: number;
  /**
   * "asc" (the default): the oldest rows of the range, oldest first. "desc": the newest rows, newest
   * first, so a hunt over a wide window sees what happened last, and `limit` cuts the oldest.
   */
  order?: "asc" | "desc";
  /**
   * Checked before each file is read: an aborted signal ends the query by throwing its reason, so a
   * caller can bound the time. A file already being read is not interrupted.
   */
  signal?: AbortSignal;
  /**
   * Read the `event` column (the event's whole source text; the largest column). Default true. With
   * false the column is not read from the file at all (Parquet is columnar) and `event` is "": for a
   * caller that shows only the typed columns.
   */
  includeEvent?: boolean;
}

export interface LakeRow {
  type: string;
  date: string;
  agentId: string;
  ts: Date;
  comm: string | null;
  path: string | null;
  imagePath: string | null;
  daddr: string | null;
  query: string | null;
  sha256: string | null;
  /** The event as ingest received it. */
  event: string;
}

export interface LakeResult {
  rows: LakeRow[];
  /** More rows matched than `limit`. */
  truncated: boolean;
  /** Files in the tenant's prefix whose partition fits the query, and how many of them were read. */
  filesMatched: number;
  filesRead: number;
  /** Matching files left unread because of {@link MAX_FILES}; non-zero means the answer is incomplete. */
  filesSkipped: number;
}

const TENANT_ID = /^[A-Za-z0-9_-]{1,128}$/;
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const TYPE = /^(?:[a-z][a-z0-9_]{0,63})$/;
const KEY = /^tenant=([A-Za-z0-9_-]+)\/date=(\d{4}-\d{2}-\d{2})\/type=([a-z][a-z0-9_]{0,63})\/[A-Za-z0-9_.-]+\.parquet$/;

function dayNumber(day: string): number {
  const ms = Date.parse(`${day}T00:00:00Z`);
  if (Number.isNaN(ms) || new Date(ms).toISOString().slice(0, 10) !== day) throw new RangeError(`invalid day: ${JSON.stringify(day)}`);
  return Math.floor(ms / 86_400_000);
}

/**
 * Runs a query.
 *
 * @throws RangeError for a tenant id, day, range, type, filter name or limit the query cannot take.
 */
export async function queryLake(reader: LakeReader, q: LakeQuery): Promise<LakeResult> {
  if (!TENANT_ID.test(q.tenantId)) throw new RangeError("invalid tenant id");
  if (!DAY.test(q.from) || !DAY.test(q.to)) throw new RangeError("from and to must be YYYY-MM-DD days");
  const first = dayNumber(q.from);
  const last = dayNumber(q.to);
  if (last < first) throw new RangeError("to is before from");
  if (last - first + 1 > MAX_RANGE_DAYS) throw new RangeError(`a query spans at most ${MAX_RANGE_DAYS} days`);
  for (const type of q.types ?? []) if (!TYPE.test(type)) throw new RangeError(`invalid event type: ${JSON.stringify(type)}`);
  if (q.order !== undefined && q.order !== "asc" && q.order !== "desc") throw new RangeError('order must be "asc" or "desc"');
  const newestFirst = q.order === "desc";
  const limit = q.limit ?? DEFAULT_ROWS;
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_ROWS) throw new RangeError(`limit must be 1 to ${MAX_ROWS}`);

  const tests: [string, string][] = [];
  for (const [name, value] of Object.entries(q.where ?? {})) {
    if (!(name in EQUALITY_COLUMNS)) throw new RangeError(`unknown filter: ${JSON.stringify(name)}`);
    if (typeof value !== "string") throw new RangeError(`filter ${name} must be a string`);
    tests.push([EQUALITY_COLUMNS[name as LakeFilterName], name === "sha256" ? value.toLowerCase() : value]);
  }
  const wantedTypes = q.types === undefined ? null : new Set(q.types);

  const prefix = `tenant=${q.tenantId}/`;
  const files: { key: string; date: string; type: string }[] = [];
  for (const { key } of await reader.list(prefix)) {
    const m = KEY.exec(key);
    // The second layer: whatever the store listed, only this tenant's well-formed keys are read.
    if (m === null || m[1] !== q.tenantId) continue;
    let day: number;
    try {
      day = dayNumber(m[2]);
    } catch {
      continue; // a `date=` segment that is not a day is not a partition
    }
    if (day < first || day > last) continue;
    if (wantedTypes !== null && !wantedTypes.has(m[3])) continue;
    files.push({ key, date: m[2], type: m[3] });
  }
  files.sort((a, b) => (a.date !== b.date ? (a.date < b.date ? -1 : 1) : a.key < b.key ? -1 : 1));
  // The files read are the first MAX_FILES in the order the query wants rows: the newest days for "desc".
  if (newestFirst) files.reverse();

  const toRead = files.slice(0, MAX_FILES);
  const withEvent = q.includeEvent !== false;
  const columns = ["agent_id", "ts", "comm", "path", "image_path", "daddr", "query", "sha256", ...(withEvent ? ["event"] : [])];
  const rows: LakeRow[] = [];
  let truncated = false;
  let filesRead = 0;

  // One day at a time: its matches are ordered by ts before they count against the limit, so the
  // limit keeps the oldest rows of the range and never cuts a day in file order.
  for (let i = 0; i < toRead.length && !truncated; ) {
    const date = toRead[i].date;
    const day: LakeRow[] = [];
    for (; i < toRead.length && toRead[i].date === date; i++) {
      q.signal?.throwIfAborted();
      const bytes = await reader.get(toRead[i].key);
      const file = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
      filesRead++;
      for (const r of (await parquetReadObjects({ file, columns })) as Record<string, unknown>[]) {
        if (!tests.every(([column, value]) => r[column] === value)) continue;
        day.push({
          type: toRead[i].type,
          date,
          agentId: String(r.agent_id),
          ts: r.ts instanceof Date ? r.ts : new Date(Number(r.ts)),
          comm: (r.comm as string | null) ?? null,
          path: (r.path as string | null) ?? null,
          imagePath: (r.image_path as string | null) ?? null,
          daddr: (r.daddr as string | null) ?? null,
          query: (r.query as string | null) ?? null,
          sha256: (r.sha256 as string | null) ?? null,
          event: withEvent ? String(r.event) : "",
        });
      }
    }
    day.sort((a, b) => (newestFirst ? b.ts.getTime() - a.ts.getTime() : a.ts.getTime() - b.ts.getTime()));
    for (const row of day) {
      if (rows.length === limit) {
        truncated = true;
        break;
      }
      rows.push(row);
    }
  }

  return { rows, truncated, filesMatched: files.length, filesRead, filesSkipped: files.length - toRead.length };
}

/**
 * Reads events back out of the telemetry lake (issue #77, ADR-0041, decision 4).
 *
 * A structured query, not SQL: a tenant, a range of UTC days, optionally event types and equality
 * filters on the typed columns, a row limit. It lists the partitions in range one day (and one type)
 * at a time, so a tenant's history outside the range is never listed (partition pruning is the path),
 * stops listing at {@link MAX_FILES} + 1 files, reads those with `hyparquet`
 * (pure JavaScript, so it runs in the server's Alpine image, where DuckDB's Node bindings have no
 * build, ADR-0041 "Findings") and filters the rows.
 *
 * **Tenant isolation is structural, in two layers that do not depend on each other.** Every listing
 * is under `tenant=<id>/` for an id that passes a closed character set, and every key a listing
 * returns is parsed against the full layout and refused unless its tenant and day segments are the
 * ones asked for, so a store that answered a wider prefix, or a stray key, reads nothing. There is no
 * query language for a compiler bug to widen.
 *
 * It is bounded the way a search must be, listing included: at most {@link MAX_RANGE_DAYS} days,
 * {@link MAX_FILES} files listed and read, {@link MAX_ROWS} rows returned, and a result says when it
 * was cut. The listing is bounded because the writer makes a file per flush, so a tenant's prefix has
 * no ceiling: the reader is asked for at most the files still wanted (`list(prefix, { limit })`). The cost is a scan
 * of every file in range: this is the engine for a hunt over days on one tenant, not for the fleet's
 * volume. DuckDB stays the planned engine for that (not measured, ADR "Measurements owed"); the
 * result shape is what a hunt layer consumes, so the engine can change under it.
 *
 * Rows come back oldest first (by `ts`, then by file) and carry `event`, the event's source text as
 * ingest received it, never re-serialised.
 */

import { parquetReadObjects } from "hyparquet";
import type { LakeReader } from "@/lib/lake-store";

export const MAX_RANGE_DAYS = 366;
export const MAX_FILES = 2000;
/** Event types one query may name: each is listed on its own, per day. */
export const MAX_TYPES = 32;
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
  /** Files whose partition fits the query, as far as the listing went (at most {@link MAX_FILES}), and how many of them were read. */
  filesMatched: number;
  filesRead: number;
  /**
   * Matching files beyond {@link MAX_FILES}. The listing stops at the first one more than the cap, so
   * this is 1 when `listingTruncated` and 0 otherwise: it says "at least one", not how many.
   */
  filesSkipped: number;
  /** The listing stopped at the cap: there are more matching files, and the answer is incomplete. */
  listingTruncated: boolean;
}

/** A partition file, as listed. */
export interface PartitionFile {
  key: string;
  date: string;
  type: string;
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

const COLUMNS = ["agent_id", "ts", "comm", "path", "image_path", "daddr", "query", "sha256", "event"];

function dayString(dayNumber: number): string {
  return new Date(dayNumber * 86_400_000).toISOString().slice(0, 10);
}

/**
 * The partition files of one tenant from day number `first` to `last` (UTC, both included), listed
 * one day (and, when `types` is given, one type) at a time and never past `maxFiles`: the reader is
 * asked for at most the files still wanted plus one, so a tenant with a million files costs the
 * same as one with `maxFiles`. `truncated` is set when there was at least one more.
 *
 * Every key returned is checked against the layout, the tenant and the day that was asked for
 * (the second isolation layer), and a key that fails is ignored. Shared by {@link queryLake} and
 * {@link scanLake}.
 */
export async function listPartitionFiles(
  reader: LakeReader,
  tenantId: string,
  first: number,
  last: number,
  types: string[] | null,
  maxFiles: number
): Promise<{ files: PartitionFile[]; truncated: boolean }> {
  const files: PartitionFile[] = [];
  const wanted = types === null ? null : Array.from(new Set(types));
  for (let day = first; day <= last; day++) {
    const date = dayString(day);
    const under = `tenant=${tenantId}/date=${date}/`;
    for (const prefix of wanted === null ? [under] : wanted.map((type) => `${under}type=${type}/`)) {
      for (const { key } of await reader.list(prefix, { limit: maxFiles + 1 - files.length })) {
        const m = KEY.exec(key);
        // The second layer: whatever the store listed, only this tenant's well-formed keys of this day are read.
        if (m === null || m[1] !== tenantId || m[2] !== date) continue;
        if (wanted !== null && !wanted.includes(m[3])) continue;
        files.push({ key, date, type: m[3] });
      }
      if (files.length > maxFiles) return { files: files.slice(0, maxFiles), truncated: true };
    }
  }
  return { files, truncated: false };
}

/** The tenant, days and types every read of the lake is held to, a scan as much as a query. */
function checkScope(q: { tenantId: string; from: string; to: string; types?: string[] }) {
  if (!TENANT_ID.test(q.tenantId)) throw new RangeError("invalid tenant id");
  if (!DAY.test(q.from) || !DAY.test(q.to)) throw new RangeError("from and to must be YYYY-MM-DD days");
  const first = dayNumber(q.from);
  const last = dayNumber(q.to);
  if (last < first) throw new RangeError("to is before from");
  if (last - first + 1 > MAX_RANGE_DAYS) throw new RangeError(`a query spans at most ${MAX_RANGE_DAYS} days`);
  for (const type of q.types ?? []) if (!TYPE.test(type)) throw new RangeError(`invalid event type: ${JSON.stringify(type)}`);
  if ((q.types ?? []).length > MAX_TYPES) throw new RangeError(`a query names at most ${MAX_TYPES} event types`);
  return { first, last, types: q.types === undefined ? null : q.types };
}

/** One file's rows that pass `tests` (typed-column equality, ANDed). */
async function readPartition(reader: LakeReader, file: PartitionFile, tests: [string, string][]): Promise<LakeRow[]> {
  const bytes = await reader.get(file.key);
  const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  const rows: LakeRow[] = [];
  for (const r of (await parquetReadObjects({ file: buffer, columns: COLUMNS })) as Record<string, unknown>[]) {
    if (!tests.every(([column, value]) => r[column] === value)) continue;
    rows.push({
      type: file.type,
      date: file.date,
      agentId: String(r.agent_id),
      ts: r.ts instanceof Date ? r.ts : new Date(Number(r.ts)),
      comm: (r.comm as string | null) ?? null,
      path: (r.path as string | null) ?? null,
      imagePath: (r.image_path as string | null) ?? null,
      daddr: (r.daddr as string | null) ?? null,
      query: (r.query as string | null) ?? null,
      sha256: (r.sha256 as string | null) ?? null,
      event: String(r.event),
    });
  }
  return rows;
}

export interface LakeScan {
  tenantId: string;
  from: string;
  to: string;
  types?: string[];
  /** Files listed and read at most; a scan that hits it says so in `listingTruncated`. Default {@link MAX_SCAN_FILES}. */
  maxFiles?: number;
}

export interface LakeScanResult {
  filesMatched: number;
  filesRead: number;
  /** Matching files beyond `maxFiles`: 1 when `listingTruncated` ("at least one", the listing stops there), else 0. */
  filesSkipped: number;
  /** The listing stopped at `maxFiles`: the scan saw only part of the range. */
  listingTruncated: boolean;
}

/** Files one {@link scanLake} reads by default. A query stops at {@link MAX_FILES}; a scan is a background job and reads more. */
export const MAX_SCAN_FILES = 50_000;

/**
 * Reads every row of a tenant's files in range, one file at a time, in day then key order (not
 * `ts` order within a day), handing each file's rows to `onFile` and keeping none. The same scope
 * checks, the same bounded listing and the same two isolation layers as {@link queryLake}, but no row
 * limit: the caller folds the rows as they come, so memory is one file, not the range. This is what
 * a rebuild reads with; {@link queryLake}'s 1000 rows per call cannot, one host's day being far more.
 *
 * @throws RangeError for a tenant id, day, range or type the scan cannot take.
 */
export async function scanLake(
  reader: LakeReader,
  q: LakeScan,
  onFile: (rows: LakeRow[], file: { date: string; type: string; key: string }) => void | Promise<void>
): Promise<LakeScanResult> {
  const { first, last, types } = checkScope(q);
  const maxFiles = q.maxFiles ?? MAX_SCAN_FILES;
  if (!Number.isInteger(maxFiles) || maxFiles < 1) throw new RangeError("maxFiles must be a positive integer");
  const listed = await listPartitionFiles(reader, q.tenantId, first, last, types, maxFiles);
  for (const file of listed.files) await onFile(await readPartition(reader, file, []), file);
  return { filesMatched: listed.files.length, filesRead: listed.files.length, filesSkipped: listed.truncated ? 1 : 0, listingTruncated: listed.truncated };
}

/**
 * Runs a query.
 *
 * @throws RangeError for a tenant id, day, range, type, filter name or limit the query cannot take.
 */
export async function queryLake(reader: LakeReader, q: LakeQuery): Promise<LakeResult> {
  const { first, last, types } = checkScope(q);
  const limit = q.limit ?? DEFAULT_ROWS;
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_ROWS) throw new RangeError(`limit must be 1 to ${MAX_ROWS}`);

  const tests: [string, string][] = [];
  for (const [name, value] of Object.entries(q.where ?? {})) {
    if (!(name in EQUALITY_COLUMNS)) throw new RangeError(`unknown filter: ${JSON.stringify(name)}`);
    if (typeof value !== "string") throw new RangeError(`filter ${name} must be a string`);
    tests.push([EQUALITY_COLUMNS[name as LakeFilterName], name === "sha256" ? value.toLowerCase() : value]);
  }
  const listed = await listPartitionFiles(reader, q.tenantId, first, last, types, MAX_FILES);
  const files = listed.files;
  files.sort((a, b) => (a.date !== b.date ? (a.date < b.date ? -1 : 1) : a.key < b.key ? -1 : 1));
  const toRead = files;
  const rows: LakeRow[] = [];
  let truncated = false;
  let filesRead = 0;

  // One day at a time: its matches are ordered by ts before they count against the limit, so the
  // limit keeps the oldest rows of the range and never cuts a day in file order.
  for (let i = 0; i < toRead.length && !truncated; ) {
    const date = toRead[i].date;
    const day: LakeRow[] = [];
    for (; i < toRead.length && toRead[i].date === date; i++) {
      filesRead++;
      day.push(...(await readPartition(reader, toRead[i], tests)));
    }
    day.sort((a, b) => a.ts.getTime() - b.ts.getTime());
    for (const row of day) {
      if (rows.length === limit) {
        truncated = true;
        break;
      }
      rows.push(row);
    }
  }

  return { rows, truncated, filesMatched: files.length, filesRead, filesSkipped: listed.truncated ? 1 : 0, listingTruncated: listed.truncated };
}

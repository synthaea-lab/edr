import type { Prisma, PrismaClient } from "@prisma/client";
import { HUNT_STATEMENT_TIMEOUT_MS, HUNT_TRANSACTION_TIMEOUT_MS } from "@/lib/hunt";
import { eventWindow, type EventQuery } from "@/lib/hunt-events";
import { SEARCH_PAGE_SIZE, admitSearch } from "@/lib/hunt-search";
import { queryLake } from "@/lib/lake-query";
import type { LakeReader } from "@/lib/lake-store";

/**
 * Ad-hoc search over the raw event archive (#933, ADR-0025 point 10): the third source of the hunt
 * search, read through `queryLake` (ADR-0041). Read-only, one page, newest first.
 *
 * The same bounds as the Postgres sources, in the form this source can take:
 * - **Time.** A search runs under `HUNT_STATEMENT_TIMEOUT_MS`. There is no SQL statement to cancel,
 *   so the deadline is an `AbortSignal` that `queryLake` checks before every file; a file already
 *   being read is not interrupted, so a search can overrun by the time of one file. Past the
 *   deadline it throws a `TimeoutError`, which `searchFailure` maps to a 504.
 * - **In flight.** It takes one of the tenant's two slots (`admitSearch`), the same slots as a
 *   detection or case search, held for the whole read (the advisory lock lives in the transaction
 *   that wraps it). `busy` is a 429.
 * - **Rows.** A page is at most `SEARCH_PAGE_SIZE` rows, and a row carries the typed columns only,
 *   each cut to `FIELD_MAX`: never the event's source text (`includeEvent: false`, so the column is
 *   not even read), which is where a command line or an argument list lives.
 *
 * **Tenant isolation is structural.** `tenantId` is the caller's, from the session; the request has
 * no field for it, and `queryLake` lists only `tenant=<id>/` and rechecks every key it gets back.
 */

/** Longest value of a text field in a row. */
export const FIELD_MAX = 256;

export type EventRow = {
  type: string;
  /** ISO time of the event. */
  timestamp: string;
  agentId: string;
  comm: string | null;
  path: string | null;
  imagePath: string | null;
  daddr: string | null;
  query: string | null;
  sha256: string | null;
};

export type EventPage = {
  source: "events";
  rows: EventRow[];
  /** More events matched than the page holds; the page is the newest ones. There is no next page: narrow the window or filter. */
  truncated: boolean;
  /** The archive had more matching files than one search reads, so the oldest days were not read and the answer is incomplete. */
  incomplete: boolean;
  /** The days searched, `YYYY-MM-DD`, both included. */
  from: string;
  to: string;
};

export type EventSearchOutcome = { status: "ok"; page: EventPage } | { status: "busy" } | { status: "lake_off" };

export type EventSearchOptions = {
  /** Test seam: a shorter time limit. */
  timeoutMs?: number;
  /** Test seam: runs once the slot is held, before the read. */
  beforeRead?: (tx: Prisma.TransactionClient) => Promise<unknown>;
};

const cut = (value: string | null): string | null => (value === null ? null : value.slice(0, FIELD_MAX));

/**
 * Runs one search of the archive for `tenantId` as of `now`. `reader` is null when the archive is
 * not available (the lake is off): `lake_off`, which the API answers with a 503.
 */
export async function searchEventsWithinLimit(
  prisma: PrismaClient,
  reader: LakeReader | null,
  tenantId: string,
  query: EventQuery,
  now: Date = new Date(),
  options: EventSearchOptions = {}
): Promise<EventSearchOutcome> {
  if (reader === null) return { status: "lake_off" };
  const timeoutMs = options.timeoutMs ?? HUNT_STATEMENT_TIMEOUT_MS;
  const { from, to } = eventWindow(query, now);
  return prisma.$transaction(
    async (tx) => {
      if (!(await admitSearch(tx, tenantId))) return { status: "busy" } as const;
      await options.beforeRead?.(tx);
      const result = await queryLake(reader, {
        tenantId,
        from,
        to,
        types: query.types,
        where: query.where,
        limit: SEARCH_PAGE_SIZE,
        order: "desc",
        includeEvent: false,
        signal: AbortSignal.timeout(timeoutMs),
      });
      const page: EventPage = {
        source: "events",
        truncated: result.truncated,
        incomplete: result.filesSkipped > 0,
        from,
        to,
        rows: result.rows.map((r) => ({
          type: r.type,
          timestamp: r.ts.toISOString(),
          agentId: r.agentId.slice(0, FIELD_MAX),
          comm: cut(r.comm),
          path: cut(r.path),
          imagePath: cut(r.imagePath),
          daddr: cut(r.daddr),
          query: cut(r.query),
          sha256: cut(r.sha256),
        })),
      };
      return { status: "ok", page } as const;
    },
    { timeout: timeoutMs + (HUNT_TRANSACTION_TIMEOUT_MS - HUNT_STATEMENT_TIMEOUT_MS) }
  );
}

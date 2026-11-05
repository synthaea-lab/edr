/**
 * Rebuilds a tenant's prevalence counters from the telemetry lake (issue #77, "graph/prevalence
 * rebuild from the lake"; ties #72 and #76) and compares them with the counters ingest wrote.
 *
 * The counters are a fold over events: `extractObservations` says what one event shows and
 * `aggregateSightings` folds those per `(kind, key)`, which ingest does per batch and per agent.
 * The lake keeps each event's source text and its agent, so the same two functions over the lake's
 * rows give the same `(agent, kind, key)` sightings. Nothing here is a second implementation of
 * the counting rules: when they change, the rebuild changes with them, which is the point of it.
 *
 * **Read, not apply.** {@link rebuildSightings} and {@link compareSightings} read the lake and the
 * table and write nothing. Whether a rebuild may replace, merge into or only be compared with the
 * table is the owner's call (`issues/issue-77.md`, "Questions"), so no apply path exists.
 *
 * What it costs: {@link scanLake} reads every `exec` and `dns_query` file in range (the two types
 * that yield observations; the other types are pruned by their path), one file at a time, so memory
 * is the distinct `(agent, kind, key)` triples and not the events. A day is read in as many files
 * as the writer flushed (no compaction yet), and a range is at most 366 days per call, so a longer
 * history is several calls whose results {@link mergeSightings} folds.
 *
 * What it cannot reproduce, and reports instead of hiding (see {@link SightingsDiff}):
 * - events the lake never held: the writer drops those past the tenant's retention and keeps
 *   nothing at retention 0, and `prune-lake` deletes old days, while the counters keep their own
 *   180-day retention;
 * - observations ingest counted from `POST /api/ingest/detection`, which is not a lake input;
 * - an event that failed to parse, counted in `skipped` rather than guessed at.
 * A comparison over a range that does not start before the table's oldest sighting is therefore
 * expected to differ, and says how.
 */

import type { LakeReader } from "@/lib/lake-store";
import { scanLake, type LakeScanResult } from "@/lib/lake-query";
import { aggregateSightings, extractObservations, type Sighting } from "@/lib/prevalence";

/** The event types `extractObservations` reads; every other type yields nothing, so it is not read. */
export const OBSERVING_TYPES = ["exec", "dns_query"] as const;

/** Most `(agent, kind, key)` triples a rebuild holds: the table's own per-tenant cap, so it never builds what ingest would prune. */
export const MAX_REBUILT_SIGHTINGS = 5_000_000;

export type AgentSighting = Sighting & { agentId: string };

export interface RebuildResult {
  sightings: AgentSighting[];
  /** Rows read, and of those, rows whose event text was not a JSON object (their observations are lost, not guessed). */
  rows: number;
  skipped: number;
  /** What the scan read; `filesSkipped > 0` or `capped` means the result is partial. */
  scan: LakeScanResult;
  /** More distinct triples than {@link MAX_REBUILT_SIGHTINGS}: the rest were not folded. */
  capped: boolean;
  /**
   * True only when every matching file was listed and read, nothing was capped **and no event was
   * skipped** (`skipped === 0`): the only result a comparison should trust. A skipped event is one
   * whose observations are missing from the rebuild, so a comparison over it would report a false
   * difference (a review point on #1086).
   */
  complete: boolean;
}

const idOf = (agentId: string, kind: string, key: string) => `${agentId}\u0000${kind}\u0000${key}`;

/**
 * Folds one tenant's lake events over `from`..`to` (UTC days, at most 366) into per-agent sightings.
 *
 * @throws RangeError as {@link scanLake} does.
 */
export async function rebuildSightings(
  reader: LakeReader,
  q: { tenantId: string; from: string; to: string; maxFiles?: number; maxSightings?: number }
): Promise<RebuildResult> {
  const cap = q.maxSightings ?? MAX_REBUILT_SIGHTINGS;
  const folded = new Map<string, AgentSighting>();
  let rows = 0;
  let skipped = 0;
  let capped = false;

  const scan = await scanLake(reader, { tenantId: q.tenantId, from: q.from, to: q.to, types: [...OBSERVING_TYPES], maxFiles: q.maxFiles }, (fileRows) => {
    // One file's rows, grouped by agent: aggregateSightings folds per (kind, key) and a file may hold several agents.
    const byAgent = new Map<string, { at: Date; observations: ReturnType<typeof extractObservations> }[]>();
    for (const row of fileRows) {
      rows += 1;
      let event: unknown;
      try {
        event = JSON.parse(row.event);
      } catch {
        skipped += 1;
        continue;
      }
      const list = byAgent.get(row.agentId) ?? [];
      // `row.ts` is the event's time as ingest judged it (`eventTime`), so `first_seen`/`last_seen` agree.
      list.push({ at: row.ts, observations: extractObservations(event) });
      byAgent.set(row.agentId, list);
    }
    for (const [agentId, items] of Array.from(byAgent)) {
      for (const s of aggregateSightings(items)) {
        const id = idOf(agentId, s.kind, s.key);
        const seen = folded.get(id);
        if (seen === undefined) {
          if (folded.size >= cap) {
            capped = true;
            continue;
          }
          folded.set(id, { ...s, agentId });
        } else {
          if (s.firstSeen < seen.firstSeen) seen.firstSeen = s.firstSeen;
          if (s.lastSeen > seen.lastSeen) seen.lastSeen = s.lastSeen;
          seen.count += s.count;
        }
      }
    }
  });

  return { sightings: sortSightings(Array.from(folded.values())), rows, skipped, scan, capped, complete: scan.filesSkipped === 0 && !capped && skipped === 0 };
}

/** A stable order, so two rebuilds of the same lake are equal as lists. */
export function sortSightings(list: AgentSighting[]): AgentSighting[] {
  return list.sort((a, b) => idOf(a.agentId, a.kind, a.key).localeCompare(idOf(b.agentId, b.kind, b.key)));
}

/** Folds the sightings of consecutive ranges (a history longer than one call) the way ingest folds batches. */
export function mergeSightings(...parts: AgentSighting[][]): AgentSighting[] {
  const folded = new Map<string, AgentSighting>();
  for (const s of parts.flat()) {
    const id = idOf(s.agentId, s.kind, s.key);
    const seen = folded.get(id);
    if (seen === undefined) {
      folded.set(id, { ...s });
    } else {
      if (s.firstSeen < seen.firstSeen) seen.firstSeen = s.firstSeen;
      if (s.lastSeen > seen.lastSeen) seen.lastSeen = s.lastSeen;
      seen.count += s.count;
    }
  }
  return sortSightings(Array.from(folded.values()));
}

export interface SightingsDiff {
  /** In the lake's rebuild and not in the table (a counter that was pruned, or never written). */
  onlyRebuilt: AgentSighting[];
  /** In the table and not in the rebuild (history the lake does not hold, or a detection-path observation). */
  onlyTable: AgentSighting[];
  /** In both, with a different count or first/last time. */
  differing: { rebuilt: AgentSighting; table: AgentSighting }[];
  matching: number;
}

/** Whether the rebuilt counters are the table's, row for row. */
export function isIdentical(d: SightingsDiff): boolean {
  return d.onlyRebuilt.length === 0 && d.onlyTable.length === 0 && d.differing.length === 0;
}

/**
 * Compares a rebuild with the table's rows for the same tenant (`prevalenceSighting.findMany`).
 * Times compare to the millisecond, the precision the lake and the table both hold.
 */
export function compareSightings(rebuilt: AgentSighting[], table: AgentSighting[]): SightingsDiff {
  const tableById = new Map(table.map((s) => [idOf(s.agentId, s.kind, s.key), s]));
  const diff: SightingsDiff = { onlyRebuilt: [], onlyTable: [], differing: [], matching: 0 };
  const seen = new Set<string>();
  for (const r of rebuilt) {
    const id = idOf(r.agentId, r.kind, r.key);
    seen.add(id);
    const t = tableById.get(id);
    if (t === undefined) diff.onlyRebuilt.push(r);
    else if (t.count !== r.count || t.firstSeen.getTime() !== r.firstSeen.getTime() || t.lastSeen.getTime() !== r.lastSeen.getTime()) diff.differing.push({ rebuilt: r, table: t });
    else diff.matching += 1;
  }
  for (const [id, t] of Array.from(tableById)) if (!seen.has(id)) diff.onlyTable.push(t);
  return diff;
}

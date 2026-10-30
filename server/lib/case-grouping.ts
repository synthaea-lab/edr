/**
 * Pure decision logic for the detection-grouping heuristic (issue #50),
 * separated from the Prisma calls in app/api/cron/group-detections/route.ts
 * so it's unit-testable without a database.
 *
 * This is the honest limit of what's derivable from the single `technique`
 * string field actually stored on `Detection` — no MITRE tactic taxonomy
 * lookup exists in this codebase, so "related" means "same technique" or
 * "shares a base technique" (the part before the sub-technique dot, for each
 * id of a "/"-separated compound tag).
 */

export const GROUPING_TIME_WINDOW_MS = 30 * 60 * 1000; // 30 minutes

/**
 * Per-tenant cap on ungrouped detections read in one cron invocation (review,
 * Jihair54/Sollykhan): without a cap, the whole sweep ran inside one 30s
 * transaction over every ungrouped detection — fine for a small backlog
 * (measured: 2,000 detections grouped in ~21s) but a larger one (measured:
 * 20,000) blows the transaction timeout and rolls back with *no* progress,
 * every retry redoing the same doomed work. 500 leaves comfortable margin
 * under that measured rate, and staying well under `caseId: null` per pass
 * means the next cron tick picks up exactly where this one left off — a
 * backlog drains over several ticks instead of never draining at all.
 */
export const GROUPING_BATCH_SIZE = 500;

const SEVERITY_RANK: Record<string, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

/**
 * The MITRE base techniques a `technique` field names: "T1059.001" -> {T1059}.
 * Rules tag a compound join with "/"-separated ids ("T1566.001/T1204.002",
 * "T1560/T1041"), so each id is split out before dropping its sub-technique
 * (#1053: splitting the whole string on "." turned that example into "T1566"
 * and lost T1204).
 */
export function baseTechniques(technique: string): Set<string> {
  return new Set(technique.split("/").map((id) => id.split(".")[0]));
}

/**
 * Some base technique named by `a` is also named by `b`. Two compound tags
 * sharing one id are related: each alert would group with an alert carrying
 * that id alone, and grouping is not meant to depend on arrival order.
 */
export function isRelatedTechnique(a: string, b: string): boolean {
  if (a === b) {
    return true;
  }
  const basesOfB = baseTechniques(b);
  return Array.from(baseTechniques(a)).some((base) => basesOfB.has(base));
}

export function withinTimeWindow(a: Date, b: Date, windowMs: number = GROUPING_TIME_WINDOW_MS): boolean {
  return Math.abs(a.getTime() - b.getTime()) <= windowMs;
}

/** Higher-severity-wins comparison; unknown severities never outrank a known one. */
export function outranksSeverity(candidate: string, current: string): boolean {
  const candidateRank = SEVERITY_RANK[candidate] ?? -1;
  const currentRank = SEVERITY_RANK[current] ?? -1;
  return candidateRank > currentRank;
}

/**
 * The damage manifest of a case (issue #82): the files a ransomware detection says its
 * process renamed or deleted, so a restoration tool has a scope.
 *
 * The agent attaches the process's recent renames and deletions to a T1486 detection as
 * further triggering events (`Detection.events` after the first). The ingest route keeps
 * the first in `event` and the rest in `meta.additional_events`; this reads both. The JSON
 * comes from an agent on a possibly compromised host, so every shape is checked and an
 * unknown one is skipped, never trusted.
 */

export const RANSOMWARE_TECHNIQUE = "T1486";
/** Entries a case's manifest returns; `truncated` says when there were more. */
export const MAX_DAMAGE_ENTRIES = 1000;

export type DamageEntry = {
  action: "renamed" | "deleted";
  path: string;
  /** The new path, for a rename. */
  to?: string;
  /** Milliseconds since the epoch, from the event's own clock; absent when it has none. */
  at?: number;
  agentId: string;
};

export type DamageManifest = { files: DamageEntry[]; truncated: boolean };

type DetectionLike = {
  technique: string;
  agentId: string;
  event: unknown;
  meta: unknown;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function entryOf(event: unknown, agentId: string): DamageEntry | null {
  if (!isRecord(event)) return null;
  const ts = isRecord(event.meta) ? event.meta.timestamp_ns : undefined;
  const at = typeof ts === "number" && Number.isFinite(ts) ? Math.floor(ts / 1_000_000) : undefined;
  if (event.type === "file_rename" && typeof event.old_path === "string" && typeof event.new_path === "string") {
    return { action: "renamed", path: event.old_path, to: event.new_path, at, agentId };
  }
  if (event.type === "file_delete" && typeof event.path === "string") {
    return { action: "deleted", path: event.path, at, agentId };
  }
  return null;
}

/** The manifest of the ransomware detections among `detections`: distinct files, oldest first. */
export function damageManifestOf(detections: DetectionLike[]): DamageManifest {
  const seen = new Set<string>();
  const files: DamageEntry[] = [];
  let truncated = false;
  for (const d of detections) {
    if (d.technique !== RANSOMWARE_TECHNIQUE) continue;
    const further = isRecord(d.meta) && Array.isArray(d.meta.additional_events) ? d.meta.additional_events : [];
    for (const event of [d.event, ...further]) {
      const entry = entryOf(event, d.agentId);
      if (!entry) continue;
      const key = `${entry.agentId}\u0000${entry.action}\u0000${entry.path}\u0000${entry.to ?? ""}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (files.length >= MAX_DAMAGE_ENTRIES) {
        truncated = true;
        continue;
      }
      files.push(entry);
    }
  }
  files.sort((a, b) => (a.at ?? 0) - (b.at ?? 0));
  return { files, truncated };
}

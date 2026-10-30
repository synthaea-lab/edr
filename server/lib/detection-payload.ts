import { z } from "zod";

const SeveritySchema = z.enum(["low", "medium", "high", "critical"]);

// The agent-supplied strings below are bounded two ways (#1060), by who controls them.
// Rule, model and feed identifiers come from content the team ships, so an oversized one is a
// bug or a forged payload and is refused, as #1058 does for techniques. The alert title and the
// correlator's case id carry text the monitored process chooses (its command line, its image
// name), so they are cut instead: refusing them would let a process pad its own argv until its
// detections stop reaching the server (a 4xx is not retried).

// Lab alerts measured on 2026-10-29 run to 358 bytes; the command line inside a title is
// unbounded by construction (2 MiB argv on Linux, 32,767 UTF-16 units from the Windows PEB).
export const MAX_TITLE_BYTES = 64 * 1024;
// `pid:comm`, where `comm` on Windows is the image basename: up to 255 UTF-16 units on NTFS.
export const MAX_CASE_ID_BYTES = 1024;

/**
 * `value` cut to at most `maxBytes` of UTF-8 on a character boundary, with a marker saying how
 * long it was; unchanged when it fits.
 */
export function truncateUtf8(value: string, maxBytes: number): string {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length <= maxBytes) {
    return value;
  }
  let end = maxBytes;
  // Back off continuation bytes (10xxxxxx) so the cut never splits a character.
  while (end > 0 && (bytes[end] & 0xc0) === 0x80) {
    end--;
  }
  return `${bytes.subarray(0, end).toString("utf8")}… [truncated, ${bytes.length} bytes]`;
}

const truncatedString = (maxBytes: number) =>
  z.string().min(1).transform((value) => truncateUtf8(value, maxBytes));

const SourceSchema = z.discriminatedUnion("engine", [
  z.object({ engine: z.literal("rule"), rule_id: z.string().min(1).max(256) }),
  z.object({ engine: z.literal("sigma"), rule_id: z.string().min(1).max(256) }),
  z.object({
    engine: z.literal("ml"),
    tier: z.number().int().min(0).max(255),
    model_id: z.string().min(1).max(128),
    model_version: z.string().min(1).max(128),
  }),
  z.object({ engine: z.literal("correlator"), case_id: truncatedString(MAX_CASE_ID_BYTES) }),
  // YARA itself caps identifiers at 128 characters.
  z.object({ engine: z.literal("yara"), rule_name: z.string().min(1).max(128) }),
  z.object({
    engine: z.literal("ioc"),
    kind: z.enum(["sha256", "sha1", "md5", "ip", "domain"]),
    // The longest canonical indicator is a 253-character domain.
    indicator: z.string().min(1).max(256),
    // The agent already cuts feed metadata at 64 (docs/detection/ioc-matching.md).
    feed: z.string().min(1).max(64),
    feed_version: z.string().min(1).max(64),
    reference: z.string().min(1).max(2048).optional(),
  }),
]);

// The technique fields are agent-supplied, so they are bounded here (#1058): before this, only
// nginx's 8 MiB body limit capped them, and a buggy or compromised agent could store
// megabyte-long tags that every case-grouping pass, case title and hunt query then processes.
// Every value emitted on 2026-10-29 fits with a wide margin: MITRE ids (`T1059.001`), the
// engine and marker tags (`BAYES`, `IOC`, `LOG-SOURCE`, `RESPONSE-*`), and at most 23
// characters for a joined compound. YARA and Sigma only ever yield `T\d{4}(\.\d{3})?`.
// One element of the structured `techniques` list: the agent splits `/`-joined compound
// tags before upload (`techniques_from`, agent/src/sink.rs), so an element has no `/`.
const TechniqueIdSchema = z.string().regex(/^[A-Za-z0-9._-]{1,64}$/);
// The legacy single `technique` string is the rule's tag as-is, compound `/` included.
const LegacyTechniqueSchema = z.string().regex(/^[A-Za-z0-9._/-]{1,128}$/);
// The longest compound joins three ids; 16 leaves room without being unbounded.
const MAX_TECHNIQUES = 16;

// Mirrors schema::Detection's JSON shape. The Rust schema owns the wire format;
// keep this validation in step with its golden fixtures when the schema changes.
const StructuredDetectionSchema = z.object({
  timestamp_ns: z.number().finite().positive(),
  severity: SeveritySchema,
  title: truncatedString(MAX_TITLE_BYTES),
  source: SourceSchema,
  score: z.number().finite().nullable().optional(),
  // Feature names come from the shipped models; the widest has 17 features today.
  attributions: z.array(z.object({
    feature: z.string().min(1).max(128),
    value: z.number().finite(),
    contribution: z.number().finite(),
  })).max(64).default([]),
  techniques: z.array(TechniqueIdSchema).max(MAX_TECHNIQUES).default([]),
  events: z.array(z.record(z.any())),
});

// Keep the original API contract for enrolled agents that have not upgraded.
const LegacyDetectionSchema = z.object({
  timestamp_ns: z.number().finite().positive(),
  technique: LegacyTechniqueSchema,
  severity: SeveritySchema,
  event: z.record(z.any()),
  meta: z.record(z.any()),
});

export type StoredDetectionPayload = {
  timestamp: Date;
  technique: string;
  severity: z.infer<typeof SeveritySchema>;
  event: Record<string, any>;
  meta: Record<string, any>;
};

function sourceIdentity(source: z.infer<typeof SourceSchema>): Record<string, string> {
  switch (source.engine) {
    case "rule":
    case "sigma":
      return { rule_id: source.rule_id };
    case "ml":
      return { model_id: source.model_id };
    case "correlator":
      return { case_id: source.case_id };
    case "yara":
      return { rule_id: source.rule_name };
    case "ioc":
      return { indicator: source.indicator, feed: source.feed };
  }
}

/** Validate both wire formats and project the structured one into current storage. */
export function parseDetectionPayload(body: unknown): StoredDetectionPayload {
  if (typeof body === "object" && body !== null && "source" in body) {
    const detection = StructuredDetectionSchema.parse(body);
    const { source, attributions, techniques, events } = detection;
    return {
      timestamp: new Date(detection.timestamp_ns / 1_000_000),
      technique: techniques[0] ?? source.engine.toUpperCase(),
      severity: detection.severity,
      event: events[0] ?? {},
      meta: {
        title: detection.title,
        source,
        // The evidence graph reads these allowlisted fields directly from meta.
        ...sourceIdentity(source),
        score: detection.score ?? null,
        attributions,
        techniques,
        // Preserve further triggering events until Detection has a dedicated
        // relation for them. The first event stays in the existing event column.
        additional_events: events.slice(1),
      },
    };
  }

  const detection = LegacyDetectionSchema.parse(body);
  return {
    timestamp: new Date(detection.timestamp_ns / 1_000_000),
    technique: detection.technique,
    severity: detection.severity,
    event: detection.event,
    meta: detection.meta,
  };
}

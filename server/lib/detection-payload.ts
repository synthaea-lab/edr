import { z } from "zod";

const SeveritySchema = z.enum(["low", "medium", "high", "critical"]);

const SourceSchema = z.discriminatedUnion("engine", [
  z.object({ engine: z.literal("rule"), rule_id: z.string().min(1) }),
  z.object({ engine: z.literal("sigma"), rule_id: z.string().min(1) }),
  z.object({
    engine: z.literal("ml"),
    tier: z.number().int().min(0).max(255),
    model_id: z.string().min(1),
    model_version: z.string().min(1),
  }),
  z.object({ engine: z.literal("correlator"), case_id: z.string().min(1) }),
  z.object({ engine: z.literal("yara"), rule_name: z.string().min(1) }),
]);

// Mirrors schema::Detection's JSON shape. The Rust schema owns the wire format;
// keep this validation in step with its golden fixtures when the schema changes.
const StructuredDetectionSchema = z.object({
  timestamp_ns: z.number().finite().positive(),
  severity: SeveritySchema,
  title: z.string().min(1),
  source: SourceSchema,
  score: z.number().finite().nullable().optional(),
  attributions: z.array(z.object({
    feature: z.string().min(1),
    value: z.number().finite(),
    contribution: z.number().finite(),
  })).default([]),
  techniques: z.array(z.string().min(1)).default([]),
  events: z.array(z.record(z.any())),
});

// Keep the original API contract for enrolled agents that have not upgraded.
const LegacyDetectionSchema = z.object({
  timestamp_ns: z.number().finite().positive(),
  technique: z.string().min(1),
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

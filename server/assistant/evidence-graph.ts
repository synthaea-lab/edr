/**
 * Evidence graph (issue #50): the only thing the narrative LLM client ever
 * sees. Built by projecting a fixed, named allowlist of fields out of each
 * Detection's `event`/`meta` JSON blobs — never a pass-through of those
 * blobs. This is the choke point that satisfies "no raw telemetry access":
 * `generateNarrative` (assistant/llm-client.ts) only accepts an
 * `EvidenceGraph`, and this is the one place that reads `event`/`meta`.
 *
 * `Detection.event`/`meta` are unstructured JSON today (the ingest route
 * validates them as `z.record(z.any())`), so the field names below are
 * read defensively — present-if-known, silently absent otherwise. Once the
 * correlator-side plumbing lands (tracked as a follow-up to this issue),
 * `meta.attributions` starts carrying real per-feature contributions and
 * flows through the same allowlist without changing its shape.
 */

import { prisma } from "@/lib/prisma";

const CMDLINE_MAX_CHARS = 200;

export interface EvidenceAttribution {
  feature: string;
  value: number;
  contribution: number;
}

export interface EvidenceItem {
  detectionId: string;
  timestamp: string; // ISO 8601
  technique: string;
  severity: string;
  processName?: string;
  parentProcessName?: string;
  cmdline?: string;
  ruleId?: string;
  modelId?: string;
  attributions?: EvidenceAttribution[];
}

export interface EvidenceGraph {
  caseId: string;
  title: string;
  severity: string;
  status: string;
  createdAt: string; // ISO 8601
  items: EvidenceItem[];
}

/**
 * Loads a case's grouped detections and projects each one through the
 * evidence allowlist. Tenant-scoped: a caseId belonging to another tenant
 * resolves to `null`, matching the not-found-vs-forbidden convention used
 * across the console API routes.
 */
export async function buildEvidenceGraph(
  tenantId: string,
  caseId: string
): Promise<EvidenceGraph | null> {
  const case_ = await prisma.case.findFirst({
    where: { id: caseId, tenantId },
    include: { detections: { orderBy: { timestamp: "asc" } } },
  });

  if (!case_) {
    return null;
  }

  return {
    caseId: case_.id,
    title: case_.title,
    severity: case_.severity,
    status: case_.status,
    createdAt: case_.createdAt.toISOString(),
    items: case_.detections.map(projectEvidenceItem),
  };
}

/** Exported for unit testing the allowlist projection in isolation from Prisma. */
export function projectEvidenceItem(detection: {
  id: string;
  timestamp: Date;
  technique: string;
  severity: string;
  event: unknown;
  meta: unknown;
}): EvidenceItem {
  const event = asRecord(detection.event);
  const meta = asRecord(detection.meta);

  return {
    detectionId: detection.id,
    timestamp: detection.timestamp.toISOString(),
    technique: detection.technique,
    severity: detection.severity,
    processName: pickString(event, "process_name"),
    parentProcessName: pickString(event, "parent_process_name"),
    cmdline: truncate(pickString(event, "cmdline"), CMDLINE_MAX_CHARS),
    ruleId: pickString(meta, "rule_id"),
    modelId: pickString(meta, "model_id"),
    attributions: pickAttributions(meta, "attributions"),
  };
}

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" ? (value as Record<string, unknown>) : {};
}

function pickString(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  return typeof value === "string" ? value : undefined;
}

function pickAttributions(
  record: Record<string, unknown>,
  key: string
): EvidenceAttribution[] | undefined {
  const value = record[key];
  if (!Array.isArray(value)) {
    return undefined;
  }

  const attributions = value
    .map((entry): EvidenceAttribution | undefined => {
      if (typeof entry !== "object" || entry === null) {
        return undefined;
      }
      const { feature, value: featureValue, contribution } = entry as Record<string, unknown>;
      if (
        typeof feature !== "string" ||
        typeof featureValue !== "number" ||
        typeof contribution !== "number"
      ) {
        return undefined;
      }
      return { feature, value: featureValue, contribution };
    })
    .filter((entry): entry is EvidenceAttribution => entry !== undefined);

  return attributions.length > 0 ? attributions : undefined;
}

function truncate(value: string | undefined, maxChars: number): string | undefined {
  if (value === undefined || value.length <= maxChars) {
    return value;
  }
  return `${value.slice(0, maxChars)} [truncated]`;
}

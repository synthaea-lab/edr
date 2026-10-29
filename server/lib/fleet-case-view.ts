/**
 * What the console shows of a fleet case (#62). Pure, and safe to import from a client component:
 * no Prisma, no Node. The wording and the styles are tested without rendering anything.
 */

export const STATUS_LABEL: Record<string, string> = {
  open: "open",
  investigating: "investigating",
  resolved: "resolved",
  false_positive: "false positive",
};

const SEVERITY_STYLE: Record<string, string> = {
  critical: "bg-red-100 text-red-800 border-red-200",
  high: "bg-orange-100 text-orange-800 border-orange-200",
  medium: "bg-yellow-100 text-yellow-800 border-yellow-200",
  low: "bg-gray-100 text-gray-700 border-gray-200",
};
const NEUTRAL_STYLE = "bg-gray-50 text-gray-600 border-gray-200";

/** A severity badge's classes; a severity the console does not know gets the neutral one. */
export function severityStyle(severity: string): string {
  return SEVERITY_STYLE[severity] ?? NEUTRAL_STYLE;
}

export type EntityLike = { kind: string; key: string };

/**
 * One entity a fleet case joined on, as a short label and the full value for a tooltip. A hash
 * is cut to 12 characters (enough to recognise, not to read); the detail page prints it whole.
 * The result is text: it is escaped where it is rendered, never trusted as markup.
 */
export function describeEntity(entity: EntityLike): { label: string; title: string } {
  if (entity.kind === "sha256") return { label: `file ${entity.key.slice(0, 12)}…`, title: entity.key };
  if (entity.kind === "identity") return { label: `account ${entity.key}`, title: entity.key };
  return { label: `${entity.kind} ${entity.key}`, title: entity.key };
}

/** "2026-10-20 14:05 UTC": the same string on every machine, unlike a locale's. */
export function formatWhen(date: Date): string {
  return `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

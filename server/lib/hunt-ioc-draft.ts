import { isIP } from "net";
import { HuntValidationError } from "@/lib/hunt";
import { ruleSlug, type GraduationDetection, type GraduationHunt, type GraduationResult } from "@/lib/hunt-graduation";

/**
 * Hunt-to-draft-IOC-set graduation (#934, the IOC half of #61's graduation box).
 *
 * The draft is one feed file in the line format `crates/intel` loads (`docs/detection/ioc-matching.md`):
 * `sha256:<hex>` and `ip:<address>` lines under `#` comments, which the engine ignores. It is the
 * indicators the hunt's matched detections carry, nothing more: a detection says something
 * suspicious happened, not that every hash or address it names is bad, so every line is for a
 * person to keep or drop. It writes nothing and ships nothing.
 *
 * Domains are not drafted. A listed domain matches every name beneath it, and the device carries
 * no public-suffix list, so a domain has to be checked against one before it enters a set
 * (ADR-0038 section 6); that check is the server's feed builder, not this exporter.
 */

/** The IOC-set directory of the content repo, beside `rules/sigma` and `rules/yara`. */
export const IOC_DRAFT_DIR = "rules/ioc";

const SHA256 = /^[0-9a-f]{64}$/i;

/** Which draft a graduation request asks for; a body without `kind` is the Sigma draft (#618). */
export function graduationKind(body: unknown): "sigma" | "ioc" {
  const kind = typeof body === "object" && body !== null && !Array.isArray(body) ? (body as Record<string, unknown>).kind : undefined;
  if (kind === undefined || kind === "sigma") return "sigma";
  if (kind === "ioc") return "ioc";
  throw new HuntValidationError('kind must be "sigma" or "ioc"');
}

/** Validates the body of an IOC graduation: `{ kind: "ioc" }` and nothing else (a set has no platform). */
export function parseIocGraduationRequest(body: unknown): void {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new HuntValidationError("body must be an object");
  }
  for (const key of Object.keys(body)) {
    if (key !== "kind") throw new HuntValidationError(`unknown field "${key}"`);
  }
}

type Skipped = { loopback: number; domains: number; malformed: number };

/**
 * The address as the device lists it, or `null` for one the engine refuses (loopback, unspecified,
 * also IPv4-mapped). An IPv4-mapped IPv6 address becomes its IPv4 form, as `intel` does, so the
 * two spellings of one host are one line.
 */
function addressLine(raw: unknown): { ok: true; address: string } | { ok: false; why: "loopback" | "malformed" } {
  if (typeof raw !== "string" || isIP(raw) === 0) return { ok: false, why: "malformed" };
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(raw);
  const text = mapped ? mapped[1] : raw.toLowerCase();
  if (isIP(text) === 4) {
    const first = Number(text.split(".")[0]);
    return first === 127 || text === "0.0.0.0" ? { ok: false, why: "loopback" } : { ok: true, address: text };
  }
  // A zone (`fe80::1%eth0`) has no place in the line format: refuse rather than widen it.
  if (text.includes("%")) return { ok: false, why: "malformed" };
  return text === "::1" || text === "::" ? { ok: false, why: "loopback" } : { ok: true, address: text };
}

/**
 * Builds the draft for `hunt` from `detections` (the sample of its newest run, newest first).
 * Pure: it reads nothing and writes nothing.
 */
export function draftIocSetFromHunt(hunt: GraduationHunt, detections: GraduationDetection[]): GraduationResult {
  const hashes = new Set<string>();
  const addresses = new Set<string>();
  const skipped: Skipped = { loopback: 0, domains: 0, malformed: 0 };

  for (const { event } of detections) {
    const e = typeof event === "object" && event !== null ? (event as Record<string, unknown>) : {};
    if (e.type === "exec" && e.sha256 !== undefined && e.sha256 !== null) {
      if (typeof e.sha256 === "string" && SHA256.test(e.sha256)) hashes.add(e.sha256.toLowerCase());
      else skipped.malformed++;
    } else if (e.type === "connect" || e.type === "network_flow") {
      const line = addressLine(e.daddr);
      if (line.ok) addresses.add(line.address);
      else skipped[line.why]++;
    } else if (e.type === "dns_query") {
      skipped.domains++;
    }
  }

  if (hashes.size === 0 && addresses.size === 0) {
    const reasons = [
      skipped.domains > 0 && `${skipped.domains} DNS queries (domains are not drafted, see below)`,
      skipped.loopback > 0 && `${skipped.loopback} loopback or unspecified addresses (the engine refuses them)`,
      skipped.malformed > 0 && `${skipped.malformed} values that are not a SHA-256 or an address`,
    ].filter(Boolean);
    return {
      ok: false,
      problems: [
        `None of the detections this hunt matched carries an indicator an IOC set can hold: an exec event with a SHA-256 (the enrichment has to have hashed the image), or a connect or network flow event with a destination address.${
          reasons.length > 0 ? ` Skipped: ${reasons.join("; ")}.` : ""
        } Run the hunt again, or narrow it to detections that carry one.`,
      ],
    };
  }

  const slug = ruleSlug(hunt.name);
  const sorted = (values: Set<string>) => Array.from(values).sort();
  const text = [
    `# DRAFT graduated from hunt ${hunt.id} (query version ${hunt.version}). A person reviews it; it enters the normal PR and CI path.`,
    "# One line per indicator. The matched detections name these values; that does not make each one bad.",
    ...sorted(hashes).map((h) => `sha256:${h}`),
    ...sorted(addresses).map((a) => `ip:${a}`),
    "",
  ].join("\n");

  const todo = [
    "Every indicator is a value a matched detection carried, not a verdict: drop the benign ones (a shared CDN address, a system binary's hash) before this ships.",
    `The file name is the feed's name in every finding (\`${slug}\`); rename it to say where the indicators came from.`,
    `The path \`${IOC_DRAFT_DIR}/\` is where this draft proposes IOC sets live in the content repo; no directory or CI check exists for one yet.`,
    "Nothing delivers a set to the agents yet: signed delivery through the content manifest waits on the production signing keys (#753).",
  ];
  if (skipped.domains > 0) {
    todo.push(`${skipped.domains} DNS queries were not drafted: a domain needs the public-suffix check of the feed builder first.`);
  }
  if (skipped.loopback > 0) todo.push(`${skipped.loopback} loopback or unspecified addresses were left out; the engine refuses them.`);
  if (skipped.malformed > 0) todo.push(`${skipped.malformed} values were left out because they are not a SHA-256 or an address.`);

  return { ok: true, files: [{ path: `${IOC_DRAFT_DIR}/${slug}.txt`, content: text }], todo };
}

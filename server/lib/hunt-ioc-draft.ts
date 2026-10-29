import { isIP } from "net";
import { HuntValidationError } from "@/lib/hunt";
import { normalizeDomain } from "@/lib/ioc-feed";
import { isPublicSuffix } from "@/lib/public-suffix";
import { observationsOfDetections, prevalenceKey, type Observation, type Prevalence } from "@/lib/prevalence";
import { ruleSlug, type GraduationDetection, type GraduationHunt, type GraduationResult } from "@/lib/hunt-graduation";

/**
 * Hunt-to-draft-IOC-set graduation (#934, the IOC half of #61's graduation box).
 *
 * The draft is one feed file in the line format `crates/intel` loads (`docs/detection/ioc-matching.md`):
 * `sha256:<hex>`, `ip:<address>` and `domain:<name>` lines under `#` comments, which the engine ignores. It is the
 * indicators the hunt's matched detections carry, nothing more: a detection says something
 * suspicious happened, not that every hash or address it names is bad, so every line is for a
 * person to keep or drop. It writes nothing and ships nothing.
 *
 * A listed domain matches every name beneath it, and the device carries no public-suffix list
 * (ADR-0038 section 6), so a queried name enters the set only if the feed builder's own rules accept
 * it (`normalizeDomain`: ASCII, 2 to 8 labels, valid syntax) and it is not itself a public suffix
 * (`isPublicSuffix`, the check `buildFeed` makes). The name is listed as queried: a hunt that
 * matched `c2.evil.example` drafts that name, not its registrable parent.
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

/**
 * What the fleet says about the hashes and domains of a draft (never addresses: prevalence does not
 * track them). `hosts` is how many hosts of the tenant have reported anything; `found` and
 * `lookedUp` are what `getPrevalenceBatch` returned and the keys it checked, so a value it did not
 * check is not described as unseen.
 */
export interface IocPrevalence {
  hosts: number;
  found: Map<string, Prevalence>;
  lookedUp: Set<string>;
}

/** A value on at least this many hosts and this share of the fleet is marked widespread. */
const WIDESPREAD_MIN_HOSTS = 5;
const WIDESPREAD_SHARE = 0.05;

/** The hash and domain observations of `detections`: what the route has prevalence looked up for. */
export function iocObservations(detections: GraduationDetection[]): Observation[] {
  return observationsOfDetections(detections).filter((o) => o.kind === "sha256" || o.kind === "domain");
}

type Skipped = { loopback: number; suffixes: number; malformed: number };

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
export function draftIocSetFromHunt(
  hunt: GraduationHunt,
  detections: GraduationDetection[],
  prevalence?: IocPrevalence
): GraduationResult {
  const hashes = new Set<string>();
  const addresses = new Set<string>();
  const domains = new Set<string>();
  const skipped: Skipped = { loopback: 0, suffixes: 0, malformed: 0 };

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
      const name = typeof e.query === "string" ? normalizeDomain(e.query) : null;
      if (name === null || !name.ok) skipped.malformed++;
      else if (isPublicSuffix(name.name)) skipped.suffixes++;
      else domains.add(name.name);
    }
  }

  if (hashes.size === 0 && addresses.size === 0 && domains.size === 0) {
    const reasons = [
      skipped.suffixes > 0 && `${skipped.suffixes} DNS queries for a public suffix (it would flag every name beneath it)`,
      skipped.loopback > 0 && `${skipped.loopback} loopback or unspecified addresses (the engine refuses them)`,
      skipped.malformed > 0 && `${skipped.malformed} values that are not a SHA-256, an address or a listable domain`,
    ].filter(Boolean);
    return {
      ok: false,
      problems: [
        `None of the detections this hunt matched carries an indicator an IOC set can hold: an exec event with a SHA-256 (the enrichment has to have hashed the image), or a connect or network flow event with a destination address, or a DNS query for a listable domain.${
          reasons.length > 0 ? ` Skipped: ${reasons.join("; ")}.` : ""
        } Run the hunt again, or narrow it to detections that carry one.`,
      ],
    };
  }

  const slug = ruleSlug(hunt.name);
  const sorted = (values: Set<string>) => Array.from(values).sort();
  let widespread = 0;
  let unchecked = 0;
  /** The comment line above an indicator that says how the fleet has seen it, if it was checked. */
  const withPrevalence = (kind: "sha256" | "domain") => (key: string): string[] => {
    const line = `${kind}:${key}`;
    if (!prevalence || prevalence.hosts === 0) return [line];
    const id = prevalenceKey(kind, key);
    if (!prevalence.lookedUp.has(id)) {
      unchecked++;
      return [line];
    }
    const seen = prevalence.found.get(id) ?? null;
    const common = seen !== null && seen.hostCount >= WIDESPREAD_MIN_HOSTS && seen.hostCount / prevalence.hosts >= WIDESPREAD_SHARE;
    if (common) widespread++;
    const text = seen
      ? `seen on ${seen.hostCount} of ${prevalence.hosts} hosts, first ${seen.firstSeen.toISOString().slice(0, 10)}`
      : "never seen on this fleet before";
    return [`# ${text}${common ? " (widespread: likely benign)" : ""}`, line];
  };
  const text = [
    `# DRAFT graduated from hunt ${hunt.id} (query version ${hunt.version}). A person reviews it; it enters the normal PR and CI path.`,
    "# One line per indicator. The matched detections name these values; that does not make each one bad.",
    ...sorted(hashes).flatMap(withPrevalence("sha256")),
    ...sorted(addresses).map((a) => `ip:${a}`),
    ...sorted(domains).flatMap(withPrevalence("domain")),
    "",
  ].join("\n");

  const todo = [
    "Every indicator is a value a matched detection carried, not a verdict: drop the benign ones (a shared CDN address, a system binary's hash) before this ships.",
    `The file name is the feed's name in every finding (\`${slug}\`); rename it to say where the indicators came from.`,
    `The path \`${IOC_DRAFT_DIR}/\` is where this draft proposes IOC sets live in the content repo; CI checks every \`*.txt\` there (the engine loads each line, the feed builder applies the public-suffix check), but no feed exists yet.`,
    "Nothing delivers a set to the agents yet: signed delivery through the content manifest waits on the production signing keys (#753).",
  ];
  if (widespread > 0) {
    todo.push(`${widespread} hashes or domains are on at least ${WIDESPREAD_SHARE * 100}% of this fleet's hosts (and ${WIDESPREAD_MIN_HOSTS}+): their comment says widespread. They are kept, since a hunt may be about a common value, but they are probably benign.`);
  }
  if (unchecked > 0) todo.push(`${unchecked} hashes or domains were not checked against the fleet's prevalence (too many to look up at once).`);
  if (prevalence && prevalence.hosts > 0) {
    todo.push("Addresses carry no fleet prevalence: check a shared address (CDN, cloud provider) by hand.");
  }
  if (domains.size > 0) {
    todo.push("A domain line matches the name and every name beneath it: widen a name to its parent only on purpose, and drop a shared service (a CDN, a cloud API) the detection merely reached.");
  }
  if (skipped.suffixes > 0) todo.push(`${skipped.suffixes} DNS queries were left out because the name is a public suffix.`);
  if (skipped.loopback > 0) todo.push(`${skipped.loopback} loopback or unspecified addresses were left out; the engine refuses them.`);
  if (skipped.malformed > 0) todo.push(`${skipped.malformed} values were left out because they are not a SHA-256, an address or a domain the feed builder accepts.`);

  return { ok: true, files: [{ path: `${IOC_DRAFT_DIR}/${slug}.txt`, content: text }], todo };
}

/**
 * IOC feed builder (issue #60, ADR-0038).
 *
 * Turns the text of one threat-intelligence feed into the file an agent loads from
 * `<content_root>/ioc/<feed>.txt`: one `sha256:<hex>`, `ip:<address>` or `domain:<name>` per line,
 * normalised, de-duplicated and sorted, so the same input always gives the same bytes (and so the
 * same hash in a content manifest).
 *
 * It applies the rules the device applies at load (`crates/intel`: hash length, loopback and
 * unspecified addresses, domain syntax and label count) so a feed that would be rejected there is
 * rejected here with a reason, and it adds the one check the device cannot make: a listed domain
 * must not be a public suffix. A listed domain covers every subdomain, so `co.uk` would flag a
 * whole country. The suffix list is a dependency this module does not carry: the caller passes
 * `isPublicSuffix`, and without one every domain is refused rather than published unchecked.
 *
 * Pure: no I/O, no clock. Sources live in their own modules (`ioc-csv.ts`, `ioc-stix.ts`, `ioc-misp.ts`); fetching,
 * MISP and per-tenant enablement are not built.
 */

import { createHash } from "crypto";
import { isIP } from "net";

/** The kinds the engine matches. */
export type IocKind = "sha256" | "ip" | "domain";

export type RejectReason =
  | "unknown_kind"
  | "bad_hash"
  | "bad_address"
  | "unusable_address"
  | "bad_domain"
  | "non_ascii_domain"
  | "domain_too_broad"
  | "domain_too_deep"
  | "public_suffix"
  | "public_suffix_unchecked"
  | "bad_csv"
  | "bad_stix"
  | "unsupported_pattern"
  | "revoked"
  | "expired"
  | "not_yet_valid"
  | "bad_misp"
  | "not_for_detection"
  | "deleted";

export interface Rejection {
  /** 1-based line number in the source text. */
  line: number;
  reason: RejectReason;
  /** The offending value, cut to 80 characters. */
  value: string;
}

export interface FeedInput {
  /** Feed name: becomes the file stem, so it is restricted (see {@link isValidFeedName}). */
  feed: string;
  text: string;
  /**
   * Whether `name` (normalised, lowercase) is itself a public suffix such as `co.uk` or
   * `blogspot.com`. Absent: every domain is refused (fail closed).
   */
  isPublicSuffix?: (name: string) => boolean;
  /** Kind assumed for a line without a `kind:` prefix (a plain list of hashes, say). */
  defaultKind?: IocKind;
  /** How many rejections to list; the total is always counted. Default 100. */
  maxRejectedListed?: number;
}

export interface FeedResult {
  feed: string;
  /** The `ioc/<feed>.txt` content: sorted, no duplicates, `\n`-terminated, empty if nothing passed. */
  text: string;
  /** SHA-256 of `text` as hex: the content-manifest key. */
  sha256: string;
  counts: { sha256: number; ip: number; domain: number; total: number };
  /** Lines carrying an indicator (blank lines and comments excluded). */
  read: number;
  /** Accepted lines that repeated an earlier indicator. */
  duplicates: number;
  rejected: Rejection[];
  rejectedTotal: number;
}

/** The engine's domain bounds (`MIN_INDICATOR_LABELS`, `MAX_INDICATOR_LABELS`, ...). */
const MIN_LABELS = 2;
const MAX_LABELS = 8;
const MAX_DOMAIN_BYTES = 253;
const MAX_LABEL_BYTES = 63;
/** Refuse a source larger than this before parsing it (the agent reads at most 512 MiB). */
export const MAX_FEED_TEXT_BYTES = 64 * 1024 * 1024;

const FEED_NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;

/**
 * A feed name the agent can use as a file stem and print in a finding: lowercase letters, digits,
 * `.`, `_`, `-`, 1 to 64 characters, starting with a letter or digit, no `..`, no trailing dot.
 */
export function isValidFeedName(name: string): boolean {
  return FEED_NAME.test(name) && !name.includes("..") && !name.endsWith(".");
}

export type DomainResult =
  | { ok: true; name: string }
  | { ok: false; reason: RejectReason };

/**
 * Normalises a DNS name as the device compares it and applies the indicator bounds: ASCII
 * lowercase, one trailing dot dropped, letters/digits/`-`/`_`, labels of 1 to 63 bytes that
 * neither start nor end with `-`, a last label that is not all digits, 2 to 8 labels. A
 * non-ASCII name is refused (convert to punycode first).
 */
export function normalizeDomain(raw: string): DomainResult {
  const stripped = raw.endsWith(".") ? raw.slice(0, -1) : raw;
  // Judge the original text: `toLowerCase` maps U+212A (KELVIN SIGN) to ASCII `k`, which would turn
  // a name the device refuses into a different indicator.
  // eslint-disable-next-line no-control-regex
  if (/[^\x00-\x7f]/.test(stripped)) return { ok: false, reason: "non_ascii_domain" };
  const name = stripped.toLowerCase();
  if (name.length === 0 || name.length > MAX_DOMAIN_BYTES) return { ok: false, reason: "bad_domain" };
  const labels = name.split(".");
  for (const label of labels) {
    if (label.length === 0 || label.length > MAX_LABEL_BYTES) return { ok: false, reason: "bad_domain" };
    if (!/^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$/.test(label)) return { ok: false, reason: "bad_domain" };
  }
  if (/^[0-9]+$/.test(labels[labels.length - 1])) return { ok: false, reason: "bad_domain" };
  if (labels.length < MIN_LABELS) return { ok: false, reason: "domain_too_broad" };
  if (labels.length > MAX_LABELS) return { ok: false, reason: "domain_too_deep" };
  return { ok: true, name };
}

/**
 * Canonical text of an address, or a reason. An IPv4-mapped IPv6 address becomes its IPv4 form (the
 * device canonicalises the same way), and loopback and unspecified addresses are refused.
 */
export function normalizeAddress(raw: string): { ok: true; address: string } | { ok: false; reason: RejectReason } {
  const text = raw.trim();
  const version = isIP(text);
  if (version === 0) return { ok: false, reason: "bad_address" };
  // `isIP` accepts a zone (`fe80::1%eth0`), which the device's parser has no place for: dropping it
  // would widen a scoped indicator to every interface.
  if (text.includes("%")) return { ok: false, reason: "bad_address" };
  if (version === 4) {
    const parts = text.split(".").map(Number);
    // `isIP` accepts only dotted-quad decimal, so the parts are 0..255.
    if (parts[0] === 127 || parts.every((p) => p === 0)) return { ok: false, reason: "unusable_address" };
    return { ok: true, address: parts.join(".") };
  }
  const groups = expandV6(text);
  if (groups === null) return { ok: false, reason: "bad_address" };
  const mapped = groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff;
  if (mapped) {
    const v4 = [groups[6] >> 8, groups[6] & 0xff, groups[7] >> 8, groups[7] & 0xff];
    if (v4[0] === 127 || v4.every((p) => p === 0)) return { ok: false, reason: "unusable_address" };
    return { ok: true, address: v4.join(".") };
  }
  const loopback = groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1;
  const unspecified = groups.every((g) => g === 0);
  if (loopback || unspecified) return { ok: false, reason: "unusable_address" };
  return { ok: true, address: compressV6(groups) };
}

/** The 8 groups of a valid IPv6 text (`isIP` already said it is one), or `null`. */
function expandV6(text: string): number[] | null {
  let body = text;
  const tail = body.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (tail) {
    const v = tail.slice(1).map(Number);
    body = body.slice(0, tail.index) + ((v[0] << 8) | v[1]).toString(16) + ":" + ((v[2] << 8) | v[3]).toString(16);
  }
  const halves = body.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] === "" ? [] : halves[0].split(":");
  const rest = halves.length === 2 && halves[1] !== "" ? halves[1].split(":") : [];
  const fill = halves.length === 2 ? 8 - head.length - rest.length : 0;
  if (fill < 0 || (halves.length === 1 && head.length !== 8)) return null;
  const groups = [...head, ...Array<string>(fill).fill("0"), ...rest].map((g) => parseInt(g, 16));
  return groups.length === 8 && groups.every((g) => Number.isInteger(g) && g >= 0 && g <= 0xffff) ? groups : null;
}

/** RFC 5952 text: lowercase, the longest run of two or more zero groups as `::`. */
function compressV6(groups: number[]): string {
  let bestAt = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) {
      bestAt = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = (slice: number[]) => slice.map((g) => g.toString(16)).join(":");
  if (bestLen < 2) return hex(groups);
  return `${hex(groups.slice(0, bestAt))}::${hex(groups.slice(bestAt + bestLen))}`;
}

function parseLine(
  line: string,
  defaultKind: IocKind | undefined,
  isPublicSuffix: ((name: string) => boolean) | undefined,
): { ok: true; kind: IocKind; value: string } | { ok: false; reason: RejectReason; value: string } {
  let kind: IocKind | undefined;
  let value = line;
  const colon = line.indexOf(":");
  const prefix = colon === -1 ? "" : line.slice(0, colon);
  if (prefix === "sha256" || prefix === "ip" || prefix === "domain") {
    kind = prefix;
    value = line.slice(colon + 1).trim();
  } else {
    kind = defaultKind;
  }
  if (kind === undefined) return { ok: false, reason: "unknown_kind", value: line };

  switch (kind) {
    case "sha256":
      return /^[0-9a-fA-F]{64}$/.test(value)
        ? { ok: true, kind, value: value.toLowerCase() }
        : { ok: false, reason: "bad_hash", value };
    case "ip": {
      const result = normalizeAddress(value);
      return result.ok ? { ok: true, kind, value: result.address } : { ok: false, reason: result.reason, value };
    }
    case "domain": {
      const result = normalizeDomain(value);
      if (!result.ok) return { ok: false, reason: result.reason, value };
      if (isPublicSuffix === undefined) return { ok: false, reason: "public_suffix_unchecked", value };
      if (isPublicSuffix(result.name)) return { ok: false, reason: "public_suffix", value };
      return { ok: true, kind, value: result.name };
    }
  }
}

/**
 * One item of a source and the 1-based line it starts on: its text (`kind:value`, or a bare value),
 * or a rejection the caller already decided on (a CSV row the CSV layer could not read).
 */
export type SourceLine =
  | { line: number; text: string }
  | { line: number; refuse: { reason: RejectReason; value: string } };

/**
 * Builds one feed file. A bad line is counted and listed, never fatal: one malformed line does not
 * discard a feed (the device behaves the same way).
 *
 * @throws RangeError for an invalid feed name or a source over {@link MAX_FEED_TEXT_BYTES}.
 */
export function buildFeed(input: FeedInput): FeedResult {
  if (!isValidFeedName(input.feed)) throw new RangeError(`invalid feed name: ${JSON.stringify(input.feed)}`);
  if (Buffer.byteLength(input.text) > MAX_FEED_TEXT_BYTES) throw new RangeError("feed text too large");
  const lines = input.text.split(/\r?\n/).map((text, index) => ({ line: index + 1, text }));
  return buildFeedFromLines(input, lines);
}

/**
 * The core of {@link buildFeed} over lines the caller already cut, each with the number it carries
 * in the source (a CSV record can span several physical lines, so the number is not the index).
 * `input.text` is not read; the caller has checked the feed name and the source size.
 */
export function buildFeedFromLines(input: Omit<FeedInput, "text">, sourceLines: SourceLine[]): FeedResult {
  const listed = input.maxRejectedListed ?? 100;

  const seen = new Set<string>();
  const accepted: { kind: IocKind; value: string }[] = [];
  const rejected: Rejection[] = [];
  let rejectedTotal = 0;
  let read = 0;
  let duplicates = 0;

  for (const item of sourceLines) {
    const lineNumber = item.line;
    if ("refuse" in item) {
      read++;
      rejectedTotal++;
      if (rejected.length < listed) {
        rejected.push({ line: lineNumber, reason: item.refuse.reason, value: item.refuse.value.slice(0, 80) });
      }
      continue;
    }
    const line = item.text.trim();
    if (line === "" || line.startsWith("#")) continue;
    read++;
    const parsed = parseLine(line, input.defaultKind, input.isPublicSuffix);
    if (!parsed.ok) {
      rejectedTotal++;
      if (rejected.length < listed) {
        rejected.push({ line: lineNumber, reason: parsed.reason, value: parsed.value.slice(0, 80) });
      }
      continue;
    }
    const key = `${parsed.kind}:${parsed.value}`;
    if (seen.has(key)) {
      duplicates++;
      continue;
    }
    seen.add(key);
    accepted.push({ kind: parsed.kind, value: parsed.value });
  }

  const lines = accepted.map((a) => `${a.kind}:${a.value}`).sort();
  const text = lines.length === 0 ? "" : `${lines.join("\n")}\n`;
  const count = (kind: IocKind) => accepted.filter((a) => a.kind === kind).length;
  return {
    feed: input.feed,
    text,
    sha256: createHash("sha256").update(text).digest("hex"),
    counts: { sha256: count("sha256"), ip: count("ip"), domain: count("domain"), total: accepted.length },
    read,
    duplicates,
    rejected,
    rejectedTotal,
  };
}

/**
 * Content of the `ioc/VERSION` file the agent reads: one line, trimmed and bounded by the agent
 * (printable, at most 64 characters).
 *
 * @throws RangeError when `version` is empty, longer than 64 characters or not printable ASCII.
 */
export function versionFile(version: string): string {
  if (!/^[\x21-\x7e]{1,64}$/.test(version)) throw new RangeError(`invalid feed version: ${JSON.stringify(version)}`);
  return `${version}\n`;
}

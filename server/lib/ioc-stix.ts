/**
 * STIX 2.1 source for the IOC feed builder (issue #60, ADR-0038).
 *
 * Reads a STIX bundle (or a TAXII envelope: an object with an `objects` array) and hands the
 * indicators it can express to {@link buildFeedFromLines}, so a STIX feed goes through the same
 * normalisation, device rules and public-suffix gate as a plain or CSV one and yields the same
 * bytes for the same indicators.
 *
 * The engine matches one value per line, so only an `indicator` whose pattern is a single
 * comparison on one of these is taken:
 *
 *   [file:hashes.'SHA-256' = '<hex>']   [ipv4-addr:value = '<addr>']
 *   [ipv6-addr:value = '<addr>']        [domain-name:value = '<name>']
 *
 * Anything else (AND, OR, FOLLOWEDBY, IN, LIKE, MATCHES, a qualifier such as WITHIN, a CIDR range,
 * another property, another `pattern_type`) is counted as `unsupported_pattern` and listed, not
 * guessed at: reading half of an `OR` would publish an indicator the feed never claimed.
 *
 * Lifetime is applied at build time against the `now` the caller passes: a `revoked` indicator, one
 * whose `valid_until` has passed and one whose `valid_from` is still ahead are refused with their
 * own reasons. The device has no expiry, so the file is a snapshot: an indicator that expires after
 * the build stays loaded until the next release replaces the file.
 *
 * Rejections carry the 1-based position of the object in `objects` in place of a line number.
 * Objects that are not indicators (malware, relationships, ...) are ignored and not counted.
 *
 * Pure: no I/O, the clock is a parameter.
 */

import {
  buildFeedFromLines,
  isValidFeedName,
  MAX_FEED_TEXT_BYTES,
  type FeedInput,
  type FeedResult,
  type RejectReason,
  type SourceLine,
} from "@/lib/ioc-feed";

export interface StixFeedInput extends Omit<FeedInput, "text" | "defaultKind"> {
  /** The bundle's JSON text. */
  json: string;
  /** The instant lifetimes are judged against. */
  now: Date;
}

const PATTERN =
  /^\[\s*(file:hashes\.'SHA-256'|ipv4-addr:value|ipv6-addr:value|domain-name:value)\s*=\s*'((?:[^'\\]|\\.)*)'\s*\]$/;

const KIND_OF: Record<string, "sha256" | "ip" | "domain"> = {
  "file:hashes.'SHA-256'": "sha256",
  "ipv4-addr:value": "ip",
  "ipv6-addr:value": "ip",
  "domain-name:value": "domain",
};

/** STIX string escapes: only `\'` and `\\` mean anything inside a quoted value. */
function unescapeStix(value: string): string {
  return value.replace(/\\(['\\])/g, "$1");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Builds one feed file from a STIX bundle.
 *
 * @throws RangeError for an invalid feed name, a source over {@link MAX_FEED_TEXT_BYTES}, or text
 *   that is not a bundle (not JSON, or no `objects` array).
 */
export function buildFeedFromStix(input: StixFeedInput): FeedResult {
  if (!isValidFeedName(input.feed)) throw new RangeError(`invalid feed name: ${JSON.stringify(input.feed)}`);
  if (Buffer.byteLength(input.json) > MAX_FEED_TEXT_BYTES) throw new RangeError("feed text too large");

  let parsed: unknown;
  try {
    parsed = JSON.parse(input.json);
  } catch {
    throw new RangeError("the source is not JSON");
  }
  if (!isRecord(parsed) || !Array.isArray(parsed.objects)) {
    throw new RangeError("the source is not a STIX bundle (no `objects` array)");
  }
  if (parsed.type !== undefined && parsed.type !== "bundle") {
    throw new RangeError(`the source is a ${JSON.stringify(parsed.type)}, not a STIX bundle`);
  }

  const lines: SourceLine[] = [];
  parsed.objects.forEach((object: unknown, index: number) => {
    const line = index + 1;
    if (!isRecord(object) || object.type !== "indicator") return;
    const refuse = (reason: RejectReason, value: string): SourceLine => ({ line, refuse: { reason, value } });

    const pattern = object.pattern;
    if (typeof pattern !== "string") {
      lines.push(refuse("bad_stix", String(object.id ?? "indicator without a pattern")));
      return;
    }
    if (object.pattern_type !== undefined && object.pattern_type !== "stix") {
      lines.push(refuse("unsupported_pattern", pattern));
      return;
    }
    if (object.revoked === true) {
      lines.push(refuse("revoked", pattern));
      return;
    }
    for (const [field, reason, outside] of [
      ["valid_until", "expired", (at: number) => at <= input.now.getTime()],
      ["valid_from", "not_yet_valid", (at: number) => at > input.now.getTime()],
    ] as const) {
      const raw = object[field];
      if (raw === undefined) continue;
      const at = typeof raw === "string" ? Date.parse(raw) : NaN;
      if (Number.isNaN(at)) {
        lines.push(refuse("bad_stix", `${field}: ${String(raw)}`));
        return;
      }
      if (outside(at)) {
        lines.push(refuse(reason, pattern));
        return;
      }
    }

    const match = PATTERN.exec(pattern.trim());
    if (match === null) {
      lines.push(refuse("unsupported_pattern", pattern));
      return;
    }
    const value = unescapeStix(match[2]).trim();
    // A CIDR range is a different indicator from its network address: never narrow it silently.
    if (KIND_OF[match[1]] === "ip" && value.includes("/")) {
      lines.push(refuse("unsupported_pattern", pattern));
      return;
    }
    lines.push({ line, text: `${KIND_OF[match[1]]}:${value}` });
  });

  return buildFeedFromLines({ ...input, defaultKind: undefined }, lines);
}

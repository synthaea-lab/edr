/**
 * MISP source for the IOC feed builder (issue #60, ADR-0038).
 *
 * Reads a MISP export (the JSON of `/events/restSearch` or of one event: `{"response": [{"Event":
 * ...}]}`, `{"Event": ...}` or a bare event) and hands the attributes the engine can match to
 * {@link buildFeedFromLines}, so a MISP feed goes through the same normalisation, device rules and
 * public-suffix gate as the other sources and yields the same bytes for the same indicators.
 *
 * Taken, from `Event.Attribute` and from the attributes of `Event.Object`:
 *
 *   sha256 -> sha256    ip-src, ip-dst -> ip    domain, hostname -> domain
 *
 * - `to_ids` must be true. MISP uses it to mark an attribute as a detection indicator; one without it
 *   is context (a victim's address, a sample's name) and publishing it as a detection would raise
 *   findings on it. Refused as `not_for_detection`.
 * - A `deleted` attribute is refused as `deleted`, and so is every attribute of a `deleted` object:
 *   MISP soft-deletes an object as a whole, without necessarily flagging its attributes one by one.
 * - Composite types (`ip-src|port`, `filename|sha256`, `domain|ip`), `md5`, `sha1`, `url`, `email-*`
 *   and everything else are `unknown_kind`: the engine does not match them, and a
 *   composite is never split, because half of `domain|ip` is not the indicator the feed claimed.
 * - MISP carries no expiry on an attribute (decay is a scoring model computed by MISP itself), so none
 *   is applied here. Filter on the MISP side (`publish_timestamp`, `last`, `decayingModel`).
 *
 * Rejections carry the attribute's 1-based position in the order read (event attributes of each
 * event, then its objects') in place of a line number. Attributes of other categories are not
 * skipped: every attribute that is read is counted.
 *
 * Pure: no I/O, no clock.
 */

import {
  buildFeedFromLines,
  isValidFeedName,
  MAX_FEED_TEXT_BYTES,
  type FeedInput,
  type FeedResult,
  type IocKind,
  type RejectReason,
  type SourceLine,
} from "@/lib/ioc-feed";

export interface MispFeedInput extends Omit<FeedInput, "text" | "defaultKind"> {
  /** The export's JSON text. */
  json: string;
}

const KIND_OF: Record<string, IocKind> = {
  sha256: "sha256",
  "ip-src": "ip",
  "ip-dst": "ip",
  domain: "domain",
  hostname: "domain",
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** MISP serialises booleans as `true`/`false` or as `"1"`/`"0"`, depending on the endpoint. */
function truthy(value: unknown): boolean {
  return value === true || value === 1 || value === "1" || value === "true";
}

/** The events an export holds, whatever envelope it came in. */
function eventsOf(parsed: unknown): Record<string, unknown>[] | null {
  if (Array.isArray(parsed)) return parsed.flatMap((item) => eventsOf(item) ?? []);
  if (!isRecord(parsed)) return null;
  if (Array.isArray(parsed.response)) return parsed.response.flatMap((item) => eventsOf(item) ?? []);
  if (isRecord(parsed.Event)) return [parsed.Event];
  if (Array.isArray(parsed.Attribute) || Array.isArray(parsed.Object)) return [parsed];
  return null;
}

/**
 * Builds one feed file from a MISP export.
 *
 * @throws RangeError for an invalid feed name, a source over {@link MAX_FEED_TEXT_BYTES}, or text
 *   that holds no MISP event (not JSON, or no `Event`/`response` envelope).
 */
export function buildFeedFromMisp(input: MispFeedInput): FeedResult {
  if (!isValidFeedName(input.feed)) throw new RangeError(`invalid feed name: ${JSON.stringify(input.feed)}`);
  if (Buffer.byteLength(input.json) > MAX_FEED_TEXT_BYTES) throw new RangeError("feed text too large");

  let parsed: unknown;
  try {
    parsed = JSON.parse(input.json);
  } catch {
    throw new RangeError("the source is not JSON");
  }
  const events = eventsOf(parsed);
  if (events === null || events.length === 0) {
    throw new RangeError("the source holds no MISP event (expected `response`, `Event` or an event with `Attribute`)");
  }

  const lines: SourceLine[] = [];
  let line = 0;
  const read = (attribute: unknown, inDeletedObject = false) => {
    line++;
    const refuse = (reason: RejectReason, value: string): void => {
      lines.push({ line, refuse: { reason, value } });
    };
    if (!isRecord(attribute) || typeof attribute.type !== "string" || typeof attribute.value !== "string") {
      refuse("bad_misp", "attribute without a type and a value");
      return;
    }
    const { type, value } = attribute;
    if (inDeletedObject || truthy(attribute.deleted)) return refuse("deleted", value);
    const kind = KIND_OF[type];
    if (kind === undefined) return refuse("unknown_kind", `${type}: ${value}`);
    if (!truthy(attribute.to_ids)) return refuse("not_for_detection", value);
    lines.push({ line, text: `${kind}:${value.trim()}` });
  };

  for (const event of events) {
    for (const attribute of Array.isArray(event.Attribute) ? event.Attribute : []) read(attribute);
    for (const object of Array.isArray(event.Object) ? event.Object : []) {
      if (!isRecord(object)) continue;
      const deleted = truthy(object.deleted);
      for (const attribute of Array.isArray(object.Attribute) ? object.Attribute : []) read(attribute, deleted);
    }
  }

  return buildFeedFromLines({ ...input, defaultKind: undefined }, lines);
}

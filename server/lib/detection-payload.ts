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

// Postgres `jsonb` refuses U+0000 anywhere, keys included, so one NUL in an agent string would
// fail the insert and the agent would retry the detection forever on the 500. A sensor string
// can carry one (an ETW field, a REG_MULTI_SZ, a DNS label), so it is replaced, not refused.
const NUL = /\u0000/g;
const REPLACEMENT = "�";

function withoutNul(value: string): string {
  return value.includes("\u0000") ? value.replace(NUL, REPLACEMENT) : value;
}

/** The first `maxBytes` of `bytes` or fewer, backed off so a character is never split. */
function headEnd(bytes: Buffer, maxBytes: number): number {
  let end = Math.min(maxBytes, bytes.length);
  // A continuation byte (10xxxxxx) at `end` means a character straddles the cut.
  while (end > 0 && end < bytes.length && (bytes[end] & 0xc0) === 0x80) {
    end--;
  }
  return end;
}

/**
 * `value` cut to at most `maxBytes` of UTF-8, the marker saying how long it was included, on a
 * character boundary; unchanged when it fits. Keeps the head only: for identifiers whose start
 * names the thing (`pid:comm`).
 */
export function truncateUtf8(value: string, maxBytes: number): string {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length <= maxBytes) {
    return value;
  }
  const marker = `… [truncated, ${bytes.length} bytes]`;
  const end = headEnd(bytes, Math.max(0, maxBytes - Buffer.byteLength(marker)));
  return `${bytes.subarray(0, end).toString("utf8")}${marker}`;
}

/**
 * `value` cut to at most `maxBytes` of UTF-8 by keeping its head and its tail around a marker
 * saying how long it was, on character boundaries; unchanged when it fits. A process that pads
 * its command line chooses where the padding goes: keeping only the head would store the padding
 * and drop the payload placed after it (`bash -c '<70 KiB of spaces>; curl … | sh'`).
 */
export function cutUtf8HeadTail(value: string, maxBytes: number): string {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length <= maxBytes) {
    return value;
  }
  const marker = ` … [truncated, ${bytes.length} bytes] … `;
  const budget = Math.max(0, maxBytes - Buffer.byteLength(marker));
  const head = headEnd(bytes, Math.ceil(budget / 2));
  let tailStart = bytes.length - (budget - Math.ceil(budget / 2));
  while (tailStart < bytes.length && (bytes[tailStart] & 0xc0) === 0x80) {
    tailStart++;
  }
  return `${bytes.subarray(0, head).toString("utf8")}${marker}${bytes.subarray(tailStart).toString("utf8")}`;
}

const truncatedString = (maxBytes: number) =>
  z.string().min(1).transform((value) => truncateUtf8(withoutNul(value), maxBytes));

const headTailString = (maxBytes: number) =>
  z.string().min(1).transform((value) => cutUtf8HeadTail(withoutNul(value), maxBytes));

// `events` are the serialized schema events: the trigger, then the rule's evidence. Their
// strings are the monitored process's own (command lines, paths, names), so they are cut, never
// refused, for the same reason as the title (#1060). Bounds from what the agent emits:
// - one event per detection, except the ransomware damage manifest: the trigger plus at most
//   100 renames and deletions (`DAMAGE_MANIFEST_MAX`, agent/src/sink.rs, which mirrors
//   `MAX_EVENTS` and is pinned to it by a test), so 101;
// - a string carries at most a command line, which the title already bounds at 64 KiB;
// - the longest array is a Linux argv. Once #1116 lands the sensor bounds it at capture to
//   32,768 tokens (an empty token costs one byte); until then a legitimate argv can be longer and
//   is cut here, counted in `cutArrays`.
// Strings and arrays keep their head and their tail, since the process chooses where its padding
// goes. The shape of an event is the one thing no monitored process controls: the Rust types fix
// the depth (4 levels today), the keys (field names, no map in `schema`) and their count. So an
// event nested past `MAX_EVENT_DEPTH`, with a key past `MAX_EVENT_KEY_BYTES` or with more than
// `MAX_EVENT_KEYS` keys in one object is a forged payload and is refused. With the per-string
// and per-array cuts, nginx's 8 MiB body limit stays the aggregate bound.
export const MAX_EVENTS = 128;
export const MAX_EVENT_STRING_BYTES = 64 * 1024;
export const MAX_EVENT_ARRAY_ITEMS = 32 * 1024;
export const MAX_EVENT_DEPTH = 16;
// The longest schema field name is under 40 bytes; the widest event struct has under 40 fields.
export const MAX_EVENT_KEY_BYTES = 128;
export const MAX_EVENT_KEYS = 256;
// The body, then `events` (or the legacy `meta`), then an event at `MAX_EVENT_DEPTH`.
export const MAX_BODY_DEPTH = MAX_EVENT_DEPTH + 2;

/** What bounding a detection's events cut, stored in `meta.events_cut` when anything was. */
export type EventsCut = {
  droppedEvents: number;
  cutStrings: number;
  cutArrays: number;
  // Strings whose NULs were replaced with U+FFFD, which `jsonb` cannot store.
  nulStrings: number;
  // Set when the agent already shortened the detection to fit its upload limit (#1122): the
  // size of the detection before that, read from the note it puts in front of the title.
  agentShortenedFromBytes?: number;
};

const emptyCut = (): EventsCut => ({ droppedEvents: 0, cutStrings: 0, cutArrays: 0, nulStrings: 0 });

class Forged extends Error {}

function boundString(value: string, cut: EventsCut): string {
  const clean = withoutNul(value);
  if (clean !== value) cut.nulStrings++;
  const bounded = cutUtf8HeadTail(clean, MAX_EVENT_STRING_BYTES);
  if (bounded !== clean) cut.cutStrings++;
  return bounded;
}

function boundValue(value: unknown, depth: number, cut: EventsCut): unknown {
  if (typeof value === "string") {
    return boundString(value, cut);
  }
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (depth > MAX_EVENT_DEPTH) {
    throw new Forged(`nested deeper than ${MAX_EVENT_DEPTH}`);
  }
  if (Array.isArray(value)) {
    let kept = value;
    if (value.length > MAX_EVENT_ARRAY_ITEMS) {
      cut.cutArrays++;
      const head = Math.ceil(MAX_EVENT_ARRAY_ITEMS / 2);
      kept = [...value.slice(0, head), ...value.slice(value.length - (MAX_EVENT_ARRAY_ITEMS - head))];
    }
    return kept.map((item) => boundValue(item, depth + 1, cut));
  }
  const entries = Object.entries(value);
  if (entries.length > MAX_EVENT_KEYS) {
    throw new Forged(`an object with more than ${MAX_EVENT_KEYS} keys`);
  }
  return Object.fromEntries(entries.map(([key, item]) => {
    if (Buffer.byteLength(key) > MAX_EVENT_KEY_BYTES) {
      throw new Forged(`a key longer than ${MAX_EVENT_KEY_BYTES} bytes`);
    }
    // A key is a schema field name, which never holds a NUL; replacing keeps `jsonb` storable.
    return [withoutNul(key), boundValue(item, depth + 1, cut)];
  }));
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * `events` with every string cut to `MAX_EVENT_STRING_BYTES`, every array to
 * `MAX_EVENT_ARRAY_ITEMS` (head and tail kept) and the list to its first `MAX_EVENTS` (the
 * trigger always kept), and what that cut. Throws on a shape no schema event has: nesting past
 * `MAX_EVENT_DEPTH`, a key past `MAX_EVENT_KEY_BYTES`, more than `MAX_EVENT_KEYS` keys.
 */
export function boundEvents(events: Record<string, unknown>[]): {
  events: Record<string, unknown>[];
  cut: EventsCut;
} {
  const cut = emptyCut();
  cut.droppedEvents = Math.max(0, events.length - MAX_EVENTS);
  const bounded = events
    .slice(0, MAX_EVENTS)
    .map((event) => boundValue(event, 1, cut) as Record<string, unknown>);
  return { events: bounded, cut };
}

/** `run`, with a forged shape reported as a validation issue (a 400 the agent does not retry). */
function refusingForged<T>(ctx: z.RefinementCtx, what: string, run: () => T): T {
  try {
    return run();
  } catch (error) {
    if (!(error instanceof Forged)) throw error;
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: `${what}: ${error.message}` });
    return z.NEVER;
  }
}

// Sliced before anything else looks at the elements: an 8 MiB body of empty objects is about
// 2.8 million events, and validating each before keeping 128 would build millions of results.
const BoundedEventsSchema = z.unknown().transform((value, ctx) => {
  if (!Array.isArray(value)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "events must be an array" });
    return z.NEVER;
  }
  const kept = value.slice(0, MAX_EVENTS);
  if (!kept.every(isRecord)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "every event must be an object" });
    return z.NEVER;
  }
  return refusingForged(ctx, "events", () => {
    const bounded = boundEvents(kept);
    bounded.cut.droppedEvents = value.length - kept.length;
    return bounded;
  });
});

const BoundedEventSchema = z.record(z.any()).transform((event, ctx) =>
  refusingForged(ctx, "event", () => {
    const { events, cut } = boundEvents([event]);
    return { event: events[0], cut };
  }),
);

// The legacy agents' free-form `meta` is agent-supplied too, so it gets the events' bounds.
const BoundedMetaSchema = z.record(z.any()).transform((meta, ctx) =>
  refusingForged(ctx, "meta", () => {
    const cut = emptyCut();
    return { meta: boundValue(meta, 1, cut) as Record<string, unknown>, cut };
  }),
);

function cutSummary(cut: EventsCut): EventsCut | undefined {
  const { agentShortenedFromBytes, ...counts } = cut;
  const any = Object.values(counts).some((n) => n > 0) || agentShortenedFromBytes !== undefined;
  return any ? cut : undefined;
}

// The note `fit_detection_to_limit` (crates/transport/src/detection_upload.rs) puts in front of
// the title of a detection it shortened to fit the upload limit. Such a detection arrives under
// every bound here, so without reading the note its evidence would look whole.
const AGENT_SHORTENED_NOTE = /^\[events shortened from (\d+) bytes\] /;

function agentShortenedFrom(title: string): number | undefined {
  const match = AGENT_SHORTENED_NOTE.exec(title);
  return match ? Number(match[1]) : undefined;
}

/**
 * The deepest nesting in `body`, counted without recursion and given up past `limit`. The route
 * hashes the raw body with `JSON.stringify`, which throws a `RangeError` (a 500 the agent retries)
 * from about 10,000 levels, and zod strips unknown keys before any other check would see them.
 */
function deeperThan(body: unknown, limit: number): boolean {
  const stack: Array<[unknown, number]> = [[body, 1]];
  while (stack.length > 0) {
    const top = stack.pop();
    if (top === undefined) break;
    const [value, depth] = top;
    if (value === null || typeof value !== "object") continue;
    if (depth > limit) return true;
    for (const item of Array.isArray(value) ? value : Object.values(value)) {
      if (item !== null && typeof item === "object") stack.push([item, depth + 1]);
    }
  }
  return false;
}

// The agent cuts feed names and versions at 64 Rust `char`s (`label`, agent/src/ioc.rs), which are
// code points; zod's `.max` counts UTF-16 units, so a non-BMP name the agent let through would be
// refused here and its detection lost.
const MAX_FEED_LABEL_CHARS = 64;
const FeedLabelSchema = z
  .string()
  .min(1)
  .refine((value) => Array.from(value).length <= MAX_FEED_LABEL_CHARS, {
    message: `at most ${MAX_FEED_LABEL_CHARS} characters`,
  });

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
    feed: FeedLabelSchema,
    feed_version: FeedLabelSchema,
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
  title: headTailString(MAX_TITLE_BYTES),
  source: SourceSchema,
  score: z.number().finite().nullable().optional(),
  // Feature names come from the shipped models; the widest has 17 features today.
  attributions: z.array(z.object({
    feature: z.string().min(1).max(128),
    value: z.number().finite(),
    contribution: z.number().finite(),
  })).max(64).default([]),
  techniques: z.array(TechniqueIdSchema).max(MAX_TECHNIQUES).default([]),
  events: BoundedEventsSchema,
});

// Keep the original API contract for enrolled agents that have not upgraded.
const LegacyDetectionSchema = z.object({
  timestamp_ns: z.number().finite().positive(),
  technique: LegacyTechniqueSchema,
  severity: SeveritySchema,
  // The pre-structured agents sent the same event, so it is bounded the same way.
  event: BoundedEventSchema,
  meta: BoundedMetaSchema,
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
  if (deeperThan(body, MAX_BODY_DEPTH)) {
    throw new z.ZodError([{
      code: z.ZodIssueCode.custom,
      path: [],
      message: `body nested deeper than ${MAX_BODY_DEPTH}`,
    }]);
  }
  if (typeof body === "object" && body !== null && "source" in body) {
    const detection = StructuredDetectionSchema.parse(body);
    const { source, attributions, techniques } = detection;
    const { events, cut } = detection.events;
    const shortenedFrom = agentShortenedFrom(detection.title);
    if (shortenedFrom !== undefined) cut.agentShortenedFromBytes = shortenedFrom;
    const eventsCut = cutSummary(cut);
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
        // Present only when something was cut, here or by the agent before upload, so an
        // analyst knows the evidence is partial.
        ...(eventsCut ? { events_cut: eventsCut } : {}),
      },
    };
  }

  const detection = LegacyDetectionSchema.parse(body);
  const { event, cut } = detection.event;
  const { meta, cut: metaCut } = detection.meta;
  for (const key of ["cutStrings", "cutArrays", "nulStrings"] as const) cut[key] += metaCut[key];
  const eventsCut = cutSummary(cut);
  return {
    timestamp: new Date(detection.timestamp_ns / 1_000_000),
    technique: detection.technique,
    severity: detection.severity,
    event,
    meta: eventsCut ? { ...meta, events_cut: eventsCut } : meta,
  };
}

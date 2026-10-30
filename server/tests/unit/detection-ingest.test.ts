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
import { MAX_TITLE_BYTES, truncateUtf8 } from "@/lib/detection-payload";

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
      expect(kept.endsWith(`… [truncated, ${title.length} bytes]`)).toBe(true);
      expect(Buffer.byteLength(kept)).toBeLessThan(MAX_TITLE_BYTES + 64);
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
    });

    it("never splits a character when it cuts", () => {
      // "é" is two bytes, "😀" four: a cut at 5 bytes lands inside one of them.
      expect(truncateUtf8("éé😀", 5)).toBe("éé… [truncated, 8 bytes]");
      expect(truncateUtf8("ééé", 5)).toBe("éé… [truncated, 6 bytes]");
      expect(truncateUtf8("short", 5)).toBe("short");
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

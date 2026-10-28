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

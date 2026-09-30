import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { readFileSync } from "node:fs";
import path from "node:path";

const db = vi.hoisted(() => ({
  agent: { findUnique: vi.fn(), update: vi.fn() },
  detection: { create: vi.fn() },
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

const post = (body: unknown) => POST(new NextRequest("http://localhost/api/ingest/detection", {
  method: "POST",
  headers,
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
});

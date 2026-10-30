import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const db = vi.hoisted(() => ({
  agent: { findUnique: vi.fn(), update: vi.fn() },
  agentHealth: { findUnique: vi.fn(), upsert: vi.fn() },
  lakeBatch: { create: vi.fn() },
  $executeRaw: vi.fn(),
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));

import { POST } from "@/app/api/ingest/events/route";
import { POST as postV1Events } from "@/app/api/v1/ingest/events/route";
import { POST as postV1Heartbeat } from "@/app/api/v1/ingest/heartbeat/route";
import { POST as postHeartbeat } from "@/app/api/ingest/heartbeat/route";
import { aggregateSightings } from "@/lib/prevalence";

const SECRET = "test-proxy-secret";
const SHA = "c".repeat(64);
const NOW = Date.UTC(2026, 8, 30, 12, 0, 0);

const AGENT_HEADERS = {
  "X-Proxy-Secret": SECRET,
  "X-Client-Cert-Verified": "SUCCESS",
  "X-Client-Cert-Subject": "CN=agent-1,O=synthaea",
  "Content-Type": "application/json",
};

const exec = (over: Record<string, unknown> = {}) => ({
  type: "exec",
  meta: { timestamp_ns: NOW * 1_000_000 },
  image_path: "/usr/bin/curl",
  parent_comm: "bash",
  sha256: SHA,
  ...over,
});


/** The `$executeRaw` calls that wrote `table`: the ingest stats (#899) share the mock with prevalence. */
const writesTo = (table: string) =>
  db.$executeRaw.mock.calls.filter((c) => String(c[0].sql).includes(table));
const stats = () => writesTo("ingest_stats").map((c) => c[0].values as unknown[]);

const post = (body: unknown, headers: Record<string, string> = AGENT_HEADERS, handler = POST) =>
  handler(
    new NextRequest("http://localhost/api/ingest/events", {
      method: "POST",
      headers,
      body: typeof body === "string" ? body : JSON.stringify(body),
    })
  );

/** The sightings the route wrote: the multi-row statement's bound parameters, 7 per row: tenant, agent, kind, key, first, last, count. */
function writtenRows(): unknown[][] {
  const params = writesTo("prevalence_sightings")[0][0].values as unknown[];
  const rows: unknown[][] = [];
  for (let i = 0; i < params.length; i += 7) rows.push(params.slice(i, i + 7));
  return rows;
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
  process.env.NGINX_PROXY_SECRET = SECRET;
  db.agent.findUnique.mockResolvedValue({ id: "a1", tenantId: "t1", ring: "prod" });
  db.agent.update.mockResolvedValue({});
  db.$executeRaw.mockResolvedValue(1);
});

describe("POST /api/ingest/events authentication", () => {
  it("refuses forged mTLS headers without the proxy secret", async () => {
    const { "X-Proxy-Secret": _omit, ...forged } = AGENT_HEADERS;
    expect((await post({ events: [exec()] }, forged)).status).toBe(403);
    expect(writesTo("prevalence_sightings")).toHaveLength(0);
  });

  it("refuses a request without a verified client certificate", async () => {
    const headers = { "X-Proxy-Secret": SECRET, "Content-Type": "application/json" };
    expect((await post({ events: [exec()] }, headers)).status).toBe(401);
  });

  it("refuses an agent that is not enrolled", async () => {
    db.agent.findUnique.mockResolvedValue(null);
    expect((await post({ events: [exec()] })).status).toBe(403);
    expect(writesTo("prevalence_sightings")).toHaveLength(0);
  });
});

describe("POST /api/ingest/events payload", () => {
  it("answers with the shape transport::UploadResponse reads", async () => {
    const res = await post({ agent_id: null, events: [exec(), exec()] });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.accepted).toBe(2);
    expect(typeof body.batch_id).toBe("string");
  });

  it("accepts an empty batch", async () => {
    const res = await post({ agent_id: null, events: [] });
    expect((await res.json()).accepted).toBe(0);
    expect(writesTo("prevalence_sightings")).toHaveLength(0);
  });

  it("skips malformed entries instead of rejecting the whole batch", async () => {
    const res = await post({ events: [exec(), null, "x", 3, {}, { type: 5 }, exec()] });
    expect(res.status).toBe(200);
    expect((await res.json()).accepted).toBe(2);
  });

  it("rejects a body that is not JSON, or has no events array", async () => {
    expect((await post("{not json")).status).toBe(400);
    expect((await post({ agent_id: null })).status).toBe(400);
    expect((await post({ events: "nope" })).status).toBe(400);
  });

  it("rejects an oversized batch and an oversized body", async () => {
    expect((await post({ events: Array.from({ length: 1001 }, () => exec()) })).status).toBe(413);
    const huge = { events: [exec({ cmdline: "x".repeat(5 * 1024 * 1024) })] };
    expect((await post(huge)).status).toBe(413);
    expect(writesTo("prevalence_sightings")).toHaveLength(0);
  });

  it("ignores the agent_id in the body: identity is the certificate", async () => {
    await post({ agent_id: "someone-else", events: [exec()] });
    expect(db.agent.findUnique.mock.calls[0][0].where).toEqual({ enrollmentId: "agent-1" });
    expect(db.agent.update.mock.calls[0][0].where).toEqual({ id: "a1" });
  });
});

describe("POST /api/ingest/events feeds prevalence", () => {
  it("writes a batch as one statement, one row per distinct key, with counts", async () => {
    await post({ events: [exec(), exec(), exec({ image_path: "/bin/ls", sha256: undefined })] });
    expect(writesTo("prevalence_sightings")).toHaveLength(1);
    const rows = writtenRows();
    const curlPath = rows.find((r) => r[3] === "/usr/bin/curl");
    expect(curlPath?.[6]).toBe(2); // two curl execs folded into one row
    expect(rows.map((r) => r[2])).toEqual(
      expect.arrayContaining(["sha256", "image_path", "transition"])
    );
  });

  it("scopes rows to the agent's tenant and agent", async () => {
    await post({ events: [exec()] });
    for (const row of writtenRows()) {
      expect(row[0]).toBe("t1");
      expect(row[1]).toBe("a1");
    }
  });

  it("uses the event's own time, so a flushed spool does not look new", async () => {
    const old = Date.UTC(2026, 8, 1);
    await post({ events: [exec({ meta: { timestamp_ns: old * 1_000_000 } })] });
    expect(writtenRows()[0][4]).toEqual(new Date(old)); // first_seen
    expect(writtenRows()[0][5]).toEqual(new Date(old)); // last_seen
  });

  it("replaces a far-future or unusable timestamp with now", async () => {
    const future = NOW + 30 * 24 * 60 * 60 * 1000;
    for (const meta of [{ timestamp_ns: future * 1_000_000 }, { timestamp_ns: 0 }, { timestamp_ns: "x" }, {}, undefined]) {
      db.$executeRaw.mockClear();
      await post({ events: [exec({ meta })] });
      expect(writtenRows()[0][4]).toEqual(new Date(NOW));
    }
  });

  // The agent drops a spooled segment on any 2xx; a counter failure must not
  // make it retry a batch that is otherwise fine.
  it("still accepts the batch when the counter update fails", async () => {
    db.$executeRaw.mockRejectedValue(new Error("db down"));
    const res = await post({ events: [exec()] });
    expect(res.status).toBe(200);
    expect(db.agent.update).toHaveBeenCalled();
  });

  it("marks the agent alive, like a heartbeat", async () => {
    await post({ events: [exec()] });
    expect(db.agent.update.mock.calls[0][0].data.lastSeen).toEqual(new Date(NOW));
  });
});

// Values of the ingest_stats statement: tenant, agent, kind, bucket, received, accepted, skipped,
// refused_4xx, refused_5xx, lag_max_ms, last_accepted_at.
describe("POST /api/ingest/events counts ingest health (#899)", () => {
  it("counts an accepted batch with its skipped entries and its worst lag", async () => {
    const late = NOW - 90_000;
    await post({ events: [exec(), null, exec({ meta: { timestamp_ns: late * 1_000_000 } }), "x"] });
    expect(stats()).toEqual([
      ["t1", "a1", "events", new Date(Date.UTC(2026, 8, 30, 12)), 4, 2, 2, 0, 0, 90_000, 2, 90_000, new Date(NOW)],
    ]);
  });

  it("counts a refused batch by status class, for the agent that sent it", async () => {
    await post("{not json");
    await post({ events: Array.from({ length: 1001 }, () => exec()) });
    expect(stats().map((v) => v.slice(4))).toEqual([
      [0, 0, 0, 1, 0, 0, 0, null, null],
      [1001, 0, 0, 1, 0, 0, 0, null, null],
    ]);
  });

  it("counts an internal failure as a refusal of the 5xx class", async () => {
    // The lake queue is the one write that must not be lost, so its failure is the 5xx.
    process.env.LAKE_DIR = "/nonexistent/lake";
    db.lakeBatch.create.mockRejectedValue(new Error("db down"));
    try {
      expect((await post({ events: [exec()] })).status).toBe(500);
    } finally {
      delete process.env.LAKE_DIR;
    }
    expect(stats().map((v) => v.slice(7, 9))).toEqual([[0, 1]]);
  });

  it("does not fail an ingest, and so does not make the agent resend, when the lastSeen update fails", async () => {
    db.agent.update.mockRejectedValue(new Error("db down"));
    expect((await post({ events: [exec()] })).status).toBe(200);
    // received, accepted, skipped, refused 4xx, refused 5xx: counted as accepted, not as a refusal.
    expect(stats().map((v) => v.slice(4, 9))).toEqual([[1, 1, 0, 0, 0]]);
  });

  it("counts nothing before the agent is identified", async () => {
    const { "X-Proxy-Secret": _omit, ...forged } = AGENT_HEADERS;
    await post({ events: [exec()] }, forged);
    db.agent.findUnique.mockResolvedValue(null);
    await post({ events: [exec()] });
    expect(stats()).toHaveLength(0);
  });

  it("does not fail an ingest when the stats write fails", async () => {
    db.$executeRaw.mockRejectedValue(new Error("db down"));
    expect((await post({ events: [exec()] })).status).toBe(200);
  });

  it("counts a heartbeat's beacon only when it was stored", async () => {
    db.agentHealth.findUnique.mockResolvedValue(null);
    db.agentHealth.upsert.mockResolvedValue({});
    db.agent.update.mockResolvedValue({ id: "a1", tenantId: "t1", ring: "prod", lastSeen: new Date(NOW) });
    const beat = (body: unknown) =>
      postHeartbeat(
        new NextRequest("http://localhost/api/ingest/heartbeat", {
          method: "POST",
          headers: AGENT_HEADERS,
          body: JSON.stringify(body),
        })
      );
    await beat({});
    await beat({ beacon: { not: "a beacon" } });
    expect(stats()).toHaveLength(0);
    await beat({
      beacon: { timestamp_ns: NOW * 1_000_000, agent_version: "1.0.0", sensors: [], spool_bytes: 0, spool_dropped: 0, enrich_dropped: 0 },
    });
    expect(db.agentHealth.upsert).toHaveBeenCalledTimes(1);
    expect(stats().map((v) => [v[2], v[4], v[5]])).toEqual([["beacon", 1, 1]]);
  });
});

describe("aggregateSightings", () => {
  it("keeps the earliest and latest time and counts events per key", () => {
    const k = { kind: "domain" as const, key: "x.example" };
    const rows = aggregateSightings([
      { at: new Date(20), observations: [k] },
      { at: new Date(5), observations: [k] },
      { at: new Date(10), observations: [k, { kind: "domain", key: "y.example" }] },
    ]);
    const x = rows.find((r) => r.key === "x.example")!;
    expect(x).toMatchObject({ count: 3, firstSeen: new Date(5), lastSeen: new Date(20) });
    expect(rows).toHaveLength(2);
  });
});

describe("versioned paths the agent actually uses", () => {
  it("serve the same handlers as the unversioned ones", () => {
    expect(postV1Events).toBe(POST);
    expect(postV1Heartbeat).toBe(postHeartbeat);
  });
});

import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const db = vi.hoisted(() => ({
  agent: { findUnique: vi.fn(), update: vi.fn() },
  detection: { create: vi.fn() },
  prevalenceSighting: { aggregate: vi.fn(), findMany: vi.fn() },
  $executeRaw: vi.fn(),
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));

import {
  extractObservations,
  getPrevalence,
  getSightingsOf,
  MAX_PIVOT_HOSTS,
  recordObservations,
} from "@/lib/prevalence";
import { GET as getPrevalenceRoute } from "@/app/api/prevalence/route";
import { POST as ingestDetection } from "@/app/api/ingest/detection/route";

const SHA = "a".repeat(64);

const exec = (overrides: Record<string, unknown> = {}) => ({
  type: "exec",
  image_path: "/usr/bin/curl",
  parent_comm: "bash",
  sha256: SHA,
  ...overrides,
});

describe("extractObservations", () => {
  it("takes the hash, image path and parent transition from an exec", () => {
    expect(extractObservations(exec())).toEqual([
      { kind: "sha256", key: SHA },
      { kind: "image_path", key: "/usr/bin/curl" },
      { kind: "transition", key: "bash -> /usr/bin/curl" },
    ]);
  });

  it("prefers the parent's full path over its comm", () => {
    const obs = extractObservations(exec({ parent_image_path: "/usr/bin/bash" }));
    expect(obs).toContainEqual({ kind: "transition", key: "/usr/bin/bash -> /usr/bin/curl" });
  });

  it("emits no transition when the parent is unknown", () => {
    const obs = extractObservations(exec({ parent_comm: undefined }));
    expect(obs.map((o) => o.kind)).toEqual(["sha256", "image_path"]);
  });

  it("treats Windows paths case-insensitively but leaves POSIX paths alone", () => {
    const win = extractObservations(exec({ image_path: "C:\\Windows\\System32\\CMD.EXE", sha256: undefined }));
    expect(win).toContainEqual({ kind: "image_path", key: "c:\\windows\\system32\\cmd.exe" });
    const posix = extractObservations(exec({ image_path: "/tmp/Payload", sha256: undefined }));
    expect(posix).toContainEqual({ kind: "image_path", key: "/tmp/Payload" });
  });

  it("drops a sha256 that is not 64 hex characters and lowercases one that is", () => {
    expect(extractObservations(exec({ sha256: "not-a-hash" })).map((o) => o.kind)).not.toContain("sha256");
    expect(extractObservations(exec({ sha256: SHA.toUpperCase() }))[0]).toEqual({ kind: "sha256", key: SHA });
  });

  it("normalizes a DNS query to one lowercase, dot-less domain", () => {
    expect(extractObservations({ type: "dns_query", query: "Example.COM." })).toEqual([
      { kind: "domain", key: "example.com" },
    ]);
  });

  it("bounds an attacker-chosen key rather than storing it", () => {
    expect(extractObservations(exec({ image_path: "/" + "a".repeat(2000), sha256: undefined, parent_comm: undefined }))).toEqual([]);
  });

  it("yields nothing for shapes it does not understand", () => {
    for (const event of [null, "exec", 3, [], {}, { type: "file_open", path: "/x" }, { type: "exec" }]) {
      expect(extractObservations(event), JSON.stringify(event)).toEqual([]);
    }
  });
});

describe("recordObservations", () => {
  beforeEach(() => vi.clearAllMocks());

  it("writes an event's observations in one statement", async () => {
    await recordObservations(db as never, "t1", "a1", new Date(0), extractObservations(exec()));
    expect(db.$executeRaw).toHaveBeenCalledTimes(1);
  });

  it("does nothing for an event with no observations", async () => {
    await recordObservations(db as never, "t1", "a1", new Date(0), []);
    expect(db.$executeRaw).not.toHaveBeenCalled();
  });
});

describe("getPrevalence", () => {
  beforeEach(() => vi.clearAllMocks());

  it("reports hosts, events and the first/last sighting across the fleet", async () => {
    db.prevalenceSighting.aggregate.mockResolvedValue({
      _count: { _all: 3 },
      _sum: { count: 10 },
      _min: { firstSeen: new Date("2026-09-01") },
      _max: { lastSeen: new Date("2026-09-29") },
    });
    expect(await getPrevalence(db as never, "t1", "sha256", SHA)).toEqual({
      hostCount: 3,
      eventCount: 10,
      firstSeen: new Date("2026-09-01"),
      lastSeen: new Date("2026-09-29"),
    });
    expect(db.prevalenceSighting.aggregate.mock.calls[0][0].where).toEqual({
      tenantId: "t1",
      kind: "sha256",
      key: SHA,
    });
  });

  it("returns null for a key this tenant has never seen", async () => {
    db.prevalenceSighting.aggregate.mockResolvedValue({
      _count: { _all: 0 },
      _sum: { count: null },
      _min: { firstSeen: null },
      _max: { lastSeen: null },
    });
    expect(await getPrevalence(db as never, "t1", "domain", "never.example")).toBeNull();
  });
});

describe("getSightingsOf", () => {
  beforeEach(() => vi.clearAllMocks());

  const row = (agentId: string) => ({
    agentId,
    firstSeen: new Date("2026-09-01"),
    lastSeen: new Date("2026-09-29"),
    count: 1,
  });

  it("returns null for a key this tenant has never seen", async () => {
    db.prevalenceSighting.findMany.mockResolvedValue([]);
    expect(await getSightingsOf(db as never, "t1", "sha256", SHA)).toBeNull();
  });

  it("reports the rows unflagged when under the cap", async () => {
    db.prevalenceSighting.findMany.mockResolvedValue([row("a1"), row("a2")]);
    const page = await getSightingsOf(db as never, "t1", "sha256", SHA);
    expect(page?.sightings).toHaveLength(2);
    expect(page?.truncated).toBe(false);
  });

  it("caps at MAX_PIVOT_HOSTS and reports the truncation, not a silent cut", async () => {
    // One row past the cap is exactly what the one-extra `take` is for: it is
    // what tells `getSightingsOf` there was more to cut, not just that the
    // fleet happened to have precisely `MAX_PIVOT_HOSTS` hosts.
    const rows = Array.from({ length: MAX_PIVOT_HOSTS + 1 }, (_, i) => row(`a${i}`));
    db.prevalenceSighting.findMany.mockResolvedValue(rows);
    const page = await getSightingsOf(db as never, "t1", "sha256", SHA);
    expect(page?.sightings).toHaveLength(MAX_PIVOT_HOSTS);
    expect(page?.truncated).toBe(true);
  });

  it("queries MAX_PIVOT_HOSTS + 1 rows so truncation is detectable", async () => {
    db.prevalenceSighting.findMany.mockResolvedValue([row("a1")]);
    await getSightingsOf(db as never, "t1", "image_path", "/usr/bin/curl");
    expect(db.prevalenceSighting.findMany.mock.calls[0][0].take).toBe(MAX_PIVOT_HOSTS + 1);
  });
});

describe("GET /api/prevalence", () => {
  beforeEach(() => vi.clearAllMocks());

  const req = (qs: string, headers: Record<string, string> = { "x-tenant-id": "t1" }) =>
    new NextRequest(`http://localhost/api/prevalence${qs}`, { headers });

  it("answers seen:false, not 404, for an unknown key", async () => {
    db.prevalenceSighting.aggregate.mockResolvedValue({
      _count: { _all: 0 }, _sum: { count: null }, _min: { firstSeen: null }, _max: { lastSeen: null },
    });
    const res = await getPrevalenceRoute(req("?kind=domain&key=x.example"));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ kind: "domain", key: "x.example", seen: false });
  });

  it("scopes the lookup to the caller's tenant", async () => {
    db.prevalenceSighting.aggregate.mockResolvedValue({
      _count: { _all: 2 }, _sum: { count: 2 }, _min: { firstSeen: new Date(0) }, _max: { lastSeen: new Date(0) },
    });
    await getPrevalenceRoute(req("?kind=domain&key=x.example", { "x-tenant-id": "tenant-b" }));
    expect(db.prevalenceSighting.aggregate.mock.calls[0][0].where.tenantId).toBe("tenant-b");
  });

  it("rejects an unknown kind and a missing key", async () => {
    expect((await getPrevalenceRoute(req("?kind=bogus&key=x"))).status).toBe(400);
    expect((await getPrevalenceRoute(req("?kind=domain"))).status).toBe(400);
  });
});

describe("detection ingest feeds prevalence", () => {
  const SECRET = "test-proxy-secret";
  const ingest = () =>
    ingestDetection(
      new NextRequest("http://localhost/api/ingest/detection", {
        method: "POST",
        headers: {
          "X-Proxy-Secret": SECRET,
          "X-Client-Cert-Verified": "SUCCESS",
          "X-Client-Cert-Subject": "CN=agent-1,O=synthaea",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          timestamp_ns: 1_700_000_000_000_000_000,
          technique: "T1059",
          severity: "high",
          event: exec(),
          meta: {},
        }),
      })
    );

  beforeEach(() => {
    vi.clearAllMocks();
    process.env.NGINX_PROXY_SECRET = SECRET;
    db.agent.findUnique.mockResolvedValue({ id: "a1", tenantId: "t1", tenant: {} });
  });

  it("records the event's observations for the agent's tenant", async () => {
    expect((await ingest()).status).toBe(200);
    expect(db.$executeRaw).toHaveBeenCalledTimes(1);
  });

  // Regression guard: the detection is already stored when counters run, and a
  // 500 here would make the agent retry and duplicate it.
  it("still accepts the detection when the counter update fails", async () => {
    db.$executeRaw.mockRejectedValue(new Error("db down"));
    const res = await ingest();
    expect(res.status).toBe(200);
    expect(db.detection.create).toHaveBeenCalledTimes(1);
  });
});

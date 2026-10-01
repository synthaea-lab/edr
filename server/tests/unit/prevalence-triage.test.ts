import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const db = vi.hoisted(() => ({
  prevalenceSighting: { groupBy: vi.fn(), deleteMany: vi.fn() },
  case: { findFirst: vi.fn() },
  caseNarrative: { findFirst: vi.fn() },
  $executeRaw: vi.fn(),
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));

import {
  MAX_LOOKUPS,
  describePrevalence,
  lookedUpKeys,
  getPrevalenceBatch,
  observationsOfDetections,
  type PrevalenceKind,
  prevalenceKey,
  prunePrevalence,
  triageLines,
  type Prevalence,
} from "@/lib/prevalence";
import { GET as getCase } from "@/app/api/cases/[id]/route";
import { GET as prune } from "@/app/api/cron/prune-prevalence/route";

const SHA = "e".repeat(64);
const exec = (over: Record<string, unknown> = {}) => ({
  type: "exec",
  image_path: "/usr/bin/curl",
  parent_comm: "bash",
  sha256: SHA,
  ...over,
});
const day = (d: number) => new Date(Date.UTC(2026, 8, d));
const prev = (hostCount: number, firstDay = 1): Prevalence => ({
  hostCount,
  eventCount: hostCount * 3,
  firstSeen: day(firstDay),
  lastSeen: day(29),
});

describe("describePrevalence", () => {
  it("says a never-seen key is new to the fleet instead of leaving it blank", () => {
    expect(describePrevalence(null)).toBe("never seen on this fleet before");
  });

  it("gives the host count and first-seen date, singular for one host", () => {
    expect(describePrevalence(prev(1, 5))).toBe("seen on 1 host, first 2026-09-05");
    expect(describePrevalence(prev(12, 2))).toBe("seen on 12 hosts, first 2026-09-02");
  });
});

describe("observationsOfDetections", () => {
  it("is the distinct observations across the detections, skipping unusable events", () => {
    const obs = observationsOfDetections([
      { event: exec() },
      { event: exec() }, // the same binary again
      { event: exec({ image_path: "/bin/ls", sha256: undefined, parent_comm: undefined }) },
      { event: { test: "data" } },
      { event: null },
    ]);
    const keys = obs.map((o) => `${o.kind}:${o.key}`);
    expect(new Set(keys).size).toBe(keys.length);
    expect(keys).toContain(`sha256:${SHA}`);
    expect(keys).toContain("image_path:/bin/ls");
    expect(keys).toContain("image_path:/usr/bin/curl");
  });
});

const allKeys = (obs: { kind: PrevalenceKind; key: string }[]) =>
  new Set(obs.map((o) => prevalenceKey(o.kind, o.key)));

describe("triageLines", () => {
  it("puts the rarest first, with never-seen ahead of everything", () => {
    const obs = [
      { kind: "domain" as const, key: "common.example" },
      { kind: "sha256" as const, key: SHA },
      { kind: "image_path" as const, key: "/opt/one-host" },
    ];
    const found = new Map([
      [prevalenceKey("domain", "common.example"), prev(40)],
      [prevalenceKey("image_path", "/opt/one-host"), prev(1)],
    ]);
    const { lines } = triageLines(obs, found, allKeys(obs));
    expect(lines.map((l) => l.text)).toEqual([
      "never seen on this fleet before",
      "seen on 1 host, first 2026-09-01",
      "seen on 40 hosts, first 2026-09-01",
    ]);
    expect(lines[0].label).toBe(`hash ${SHA.slice(0, 12)}…`);
  });

  it("does not call a key 'never seen' when it was never looked up", () => {
    const obs = Array.from({ length: MAX_LOOKUPS + 5 }, (_, i) => ({
      kind: "domain" as const,
      key: `d${i}.example`,
    }));
    const { lines, omitted } = triageLines(obs, new Map(), allKeys(lookedUpKeys(obs)));
    expect(lines).toHaveLength(MAX_LOOKUPS);
    expect(omitted).toBe(5);
  });

  it("counts a later detection's keys as omitted when the case-wide cap never looked them up", () => {
    const domains = (from: number, n: number) =>
      Array.from({ length: n }, (_, i) => ({ kind: "domain" as const, key: `d${from + i}.example` }));
    const first = domains(0, MAX_LOOKUPS);
    const second = domains(MAX_LOOKUPS, 3); // each detection is under the cap on its own
    const lookedUp = allKeys(lookedUpKeys([...first, ...second]));

    const { lines, omitted } = triageLines(second, new Map(), lookedUp);
    expect(lines).toEqual([]);
    expect(omitted).toBe(3);
  });

  it("shortens a long path for display but keeps the full key", () => {
    const long = "/" + "a".repeat(200);
    const { lines } = triageLines([{ kind: "image_path", key: long }], new Map(), allKeys([{ kind: "image_path", key: long }]));
    expect(lines[0].label.length).toBeLessThan(100);
    expect(lines[0].key).toBe(long);
  });
});

describe("getPrevalenceBatch", () => {
  beforeEach(() => vi.clearAllMocks());

  it("looks all keys up in one grouped, tenant-scoped query", async () => {
    db.prevalenceSighting.groupBy.mockResolvedValue([
      {
        kind: "sha256",
        key: SHA,
        _count: { _all: 2 },
        _sum: { count: 5 },
        _min: { firstSeen: day(3) },
        _max: { lastSeen: day(20) },
      },
    ]);
    const found = await getPrevalenceBatch(db as never, "t1", [
      { kind: "sha256", key: SHA },
      { kind: "domain", key: "x.example" },
      { kind: "sha256", key: SHA }, // duplicate
    ]);
    expect(db.prevalenceSighting.groupBy).toHaveBeenCalledTimes(1);
    const args = db.prevalenceSighting.groupBy.mock.calls[0][0];
    expect(args.where.tenantId).toBe("t1");
    expect(args.where.OR).toHaveLength(2);
    expect(found.get(prevalenceKey("sha256", SHA))).toMatchObject({ hostCount: 2, eventCount: 5 });
    expect(found.has(prevalenceKey("domain", "x.example"))).toBe(false);
  });

  it("makes no query at all when there is nothing to look up", async () => {
    expect((await getPrevalenceBatch(db as never, "t1", [])).size).toBe(0);
    expect(db.prevalenceSighting.groupBy).not.toHaveBeenCalled();
  });

  it("never asks for more than MAX_LOOKUPS keys", async () => {
    db.prevalenceSighting.groupBy.mockResolvedValue([]);
    const many = Array.from({ length: MAX_LOOKUPS + 50 }, (_, i) => ({
      kind: "domain" as const,
      key: `d${i}.example`,
    }));
    await getPrevalenceBatch(db as never, "t1", many);
    expect(db.prevalenceSighting.groupBy.mock.calls[0][0].where.OR).toHaveLength(MAX_LOOKUPS);
  });
});

describe("GET /api/cases/[id] prevalence", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    db.caseNarrative.findFirst.mockResolvedValue(null);
    db.prevalenceSighting.groupBy.mockResolvedValue([]);
  });

  const call = (tenant = "t1") =>
    getCase(
      new NextRequest("http://localhost/api/cases/c1", { headers: { "x-tenant-id": tenant } }),
      { params: { id: "c1" } }
    );

  it("adds each detection's triage lines, looked up within the caller's tenant", async () => {
    db.case.findFirst.mockResolvedValue({
      id: "c1",
      detections: [{ id: "d1", event: exec(), updatedAt: new Date(0) }],
    });
    const body = await (await call("tenant-b")).json();
    expect(body.prevalence.d1.lines.map((l: { kind: string }) => l.kind)).toEqual(
      expect.arrayContaining(["sha256", "image_path", "transition"])
    );
    expect(body.prevalence.d1.lines[0].text).toBe("never seen on this fleet before");
    expect(db.prevalenceSighting.groupBy.mock.calls[0][0].where.tenantId).toBe("tenant-b");
  });

  it("gives a detection with no usable event an empty list", async () => {
    db.case.findFirst.mockResolvedValue({
      id: "c1",
      detections: [{ id: "d1", event: { test: "data" }, updatedAt: new Date(0) }],
    });
    expect((await (await call()).json()).prevalence.d1).toEqual({ lines: [], omitted: 0 });
  });
});

describe("prunePrevalence", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    db.prevalenceSighting.deleteMany.mockResolvedValue({ count: 7 });
    db.prevalenceSighting.groupBy.mockResolvedValue([
      { tenantId: "small", _count: { _all: 10 } },
      { tenantId: "huge", _count: { _all: 1500 } },
    ]);
    db.$executeRaw.mockResolvedValue(500);
  });

  it("drops what has not been renewed since the cutoff", async () => {
    const olderThan = day(1);
    const r = await prunePrevalence(db as never, { olderThan, maxRowsPerTenant: 1000 });
    expect(db.prevalenceSighting.deleteMany.mock.calls[0][0]).toEqual({
      where: { lastSeen: { lt: olderThan } },
    });
    expect(r.expired).toBe(7);
  });

  it("trims only a tenant that is over the cap, and only past the cap", async () => {
    const r = await prunePrevalence(db as never, { olderThan: day(1), maxRowsPerTenant: 1000 });
    expect(db.$executeRaw).toHaveBeenCalledTimes(1);
    const values = db.$executeRaw.mock.calls[0].slice(1);
    expect(values).toEqual(["huge", 1000]);
    expect(r.overCap).toBe(500);
  });

  it("does nothing further when every tenant is within the cap", async () => {
    db.prevalenceSighting.groupBy.mockResolvedValue([{ tenantId: "a", _count: { _all: 1000 } }]);
    await prunePrevalence(db as never, { olderThan: day(1), maxRowsPerTenant: 1000 });
    expect(db.$executeRaw).not.toHaveBeenCalled();
  });
});

describe("GET /api/cron/prune-prevalence", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.CRON_SECRET = "cron-secret";
    delete process.env.PREVALENCE_RETENTION_DAYS;
    delete process.env.PREVALENCE_MAX_ROWS_PER_TENANT;
    db.prevalenceSighting.deleteMany.mockResolvedValue({ count: 0 });
    db.prevalenceSighting.groupBy.mockResolvedValue([]);
  });

  const call = (auth: string | null = "Bearer cron-secret") =>
    prune(
      new NextRequest("http://localhost/api/cron/prune-prevalence", {
        headers: auth ? { Authorization: auth } : {},
      })
    );

  it("refuses a call without the cron secret and deletes nothing", async () => {
    expect((await call(null)).status).toBe(401);
    expect((await call("Bearer nope")).status).toBe(401);
    expect(db.prevalenceSighting.deleteMany).not.toHaveBeenCalled();
  });

  it("fails closed when no cron secret is configured", async () => {
    delete process.env.CRON_SECRET;
    expect((await call("Bearer undefined")).status).toBe(500);
    expect(db.prevalenceSighting.deleteMany).not.toHaveBeenCalled();
  });

  it("uses the documented defaults and reports what it applied", async () => {
    const body = await (await call()).json();
    expect(body).toMatchObject({ retentionDays: 180, maxRowsPerTenant: 5_000_000, expired: 0, overCap: 0 });
  });

  it("honours the environment, and refuses a value that is set but wrong", async () => {
    process.env.PREVALENCE_RETENTION_DAYS = "30";
    expect((await (await call()).json()).retentionDays).toBe(30);
    for (const bad of ["abc", "0", "-5", "1.5"]) {
      process.env.PREVALENCE_RETENTION_DAYS = bad;
      db.prevalenceSighting.deleteMany.mockClear();
      expect((await call()).status, bad).toBe(500);
      expect(db.prevalenceSighting.deleteMany).not.toHaveBeenCalled();
    }
  });
});

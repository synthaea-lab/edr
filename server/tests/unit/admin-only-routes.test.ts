import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { mkdirSync, rmSync } from "fs";
import { join } from "path";

// Route logic runs against a mocked Prisma client, so these need no database.
const db = vi.hoisted(() => ({
  agent: { findFirst: vi.fn(), update: vi.fn() },
  corpusVersion: { findUnique: vi.fn(), update: vi.fn() },
  corpusSample: { findMany: vi.fn() },
  auditLog: { create: vi.fn() },
  member: { findFirst: vi.fn() },
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));

import { POST as assignRing } from "@/app/api/agents/[agentId]/ring/route";
import { POST as finalizeCorpus } from "@/app/api/corpus/finalize/route";

function req(url: string, body: unknown) {
  return new NextRequest(`http://localhost${url}`, {
    method: "POST",
    headers: { "x-tenant-id": "t1", "x-user-id": "u1", "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

const ringReq = (body: unknown = { ring: "prod" }) => req("/api/agents/a1/ring", body);
const ringParams = { params: { agentId: "a1" } };
const finalizeReq = (body: unknown = { version: 1 }) => req("/api/corpus/finalize", body);

let originalCwd: string;
let sandbox: string;

beforeEach(() => {
  vi.clearAllMocks();
  // finalize writes its export under ./storage: keep it out of the repo.
  originalCwd = process.cwd();
  sandbox = join(originalCwd, ".test-sandbox-admin-only-routes");
  mkdirSync(sandbox, { recursive: true });
  process.chdir(sandbox);

  db.agent.findFirst.mockResolvedValue({ id: "a1", tenantId: "t1", ring: "canary_0", enrollmentId: "e1", hostname: "h1" });
  db.agent.update.mockImplementation(async ({ where, data }) => ({ id: where.id, ...data }));
  db.corpusVersion.findUnique.mockResolvedValue({ id: "cv1", version: 1, status: "collecting" });
  db.corpusVersion.update.mockImplementation(async ({ data }) => ({ id: "cv1", sampleCount: 0, ...data }));
  db.corpusSample.findMany.mockResolvedValue([]);
  db.auditLog.create.mockResolvedValue({});
  db.member.findFirst.mockResolvedValue({ role: "owner" });
});

afterEach(() => {
  process.chdir(originalCwd);
  rmSync(sandbox, { recursive: true, force: true });
});

describe("agents/[agentId]/ring and corpus/finalize require the admin role (#837)", () => {
  it("refuses a plain member on both routes, before either reads its body", async () => {
    db.member.findFirst.mockResolvedValue({ role: "member" });

    expect((await assignRing(ringReq(), ringParams)).status).toBe(403);
    expect(db.agent.findFirst).not.toHaveBeenCalled();
    expect(db.agent.update).not.toHaveBeenCalled();

    expect((await finalizeCorpus(finalizeReq())).status).toBe(403);
    expect(db.corpusVersion.findUnique).not.toHaveBeenCalled();
    expect(db.corpusVersion.update).not.toHaveBeenCalled();
  });

  it("refuses a member with an invalid body with 403, not the schema's 400", async () => {
    // Pins the gate running before the body is parsed.
    db.member.findFirst.mockResolvedValue({ role: "member" });
    expect((await assignRing(ringReq({ ring: "not-a-ring" }), ringParams)).status).toBe(403);
    expect((await finalizeCorpus(finalizeReq({ version: "x" }))).status).toBe(403);
  });

  it("refuses a caller with no membership row at all", async () => {
    db.member.findFirst.mockResolvedValue(null);
    expect((await assignRing(ringReq(), ringParams)).status).toBe(403);
    expect((await finalizeCorpus(finalizeReq())).status).toBe(403);
  });

  it("moves the agent for an admin and audits it under the caller's id", async () => {
    db.member.findFirst.mockResolvedValue({ role: "admin" });
    const res = await assignRing(ringReq(), ringParams);
    expect(res.status).toBe(200);
    expect(db.agent.update).toHaveBeenCalledWith({ where: { id: "a1" }, data: { ring: "prod" } });
    expect(db.auditLog.create).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ tenantId: "t1", userId: "u1" }) })
    );
  });

  it("finalizes the corpus for an owner and audits it under the caller's id", async () => {
    const res = await finalizeCorpus(finalizeReq());
    expect(res.status).toBe(200);
    expect(db.corpusVersion.update).toHaveBeenCalledOnce();
    expect(db.auditLog.create).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ tenantId: "t1", userId: "u1" }) })
    );
  });

  it("looks the membership up by the caller's own tenant and user id", async () => {
    await assignRing(ringReq(), ringParams);
    await finalizeCorpus(finalizeReq());
    for (const call of db.member.findFirst.mock.calls) {
      expect(call[0]).toEqual({ where: { organizationId: "t1", userId: "u1" }, select: { role: true } });
    }
    expect(db.member.findFirst).toHaveBeenCalledTimes(2);
  });
});

import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { cleanDatabase, createTestAgent, createTestCase, createTestTenant, prisma } from "../helpers/db";
import { createMtlsHeaders, createTenantHeaders } from "../helpers/http";
import { POST as ingestDetection } from "@/app/api/ingest/detection/route";
import { GET as getCase } from "@/app/api/cases/[id]/route";

/**
 * The damage manifest (issue #82) end to end through the real ingest route: a ransomware
 * detection as the agent serializes it (the golden `schema::Detection` and `FileRenameEvent`
 * JSON, the wire format the Rust side owns), posted to the ingest route, then read back as a
 * case. This is the path `--alerts` does not show: the extra events travel in the detection
 * (`events` after the first), the route keeps the first in `event` and the rest in
 * `meta.additional_events`, and the case route turns them into `damageManifest`.
 */
const FIXTURES = path.resolve(__dirname, "../../../crates/schema/tests/fixtures");
const SECRET = "test-proxy-secret";

/** The newest schema version's fixtures: the version moves, the shapes are the point. */
function fixture(name: string): Record<string, any> {
  const versions = readdirSync(FIXTURES)
    .filter((d) => /^v\d+$/.test(d) && existsSync(path.join(FIXTURES, d, name)))
    .sort((a, b) => Number(b.slice(1)) - Number(a.slice(1)));
  return JSON.parse(readFileSync(path.join(FIXTURES, versions[0], name), "utf8"));
}

function rename(base: Record<string, any>, from: string, to: string, ns: number) {
  return { ...base, meta: { ...base.meta, timestamp_ns: ns }, old_path: from, new_path: to };
}

describe("damage manifest through the ingest route (real database)", () => {
  beforeEach(async () => {
    process.env.NGINX_PROXY_SECRET = SECRET;
    await cleanDatabase();
  });
  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  it("carries a T1486 detection's further events from the agent's JSON to the case's manifest", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const base = fixture("file_rename.json");
    const detection = {
      ...fixture("detection_rule.json"),
      title: "20 files renamed with an appended suffix in 5s",
      techniques: ["T1486"],
      events: [
        // The triggering event first, then the process's earlier renames, oldest first.
        rename(base, "/home/user/c.docx", "/home/user/c.docx.locked", 3_000_000_000),
        rename(base, "/home/user/a.docx", "/home/user/a.docx.locked", 1_000_000_000),
        rename(base, "/home/user/b.docx", "/home/user/b.docx.locked", 2_000_000_000),
      ],
    };

    const res = await ingestDetection(
      new NextRequest("http://localhost/api/ingest/detection", {
        method: "POST",
        headers: { ...createMtlsHeaders(agent.enrollmentId), "X-Proxy-Secret": SECRET },
        body: JSON.stringify(detection),
      })
    );
    expect(res.status).toBe(200);

    const stored = await prisma.detection.findFirstOrThrow({ where: { agentId: agent.id } });
    expect(stored.technique).toBe("T1486");
    expect((stored.event as any).new_path).toBe("/home/user/c.docx.locked");
    expect((stored.meta as any).additional_events).toHaveLength(2);

    const incident = await createTestCase(tenant.id, { title: "T1486 activity" });
    await prisma.detection.update({ where: { id: stored.id }, data: { caseId: incident.id } });

    const body = await (
      await getCase(
        new NextRequest("http://localhost/api/cases/x", { headers: createTenantHeaders(tenant.id) }),
        { params: { id: incident.id } }
      )
    ).json();

    expect(body.damageManifest.truncated).toBe(false);
    expect(body.damageManifest.files.map((f: { path: string; to?: string }) => [f.path, f.to])).toEqual([
      ["/home/user/a.docx", "/home/user/a.docx.locked"],
      ["/home/user/b.docx", "/home/user/b.docx.locked"],
      ["/home/user/c.docx", "/home/user/c.docx.locked"],
    ]);
    expect(body.damageManifest.files.every((f: { agentId: string }) => f.agentId === agent.id)).toBe(true);
  });

  it("gives a detection that is not ransomware no manifest, whatever events it carries", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const base = fixture("file_rename.json");
    const detection = {
      ...fixture("detection_rule.json"),
      techniques: ["T1059.004"],
      events: [rename(base, "/a", "/a.x", 1_000_000_000), rename(base, "/b", "/b.x", 2_000_000_000)],
    };
    const res = await ingestDetection(
      new NextRequest("http://localhost/api/ingest/detection", {
        method: "POST",
        headers: { ...createMtlsHeaders(agent.enrollmentId), "X-Proxy-Secret": SECRET },
        body: JSON.stringify(detection),
      })
    );
    expect(res.status).toBe(200);
    const stored = await prisma.detection.findFirstOrThrow({ where: { agentId: agent.id } });
    const incident = await createTestCase(tenant.id);
    await prisma.detection.update({ where: { id: stored.id }, data: { caseId: incident.id } });

    const body = await (
      await getCase(
        new NextRequest("http://localhost/api/cases/x", { headers: createTenantHeaders(tenant.id) }),
        { params: { id: incident.id } }
      )
    ).json();
    expect(body.damageManifest).toEqual({ files: [], truncated: false });
  });
});

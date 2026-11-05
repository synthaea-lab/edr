import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { createHash, randomBytes } from "crypto";
import { mkdirSync, rmSync, writeFileSync } from "fs";
import { join } from "path";

// Route logic runs against a mocked Prisma client, so these need no database.
const db = vi.hoisted(() => ({
  contentRelease: { findFirst: vi.fn(), create: vi.fn(), update: vi.fn() },
  auditLog: { create: vi.fn() },
  member: { findFirst: vi.fn() },
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));

import { POST as publish } from "@/app/api/content/release/route";
import { POST as rollback } from "@/app/api/content/rollback/route";
import { POST as halt } from "@/app/api/content/halt/route";

const sha = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");

const RULE_V2 = Buffer.from("title: rule as of release 2\n");
const RULE_V4 = Buffer.from("title: rule as modified by release 4\n");
const OTHER = Buffer.from("title: another rule\n");

let originalCwd: string;
let sandbox: string;

function manifestFor(overrides: Record<string, unknown> = {}) {
  return Buffer.from(
    JSON.stringify({
      schema_version: 1,
      release_version: 5,
      ring: "canary_0",
      released_at: "2026-10-12T09:30:00Z",
      entries: [
        { path: "rules/x.sigma", type: "rule", sha256: sha(RULE_V2), size: RULE_V2.length },
        { path: "rules/y.sigma", type: "rule", sha256: sha(OTHER), size: OTHER.length },
      ],
      signature: "00",
      ...overrides,
    })
  );
}

/**
 * Puts a manifest at storage://manifests/<name> and the given artifacts' bytes in
 * storage/artifacts, under their own hash (#804) — the map's keys are only there to make
 * call sites at tests below readable, the store itself does not key on them.
 */
function store(manifest: Buffer, artifacts: Record<string, Buffer>, name = "content-canary_0-v5.json") {
  writeFileSync(join(sandbox, "storage", "manifests", name), manifest);
  for (const bytes of Object.values(artifacts)) {
    writeFileSync(join(sandbox, "storage", "artifacts", sha(bytes)), bytes);
  }
}

const GOOD_ARTIFACTS = { "rules/x.sigma": RULE_V2, "rules/y.sigma": OTHER };

function post(body: unknown) {
  return new NextRequest("http://localhost/api/content/release", {
    method: "POST",
    headers: { "x-tenant-id": "t1", "x-user-id": "u1", "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

function publishBody(manifest: Buffer, overrides: Record<string, unknown> = {}) {
  return {
    ring: "canary_0",
    manifestUrl: "storage://manifests/content-canary_0-v5.json",
    manifestSha256: sha(manifest),
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  originalCwd = process.cwd();
  sandbox = join(originalCwd, ".test-sandbox-content-publish");
  mkdirSync(join(sandbox, "storage", "manifests"), { recursive: true });
  mkdirSync(join(sandbox, "storage", "artifacts"), { recursive: true });
  process.chdir(sandbox);
  // The ring's highest release is 4 (rolled back): the next number is 5.
  db.contentRelease.findFirst.mockResolvedValue({ releaseVersion: 4, status: "rolled_back" });
  db.contentRelease.create.mockImplementation(async ({ data }) => ({ id: "r5", ...data }));
  db.auditLog.create.mockResolvedValue({});
  // The caller is the tenant's owner by default (#803); tests of the admin check itself
  // override this.
  db.member.findFirst.mockResolvedValue({ role: "owner" });
});

afterEach(() => {
  process.chdir(originalCwd);
  rmSync(sandbox, { recursive: true, force: true });
});

describe("POST /api/content/release: nothing is published that an agent could not apply (#665)", () => {
  it("publishes a release whose manifest, number, ring and artifacts all check out", async () => {
    const manifest = manifestFor();
    store(manifest, GOOD_ARTIFACTS);
    const res = await publish(post(publishBody(manifest)));
    expect(res.status).toBe(200);
    expect(db.contentRelease.create).toHaveBeenCalledOnce();
    expect(db.contentRelease.create.mock.calls[0][0].data.releaseVersion).toBe(5);
    expect(db.auditLog.create).toHaveBeenCalledOnce();
  });

  it("publishes an IOC feed and its version file as entries of type ioc (#60)", async () => {
    const feedBytes = Buffer.from(`sha256:${"a".repeat(64)}\nip:203.0.113.9\n`);
    const versionBytes = Buffer.from("2026-10-28\n");
    const manifest = manifestFor({
      entries: [
        { path: "ioc/lab.txt", type: "ioc", sha256: sha(feedBytes), size: feedBytes.length },
        { path: "ioc/VERSION", type: "ioc", sha256: sha(versionBytes), size: versionBytes.length },
      ],
    });
    store(manifest, { feed: feedBytes, version: versionBytes });
    const res = await publish(post(publishBody(manifest)));
    expect(res.status).toBe(200);
    expect(db.contentRelease.create).toHaveBeenCalledOnce();
  });

  it("refuses a release whose rule entry sits under ioc/, which the agent would load as a feed (#60)", async () => {
    const manifest = manifestFor({
      entries: [{ path: "ioc/sneaky.txt", type: "rule", sha256: sha(RULE_V2), size: RULE_V2.length }],
    });
    store(manifest, { rule: RULE_V2 });
    const res = await publish(post(publishBody(manifest)));
    expect(res.status).toBe(422);
    expect((await res.json()).error).toContain("ioc/");
    expect(db.contentRelease.create).not.toHaveBeenCalled();
  });

  it("refuses a release whose IOC feed has a line the device would skip (#60)", async () => {
    const bad = Buffer.from("ip:127.0.0.1\n");
    const manifest = manifestFor({
      entries: [{ path: "ioc/lab.txt", type: "ioc", sha256: sha(bad), size: bad.length }],
    });
    store(manifest, { bad });
    const res = await publish(post(publishBody(manifest)));
    expect(res.status).toBe(422);
    expect((await res.json()).error).toContain("unusable_address");
    expect(db.contentRelease.create).not.toHaveBeenCalled();
  });

  it("numbers the release after the ring's highest, rolled-back releases included", async () => {
    const manifest = manifestFor();
    store(manifest, GOOD_ARTIFACTS);
    await publish(post(publishBody(manifest)));
    // No status filter: a rolled-back or halted release still owns its number.
    expect(db.contentRelease.findFirst).toHaveBeenCalledWith({
      where: { tenantId: "t1", ring: "canary_0" },
      orderBy: { releaseVersion: "desc" },
    });
  });

  it("refuses a manifest that carries another number than the one the control plane will assign", async () => {
    // Otherwise every agent of the ring gets a 502 when the manifest is served.
    const manifest = manifestFor({ release_version: 7 });
    store(manifest, GOOD_ARTIFACTS);
    const res = await publish(post(publishBody(manifest)));
    expect(res.status).toBe(422);
    const body = await res.json();
    expect(body.error).toContain("5");
    expect(body.error).toContain("7");
    expect(db.contentRelease.create).not.toHaveBeenCalled();
  });

  it("refuses a manifest that lists nothing: an empty one would wipe every agent of the ring", async () => {
    const manifest = manifestFor({ entries: [] });
    store(manifest, {});
    const res = await publish(post(publishBody(manifest)));
    expect(res.status).toBe(422);
    expect(db.contentRelease.create).not.toHaveBeenCalled();
  });

  it("refuses a manifest for another ring than the one it is published to", async () => {
    const manifest = manifestFor({ ring: "prod" });
    store(manifest, GOOD_ARTIFACTS);
    expect((await publish(post(publishBody(manifest)))).status).toBe(422);
    expect(db.contentRelease.create).not.toHaveBeenCalled();
  });

  it("refuses a manifest that does not hash to the value it is published with", async () => {
    const manifest = manifestFor();
    store(manifest, GOOD_ARTIFACTS);
    const res = await publish(post(publishBody(manifest, { manifestSha256: "c".repeat(64) })));
    expect(res.status).toBe(422);
  });

  it("refuses a release whose artifact is not in the store", async () => {
    const manifest = manifestFor();
    store(manifest, { "rules/x.sigma": RULE_V2 }); // rules/y.sigma missing
    const res = await publish(post(publishBody(manifest)));
    expect(res.status).toBe(422);
    expect((await res.json()).error).toContain("rules/y.sigma");
    expect(db.contentRelease.create).not.toHaveBeenCalled();
  });

  it("publishes a corrective release over a modified path with nothing restored first (#804)", async () => {
    // Release 2 uploaded RULE_V2 under its own hash; release 4 later changed rules/x.sigma
    // and uploaded RULE_V4 under ITS hash — content-addressed, so this never touched RULE_V2's
    // bytes. A corrective release naming RULE_V2's hash for rules/x.sigma again (ADR-0032)
    // needs nothing put back: those bytes never moved.
    const manifest = manifestFor(); // lists RULE_V2's hash for rules/x.sigma
    store(manifest, GOOD_ARTIFACTS); // RULE_V2 and OTHER, as release 2 (or the test fixture) uploaded them
    writeFileSync(join(sandbox, "storage", "artifacts", sha(RULE_V4)), RULE_V4); // release 4's separate upload
    const res = await publish(post(publishBody(manifest)));
    expect(res.status).toBe(200);
    expect(db.contentRelease.create).toHaveBeenCalledOnce();
  });

  it("refuses an entry path that would leave the store", async () => {
    const manifest = manifestFor({
      entries: [{ path: "../../etc/passwd", type: "rule", sha256: sha(OTHER), size: 1 }],
    });
    store(manifest, {});
    expect((await publish(post(publishBody(manifest)))).status).toBe(422);
  });

  it("refuses an entry sha256 that is not 64 lowercase hex characters, before it ever reaches the filesystem", async () => {
    // The store now reads an entry by its sha256 as a path component (#804): without the
    // schema's regex, a crafted manifest could point that read outside storage/artifacts
    // (review of #835). An empty store already answers 422 "not in the store" for ANY
    // sha256, traversal or not, which made the original version of this test pass whether
    // or not the regex existed (SherlockOmss's review): removing the regex left all tests
    // green. A file genuinely readable at the path the traversal targets, outside
    // storage/artifacts, makes the two cases diverge: without the regex, the read would
    // succeed and the loop would move on to the next entry; with it,
    // `ContentManifest.safeParse` rejects the manifest before any file lookup runs. The
    // error text is schema wording ("does not match the content manifest schema"), not the
    // store's ("is not in the store") — asserting on it is what actually pins the regex.
    // A per-run unique name, not a fixed one: `sandbox`'s parent is the real project
    // directory (`originalCwd`), shared by every test file and worker, not a sandbox
    // of its own — a fixed name would collide under parallel test execution, and a
    // crash before the `finally` below would leave a stray file for the next run to
    // trip over (review of #835).
    const traversalName = `escaped-by-835-test-${randomBytes(8).toString("hex")}.txt`;
    const traversalTarget = join(sandbox, "..", traversalName);
    writeFileSync(traversalTarget, "should never be read as an artifact");
    try {
      const manifest = manifestFor({
        entries: [
          { path: "rules/x.sigma", type: "rule", sha256: `../../../${traversalName}`, size: 1 },
        ],
      });
      store(manifest, {});
      const res = await publish(post(publishBody(manifest)));
      const body = await res.json();
      expect(res.status).toBe(422);
      expect(body.error).toContain("does not match the content manifest schema");
      expect(body.error).not.toContain("is not in the store");
    } finally {
      rmSync(traversalTarget, { force: true });
    }
  });

  it("answers 409, not 500, when a concurrent publish took the number first", async () => {
    // Two publishes read the same highest release; the unique (tenant, ring, version) row
    // makes the second `create` fail. The binary release route already says so with a 409.
    const manifest = manifestFor();
    store(manifest, GOOD_ARTIFACTS);
    db.contentRelease.create.mockRejectedValue(Object.assign(new Error("unique"), { code: "P2002" }));
    const res = await publish(post(publishBody(manifest)));
    expect(res.status).toBe(409);
    expect(db.auditLog.create).not.toHaveBeenCalled();
  });

  it("without a tenant context it is not served", async () => {
    const manifest = manifestFor();
    store(manifest, GOOD_ARTIFACTS);
    const res = await publish(
      new NextRequest("http://localhost/api/content/release", {
        method: "POST",
        body: JSON.stringify(publishBody(manifest)),
      })
    );
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(db.contentRelease.create).not.toHaveBeenCalled();
  });
});

describe("POST /api/content/rollback: it says what it does not do (#665)", () => {
  function rollbackReq() {
    return new NextRequest("http://localhost/api/content/rollback", {
      method: "POST",
      headers: { "x-tenant-id": "t1", "x-user-id": "u1", "content-type": "application/json" },
      body: JSON.stringify({ ring: "canary_0", reason: "bad rule" }),
    });
  }

  it("names the corrective release after the ring's highest release, rolled-back ones included, and audits it", async () => {
    db.contentRelease.findFirst
      .mockResolvedValueOnce({ id: "r4", releaseVersion: 4, status: "active" }) // current
      .mockResolvedValueOnce({ id: "r2", releaseVersion: 2, status: "active" }) // target
      .mockResolvedValueOnce({ releaseVersion: 4 }); // highest of the ring
    db.contentRelease.update.mockImplementation(async ({ where, data }) => ({ id: where.id, ...data }));

    const res = await rollback(rollbackReq());

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.correctiveRelease.releaseVersion).toBe(5);
    expect(body.correctiveRelease.restoreVersion).toBe(2);
    expect(db.auditLog.create.mock.calls[0][0].data.details.correctiveReleaseVersion).toBe(5);
    // The highest-release lookup has no status filter.
    expect(db.contentRelease.findFirst.mock.calls[2][0]).toEqual({
      where: { tenantId: "t1", ring: "canary_0" },
      orderBy: { releaseVersion: "desc" },
      select: { releaseVersion: true },
    });
  });
});

describe("content/release, content/rollback and content/halt require the admin role (#803)", () => {
  function rollbackReq(body: unknown = { ring: "canary_0", reason: "bad rule" }) {
    return new NextRequest("http://localhost/api/content/rollback", {
      method: "POST",
      headers: { "x-tenant-id": "t1", "x-user-id": "u1", "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  function haltReq(body: unknown = { ring: "canary_0", reason: "bad rule" }) {
    return new NextRequest("http://localhost/api/content/halt", {
      method: "POST",
      headers: { "x-tenant-id": "t1", "x-user-id": "u1", "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  it("refuses a plain member on all three routes, before any of them reads its body", async () => {
    db.member.findFirst.mockResolvedValue({ role: "member" });
    const manifest = manifestFor();
    store(manifest, GOOD_ARTIFACTS);

    const publishRes = await publish(post(publishBody(manifest)));
    expect(publishRes.status).toBe(403);
    expect(db.contentRelease.create).not.toHaveBeenCalled();

    const rollbackRes = await rollback(rollbackReq());
    expect(rollbackRes.status).toBe(403);
    expect(db.contentRelease.update).not.toHaveBeenCalled();

    const haltRes = await halt(haltReq());
    expect(haltRes.status).toBe(403);
    expect(db.contentRelease.update).not.toHaveBeenCalled();
  });

  it("refuses a caller with no membership row at all", async () => {
    db.member.findFirst.mockResolvedValue(null);
    const manifest = manifestFor();
    store(manifest, GOOD_ARTIFACTS);
    expect((await publish(post(publishBody(manifest)))).status).toBe(403);
  });

  it("accepts an admin member, not only an owner", async () => {
    db.member.findFirst.mockResolvedValue({ role: "admin" });
    const manifest = manifestFor();
    store(manifest, GOOD_ARTIFACTS);
    expect((await publish(post(publishBody(manifest)))).status).toBe(200);
  });

  it("accepts a member whose role is a comma-separated list including admin or owner", async () => {
    // better-auth stores several roles as one comma-separated string (`updateMemberRole`
    // takes an array); a caller given two roles must not be refused because the whole
    // string never equals "admin" or "owner".
    db.member.findFirst.mockResolvedValue({ role: "admin,member" });
    const manifest = manifestFor();
    store(manifest, GOOD_ARTIFACTS);
    expect((await publish(post(publishBody(manifest)))).status).toBe(200);
  });

  it("looks the membership up by the caller's own tenant and user id", async () => {
    const manifest = manifestFor();
    store(manifest, GOOD_ARTIFACTS);
    await publish(post(publishBody(manifest)));
    expect(db.member.findFirst).toHaveBeenCalledWith({
      where: { organizationId: "t1", userId: "u1" },
      select: { role: true },
    });
  });

  it("refuses a member with an invalid body with 403, not the schema's 400 (review of #831)", async () => {
    // Pins the gate running before the body is parsed: if a route were reordered to
    // validate the body first, a member sending garbage would get 400 instead of 403.
    db.member.findFirst.mockResolvedValue({ role: "member" });
    const res = await publish(post({ ring: "not-a-real-ring" }));
    expect(res.status).toBe(403);
  });

  it("refuses a member with an invalid rollback body with 403, not the schema's 400", async () => {
    // The first such test (above) only exercised /release; the gate runs identically before
    // the body is read on every one of the three routes, not just that one (review of #831).
    db.member.findFirst.mockResolvedValue({ role: "member" });
    const res = await rollback(rollbackReq({ ring: "not-a-real-ring" }));
    expect(res.status).toBe(403);
  });

  it("refuses a member with an invalid halt body with 403, not the schema's 400", async () => {
    db.member.findFirst.mockResolvedValue({ role: "member" });
    const res = await halt(haltReq({ ring: "not-a-real-ring" }));
    expect(res.status).toBe(403);
  });

  it("accepts a comma-separated role including admin or owner on a route other than release", async () => {
    // The release-only version of this test (above) could pass even if another route's own
    // split/compare had a bug of its own; this pins the same behavior on rollback too
    // (review of #831).
    db.contentRelease.findFirst
      .mockResolvedValueOnce({ id: "r4", releaseVersion: 4, status: "active" })
      .mockResolvedValueOnce({ id: "r2", releaseVersion: 2, status: "active" })
      .mockResolvedValueOnce({ releaseVersion: 4 });
    db.contentRelease.update.mockImplementation(async ({ where, data }) => ({ id: where.id, ...data }));
    db.member.findFirst.mockResolvedValue({ role: "member,admin" });
    expect((await rollback(rollbackReq())).status).toBe(200);
  });

  it("a caller with no tenant context (no active organization) gets a clean 401, not a 500", async () => {
    // getTenantId/getUserId throw when the middleware found no active organization to set
    // x-tenant-id/x-user-id from; requireTenantAdmin must not let that fall through to the
    // route's generic catch, which would answer 500 (review of #831).
    const req = new NextRequest("http://localhost/api/content/release", {
      method: "POST",
      headers: { "content-type": "application/json" }, // no x-tenant-id, no x-user-id
      body: JSON.stringify({ ring: "canary_0" }),
    });
    const res = await publish(req);
    expect(res.status).toBe(401);
    expect(db.contentRelease.create).not.toHaveBeenCalled();
  });

  it("halts the ring for an admin and audits it", async () => {
    db.contentRelease.findFirst.mockResolvedValue({ id: "r4", releaseVersion: 4, status: "active" });
    db.contentRelease.update.mockImplementation(async ({ where, data }) => ({ id: where.id, ...data }));
    const res = await halt(haltReq());
    expect(res.status).toBe(200);
    expect(db.contentRelease.update).toHaveBeenCalledWith({
      where: { id: "r4" },
      data: { status: "halted" },
    });
    expect(db.auditLog.create).toHaveBeenCalledOnce();
  });
});

describe("content/release marks a corrective release in its audit entry (#803)", () => {
  it("records restoresVersion and corrective:true when the publish names the release it restores", async () => {
    const manifest = manifestFor();
    store(manifest, GOOD_ARTIFACTS);
    await publish(post(publishBody(manifest, { restoresVersion: 2 })));
    const details = db.auditLog.create.mock.calls[0][0].data.details;
    expect(details.corrective).toBe(true);
    expect(details.restoresVersion).toBe(2);
  });

  it("records corrective:false for an ordinary release", async () => {
    const manifest = manifestFor();
    store(manifest, GOOD_ARTIFACTS);
    await publish(post(publishBody(manifest)));
    const details = db.auditLog.create.mock.calls[0][0].data.details;
    expect(details.corrective).toBe(false);
    expect(details.restoresVersion).toBeNull();
  });
});

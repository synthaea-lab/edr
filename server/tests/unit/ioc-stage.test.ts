import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { createHash } from "crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "fs";
import { join } from "path";

// Route logic runs against a mocked Prisma client, so these need no database.
const db = vi.hoisted(() => ({
  contentRelease: { findFirst: vi.fn(), create: vi.fn(), update: vi.fn() },
  auditLog: { create: vi.fn() },
  member: { findFirst: vi.fn() },
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));

import { POST as stageRoute } from "@/app/api/content/ioc-feed/route";
import { POST as publish } from "@/app/api/content/release/route";
import { buildIocStage, MAX_STAGE_BODY_BYTES } from "@/lib/ioc-stage";
import { iocEntryError } from "@/lib/content-publish";

const sha = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
const PLAIN = `# lab\nsha256:${HASH}\nip:203.0.113.9\ndomain:Evil.Example.Org.\n`;
const CSV = `indicator,type\n${HASH},sha256\n203.0.113.9,ip\nevil.example.org,domain\n`;
const FEED_TEXT = `domain:evil.example.org\nip:203.0.113.9\nsha256:${HASH}\n`;

describe("buildIocStage", () => {
  it("builds the feed and lists it as an ioc entry under its own hash", () => {
    const r = buildIocStage({ feed: "lab", source: { format: "plain", text: PLAIN } });
    if (!r.ok) throw new Error(r.error);
    expect(r.artifacts).toHaveLength(1);
    const [a] = r.artifacts;
    expect(a.bytes.toString()).toBe(FEED_TEXT);
    expect(a.entry).toEqual({ path: "ioc/lab.txt", type: "ioc", sha256: sha(FEED_TEXT), size: FEED_TEXT.length });
    expect(r.report.counts).toEqual({ sha256: 1, ip: 1, domain: 1, total: 3 });
  });

  it("gives the same bytes for a CSV source and a plain one with the same indicators", () => {
    const plain = buildIocStage({ feed: "lab", source: { format: "plain", text: PLAIN } });
    const csv = buildIocStage({
      feed: "lab",
      source: { format: "csv", csv: CSV, valueColumn: "indicator", typeColumn: "type" },
    });
    if (!plain.ok || !csv.ok) throw new Error("build failed");
    expect(csv.artifacts[0].entry).toEqual(plain.artifacts[0].entry);
  });

  it("adds ioc/VERSION only when a version is given", () => {
    const without = buildIocStage({ feed: "lab", source: { format: "plain", text: PLAIN } });
    const withV = buildIocStage({ feed: "lab", version: "2026-10-28", source: { format: "plain", text: PLAIN } });
    if (!without.ok || !withV.ok) throw new Error("build failed");
    expect(without.artifacts.map((a) => a.entry.path)).toEqual(["ioc/lab.txt"]);
    expect(withV.artifacts.map((a) => a.entry.path)).toEqual(["ioc/lab.txt", "ioc/VERSION"]);
    expect(withV.artifacts[1].bytes.toString()).toBe("2026-10-28\n");
  });

  it("only ever produces entries the publish check accepts", () => {
    const r = buildIocStage({
      feed: "lab",
      version: "v1",
      source: { format: "plain", text: `${PLAIN}ip:127.0.0.1\nnonsense\ndomain:co.uk\n` },
    });
    if (!r.ok) throw new Error(r.error);
    for (const a of r.artifacts) expect(iocEntryError(a.entry, a.bytes)).toBeNull();
    // The lines the device would skip are dropped and reported, not published.
    expect(r.report.rejectedTotal).toBe(3);
    expect(r.artifacts[0].bytes.toString()).toBe(FEED_TEXT);
  });

  it("refuses a source that leaves no indicator: an empty feed would unload the set", () => {
    const r = buildIocStage({ feed: "lab", source: { format: "plain", text: "<html>502 Bad Gateway</html>\n" } });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error).toContain("No indicator survived");
      expect(r.error).toContain("allowEmpty");
    }
  });

  it("publishes an empty feed when that is asked for", () => {
    const r = buildIocStage({ feed: "lab", allowEmpty: true, source: { format: "plain", text: "" } });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.artifacts[0].bytes.length).toBe(0);
  });

  it("says plainly what is wrong with the request rather than throwing", () => {
    const bad = (input: Parameters<typeof buildIocStage>[0]) => {
      const r = buildIocStage(input);
      return r.ok ? "ok" : r.error;
    };
    expect(bad({ feed: "../x", source: { format: "plain", text: PLAIN } })).toContain("invalid feed name");
    expect(bad({ feed: "lab", source: { format: "csv", csv: CSV, valueColumn: "nope" } })).toContain("not in the header");
    expect(bad({ feed: "lab", version: "two words", source: { format: "plain", text: PLAIN } })).toContain("invalid feed version");
  });
});

describe("POST /api/content/ioc-feed, then POST /api/content/release", () => {
  let originalCwd: string;
  let sandbox: string;
  const req = (url: string, body: unknown) =>
    new NextRequest(`http://localhost${url}`, {
      method: "POST",
      headers: { "x-tenant-id": "t1", "x-user-id": "u1", "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  const stageReq = (body: unknown) => req("/api/content/ioc-feed", body);
  const artifacts = () => join(sandbox, "storage", "artifacts");

  beforeEach(() => {
    vi.clearAllMocks();
    originalCwd = process.cwd();
    sandbox = join(originalCwd, ".test-sandbox-ioc-stage");
    mkdirSync(join(sandbox, "storage", "manifests"), { recursive: true });
    process.chdir(sandbox);
    db.auditLog.create.mockResolvedValue({});
    db.contentRelease.findFirst.mockResolvedValue(null);
    db.contentRelease.create.mockImplementation(async ({ data }) => ({ id: "r1", ...data }));
    db.member.findFirst.mockResolvedValue({ role: "owner" });
  });

  afterEach(() => {
    process.chdir(originalCwd);
    rmSync(sandbox, { recursive: true, force: true });
  });

  it("stages the feed and its version file under their hashes and answers the entries", async () => {
    const res = await stageRoute(stageReq({ feed: "lab", version: "v1", source: { format: "plain", text: PLAIN } }));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe("staged");
    expect(body.entries.map((e: { path: string }) => e.path)).toEqual(["ioc/lab.txt", "ioc/VERSION"]);
    for (const e of body.entries) {
      expect(sha(readFileSync(join(artifacts(), e.sha256)))).toBe(e.sha256);
    }
    expect(readFileSync(join(artifacts(), body.entries[0].sha256), "utf8")).toBe(FEED_TEXT);
    expect(readdirSync(artifacts()).filter((f) => f.endsWith(".tmp"))).toEqual([]);
    expect(db.auditLog.create).toHaveBeenCalledOnce();
    expect(db.auditLog.create.mock.calls[0][0].data.action).toBe("content.ioc_feed.stage");
  });

  it("is idempotent: staging the same source twice is the same file", async () => {
    const a = await (await stageRoute(stageReq({ feed: "lab", source: { format: "plain", text: PLAIN } }))).json();
    const b = await (await stageRoute(stageReq({ feed: "lab", source: { format: "plain", text: PLAIN } }))).json();
    expect(b.entries).toEqual(a.entries);
    expect(readdirSync(artifacts())).toEqual([a.entries[0].sha256]);
  });

  it("stages the same content from concurrent requests without one failing the other, and leaves no temporary file", async () => {
    const results = await Promise.all(Array.from({ length: 25 }, () => stageRoute(stageReq({ feed: "lab", source: { format: "plain", text: PLAIN } }))));
    expect(results.map((r) => r.status)).toEqual(Array(25).fill(200));
    const names = readdirSync(artifacts());
    expect(names.filter((f) => f.endsWith(".tmp"))).toEqual([]);
    expect(names).toHaveLength(1);
  });

  it("goes from a CSV source to an accepted release: the staged entries are what publish checks", async () => {
    const staged = await (
      await stageRoute(
        stageReq({
          feed: "lab",
          version: "2026-10-28",
          source: { format: "csv", csv: CSV, valueColumn: "indicator", typeColumn: "type" },
        })
      )
    ).json();

    // What the operator does next: put the entries in the unsigned manifest and sign it offline.
    const manifest = Buffer.from(
      JSON.stringify({
        schema_version: 1,
        release_version: 1,
        ring: "canary_0",
        released_at: "2026-10-28T09:30:00Z",
        entries: staged.entries,
        signature: "00",
      })
    );
    writeFileSync(join(sandbox, "storage", "manifests", "content-canary_0-v1.json"), manifest);

    const res = await publish(
      req("/api/content/release", {
        ring: "canary_0",
        manifestUrl: "storage://manifests/content-canary_0-v1.json",
        manifestSha256: sha(manifest),
      })
    );
    expect(res.status).toBe(200);
    expect(db.contentRelease.create).toHaveBeenCalledOnce();
  });

  it("refuses a source with no indicator (422) and writes nothing", async () => {
    const res = await stageRoute(stageReq({ feed: "lab", source: { format: "plain", text: "garbage\n" } }));
    expect(res.status).toBe(422);
    expect((await res.json()).error).toContain("No indicator survived");
    expect(existsSync(artifacts())).toBe(false);
    expect(db.auditLog.create).not.toHaveBeenCalled();
  });

  it("refuses a body over the cap (413) before parsing it, and one that is not JSON (400)", async () => {
    const big = JSON.stringify({ feed: "lab", source: { format: "plain", text: "x".repeat(MAX_STAGE_BODY_BYTES) } });
    const raw = (body: string) =>
      new NextRequest("http://localhost/api/content/ioc-feed", {
        method: "POST",
        headers: { "x-tenant-id": "t1", "x-user-id": "u1", "content-type": "application/json" },
        body,
      });
    const res = await stageRoute(raw(big));
    expect(res.status).toBe(413);
    const garbage = await stageRoute(raw("{nope"));
    expect(garbage.status).toBe(400);
    expect(existsSync(artifacts())).toBe(false);
  });

  it("accepts a feed over nginx's old 1 MiB default", async () => {
    const lines = Array.from({ length: 20_000 }, (_, i) => `ip:203.${(i >> 8) & 255}.${i & 255}.9`).join("\n");
    expect(lines.length).toBeGreaterThan(1024 * 1024 * 0.25);
    const text = `${lines}\n${"# padding ".repeat(110_000)}\n`;
    expect(text.length).toBeGreaterThan(1024 * 1024);
    const res = await stageRoute(stageReq({ feed: "lab", source: { format: "plain", text } }));
    expect(res.status).toBe(200);
  });

  it("refuses a malformed request (400) and a plain member (403) before reading anything", async () => {
    expect((await stageRoute(stageReq({ feed: "lab" }))).status).toBe(400);
    expect((await stageRoute(stageReq({ feed: "lab", source: { format: "xml", text: "" } }))).status).toBe(400);
    db.member.findFirst.mockResolvedValue({ role: "member" });
    const res = await stageRoute(stageReq({ feed: "lab", source: { format: "plain", text: PLAIN } }));
    expect(res.status).toBe(403);
    expect(existsSync(artifacts())).toBe(false);
  });
});

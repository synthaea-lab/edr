import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "fs";
import { join } from "path";

// Route logic runs against a mocked Prisma client, so these need no database.
const db = vi.hoisted(() => ({ agent: { findUnique: vi.fn() } }));
vi.mock("@/lib/prisma", () => ({ prisma: db }));

import { GET } from "@/app/api/release/key-rotation/route";
import { KeyRotationManifest } from "@/lib/key-rotation";

const SECRET = "test-proxy-secret";
const HEX = (c: string) => c.repeat(64);

/** The golden fixture the Rust side signs and verifies (`crates/updater`, #961). */
const GOLDEN = join(__dirname, "../../../crates/updater/tests/fixtures/key-rotation-golden.json");

function rotation(overrides: Record<string, unknown> = {}) {
  return {
    expires_at: 1760604800,
    issued_at: 1760000000,
    new_content_key: null,
    new_release_key: HEX("a"),
    reason: "scheduled",
    release_version: 9,
    retired_content_key: null,
    retired_release_key: HEX("b"),
    schema_version: 1,
    signature: "00",
    ...overrides,
  };
}

function agentHeaders(extra: Record<string, string> = {}) {
  return {
    "X-Proxy-Secret": SECRET,
    "X-Client-Cert-Verified": "SUCCESS",
    "X-Client-Cert-Subject": "CN=agent-1,O=synthaea",
    ...extra,
  };
}

const request = (headers: Record<string, string> = agentHeaders()) =>
  new NextRequest("http://localhost/api/release/key-rotation", { headers });

let originalCwd: string;
let sandbox: string;

function store(ring: string, bytes: Buffer | string) {
  writeFileSync(join(sandbox, "storage", "key-rotations", `${ring}.json`), bytes);
}

beforeEach(() => {
  vi.clearAllMocks();
  process.env.NGINX_PROXY_SECRET = SECRET;
  originalCwd = process.cwd();
  sandbox = join(originalCwd, ".test-sandbox-key-rotation");
  mkdirSync(join(sandbox, "storage", "key-rotations"), { recursive: true });
  process.chdir(sandbox);
  db.agent.findUnique.mockResolvedValue({ id: "a1", tenantId: "t1", ring: "canary_0" });
});

afterEach(() => {
  process.chdir(originalCwd);
  rmSync(sandbox, { recursive: true, force: true });
});

describe("agent authentication", () => {
  it("a request that did not come through the proxy is forbidden", async () => {
    expect((await GET(request(agentHeaders({ "X-Proxy-Secret": "wrong" })))).status).toBe(403);
  });

  it("without a verified client certificate the request is unauthorized", async () => {
    expect((await GET(request(agentHeaders({ "X-Client-Cert-Verified": "NONE" })))).status).toBe(401);
  });

  it("an unenrolled agent is forbidden, and is not told whether a rotation exists", async () => {
    store("canary_0", JSON.stringify(rotation()));
    db.agent.findUnique.mockResolvedValue(null);
    const res = await GET(request());
    expect(res.status).toBe(403);
    expect(await res.text()).not.toContain("retired_release_key");
  });
});

describe("GET /api/release/key-rotation", () => {
  it("is 404 when nothing is published", async () => {
    const res = await GET(request());
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "No key rotation pending" });
  });

  it("serves the stored manifest byte for byte, as JSON", async () => {
    // Pretty-printed with a trailing newline and a key order the server would not produce: any
    // re-serialisation would show.
    const bytes = Buffer.from(JSON.stringify(rotation(), null, 2) + "\n");
    store("canary_0", bytes);
    const res = await GET(request());
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("application/json");
    expect(Buffer.from(await res.arrayBuffer()).equals(bytes)).toBe(true);
  });

  it("serves the Rust golden fixture's manifest exactly as signed", async () => {
    const golden = JSON.parse(readFileSync(GOLDEN, "utf-8")).manifest;
    const bytes = Buffer.from(JSON.stringify(golden, null, 2));
    store("canary_0", bytes);
    const res = await GET(request());
    expect(res.status).toBe(200);
    expect(JSON.parse(await res.text())).toEqual(golden);
    expect(KeyRotationManifest.safeParse(golden).success).toBe(true);
  });

  it("serves the agent's own ring and no other", async () => {
    store("prod", JSON.stringify(rotation()));
    expect((await GET(request())).status).toBe(404); // the agent is canary_0
    db.agent.findUnique.mockResolvedValue({ id: "a2", tenantId: "t1", ring: "prod" });
    expect((await GET(request())).status).toBe(200);
  });

  it("does not sign, check or touch anything: an unverifiable signature is still served", async () => {
    // The agents verify; a server that judged signatures would need the recovery key.
    store("canary_0", JSON.stringify(rotation({ signature: "not-a-signature" })));
    expect((await GET(request())).status).toBe(200);
  });

  it.each([
    ["not JSON", "{ truncated"],
    ["an unknown field", JSON.stringify(rotation({ extra: 1 }))],
    ["a wrong schema_version", JSON.stringify(rotation({ schema_version: 2 }))],
    ["a key that is not canonical hex", JSON.stringify(rotation({ new_release_key: HEX("A") }))],
    ["half a pair", JSON.stringify(rotation({ retired_release_key: null }))],
    ["no key rotated", JSON.stringify(rotation({ new_release_key: null, retired_release_key: null }))],
    ["a window beyond 30 days", JSON.stringify(rotation({ expires_at: 1760000000 + 31 * 86400 }))],
    ["an empty reason", JSON.stringify(rotation({ reason: " " }))],
  ])("a stored file that is %s is a 502, not something an agent is handed", async (_n, body) => {
    store("canary_0", body);
    const res = await GET(request());
    expect(res.status).toBe(502);
    expect((await res.json()).error).toBeTruthy();
  });

  it("never reads outside the ring files: the path comes from the ring enum, not the request", async () => {
    // A ring that is not one of the four (a corrupted agent row) finds nothing rather than a path.
    db.agent.findUnique.mockResolvedValue({ id: "a3", tenantId: "t1", ring: "../../etc/passwd" });
    expect((await GET(request())).status).toBe(404);
  });
});

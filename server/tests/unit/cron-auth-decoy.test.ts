import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

/**
 * A rejected bearer that is a decoy must not make the 401 slower than any other bad bearer
 * (issue #81, review of #732): the alarm is recorded after the answer, so a client cannot
 * tell a decoy from a wrong guess by how long the response takes.
 */
const gate = vi.hoisted(() => {
  let release: () => void = () => {};
  const blocked = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { blocked, release: () => release() };
});

const second = vi.hoisted(() => {
  let release: () => void = () => {};
  const blocked = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { blocked, release: () => release() };
});

vi.mock("@/lib/prisma", () => ({
  prisma: {
    detection: {
      // The cooldown check: held, so every presentation that got past the lookup waits here.
      findFirst: vi.fn(async () => {
        await second.blocked;
        return null;
      }),
      create: vi.fn(async () => ({})),
    },
    decoyToken: {
      // The lookup for a decoy-shaped bearer: held until the test lets it go.
      findMany: vi.fn(async () => {
        await gate.blocked;
        return [];
      }),
    },
  },
}));

import { verifyCronRequest } from "@/lib/cron-auth";
import { flushDecoyReports, hashToken } from "@/lib/decoy";
import { prisma } from "@/lib/prisma";

const request = (auth: string) =>
  new NextRequest("http://localhost/api/cron/detect-silent-agents", {
    headers: { Authorization: auth },
  });

describe("verifyCronRequest and decoy lookups", () => {
  beforeEach(() => {
    process.env.CRON_SECRET = "test_cron_secret";
    vi.mocked(prisma.decoyToken.findMany).mockClear();
  });

  it("answers a decoy-shaped bearer while its lookup is still pending", async () => {
    const answered = await verifyCronRequest(request("Bearer syn_dk_0123456789abcdef0123456789abcdef"));
    expect(answered?.status).toBe(401);
    // The lookup was started, and it has not finished: the answer did not wait for it.
    expect(prisma.decoyToken.findMany).toHaveBeenCalledTimes(1);
    gate.release();
    await flushDecoyReports();
  });

  it("records one alarm for presentations that arrive together, deterministically", async () => {
    const decoy = {
      id: "decoy-1",
      tokenSha256: "a".repeat(64),
      agentId: "agent-1",
      agent: { id: "agent-1", tenantId: "tenant-1", hostname: "web-01", enrollmentId: "e-1" },
    };
    vi.mocked(prisma.decoyToken.findMany).mockImplementation((async () => [decoy]) as never);
    gate.release();
    for (let i = 0; i < 5; i++) {
      await verifyCronRequest(request("Bearer syn_dk_0123456789abcdef0123456789abcdef"));
    }
    // All five are past the lookup; the first is held in the cooldown check, the rest must
    // already have stopped. Let the first go and count the writes.
    await new Promise((resolve) => setTimeout(resolve, 20));
    second.release();
    await flushDecoyReports();
    expect(vi.mocked(prisma.detection.create)).toHaveBeenCalledTimes(1);
  });

  it("does not look anything up for a bearer without the decoy prefix", async () => {
    const answered = await verifyCronRequest(request("Bearer not-a-decoy"));
    expect(answered?.status).toBe(401);
    await flushDecoyReports();
    expect(prisma.decoyToken.findMany).not.toHaveBeenCalled();
  });

  it("hashes with the same function the registration uses", () => {
    expect(hashToken("syn_dk_x")).toMatch(/^[0-9a-f]{64}$/);
  });
});

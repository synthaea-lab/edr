import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import type { PrismaClient } from "@prisma/client";
import {
  MAX_ALARMS_PER_PRESENTATION,
  MAX_CONCURRENT_LOOKUPS,
  MAX_QUEUED_LOOKUPS,
  checkDecoyTable,
  checkShutdownOwnership,
  hashToken,
  metaHost,
  reportDecoyUse,
  droppedDecoyReports,
  flushDecoyReports,
  installDecoyShutdownFlush,
  resetDroppedDecoyReports,
  scheduleDecoyReport,
} from "@/lib/decoy";

/**
 * What bounds the decoy alarm on a server (issue #81, review of #732): a flood of decoy-shaped
 * bearers, a process told to stop with alarms pending, a database without the table.
 */
const request = () =>
  new NextRequest("http://localhost/api/cron/detect-silent-agents", {
    headers: { Authorization: "Bearer syn_dk_0123456789abcdef0123456789abcdef" },
  });
const bearer = "Bearer syn_dk_0123456789abcdef0123456789abcdef";

/** A database whose decoy lookup waits until `release()`; counts the lookups started. */
function slowDatabase() {
  let release: () => void = () => {};
  const blocked = new Promise<void>((resolve) => {
    release = resolve;
  });
  const findMany = vi.fn(async (_args: unknown) => {
    await blocked;
    return [];
  });
  const prisma = { decoyToken: { findMany } } as unknown as PrismaClient;
  return { prisma, findMany, release: () => release() };
}

describe("a flood of decoy-shaped bearers", () => {
  beforeEach(() => resetDroppedDecoyReports());

  it("starts no more lookups than the bound allows and queues the rest", async () => {
    const db = slowDatabase();
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    for (let i = 0; i < MAX_CONCURRENT_LOOKUPS + 9; i++) {
      scheduleDecoyReport(db.prisma, request(), bearer);
    }
    expect(db.findMany).toHaveBeenCalledTimes(MAX_CONCURRENT_LOOKUPS);
    expect(droppedDecoyReports(), "queued, not shed").toBe(0);
    db.release();
    await flushDecoyReports();
    expect(db.findMany, "the queued ones ran once slots freed").toHaveBeenCalledTimes(
      MAX_CONCURRENT_LOOKUPS + 9
    );
    // Room again once they finish.
    const again = slowDatabase();
    scheduleDecoyReport(again.prisma, request(), bearer);
    expect(again.findMany).toHaveBeenCalledTimes(1);
    again.release();
    await flushDecoyReports();
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it("sheds the oldest waiting bearer, never a real alarm that arrived after the junk", async () => {
    const db = slowDatabase();
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const junk = (i: number) => `Bearer syn_dk_junk${i}`;
    const real = "Bearer syn_dk_the_real_stolen_token";
    // 16 junk lookups hold every slot, then enough junk to fill the queue, then the real one.
    const flood = MAX_CONCURRENT_LOOKUPS + MAX_QUEUED_LOOKUPS;
    for (let i = 0; i < flood; i++) scheduleDecoyReport(db.prisma, request(), junk(i));
    scheduleDecoyReport(db.prisma, request(), real);
    expect(droppedDecoyReports(), "one shed to make room for the real one").toBe(1);
    db.release();
    await flushDecoyReports();
    const looked = db.findMany.mock.calls.map(
      (c) => (c[0] as { where: { tokenSha256: string } }).where.tokenSha256
    );
    expect(looked).toContain(hashToken("syn_dk_the_real_stolen_token"));
    expect(looked, "the oldest waiting junk is the one shed").not.toContain(
      hashToken(`syn_dk_junk${MAX_CONCURRENT_LOOKUPS}`)
    );
    expect(looked).toContain(hashToken(`syn_dk_junk${MAX_CONCURRENT_LOOKUPS + 1}`));
    spy.mockRestore();
  });

  it("counts what it sheds and says so at powers of two", async () => {
    const db = slowDatabase();
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const total = MAX_CONCURRENT_LOOKUPS + MAX_QUEUED_LOOKUPS + 9;
    for (let i = 0; i < total; i++) scheduleDecoyReport(db.prisma, request(), bearer);
    expect(droppedDecoyReports()).toBe(9);
    expect(spy).toHaveBeenCalledTimes(4); // 1, 2, 4, 8
    db.release();
    await flushDecoyReports();
    spy.mockRestore();
  });

  it("does nothing at all for a bearer that is not decoy-shaped", async () => {
    const db = slowDatabase();
    for (const header of ["Bearer nope", "Basic syn_dk_x", "Bearer ", null]) {
      scheduleDecoyReport(db.prisma, request(), header);
    }
    expect(db.findMany).not.toHaveBeenCalled();
    expect(droppedDecoyReports()).toBe(0);
  });

  it("asks for at most one alarm's worth of holders per presentation", async () => {
    const db = slowDatabase();
    scheduleDecoyReport(db.prisma, request(), bearer);
    expect(db.findMany.mock.calls[0][0]).toMatchObject({ take: MAX_ALARMS_PER_PRESENTATION });
    db.release();
    await flushDecoyReports();
  });
});

describe("shutdown", () => {
  function fakeProcess() {
    const handlers = new Map<string, () => void>();
    const exit = vi.fn();
    const proc = {
      once: (signal: string, handler: () => void) => {
        handlers.set(signal, handler);
        return proc;
      },
      exit,
    } as unknown as Pick<NodeJS.Process, "once" | "exit">;
    return { proc, handlers, exit };
  }

  it("lets the pending alarms finish before the process exits on SIGTERM", async () => {
    const db = slowDatabase();
    scheduleDecoyReport(db.prisma, request(), bearer);
    const { proc, handlers, exit } = fakeProcess();
    installDecoyShutdownFlush(proc);
    expect(Array.from(handlers.keys()).sort()).toEqual(["SIGINT", "SIGTERM"]);

    handlers.get("SIGTERM")!();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(exit, "an alarm is still being written").not.toHaveBeenCalled();
    db.release();
    await vi.waitFor(() => expect(exit).toHaveBeenCalledWith(0));
  });

  it("exits anyway after the wait when the database never answers", async () => {
    const db = slowDatabase();
    scheduleDecoyReport(db.prisma, request(), bearer);
    const { proc, handlers, exit } = fakeProcess();
    installDecoyShutdownFlush(proc, 30);
    handlers.get("SIGINT")!();
    await vi.waitFor(() => expect(exit).toHaveBeenCalledWith(0));
    db.release();
    await flushDecoyReports();
  });
});

describe("shutdown ownership", () => {
  it("is trusted when Next's own signal handler is switched off", () => {
    expect(checkShutdownOwnership({ NODE_ENV: "production", NEXT_MANUAL_SIG_HANDLE: "true" })).toBe(
      true
    );
  });

  it("warns in production when Next's own handler could exit before the flush", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(checkShutdownOwnership({ NODE_ENV: "production" })).toBe(false);
    expect(String(spy.mock.calls[0][0])).toContain("NEXT_MANUAL_SIG_HANDLE");
    spy.mockRestore();
  });

  it("stays quiet outside production", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(checkShutdownOwnership({ NODE_ENV: "development" })).toBe(true);
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it("installs its handlers once per process, so a second register() adds none", () => {
    const once = vi.fn();
    const proc = { once, exit: vi.fn() } as unknown as Pick<NodeJS.Process, "once" | "exit">;
    installDecoyShutdownFlush(proc);
    installDecoyShutdownFlush(proc);
    expect(once).toHaveBeenCalledTimes(2); // SIGTERM and SIGINT, not four
  });
});

describe("the planting host recorded in an alarm", () => {
  it("is cut and stripped of control characters, whatever the row holds", async () => {
    const created: { data: { meta: { planting_host: string } } }[] = [];
    const prisma = {
      decoyToken: {
        findMany: async () => [
          {
            id: "d1",
            tokenSha256: "a".repeat(64),
            agentId: "agent-1",
            agent: {
              id: "agent-1",
              tenantId: "t1",
              hostname: "dc01\n\u0007" + "x".repeat(400),
              enrollmentId: "e1",
            },
          },
        ],
      },
      detection: {
        findFirst: async () => null,
        create: async (args: (typeof created)[number]) => {
          created.push(args);
        },
      },
    } as unknown as PrismaClient;
    await reportDecoyUse(prisma, request(), bearer);
    const host = created[0].data.meta.planting_host;
    expect(host.length).toBeLessThanOrEqual(253);
    expect(host).not.toMatch(/[\x00-\x1f\x7f]/);
    expect(host.startsWith("dc01x")).toBe(true);
    expect(metaHost("web-01")).toBe("web-01");
  });
});

describe("the decoy_tokens table check", () => {
  const database = (query: () => Promise<unknown>) =>
    ({ $queryRaw: vi.fn(query) }) as unknown as PrismaClient;

  it("is true when the table exists and silent", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(await checkDecoyTable(database(async () => [{ present: true }]))).toBe(true);
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it("is false and says how to fix it when the table is missing", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(await checkDecoyTable(database(async () => [{ present: false }]))).toBe(false);
    expect(String(spy.mock.calls[0][0])).toContain("prisma db push");
    spy.mockRestore();
  });

  it("is false, never throws, when the database cannot be reached", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const down = database(async () => {
      throw new Error("connection refused");
    });
    expect(await checkDecoyTable(down)).toBe(false);
    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
  });
});

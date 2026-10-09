import { createHash } from "node:crypto";
import { NextRequest } from "next/server";
import { z } from "zod";
import type { PrismaClient } from "@prisma/client";
import { verifyProxyAuth } from "@/lib/tenant";

/**
 * Decoy credentials (issue #81). An agent plants fake tokens in canary files and registers
 * their SHA-256 here; a request that presents one of them is the alarm: someone read the
 * file on that host and is using what they found. The token itself never reaches the
 * control plane, so the control plane can recognise a decoy and cannot issue one.
 */

/** What an agent's decoy tokens start with. A bearer without it is never looked up. */
export const DECOY_TOKEN_PREFIX = "syn_dk_";

/** Most hashes one agent may have registered. Agents plant a few per canary directory. */
export const MAX_DECOY_TOKENS_PER_AGENT = 256;

/** A presented bearer longer than this is not a decoy and is not hashed. */
const MAX_TOKEN_LENGTH = 256;

/** One alarm per decoy per minute: a client retrying a rejected token is one event. */
export const DECOY_ALARM_COOLDOWN_MS = 60_000;

/**
 * Alarms one presentation may raise: one per agent holding the hash. A token is normally held
 * by one agent; many holders means copies or squatting, and the cap keeps one request from
 * writing an unbounded number of rows.
 */
export const MAX_ALARMS_PER_PRESENTATION = 32;

/** Decoy-shaped bearers looked up at once (flood bound). */
export const MAX_CONCURRENT_LOOKUPS = 16;

/**
 * Decoy-shaped bearers waiting for a lookup slot. Past this the *oldest* waiting one is shed
 * and counted, so a burst of junk `syn_dk_` bearers cannot starve a real alarm that arrived
 * after it: the real one is queued behind at most this many, and sheds only junk that is older.
 */
export const MAX_QUEUED_LOOKUPS = 1024;

/** Longest attacker-supplied header value kept in an alarm. */
const MAX_HEADER_ECHO = 200;

const SHA256_HEX = /^[0-9a-f]{64}$/;

export const DecoyRegistration = z.object({
  tokens: z.array(z.string().regex(SHA256_HEX)).max(MAX_DECOY_TOKENS_PER_AGENT),
});

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/**
 * The token of an `Authorization: Bearer <token>` header, or null. Lenient on purpose: the
 * scheme is case-insensitive in HTTP and whitespace around the token is not significant, so
 * `bearer syn_dk_...` must raise the alarm too. This only decides what is *looked up*; whether
 * the call is authorised is `checkCronAuth`'s stricter comparison, which still rejects it.
 */
export function bearerToken(header: string | null): string | null {
  if (header === null) return null;
  const match = /^Bearer\s+(\S+)\s*$/i.exec(header);
  return match ? match[1] : null;
}

/** Whether a presented token has the shape of a decoy (cheap, before any hashing or query). */
export function looksLikeDecoy(token: string | null): token is string {
  return token !== null && token.length <= MAX_TOKEN_LENGTH && token.startsWith(DECOY_TOKEN_PREFIX);
}

export interface RegistrationResult {
  /** Hashes this agent now holds, of the ones it sent. Always all of them. */
  registered: number;
}

export class DecoyLimitError extends Error {}

/**
 * Registers an agent's decoy hashes. Idempotent (the agent re-sends them) and bounded per agent.
 * A hash belongs to the agent that registered it, **and to any other that registers the same
 * one**: nothing is first-come-first-served, so an agent that has read another's decoy token
 * cannot take its hash, and a caller learns nothing about hashes it did not register. The
 * presentation of a token alarms for every agent that holds it (see [`reportDecoyUse`]).
 */
export async function registerDecoyTokens(
  prisma: PrismaClient,
  agent: { id: string; tenantId: string },
  hashes: string[]
): Promise<RegistrationResult> {
  const unique = Array.from(new Set(hashes));
  // One registration per agent at a time: the cap below is a count and then an insert, which
  // two concurrent requests would both pass. The lock is released when the transaction ends.
  return prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${agent.id}))`;
    const held = await tx.decoyToken.findMany({
      where: { agentId: agent.id },
      select: { tokenSha256: true },
    });
    const have = new Set(held.map((t) => t.tokenSha256));
    const fresh = unique.filter((h) => !have.has(h));
    if (held.length + fresh.length > MAX_DECOY_TOKENS_PER_AGENT) {
      throw new DecoyLimitError(
        `at most ${MAX_DECOY_TOKENS_PER_AGENT} decoy tokens per agent`
      );
    }

    if (fresh.length > 0) {
      await tx.decoyToken.createMany({
        data: fresh.map((tokenSha256) => ({
          tenantId: agent.tenantId,
          agentId: agent.id,
          tokenSha256,
        })),
        skipDuplicates: true,
      });
    }
    const kept = unique.filter((h) => have.has(h));
    if (kept.length > 0) {
      await tx.decoyToken.updateMany({
        where: { agentId: agent.id, tokenSha256: { in: kept } },
        data: { lastRegisteredAt: new Date() },
      });
    }
    return { registered: unique.length };
  });
}

const echo = (value: string | null) =>
  value === null ? null : value.slice(0, MAX_HEADER_ECHO);

/** What an alarm records as the source when the request did not provably pass the proxy. */
export const UNVERIFIED_ADDRESS = "unverified";

/**
 * The address to record for `req`: [`clientAddress`] when the request carries the proxy's
 * secret (so `X-Real-IP` is what nginx set from the connection), [`UNVERIFIED_ADDRESS`]
 * otherwise. A client that reaches the app port directly can write any header it likes.
 */
export function recordedAddress(req: NextRequest): string {
  try {
    verifyProxyAuth(req);
  } catch {
    return UNVERIFIED_ADDRESS;
  }
  return clientAddress(req.headers) ?? UNVERIFIED_ADDRESS;
}

/** A self-declared host name with control characters removed, cut to `max`. */
const printable = (value: string, max: number) =>
  // eslint-disable-next-line no-control-regex
  value.replace(/[\x00-\x1f\x7f]/g, "").slice(0, max);

/** A host name as it may appear in a title: bounded, printable. It is self-declared. */
const titleHost = (value: string) => printable(value, 80);

/**
 * The host name kept in `meta.planting_host`. Enrollment bounds it to 253 printable characters
 * today, but rows enrolled before that cap can hold anything, and the alarm must not copy it.
 */
export const metaHost = (value: string) => printable(value, 253);

/**
 * The address the request came from, as far as the proxy saw it. `X-Real-IP` is set by nginx
 * from the connection (and replaces any value the client sent); `X-Forwarded-For` is a list
 * a client can prefix, and nginx's `$proxy_add_x_forwarded_for` appends the connection's
 * address at the end, so its last hop is the trustworthy one and its first is whatever the
 * attacker wrote. Behind any other proxy, neither is evidence.
 */
export function clientAddress(headers: Headers): string | null {
  const real = headers.get("x-real-ip")?.trim();
  if (real) return echo(real);
  const forwarded = headers.get("x-forwarded-for");
  if (!forwarded) return null;
  const last = forwarded.split(",").pop()?.trim();
  return last ? echo(last) : null;
}

/**
 * If the request presents a decoy token, records a high-severity detection against the agent
 * that planted it, naming its host. Best effort and silent: it never throws and never changes
 * the response the caller sends, so a probing client learns nothing from it. One alarm per
 * decoy per [`DECOY_ALARM_COOLDOWN_MS`].
 */
export async function reportDecoyUse(
  prisma: PrismaClient,
  req: NextRequest,
  authorization: string | null,
  now: Date = new Date()
): Promise<void> {
  try {
    const token = bearerToken(authorization);
    if (!looksLikeDecoy(token)) return;
    // Every agent that registered this hash: the lookup has no tenant (the cron routes are
    // unauthenticated), and registering a hash someone else holds must not hide their alarm.
    const decoys = await prisma.decoyToken.findMany({
      where: { tokenSha256: hashToken(token) },
      take: MAX_ALARMS_PER_PRESENTATION,
      include: { agent: { select: { id: true, tenantId: true, hostname: true, enrollmentId: true } } },
    });
    if (decoys.length === 0) return;

    // Presentations that arrive together are one event: the first to get here records it, the
    // others stop, so the check below (a read, then a write) cannot let two through. Per
    // server process; behind several, the database check still bounds it to about one.
    const address = recordedAddress(req);
    for (const decoy of decoys) {
      const key = `${decoy.id}|${address}`;
      if (inFlight.has(key)) continue;
      inFlight.add(key);
      try {
        await recordIfNotRecent(prisma, req, decoy, address, now);
      } finally {
        inFlight.delete(key);
      }
    }
  } catch (error) {
    console.error("Decoy credential check failed:", error);
  }
}

/** Decoy-and-address pairs whose alarm is being recorded right now (see [`reportDecoyUse`]). */
const inFlight = new Set<string>();

/** Reports still running, so a test (or a shutdown hook) can wait for them. */
const pending = new Set<Promise<void>>();

/**
 * [`reportDecoyUse`] started after the caller has its answer: the response of a rejected
 * request must not take longer when the bearer is a decoy (three queries) than when it is
 * not (none), or a client can tell them apart by timing. The work is started, not awaited;
 * `reportDecoyUse` never throws, so nothing is left unhandled. On a long-running Node server
 * (`next start`) the promise lives on; on a platform that freezes the process after the
 * response it may be cut off, which is why the ADR names the deployment it assumes.
 */
export function scheduleDecoyReport(
  prisma: PrismaClient,
  req: NextRequest,
  authorization: string | null
): void {
  // Anything that is not decoy-shaped costs nothing: no promise, no query.
  if (!looksLikeDecoy(bearerToken(authorization))) return;
  const job = { prisma, req, authorization };
  if (pending.size < MAX_CONCURRENT_LOOKUPS) {
    start(job);
    return;
  }
  // A flood of decoy-shaped bearers must not put one lookup each on the database pool, nor
  // shed a real alarm just because 16 junk ones are in flight: the overflow waits in a bounded
  // queue and, when that is full, the oldest waiting one is shed and counted (said at powers
  // of two). nginx limits the rate per address; this bounds what one process holds.
  waiting.push(job);
  if (waiting.length > MAX_QUEUED_LOOKUPS) {
    waiting.shift();
    dropped += 1;
    if ((dropped & (dropped - 1)) === 0) {
      console.error(`Decoy reports dropped under load: ${dropped} so far`);
    }
  }
}

interface ReportJob {
  prisma: PrismaClient;
  req: NextRequest;
  authorization: string | null;
}

/** Lookups waiting for one of the [`MAX_CONCURRENT_LOOKUPS`] slots, oldest first. */
const waiting: ReportJob[] = [];

function start(job: ReportJob): void {
  const work = reportDecoyUse(job.prisma, job.req, job.authorization).finally(() => {
    pending.delete(work);
    const next = waiting.shift();
    if (next) start(next);
  });
  pending.add(work);
}

let dropped = 0;

/** Reports shed because [`MAX_QUEUED_LOOKUPS`] were already waiting. */
export function droppedDecoyReports(): number {
  return dropped;
}

/** Test seam: forget the drop count and the waiting queue. */
export function resetDroppedDecoyReports(): void {
  dropped = 0;
  waiting.length = 0;
}

const flushInstalledOn = new WeakSet<object>();

/**
 * Next installs its own SIGINT/SIGTERM handler (`server.close()` then `process.exit(0)`) unless
 * `NEXT_MANUAL_SIG_HANDLE` is set (14.2.35, `start-server.js`). Both handlers run, and Next's
 * exits as soon as the HTTP server has closed, which can be before [`installDecoyShutdownFlush`]
 * has written the pending alarms. So in production the flag must be set (the Dockerfile does);
 * this says so at start when it is not. Returns whether the flush can be trusted.
 */
export function checkShutdownOwnership(env: NodeJS.ProcessEnv = process.env): boolean {
  if (env.NEXT_MANUAL_SIG_HANDLE || env.NODE_ENV !== "production") return true;
  console.error(
    "NEXT_MANUAL_SIG_HANDLE is not set: Next's own SIGTERM handler may exit before pending " +
      "decoy alarms are written. Set NEXT_MANUAL_SIG_HANDLE=true."
  );
  return false;
}

/**
 * Lets the pending alarms finish when the process is asked to stop: a SIGTERM between the
 * response and the write would otherwise lose the alarm. Waits at most `waitMs`, then exits
 * anyway so a stuck database cannot keep the process alive. With `NEXT_MANUAL_SIG_HANDLE`
 * set this is the only handler, so it exits itself: see [`checkShutdownOwnership`].
 */
export function installDecoyShutdownFlush(
  proc: Pick<NodeJS.Process, "once" | "exit">,
  waitMs = 5_000
): void {
  // `register()` runs again on a dev hot reload; one set of handlers per process is enough.
  if (flushInstalledOn.has(proc)) return;
  flushInstalledOn.add(proc);
  for (const signal of ["SIGTERM", "SIGINT"] as const) {
    proc.once(signal, () => {
      const limit = new Promise<void>((resolve) => setTimeout(resolve, waitMs).unref?.());
      void Promise.race([flushDecoyReports(), limit]).finally(() => proc.exit(0));
    });
  }
}

/**
 * Whether the `decoy_tokens` table exists. Without it a registration answers 500 and an alarm
 * is logged and dropped (the schema ships with `db push`, no tracked migration creates it), so
 * the server says so at start instead of when a decoy is first used. Never throws.
 */
export async function checkDecoyTable(prisma: PrismaClient): Promise<boolean> {
  try {
    const rows = await prisma.$queryRaw<{ present: boolean }[]>`
      SELECT to_regclass('public.decoy_tokens') IS NOT NULL AS present`;
    if (rows[0]?.present === true) return true;
    console.error(
      "decoy_tokens table is missing: decoy registration will fail and decoy alarms will be " +
        "lost. Create the schema (`prisma db push`)."
    );
  } catch (error) {
    console.error("Could not check the decoy_tokens table:", error);
  }
  return false;
}

/** Resolves when every scheduled report has finished. For tests and graceful shutdown. */
export async function flushDecoyReports(): Promise<void> {
  while (pending.size > 0 || waiting.length > 0) {
    await Promise.all(Array.from(pending));
  }
}

async function recordIfNotRecent(
  prisma: PrismaClient,
  req: NextRequest,
  decoy: {
    id: string;
    tokenSha256: string;
    agentId: string;
    agent: { id: string; tenantId: string; hostname: string | null; enrollmentId: string };
  },
  address: string,
  now: Date
): Promise<void> {
  const recent = await prisma.detection.findFirst({
    where: {
      agentId: decoy.agentId,
      technique: "T1552.001",
      timestamp: { gte: new Date(now.getTime() - DECOY_ALARM_COOLDOWN_MS) },
      // The same decoy from another address within the minute is a second source, not a retry.
      AND: [
        { meta: { path: ["decoy_id"], equals: decoy.id } },
        { meta: { path: ["client_address"], equals: address } },
      ],
    },
    select: { id: true },
  });
  if (recent) return;

  const host = decoy.agent.hostname ?? decoy.agent.enrollmentId;
  await prisma.detection.create({
    data: {
      tenantId: decoy.agent.tenantId,
      agentId: decoy.agent.id,
      timestamp: now,
      technique: "T1552.001",
      severity: "high",
      event: {
        type: "decoy_credential_used",
        // The agent id leads: it is the identifier the server issued. The host name is what the
        // agent declared at enrollment and is shown for the analyst, not as evidence.
        title: `Decoy credential of agent ${decoy.agent.id} (host ${titleHost(host)}) was presented to the control plane`,
        decoy_token_sha256: decoy.tokenSha256.slice(0, 16),
        route: req.nextUrl.pathname,
        method: req.method,
      },
      meta: {
        source: "deception",
        decoy_id: decoy.id,
        planting_host: metaHost(host),
        planting_agent_id: decoy.agent.id,
        client_address: address,
        user_agent: echo(req.headers.get("user-agent")),
      },
    },
  });
}

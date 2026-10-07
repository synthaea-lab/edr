import { createHash } from "node:crypto";
import { NextRequest } from "next/server";
import { z } from "zod";
import type { PrismaClient } from "@prisma/client";

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

/** Longest attacker-supplied header value kept in an alarm. */
const MAX_HEADER_ECHO = 200;

const SHA256_HEX = /^[0-9a-f]{64}$/;

export const DecoyRegistration = z.object({
  tokens: z.array(z.string().regex(SHA256_HEX)).max(MAX_DECOY_TOKENS_PER_AGENT),
});

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/** The token of an `Authorization: Bearer <token>` header, or null. */
export function bearerToken(header: string | null): string | null {
  if (header === null) return null;
  const match = /^Bearer (\S+)$/.exec(header);
  return match ? match[1] : null;
}

/** Whether a presented token has the shape of a decoy (cheap, before any hashing or query). */
export function looksLikeDecoy(token: string | null): token is string {
  return token !== null && token.length <= MAX_TOKEN_LENGTH && token.startsWith(DECOY_TOKEN_PREFIX);
}

export interface RegistrationResult {
  registered: number;
  /** Hashes already held by another agent: not re-assigned. */
  conflicts: number;
}

export class DecoyLimitError extends Error {}

/**
 * Registers an agent's decoy hashes. Idempotent (the agent re-sends them), bounded per agent,
 * and a hash another agent registered first is a conflict, not a transfer.
 */
export async function registerDecoyTokens(
  prisma: PrismaClient,
  agent: { id: string; tenantId: string },
  hashes: string[]
): Promise<RegistrationResult> {
  const unique = Array.from(new Set(hashes));
  const existing = await prisma.decoyToken.findMany({
    where: { tokenSha256: { in: unique } },
    select: { tokenSha256: true, agentId: true },
  });
  const owner = new Map(existing.map((t) => [t.tokenSha256, t.agentId]));
  const mine = unique.filter((h) => !owner.has(h) || owner.get(h) === agent.id);
  const fresh = mine.filter((h) => !owner.has(h));

  const held = await prisma.decoyToken.count({ where: { agentId: agent.id } });
  if (held + fresh.length > MAX_DECOY_TOKENS_PER_AGENT) {
    throw new DecoyLimitError(
      `at most ${MAX_DECOY_TOKENS_PER_AGENT} decoy tokens per agent`
    );
  }

  const now = new Date();
  if (fresh.length > 0) {
    await prisma.decoyToken.createMany({
      data: fresh.map((tokenSha256) => ({
        tenantId: agent.tenantId,
        agentId: agent.id,
        tokenSha256,
      })),
      skipDuplicates: true,
    });
  }
  const known = mine.filter((h) => owner.get(h) === agent.id);
  if (known.length > 0) {
    await prisma.decoyToken.updateMany({
      where: { agentId: agent.id, tokenSha256: { in: known } },
      data: { lastRegisteredAt: now },
    });
  }
  return { registered: mine.length, conflicts: unique.length - mine.length };
}

const echo = (value: string | null) =>
  value === null ? null : value.slice(0, MAX_HEADER_ECHO);

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
    const decoy = await prisma.decoyToken.findUnique({
      where: { tokenSha256: hashToken(token) },
      include: { agent: { select: { id: true, tenantId: true, hostname: true, enrollmentId: true } } },
    });
    if (!decoy) return;

    const recent = await prisma.detection.findFirst({
      where: {
        agentId: decoy.agentId,
        technique: "T1552.001",
        timestamp: { gte: new Date(now.getTime() - DECOY_ALARM_COOLDOWN_MS) },
        meta: { path: ["decoy_id"], equals: decoy.id },
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
          title: `Decoy credential planted on ${host} was presented to the control plane`,
          decoy_token_sha256: decoy.tokenSha256.slice(0, 16),
          route: req.nextUrl.pathname,
          method: req.method,
        },
        meta: {
          source: "deception",
          decoy_id: decoy.id,
          planting_host: host,
          planting_agent_id: decoy.agent.id,
          client_address: echo(req.headers.get("x-forwarded-for") ?? req.headers.get("x-real-ip")),
          user_agent: echo(req.headers.get("user-agent")),
        },
      },
    });
  } catch (error) {
    console.error("Decoy credential check failed:", error);
  }
}

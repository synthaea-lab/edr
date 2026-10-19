import { randomBytes } from "node:crypto";
import type { NotificationChannel } from "@prisma/client";
import { EVENTS } from "./outbox";

/** A new signing secret, shown to the admin once. */
export function newSigningSecret(): string {
  return `whsec_${randomBytes(24).toString("hex")}`;
}

export function isEvent(e: string): boolean {
  return (EVENTS as readonly string[]).includes(e);
}

/**
 * What a signed-in member may see of a channel (ADR-0036 point 8): that it exists and
 * whether it works. The URL is shown as its host only; the secret and its ciphertext never.
 */
export function channelView(c: NotificationChannel) {
  let host = "";
  try {
    host = new URL(c.url).host;
  } catch {
    host = "";
  }
  return {
    id: c.id,
    kind: c.kind,
    host,
    status: c.status,
    events: c.events,
    huntIds: c.huntIds,
    cooldownSeconds: c.cooldownSeconds,
    lastStatusCode: c.lastStatusCode,
    lastError: c.lastError,
    lastDeliveredAt: c.lastDeliveredAt,
    createdAt: c.createdAt,
  };
}

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
 * whether it works. The URL is shown as its host only (it is stored sealed, its path is often a
 * credential); the secret and the ciphertexts never.
 */
export function channelView(c: NotificationChannel) {
  return {
    id: c.id,
    kind: c.kind,
    host: c.host,
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

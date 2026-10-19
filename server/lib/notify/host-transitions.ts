import type { PrismaClient } from "@prisma/client";
import { fleetStatus, sensorsOf, lostRecently, type FleetStatus } from "@/lib/fleet-health";
import { enqueue, type NotifyEvent } from "./outbox";

/**
 * Host state transitions for the notification outbox (ADR-0036 point 2, slice 2, #863).
 *
 * `degraded` is computed on read and expires with a clock (the loss window), so no beacon
 * marks the end of a loss: the transition is found by comparing what `fleetStatus` says now
 * with `Agent.notifiedStatus`, what the server last told someone. The delivery cron runs this
 * every tick. `fleetStatus` itself is not changed by any of it.
 */

export type NotifyState = "healthy" | "degraded" | "silent";

/** `no_beacon` is an agent that is alive but sends no health: nothing to tell anyone. */
export function notifyState(status: FleetStatus): NotifyState {
  return status === "degraded" || status === "silent" ? status : "healthy";
}

export type Transition =
  | { kind: "event"; event: Extract<NotifyEvent, "host.degraded" | "host.silent" | "host.recovered"> }
  | { kind: "baseline" }
  | { kind: "none" };

/**
 * What a change of state means. The first evaluation of an agent (`notified` null) records
 * where it is without a message, so registering a channel does not announce every host that is
 * already degraded: the first message is its next change.
 */
export function transitionFor(notified: NotifyState | null, current: NotifyState): Transition {
  if (notified === null) return { kind: "baseline" };
  if (notified === current) return { kind: "none" };
  if (current === "degraded") return { kind: "event", event: "host.degraded" };
  if (current === "silent") return { kind: "event", event: "host.silent" };
  return { kind: "event", event: "host.recovered" };
}

const HOST_EVENTS = ["host.degraded", "host.silent", "host.recovered"];

function isNotifyState(v: string | null): v is NotifyState {
  return v === "healthy" || v === "degraded" || v === "silent";
}

function baseUrl(env: Record<string, string | undefined>): string {
  return (env.NOTIFY_CONSOLE_URL ?? env.NEXTAUTH_URL ?? "").replace(/\/$/, "");
}

/**
 * Looks at every host of every tenant that has a channel subscribed to a host event and
 * enqueues one message per change. `notifiedStatus` advances only when a row was written, so a
 * message held back by the cooldown is tried again on the next tick and is dropped for free if
 * the host went back to where it was meanwhile.
 */
export async function evaluateHostTransitions(
  db: PrismaClient,
  now = new Date(),
  env: Record<string, string | undefined> = process.env
): Promise<{ evaluated: number; baselined: number; enqueued: number }> {
  const tally = { evaluated: 0, baselined: 0, enqueued: 0 };

  const subscribed = await db.notificationChannel.findMany({
    where: { kind: "webhook", status: { in: ["active", "paused"] }, events: { hasSome: HOST_EVENTS } },
    select: { tenantId: true },
    distinct: ["tenantId"],
  });
  if (subscribed.length === 0) return tally;

  const agents = await db.agent.findMany({
    where: { tenantId: { in: subscribed.map((c) => c.tenantId) } },
    include: { health: true },
  });
  const base = baseUrl(env);

  for (const agent of agents) {
    tally.evaluated++;
    const health = agent.health
      ? { sensors: sensorsOf(agent.health.sensors), lossObservedAt: agent.health.lossObservedAt }
      : null;
    const status = fleetStatus(agent, health, now);
    const current = notifyState(status);
    const notified = isNotifyState(agent.notifiedStatus) ? agent.notifiedStatus : null;
    const t = transitionFor(notified, current);
    if (t.kind === "none") continue;
    if (t.kind === "baseline") {
      await db.agent.update({ where: { id: agent.id }, data: { notifiedStatus: current } });
      tally.baselined++;
      continue;
    }

    const silentSensors = health ? health.sensors.filter((s) => s.silent).map((s) => s.name) : [];
    let caseLink: string | null = null;
    if (t.event === "host.silent") {
      // The silent-agent cron's case, when it has opened one by now.
      const c = await db.case.findFirst({
        where: { tenantId: agent.tenantId, status: "open", title: { contains: agent.id } },
        select: { id: true },
      });
      caseLink = c ? `${base}/console/cases/${c.id}` : null;
    }
    const written = await enqueue(
      db,
      {
        tenantId: agent.tenantId,
        event: t.event,
        subject: agent.id,
        occurredAt: now,
        data: {
          subject: { id: agent.id, hostname: agent.hostname ?? null, console_url: `${base}/console/ops` },
          change: {
            from: notified,
            to: current,
            ...(t.event === "host.degraded"
              ? { silent_sensors: silentSensors, telemetry_loss: lostRecently(health?.lossObservedAt, now) }
              : {}),
            ...(t.event === "host.silent" ? { last_seen: agent.lastSeen.toISOString(), case_url: caseLink } : {}),
          },
        },
      },
      now
    );
    if (written > 0) {
      await db.agent.update({ where: { id: agent.id }, data: { notifiedStatus: current } });
      tally.enqueued += written;
    }
  }
  return tally;
}

import type { PrismaClient } from "@prisma/client";
import { fleetStatus, sensorsOf, lostRecently, type FleetStatus } from "@/lib/fleet-health";
import { enqueueForChannel, type NotifyEvent } from "./outbox";
import { consoleUrl } from "./urls";

/**
 * Host state transitions for the notification outbox (ADR-0036 point 2, slice 2, #863).
 *
 * `degraded` is computed on read and expires with a clock (the loss window), so no beacon
 * marks the end of a loss: the transition is found by comparing what `fleetStatus` says now
 * with `NotificationState`, what **each channel** was last told about the host (per channel, not
 * per agent: a channel in cooldown must not make another channel miss the transition). The
 * delivery cron runs this every tick. `fleetStatus` itself is not changed by any of it.
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

function isNotifyState(v: string | null | undefined): v is NotifyState {
  return v === "healthy" || v === "degraded" || v === "silent";
}

/**
 * Looks at every host of every tenant that has a channel subscribed to a host event and, for
 * each such channel, enqueues one message per change from what that channel was told.
 *
 * - A channel's state for a host advances only when a row was enqueued for it, so a message held
 *   back by the cooldown is tried again on the next tick and is dropped for free if the host
 *   went back to where the channel last heard it was.
 * - A channel that does not subscribe to the event a change maps to has nothing to be told; its
 *   state advances without a row, otherwise it would never hear the next change.
 * - The first time a channel sees a host it records the state and sends nothing.
 */
export async function evaluateHostTransitions(
  db: PrismaClient,
  now = new Date(),
  env: Record<string, string | undefined> = process.env
): Promise<{ evaluated: number; baselined: number; enqueued: number }> {
  const tally = { evaluated: 0, baselined: 0, enqueued: 0 };

  const channels = await db.notificationChannel.findMany({
    where: { kind: "webhook", status: { in: ["active", "paused"] }, events: { hasSome: HOST_EVENTS } },
  });
  if (channels.length === 0) return tally;

  const byTenant = new Map<string, typeof channels>();
  for (const c of channels) byTenant.set(c.tenantId, [...(byTenant.get(c.tenantId) ?? []), c]);

  for (const [tenantId, tenantChannels] of Array.from(byTenant.entries())) {
    const agents = await db.agent.findMany({ where: { tenantId }, include: { health: true } });
    const states = await db.notificationState.findMany({
      where: { channelId: { in: tenantChannels.map((c) => c.id) } },
    });
    const told = new Map(states.map((s) => [`${s.channelId}|${s.subject}`, s.state]));

    for (const agent of agents) {
      tally.evaluated++;
      const health = agent.health
        ? { sensors: sensorsOf(agent.health.sensors), lossObservedAt: agent.health.lossObservedAt }
        : null;
      const current = notifyState(fleetStatus(agent, health, now));
      const silentSensors = health ? health.sensors.filter((s) => s.silent).map((s) => s.name) : [];
      let caseLink: string | null | undefined; // looked up once per host, only if a silent message is built

      for (const channel of tenantChannels) {
        const key = `${channel.id}|${agent.id}`;
        const was = told.get(key);
        const notified = isNotifyState(was) ? was : null;
        const t = transitionFor(notified, current);
        if (t.kind === "none") continue;

        const advance = () =>
          db.notificationState.upsert({
            where: { channelId_subject: { channelId: channel.id, subject: agent.id } },
            create: { channelId: channel.id, subject: agent.id, state: current },
            update: { state: current },
          });

        if (t.kind === "baseline") {
          await advance();
          tally.baselined++;
          continue;
        }
        if (!channel.events.includes(t.event)) {
          await advance(); // nothing to tell this channel about this change
          continue;
        }

        if (t.event === "host.silent" && caseLink === undefined) {
          // The silent-agent cron's case, when it has opened one by now. The cron titles it by the
          // host name when there is one (`Agent Silent: web-01`), so the title cannot find it by
          // agent id; its description always ends with the enrollment id, which is unique.
          const c = await db.case.findFirst({
            where: {
              tenantId,
              status: "open",
              title: { startsWith: "Agent Silent:" },
              description: { contains: `Enrollment ID: ${agent.enrollmentId}` },
            },
            select: { id: true },
          });
          caseLink = c ? consoleUrl(env, `/console/cases/${c.id}`) : null;
        }
        const written = await enqueueForChannel(
          db,
          channel,
          {
            tenantId,
            event: t.event,
            subject: agent.id,
            occurredAt: now,
            data: {
              subject: { id: agent.id, hostname: agent.hostname ?? null, console_url: consoleUrl(env, "/console/ops") },
              change: {
                from: notified,
                to: current,
                ...(t.event === "host.degraded"
                  ? { silent_sensors: silentSensors, telemetry_loss: lostRecently(health?.lossObservedAt, now) }
                  : {}),
                ...(t.event === "host.silent" ? { last_seen: agent.lastSeen.toISOString(), case_url: caseLink ?? null } : {}),
              },
            },
          },
          now
        );
        if (written > 0) {
          await advance();
          tally.enqueued += written;
        }
      }
    }
  }
  return tally;
}

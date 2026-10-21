import { NextRequest, NextResponse } from "next/server";
import { randomUUID } from "crypto";
import { prisma } from "@/lib/prisma";
import { authenticateAgent, type AuthenticatedAgent } from "@/lib/agent-auth";
import { acceptedOutcome, recordIngest, refusedOutcome, lagOf } from "@/lib/ingest-stats";
import { aggregateSightings, extractObservations, recordSightings } from "@/lib/prevalence";

/** Body ceiling, checked on the bytes actually read (not the Content-Length header). */
const MAX_BODY_BYTES = 4 * 1024 * 1024;
/** The agent sends batches of 100 (`transport::DEFAULT_BATCH_SIZE`); this is headroom, not a target. */
const MAX_EVENTS_PER_BATCH = 1000;
/** One day: an agent clock further ahead than this is treated as unset rather than believed. */
const MAX_CLOCK_SKEW_MS = 24 * 60 * 60 * 1000;

/**
 * When an event happened, from its `meta.timestamp_ns`. A missing, non-numeric,
 * non-positive or far-future stamp becomes `now`: an enrolled agent with a bad
 * clock must not be able to backdate or postdate a sighting and so bend
 * "first seen on the fleet".
 */
function eventTime(event: Record<string, unknown>, now: Date): Date {
  const meta = event.meta;
  const ns =
    typeof meta === "object" && meta !== null
      ? (meta as Record<string, unknown>).timestamp_ns
      : undefined;
  if (typeof ns !== "number" || !Number.isFinite(ns) || ns <= 0) return now;
  const at = new Date(Math.floor(ns / 1_000_000));
  return at.getTime() > now.getTime() + MAX_CLOCK_SKEW_MS ? now : at;
}

/**
 * POST /api/ingest/events (also served at /api/v1/ingest/events, the path
 * `transport::DEFAULT_INGEST_ENDPOINT` uses)
 * Agent endpoint: a batch of `schema::Event` from the store-and-forward spool.
 *
 * Authentication: nginx proxy secret + mTLS + enrolled agent (`authenticateAgent`).
 * Body: `{ agent_id: string | null, events: Event[] }` (`agent_id` is never
 * trusted; identity is the certificate).
 * Response: `{ accepted, batch_id }`, the shape `transport::UploadResponse` reads.
 *
 * INTERIM: events are counted into fleet prevalence (issue #76) and nothing
 * else. Raw telemetry belongs in the lake (`server/datalake`), which does not
 * exist yet, so an accepted event is not retained. The agent drops a spooled
 * segment once it gets a 2xx.
 */
export async function POST(req: NextRequest) {
  // Known once the certificate is checked: a refusal or failure after that is counted for it (#899).
  let known: AuthenticatedAgent | null = null;
  const refuse = async (error: string, status: number, received = 0) => {
    if (known) await recordIngest(prisma, known.tenantId, known.id, "events", refusedOutcome(status, received), new Date());
    return NextResponse.json({ error }, { status });
  };
  try {
    const authenticated = await authenticateAgent(req);
    if ("response" in authenticated) return authenticated.response;
    const { agent } = authenticated;
    known = agent;

    const raw = await req.text();
    if (Buffer.byteLength(raw) > MAX_BODY_BYTES) {
      return refuse("Payload too large", 413);
    }

    let body: unknown;
    try {
      body = JSON.parse(raw);
    } catch {
      return refuse("Body is not valid JSON", 400);
    }
    const events = (body as { events?: unknown } | null)?.events;
    if (!Array.isArray(events)) {
      return refuse("Missing 'events' array", 400);
    }
    if (events.length > MAX_EVENTS_PER_BATCH) {
      return refuse(`At most ${MAX_EVENTS_PER_BATCH} events per batch`, 413, events.length);
    }

    // A malformed entry is skipped, not a reason to reject the batch: one bad
    // event would otherwise make the agent retry the same segment until it
    // gives up and discards the good ones with it.
    const now = new Date();
    const items: { at: Date; observations: ReturnType<typeof extractObservations> }[] = [];
    let accepted = 0;
    for (const event of events) {
      if (typeof event !== "object" || event === null || typeof (event as { type?: unknown }).type !== "string") {
        continue;
      }
      accepted += 1;
      const e = event as Record<string, unknown>;
      items.push({ at: eventTime(e, now), observations: extractObservations(e) });
    }

    // Best effort, like the detection route: the agent must not retry a batch
    // over a counter failure.
    try {
      await recordSightings(prisma, agent.tenantId, agent.id, aggregateSightings(items));
    } catch (error) {
      console.error("Prevalence update failed:", error);
    }

    await prisma.agent.update({ where: { id: agent.id }, data: { lastSeen: now } });

    // Best effort too (`recordIngest` never throws). Counted last so that a 500 above is
    // counted as a refusal, not as an accepted batch.
    await recordIngest(
      prisma,
      agent.tenantId,
      agent.id,
      "events",
      acceptedOutcome(events.length, events.length - accepted, lagOf(items.map((i) => i.at), now)),
      now
    );

    return NextResponse.json({ accepted, batch_id: randomUUID() });
  } catch (error) {
    console.error("Event ingest error:", error);
    return refuse("Internal server error", 500);
  }
}

import { NextRequest, NextResponse } from "next/server";
import { randomUUID } from "crypto";
import { prisma } from "@/lib/prisma";
import { authenticateAgent, type AuthenticatedAgent } from "@/lib/agent-auth";
import { acceptedOutcome, recordIngest, refusedOutcome, lagOf } from "@/lib/ingest-stats";
import { aggregateSightings, extractObservations, recordSightings } from "@/lib/prevalence";
import { eventTime } from "@/lib/event-time";
import { lakeEnabled } from "@/lib/lake-store";
import { enqueueLakeBatch, eventSources } from "@/lib/lake-writer";

/** Body ceiling, checked on the bytes actually read (not the Content-Length header). */
const MAX_BODY_BYTES = 4 * 1024 * 1024;
/** The agent sends batches of 100 (`transport::DEFAULT_BATCH_SIZE`); this is headroom, not a target. */
const MAX_EVENTS_PER_BATCH = 1000;

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
 * Events are counted into fleet prevalence (issue #76). With `LAKE_DIR` set they are also queued
 * for the telemetry lake (issue #77, ADR-0041, `lib/lake-writer.ts`); without it an accepted event
 * is not retained. The agent drops a spooled segment once it gets a 2xx, which with the lake on
 * means "durably queued", not "written to the lake".
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
    const lakeEvents: unknown[] = [];
    // The lake keeps each event's text as received; the parsed value rounds integers above 2^53.
    const sources = eventSources(raw);
    let accepted = 0;
    for (let index = 0; index < events.length; index += 1) {
      const event: unknown = events[index];
      if (typeof event !== "object" || event === null || typeof (event as { type?: unknown }).type !== "string") {
        continue;
      }
      accepted += 1;
      lakeEvents.push(sources !== null && sources.length === events.length ? sources[index] : event);
      const e = event as Record<string, unknown>;
      items.push({ at: eventTime(e, now), observations: extractObservations(e) });
    }

    // Not best effort: a batch that cannot be queued answers 5xx so the agent keeps its segment and
    // retries, instead of dropping events the lake was meant to keep. Off unless LAKE_DIR is set.
    if (lakeEnabled()) {
      await enqueueLakeBatch(prisma, { tenantId: agent.tenantId, agentId: agent.id, events: lakeEvents, receivedAt: now });
    }

    // Best effort, like the detection route: the agent must not retry a batch
    // over a counter failure.
    try {
      await recordSightings(prisma, agent.tenantId, agent.id, aggregateSightings(items));
    } catch (error) {
      console.error("Prevalence update failed:", error);
    }

    // Best effort as well: past the enqueue a 500 would make the agent resend a batch already queued.
    try {
      await prisma.agent.update({ where: { id: agent.id }, data: { lastSeen: now } });
    } catch (error) {
      console.error("lastSeen update failed:", error);
    }

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

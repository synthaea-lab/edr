import type { PrismaClient } from "@prisma/client";
import { enqueue } from "./outbox";
import { consoleUrl } from "./urls";

/**
 * `hunt.new_matches` (ADR-0036 point 2, slice 3, #863): called by `runHunt` once a run is
 * recorded with `newMatchCount` above zero. Only a channel that lists the hunt receives it
 * (the subscription is the channel's, an admin decision). The payload is a pointer: the hunt's
 * name, the counts and the console link, never a match's contents.
 *
 * A failure here must not fail the run, which is already recorded: the error is logged and the
 * run goes on. Fewer messages than runs is by design: the outbox's cooldown holds a hunt that
 * has new matches on every run to one message per cooldown and channel.
 */
export async function notifyHuntNewMatches(
  db: PrismaClient,
  hunt: { id: string; tenantId: string; version: number },
  run: { id: string; newMatchCount: number; matchCount: number; startedAt: Date },
  env: Record<string, string | undefined> = process.env
): Promise<number> {
  if (run.newMatchCount <= 0) return 0;
  try {
    const row = await db.hunt.findFirst({ where: { id: hunt.id, tenantId: hunt.tenantId }, select: { name: true } });
    return await enqueue(
      db,
      {
        tenantId: hunt.tenantId,
        event: "hunt.new_matches",
        subject: hunt.id,
        occurredAt: run.startedAt,
        data: {
          subject: { id: hunt.id, name: row?.name ?? null, console_url: consoleUrl(env, `/console/hunts/${hunt.id}`) },
          change: { new_match_count: run.newMatchCount, match_count: run.matchCount, run_id: run.id, query_version: hunt.version },
        },
      },
      run.startedAt
    );
  } catch (error) {
    console.error("Hunt notification failed:", hunt.id, error);
    return 0;
  }
}

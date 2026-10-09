import { timingSafeEqual } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { scheduleDecoyReport } from "@/lib/decoy";

export type CronAuthResult = "ok" | "unconfigured" | "unauthorized";

/**
 * Checks a cron call's `Authorization` header against `CRON_SECRET`.
 *
 * Fails closed: an unset or empty secret is "unconfigured", never a match.
 * Building the expected value as `` `Bearer ${process.env.CRON_SECRET}` ``
 * instead turns an unset secret into the literal string "Bearer undefined",
 * which anyone can send.
 *
 * The comparison is constant-time. The length check up front leaks only the
 * header's length, not how many leading bytes match.
 */
export function checkCronAuth(
  authHeader: string | null,
  secret: string | undefined
): CronAuthResult {
  if (!secret) {
    return "unconfigured";
  }
  if (!authHeader) {
    return "unauthorized";
  }
  const expected = Buffer.from(`Bearer ${secret}`);
  const received = Buffer.from(authHeader);
  if (received.length !== expected.length) {
    return "unauthorized";
  }
  return timingSafeEqual(received, expected) ? "ok" : "unauthorized";
}

/**
 * Route guard for the `/api/cron/*` endpoints. Returns the error response to
 * send, or `null` when the call is authorized.
 *
 * A rejected bearer that is one of an agent's decoy credentials (issue #81) also raises an
 * alarm naming the host it was planted on. The alarm is recorded after the answer is ready, not
 * before, so the response costs the same for a decoy as for any other bad bearer.
 */
export async function verifyCronRequest(req: NextRequest): Promise<NextResponse | null> {
  const authorization = req.headers.get("Authorization");
  switch (checkCronAuth(authorization, process.env.CRON_SECRET)) {
    case "ok":
      return null;
    case "unconfigured":
      scheduleDecoyReport(prisma, req, authorization);
      console.error("CRON_SECRET environment variable is not configured");
      return NextResponse.json(
        { error: "Server misconfiguration - CRON_SECRET not set" },
        { status: 500 }
      );
    case "unauthorized":
      scheduleDecoyReport(prisma, req, authorization);
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
}

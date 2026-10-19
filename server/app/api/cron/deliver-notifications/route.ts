import { NextRequest, NextResponse } from "next/server";
import { verifyCronRequest } from "@/lib/cron-auth";
import { prisma } from "@/lib/prisma";
import { deliverDue, purge } from "@/lib/notify/outbox";
import { evaluateHostTransitions } from "@/lib/notify/host-transitions";

// One tick of the notification outbox (ADR-0036, #863): turn host state changes into rows, send
// the due rows, tidy up. The three phases are independent: one that throws is reported and does
// not stop the others (a failed evaluation must not stop delivery of what is already queued).
export async function GET(req: NextRequest) {
  try {
    const denied = await verifyCronRequest(req);
    if (denied) {
      return denied;
    }
    const failed: string[] = [];
    const phase = async <T>(name: string, run: () => Promise<T>): Promise<T | null> => {
      try {
        return await run();
      } catch (error) {
        console.error(`Notification ${name} error:`, error);
        failed.push(name);
        return null;
      }
    };
    const transitions = await phase("evaluation", () => evaluateHostTransitions(prisma));
    const delivery = await phase("delivery", () => deliverDue(prisma));
    const housekeeping = await phase("housekeeping", () => purge(prisma, new Date()));
    return NextResponse.json({ ...(delivery ?? {}), transitions, housekeeping, failed }, { status: failed.length ? 500 : 200 });
  } catch (error) {
    console.error("Notification delivery error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

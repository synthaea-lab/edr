import { NextRequest, NextResponse } from "next/server";
import { verifyCronRequest } from "@/lib/cron-auth";
import { prisma } from "@/lib/prisma";
import { deliverDue, purge } from "@/lib/notify/outbox";
import { evaluateHostTransitions } from "@/lib/notify/host-transitions";

// One tick of the notification outbox (ADR-0036, #863): turn host state changes into rows,
// then send the due rows.
export async function GET(req: NextRequest) {
  try {
    const denied = await verifyCronRequest(req);
    if (denied) {
      return denied;
    }
    const transitions = await evaluateHostTransitions(prisma);
    const housekeeping = await purge(prisma, new Date());
    return NextResponse.json({ ...(await deliverDue(prisma)), transitions, housekeeping });
  } catch (error) {
    console.error("Notification delivery error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

import { NextRequest, NextResponse } from "next/server";
import { verifyCronRequest } from "@/lib/cron-auth";
import { prisma } from "@/lib/prisma";
import { deliverDue } from "@/lib/notify/outbox";

// Sends the due rows of the notification outbox (ADR-0036, #863).
export async function GET(req: NextRequest) {
  try {
    const denied = await verifyCronRequest(req);
    if (denied) {
      return denied;
    }
    return NextResponse.json(await deliverDue(prisma));
  } catch (error) {
    console.error("Notification delivery error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

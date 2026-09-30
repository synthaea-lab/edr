import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { extractEnrollmentId, verifyProxyAuth } from "@/lib/tenant";

export type AuthenticatedAgent = { id: string; tenantId: string; ring: string };

/**
 * Authenticates an agent request the way `/api/ingest/*` does: the request must
 * have come through the nginx proxy (`X-Proxy-Secret`, else the mTLS headers
 * below are spoofable), carry a verified client certificate, and name an
 * enrolled agent.
 *
 * Returns the agent, or the `NextResponse` to send back.
 */
export async function authenticateAgent(
  req: NextRequest
): Promise<{ agent: AuthenticatedAgent } | { response: NextResponse }> {
  try {
    verifyProxyAuth(req);
  } catch (error) {
    console.error("Proxy auth failed:", error);
    return {
      response: NextResponse.json(
        { error: "Forbidden - invalid proxy authentication" },
        { status: 403 }
      ),
    };
  }

  const certVerified = req.headers.get("X-Client-Cert-Verified");
  const certSubject = req.headers.get("X-Client-Cert-Subject");
  if (certVerified !== "SUCCESS" || !certSubject) {
    return {
      response: NextResponse.json(
        { error: "Unauthorized - mTLS authentication required" },
        { status: 401 }
      ),
    };
  }

  const enrollmentId = extractEnrollmentId(certSubject);
  if (!enrollmentId) {
    return {
      response: NextResponse.json({ error: "Invalid certificate subject" }, { status: 400 }),
    };
  }

  const agent = await prisma.agent.findUnique({
    where: { enrollmentId },
    select: { id: true, tenantId: true, ring: true },
  });
  if (!agent) {
    return { response: NextResponse.json({ error: "Agent not enrolled" }, { status: 403 }) };
  }
  return { agent };
}

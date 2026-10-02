import { NextRequest, NextResponse } from "next/server";
import { authenticateAgent } from "@/lib/agent-auth";
import { loadActiveManifest } from "@/lib/active-content-manifest";

const VALID_RINGS = ["canary_0", "canary_1", "canary_2", "prod"];

/**
 * GET /api/content/manifest/{ring}
 * Agent endpoint: Fetch latest content manifest for assigned ring
 * A halted newest release returns 423 until the ring is resumed or rolled back.
 *
 * Authentication: nginx proxy secret + mTLS + enrolled agent (`authenticateAgent`)
 * Response: ContentManifest JSON (signed)
 */
export async function GET(
  req: NextRequest,
  { params }: { params: { ring: string } }
) {
  try {
    const authenticated = await authenticateAgent(req);
    if ("response" in authenticated) return authenticated.response;
    const { agent } = authenticated;

    // Validate ring parameter
    const { ring } = params;
    if (!VALID_RINGS.includes(ring)) {
      return NextResponse.json(
        { error: "Invalid ring", validRings: VALID_RINGS },
        { status: 400 }
      );
    }

    // Verify agent is in requested ring (prevent ring spoofing)
    if (agent.ring !== ring) {
      return NextResponse.json(
        {
          error: "Ring mismatch",
          message: `Agent is assigned to ring '${agent.ring}', cannot fetch manifest for '${ring}'`,
        },
        { status: 403 }
      );
    }

    const active = await loadActiveManifest(agent);
    if (!active.ok) {
      return NextResponse.json({ error: active.error }, { status: active.status });
    }
    return NextResponse.json(active.manifest);
  } catch (error) {
    console.error("Content manifest fetch error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

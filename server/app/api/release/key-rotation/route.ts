import { NextRequest, NextResponse } from "next/server";
import { authenticateAgent } from "@/lib/agent-auth";
import { loadKeyRotation } from "@/lib/key-rotation";

/**
 * GET /api/release/key-rotation
 * Agent endpoint: the key rotation pending for this agent's ring (ADR-0027), signed offline by
 * the `recovery` key. 404 when nothing is pending.
 *
 * The server only serves a file an operator placed under `storage/key-rotations/<ring>.json`: it
 * never signs and never verifies (every agent verifies against the `recovery` key it embeds, and
 * checks that the rotation retires the key it trusts now, is not expired and is newer than what
 * it applied). No ring or tenant in the request: the ring is the one the server assigned to the
 * agent's mTLS identity, like `/api/release/manifest`.
 *
 * Authentication: nginx proxy secret + mTLS (see `authenticateAgent`).
 * Response: the stored JSON, byte for byte.
 */
export async function GET(req: NextRequest) {
  try {
    const auth = await authenticateAgent(req);
    if ("response" in auth) return auth.response;
    const { agent } = auth;

    const loaded = await loadKeyRotation(agent.ring);
    if (!loaded.ok) {
      return NextResponse.json({ error: loaded.error }, { status: loaded.status });
    }
    return new NextResponse(new Uint8Array(loaded.bytes), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Content-Length": loaded.bytes.length.toString(),
      },
    });
  } catch (error) {
    console.error("Key rotation fetch error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

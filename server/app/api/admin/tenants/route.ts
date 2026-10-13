import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/prisma";
import { getUserId } from "@/lib/tenant";
import { provisionTenant } from "@/lib/tenant-provisioning";

const CreateTenantSchema = z.object({
  name: z.string().min(1).max(200),
});

/**
 * POST /api/admin/tenants
 * Admin endpoint: provision a new tenant and its paired better-auth organization (#821).
 *
 * Authentication: better-auth session (admin only, same as the other admin endpoints —
 * #803 tracks making that a real role check rather than "any signed-in session").
 * Request body: { name }
 * Response: { tenant: { id, name } }
 *
 * The caller is added as the tenant's owning `Member`, so their own session can be made
 * active against it right after (better-auth's `POST /api/auth/organization/set-active`)
 * without a second admin step.
 */
export async function POST(req: NextRequest) {
  try {
    const userId = await getUserId(req);

    const body = await req.json();
    const validation = CreateTenantSchema.safeParse(body);
    if (!validation.success) {
      return NextResponse.json(
        { error: "Invalid request", details: validation.error.errors },
        { status: 400 }
      );
    }

    const tenant = await provisionTenant(prisma, validation.data.name, { userId });

    return NextResponse.json({ tenant }, { status: 201 });
  } catch (error) {
    console.error("Tenant provisioning error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

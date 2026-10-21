import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/prisma";
import { requirePlatformOperator } from "@/lib/platform-operator";
import { provisionTenant } from "@/lib/tenant-provisioning";

const CreateTenantSchema = z.object({
  name: z.string().min(1).max(200),
});

/**
 * POST /api/admin/tenants
 * Platform-operator endpoint: provision a new tenant and its paired better-auth
 * organization (#821).
 *
 * Authentication: `PLATFORM_OPERATOR_USER_IDS` allow-list (review of #829) — the caller
 * has no tenant yet at this point, so `requireTenantAdmin` (#803), which checks a role
 * *within* a tenant, cannot gate this route.
 * Request body: { name }
 * Response: { tenant: { id, name } }
 *
 * The caller is added as the tenant's owning `Member`, so their own session can be made
 * active against it right after (better-auth's `POST /api/auth/organization/set-active`)
 * without a second admin step.
 */
export async function POST(req: NextRequest) {
  try {
    const authed = await requirePlatformOperator(req);
    if ("response" in authed) return authed.response;
    const { userId } = authed;

    let body: unknown;
    try {
      body = await req.json();
    } catch {
      return NextResponse.json({ error: "Request body is not valid JSON" }, { status: 400 });
    }
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

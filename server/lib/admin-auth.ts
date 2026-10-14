import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId, getUserId } from "@/lib/tenant";

/**
 * better-auth's organization plugin's own default roles (`owner`/`admin`/`member`,
 * `better-auth/plugins/organization/access/statement`) — there is no RBAC system of this
 * codebase's own yet (#89), so this reuses the roles already stored in `Member.role` rather
 * than adding a second notion of "admin".
 */
const ADMIN_ROLES = new Set(["owner", "admin"]);

/**
 * Requires the caller to be an `owner` or `admin` member of their tenant's organization
 * (#803): a route whose docstring says "admin only" but only checked that a session existed
 * let any member of the tenant publish or roll back content fleet-wide. Refuses a plain
 * `member`, or a caller with no membership row at all, with 403 before the route reads the
 * request body.
 *
 * Returns the tenant and user ids on success, or the `NextResponse` to send back.
 */
export async function requireTenantAdmin(
  req: NextRequest
): Promise<{ tenantId: string; userId: string } | { response: NextResponse }> {
  const tenantId = await getTenantId(req);
  const userId = await getUserId(req);

  const member = await prisma.member.findFirst({
    where: { organizationId: tenantId, userId },
    select: { role: true },
  });

  // better-auth stores several roles as one comma-separated string (`updateMemberRole`
  // accepts an array; its own checks split on ",") — a member given two roles through
  // better-auth's own API must not be locked out of both just because the whole string
  // never equals "admin" or "owner".
  const roles = member?.role.split(",").map((r) => r.trim()) ?? [];
  if (!roles.some((r) => ADMIN_ROLES.has(r))) {
    return {
      response: NextResponse.json({ error: "Admin role required" }, { status: 403 }),
    };
  }

  return { tenantId, userId };
}

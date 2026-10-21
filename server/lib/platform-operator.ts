import { NextRequest, NextResponse } from "next/server";
import { getUserId } from "@/lib/tenant";

/**
 * Gate for a route that acts before any tenant exists (#821 review of #829): today
 * only tenant provisioning. `requireTenantAdmin` (`lib/admin-auth.ts`, #803) checks the
 * caller's role *within* their current tenant, which cannot gate this — the caller has
 * no tenant yet, and `allowUserToCreateOrganization: false` (`lib/auth.ts`) only stops
 * better-auth's own organization API, not this route.
 *
 * `PLATFORM_OPERATOR_USER_IDS` is a comma-separated list of `auth_user.id` values,
 * checked directly — there is no platform-operator concept in the schema to check a
 * role against. Unset or empty means no caller is allowed, the same "unconfigured never
 * matches" rule `lib/cron-auth.ts`'s `CRON_SECRET` follows, rather than treating a
 * misconfigured deploy as open to every signed-up user.
 */
export async function requirePlatformOperator(
  req: NextRequest
): Promise<{ userId: string } | { response: NextResponse }> {
  const userId = await getUserId(req);
  const allowed = (process.env.PLATFORM_OPERATOR_USER_IDS ?? "")
    .split(",")
    .map((id) => id.trim())
    .filter((id) => id.length > 0);
  if (!allowed.includes(userId)) {
    return {
      response: NextResponse.json({ error: "Platform operator access required" }, { status: 403 }),
    };
  }
  return { userId };
}

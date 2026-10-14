import { randomUUID } from "crypto";
import { PrismaClient } from "@prisma/client";

/**
 * Creates a tenant and its paired better-auth organization together (#821): nothing else in
 * this codebase does, so until now the pair had to be made by hand (`server/README.md`'s
 * "set the session's active_organization_id by hand" step) — a `Tenant` with no matching
 * `Organization` row, which works only because `middleware.ts` reads `activeOrganizationId`
 * straight off the session and never actually checks the `Organization` table itself. A real
 * sign-in does check it: better-auth's own `setActiveOrganization` refuses an id with no
 * `Organization` row, or where the signed-in user isn't a `Member` of it.
 *
 * Both rows share one id, by product convention (`server/README.md`: "an organization's id
 * must equal its tenant's" — one less join, not a relation `schema.prisma` models). Writes to
 * both tables directly with Prisma rather than calling `auth.api.createOrganization`: that
 * endpoint generates its own id and has no parameter to pin it to a given `Tenant`, so getting
 * the ids to match would mean creating the `Tenant` to catch up with whatever id it chose —
 * backwards from this function's actual job. `owner`, when given, is added as a `Member` in
 * the same transaction, so a human only ever sees a tenant that already has someone who can
 * make it their session's active organization — never a tenant momentarily orphaned of one.
 */
export async function provisionTenant(
  prisma: PrismaClient,
  name: string,
  owner?: { userId: string; role?: string }
): Promise<{ id: string; name: string }> {
  const id = randomUUID();
  return prisma.$transaction(async (tx) => {
    const tenant = await tx.tenant.create({ data: { id, name } });
    await tx.organization.create({
      data: { id, name, slug: organizationSlug(name, id) },
    });
    if (owner) {
      await tx.member.create({
        data: {
          id: randomUUID(),
          organizationId: id,
          userId: owner.userId,
          role: owner.role ?? "owner",
        },
      });
      // Creating a tenant is at least as sensitive as any action content/release or
      // content/rollback already audit — more so, given it's the one route no
      // tenant-scoped role check can gate (review of #829). Written in the same
      // transaction so a rolled-back provision leaves no orphaned entry; skipped
      // without an owner (a test-only path with no caller to attribute it to).
      await tx.auditLog.create({
        data: {
          tenantId: tenant.id,
          userId: owner.userId,
          action: "tenant.create",
          resource: `tenants/${tenant.id}`,
          details: { name: tenant.name },
        },
      });
    }
    return { id: tenant.id, name: tenant.name };
  });
}

/**
 * A readable slug from `name`, made unique by appending part of `id` — never the bare name:
 * two tenants can share a name (two customers both called "Acme"), and `Organization.slug` is
 * `@unique`. `id` is already unique and already generated for this tenant, so reusing a slice
 * of it avoids a retry-on-collision loop for what the slug is not promising to be anyway (a
 * stable, meaningful public identifier — nothing in this codebase routes on it yet).
 */
function organizationSlug(name: string, id: string): string {
  const base = name
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  const suffix = id.slice(0, 8);
  return base ? `${base}-${suffix}` : suffix;
}

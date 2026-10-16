import { betterAuth } from "better-auth";
import { prismaAdapter } from "better-auth/adapters/prisma";
import { organization } from "better-auth/plugins";
import { prisma } from "@/lib/prisma";

export const auth = betterAuth({
  // The Prisma client the rest of the server uses; the auth tables are Prisma models
  // (`prisma/schema.prisma`). A bare `{ provider, url }` is not a shape better-auth accepts:
  // it left the adapter uninitialized and every sign-in failed (#810).
  database: prismaAdapter(prisma, { provider: "postgresql" }),
  emailAndPassword: {
    enabled: true,
  },
  plugins: [
    organization({
      // Organization = Tenant
      allowUserToCreateOrganization: false, // Admin-only tenant creation
      // An Organization pairs 1:1 with a Tenant by shared id (#821); better-auth's own
      // delete API has no notion of that pairing and would remove the Organization/Member
      // rows while leaving the Tenant and all its data orphaned, reachable by no one
      // (review of #829). Nothing in this product needs organization deletion as a
      // feature, so it is disabled outright rather than hooked.
      disableOrganizationDeletion: true,
    }),
  ],
  trustedOrigins: [
    "http://localhost:3000",
    "http://localhost:8443",
  ],
});

export type Session = typeof auth.$Infer.Session;

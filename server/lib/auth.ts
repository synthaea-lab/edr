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
    }),
  ],
  trustedOrigins: [
    "http://localhost:3000",
    "http://localhost:8443",
  ],
});

export type Session = typeof auth.$Infer.Session;

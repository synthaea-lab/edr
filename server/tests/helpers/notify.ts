import { randomUUID } from "node:crypto";
import type { PrismaClient } from "@prisma/client";
import { sealSecret, sealUrl } from "@/lib/notify/secret";

export const NOTIFY_KEY = "k1:" + "11".repeat(32);
export const NOTIFY_ENV = { NOTIFY_SECRET_KEY: NOTIFY_KEY };

/** A channel as the create route would write it: the URL and the secret sealed, the host in clear. */
export async function makeChannel(
  prisma: PrismaClient,
  tenantId: string,
  over: Record<string, unknown> & { url?: string; secret?: string } = {}
) {
  const { url = "https://hooks.example.com/x", secret = "whsec_x", ...rest } = over;
  const id = randomUUID();
  const sealedSecret = sealSecret(secret, id, NOTIFY_ENV)!;
  const sealedUrl = sealUrl(url, id, NOTIFY_ENV)!;
  return prisma.notificationChannel.create({
    data: {
      id,
      tenantId,
      host: new URL(url).host,
      urlKeyId: sealedUrl.keyId,
      urlSealed: sealedUrl.sealed,
      secretKeyId: sealedSecret.keyId,
      secretSealed: sealedSecret.sealed,
      events: ["host.degraded", "host.silent", "host.recovered", "hunt.new_matches"],
      createdBy: "u",
      ...rest,
    },
  });
}

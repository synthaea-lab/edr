/**
 * The session behind a request's cookie, for `middleware.ts` (#810).
 *
 * The middleware runs in Next's Edge runtime, where Prisma, and so better-auth's database
 * adapter, cannot run (`PrismaClient is not configured to run in Edge Runtime`). It therefore
 * asks the Node route `/api/auth/get-session` over the loopback and reads the answer, instead of
 * importing `@/lib/auth`. Keep this module free of `@/lib/auth` and `@/lib/prisma`.
 *
 * Fails closed: a missing cookie, a refusal, a network error, a timeout or an answer of an
 * unexpected shape is "no session", which the middleware turns into a redirect to `/login`.
 */

/** What the middleware needs from a session. */
export type LookedUpSession = {
  session: { activeOrganizationId: string | null };
  user: { id: string };
};

/** A hung auth route must not hang every console request. */
const LOOKUP_TIMEOUT_MS = 5_000;

/**
 * Where this server answers on its own loopback. Never derived from the request's `Host` or
 * `X-Forwarded-Host`: those are the client's, and the request carries the session cookie.
 */
function selfOrigin(): string {
  return `http://127.0.0.1:${process.env.PORT ?? "3000"}`;
}

export async function lookupSession(headers: Headers): Promise<LookedUpSession | null> {
  const cookie = headers.get("cookie");
  if (!cookie) return null;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), LOOKUP_TIMEOUT_MS);
  try {
    const res = await fetch(`${selfOrigin()}/api/auth/get-session`, {
      headers: { cookie },
      signal: controller.signal,
    });
    if (!res.ok) return null;
    const body: unknown = await res.json();
    return readSession(body);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function readSession(body: unknown): LookedUpSession | null {
  if (typeof body !== "object" || body === null) return null;
  const { session, user } = body as { session?: unknown; user?: unknown };
  if (typeof session !== "object" || session === null) return null;
  if (typeof user !== "object" || user === null) return null;
  const id = (user as { id?: unknown }).id;
  if (typeof id !== "string" || id.length === 0) return null;
  const org = (session as { activeOrganizationId?: unknown }).activeOrganizationId;
  return {
    session: { activeOrganizationId: typeof org === "string" && org.length > 0 ? org : null },
    user: { id },
  };
}

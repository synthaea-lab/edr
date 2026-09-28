import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { buildIdentityHeaders, stripIdentityHeaders } from "@/lib/tenant";

export async function middleware(req: NextRequest) {
  // Public routes - no authentication required, and no identity either: the
  // client's own identity headers are dropped here too, not just on protected
  // routes.
  if (
    req.nextUrl.pathname.startsWith("/api/ingest") ||
    req.nextUrl.pathname.startsWith("/api/auth") ||
    req.nextUrl.pathname.startsWith("/api/health") ||
    req.nextUrl.pathname === "/login" ||
    req.nextUrl.pathname === "/"
  ) {
    return NextResponse.next({
      request: { headers: stripIdentityHeaders(req.headers) },
    });
  }

  // Check session for protected routes
  const session = await auth.api.getSession({
    headers: req.headers,
  });

  // Redirect to login if no session
  if (!session) {
    return NextResponse.redirect(new URL("/login", req.url));
  }

  // Inject tenant context for protected routes
  const headers = buildIdentityHeaders(req.headers, {
    tenantId: session.session.activeOrganizationId,
    userId: session.user.id,
  });

  return NextResponse.next({
    request: { headers },
  });
}

// Every API route runs the middleware, public ones included. The old matcher
// excluded ingest/auth/health, so the public branch above never ran for them
// and their handlers received client identity headers untouched.
export const config = {
  matcher: ["/console/:path*", "/api/:path*"],
};

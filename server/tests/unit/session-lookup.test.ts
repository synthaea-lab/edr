import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { lookupSession } from "@/lib/session-lookup";

// The middleware runs in Next's Edge runtime, where Prisma (and so better-auth's database
// adapter) cannot run. It asks the Node route `/api/auth/get-session` instead (#810).
const fetchMock = vi.fn();

const body = (session: unknown, user: unknown) =>
  new Response(JSON.stringify({ session, user }), { status: 200 });

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("lookupSession", () => {
  it("returns the session and user the auth route reports for the cookie", async () => {
    fetchMock.mockResolvedValue(body({ activeOrganizationId: "t1" }, { id: "u1" }));

    const found = await lookupSession(new Headers({ cookie: "better-auth.session_token=abc" }));

    expect(found).toEqual({ session: { activeOrganizationId: "t1" }, user: { id: "u1" } });
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toMatch(/\/api\/auth\/get-session$/);
    expect(new Headers(init.headers).get("cookie")).toBe("better-auth.session_token=abc");
  });

  it("asks the loopback, never a host the client chose", async () => {
    fetchMock.mockResolvedValue(body({}, { id: "u1" }));

    await lookupSession(new Headers({ cookie: "a=b", host: "attacker.example", "x-forwarded-host": "evil.example" }));

    const url = new URL(String(fetchMock.mock.calls[0][0]));
    expect(url.hostname).toBe("127.0.0.1");
  });

  it("sends nothing and finds nothing for a request without a cookie", async () => {
    expect(await lookupSession(new Headers())).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("fails closed: no session on a refusal, a network error, or an unusable answer", async () => {
    const cookie = new Headers({ cookie: "a=b" });
    fetchMock.mockResolvedValueOnce(new Response("nope", { status: 500 }));
    expect(await lookupSession(cookie)).toBeNull();

    fetchMock.mockRejectedValueOnce(new Error("connect ECONNREFUSED"));
    expect(await lookupSession(cookie)).toBeNull();

    fetchMock.mockResolvedValueOnce(new Response("null", { status: 200 }));
    expect(await lookupSession(cookie)).toBeNull();

    fetchMock.mockResolvedValueOnce(new Response("not json", { status: 200 }));
    expect(await lookupSession(cookie)).toBeNull();

    fetchMock.mockResolvedValueOnce(body({ activeOrganizationId: "t1" }, null));
    expect(await lookupSession(cookie)).toBeNull();

    fetchMock.mockResolvedValueOnce(body(null, { id: "u1" }));
    expect(await lookupSession(cookie)).toBeNull();

    fetchMock.mockResolvedValueOnce(body({}, { id: 7 }));
    expect(await lookupSession(cookie)).toBeNull();
  });

  it("reports a missing or non-string active organization as none", async () => {
    fetchMock.mockResolvedValue(body({ activeOrganizationId: 42 }, { id: "u1" }));
    const found = await lookupSession(new Headers({ cookie: "a=b" }));
    expect(found?.session.activeOrganizationId).toBeNull();
  });

  it("gives up on a hung auth route instead of hanging every request", async () => {
    fetchMock.mockImplementation(
      (_url: string, init: { signal: AbortSignal }) =>
        new Promise((_resolve, reject) => {
          init.signal.addEventListener("abort", () => reject(new Error("aborted")));
        })
    );
    vi.useFakeTimers();
    const pending = lookupSession(new Headers({ cookie: "a=b" }));
    await vi.advanceTimersByTimeAsync(5_000);
    expect(await pending).toBeNull();
    vi.useRealTimers();
  });
});

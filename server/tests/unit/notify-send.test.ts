import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseRetryAfter, sendWebhook } from "@/lib/notify/send";

// A self-signed cert for `hooks.test`, listening on 127.0.0.1: the guard's resolver says
// `hooks.test` is 127.0.0.1 and the operator allowlist lets that one host through, so the
// test proves the client connects to the validated address while keeping Host and SNI.
let dir: string;
let server: Server;
let port: number;
let cert: string;
const seen: { host?: string; sni?: string; sig?: string; body: string }[] = [];
let reply = { status: 204, location: "" };
let big = false;
let stall = false;
let drip = false;
let retryAfter = "";

const guard = (extra: object = {}) => ({
  resolve: async () => ["127.0.0.1"],
  allowedPrivateHosts: new Set(["t1:hooks.test"]),
  tenantId: "t1",
  unsafeAllowLoopbackForTests: true, // the receiver here is on 127.0.0.1; production never allows loopback
  extraPorts: new Set([port]),
  ...extra,
});

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "notify-send-"));
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=hooks.test",
    "-addext", "subjectAltName=DNS:hooks.test", "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem"),
  ], { stdio: "ignore" });
  cert = readFileSync(join(dir, "c.pem"), "utf8");
  server = createServer({ key: readFileSync(join(dir, "k.pem")), cert }, (req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      seen.push({
        host: req.headers.host,
        sni: (req.socket as unknown as { servername?: string }).servername,
        sig: req.headers["x-synthaea-signature"] as string,
        body,
      });
      if (stall) return; // never answers: only the deadline ends this call
      const h: Record<string, string> = {};
      if (reply.location) h.Location = reply.location;
      if (retryAfter) h["Retry-After"] = retryAfter;
      res.writeHead(reply.status, h);
      if (drip) {
        // Headers out at once, then a byte every 200 ms for ever: only an answer that ends at the
        // status line is not held by it.
        res.write("x");
        const t = setInterval(() => res.write("x"), 200);
        res.on("close", () => clearInterval(t));
        return;
      }
      res.end(big ? "x".repeat(300_000) : "");
    });
  });
  server.on("secureConnection", () => {});
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as { port: number }).port;
});

afterAll(() => {
  server.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("sendWebhook", () => {
  it("connects to the validated address, keeping Host and SNI", async () => {
    reply = { status: 204, location: "" };
    const r = await sendWebhook(`https://hooks.test:${port}/path?q=1`, '{"a":1}', { "X-Synthaea-Signature": "t=1,v1=ab" }, guard(), cert);
    expect(r).toEqual({ ok: true, statusCode: 204 });
    const last = seen[seen.length - 1];
    expect(last.host).toBe(`hooks.test:${port}`);
    expect(last.sni).toBe("hooks.test");
    expect(last.sig).toBe("t=1,v1=ab");
    expect(last.body).toBe('{"a":1}');
  });

  it("does not follow a redirect and reports http_status", async () => {
    reply = { status: 302, location: "https://169.254.169.254/" };
    const before = seen.length;
    const r = await sendWebhook(`https://hooks.test:${port}/`, "{}", {}, guard(), cert);
    expect(r).toEqual({ ok: false, statusCode: 302, errorClass: "http_status" });
    expect(seen.length).toBe(before + 1);
  });

  it("reports a non-2xx as http_status and survives an oversized response body", async () => {
    reply = { status: 500, location: "" };
    big = true;
    const r = await sendWebhook(`https://hooks.test:${port}/`, "{}", {}, guard(), cert);
    big = false;
    expect(r.errorClass).toBe("http_status");
    expect(r.statusCode).toBe(500);
  });

  it("reports a certificate it does not trust as tls", async () => {
    reply = { status: 204, location: "" };
    const r = await sendWebhook(`https://hooks.test:${port}/`, "{}", {}, guard()); // no ca
    expect(r).toEqual({ ok: false, errorClass: "tls" });
  });

  it("refuses to connect at all when the name resolves to a private address", async () => {
    const before = seen.length;
    const r = await sendWebhook(`https://other.test:${port}/`, "{}", {}, guard(), cert);
    expect(r).toEqual({ ok: false, errorClass: "blocked" });
    expect(seen.length).toBe(before);
  });

  it("one total deadline ends a receiver that never answers", async () => {
    stall = true;
    const t0 = Date.now();
    const r = await sendWebhook(`https://hooks.test:${port}/`, "{}", {}, guard(), cert, 600);
    stall = false;
    expect(r).toEqual({ ok: false, errorClass: "timeout" });
    expect(Date.now() - t0).toBeLessThan(3000);
  });

  it("settles at the status line: a body dripped after the headers does not hold the call", async () => {
    reply = { status: 200, location: "" }; // a 204 cannot carry a body, so its headers would not leave before the end
    drip = true;
    const t0 = Date.now();
    const r = await sendWebhook(`https://hooks.test:${port}/`, "{}", {}, guard(), cert, 5000);
    drip = false;
    expect(r).toEqual({ ok: true, statusCode: 200 });
    expect(Date.now() - t0).toBeLessThan(1500);
  });

  it("tries the next validated address when a connection cannot be made, and only then", async () => {
    reply = { status: 204, location: "" };
    // 127.0.0.2 has nothing listening on that port; 127.0.0.1 is the receiver.
    const r = await sendWebhook(`https://hooks.test:${port}/`, "{}", {}, guard({ resolve: async () => ["127.0.0.2", "127.0.0.1"] }), cert);
    expect(r).toEqual({ ok: true, statusCode: 204 });
    // An HTTP answer ends the call: the second address is not tried after a 500.
    reply = { status: 500, location: "" };
    const before = seen.length;
    const r2 = await sendWebhook(`https://hooks.test:${port}/`, "{}", {}, guard({ resolve: async () => ["127.0.0.1", "127.0.0.1"] }), cert);
    expect(r2.statusCode).toBe(500);
    expect(seen.length).toBe(before + 1);
  });

  it("refuses an allowlisted host that resolves to loopback unless the test flag is set", async () => {
    const r = await sendWebhook(`https://hooks.test:${port}/`, "{}", {}, guard({ unsafeAllowLoopbackForTests: false }), cert);
    expect(r).toEqual({ ok: false, errorClass: "blocked" });
  });

  it("a name that does not resolve and one that resolves to a refused address are both `blocked`", async () => {
    const dns = await sendWebhook(`https://nope.test:${port}/`, "{}", {}, guard({ resolve: async () => { throw new Error("ENOTFOUND"); } }), cert);
    const priv = await sendWebhook(`https://other.test:${port}/`, "{}", {}, guard(), cert);
    expect(dns).toEqual({ ok: false, errorClass: "blocked" });
    expect(priv).toEqual({ ok: false, errorClass: "blocked" });
  });

  it("hands a Retry-After back with the status", async () => {
    reply = { status: 429, location: "" };
    retryAfter = "120";
    const r = await sendWebhook(`https://hooks.test:${port}/`, "{}", {}, guard(), cert);
    retryAfter = "";
    expect(r).toEqual({ ok: false, statusCode: 429, errorClass: "http_status", retryAfterSeconds: 120 });
  });

  it("does not let a tenant that is not listed reach the private host", async () => {
    const r = await sendWebhook(`https://hooks.test:${port}/`, "{}", {}, guard({ tenantId: "t2" }), cert);
    expect(r).toEqual({ ok: false, errorClass: "blocked" });
  });

  it("reports a closed port as connect", async () => {
    const r = await sendWebhook("https://hooks.test:9/", "{}", {}, guard({ extraPorts: new Set([9]) }), cert);
    expect(r.errorClass).toBe("connect");
  });
});

describe("parseRetryAfter", () => {
  it("reads seconds and dates, and ignores the rest", () => {
    expect(parseRetryAfter("90")).toBe(90);
    expect(parseRetryAfter(" 7 ")).toBe(7);
    expect(parseRetryAfter("Mon, 19 Oct 2026 10:02:00 GMT", Date.parse("Mon, 19 Oct 2026 10:00:00 GMT"))).toBe(120);
    expect(parseRetryAfter("Mon, 19 Oct 2026 09:00:00 GMT", Date.parse("Mon, 19 Oct 2026 10:00:00 GMT"))).toBe(0);
    expect(parseRetryAfter("soon")).toBeUndefined();
    expect(parseRetryAfter(undefined)).toBeUndefined();
  });
});

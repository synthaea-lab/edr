import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sendWebhook } from "@/lib/notify/send";

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

const guard = (extra: object = {}) => ({
  resolve: async () => ["127.0.0.1"],
  allowedPrivateHosts: new Set(["hooks.test"]),
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
      res.writeHead(reply.status, reply.location ? { Location: reply.location } : {});
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

  it("reports a closed port as connect", async () => {
    const r = await sendWebhook("https://hooks.test:9/", "{}", {}, guard({ extraPorts: new Set([9]) }), cert);
    expect(r.errorClass).toBe("connect");
  });
});

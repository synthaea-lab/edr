import { Agent, request } from "node:https";
import { isIP } from "node:net";
import { NotifyBlockedError, resolvePublicTarget, type GuardOptions } from "./guard";

/**
 * The coarse classes a tenant may see (ADR-0036 point 6): never the finer cause. A name that does
 * not resolve and one that resolves to a refused address are both `blocked`, so a tenant cannot
 * tell the server's internal DNS from a miss; the finer reason goes to the server log.
 */
export type ErrorClass = "blocked" | "connect" | "tls" | "timeout" | "http_status";

export interface SendResult {
  ok: boolean;
  statusCode?: number;
  errorClass?: ErrorClass;
  /** `Retry-After` of the answer, in seconds, when it was a number of seconds or a date. */
  retryAfterSeconds?: number;
}

/** Total deadline of a send: resolve, connect, TLS and response (not an idle timeout). */
export const SEND_DEADLINE_MS = 10_000;

const TLS_CODES = new Set([
  "CERT_HAS_EXPIRED", "DEPTH_ZERO_SELF_SIGNED_CERT", "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "UNABLE_TO_GET_ISSUER_CERT_LOCALLY", "ERR_TLS_CERT_ALTNAME_INVALID",
  "ERR_SSL_WRONG_VERSION_NUMBER", "ECONNRESET_TLS",
]);

function classify(err: NodeJS.ErrnoException): ErrorClass {
  const code = err.code ?? "";
  if (code === "ETIMEDOUT" || code === "ESOCKETTIMEDOUT") return "timeout";
  if (TLS_CODES.has(code) || code.startsWith("ERR_SSL") || code.startsWith("ERR_TLS")) return "tls";
  return "connect";
}

/** `Retry-After` as seconds: a number of seconds, or an HTTP date relative to `now`. */
export function parseRetryAfter(value: string | string[] | undefined, now = Date.now()): number | undefined {
  const v = Array.isArray(value) ? value[0] : value;
  if (!v) return undefined;
  if (/^\d{1,9}$/.test(v.trim())) return Number(v.trim());
  const at = Date.parse(v);
  return Number.isNaN(at) ? undefined : Math.max(0, Math.ceil((at - now) / 1000));
}

/**
 * An explicit agent, so the process's own settings cannot reroute this call: the global agent of a
 * recent Node honours `HTTPS_PROXY` when `NODE_USE_ENV_PROXY` is set, which would bypass the guard.
 */
const agent = new Agent({ keepAlive: false });

/**
 * One attempt against one validated address. It settles as soon as the status line is in: the
 * answer's body is never read, so a receiver that drips bytes after its headers cannot hold the
 * call, and the 64 KiB cap is only a backstop for what arrives with the headers.
 */
function attempt(
  url: URL,
  address: string,
  family: 4 | 6,
  body: string,
  headers: Record<string, string>,
  left: () => number,
  ca?: string
): Promise<SendResult> {
  const host = url.hostname.replace(/^\[|\]$/g, "");
  return new Promise<SendResult>((resolve) => {
    let settled = false;
    let timer: NodeJS.Timeout | undefined;
    const done = (r: SendResult) => {
      if (!settled) {
        settled = true;
        if (timer) clearTimeout(timer);
        resolve(r);
      }
    };
    const req = request(
      {
        agent,
        host: address,
        port: url.port ? Number(url.port) : 443,
        path: url.pathname + url.search,
        method: "POST",
        servername: isIP(host) ? undefined : host,
        ...(ca ? { ca } : {}),
        // Connect to the validated address, whatever the name resolves to now.
        lookup: (_h, _o, cb) => (cb as (e: null, a: string, f: number) => void)(null, address, family),
        headers: {
          ...headers,
          Host: url.host,
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body).toString(),
        },
      },
      (res) => {
        const code = res.statusCode ?? 0;
        // 3xx is a failure: a redirect is never followed.
        done(
          code >= 200 && code < 300
            ? { ok: true, statusCode: code }
            : { ok: false, statusCode: code, errorClass: "http_status", retryAfterSeconds: parseRetryAfter(res.headers["retry-after"]) }
        );
        res.destroy(); // the body is never read
      }
    );
    timer = setTimeout(() => {
      req.destroy();
      done({ ok: false, errorClass: "timeout" });
    }, left());
    req.on("error", (err: NodeJS.ErrnoException) => done({ ok: false, errorClass: classify(err) }));
    req.end(body);
  });
}

/**
 * POSTs `body` to a channel URL after the guard has resolved it once, connecting to a validated
 * address (the original host stays in `Host` and SNI, and TLS is verified against it: there is
 * no skip-verify). The addresses are tried in turn when a connection cannot be made; any other
 * outcome ends the call. No redirect is followed, no proxy is used, the answer's body is not read.
 *
 * The whole call, resolution included, has one deadline (`SEND_DEADLINE_MS`): a receiver that
 * answers a byte a second cannot hold a delivery tick for longer than that.
 */
export async function sendWebhook(
  rawUrl: string,
  body: string,
  headers: Record<string, string>,
  guard: GuardOptions = {},
  /** Extra trusted CA (tests only); production uses the system store. */
  ca?: string,
  /** The total deadline; only tests change it. */
  deadlineMs = SEND_DEADLINE_MS
): Promise<SendResult> {
  const deadline = Date.now() + deadlineMs;
  const left = () => Math.max(1, deadline - Date.now());

  let target;
  try {
    target = await Promise.race([
      resolvePublicTarget(rawUrl, guard),
      new Promise<never>((_, reject) => setTimeout(() => reject(new NotifyBlockedError("dns")), left()).unref()),
    ]);
  } catch (e) {
    // The tenant sees one class; the finer reason is for the operator.
    console.warn("Notification target refused:", e instanceof NotifyBlockedError ? e.reason : "error");
    return { ok: false, errorClass: "blocked" };
  }

  let last: SendResult = { ok: false, errorClass: "connect" };
  for (const { address, family } of target.addresses) {
    if (Date.now() >= deadline) return { ok: false, errorClass: "timeout" };
    last = await attempt(target.url, address, family, body, headers, left, ca);
    if (last.ok || last.errorClass !== "connect") return last;
  }
  return last;
}

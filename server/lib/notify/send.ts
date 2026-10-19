import { request } from "node:https";
import { isIP } from "node:net";
import { NotifyBlockedError, resolvePublicTarget, type GuardOptions } from "./guard";

/** The coarse classes a tenant may see (ADR-0036 point 6): never the finer cause. */
export type ErrorClass = "blocked" | "dns" | "connect" | "tls" | "timeout" | "http_status";

export interface SendResult {
  ok: boolean;
  statusCode?: number;
  errorClass?: ErrorClass;
}

export const SEND_TIMEOUT_MS = 5000;
export const RESPONSE_CAP_BYTES = 64 * 1024;

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

/**
 * POSTs `body` to a channel URL after the guard has resolved it once, connecting to that
 * validated address (the original host stays in `Host` and SNI). No redirect is followed, no
 * proxy is used (`node:https` ignores `HTTP(S)_PROXY`), the response is read up to
 * `RESPONSE_CAP_BYTES` and thrown away.
 */
export async function sendWebhook(
  rawUrl: string,
  body: string,
  headers: Record<string, string>,
  guard: GuardOptions = {}
): Promise<SendResult> {
  let target;
  try {
    target = await resolvePublicTarget(rawUrl, guard);
  } catch (e) {
    if (e instanceof NotifyBlockedError) {
      return { ok: false, errorClass: e.reason === "dns" ? "dns" : "blocked" };
    }
    return { ok: false, errorClass: "blocked" };
  }
  const { url, address, family } = target;
  const host = url.hostname.replace(/^\[|\]$/g, "");

  return new Promise<SendResult>((resolve) => {
    let settled = false;
    const done = (r: SendResult) => {
      if (!settled) {
        settled = true;
        resolve(r);
      }
    };
    const req = request(
      {
        host: address,
        port: url.port ? Number(url.port) : 443,
        path: url.pathname + url.search,
        method: "POST",
        servername: isIP(host) ? undefined : host,
        // Connect to the validated address, whatever the name resolves to now.
        lookup: (_h, _o, cb) => (cb as (e: null, a: string, f: number) => void)(null, address, family),
        headers: {
          ...headers,
          Host: url.host,
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body).toString(),
        },
        timeout: SEND_TIMEOUT_MS,
      },
      (res) => {
        let seen = 0;
        res.on("data", (chunk: Buffer) => {
          seen += chunk.length;
          if (seen > RESPONSE_CAP_BYTES) res.destroy();
        });
        const finish = () => {
          const code = res.statusCode ?? 0;
          // 3xx is a failure: a redirect is never followed.
          done(code >= 200 && code < 300 ? { ok: true, statusCode: code } : { ok: false, statusCode: code, errorClass: "http_status" });
        };
        res.on("end", finish);
        res.on("close", finish);
        res.on("error", finish);
      }
    );
    req.on("timeout", () => {
      req.destroy();
      done({ ok: false, errorClass: "timeout" });
    });
    req.on("error", (err: NodeJS.ErrnoException) => done({ ok: false, errorClass: classify(err) }));
    req.end(body);
  });
}

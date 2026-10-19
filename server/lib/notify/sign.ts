import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * `X-Synthaea-Signature: t=<unix>,v1=<hex HMAC-SHA256 of "<t>.<body>">` (ADR-0036 point 5).
 * Every delivery attempt is signed with a fresh `t`, so a retry hours later still passes a
 * receiver's freshness check.
 */
export function signBody(secret: string, body: string, nowSeconds: number): string {
  const mac = createHmac("sha256", secret).update(`${nowSeconds}.${body}`).digest("hex");
  return `t=${nowSeconds},v1=${mac}`;
}

/** What a receiver does; here for the tests and as the reference for the docs. */
export function verifySignature(
  secret: string,
  body: string,
  header: string,
  nowSeconds: number,
  toleranceSeconds = 300
): boolean {
  const m = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(header);
  if (!m) return false;
  const t = Number(m[1]);
  if (Math.abs(nowSeconds - t) > toleranceSeconds) return false;
  const expected = createHmac("sha256", secret).update(`${t}.${body}`).digest();
  return timingSafeEqual(expected, Buffer.from(m[2], "hex"));
}

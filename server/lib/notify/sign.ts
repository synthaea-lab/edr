import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * `X-Synthaea-Signature: t=<unix>,v1=<hex HMAC-SHA256 of "<t>.<body>">` (ADR-0036 point 5).
 * Every delivery attempt is signed with a fresh `t`, so a retry hours later passes a receiver's
 * freshness check.
 *
 * For 24 hours after a rotation the header carries two signatures, `v1=<new>,v1=<old>`, and a
 * receiver accepts either: pass the new secret first, then the one still in its overlap.
 */
export function signBody(secrets: string | readonly string[], body: string, nowSeconds: number): string {
  const list = typeof secrets === "string" ? [secrets] : secrets;
  const macs = list.map((s) => createHmac("sha256", s).update(`${nowSeconds}.${body}`).digest("hex"));
  return `t=${nowSeconds},${macs.map((m) => `v1=${m}`).join(",")}`;
}

/** What a receiver does; here for the tests and as the reference for the docs. */
export function verifySignature(
  secret: string,
  body: string,
  header: string,
  nowSeconds: number,
  toleranceSeconds = 300
): boolean {
  const m = /^t=(\d+)((?:,v1=[0-9a-f]{64})+)$/.exec(header);
  if (!m) return false;
  const t = Number(m[1]);
  if (Math.abs(nowSeconds - t) > toleranceSeconds) return false;
  const expected = createHmac("sha256", secret).update(`${t}.${body}`).digest();
  return m[2]
    .split(",")
    .filter(Boolean)
    .some((part) => timingSafeEqual(expected, Buffer.from(part.slice(3), "hex")));
}

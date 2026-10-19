import { lookup } from "node:dns/promises";
import type { Env } from "./secret";
import { isIP } from "node:net";

/**
 * The SSRF guard of the notification channel (ADR-0036 point 6, #863).
 *
 * A channel URL is chosen by a tenant admin and called by the server, so it must not be
 * a way into the server's own network. The caller resolves the name once with
 * `resolvePublicTarget`, and the HTTP client connects to the returned address (keeping the
 * original `Host` and SNI): a DNS answer that changes between check and connect cannot pass.
 */

export type BlockReason = "scheme" | "port" | "credentials" | "address" | "dns";

export class NotifyBlockedError extends Error {
  constructor(public readonly reason: BlockReason) {
    super(`notification target refused: ${reason}`);
    this.name = "NotifyBlockedError";
  }
}

export interface PublicTarget {
  url: URL;
  /** The validated address the client must connect to. */
  address: string;
  family: 4 | 6;
}

/** Parses a dotted IPv4 string (already normalised by `URL`) into 4 bytes, or null. */
function parseV4(text: string): number[] | null {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  const bytes = parts.map((p) => (/^\d{1,3}$/.test(p) ? Number(p) : NaN));
  return bytes.every((b) => b >= 0 && b <= 255) ? bytes : null;
}

/** Parses an IPv6 string (with `::` and an optional embedded IPv4 tail) into 16 bytes. */
function parseV6(text: string): number[] | null {
  let s = text.toLowerCase();
  const zone = s.indexOf("%");
  if (zone !== -1) s = s.slice(0, zone);
  let tail: number[] = [];
  const lastColon = s.lastIndexOf(":");
  if (s.slice(lastColon + 1).includes(".")) {
    const v4 = parseV4(s.slice(lastColon + 1));
    if (!v4) return null;
    tail = v4;
    s = s.slice(0, lastColon + 1) + "0:0";
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const toGroups = (h: string): number[] | null => {
    if (h === "") return [];
    const out: number[] = [];
    for (const g of h.split(":")) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  const head = toGroups(halves[0]);
  const rest = halves.length === 2 ? toGroups(halves[1]) : [];
  if (!head || !rest) return null;
  let groups: number[];
  if (halves.length === 2) {
    const fill = 8 - head.length - rest.length;
    if (fill < 1) return null;
    groups = [...head, ...new Array<number>(fill).fill(0), ...rest];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;
  const bytes = groups.flatMap((g) => [g >> 8, g & 0xff]);
  if (tail.length === 4) {
    bytes.splice(12, 4, ...tail);
  }
  return bytes;
}

function isPrivateV4(b: number[]): boolean {
  const [a, c, d] = b;
  return (
    a === 0 || // 0.0.0.0/8
    a === 10 ||
    (a === 100 && c >= 64 && c <= 127) || // CGNAT
    a === 127 ||
    (a === 169 && c === 254) || // link-local, cloud metadata
    (a === 172 && c >= 16 && c <= 31) ||
    (a === 192 && c === 0 && d === 0) || // IETF protocol assignments
    (a === 192 && c === 0 && d === 2) || // TEST-NET-1
    (a === 192 && c === 168) ||
    (a === 198 && (c === 18 || c === 19)) || // benchmarking
    (a === 198 && c === 51 && d === 100) || // TEST-NET-2
    (a === 203 && c === 0 && d === 113) || // TEST-NET-3
    a >= 224 // multicast, reserved, broadcast
  );
}

function isPrivateV6(b: number[]): boolean {
  const allZero = (from: number, to: number) => b.slice(from, to).every((x) => x === 0);
  const v4 = (at: number) => b.slice(at, at + 4);
  // ::, ::1 and the IPv4-compatible ::a.b.c.d (judged by the embedded IPv4).
  if (allZero(0, 12)) return b[12] === 0 && b[13] === 0 && b[14] === 0 ? true : isPrivateV4(v4(12));
  // ::ffff:a.b.c.d (IPv4-mapped).
  if (allZero(0, 10) && b[10] === 0xff && b[11] === 0xff) return isPrivateV4(v4(12));
  // 64:ff9b::/96 (NAT64) is judged by the embedded IPv4.
  if (b[0] === 0 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && allZero(4, 12)) {
    return isPrivateV4(v4(12));
  }
  // 2002::/16 (6to4) carries an IPv4 in bytes 2..5.
  if (b[0] === 0x20 && b[1] === 0x02) return isPrivateV4(v4(2));
  return (
    (b[0] & 0xfe) === 0xfc || // fc00::/7 unique-local (includes the IPv6 metadata address)
    (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) || // fe80::/10 link-local
    (b[0] === 0xfe && (b[1] & 0xc0) === 0xc0) || // fec0::/10 site-local (deprecated)
    b[0] === 0xff || // multicast
    (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) || // documentation
    (b[0] === 0x01 && allZero(1, 8)) // 100::/64 discard
  );
}

/** True when the address is not one a tenant-chosen URL may reach. Unparseable means true. */
export function isPrivateAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) {
    const b = parseV4(address);
    return !b || isPrivateV4(b);
  }
  if (family === 6) {
    const b = parseV6(address);
    return !b || isPrivateV6(b);
  }
  return true;
}

export interface GuardOptions {
  /** Ports allowed besides 443 (the server's explicit allowlist). */
  extraPorts?: ReadonlySet<number>;
  /** Hostnames a server operator allowed to resolve to private addresses (NOTIFY_ALLOWED_PRIVATE_HOSTS). */
  allowedPrivateHosts?: ReadonlySet<string>;
  /** Injected for tests; defaults to the system resolver. */
  resolve?: (host: string) => Promise<string[]>;
}

async function systemResolve(host: string): Promise<string[]> {
  const answers = await lookup(host, { all: true, verbatim: true });
  return answers.map((a) => a.address);
}

/** Parses `NOTIFY_ALLOWED_PRIVATE_HOSTS` and `NOTIFY_ALLOWED_PORTS` (comma-separated). */
export function guardOptionsFromEnv(env: Env = process.env): GuardOptions {
  const list = (v: string | undefined) =>
    (v ?? "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  return {
    allowedPrivateHosts: new Set(list(env.NOTIFY_ALLOWED_PRIVATE_HOSTS)),
    extraPorts: new Set(list(env.NOTIFY_ALLOWED_PORTS).map(Number).filter((n) => n > 0 && n < 65536)),
  };
}

/**
 * Checks the URL syntactically, resolves its host once and checks every answer.
 * Throws `NotifyBlockedError`; the reason is for the server log, not for the tenant.
 */
export async function resolvePublicTarget(raw: string, opts: GuardOptions = {}): Promise<PublicTarget> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new NotifyBlockedError("scheme");
  }
  if (url.protocol !== "https:") throw new NotifyBlockedError("scheme");
  if (url.username || url.password) throw new NotifyBlockedError("credentials");
  const port = url.port === "" ? 443 : Number(url.port);
  if (port !== 443 && !opts.extraPorts?.has(port)) throw new NotifyBlockedError("port");

  // `URL` has already folded decimal, octal and hex IPv4 forms to dotted decimal.
  const host = url.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  const allowPrivate = opts.allowedPrivateHosts?.has(host) ?? false;

  let addresses: string[];
  if (isIP(host)) {
    addresses = [host];
  } else {
    try {
      addresses = await (opts.resolve ?? systemResolve)(host);
    } catch {
      throw new NotifyBlockedError("dns");
    }
    if (addresses.length === 0) throw new NotifyBlockedError("dns");
  }
  if (!allowPrivate && addresses.some(isPrivateAddress)) throw new NotifyBlockedError("address");

  const address = addresses[0];
  return { url, address, family: isIP(address) === 6 ? 6 : 4 };
}

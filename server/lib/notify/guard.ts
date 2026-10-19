import { Resolver } from "node:dns/promises";
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
  /** Every validated address, in the order the resolver gave them: the client tries them in turn. */
  addresses: { address: string; family: 4 | 6 }[];
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

/**
 * The ranges a tenant-chosen URL may not reach, taken from the IANA special-purpose address
 * registries (IPv4: iana.org/assignments/iana-ipv4-special-registry, IPv6:
 * iana.org/assignments/iana-ipv6-special-registry; read 2026-10-19) and not only from the ADR's
 * list, which is a minimum. Every entry that is not globally reachable is here, and so are the
 * few that are (the AS112 and AMT anycast prefixes, the PCP and TURN anycast addresses): no
 * webhook receiver lives there, so refusing them costs nothing and keeps the table simple. An
 * address that embeds an IPv4 (mapped, translated, NAT64, 6to4, IPv4-compatible) is judged by
 * the IPv4 it embeds; the 2001::/23 block (IETF protocol assignments, Teredo included) is
 * refused as a whole.
 */
export const SPECIAL_V4_CIDRS = [
  "0.0.0.0/8", // "this network", 0.0.0.0/32 included
  "10.0.0.0/8", // private
  "100.64.0.0/10", // shared address space (CGNAT)
  "127.0.0.0/8", // loopback
  "169.254.0.0/16", // link-local, the cloud metadata address
  "172.16.0.0/12", // private
  "192.0.0.0/24", // IETF protocol assignments
  "192.0.2.0/24", // documentation (TEST-NET-1)
  "192.31.196.0/24", // AS112-v4
  "192.52.193.0/24", // AMT
  "192.88.99.0/24", // 6to4 relay anycast (deprecated)
  "192.168.0.0/16", // private
  "192.175.48.0/24", // direct delegation AS112
  "198.18.0.0/15", // benchmarking
  "198.51.100.0/24", // documentation (TEST-NET-2)
  "203.0.113.0/24", // documentation (TEST-NET-3)
  "224.0.0.0/4", // multicast
  "240.0.0.0/4", // reserved, 255.255.255.255/32 (limited broadcast) included
] as const;

export const SPECIAL_V6_CIDRS = [
  "::/128", // unspecified
  "::1/128", // loopback
  "100::/64", // discard-only
  "100:0:0:1::/64", // dummy IPv6 prefix
  "2001::/23", // IETF protocol assignments: Teredo 2001::/32, benchmarking, AMT, AS112, ORCHID, drone ID
  "2001:db8::/32", // documentation
  "3fff::/20", // documentation (RFC 9637)
  "5f00::/16", // SRv6 SIDs
  "64:ff9b:1::/48", // NAT64 local-use
  "fc00::/7", // unique local (the IPv6 metadata address included)
  "fe80::/10", // link-local
  "fec0::/10", // site-local (deprecated)
  "ff00::/8", // multicast
] as const;

function parseCidr4(cidr: string): { base: number; mask: number } {
  const [addr, len] = cidr.split("/");
  const b = parseV4(addr)!;
  const base = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
  const bits = Number(len);
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { base: (base & mask) >>> 0, mask };
}

function parseCidr6(cidr: string): { bytes: number[]; bits: number } {
  const [addr, len] = cidr.split("/");
  return { bytes: parseV6(addr)!, bits: Number(len) };
}

const V4_TABLE = SPECIAL_V4_CIDRS.map(parseCidr4);
const V6_TABLE = SPECIAL_V6_CIDRS.map(parseCidr6);

function inV6(b: number[], c: { bytes: number[]; bits: number }): boolean {
  let left = c.bits;
  for (let i = 0; left > 0; i++, left -= 8) {
    const mask = left >= 8 ? 0xff : (0xff << (8 - left)) & 0xff;
    if ((b[i] & mask) !== (c.bytes[i] & mask)) return false;
  }
  return true;
}

function isPrivateV4(b: number[]): boolean {
  const n = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
  return V4_TABLE.some((c) => ((n & c.mask) >>> 0) === c.base);
}

function isPrivateV6(b: number[]): boolean {
  const allZero = (from: number, to: number) => b.slice(from, to).every((x) => x === 0);
  const v4 = (at: number) => b.slice(at, at + 4);
  // ::a.b.c.d (IPv4-compatible, deprecated) and ::, ::1 — the unspecified and loopback addresses
  // are refused outright, the rest is judged by the IPv4 it embeds.
  if (allZero(0, 12)) return b[12] === 0 && b[13] === 0 && b[14] === 0 ? true : isPrivateV4(v4(12));
  // ::ffff:a.b.c.d (IPv4-mapped).
  if (allZero(0, 10) && b[10] === 0xff && b[11] === 0xff) return isPrivateV4(v4(12));
  // ::ffff:0:a.b.c.d (IPv4-translated, deprecated).
  if (allZero(0, 8) && b[8] === 0xff && b[9] === 0xff && b[10] === 0 && b[11] === 0) return isPrivateV4(v4(12));
  // 64:ff9b::/96 (NAT64): the IPv4 it embeds. (64:ff9b:1::/48 is in the table, refused whole.)
  if (b[0] === 0 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && allZero(4, 12)) return isPrivateV4(v4(12));
  // 2002::/16 (6to4) carries an IPv4 in bytes 2..5.
  if (b[0] === 0x20 && b[1] === 0x02) return isPrivateV4(v4(2));
  return V6_TABLE.some((c) => inV6(b, c));
}

/** True when the address is not one a tenant-chosen URL may reach. Unparseable means true. */
export function isPrivateAddress(address: string): boolean {
  if (isMetadataAddress(address)) return true;
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

/**
 * Cloud metadata services that sit outside the ranges above or inside a range an allowlist may
 * open: AWS IPv6 (`fd00:ec2::254`, in fc00::/7), Alibaba (`100.100.100.200`, in CGNAT), Oracle
 * (`192.0.0.192`) and Azure's WireServer (`168.63.129.16`, a public address). They are refused
 * for everyone, allowlisted or not; 169.254.169.254 and the ECS task endpoint are link-local.
 */
export const METADATA_ADDRESSES = ["fd00:ec2::254", "100.100.100.200", "192.0.0.192", "168.63.129.16"] as const;

function isMetadataAddress(address: string): boolean {
  const family = isIP(address);
  const key = (a: string) => (isIP(a) === 6 ? (parseV6(a) ?? []).join(".") : (parseV4(a) ?? []).join("."));
  const target = key(address);
  if (!target) return false;
  if (METADATA_ADDRESSES.some((m) => key(m) === target)) return true;
  // The same addresses reached through a mapped, translated, NAT64 or 6to4 form.
  if (family === 6) {
    const b = parseV6(address);
    if (b) {
      const embedded =
        (b.slice(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff) ||
        (b.slice(0, 8).every((x) => x === 0) && b[8] === 0xff && b[9] === 0xff && b[10] === 0 && b[11] === 0) ||
        (b[0] === 0 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && b.slice(4, 12).every((x) => x === 0))
          ? b.slice(12, 16)
          : b[0] === 0x20 && b[1] === 0x02
            ? b.slice(2, 6)
            : null;
      if (embedded) return METADATA_ADDRESSES.some((m) => isIP(m) === 4 && key(m) === embedded.join("."));
    }
  }
  return false;
}

/**
 * Addresses no allowlist can open: loopback, link-local (the cloud metadata address included) and
 * the unspecified address, judged by the embedded IPv4 for the mapped, compatible, NAT64 and
 * 6to4 forms. The operator allowlist (`NOTIFY_ALLOWED_PRIVATE_HOSTS`) is for an on-prem receiver
 * on a private network, not for the server's own host or its metadata service.
 */
export function isNeverAllowed(address: string): boolean {
  if (isMetadataAddress(address)) return true;
  const family = isIP(address);
  const v4 = (b: number[]) => b[0] === 0 || b[0] === 127 || (b[0] === 169 && b[1] === 254);
  if (family === 4) {
    const b = parseV4(address);
    return !b || v4(b);
  }
  if (family === 6) {
    const b = parseV6(address);
    if (!b) return true;
    const allZero = (from: number, to: number) => b.slice(from, to).every((x) => x === 0);
    if (allZero(0, 12)) return b[12] === 0 && b[13] === 0 && b[14] === 0 ? b[15] <= 1 : v4(b.slice(12));
    if (allZero(0, 10) && b[10] === 0xff && b[11] === 0xff) return v4(b.slice(12));
    if (b[0] === 0 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && allZero(4, 12)) return v4(b.slice(12));
    if (b[0] === 0x20 && b[1] === 0x02) return v4(b.slice(2, 6));
    return (b[0] === 0xfe && (b[1] & 0xc0) === 0x80); // fe80::/10
  }
  return true;
}

export interface GuardOptions {
  /**
   * Tests only: lets an allowlisted host resolve to loopback, which production never allows.
   * Not read from the environment.
   */
  unsafeAllowLoopbackForTests?: boolean;
  /** Ports allowed besides 443 (the server's explicit allowlist). */
  extraPorts?: ReadonlySet<number>;
  /**
   * `<tenant id>:<host>` entries a server operator allowed to resolve to private addresses
   * (NOTIFY_ALLOWED_PRIVATE_HOSTS, ADR-0036 point 6): a tenant cannot aim a channel at another
   * tenant's on-prem host, and there is no wildcard tenant.
   */
  allowedPrivateHosts?: ReadonlySet<string>;
  /** The tenant the channel belongs to; without it no private host is allowed. */
  tenantId?: string;
  /** Injected for tests; defaults to the system resolver. */
  resolve?: (host: string) => Promise<string[]>;
}

/**
 * The default resolver. It is c-ares (`dns.Resolver`) with its own timeout and retry count, not
 * `dns.lookup`: `getaddrinfo` cannot be cancelled and holds one of libuv's four threads until it
 * answers, so eight tenants with black-holed names could stall every other lookup in the process
 * past the send's 10 s deadline. The cost: c-ares reads `resolv.conf` but not `/etc/hosts`, so an
 * allowlisted on-prem name has to be in DNS (or be an IP literal, which needs no lookup).
 */
async function systemResolve(host: string): Promise<string[]> {
  const resolver = new Resolver({ timeout: 1500, tries: 2 });
  const [v4, v6] = await Promise.allSettled([resolver.resolve4(host), resolver.resolve6(host)]);
  const found = [...(v4.status === "fulfilled" ? v4.value : []), ...(v6.status === "fulfilled" ? v6.value : [])];
  if (found.length === 0) throw v4.status === "rejected" ? v4.reason : new Error("no address");
  return found;
}

/**
 * Parses `NOTIFY_ALLOWED_PRIVATE_HOSTS` (comma-separated `<tenant id>:<host>`; an entry with no
 * tenant, or a `*` tenant, is ignored) and `NOTIFY_ALLOWED_PORTS` (comma-separated).
 */
export function guardOptionsFromEnv(env: Env = process.env): GuardOptions {
  const list = (v: string | undefined) =>
    (v ?? "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  return {
    allowedPrivateHosts: new Set(
      list(env.NOTIFY_ALLOWED_PRIVATE_HOSTS).filter((e) => {
        const i = e.indexOf(":");
        return i > 0 && e.slice(0, i) !== "*" && i < e.length - 1;
      })
    ),
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
  const allowPrivate = !!opts.tenantId && (opts.allowedPrivateHosts?.has(`${opts.tenantId.toLowerCase()}:${host}`) ?? false);

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
  // An allowlisted private host is still never the server's own loopback, link-local or metadata address.
  if (allowPrivate && !opts.unsafeAllowLoopbackForTests && addresses.some(isNeverAllowed)) {
    throw new NotifyBlockedError("address");
  }

  return { url, addresses: addresses.map((address) => ({ address, family: isIP(address) === 6 ? 6 : 4 })) };
}

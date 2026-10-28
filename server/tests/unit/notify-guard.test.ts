import { describe, it, expect } from "vitest";
import {
  guardOptionsFromEnv,
  isNeverAllowed,
  isPrivateAddress,
  resolvePublicTarget,
  NotifyBlockedError,
  SPECIAL_V4_CIDRS,
  SPECIAL_V6_CIDRS,
} from "@/lib/notify/guard";

const pub = async () => ["93.184.216.34"];

describe("isPrivateAddress", () => {
  it.each([
    "127.0.0.1", "0.0.0.0", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
    "169.254.169.254", "100.64.0.1", "100.127.255.255", "224.0.0.1", "255.255.255.255",
    "::1", "::", "fe80::1", "fc00::1", "fd00:ec2::254", "ff02::1",
    "::ffff:127.0.0.1", "::ffff:7f00:1", "::127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::1",
    "2001:db8::1",
    "2001:0:4136:e378:8000:63bf:3fff:fdd2", // Teredo 2001::/32, refused outright
    "2001::1",
    "64:ff9b:1::1", // NAT64 local-use prefix
    "64:ff9b:1:abcd::8.8.8.8",
    "192.88.99.1", // 6to4 relay anycast
    "::ffff:192.88.99.1",
  ])("refuses %s", (a) => expect(isPrivateAddress(a)).toBe(true));

  it.each(["93.184.216.34", "8.8.8.8", "172.32.0.1", "100.128.0.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"])(
    "accepts %s",
    (a) => expect(isPrivateAddress(a)).toBe(false)
  );

  it("refuses what it cannot parse", () => {
    expect(isPrivateAddress("not-an-ip")).toBe(true);
  });
});

describe("the special-purpose ranges (IANA registries, ADR-0036 point 6: the ADR's list is a minimum)", () => {
  const v4 = (n: number) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
  const edges4 = (cidr: string) => {
    const [a, len] = cidr.split("/");
    const n = a.split(".").reduce((x, o) => ((x << 8) | Number(o)) >>> 0, 0);
    const mask = len === "0" ? 0 : (0xffffffff << (32 - Number(len))) >>> 0;
    const first = (n & mask) >>> 0;
    return [v4(first), v4((first | (~mask >>> 0)) >>> 0)];
  };
  const edges6 = (cidr: string) => {
    const [addr, len] = cidr.split("/");
    // Expand through the URL parser's normal form: ::-compressed groups to 8 groups.
    const [head, tail = ""] = addr.split("::");
    const hg = head ? head.split(":") : [];
    const tg = tail ? tail.split(":") : [];
    const groups = [...hg, ...Array(8 - hg.length - tg.length).fill("0"), ...tg].map((g) => parseInt(g, 16));
    const bytes = groups.flatMap((g) => [g >> 8, g & 255]);
    const lo = bytes.map((b, i) => (i * 8 + 8 <= Number(len) ? b : i * 8 >= Number(len) ? 0 : b & (0xff << (8 - (Number(len) - i * 8))) & 0xff));
    const hi = bytes.map((b, i) => (i * 8 + 8 <= Number(len) ? b : i * 8 >= Number(len) ? 255 : (b & (0xff << (8 - (Number(len) - i * 8))) & 0xff) | (0xff >> (Number(len) - i * 8))));
    const text = (x: number[]) => Array.from({ length: 8 }, (_, g) => ((x[g * 2] << 8) | x[g * 2 + 1]).toString(16)).join(":");
    return [text(lo), text(hi)];
  };

  it.each(SPECIAL_V4_CIDRS)("refuses the first and the last address of %s", (cidr) => {
    for (const a of edges4(cidr)) expect(isPrivateAddress(a), a).toBe(true);
  });
  it.each(SPECIAL_V6_CIDRS)("refuses the first and the last address of %s", (cidr) => {
    for (const a of edges6(cidr)) expect(isPrivateAddress(a), a).toBe(true);
  });

  // Typed out from the registries (not read from the table above), so that dropping a row from the
  // table is caught: the first and the last address of each entry must be refused.
  const IANA_V4 = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.0.0.0/29", "192.0.0.8/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24",
    "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16", "192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32", "224.0.0.0/4",
  ];
  const IANA_V6 = [
    "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "100:0:0:1::/64", "2001::/23",
    "2001::/32", "2001:1::1/128", "2001:1::2/128", "2001:2::/48", "2001:3::/32", "2001:4:112::/48", "2001:10::/28",
    "2001:20::/28", "2001:30::/28", "2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10",
    "fec0::/10", "ff00::/8",
  ];
  it.each(IANA_V4)("the registry's %s is refused at both ends", (cidr) => {
    for (const a of edges4(cidr)) expect(isPrivateAddress(a), a).toBe(true);
  });
  it.each(IANA_V6)("the registry's %s is refused at both ends", (cidr) => {
    for (const a of edges6(cidr)) expect(isPrivateAddress(a), a).toBe(true);
  });

  it.each(["2001:db8::/32", "198.18.0.0/15", "192.0.0.0/24", "240.0.0.0/4", "::/128", "0.0.0.0/32", "255.255.255.255/32"])(
    "old-dov's examples: %s",
    (cidr) => {
      const a = cidr.split("/")[0];
      expect(isPrivateAddress(a)).toBe(true);
    }
  );

  it.each([
    "9.255.255.255", "11.0.0.0", "100.63.255.255", "100.128.0.0", "126.255.255.255", "128.0.0.0", "169.253.255.255",
    "169.255.0.0", "172.15.255.255", "172.32.0.0", "192.0.1.1", "192.0.3.1", "192.167.255.255", "192.169.0.0",
    "198.17.255.255", "198.20.0.0", "198.51.99.1", "198.51.101.1", "203.0.112.255", "203.0.114.0", "223.255.255.255",
    "2001:200::1", "2001:da8::1", "2001:db9::1", "2400::1", "2606:4700::1", "2a00::1", "3ffe::1", "3fff:1000::1",
    "5e00::1", "5f01::1", "fbff::1",
  ])("accepts the public neighbour %s", (a) => expect(isPrivateAddress(a)).toBe(false));

  it("judges 6to4, NAT64, mapped and translated forms by the IPv4 they embed", () => {
    expect(isPrivateAddress("2002:0808:0808::1")).toBe(false); // 8.8.8.8
    expect(isPrivateAddress("2002:c0a8:0101::1")).toBe(true); // 192.168.1.1
    expect(isPrivateAddress("64:ff9b::808:808")).toBe(false);
    expect(isPrivateAddress("64:ff9b::c0a8:101")).toBe(true);
    expect(isPrivateAddress("::ffff:8.8.8.8")).toBe(false);
    expect(isPrivateAddress("::ffff:0:192.168.1.1")).toBe(true); // IPv4-translated
  });
});

describe("resolvePublicTarget", () => {
  const blocked = async (url: string, reason: string, opts = {}) => {
    const err = await resolvePublicTarget(url, { resolve: pub, ...opts }).catch((e) => e);
    expect(err).toBeInstanceOf(NotifyBlockedError);
    expect(err.reason).toBe(reason);
  };

  it("accepts https on 443 and returns the validated address", async () => {
    const t = await resolvePublicTarget("https://hooks.example.com/x", { resolve: pub });
    expect(t.addresses).toEqual([{ address: "93.184.216.34", family: 4 }]);
  });

  it("refuses other schemes, credentials and ports", async () => {
    await blocked("http://hooks.example.com/", "scheme");
    await blocked("ftp://hooks.example.com/", "scheme");
    await blocked("nonsense", "scheme");
    await blocked("https://u:p@hooks.example.com/", "credentials");
    await blocked("https://hooks.example.com:8443/", "port");
  });

  it("allows a port the server operator listed", async () => {
    const t = await resolvePublicTarget("https://hooks.example.com:8443/", {
      resolve: pub,
      extraPorts: new Set([8443]),
    });
    expect(t.url.port).toBe("8443");
  });

  it("refuses IP literals in decimal, octal, hex and bracketed forms", async () => {
    await blocked("https://2130706433/", "address"); // 127.0.0.1
    await blocked("https://0177.0.0.1/", "address");
    await blocked("https://0x7f.1/", "address");
    await blocked("https://[::1]/", "address");
    await blocked("https://[::ffff:127.0.0.1]/", "address");
    await blocked("https://169.254.169.254/", "address");
  });

  it("refuses a name that resolves to a private address, even among public ones", async () => {
    await blocked("https://rebind.example.com/", "address", { resolve: async () => ["93.184.216.34", "10.0.0.5"] });
    await blocked("https://meta.example.com/", "address", { resolve: async () => ["169.254.169.254"] });
  });

  it("reports an unresolvable name as dns", async () => {
    await blocked("https://nope.example.com/", "dns", { resolve: async () => { throw new Error("ENOTFOUND"); } });
    await blocked("https://empty.example.com/", "dns", { resolve: async () => [] });
  });

  it("lets an operator-listed private host through, for the tenant it is listed for and only that host", async () => {
    const allowed = new Set(["t1:soar.corp.example"]);
    const t = await resolvePublicTarget("https://soar.corp.example/", {
      resolve: async () => ["10.1.1.1"],
      allowedPrivateHosts: allowed,
      tenantId: "t1",
    });
    expect(t.addresses[0].address).toBe("10.1.1.1");
    // Another host, another tenant, or no tenant at all: refused.
    await blocked("https://other.corp.example/", "address", { resolve: async () => ["10.1.1.1"], allowedPrivateHosts: allowed, tenantId: "t1" });
    await blocked("https://soar.corp.example/", "address", { resolve: async () => ["10.1.1.1"], allowedPrivateHosts: allowed, tenantId: "t2" });
    await blocked("https://soar.corp.example/", "address", { resolve: async () => ["10.1.1.1"], allowedPrivateHosts: allowed });
  });
});

describe("an allowlisted private host is still never the server's own loopback, link-local or metadata address", () => {
  const opts = (answer: string[]) => ({ resolve: async () => answer, allowedPrivateHosts: new Set(["t1:soar.corp.example"]), tenantId: "t1" });
  it.each(["127.0.0.1", "127.9.9.9", "::1", "169.254.169.254", "169.254.0.5", "fe80::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "0.0.0.0", "::", "64:ff9b::7f00:1", "2002:7f00:1::1"])(
    "refuses %s even for an allowlisted name",
    async (address) => {
      const err = await resolvePublicTarget("https://soar.corp.example/", opts([address])).catch((e) => e);
      expect(err).toBeInstanceOf(NotifyBlockedError);
      expect(err.reason).toBe("address");
    }
  );
  it.each([
    "fd00:ec2::254", // AWS IPv6 metadata, inside fc00::/7
    "100.100.100.200", // Alibaba, inside CGNAT
    "192.0.0.192", // Oracle
    "168.63.129.16", // Azure WireServer, a public address
    "::ffff:100.100.100.200",
    "64:ff9b::6464:64c8", // NAT64 form of 100.100.100.200
    "2002:6464:64c8::1", // 6to4 form of 100.100.100.200
  ])("refuses the cloud metadata address %s even for an allowlisted name", async (address) => {
    const err = await resolvePublicTarget("https://soar.corp.example/", opts([address])).catch((e) => e);
    expect(err).toBeInstanceOf(NotifyBlockedError);
    expect(err.reason).toBe("address");
  });
  it("and for everyone else: the metadata addresses are refused as private, Azure's public one included", () => {
    for (const a of ["fd00:ec2::254", "100.100.100.200", "192.0.0.192", "168.63.129.16"]) expect(isPrivateAddress(a)).toBe(true);
    expect(isPrivateAddress("168.63.129.17")).toBe(false);
    expect(isNeverAllowed("168.63.129.16")).toBe(true);
    expect(isNeverAllowed("fd00:ec2::255")).toBe(false); // a neighbour in fc00::/7 is private, not never-allowed
  });
  it.each(["10.1.1.1", "172.16.4.4", "192.168.7.7", "fd12:3456::1", "100.64.1.1"])("still lets %s through for the allowlisted name", async (address) => {
    const t = await resolvePublicTarget("https://soar.corp.example/", opts([address]));
    expect(t.addresses[0].address).toBe(address);
  });
  it("a name that returns a private and a loopback address is refused as a whole", async () => {
    const err = await resolvePublicTarget("https://soar.corp.example/", opts(["10.1.1.1", "127.0.0.1"])).catch((e) => e);
    expect(err).toBeInstanceOf(NotifyBlockedError);
  });
  it("isNeverAllowed on its own", () => {
    expect(isNeverAllowed("10.0.0.1")).toBe(false);
    expect(isNeverAllowed("8.8.8.8")).toBe(false);
    expect(isNeverAllowed("169.254.169.254")).toBe(true);
    expect(isNeverAllowed("not-an-ip")).toBe(true);
  });
  it("returns every validated address, not only the first", async () => {
    const t = await resolvePublicTarget("https://hooks.example.com/", { resolve: async () => ["93.184.216.34", "2606:4700:4700::1111"] });
    expect(t.addresses.map((a) => a.address)).toEqual(["93.184.216.34", "2606:4700:4700::1111"]);
    expect(t.addresses.map((a) => a.family)).toEqual([4, 6]);
  });
});

describe("guardOptionsFromEnv", () => {
  it("reads <tenant>:<host> entries and ignores a wildcard tenant or an entry with no tenant", () => {
    const o = guardOptionsFromEnv({
      NOTIFY_ALLOWED_PRIVATE_HOSTS: "T1:SOAR.corp.example, *:everyone.example, bare.example, t2:, :nohost, t3:b.example",
      NOTIFY_ALLOWED_PORTS: "9443, 70000, x",
    });
    expect(Array.from(o.allowedPrivateHosts!).sort()).toEqual(["t1:soar.corp.example", "t3:b.example"]);
    expect(Array.from(o.extraPorts!)).toEqual([9443]);
  });
});

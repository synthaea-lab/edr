import { describe, it, expect } from "vitest";
import { guardOptionsFromEnv, isPrivateAddress, resolvePublicTarget, NotifyBlockedError } from "@/lib/notify/guard";

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
  ])("refuses %s", (a) => expect(isPrivateAddress(a)).toBe(true));

  it.each(["93.184.216.34", "8.8.8.8", "172.32.0.1", "100.128.0.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"])(
    "accepts %s",
    (a) => expect(isPrivateAddress(a)).toBe(false)
  );

  it("refuses what it cannot parse", () => {
    expect(isPrivateAddress("not-an-ip")).toBe(true);
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
    expect(t.address).toBe("93.184.216.34");
    expect(t.family).toBe(4);
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
    expect(t.address).toBe("10.1.1.1");
    // Another host, another tenant, or no tenant at all: refused.
    await blocked("https://other.corp.example/", "address", { resolve: async () => ["10.1.1.1"], allowedPrivateHosts: allowed, tenantId: "t1" });
    await blocked("https://soar.corp.example/", "address", { resolve: async () => ["10.1.1.1"], allowedPrivateHosts: allowed, tenantId: "t2" });
    await blocked("https://soar.corp.example/", "address", { resolve: async () => ["10.1.1.1"], allowedPrivateHosts: allowed });
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

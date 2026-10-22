import { describe, it, expect } from "vitest";
import { signBody, verifySignature } from "@/lib/notify/sign";
import { sealSecret, openSecret, sealUrl, openUrl } from "@/lib/notify/secret";

const K1 = "k1:" + "11".repeat(32);
const K2 = "k2:" + "22".repeat(32);

describe("signBody", () => {
  it("is verifiable and bound to the body, the secret and the time", () => {
    const h = signBody("s3", '{"a":1}', 1000);
    expect(h).toMatch(/^t=1000,v1=[0-9a-f]{64}$/);
    expect(verifySignature("s3", '{"a":1}', h, 1000)).toBe(true);
    expect(verifySignature("s3", '{"a":2}', h, 1000)).toBe(false);
    expect(verifySignature("other", '{"a":1}', h, 1000)).toBe(false);
  });

  it("rejects a replay outside the window, and malformed headers", () => {
    const h = signBody("s3", "{}", 1000);
    expect(verifySignature("s3", "{}", h, 1000 + 301)).toBe(false);
    expect(verifySignature("s3", "{}", h, 1000 + 299)).toBe(true);
    expect(verifySignature("s3", "{}", "t=1000", 1000)).toBe(false);
  });

  it("gives a different signature on each attempt for the same body", () => {
    expect(signBody("s3", "{}", 1000)).not.toBe(signBody("s3", "{}", 1001));
  });
});

describe("signature overlap after a rotation", () => {
  it("carries two v1= values and either secret verifies it", () => {
    const h = signBody(["new-secret", "old-secret"], "{}", 1000);
    expect(h.match(/v1=/g)).toHaveLength(2);
    expect(verifySignature("new-secret", "{}", h, 1000)).toBe(true);
    expect(verifySignature("old-secret", "{}", h, 1000)).toBe(true);
    expect(verifySignature("third", "{}", h, 1000)).toBe(false);
  });

  it("is the single-signature header when only one secret signs", () => {
    expect(signBody(["only"], "{}", 1000)).toBe(signBody("only", "{}", 1000));
  });
});

describe("sealUrl / openUrl", () => {
  it("round-trips, keeps the URL out of the ciphertext and is bound to its channel", () => {
    const url = "https://hooks.slack.example/services/T000/B000/SECRETPATH";
    const sealed = sealUrl(url, "chan-1", { NOTIFY_SECRET_KEY: K1 })!;
    expect(Buffer.from(sealed.sealed, "base64").toString("utf8")).not.toContain("SECRETPATH");
    expect(openUrl(sealed, "chan-1", { NOTIFY_SECRET_KEY: K1 })).toBe(url);
    expect(openUrl(sealed, "chan-2", { NOTIFY_SECRET_KEY: K1 })).toBeNull();
  });

  it("a ciphertext cannot be moved between the URL and the secret column", () => {
    const env = { NOTIFY_SECRET_KEY: K1 };
    const asUrl = sealUrl("https://a.example/", "chan-1", env)!;
    const asSecret = sealSecret("whsec_x", "chan-1", env)!;
    expect(openSecret(asUrl, "chan-1", env)).toBeNull();
    expect(openUrl(asSecret, "chan-1", env)).toBeNull();
  });
});

describe("sealSecret / openSecret", () => {
  it("round-trips and never stores the secret in clear", () => {
    const sealed = sealSecret("whsec_abc", "chan-1", { NOTIFY_SECRET_KEY: K1 })!;
    expect(sealed.keyId).toBe("k1");
    expect(Buffer.from(sealed.sealed, "base64").toString("utf8")).not.toContain("whsec_abc");
    expect(openSecret(sealed, "chan-1", { NOTIFY_SECRET_KEY: K1 })).toBe("whsec_abc");
  });

  it("is bound to the channel id", () => {
    const sealed = sealSecret("whsec_abc", "chan-1", { NOTIFY_SECRET_KEY: K1 })!;
    expect(openSecret(sealed, "chan-2", { NOTIFY_SECRET_KEY: K1 })).toBeNull();
  });

  it("detects tampering", () => {
    const sealed = sealSecret("whsec_abc", "chan-1", { NOTIFY_SECRET_KEY: K1 })!;
    const raw = Buffer.from(sealed.sealed, "base64");
    raw[raw.length - 1] ^= 1;
    expect(openSecret({ ...sealed, sealed: raw.toString("base64") }, "chan-1", { NOTIFY_SECRET_KEY: K1 })).toBeNull();
  });

  it("rotates: the new key seals, the previous one still opens old rows", () => {
    const old = sealSecret("whsec_abc", "chan-1", { NOTIFY_SECRET_KEY: K1 })!;
    const env = { NOTIFY_SECRET_KEY: K2, NOTIFY_SECRET_KEY_PREVIOUS: K1 };
    expect(openSecret(old, "chan-1", env)).toBe("whsec_abc");
    expect(sealSecret("x", "chan-1", env)!.keyId).toBe("k2");
    expect(openSecret(old, "chan-1", { NOTIFY_SECRET_KEY: K2 })).toBeNull();
  });

  it("refuses to seal when no valid key is configured", () => {
    expect(sealSecret("x", "c", {})).toBeNull();
    expect(sealSecret("x", "c", { NOTIFY_SECRET_KEY: "k1:short" })).toBeNull();
  });
});

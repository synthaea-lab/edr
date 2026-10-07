import { describe, expect, it } from "vitest";
import {
  DECOY_TOKEN_PREFIX,
  DecoyRegistration,
  MAX_DECOY_TOKENS_PER_AGENT,
  bearerToken,
  clientAddress,
  hashToken,
  looksLikeDecoy,
} from "@/lib/decoy";

describe("decoy token helpers", () => {
  it("takes the token of a Bearer header and nothing else", () => {
    expect(bearerToken("Bearer abc")).toBe("abc");
    expect(bearerToken("bearer abc")).toBeNull();
    expect(bearerToken("Basic abc")).toBeNull();
    expect(bearerToken("Bearer a b")).toBeNull();
    expect(bearerToken(null)).toBeNull();
  });

  it("only treats a prefixed, bounded token as decoy-shaped", () => {
    expect(looksLikeDecoy(`${DECOY_TOKEN_PREFIX}abc`)).toBe(true);
    expect(looksLikeDecoy("abc")).toBe(false);
    expect(looksLikeDecoy(null)).toBe(false);
    expect(looksLikeDecoy(DECOY_TOKEN_PREFIX + "x".repeat(300))).toBe(false);
  });

  it("hashes to the lowercase SHA-256 hex the agent sends", () => {
    expect(hashToken("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
  });

  it("hashes a decoy token to the value the agent computes (crates/deception, plan.rs)", () => {
    expect(hashToken("syn_dk_0123456789abcdef0123456789abcdef")).toBe(
      "a4f205745e0254733ec14acd490bab0ec51dfcb67eede6fce2c02397f4064f87"
    );
  });

  it("accepts only 64-hex hashes and a bounded count", () => {
    const hash = "a".repeat(64);
    expect(DecoyRegistration.safeParse({ tokens: [hash] }).success).toBe(true);
    expect(DecoyRegistration.safeParse({ tokens: ["A".repeat(64)] }).success).toBe(false);
    expect(DecoyRegistration.safeParse({ tokens: ["abc"] }).success).toBe(false);
    expect(DecoyRegistration.safeParse({ tokens: [`${DECOY_TOKEN_PREFIX}real-token`] }).success).toBe(false);
    expect(
      DecoyRegistration.safeParse({ tokens: Array(MAX_DECOY_TOKENS_PER_AGENT + 1).fill(hash) })
        .success
    ).toBe(false);
  });

  it("prefers X-Real-IP and otherwise the last X-Forwarded-For hop", () => {
    const h = (init: Record<string, string>) => new Headers(init);
    expect(clientAddress(h({ "x-real-ip": "192.0.2.1", "x-forwarded-for": "6.6.6.6" }))).toBe("192.0.2.1");
    expect(clientAddress(h({ "x-forwarded-for": "6.6.6.6, 7.7.7.7, 192.0.2.2" }))).toBe("192.0.2.2");
    expect(clientAddress(h({ "x-forwarded-for": "192.0.2.3" }))).toBe("192.0.2.3");
    expect(clientAddress(h({}))).toBeNull();
    expect(clientAddress(h({ "x-forwarded-for": " , " }))).toBeNull();
  });

  it("bounds the echoed address", () => {
    const long = "1".repeat(500);
    expect(clientAddress(new Headers({ "x-real-ip": long }))?.length).toBe(200);
  });
});

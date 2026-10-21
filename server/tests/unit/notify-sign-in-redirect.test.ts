import { describe, expect, it } from "vitest";
import { isSignInRedirect } from "@/lib/notify/sign-in-redirect";

describe("isSignInRedirect", () => {
  it("recognises a fetch that ended on the sign-in page", () => {
    expect(isSignInRedirect({ redirected: true, url: "https://console.example.com/login" })).toBe(true);
    expect(isSignInRedirect({ redirected: true, url: "https://console.example.com/login/" })).toBe(true);
    expect(isSignInRedirect({ redirected: true, url: "/login?next=%2Fconsole" })).toBe(true);
  });
  it("does not take another redirect, or a plain answer, for an ended session", () => {
    expect(isSignInRedirect({ redirected: false, url: "https://console.example.com/login" })).toBe(false);
    expect(isSignInRedirect({ redirected: true, url: "https://console.example.com/api/notify/channels" })).toBe(false);
    expect(isSignInRedirect({ redirected: true, url: "https://console.example.com/login-help" })).toBe(false);
  });
});

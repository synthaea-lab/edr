/**
 * A `fetch` that was answered by a redirect to the sign-in page means the session ended: the
 * browser followed it silently and handed back the login page with a 200, which is not the JSON
 * the action expected. Said as such, instead of as a failure the user cannot act on.
 */
export function isSignInRedirect(res: { redirected: boolean; url: string }): boolean {
  if (!res.redirected) return false;
  try {
    return new URL(res.url, "http://localhost").pathname.replace(/\/+$/, "") === "/login";
  } catch {
    return false;
  }
}

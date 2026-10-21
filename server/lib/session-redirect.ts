/**
 * A `fetch` answered by a redirect to the sign-in page means the session ended: the browser
 * followed it and handed back the login page with a 200, not the JSON the action expected.
 */
export function endedSession(res: { redirected: boolean; url: string }): boolean {
  if (!res.redirected) return false;
  try {
    return new URL(res.url, "http://localhost").pathname.replace(/\/+$/, "") === "/login";
  } catch {
    return false;
  }
}

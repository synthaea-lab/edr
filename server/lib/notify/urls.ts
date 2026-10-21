/**
 * A link into the console for a notification payload. Without a configured base (`NOTIFY_CONSOLE_URL`,
 * or `NEXTAUTH_URL`) there is no honest absolute link to give, and a relative one would mean
 * nothing to a receiver: the field is null.
 */
export function consoleUrl(env: Record<string, string | undefined>, path: string): string | null {
  const base = (env.NOTIFY_CONSOLE_URL || env.NEXTAUTH_URL || "").trim().replace(/\/$/, "");
  return base ? `${base}${path}` : null;
}

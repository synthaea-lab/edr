/** Retry delays (ADR-0036 point 7): 1, 5, 30 minutes, 2 and 6 hours, then the row is `failed`. */
export const BACKOFF_MS = [60_000, 5 * 60_000, 30 * 60_000, 2 * 3_600_000, 6 * 3_600_000] as const;

/** Failed rows in a row that pause a channel. */
export const PAUSE_AFTER_FAILED_ROWS = 5;

/** `attempts` is the number made so far, this one included. Null means give up. */
export function nextDelayMs(attempts: number): number | null {
  return attempts >= 1 && attempts <= BACKOFF_MS.length ? BACKOFF_MS[attempts - 1] : null;
}

/** Longest wait between two attempts: the cap of a `Retry-After`. */
export const MAX_DELAY_MS = BACKOFF_MS[BACKOFF_MS.length - 1];

/** Delivered rows are kept this long, then deleted by the delivery cron. */
export const RETENTION_DELIVERED_DAYS = 30;
/** Failed rows are kept this long, then deleted by the delivery cron. */
export const RETENTION_FAILED_DAYS = 90;

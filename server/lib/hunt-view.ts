import { HUNT_TRANSACTION_TIMEOUT_MS, HuntValidationError, parseHuntQuery } from "@/lib/hunt";

/**
 * What the console shows of a saved hunt (#61). Pure functions over what the database
 * holds, so the pages stay thin and the wording is tested without rendering anything.
 */

/**
 * A run whose row says it has not finished is "running" for this long after it started,
 * and "interrupted" after: the server that started it died, and nothing will finish it.
 * `startedAt` is taken before the lock transaction (it waits up to its `maxWait`, then runs
 * within its timeout) and the search has its own transaction: three transaction timeouts in
 * the worst case, plus a margin, derived from the constants so that changing one moves this.
 */
export const RUNNING_GRACE_MS = 3 * HUNT_TRANSACTION_TIMEOUT_MS + 5_000;

/** The query in one line: "last 7 days · T1059, T1003 · high, critical · 2 hosts · text “mimikatz”". */
export function describeQuery(query: unknown): string {
  let parsed;
  try {
    parsed = parseHuntQuery(query);
  } catch (error) {
    if (error instanceof HuntValidationError) return "stored query no longer valid";
    throw error;
  }
  const parts = [parsed.lastHours % 24 === 0 ? `last ${parsed.lastHours / 24} d` : `last ${parsed.lastHours} h`];
  if (parsed.techniques?.length) parts.push(parsed.techniques.join(", "));
  if (parsed.severities?.length) parts.push(parsed.severities.join(", "));
  if (parsed.agentIds?.length) parts.push(`${parsed.agentIds.length} host${parsed.agentIds.length === 1 ? "" : "s"}`);
  if (parsed.text) parts.push(`text “${parsed.text}”`);
  return parts.join(" · ");
}

/** "manual only", "every 15 min", "every 2 h", "every day", with "paused" when the hunt is inactive. */
export function describeSchedule(scheduleMinutes: number | null, active: boolean): string {
  if (scheduleMinutes === null) return "manual only";
  let every: string;
  if (scheduleMinutes % 1440 === 0) every = scheduleMinutes === 1440 ? "every day" : `every ${scheduleMinutes / 1440} d`;
  else if (scheduleMinutes % 60 === 0) every = `every ${scheduleMinutes / 60} h`;
  else every = `every ${scheduleMinutes} min`;
  return active ? every : `${every}, paused`;
}

export type RunState = "running" | "ok" | "failed" | "interrupted";

export const STATE_STYLE: Record<RunState, string> = {
  running: "bg-blue-100 text-blue-800 border-blue-200",
  ok: "bg-green-100 text-green-800 border-green-200",
  failed: "bg-red-100 text-red-800 border-red-200",
  interrupted: "bg-orange-100 text-orange-800 border-orange-200",
};

export const STATE_LABEL: Record<RunState, string> = {
  running: "Running",
  ok: "Done",
  failed: "Failed",
  interrupted: "Did not finish",
};

export type RunLike = { startedAt: Date; finishedAt: Date | null; error: string | null };

/** `finishedAt` null is a run in flight, or one that never finished; an `error` is a failed run. */
export function runState(run: RunLike, now: Date): RunState {
  if (run.error) return "failed";
  if (run.finishedAt) return "ok";
  return now.getTime() - run.startedAt.getTime() < RUNNING_GRACE_MS ? "running" : "interrupted";
}

/** "2026-10-15 14:03 UTC": a fixed zone, so the page reads the same wherever it is opened. */
export function formatTime(date: Date): string {
  return `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

/** How long a finished run took ("0.4 s", "12 s"), or null while it has not finished. */
export function formatDuration(run: RunLike): string | null {
  if (!run.finishedAt) return null;
  const ms = Math.max(0, run.finishedAt.getTime() - run.startedAt.getTime());
  return ms < 10_000 ? `${(ms / 1000).toFixed(1)} s` : `${Math.round(ms / 1000)} s`;
}

/**
 * What the "Run now" button tells the user about the answer of `POST /api/hunts/[id]/run`:
 * null when the run completed, a sentence otherwise. The API answers 200 for a run that
 * failed (its `error` is set), 429 when the tenant used its runs for the minute.
 */
export function runResponseMessage(status: number, body: unknown): string | null {
  const record = typeof body === "object" && body !== null ? (body as Record<string, unknown>) : {};
  if (status >= 200 && status < 300) {
    const run = record.run as { error?: unknown } | undefined;
    return typeof run?.error === "string" && run.error ? `The run failed: ${run.error}` : null;
  }
  if (typeof record.error === "string" && record.error) return record.error;
  return `Request failed with status ${status}`;
}

/** What the "Run now" button tells the user when the run completed: "Done: 12 matches, 3 new." */
export function runSummary(body: unknown): string {
  const record = typeof body === "object" && body !== null ? (body as Record<string, unknown>) : {};
  const run = record.run as { matchCount?: unknown; newMatchCount?: unknown } | undefined;
  if (typeof run?.matchCount === "number" && typeof run?.newMatchCount === "number") {
    const matches = `${run.matchCount} match${run.matchCount === 1 ? "" : "es"}`;
    return `Done: ${matches}, ${run.newMatchCount} new.`;
  }
  return "Done.";
}

/**
 * Whether a `fetch` answer is the sign-in page and not the API's: an expired session makes the
 * middleware redirect, `fetch` follows it, and the page comes back with status 200, which a
 * caller that only reads `res.ok` takes for success.
 */
export function isSignInRedirect(res: { redirected: boolean; url: string }): boolean {
  if (!res.redirected) return false;
  try {
    return new URL(res.url, "http://localhost").pathname.startsWith("/login");
  } catch {
    return false;
  }
}

export const SESSION_EXPIRED_MESSAGE = "Your session has expired. Sign in again, then retry.";

/** "you" for the signed-in user's own hunt, otherwise "another member": the id stays in a tooltip. */
export function ownerLabel(ownerId: string, userId: string | null | undefined): string {
  return userId && ownerId === userId ? "you" : "another member";
}

/** What the graduation form holds (#618): the platform, and an optional benign lookalike. */
export type GraduationForm = {
  platform: "linux" | "windows" | "macos";
  negativeImage: string;
  negativeCmdline: string;
  negativeNote: string;
};

/**
 * The body of `POST /api/hunts/[id]/graduate` from the form. A negative sample needs both its
 * image and its command line: with one of them it is refused here, not dropped, because a
 * draft made without the negative the person typed would look checked and not be.
 */
export function graduationBody(
  form: GraduationForm
): { ok: true; body: Record<string, unknown> } | { ok: false; message: string } {
  const image = form.negativeImage.trim();
  const cmdline = form.negativeCmdline.trim();
  const note = form.negativeNote.trim();
  if (!image && !cmdline) return { ok: true, body: { platform: form.platform } };
  if (!image || !cmdline) {
    return { ok: false, message: "A benign lookalike needs both the image and the command line, or neither." };
  }
  return { ok: true, body: { platform: form.platform, negative: { image, cmdline, ...(note && { note }) } } };
}

export type DraftFile = { path: string; content: string };

/** What the draft button shows of the server's answer. */
export type GraduationResult =
  | { ok: true; files: DraftFile[]; todo: string[] }
  | { ok: false; message: string; problems: string[] };

/** The answer of the graduate endpoint: a draft's files and to-do list, or why there is none. */
export function graduationResult(status: number, body: unknown): GraduationResult {
  const record = typeof body === "object" && body !== null ? (body as Record<string, unknown>) : {};
  if (status >= 200 && status < 300) {
    const files = record.files;
    const todo = record.todo;
    const wellFormed =
      Array.isArray(files) &&
      files.length > 0 &&
      files.every((f) => typeof f?.path === "string" && typeof f?.content === "string") &&
      Array.isArray(todo) &&
      todo.every((t) => typeof t === "string");
    return wellFormed
      ? { ok: true, files: files as DraftFile[], todo: todo as string[] }
      : { ok: false, message: "The server's answer was not a draft", problems: [] };
  }
  const problems = Array.isArray(record.problems) ? record.problems.filter((p): p is string => typeof p === "string") : [];
  const message = typeof record.error === "string" && record.error ? record.error : `Request failed with status ${status}`;
  return { ok: false, message, problems };
}

/** The name a downloaded draft file gets: the file's own, not its path in the content repo. */
export function draftDownloadName(path: string): string {
  return path.slice(path.lastIndexOf("/") + 1);
}

import { describe, expect, it } from "vitest";
import {
  RUNNING_GRACE_MS,
  draftDownloadName,
  graduationBody,
  graduationResult,
  SESSION_EXPIRED_MESSAGE,
  describeQuery,
  describeSchedule,
  formatDuration,
  formatTime,
  isSignInRedirect,
  ownerLabel,
  runResponseMessage,
  runState,
  runSummary,
} from "@/lib/hunt-view";
import { HUNT_TRANSACTION_TIMEOUT_MS } from "@/lib/hunt";

describe("describeQuery", () => {
  it("says the window in days when it is a whole number of days, in hours otherwise", () => {
    expect(describeQuery({ version: 1, lastHours: 168 })).toBe("last 7 d");
    expect(describeQuery({ version: 1, lastHours: 24 })).toBe("last 1 d");
    expect(describeQuery({ version: 1, lastHours: 36 })).toBe("last 36 h");
  });

  it("lists the techniques, severities, hosts and text that narrow the search", () => {
    expect(
      describeQuery({
        version: 1,
        lastHours: 48,
        techniques: ["T1059", "T1003.001"],
        severities: ["high", "critical"],
        agentIds: ["0b3f1c9e-3b1a-4a6e-9d3b-1f6f2f2f2f2f"],
        text: "mimikatz",
      })
    ).toBe("last 2 d · T1059, T1003.001 · high, critical · 1 host · text “mimikatz”");
    expect(
      describeQuery({
        version: 1,
        lastHours: 24,
        agentIds: ["0b3f1c9e-3b1a-4a6e-9d3b-1f6f2f2f2f2f", "1b3f1c9e-3b1a-4a6e-9d3b-1f6f2f2f2f2f"],
      })
    ).toBe("last 1 d · 2 hosts");
  });

  it("does not throw on a stored query that no longer parses: the list must still render", () => {
    expect(describeQuery({ version: 1, lastHours: 0 })).toBe("stored query no longer valid");
    expect(describeQuery(null)).toBe("stored query no longer valid");
    expect(describeQuery("not a query")).toBe("stored query no longer valid");
  });
});

describe("describeSchedule", () => {
  it("names the interval in the largest whole unit, and says when the hunt is paused", () => {
    expect(describeSchedule(null, true)).toBe("manual only");
    expect(describeSchedule(15, true)).toBe("every 15 min");
    expect(describeSchedule(120, true)).toBe("every 2 h");
    expect(describeSchedule(1440, true)).toBe("every day");
    expect(describeSchedule(2880, true)).toBe("every 2 d");
    expect(describeSchedule(90, true)).toBe("every 90 min");
    expect(describeSchedule(60, false)).toBe("every 1 h, paused");
  });
});

describe("runState", () => {
  const started = new Date("2026-10-15T10:00:00Z");
  const at = (ms: number) => new Date(started.getTime() + ms);

  it("is ok for a finished run and failed for a run with an error, finished or not", () => {
    expect(runState({ startedAt: started, finishedAt: at(500), error: null }, at(60_000))).toBe("ok");
    expect(runState({ startedAt: started, finishedAt: at(500), error: "x" }, at(60_000))).toBe("failed");
    expect(runState({ startedAt: started, finishedAt: null, error: "x" }, at(1_000))).toBe("failed");
  });

  it("is running while an unfinished run is young, and interrupted once nothing can still finish it", () => {
    expect(runState({ startedAt: started, finishedAt: null, error: null }, at(RUNNING_GRACE_MS - 1))).toBe("running");
    expect(runState({ startedAt: started, finishedAt: null, error: null }, at(RUNNING_GRACE_MS))).toBe("interrupted");
  });
});

describe("formatting", () => {
  it("writes a time in UTC, whatever the server's zone", () => {
    expect(formatTime(new Date("2026-10-15T14:03:59Z"))).toBe("2026-10-15 14:03 UTC");
  });

  it("writes how long a finished run took, and nothing for one that has not finished", () => {
    const startedAt = new Date("2026-10-15T10:00:00Z");
    expect(formatDuration({ startedAt, finishedAt: new Date(startedAt.getTime() + 400), error: null })).toBe("0.4 s");
    expect(formatDuration({ startedAt, finishedAt: new Date(startedAt.getTime() + 12_400), error: null })).toBe("12 s");
    expect(formatDuration({ startedAt, finishedAt: null, error: null })).toBeNull();
  });
});

describe("runResponseMessage", () => {
  it("has nothing to say about a run that completed", () => {
    expect(runResponseMessage(200, { run: { error: null } })).toBeNull();
  });

  it("reports a run that failed, which the API still answers 200 for", () => {
    expect(runResponseMessage(200, { run: { error: "the search exceeded its time limit and was cancelled" } })).toBe(
      "The run failed: the search exceeded its time limit and was cancelled"
    );
  });

  it("shows the API's own message for a 429 or another refusal, and a generic one when there is none", () => {
    expect(runResponseMessage(429, { error: "At most 20 hunt runs per minute per tenant; try again shortly" })).toBe(
      "At most 20 hunt runs per minute per tenant; try again shortly"
    );
    expect(runResponseMessage(500, {})).toBe("Request failed with status 500");
    expect(runResponseMessage(404, null)).toBe("Request failed with status 404");
    expect(runResponseMessage(502, "<html>bad gateway</html>")).toBe("Request failed with status 502");
  });
});

describe("RUNNING_GRACE_MS", () => {
  it("covers the worst case of a run: the lock wait, the lock transaction and the search transaction", () => {
    // `startedAt` is taken before the lock transaction (maxWait + timeout), then the search has its own.
    expect(RUNNING_GRACE_MS).toBeGreaterThan(3 * HUNT_TRANSACTION_TIMEOUT_MS);
  });
});

describe("runSummary", () => {
  it("says what a run found, and just \"Done.\" when the answer has no counts", () => {
    expect(runSummary({ run: { matchCount: 12, newMatchCount: 3 } })).toBe("Done: 12 matches, 3 new.");
    expect(runSummary({ run: { matchCount: 1, newMatchCount: 0 } })).toBe("Done: 1 match, 0 new.");
    expect(runSummary({})).toBe("Done.");
    expect(runSummary(null)).toBe("Done.");
  });
});

describe("isSignInRedirect", () => {
  it("is true for an answer that came from the sign-in page after a redirect, and only then", () => {
    expect(isSignInRedirect({ redirected: true, url: "https://edr.example/login?next=/console/hunts" })).toBe(true);
    expect(isSignInRedirect({ redirected: true, url: "https://edr.example/api/hunts" })).toBe(false);
    expect(isSignInRedirect({ redirected: false, url: "https://edr.example/login" })).toBe(false);
    expect(isSignInRedirect({ redirected: true, url: "" })).toBe(false);
    expect(SESSION_EXPIRED_MESSAGE).toMatch(/session has expired/);
  });
});

describe("ownerLabel", () => {
  it("says \"you\" for the signed-in user's own hunt and \"another member\" otherwise", () => {
    expect(ownerLabel("u1", "u1")).toBe("you");
    expect(ownerLabel("u1", "u2")).toBe("another member");
    expect(ownerLabel("u1", null)).toBe("another member");
  });
});

describe("graduationBody", () => {
  it("sends the platform alone when no negative sample is given", () => {
    expect(graduationBody({ platform: "linux", negativeImage: "", negativeCmdline: "", negativeNote: "" })).toEqual({
      ok: true,
      body: { platform: "linux" },
    });
  });

  it("sends the negative sample when both its fields are given, trimmed, with the note only if there is one", () => {
    expect(
      graduationBody({ platform: "windows", negativeImage: " C:\\a.exe ", negativeCmdline: " a /x ", negativeNote: " " })
    ).toEqual({ ok: true, body: { platform: "windows", negative: { image: "C:\\a.exe", cmdline: "a /x" } } });
    expect(
      graduationBody({ platform: "macos", negativeImage: "/bin/a", negativeCmdline: "a", negativeNote: "admin script" })
    ).toEqual({ ok: true, body: { platform: "macos", negative: { image: "/bin/a", cmdline: "a", note: "admin script" } } });
  });

  it("refuses a negative sample with only one of its two fields instead of dropping it silently", () => {
    for (const [image, cmdline] of [["/bin/a", ""], ["", "a"]]) {
      const r = graduationBody({ platform: "linux", negativeImage: image, negativeCmdline: cmdline, negativeNote: "" });
      expect(r).toEqual({ ok: false, message: expect.stringMatching(/both the image and the command line/) });
    }
  });
});

describe("graduationResult", () => {
  const files = [
    { path: "rules/sigma/linux/x.yml", content: "title: x\n" },
    { path: "rules/sigma/linux/x.samples.json", content: "{}\n" },
  ];

  it("reads the files and the to-do list of a draft", () => {
    expect(graduationResult(200, { files, todo: ["write falsepositives"] })).toEqual({
      ok: true,
      files,
      todo: ["write falsepositives"],
    });
  });

  it("gives the problems of a hunt that cannot be drafted, after the reason", () => {
    const r = graduationResult(422, { error: "No draft rule can be made from this hunt", problems: ["no exec detection", "no text"] });
    expect(r).toEqual({ ok: false, message: "No draft rule can be made from this hunt", problems: ["no exec detection", "no text"] });
  });

  it("falls back to the status when the answer says nothing, and ignores files of the wrong shape", () => {
    expect(graduationResult(500, null)).toEqual({ ok: false, message: "Request failed with status 500", problems: [] });
    expect(graduationResult(200, { files: [{ path: 3 }], todo: "x" })).toEqual({
      ok: false,
      message: "The server's answer was not a draft",
      problems: [],
    });
  });
});

describe("draftDownloadName", () => {
  it("is the file's own name, never a path", () => {
    expect(draftDownloadName("rules/sigma/linux/x.yml")).toBe("x.yml");
    expect(draftDownloadName("x.yml")).toBe("x.yml");
  });
});

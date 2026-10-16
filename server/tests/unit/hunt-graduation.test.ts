import { describe, expect, it } from "vitest";
import {
  draftRuleFromHunt,
  parseGraduationRequest,
  ruleSlug,
  type GraduationDetection,
  type GraduationHunt,
} from "@/lib/hunt-graduation";

const exec = (id: string, image: string, cmdline: string, extra: Partial<GraduationDetection> = {}): GraduationDetection => ({
  id,
  technique: "T1003.008",
  severity: "medium",
  event: { type: "exec", image_path: image, cmdline },
  ...extra,
});

const hunt = (query: Partial<GraduationHunt["query"]> = {}, extra: Partial<GraduationHunt> = {}): GraduationHunt => ({
  id: "h-1",
  name: "Shadow file copy",
  description: null,
  version: 2,
  query: { version: 1, lastHours: 168, text: "/etc/shadow", ...query },
  ...extra,
});

const matches = [
  exec("d1", "/usr/bin/cp", "cp --preserve=mode /etc/shadow /root/shadow.backup"),
  exec("d2", "/usr/bin/cp", "cp /etc/shadow /tmp/s"),
];

function ok(result: ReturnType<typeof draftRuleFromHunt>) {
  if (!result.ok) throw new Error(`expected a draft, got ${JSON.stringify(result.problems)}`);
  return result;
}

describe("draftRuleFromHunt", () => {
  it("writes the rule and its samples side by side, in the platform directory", () => {
    const { files, todo } = ok(draftRuleFromHunt(hunt(), matches, { platform: "linux" }));
    expect(files.map((f) => f.path)).toEqual([
      "rules/sigma/linux/shadow_file_copy.yml",
      "rules/sigma/linux/shadow_file_copy.samples.json",
    ]);
    const [yml, samples] = files.map((f) => f.content);
    expect(yml).toContain("title: 'Shadow file copy'");
    expect(yml).toContain("  - attack.t1003.008");
    expect(yml).toContain("level: medium");
    expect(yml).toContain("    Image|endswith: '/cp'");
    expect(yml).toContain("    CommandLine|contains: '/etc/shadow'");
    expect(yml).toContain("  condition: selection");
    expect(yml).toContain("# DRAFT graduated from hunt h-1 (query version 2)");
    expect(JSON.parse(samples)).toEqual({
      matching: { image: "/usr/bin/cp", cmdline: "cp --preserve=mode /etc/shadow /root/shadow.backup" },
      non_matching: {
        image: "/usr/bin/cp",
        cmdline: "cp --preserve=mode /root/shadow.backup",
        note: expect.stringContaining("DRAFT"),
      },
    });
    // Everything a person still has to do is said.
    expect(todo.join(" ")).toMatch(/negative sample/);
    expect(todo.join(" ")).toMatch(/falsepositives/);
  });

  it("takes the technique from the matches inside the hunt's list, and the level from the hunt's single severity", () => {
    const detections = [
      exec("a", "/usr/bin/cp", "cp /etc/shadow x", { technique: "T1059.004", severity: "low" }),
      exec("b", "/usr/bin/cp", "cp /etc/shadow y", { technique: "T1003.008", severity: "low" }),
      exec("c", "/usr/bin/cp", "cp /etc/shadow z", { technique: "T1003.008", severity: "low" }),
    ];
    const result = ok(draftRuleFromHunt(hunt({ techniques: ["T1003"], severities: ["critical"] }), detections, { platform: "linux" }));
    expect(result.files[0].content).toContain("attack.t1003.008");
    expect(result.files[0].content).toContain("level: critical");
  });

  it("matches a Windows image on the backslash path and keeps a quote in the text", () => {
    const result = ok(
      draftRuleFromHunt(
        hunt({ text: "-enc" }),
        [exec("w", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -enc SQBFAFgA", { technique: "T1059.001" })],
        { platform: "windows" }
      )
    );
    expect(result.files[0].path).toBe("rules/sigma/windows/shadow_file_copy.yml");
    expect(result.files[0].content).toContain("Image|endswith: '\\powershell.exe'");
    const quoted = ok(
      draftRuleFromHunt(hunt({ text: "it's" }), [exec("q", "/bin/echo", "echo it's here")], { platform: "linux" })
    );
    expect(quoted.files[0].content).toContain("CommandLine|contains: 'it''s'");
  });

  it("uses the first sample that holds the text, not just the newest", () => {
    const result = ok(
      draftRuleFromHunt(hunt(), [exec("x", "/usr/bin/ls", "ls /"), ...matches], { platform: "linux" })
    );
    expect(JSON.parse(result.files[1].content).matching.image).toBe("/usr/bin/cp");
  });

  it("refuses when no matched detection is a process start", () => {
    const result = draftRuleFromHunt(hunt(), [{ id: "f", technique: "T1003", severity: "high", event: { type: "file_open" } }], {
      platform: "linux",
    });
    expect(result).toMatchObject({ ok: false, problems: [expect.stringContaining("process start")] });
  });

  it("refuses when the hunt text is in no exec command line, naming the text", () => {
    const result = draftRuleFromHunt(hunt({ text: "mimikatz" }), matches, { platform: "linux" });
    expect(result).toMatchObject({ ok: false, problems: [expect.stringContaining("“mimikatz”")] });
  });

  it("refuses a hunt with no technique among its matches, and one with no severity", () => {
    const result = draftRuleFromHunt(
      hunt(),
      [exec("n", "/usr/bin/cp", "cp /etc/shadow x", { technique: "SIGMA", severity: "bad" })],
      { platform: "linux" }
    );
    expect(result).toMatchObject({ ok: false });
    if (!result.ok) {
      expect(result.problems.join(" ")).toMatch(/ATT&CK technique/);
      expect(result.problems.join(" ")).toMatch(/severity/);
    }
  });

  it("needs a negative sample when the hunt has no text, and accepts one that the selection ignores", () => {
    const noText = hunt({ text: undefined });
    const refused = draftRuleFromHunt(noText, matches, { platform: "linux" });
    expect(refused).toMatchObject({ ok: false, problems: [expect.stringContaining("negative")] });

    const result = ok(
      draftRuleFromHunt(noText, matches, { platform: "linux", negative: { image: "/usr/bin/ls", cmdline: "ls /etc" } })
    );
    expect(result.files[0].content).not.toContain("CommandLine");
    expect(result.todo.join(" ")).toMatch(/no text filter/);
    expect(JSON.parse(result.files[1].content).non_matching.note).toBeTruthy();
  });

  it("refuses a negative sample that fires on the draft's own selection", () => {
    const result = draftRuleFromHunt(hunt(), matches, {
      platform: "linux",
      negative: { image: "/bin/CP", cmdline: "cp /ETC/SHADOW elsewhere" },
    });
    expect(result).toMatchObject({ ok: false, problems: [expect.stringContaining("fires on the draft's own selection")] });
  });

  it("refuses a value with a line break instead of writing broken YAML", () => {
    const result = draftRuleFromHunt(hunt({ text: "shadow" }), [exec("l", "/bin/sh", "sh -c 'cat shadow\nrm x'")], {
      platform: "linux",
    });
    expect(result).toMatchObject({ ok: false, problems: [expect.stringContaining("line break")] });
  });
});

describe("ruleSlug", () => {
  it("keeps letters, digits and underscores", () => {
    expect(ruleSlug("Shadow file copy!")).toBe("shadow_file_copy");
    expect(ruleSlug("  ../../etc  ")).toBe("etc");
    expect(ruleSlug("???")).toBe("hunt_draft");
  });
});

describe("parseGraduationRequest", () => {
  it("accepts a platform and an optional negative, and refuses anything else", () => {
    expect(parseGraduationRequest({ platform: "macos" })).toEqual({ platform: "macos" });
    expect(parseGraduationRequest({ platform: "linux", negative: { image: "/bin/ls", cmdline: "ls", note: "n" } })).toEqual({
      platform: "linux",
      negative: { image: "/bin/ls", cmdline: "ls", note: "n" },
    });
    expect(() => parseGraduationRequest(null)).toThrow("body must be an object");
    expect(() => parseGraduationRequest({})).toThrow("platform must be one of");
    expect(() => parseGraduationRequest({ platform: "bsd" })).toThrow("platform must be one of");
    expect(() => parseGraduationRequest({ platform: "linux", path: "x" })).toThrow('unknown field "path"');
    expect(() => parseGraduationRequest({ platform: "linux", negative: { image: "/bin/ls" } })).toThrow("negative.cmdline");
    expect(() => parseGraduationRequest({ platform: "linux", negative: { image: "a", cmdline: "b", x: 1 } })).toThrow(
      'unknown field "negative.x"'
    );
  });
});

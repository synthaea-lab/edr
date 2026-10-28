import { HuntValidationError, type HuntQuery } from "@/lib/hunt";

/**
 * Hunt-to-draft-rule graduation (#618, detection-as-code gap 4).
 *
 * A hunt queries the detection store, not normalised events, so it cannot be compiled into
 * a Sigma `selection` in general. What it can do is an assisted draft: the metadata comes
 * from the hunt and the detections it matched, the matching sample is one of those
 * detections' exec events, and the selection is read off that sample (the image, and the
 * hunt's `text` when it is in the command line). A person reviews every draft, it enters
 * the normal PR and CI path, and nothing here merges or ships content.
 *
 * The draft is two files, laid out as `rules/sigma/README.md` and ADR-0031 want them:
 * `<rule>.yml` and `<rule>.samples.json`. It is checked here the way the engine will check
 * it (`crates/sigma/src/validate.rs`, `eval.rs`): the sample must fire and the negative must
 * not. A draft that cannot be made says why, in `problems`.
 */

export const PLATFORMS = ["linux", "windows", "macos"] as const;
export type Platform = (typeof PLATFORMS)[number];

export type GraduationRequest = {
  platform: Platform;
  /** A benign lookalike that must not fire. Needed when the hunt has no `text` to derive one from. */
  negative?: { image: string; cmdline: string; note?: string };
};

export type GraduationHunt = { id: string; name: string; description: string | null; version: number; query: HuntQuery };

/** The part of a stored detection the exporter reads. */
export type GraduationDetection = { id: string; technique: string; severity: string; event: unknown };

export type DraftFile = { path: string; content: string };

export type GraduationResult =
  | { ok: true; files: DraftFile[]; todo: string[] }
  | { ok: false; problems: string[] };

const TECHNIQUE_RE = /^T\d{4}(\.\d{3})?$/;
const SEVERITY_RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };
const FIELD_MAX = 2000;

/** Validates the body of `POST /api/hunts/[id]/graduate`; throws `HuntValidationError`. */
export function parseGraduationRequest(body: unknown): GraduationRequest {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new HuntValidationError("body must be an object");
  }
  const raw = body as Record<string, unknown>;
  for (const key of Object.keys(raw)) {
    if (key !== "kind" && key !== "platform" && key !== "negative") throw new HuntValidationError(`unknown field "${key}"`);
  }
  if (typeof raw.platform !== "string" || !(PLATFORMS as readonly string[]).includes(raw.platform)) {
    throw new HuntValidationError(`platform must be one of ${PLATFORMS.join(", ")}`);
  }
  const request: GraduationRequest = { platform: raw.platform as Platform };
  if (raw.negative !== undefined) {
    const n = raw.negative as Record<string, unknown> | null;
    if (typeof n !== "object" || n === null || Array.isArray(n)) {
      throw new HuntValidationError("negative must be an object with image and cmdline");
    }
    for (const key of Object.keys(n)) {
      if (key !== "image" && key !== "cmdline" && key !== "note") {
        throw new HuntValidationError(`unknown field "negative.${key}"`);
      }
    }
    for (const key of ["image", "cmdline"] as const) {
      if (typeof n[key] !== "string" || (n[key] as string).trim() === "" || (n[key] as string).length > FIELD_MAX) {
        throw new HuntValidationError(`negative.${key} must be a string of 1 to ${FIELD_MAX} characters`);
      }
    }
    if (n.note !== undefined && (typeof n.note !== "string" || n.note.length > FIELD_MAX)) {
      throw new HuntValidationError(`negative.note must be a string of at most ${FIELD_MAX} characters`);
    }
    request.negative = { image: n.image as string, cmdline: n.cmdline as string, ...(n.note !== undefined && { note: n.note as string }) };
  }
  return request;
}

type Exec = { detection: GraduationDetection; image: string; cmdline: string };

function execOf(detection: GraduationDetection): Exec | null {
  const event = detection.event as Record<string, unknown> | null;
  if (typeof event !== "object" || event === null || event.type !== "exec") return null;
  if (typeof event.image_path !== "string" || event.image_path === "") return null;
  if (typeof event.cmdline !== "string" || event.cmdline === "") return null;
  return { detection, image: event.image_path, cmdline: event.cmdline };
}

const contains = (haystack: string, needle: string) => haystack.toLowerCase().includes(needle.toLowerCase());

/** The last path component, whichever separator the platform uses. */
function basename(image: string): { name: string; separator: string } {
  const cut = Math.max(image.lastIndexOf("/"), image.lastIndexOf("\\"));
  return cut < 0
    ? { name: image, separator: "" }
    : { name: image.slice(cut + 1), separator: image[cut] };
}

/** Removes every case-insensitive occurrence of `needle`, and the spaces that leaves doubled. */
function withoutText(cmdline: string, needle: string): string {
  const lower = cmdline.toLowerCase();
  const target = needle.toLowerCase();
  let out = "";
  let from = 0;
  for (let at = lower.indexOf(target); at >= 0; at = lower.indexOf(target, from)) {
    out += cmdline.slice(from, at);
    from = at + target.length;
  }
  return (out + cmdline.slice(from)).replace(/\s{2,}/g, " ").trim();
}

/** YAML single-quoted scalar: the only escape is a doubled quote, and nothing is interpreted. */
const quote = (value: string) => `'${value.replace(/'/g, "''")}'`;

/** A file name from the hunt's name: lowercase letters, digits and underscores. */
export function ruleSlug(name: string): string {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 60);
  return slug === "" ? "hunt_draft" : slug;
}

/** What the engine will decide for the selection this exporter writes: the same case-insensitive rules. */
function fires(selection: { endswith: string; contains?: string }, event: { image: string; cmdline: string }): boolean {
  return (
    event.image.toLowerCase().endsWith(selection.endswith.toLowerCase()) &&
    (selection.contains === undefined || contains(event.cmdline, selection.contains))
  );
}

function mostFrequent(values: string[], tiebreak: (a: string, b: string) => number): string | undefined {
  const counts = new Map<string, number>();
  for (const v of values) counts.set(v, (counts.get(v) ?? 0) + 1);
  return Array.from(counts.entries()).sort((a, b) => b[1] - a[1] || tiebreak(a[0], b[0]))[0]?.[0];
}

/**
 * Builds the draft for `hunt` from `detections` (the sample of its newest run, newest first).
 * Pure: it reads nothing and writes nothing.
 */
export function draftRuleFromHunt(
  hunt: GraduationHunt,
  detections: GraduationDetection[],
  request: GraduationRequest
): GraduationResult {
  const problems: string[] = [];
  const todo: string[] = [];
  const text = hunt.query.text;

  const execs = detections.map(execOf).filter((e): e is Exec => e !== null);
  if (execs.length === 0) {
    return {
      ok: false,
      problems: [
        "None of the detections this hunt matched is a process start (an exec event with an image and a command line), and a Sigma draft can only be built from one. Run the hunt again, or narrow it to detections that carry an exec event.",
      ],
    };
  }

  // The matching sample: the newest exec the selection will hold for. With a text filter, one that has the text.
  const sample = text ? execs.find((e) => contains(e.cmdline, text)) : execs[0];
  if (!sample) {
    return {
      ok: false,
      problems: [
        `The hunt's text “${text}” is not in the command line of any of the ${execs.length} matched exec events, so the draft has no sample to fire on. The text is matched against the whole stored event; a rule can only match the image and the command line.`,
      ],
    };
  }

  // ATT&CK technique: from the matches, within the hunt's own list when it has one.
  const listed = hunt.query.techniques;
  const techniques = detections
    .map((d) => d.technique)
    .filter((t) => TECHNIQUE_RE.test(t) && (!listed || listed.some((l) => t === l || t.startsWith(`${l}.`))));
  const technique = mostFrequent(techniques, (a, b) => a.localeCompare(b));
  if (!technique) {
    problems.push(
      "No matched detection carries an ATT&CK technique id (T1059 or T1059.001), and a rule needs one. Add one to the hunt's techniques or fix the detections' technique."
    );
  }

  // Level: the hunt's single severity, else the commonest among the matches (the higher on a tie).
  const severities = hunt.query.severities;
  const level =
    severities?.length === 1
      ? severities[0]
      : mostFrequent(
          detections.map((d) => d.severity).filter((s) => s in SEVERITY_RANK),
          (a, b) => SEVERITY_RANK[b] - SEVERITY_RANK[a]
        );
  if (!level) problems.push("No matched detection carries a severity (low, medium, high, critical).");

  // The selection, read off the sample.
  const { name: imageName, separator } = basename(sample.image);
  if (imageName === "") problems.push(`The sample image “${sample.image}” has no file name to match on.`);
  const selection: { endswith: string; contains?: string } = { endswith: `${separator}${imageName}` };
  if (text) selection.contains = text;
  else {
    todo.push(
      "The hunt has no text filter, so the selection matches every start of this image. Narrow it by hand: add a CommandLine condition."
    );
  }

  // The negative sample: given, or derived by taking the hunt's text out of the matching one.
  let negative: { image: string; cmdline: string; note: string };
  if (request.negative) {
    negative = { note: "A benign lookalike supplied with the export.", ...request.negative };
  } else if (text) {
    const stripped = withoutText(sample.cmdline, text);
    negative = {
      image: sample.image,
      cmdline: stripped === "" ? imageName : stripped,
      note: "DRAFT: the matching command line with the hunt's text removed. Replace it with a real benign lookalike that probes the boundary of the rule.",
    };
    todo.push("The negative sample is derived (the matching command line without the text); replace it with a real benign lookalike.");
  } else {
    problems.push(
      "The hunt has no text filter, so there is nothing to derive a negative sample from. Send one as `negative` ({ image, cmdline }): a benign process start the rule must not fire on."
    );
    negative = { image: sample.image, cmdline: sample.cmdline, note: "" };
  }

  // What the YAML and JSON cannot carry safely.
  const scalars: [string, string][] = [
    ["the hunt name", hunt.name],
    ["the sample image", sample.image],
    ["the sample command line", sample.cmdline],
    ["the negative image", negative.image],
    ["the negative command line", negative.cmdline],
  ];
  if (text) scalars.push(["the hunt text", text]);
  for (const [what, value] of scalars) {
    if (/[\u0000-\u001f\u007f]/.test(value)) {
      problems.push(`${what} contains a line break or a control character, which the draft cannot carry; fix it first.`);
    }
  }

  if (problems.length === 0) {
    // The engine's verdict, reproduced: the sample fires, the negative does not.
    if (!fires(selection, sample)) problems.push("Internal check failed: the draft's selection does not fire on its own matching sample.");
    if (fires(selection, negative)) {
      problems.push(
        `The negative sample (${negative.image}: ${negative.cmdline}) fires on the draft's own selection, so the rule would never pass its negative check. Send a lookalike that the selection ignores.`
      );
    }
  }
  if (problems.length > 0 || !technique || !level) return { ok: false, problems };

  const tag = `attack.${technique.toLowerCase()}`;
  const fromHunt = `hunt ${hunt.id} (query version ${hunt.version})`;
  const description = hunt.description?.trim()
    ? `${hunt.description.trim().replace(/\s+/g, " ")} Graduated from a saved hunt; review before merging.`
    : `Graduated from a saved hunt; review before merging. Matches ${imageName} starts${text ? ` whose command line contains ${text}` : ""}.`;
  todo.push("falsepositives is a placeholder; list the real known false-positive scenarios.");
  todo.push("Set the tactic and coverage tags (`attack.<tactic>`, `synthaea.coverage.<tactic>`) and check the title and description.");

  const yml = [
    `# DRAFT graduated from ${fromHunt}. A person reviews it; it enters the normal PR and CI path.`,
    `title: ${quote(hunt.name)}`,
    `description: ${quote(description)}`,
    "tags:",
    `  - ${tag}`,
    `level: ${level}`,
    "falsepositives:",
    "  - 'TODO(analyst): the known benign scenarios for this rule.'",
    "detection:",
    "  selection:",
    `    Image|endswith: ${quote(selection.endswith)}`,
    ...(selection.contains !== undefined ? [`    CommandLine|contains: ${quote(selection.contains)}`] : []),
    "  condition: selection",
    "",
  ].join("\n");

  const samples = `${JSON.stringify(
    {
      matching: { image: sample.image, cmdline: sample.cmdline },
      non_matching: { image: negative.image, cmdline: negative.cmdline, note: negative.note },
    },
    null,
    2
  )}\n`;

  const base = `rules/sigma/${request.platform}/${ruleSlug(hunt.name)}`;
  return { ok: true, files: [{ path: `${base}.yml`, content: yml }, { path: `${base}.samples.json`, content: samples }], todo };
}

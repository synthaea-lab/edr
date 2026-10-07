import { describe, expect, it } from "vitest";
import { MAX_DAMAGE_ENTRIES, damageManifestOf } from "@/lib/damage-manifest";

const rename = (from: string, to: string, ns: number) => ({
  type: "file_rename",
  meta: { pid: 9, timestamp_ns: ns },
  old_path: from,
  new_path: to,
});
const del = (path: string, ns: number) => ({ type: "file_delete", meta: { pid: 9, timestamp_ns: ns }, path });
const detection = (technique: string, event: unknown, additional: unknown[] = [], agentId = "agent-1") => ({
  technique,
  agentId,
  event,
  meta: { additional_events: additional },
});

describe("damageManifestOf", () => {
  it("lists the files a ransomware detection says were renamed or deleted, oldest first", () => {
    const manifest = damageManifestOf([
      detection("T1486", rename("/h/c", "/h/c.locked", 3_000_000_000), [
        del("/h/b", 2_000_000_000),
        rename("/h/a", "/h/a.locked", 1_000_000_000),
      ]),
    ]);
    expect(manifest.truncated).toBe(false);
    expect(manifest.files).toEqual([
      { action: "renamed", path: "/h/a", to: "/h/a.locked", at: 1000, agentId: "agent-1" },
      { action: "deleted", path: "/h/b", at: 2000, agentId: "agent-1" },
      { action: "renamed", path: "/h/c", to: "/h/c.locked", at: 3000, agentId: "agent-1" },
    ]);
  });

  it("ignores detections that are not ransomware", () => {
    const manifest = damageManifestOf([detection("T1059.001", rename("/h/a", "/h/a.x", 1), [del("/h/b", 2)])]);
    expect(manifest).toEqual({ files: [], truncated: false });
  });

  it("counts a file once however many detections mention it, but not across hosts", () => {
    const a = detection("T1486", rename("/h/a", "/h/a.locked", 1), [], "agent-1");
    const again = detection("T1486", rename("/h/a", "/h/a.locked", 1), [], "agent-1");
    const other = detection("T1486", rename("/h/a", "/h/a.locked", 1), [], "agent-2");
    expect(damageManifestOf([a, again]).files).toHaveLength(1);
    expect(damageManifestOf([a, other]).files).toHaveLength(2);
  });

  it("skips shapes it does not know instead of trusting them", () => {
    const hostile = [
      null,
      "string",
      42,
      [],
      { type: "file_rename", old_path: 5, new_path: "x" },
      { type: "file_delete" },
      { type: "exec", path: "/bin/sh" },
      { type: "file_delete", path: "/h/ok", meta: { timestamp_ns: "later" } },
    ];
    const manifest = damageManifestOf([
      { technique: "T1486", agentId: "a", event: hostile[0], meta: { additional_events: hostile.slice(1) } },
      { technique: "T1486", agentId: "a", event: {}, meta: null },
      { technique: "T1486", agentId: "a", event: {}, meta: { additional_events: "not a list" } },
    ]);
    expect(manifest.files).toEqual([{ action: "deleted", path: "/h/ok", at: undefined, agentId: "a" }]);
  });

  it("caps the manifest and says so", () => {
    const many = Array.from({ length: MAX_DAMAGE_ENTRIES + 5 }, (_, i) => del(`/h/${i}`, i));
    const manifest = damageManifestOf([detection("T1486", many[0], many.slice(1))]);
    expect(manifest.files).toHaveLength(MAX_DAMAGE_ENTRIES);
    expect(manifest.truncated).toBe(true);
  });
});

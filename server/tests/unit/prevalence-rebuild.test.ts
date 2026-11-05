import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FsLakeStore } from "@/lib/lake-store";
import { encodeParquet, lakeKey, lakeRow, type LakeRow as WriterRow } from "@/lib/lake-writer";
import { aggregateSightings, extractObservations } from "@/lib/prevalence";
import {
  compareSightings,
  isIdentical,
  mergeSightings,
  rebuildSightings,
  type AgentSighting,
} from "@/lib/prevalence-rebuild";

const T1 = "tenant-one";
const T2 = "tenant-two";
const SHA = "d".repeat(64);

let dir: string;
let store: FsLakeStore;
beforeEach(async () => {
  dir = await mkdtemp(path.join(os.tmpdir(), "prev-rebuild-"));
  store = new FsLakeStore(dir);
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const at = (day: string, hhmmss: string) => new Date(`${day}T${hhmmss}Z`);

/** One event as the agent sends it, stamped with its own time so the lake's `ts` is that time. */
function event(when: Date, over: Record<string, unknown> = {}) {
  return { type: "exec", meta: { timestamp_ns: when.getTime() * 1_000_000 }, image_path: "/usr/bin/curl", parent_comm: "bash", sha256: SHA, ...over };
}
function row(agent: string, e: Record<string, unknown>): WriterRow {
  return lakeRow(agent, e, new Date(), JSON.stringify(e));
}
async function put(tenant: string, day: string, type: string, flush: string, rows: WriterRow[]) {
  await store.put(lakeKey(tenant, day, type, flush), encodeParquet(rows));
}

/** What ingest does with the same events: per batch and per agent, aggregate, then sum into the table. */
function ingest(batches: { agent: string; events: Record<string, unknown>[] }[]): AgentSighting[] {
  const table = new Map<string, AgentSighting>();
  for (const { agent, events } of batches) {
    const items = events.map((e) => ({ at: new Date(Number((e.meta as { timestamp_ns: number }).timestamp_ns) / 1_000_000), observations: extractObservations(e) }));
    for (const s of aggregateSightings(items)) {
      const id = `${agent}\u0000${s.kind}\u0000${s.key}`;
      const seen = table.get(id);
      if (!seen) table.set(id, { ...s, agentId: agent });
      else {
        seen.firstSeen = new Date(Math.min(seen.firstSeen.getTime(), s.firstSeen.getTime()));
        seen.lastSeen = new Date(Math.max(seen.lastSeen.getTime(), s.lastSeen.getTime()));
        seen.count += s.count;
      }
    }
  }
  return Array.from(table.values());
}
const key = (s: AgentSighting) => `${s.agentId}|${s.kind}|${s.key}`;
const byKey = (list: AgentSighting[]) => [...list].sort((a, b) => key(a).localeCompare(key(b)));

const RANGE = { from: "2026-10-01", to: "2026-10-31" };

describe("rebuildSightings", () => {
  it("reproduces what ingest folded, across batches, agents, days and the four kinds", async () => {
    const day1 = [
      event(at("2026-10-28", "08:00:00")),
      event(at("2026-10-28", "09:00:00")),
      event(at("2026-10-28", "09:30:00"), { image_path: "C:\\Windows\\System32\\CMD.EXE", parent_comm: "", parent_image_path: "C:\\Windows\\Explorer.EXE", sha256: "" }),
    ];
    const day2 = [event(at("2026-10-29", "01:00:00")), event(at("2026-10-29", "02:00:00"), { image_path: "/tmp/x", sha256: "e".repeat(64) })];
    const dns = [{ type: "dns_query", meta: { timestamp_ns: at("2026-10-29", "03:00:00").getTime() * 1_000_000 }, query: "Example.COM." }];
    const other = [event(at("2026-10-29", "04:00:00"))];

    await put(T1, "2026-10-28", "exec", "a", day1.map((e) => row("a1", e)));
    await put(T1, "2026-10-29", "exec", "a", [...day2.map((e) => row("a1", e)), ...other.map((e) => row("a2", e))]);
    await put(T1, "2026-10-29", "dns_query", "a", dns.map((e) => row("a2", e)));

    const reference = ingest([
      { agent: "a1", events: day1 },
      { agent: "a1", events: day2 },
      { agent: "a2", events: other },
      { agent: "a2", events: dns },
    ]);
    const rebuilt = await rebuildSightings(store, { tenantId: T1, ...RANGE });

    expect(rebuilt.complete).toBe(true);
    expect(rebuilt.sightings).toEqual(byKey(reference));
    expect(isIdentical(compareSightings(rebuilt.sightings, reference))).toBe(true);
    // A key the reference never held would show: the Windows path and the domain are the normalised ones.
    expect(rebuilt.sightings.map((s) => s.key)).toContain("c:\\windows\\system32\\cmd.exe");
    expect(rebuilt.sightings.map((s) => s.key)).toContain("example.com");
  });

  it("counts every row of a day, past the 1000 rows a query returns", async () => {
    const events = Array.from({ length: 1500 }, (_, i) => event(new Date(at("2026-10-29", "00:00:00").getTime() + i * 1000)));
    await put(T1, "2026-10-29", "exec", "a", events.slice(0, 700).map((e) => row("a1", e)));
    await put(T1, "2026-10-29", "exec", "b", events.slice(700).map((e) => row("a1", e)));
    const r = await rebuildSightings(store, { tenantId: T1, ...RANGE });
    const sha = r.sightings.find((s) => s.kind === "sha256");
    expect(sha?.count).toBe(1500);
    expect(r.rows).toBe(1500);
  });

  it("reads only the types that yield observations", async () => {
    await put(T1, "2026-10-29", "exec", "a", [row("a1", event(at("2026-10-29", "01:00:00")))]);
    await put(T1, "2026-10-29", "file_open", "a", [row("a1", { type: "file_open", meta: { timestamp_ns: 1 }, path: "/etc/passwd" })]);
    await put(T1, "2026-10-29", "connect", "a", [row("a1", { type: "connect", meta: { timestamp_ns: 1 }, daddr: "203.0.113.9" })]);
    const r = await rebuildSightings(store, { tenantId: T1, ...RANGE });
    expect(r.scan).toMatchObject({ filesMatched: 1, filesRead: 1, filesSkipped: 0 });
  });

  it("never counts another tenant's events or a day outside the range", async () => {
    await put(T1, "2026-10-29", "exec", "a", [row("a1", event(at("2026-10-29", "01:00:00")))]);
    await put(T2, "2026-10-29", "exec", "a", [row("b1", event(at("2026-10-29", "02:00:00"), { image_path: "/tmp/other-tenant" }))]);
    await put(T1, "2026-09-15", "exec", "a", [row("a1", event(at("2026-09-15", "02:00:00"), { image_path: "/tmp/too-old" }))]);
    const r = await rebuildSightings(store, { tenantId: T1, ...RANGE });
    expect(r.sightings.map((s) => s.key)).not.toContain("/tmp/other-tenant");
    expect(r.sightings.map((s) => s.key)).not.toContain("/tmp/too-old");
    expect(new Set(r.sightings.map((s) => s.agentId))).toEqual(new Set(["a1"]));
  });

  it("counts an event it cannot parse as skipped and folds nothing from it", async () => {
    const good = event(at("2026-10-29", "01:00:00"));
    const broken: WriterRow = { ...row("a1", good), event: "{not json" };
    await put(T1, "2026-10-29", "exec", "a", [row("a1", good), broken]);
    const r = await rebuildSightings(store, { tenantId: T1, ...RANGE });
    // A skipped event is missing from the rebuild: not complete, so a comparison cannot trust it.
    expect(r).toMatchObject({ rows: 2, skipped: 1, complete: false });
    expect(r.sightings.find((s) => s.kind === "sha256")?.count).toBe(1);
  });

  it("says it is incomplete when files were left unread or the sighting cap was reached", async () => {
    await put(T1, "2026-10-28", "exec", "a", [row("a1", event(at("2026-10-28", "01:00:00")))]);
    await put(T1, "2026-10-29", "exec", "a", [row("a1", event(at("2026-10-29", "01:00:00")))]);
    const files = await rebuildSightings(store, { tenantId: T1, ...RANGE, maxFiles: 1 });
    expect(files).toMatchObject({ complete: false, capped: false });
    // The listing stops at maxFiles + 1: it says there is at least one more, not how many.
    expect(files.scan).toMatchObject({ filesMatched: 1, filesRead: 1, filesSkipped: 1, listingTruncated: true });
    const cap = await rebuildSightings(store, { tenantId: T1, ...RANGE, maxSightings: 2 });
    expect(cap).toMatchObject({ complete: false, capped: true });
    expect(cap.sightings).toHaveLength(2);
  });

  it("does not depend on the order the files were written or listed", async () => {
    const a = row("a1", event(at("2026-10-29", "01:00:00")));
    const b = row("a1", event(at("2026-10-29", "05:00:00")));
    await put(T1, "2026-10-29", "exec", "z", [b]);
    await put(T1, "2026-10-29", "exec", "a", [a]);
    const r = await rebuildSightings(store, { tenantId: T1, ...RANGE });
    const sha = r.sightings.find((s) => s.kind === "sha256");
    expect(sha).toMatchObject({ count: 2, firstSeen: at("2026-10-29", "01:00:00"), lastSeen: at("2026-10-29", "05:00:00") });
  });

  it("refuses a range or tenant the scan refuses", async () => {
    await expect(rebuildSightings(store, { tenantId: "../x", ...RANGE })).rejects.toThrow(RangeError);
    await expect(rebuildSightings(store, { tenantId: T1, from: "2025-01-01", to: "2026-10-31" })).rejects.toThrow(RangeError);
  });
});

describe("mergeSightings", () => {
  it("folds the results of consecutive ranges into the result of one", async () => {
    await put(T1, "2026-10-27", "exec", "a", [row("a1", event(at("2026-10-27", "01:00:00")))]);
    await put(T1, "2026-10-29", "exec", "a", [row("a1", event(at("2026-10-29", "01:00:00")))]);
    const whole = await rebuildSightings(store, { tenantId: T1, from: "2026-10-27", to: "2026-10-29" });
    const first = await rebuildSightings(store, { tenantId: T1, from: "2026-10-27", to: "2026-10-28" });
    const second = await rebuildSightings(store, { tenantId: T1, from: "2026-10-29", to: "2026-10-29" });
    expect(mergeSightings(first.sightings, second.sightings)).toEqual(whole.sightings);
    expect(whole.sightings.find((s) => s.kind === "sha256")?.count).toBe(2);
  });
});

describe("compareSightings", () => {
  const base: AgentSighting = { agentId: "a1", kind: "sha256", key: SHA, firstSeen: at("2026-10-28", "01:00:00"), lastSeen: at("2026-10-29", "01:00:00"), count: 3 };

  it("is identical for equal rows and names each kind of difference", () => {
    expect(compareSightings([base], [{ ...base }])).toMatchObject({ matching: 1, onlyRebuilt: [], onlyTable: [], differing: [] });
    const other: AgentSighting = { ...base, key: "e".repeat(64) };
    expect(compareSightings([base, other], [base]).onlyRebuilt).toEqual([other]);
    expect(compareSightings([base], [base, other]).onlyTable).toEqual([other]);
    for (const changed of [{ count: 4 }, { firstSeen: at("2026-10-28", "01:00:01") }, { lastSeen: at("2026-10-29", "01:00:01") }]) {
      const d = compareSightings([{ ...base, ...changed }], [base]);
      expect(d.differing).toHaveLength(1);
      expect(isIdentical(d)).toBe(false);
    }
  });

  it("tells one agent's row from another's for the same key", () => {
    const d = compareSightings([{ ...base, agentId: "a2" }], [base]);
    expect(d.onlyRebuilt).toHaveLength(1);
    expect(d.onlyTable).toHaveLength(1);
  });
});

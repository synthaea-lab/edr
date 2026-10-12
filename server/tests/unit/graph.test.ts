import { describe, expect, it } from "vitest";
import {
  caseSubgraph,
  extractGraphFacts,
  type GraphNode,
  hashPivot,
  mergeGraphs,
  nodeId,
  sortGraph,
} from "@/lib/graph";

const SHA = "a".repeat(64);
const T0 = new Date("2026-10-09T10:00:00Z");
const T1 = new Date("2026-10-09T10:00:05Z");

const exec = (overrides: Record<string, unknown> = {}) => ({
  type: "exec",
  meta: { pid: 100, ppid: 1, comm: "curl", timestamp_ns: 1, ...((overrides.meta as object) ?? {}) },
  image_path: "/usr/bin/curl",
  sha256: SHA,
  parent_comm: "bash",
  ...overrides,
});

describe("extractGraphFacts", () => {
  it("an exec with a parent yields host, process, file and spawned/opened/ran_on edges", () => {
    const { nodes, edges } = extractGraphFacts("host-1", exec(), T0);

    expect(nodes.map((n) => n.kind).sort()).toEqual(["file", "host", "process", "process"].sort());
    const proc = nodes.find((n) => n.kind === "process" && n.label === "/usr/bin/curl");
    expect(proc).toBeDefined();
    const file = nodes.find((n) => n.kind === "file");
    expect(file?.key).toBe(`sha256:${SHA}`);

    expect(edges).toContainEqual(
      expect.objectContaining({ kind: "ran_on", to: { kind: "host", key: "host-1" } })
    );
    expect(edges).toContainEqual(expect.objectContaining({ kind: "opened" }));
    expect(edges).toContainEqual(expect.objectContaining({ kind: "spawned" }));
  });

  it("falls back to the path when there is no hash", () => {
    const { nodes } = extractGraphFacts("host-1", exec({ sha256: undefined }), T0);
    const file = nodes.find((n) => n.kind === "file");
    expect(file?.key).toBe("path:/usr/bin/curl");
  });

  it("Windows image paths are case-folded, POSIX paths are not", () => {
    const win = extractGraphFacts(
      "host-1",
      exec({ sha256: undefined, image_path: "C:\\Windows\\System32\\CMD.EXE" }),
      T0
    );
    expect(win.nodes.find((n) => n.kind === "file")?.key).toBe("path:c:\\windows\\system32\\cmd.exe");

    const posix = extractGraphFacts("host-1", exec({ sha256: undefined, image_path: "/tmp/Payload" }), T0);
    expect(posix.nodes.find((n) => n.kind === "file")?.key).toBe("path:/tmp/Payload");
  });

  it("emits no spawned edge when the parent is unknown", () => {
    const { edges } = extractGraphFacts(
      "host-1",
      exec({ parent_comm: undefined, parent_image_path: undefined }),
      T0
    );
    expect(edges.some((e) => e.kind === "spawned")).toBe(false);
  });

  it("a file_open yields an opened edge keyed by path, not hash", () => {
    const { nodes, edges } = extractGraphFacts(
      "host-1",
      { type: "file_open", meta: { pid: 100, ppid: 1, comm: "sh", timestamp_ns: 1 }, path: "/etc/passwd", flags: 0 },
      T0
    );
    expect(nodes.find((n) => n.kind === "file")?.key).toBe("path:/etc/passwd");
    expect(edges).toContainEqual(expect.objectContaining({ kind: "opened" }));
  });

  it("a connect yields a connected_to edge to a tcp network node", () => {
    const { nodes, edges } = extractGraphFacts(
      "host-1",
      { type: "connect", meta: { pid: 100, ppid: 1, comm: "curl", timestamp_ns: 1 }, daddr: "1.2.3.4", dport: 443 },
      T0
    );
    expect(nodes.find((n) => n.kind === "network")?.key).toBe("tcp:1.2.3.4:443");
    expect(edges).toContainEqual(expect.objectContaining({ kind: "connected_to" }));
  });

  it("a dns_query yields a resolved edge to a dns network node, normalized", () => {
    const { nodes, edges } = extractGraphFacts(
      "host-1",
      {
        type: "dns_query",
        meta: { pid: 100, ppid: 1, comm: "curl", timestamp_ns: 1 },
        query: "Example.COM.",
        qtype: 1,
        status: 0,
      },
      T0
    );
    expect(nodes.find((n) => n.kind === "network")?.key).toBe("dns:example.com");
    expect(edges).toContainEqual(expect.objectContaining({ kind: "resolved" }));
  });

  it("a session yields a logged_in edge from an identity to the host", () => {
    const { nodes, edges } = extractGraphFacts(
      "host-1",
      { type: "session", meta: { pid: 4, ppid: 0, comm: "winlogon", timestamp_ns: 1 }, state: "logon", target_user: "CORP\\alice", console: true },
      T0
    );
    expect(nodes.find((n) => n.kind === "identity")?.key).toBe("CORP\\alice");
    expect(edges).toContainEqual(
      expect.objectContaining({ kind: "logged_in", to: { kind: "host", key: "host-1" } })
    );
  });

  it("an event of an unrecognized shape yields nothing, not an error", () => {
    expect(extractGraphFacts("host-1", { type: "registry_set" }, T0)).toEqual({ nodes: [], edges: [] });
    expect(extractGraphFacts("host-1", null, T0)).toEqual({ nodes: [], edges: [] });
    expect(extractGraphFacts("host-1", "not an object", T0)).toEqual({ nodes: [], edges: [] });
    expect(extractGraphFacts("host-1", {}, T0)).toEqual({ nodes: [], edges: [] });
  });
});

describe("mergeGraphs", () => {
  it("deduplicates repeated nodes and edges, keeping the most recent edge", () => {
    const a = extractGraphFacts("host-1", exec(), T0);
    const b = extractGraphFacts("host-1", exec(), T1);
    const merged = mergeGraphs([a, b]);

    // Same process/file keys both times (same pid/tick/hash) -> one of each, not two.
    expect(merged.nodes.filter((n) => n.kind === "file")).toHaveLength(1);
    expect(merged.edges.filter((e) => e.kind === "ran_on")).toHaveLength(1);
    expect(merged.edges.find((e) => e.kind === "ran_on")?.at).toEqual(T1);
  });

  it("breaks a tie between two facts sharing the same `at` deterministically, not by order", () => {
    // Same node key (a Windows path differing only by case — one key, per
    // `normalizePath`), same timestamp, different label: nothing about *when*
    // these were observed picks a winner, so without a tie-break the result
    // would depend on which fact `parts` happens to list first.
    const node = (label: string): GraphNode => ({
      kind: "file",
      key: "path:c:\\windows\\system32\\cmd.exe",
      label,
      attrs: {},
      at: T0,
    });
    const forward = mergeGraphs([{ nodes: [node("C:\\Windows\\System32\\CMD.EXE")], edges: [] }, { nodes: [node("c:\\windows\\system32\\cmd.exe")], edges: [] }]);
    const reversed = mergeGraphs([{ nodes: [node("c:\\windows\\system32\\cmd.exe")], edges: [] }, { nodes: [node("C:\\Windows\\System32\\CMD.EXE")], edges: [] }]);
    expect(forward).toEqual(reversed);
  });
});

describe("caseSubgraph and hashPivot are rebuildable", () => {
  it("caseSubgraph does not depend on the order its detections are read in", () => {
    const detections = [
      { agentId: "host-1", event: exec(), timestamp: T0 },
      {
        agentId: "host-1",
        event: { type: "connect", meta: { pid: 100, ppid: 1, comm: "curl", timestamp_ns: 1 }, daddr: "1.2.3.4", dport: 443 },
        timestamp: T1,
      },
    ];
    const forward = sortGraph(caseSubgraph(detections));
    const reversed = sortGraph(caseSubgraph([...detections].reverse()));
    expect(reversed).toEqual(forward);
  });

  it("computing the same case subgraph twice (a 'rebuild') is identical", () => {
    const detections = [{ agentId: "host-1", event: exec(), timestamp: T0 }];
    expect(sortGraph(caseSubgraph(detections))).toEqual(sortGraph(caseSubgraph(detections)));
  });

  it("hashPivot turns per-agent sightings into a file node and one host node each", () => {
    const sightings = [
      { agentId: "host-1", firstSeen: T0, lastSeen: T0, count: 1 },
      { agentId: "host-2", firstSeen: T0, lastSeen: T1, count: 3 },
    ];
    const graph = hashPivot("sha256", SHA, sightings);

    expect(graph.nodes).toHaveLength(3); // 1 file + 2 hosts
    expect(graph.edges).toHaveLength(2);
    expect(graph.edges.map((e) => nodeId(e.to)).sort()).toEqual(
      ["host\u0000host-1", "host\u0000host-2"].sort()
    );
    expect(sortGraph(hashPivot("sha256", SHA, sightings))).toEqual(
      sortGraph(hashPivot("sha256", SHA, [...sightings].reverse()))
    );
  });

  it("hashPivot renders a domain pivot as a network node, not a file node", () => {
    const graph = hashPivot("domain", "example.com", [{ agentId: "host-1", firstSeen: T0, lastSeen: T0, count: 1 }]);
    expect(graph.nodes.find((n) => n.label === "example.com")?.kind).toBe("network");
  });

  it("keys an image_path pivot's subject exactly as extractGraphFacts keys the same file by path", () => {
    // SherlockOmss's review of the PR this came from: `hashPivot` used to key
    // an `image_path` subject as `file:image_path:<path>`, which never
    // matches the `path:<path>` key a case subgraph gives the same file —
    // the two could never be the same node in a console that overlays them.
    const path = "/usr/bin/curl";
    const pivot = hashPivot("image_path", path, [{ agentId: "host-1", firstSeen: T0, lastSeen: T0, count: 1 }]);
    const subject = pivot.nodes.find((n) => n.kind === "file");
    const caseNode = extractGraphFacts("host-1", exec({ sha256: undefined, image_path: path }), T0).nodes.find(
      (n) => n.kind === "file"
    );
    expect(subject?.key).toBe(caseNode?.key);
  });

  it("hashPivot's type rejects `transition`, which pairs two entities, not one", () => {
    const sightings = [{ agentId: "host-1", firstSeen: T0, lastSeen: T0, count: 1 }];
    // @ts-expect-error — `PivotKind` excludes "transition" on purpose; this
    // line exists to prove the exclusion actually compiles away, not to
    // exercise runtime behavior.
    hashPivot("transition", "a -> b", sightings);
  });
});

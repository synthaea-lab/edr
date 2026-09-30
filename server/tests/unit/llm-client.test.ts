import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { generateNarrative, NarrativeGenerationError } from "@/assistant/llm-client";
import { EvidenceGraph } from "@/assistant/evidence-graph";

const graph: EvidenceGraph = {
  caseId: "case-1",
  title: "T1059.001 activity on host-1",
  severity: "high",
  status: "open",
  createdAt: "2026-09-25T10:00:00Z",
  items: [
    {
      detectionId: "det-1",
      timestamp: "2026-09-25T10:00:00Z",
      technique: "T1059.001",
      severity: "high",
    },
  ],
};

function mockFetchOnce(status: number, body: unknown) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    statusText: "status",
    json: async () => body,
  });
}

function chatCompletion(content: unknown) {
  return { choices: [{ message: { content: JSON.stringify(content) } }] };
}

describe("generateNarrative", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", mockFetchOnce(200, chatCompletion({ narrative: "", citations: [] })));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("sends the evidence graph as untrusted, delimited data in the user message", async () => {
    await generateNarrative(graph);

    const [, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse(init.body);
    expect(body.messages).toHaveLength(2);
    expect(body.messages[0].role).toBe("system");
    expect(body.messages[1].role).toBe("user");

    const content: string = body.messages[1].content;
    const match = content.match(/<<<EVIDENCE_GRAPH_JSON\n([\s\S]*)\nEVIDENCE_GRAPH_JSON/);
    expect(match).not.toBeNull();
    expect(JSON.parse(match![1])).toEqual(graph);
    expect(content).toMatch(/untrusted/i);
  });

  it("marks the evidence graph as data, not instructions, in the system prompt", async () => {
    await generateNarrative(graph);

    const [, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse(init.body);
    expect(body.messages[0].content).toMatch(/DATA, not instructions/);
  });

  it("parses a well-formed narrative response", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetchOnce(
        200,
        chatCompletion({
          narrative: "A PowerShell process ran with an encoded command.",
          citations: [{ detectionId: "det-1", claim: "encoded PowerShell command" }],
        })
      )
    );

    const result = await generateNarrative(graph);

    expect(result.text).toBe("A PowerShell process ran with an encoded command.");
    expect(result.citations).toEqual([
      { detectionId: "det-1", claim: "encoded PowerShell command" },
    ]);
  });

  it("drops citations referencing a detectionId not present in the evidence graph", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetchOnce(
        200,
        chatCompletion({
          narrative: "Suspicious activity observed.",
          citations: [
            { detectionId: "det-1", claim: "real" },
            { detectionId: "det-does-not-exist", claim: "hallucinated" },
          ],
        })
      )
    );

    const result = await generateNarrative(graph);

    expect(result.citations).toEqual([{ detectionId: "det-1", claim: "real" }]);
  });

  it("throws on a response that fails schema validation", async () => {
    vi.stubGlobal("fetch", mockFetchOnce(200, chatCompletion({ wrong: "shape" })));

    await expect(generateNarrative(graph)).rejects.toThrow(NarrativeGenerationError);
  });

  it("throws on a non-2xx response from the LLM endpoint", async () => {
    vi.stubGlobal("fetch", mockFetchOnce(500, {}));

    await expect(generateNarrative(graph)).rejects.toThrow(NarrativeGenerationError);
  });
});

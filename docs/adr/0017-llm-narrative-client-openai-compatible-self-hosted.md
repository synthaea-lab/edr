# ADR-0017: Case narrative LLM client — OpenAI-compatible, self-hosted by default

- **Status**: accepted
- **Date**: 2026-09-25

## Context

Issue #50 needs server-side narrative generation from a case's structured
evidence (`server/assistant/`, "Explanations at detection time" in
`docs/detection/ml.md`): the LLM narrates evidence for the analyst, it never
scores or judges, and it never runs on the endpoint. `assistant/README.md`
already commits to grounded citations and visibly-labeled output.

ADR-0001 commits the control plane to a self-hosting stance: one deployable,
one database, `docker-compose up` for a working dev/self-hosted stack. No
AI/LLM dependency exists in `server/package.json` today, and adding one that
requires a cloud API key just to run the product locally would break that
stance. A choice is needed for how the narrative feature talks to a model and
what it depends on to do so.

## Decision

Speak the OpenAI-compatible chat-completions HTTP API
(`POST {LLM_BASE_URL}/chat/completions`, `response_format: json_object`) via
a minimal hand-written `fetch`-based client (`server/assistant/llm-client.ts`)
— no vendor SDK dependency.

`LLM_BASE_URL` defaults to a locally self-hosted OpenAI-compatible endpoint
(Ollama, `http://localhost:11434/v1`), so the feature works out of the box in
a self-hosted deployment with zero external network calls and zero API key.
`LLM_BASE_URL` / `LLM_MODEL` / `LLM_API_KEY` / `LLM_PROVIDER_LABEL` are
env-configurable, so an operator can point the same code at any
OpenAI-compatible provider (OpenAI directly, or others via a compatibility
shim) without a code change.

The request body is built exclusively from the `EvidenceGraph`
(`server/assistant/evidence-graph.ts`) — a fixed allowlist projection of
`Detection` fields. The client has no other input type: it cannot see a raw
`Detection.event`/`meta` blob, and evidence is never used to fine-tune or
train anything server-side.

## Consequences

Easier: swapping providers is a config change, not a dependency or code
change; no heavyweight SDK to track for vulnerabilities or breaking API
changes; the self-hosted default demonstrably keeps case evidence inside the
deployment by default, consistent with ADR-0001; response citations are
cross-checked against the evidence graph before being stored, so a
hallucinated citation is dropped rather than surfacing to the analyst.

Harder: no SDK means no built-in streaming, retry, or backoff — the initial
client is a single attempt with a timeout (`LLM_TIMEOUT_MS`), documented as a
known limitation rather than solved now; response-shape validation (zod) is
entirely on us, since different OpenAI-compatible providers have had minor
JSON-mode quirks historically.

Committed to: every narrative-generation call is tenant-scoped, evidence-graph
-only input, and audit-logged (`case.narrative.generate`), regardless of which
provider or model is configured.

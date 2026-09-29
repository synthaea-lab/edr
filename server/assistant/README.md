# server/assistant — Analyst AI Assistant

Server-side LLM assistance for the analyst, built on the grounding rule recorded in
docs/detection/ml.md: **the LLM narrates and navigates structured evidence; it never
scores, never judges, never runs on the endpoint.**

Planned capabilities, in trust order:
1. **Case narratives** — generate the human-readable story of a case from its
   evidence graph (detections + attributions + timeline), with every claim linked to
   the underlying record; regenerated on evidence change.
2. **Natural-language navigation** — "show hosts where this hash ran last week"
   compiled to hunt/graph queries the analyst can see and edit before running.
3. **Triage drafting** — suggested next steps and draft disruption playbook choices,
   always as proposals requiring the analyst's action; the assistant holds no
   execution authority of its own.

Constraints: assistant output is visibly labeled, grounded citations are mandatory,
prompts/outputs land in the audit log, and tenant data never trains shared models.

## Status

Capability 1 (case narratives) is implemented (issue #50): `evidence-graph.ts` builds
the allowlisted evidence graph a case's grouped detections project into,
`llm-client.ts` narrates it against an OpenAI-compatible endpoint (ADR-0017,
self-hosted by default), `prompt.ts` holds the versioned system prompt. Detections are
grouped into cases by the `group-detections` cron sweep
(`app/api/cron/group-detections/route.ts`) — a server-side heuristic (same agent,
30-minute window, related MITRE technique), standing in for the correlator-side
`case_id`/attribution plumbing that doesn't exist yet (tracked as a follow-up issue).
Capabilities 2 and 3 are not started.

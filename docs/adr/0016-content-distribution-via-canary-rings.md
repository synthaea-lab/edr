# ADR-0016: Content Distribution via Canary Rings

**Status:** Accepted
**Date:** 2026-09-23
**Author:** Issue #30 Implementation
**Related ADRs:** ADR-0015 (Updater manifest signing)
**Related Issues:** #30 (Updater rings), #49 (Per-site model adaptation), #73 (Detection-as-code)

---

## Context

Issue #30 originally requested "staged, signature-verified self-update with rollback" **plus** "rule/model download via canary rings" — two separate problems. ADR-0015 scoped Phase 1 to binary self-update on Linux only. This ADR addresses Phase 2: **content distribution** (rules, models, policy) without requiring binary updates.

### Requirements

1. **Canary deployment**: New content (rules/models) must deploy progressively through rings to limit blast radius:
   - Ring 0 (canary_0): 1% of fleet
   - Ring 1 (canary_1): 10% of fleet
   - Ring 2 (canary_2): 50% of fleet
   - Prod: 100% of fleet

2. **Integrity verification**: Same Ed25519 signature verification as binary manifests (ADR-0015)

3. **Rollback capability**: Failed deployments must halt and revert to previous content version

4. **Tenant isolation**: Multi-tenant control plane; each tenant has independent ring configurations

5. **Content types**:
   - **Rules**: Sigma YAML detection rules
   - **Models**: ML models (pickle + model_record.json)
   - **Policy**: JSON policy configuration

6. **No binary coupling**: Content updates must **not** require agent binary updates

---

## Decision

### 1. Content Manifest Format

**Extends ADR-0015's binary manifest** for consistency:

```typescript
{
  schema_version: 1,           // Schema version (strict rejection of unknown versions)
  release_version: 42,         // Monotone counter (anti-rollback)
  ring: "canary_0",            // Target ring
  released_at: "2026-09-23T16:00:00Z", // ISO 8601 UTC
  entries: [
    {
      path: "rules/beacon.sigma",
      type: "rule",            // Content type: rule, model, policy
      sha256: "a...a",         // SHA-256 hash (hex)
      size: 1234,              // File size in bytes
      metadata: {              // Optional metadata
        technique: "T1071.001",
        severity: "high"
      }
    },
    {
      path: "models/cmdline-iforest-linux/0.3.0/model.pkl",
      type: "model",
      sha256: "b...b",
      size: 10485760,
      metadata: { version: "0.3.0", escape_rate: 0.08 }
    }
  ],
  signature: "0...0"           // Ed25519 signature (hex) over canonical JSON
}
```

**Canonical JSON** (for signing):
- 2-space indent
- Sorted keys
- No `signature` field in signed payload

**Filename pattern**: `content-{ring}-v{version}.json`
**Example**: `content-canary_0-v42.json`

### 2. Content Storage

**Database schema** (`content_releases` table):

```prisma
model ContentRelease {
  id              String   @id @default(uuid())
  tenantId        String   // Tenant isolation
  ring            String   // canary_0, canary_1, canary_2, prod
  releaseVersion  Int      // Monotone counter
  manifestUrl     String   // Storage URL for manifest JSON
  manifestSha256  String   // SHA-256 of manifest file itself
  status          String   @default("active") // active, halted, rolled_back
  releasedAt      DateTime
  createdAt       DateTime @default(now())

  @@unique([tenantId, ring, releaseVersion])
  @@index([tenantId, ring, status])
}
```

**Artifact storage**: Object store or filesystem
- Manifests: `manifests/content-{ring}-v{version}.json`
- Artifacts: `artifacts/{path}` (e.g., `artifacts/rules/beacon.sigma`)

### 3. Agent Content Distribution Flow

**Enrollment/Heartbeat**:
- Agent includes current content `release_version` in heartbeat
- Server responds with assigned `ring` and latest `release_version` for that ring
- If server version > agent version, agent fetches new content manifest

**Content Update Flow**:
1. Agent: `GET /api/content/manifest/{ring}` → Latest manifest for assigned ring
2. Server: Returns signed content manifest (tenant-scoped)
3. Agent: Verifies Ed25519 signature using embedded public key
4. Agent: Checks `release_version` > current (anti-rollback)
5. Agent: Downloads artifacts, verifies SHA-256 hashes
6. Agent: Applies content (loads new rules/models)
7. Agent: Reports success/failure in next heartbeat

**Applied-content layout and reload (issue #530)**:
- Applied content lives under one content directory, `<storage.state_dir>/content` by default. Artifact `path` values are relative to it: Sigma rules under `rules/sigma/<platform>/`, YARA under `rules/yara/`. `agent apply-content-manifest` writes there and `agent run` loads from there; both share the same default and the same `--content-dir` override.
- Step 6 is a hot reload, not a restart: after a successful apply, `apply-content-manifest` sends the running agent an IPC `ReloadContent` request (local socket, protocol v2), and the detection sink re-reads Sigma and YARA and swaps them in. No running agent is not an error: the content is on disk and loads at the next start. `SIGHUP` is not used; it already means graceful shutdown.
- A reload never disarms detection: an absent content subdirectory unloads that engine, but a present one that fails to load leaves the previous engine running and is reported (`*_reload_failed`). YARA fails the whole set on one bad rule; Sigma skips a bad rule with a warning, so a partly broken Sigma set shows up as a lower rule count.
- The ring comes from `[updates] ring` in `agent.toml` (ADR-0013 amendment), with `--ring` as an override, and `apply-content-manifest` takes the control plane URL and mTLS pair from the same file when `--server` is omitted. There is no default ring. An explicit `--server` is used as given and never receives the configured client certificate.
- Not covered yet: model swap (the ML scorer still loads once at startup) and ring-driven fetch scheduling (nothing runs `apply-content-manifest` periodically yet).

**Failure Handling**:
- Signature verification failure → reject manifest, report to server
- Hash mismatch → reject artifact, report to server
- Load failure (e.g., invalid Sigma rule) → rollback to previous content, report to server
- Server tracks failure rate per ring; auto-halts deployment if >threshold

### 4. Ring Progression Strategy

**Deployment Timeline**:
- **Day 0**: Deploy to Ring 0 (canary_0, 1% fleet)
- **Day 1**: If Ring 0 healthy (FP rate < threshold, detection rate >= expected), promote to Ring 1
- **Day 3**: If Ring 1 healthy, promote to Ring 2
- **Day 7**: If Ring 2 healthy, promote to Prod

**Health Metrics** (per ring):
- Silent agent rate (% agents with no heartbeat in 5 minutes)
- False positive rate (detections marked as false_positive)
- Detection rate (expected detections per scenario)
- Load failure rate (% agents reporting artifact load failures)

**Auto-Halt Criteria**:
- Silent agent rate > 5%
- FP rate increase > 2× baseline
- Load failure rate > 10%

**Manual Rollback**:
- Halting a ring stops delivery: its newest release is marked `halted`, and the
  manifest and artifact endpoints return `423 Locked` instead of serving the
  previous active release. Agents keep their installed content and fetch no new
  content until the halt is lifted or the ring is rolled back.
- Rollback is a separate admin action that marks the halted release
  `rolled_back` and serves the previous active `release_version`.

### 5. API Endpoints

**Agent Endpoints** (mTLS authentication):
```
GET  /api/content/manifest/{ring}  → ContentManifest, or 423 when the ring is halted
GET  /api/content/artifact/{path}  → Binary artifact, or 423 when the ring is halted
POST /api/content/report            → { status: "success"|"failure", details }
```

**Admin Endpoints** (better-auth + session):
```
POST /api/content/release           → Create new content release for ring
POST /api/content/promote           → Promote ring to next stage
POST /api/content/halt              → Halt deployment for ring
POST /api/content/rollback          → Rollback ring to previous version
GET  /api/content/releases          → List content releases (tenant-scoped)
GET  /api/rings/{ring}/health       → Ring health metrics
```

---

## Consequences

### Positive

1. **Independent release cadence**: Rules/models can ship independently of agent binaries
2. **Canary safety**: Progressive rollout limits blast radius
3. **Fast iteration**: Rule updates deploy in minutes (vs days for binary releases)
4. **Tenant flexibility**: Each tenant can have different ring configurations
5. **Consistent verification**: Reuses ADR-0015's Ed25519 signing infrastructure

### Negative

1. **Storage overhead**: Manifests + artifacts stored per ring per tenant
2. **Network bandwidth**: Large models (10MB+) consume bandwidth on updates
3. **Complexity**: Agents must manage dual update paths (binary + content)
4. **Partial state**: Agent may have binary v1.0 + content v42 (complex debugging)

### Mitigations

- **Storage**: Use object store (S3/GCS) with lifecycle policies (delete superseded versions after 30 days)
- **Bandwidth**: Delta updates for models (future enhancement)
- **Complexity**: Agent logs content version prominently; server tracks per-agent state
- **Partial state**: Compatibility matrix enforced (agent v1.0 → content v40-45 only)

---

## Alternatives Considered

### 1. Embed Content in Binary Releases

**Rejected**: Forces binary rebuild for every rule change; slow iteration (days vs minutes)

### 2. Git-Based Distribution

**Rejected**: Requires agents to run `git pull`; complex authentication; no signature verification

### 3. Docker-Style Layer Deduplication

**Deferred**: Valuable for large models, but adds significant complexity. Revisit in Issue #407.

---

## Implementation Notes

### Ring Assignment Logic

**Server-side** (per tenant):
- Agents default to `ring = "prod"` on enrollment
- Admin manually assigns agents to canary rings via `/api/agents/{id}/ring`
- Ring membership is **sticky**: agent stays in ring until explicitly reassigned

**Ring Size Targets**:
- canary_0: ~1% of enrolled agents
- canary_1: ~10% of enrolled agents
- canary_2: ~50% of enrolled agents
- prod: All remaining agents

Admin UI shows ring distribution per tenant and suggests agents for canary enrollment (e.g., dev/staging machines).

### Content Signing Workflow

**Development**:
- Use test key (`SYNTHAEA_CONTENT_TEST_KEY = true`, same as updater test key)
- Private key in repo (`.dev-keys/content-signing.key`)

**Production** (deferred, same as ADR-0015):
- HSM-backed private key
- Signing performed by CI/CD or release manager
- Public key embedded in agent binary at compile time

### Compatibility Matrix

**Agent v1.0** supports:
- Content schema v1
- Content types: rule, model, policy

**Future Agent v2.0** may support:
- Content schema v2 (e.g., delta updates)
- Content types: yara, correlation_rule

Agents **reject** manifests with `schema_version > max_supported`.

### Content Types Detail

**Rule** (`type: "rule"`):
- Format: Sigma YAML
- Validation: Agent parses YAML, rejects if invalid
- Application: Loaded into detection engine, replaces previous rule with same ID

**Model** (`type: "model"`):
- Format: Pickle (`.pkl`) + JSON metadata (`model_record.json`)
- Validation: Agent verifies schema v3 (Issue #45 RobustnessCard)
- Application: Loaded into ML engine, replaces previous model for same platform

**Policy** (`type: "policy"`):
- Format: JSON
- Validation: Agent parses JSON, validates against schema
- Application: Merged with agent config, overrides local settings

---

## References

- **Issue #30** — "Build updater: self-update + content distribution client"
- **Issue #49** — "Per-site model adaptation loop" (primary consumer)
- **Issue #73** — "Detection-as-code ring deployment" (shares mechanism)
- **ADR-0015** — Updater manifest signing and rollback (binary self-update)
- **ADR-0010** — Shared policy model (Ed25519 choice)
- **ADR-0009** — Model record / scenario-replay binding (model_record.json schema)

---

**Next Steps (Issue #30 Phase 2)**:
1. ✅ Content manifest format (this ADR)
2. ⏳ Server API implementation (Task #15)
3. 🚧 Agent integration (fetch + verify + apply content): manifest fetch/verify and artifact download/apply merged (#509, #520); Sigma/YARA hot reload in review (#530); model swap and periodic fetch pending
4. ⏳ Ring health monitoring + auto-halt
5. ⏳ Integration tests + lab scenario

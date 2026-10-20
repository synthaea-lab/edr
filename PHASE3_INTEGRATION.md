# Phase 3 Integration Guide (Issue #46)

**Status:** Blocked by #13 (ML scorer integration), #14 (cmdline scorer), #47 (agent integration)

This document describes how to complete Phase 3 of issue #46 (correlator no-score handling) once the ML scorer is integrated into the agent.

## Current State

Phases 1-2 are complete:
- ✅ **Phase 1:** Conformal calibration (Python)
  - `ml/synthaea_ml/calibration/calibrate_conformal.py`
  - TrainingRecord schema v3 with `conformal_calibration` and `feature_bounds`
  - Training scripts updated (train_linux.py, train_windows.py, train_correlation.py)
  - `model_metadata.json` exported alongside `model.onnx`

- ✅ **Phase 2:** OOD guards (Rust)
  - `crates/ml/src/bounds.rs` with `FeatureBounds::validate`
  - `ScorerError::FeatureOutOfBounds` variant
  - `CmdlineScorer::from_onnx_bytes_with_metadata` loads bounds from metadata
  - `CorrelationScorer` has same OOD validation
  - Legacy models (no metadata) still work

## Phase 3: Correlator Integration

### Goal

Allow the correlator's `update_belief` to accept an optional ML LLR contribution, with clean semantics for "no score available" (gating, OOD rejection, errors).

### Changes Required

#### 1. Update `bayes::update_belief` Signature

**File:** `crates/correlator/src/bayes.rs:123`

Current:
```rust
pub(crate) fn update_belief(state: &mut BeliefState, v: &BehaviorVector, now_ns: u64)
```

Proposed:
```rust
pub(crate) fn update_belief(
    state: &mut BeliefState,
    v: &BehaviorVector,
    ml_llr: Option<f32>,  // NEW: ML contribution (None = no score)
    now_ns: u64,
)
```

Add before `state.last_update_ns = now_ns`:
```rust
// ML contribution: only if we have a score
if let Some(llr) = ml_llr {
    state.log_odds += llr;
}
// If ml_llr is None, skip this contribution entirely (no evidence)
```

**Key semantics:**
- `None` means "I don't know" (not "benign")
- OOD rejection → `None` → no ML evidence contribution
- T1 hand-calibrated LLRs still apply normally

#### 2. Update Call Sites in `engine.rs`

**File:** `crates/correlator/src/engine.rs`

Find all calls to `update_belief` and add the `ml_llr` parameter:

```rust
// OLD:
update_belief(&mut belief, bv, now_ns);

// NEW:
update_belief(&mut belief, bv, None, now_ns);
```

This `None` is not a placeholder waiting on agent wiring — it is permanent:
`on_event` always calls `update_belief` with `None` (`engine.rs:286`), and the
ML term is added separately, after `on_event` returns, by
`update_belief_with_ml` (point 3 below). Computing the ML score needs the
belief state `on_event` just built, so it cannot happen inside the same call
without restructuring the belief update itself — adding it as a second,
optional call keeps `on_event` usable with no ML scorer loaded at all. See
`update_belief_with_ml`'s own doc (`engine.rs:470-479`): calling
`update_belief` a second time here, instead, used to double-count the
hand-calibrated feature evidence (PR #345 review).

#### 3. Agent Integration Point (shipped, #47)

**File:** `agent/src/sink.rs`'s `correlate()`, right after `engine.on_event(event)`.

Wiring pattern, matching what is actually there:

```rust
let pid = event.meta().pid;
let generation = event.meta().process_generation;
if let Some(ref mut scorer) = *self.ml_scorer.lock().unwrap() {
    let ml_llr = match scorer.score(engine.bus(), pid, generation) {
        Ok(Some(score)) => Some(ml::score_to_llr(score)),
        Ok(None) => None,  // Gated (< MIN_EVENT_COUNT)
        Err(ml::ScorerError::FeatureOutOfBounds { .. }) => {
            // Log OOD rejection for telemetry
            tracing::warn!(pid = pid, "ML scorer OOD rejection");
            None  // Treat OOD as no score
        }
        Err(e) => {
            tracing::error!(pid = pid, error = %e, "ML scorer error");
            None  // Fail open: skip ML contribution
        }
    };

    // Update belief with optional ML LLR
    if let Err(()) = engine.update_belief_with_ml(pid, generation, ml_llr) {
        // No behavior vector yet for this pid — normal for its first events.
    }
}
```

**Error handling policy:**
- `FeatureOutOfBounds` → log warning, treat as `None`
- Other errors → log error, treat as `None` (fail open)
- Gating (`event_count < MIN_EVENT_COUNT`) → `None` (no evidence yet)

### Testing

#### Unit Tests

**File:** `crates/correlator/tests/bayes.rs` (add after Phase 3 changes)

```rust
#[test]
fn test_update_belief_with_ml_llr() {
    let mut state = BeliefState::new(0);
    let v = BehaviorVector::default();

    // With ML contribution
    update_belief(&mut state, &v, Some(1.5), 1_000_000_000);
    assert!(state.log_odds > PRIOR_LOG_ODDS);  // ML pushed belief up
}

#[test]
fn test_update_belief_ml_none_skipped() {
    let mut state = BeliefState::new(0);
    let v = BehaviorVector::default();

    // Without ML contribution
    update_belief(&mut state, &v, None, 1_000_000_000);
    // Only hand-calibrated LLRs applied
}
```

#### End-to-End Verification (After #47)

1. **Run agent with ML scorer on benign baseline**
   - Check telemetry: no OOD rejections on training-distribution data
   - Verify belief updates include ML LLR contributions

2. **Inject synthetic OOD vector**
   - Example: cmdline length = 1M chars (far outside training bounds)
   - Check telemetry: OOD rejection logged
   - Verify: no ML LLR contribution, hand-calibrated LLRs still apply

3. **Inject low-event-count process**
   - Example: process with only 1-2 events in correlator window
   - Check: `ml_llr = None` due to `MIN_EVENT_COUNT` gate
   - Verify: no ML contribution, no error

## Backward Compatibility

- Legacy models (no `model_metadata.json`) → `bounds = None` → no OOD validation
- Existing correlator code → pass `ml_llr = None` until agent wiring is complete
- Graceful degradation: system works without ML scorer, just missing that evidence term

## Migration Checklist

- [ ] Update `bayes::update_belief` signature (add `ml_llr` parameter)
- [ ] Update all `update_belief` call sites in `engine.rs` (pass `None` initially)
- [ ] Expose `update_belief_with_ml` or similar in correlator public API (for agent)
- [ ] Implement agent sink wiring (#47)
- [ ] Add unit tests for `ml_llr = Some(...)` and `ml_llr = None`
- [ ] End-to-end test: benign baseline (no OOD), OOD injection, low event count
- [ ] Update `docs/detection/ml.md` with Phase 3 semantics

## Timeline

Phase 3 can proceed once:
1. ML scorer is integrated into agent (#13, #14)
2. Agent has access to `CorrelationScorer` (#47)
3. Correlator exposes an API to pass `ml_llr` from agent sink

Estimated effort: 1-2 hours for correlator changes + agent wiring, 1-2 hours for tests.

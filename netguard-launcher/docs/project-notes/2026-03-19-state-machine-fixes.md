# 2026-03-19 — State Machine Transition Table Fixes

## Context

Spec review identified 3 internal inconsistencies in the state machine
transition table and `allowed_commands()`. The code faithfully implemented
the spec, but the spec itself had gaps that would create impossible runtime
scenarios. All 3 were fixed in code and spec simultaneously.

---

## Issues Found and Fixed

### Issue 1 — Degraded(CapabilitiesMissing) → Operating (CRITICAL)

**Problem:** `allowed_commands()` returned `[RunWorkflow, LoadFile]` for
`CapabilitiesMissing`, but executing those commands requires transitioning to
`Operating`. `can_transition_to(Degraded, Operating)` returned `false` —
making those commands "allowed" but unexecutable.

**Fix:** Added `(Degraded { CapabilitiesMissing }, Operating { .. }) => true`
to `can_transition_to()`. Placed before the generic `Degraded → Connecting`
arm so only `CapabilitiesMissing` gets this transition path. Other degraded
reasons (e.g. `SidecarCrashed`) are still blocked from `Operating`.

### Issue 2 — Operating → Degraded state loss (noted, not code-changed)

**Problem:** After `Degraded(CapsMissing) → Operating → Ready`, the degraded
status is lost. The frontend stops showing the "Capture unavailable" banner.
Per ADR 006, `CapabilitiesMissing` is persistent, not transient.

**Resolution:** The `Operating → Degraded` transition already exists in
`can_transition_to()`. The orchestrator (when implemented) must return to
`Degraded { CapabilitiesMissing }` instead of `Ready` when the prior state
was degraded. No `state.rs` change needed — this is an orchestrator-level
concern tracked for Phase 3.

### Issue 3 — IpcSocketUnavailable command permissions

**Problem:** The `DegradedReason` reference table says `IpcSocketUnavailable`
has "Degraded" capability for both capture and analysis (stdio fallback). But
`allowed_commands()` returned `&[]` for all degraded reasons except
`CapabilitiesMissing`.

**Fix:** Extended the `allowed_commands()` match to also permit `RunWorkflow`
and `LoadFile` for `IpcSocketUnavailable` using an or-pattern:

```rust
Self::Degraded {
    reason: DegradedReason::CapabilitiesMissing
        | DegradedReason::IpcSocketUnavailable,
    ..
} => &[CommandKind::RunWorkflow, CommandKind::LoadFile],
```

---

## Deferred Items (require architectural discussion)

These were identified during analysis but intentionally not implemented:

- **Connecting → Degraded:** Would support retry-before-fatal during handshake
- **Ready/Operating → Fatal:** Would handle unrecoverable runtime errors directly
- **Fatal → ShuttingDown:** Would allow cleanup on SIGTERM in fatal state

All three require ADR-level discussion before adding.

---

## Files Changed

| File | Change |
|------|--------|
| `src/orchestrator/state.rs` | New transition arm, `allowed_commands()` or-pattern, 3 new tests |
| `.claude/rules/state-machine.md` | Transition table + allowed commands table updated |
| `ARCHITECTURE.md` | Added full state machine transition table section |
| `docs/TODO/phase-1-foundation.md` | Tracked fixes as completed |

---

## Build Health

- `cargo test` — 99 passed, 0 failed (3 new tests added)
- `cargo check` — clean
- Pre-existing clippy warnings unchanged (dead_code, private_interfaces)

---

## Next Session Priority

Unchanged from 2026-03-18:

1. Configuration system (`UserPreferences`, TOML read/write, config discovery)
2. Validation layer (interface names, BPF filters, output paths, durations)
3. Environment checker (`EnvironmentChecker` with all pre-flight checks)
4. `main.rs` panic hook + minimal CLI wiring for `doctor`

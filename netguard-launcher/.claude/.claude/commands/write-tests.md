# Write Tests

Follow this process. Confirm with the user before creating any test file.

## Step 1 — Identify Scope

Read the relevant source file. Determine:
- Module being tested
- Unit / integration / property test?
- Extending existing tests or new file?

## Step 2 — Load Relevant Rules

- Testing `state.rs` → `.claude/rules/state-machine.md`
- Testing error variants → `.claude/rules/error-handling.md`
- Testing IPC → `.claude/rules/ipc-protocol.md`
- Testing anything Python-adjacent → `.claude/rules/python-boundary.md`

## Step 3 — Plan the Tests

**Unit tests:** Name (pattern: `given_{context}_when_{action}_then_{result}`),
what property it verifies, what it does NOT test.

**Integration tests:** What real components are involved, what is mocked and why,
what the observable outcome must be.

**Property tests:** Confirm the three required properties:
1. Never panics on arbitrary input
2. Deterministic
3. Correct (valid accepted, invalid rejected)

**Confirm the plan with the user before writing any code.**

## Step 4 — Write Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // One comment explaining WHY this test exists.
    #[test]
    fn given_ready_state_when_start_capture_then_transition_allowed() {
        let state = SystemState::Ready;
        assert!(state.can_transition_to(&SystemState::Operating {
            operation: ActiveOperation::Capture,
        }));
    }
}
```

Rules:
- Use `result.unwrap()` in tests, not `assert!(result.is_ok())`
- Test naming: `given_{context}_when_{action}_then_{result}`
- Never leave `todo!()` inside a test

## Step 5 — Run and Report

```bash
cargo test [module_name]
```

Report: how many pass, any failures with full output.

## Step 6 — Coverage Check

Verify: happy path, sad path, edge cases, adjacent invalid state transitions.
Ask the user whether uncovered scenarios should be added now or deferred.

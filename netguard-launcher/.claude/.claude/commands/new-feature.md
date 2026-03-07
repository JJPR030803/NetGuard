# New Feature / Phase Work

Before writing a single line of code, complete all steps in order.
Confirm with the user before proceeding past Step 3.

## Step 1 — Load Context

Read silently:
- `CLAUDE.md` → check the "Current Working Context" block
- `IMPLEMENTATION_TODO.md` → find the current phase checklist
- `IMPLEMENTATION.md` → find the relevant "How to..." section

Report: current phase, which checklist item this maps to, any prerequisites.

## Step 2 — Check Architecture Constraints

Read `.claude/rules/adr-decisions.md`.

Identify which ADRs govern this area. Then load additional rule files as needed:
- Touches Python? → `.claude/rules/python-boundary.md`
- Adds a state transition? → `.claude/rules/state-machine.md`
- Touches IPC? → `.claude/rules/ipc-protocol.md`
- Adds error variants? → `.claude/rules/error-handling.md`

Report any constraints the implementation must respect.

## Step 3 — Write the Implementation Plan

Produce a numbered plan listing:
1. Every file that will be created or modified (full path)
2. One sentence per file describing the change
3. Which tests need to be written
4. Expected outcome of `cargo test` after completion

**Stop here. Confirm the plan with the user before writing any code.**

## Step 4 — Implement (After Confirmation)

For each file:
1. State: "I will now create/edit [file]. Confirming..."
2. Wait for confirmation
3. Make the change
4. Run `cargo check`
5. Move to the next file

Do not combine multiple file changes into one step.

## Step 5 — Write Tests

1. Write unit tests in `#[cfg(test)]` block
2. Write integration tests if cross-module behavior is involved
3. Run `cargo test` and report results
4. Fix failures before marking complete

## Step 6 — Update Context

After everything passes, run `/update-context` to refresh `CLAUDE.md`.

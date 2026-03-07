# Phase Validation Gate

Run the gate for the current phase and report results.
Do not fix anything automatically — report only, then ask.

## Step 1 — Determine Current Phase

Read "Phase Status" table and "Current Working Context" in `CLAUDE.md`.

## Step 2 — Run Gate Commands

### Gate 1 (Phase 1)
```bash
cargo test
cargo clippy -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
cargo fmt --check
cargo run -- doctor
```

### Gate 2 (Phase 2)
```bash
cargo test
cargo test --test ipc
uv run pytest tests/ipc/ -v
```
Note: "Kill Python sidecar mid-run and verify supervisor restarts — manual verification required."

### Gate 3 (Phase 3)
```bash
cargo test
just check
netguard interfaces
netguard doctor
```
Note: "Manual check: `netguard capture --interface lo --duration 5 --output /tmp/test.parquet`"

### Gate 4 (Phase 4)
```bash
just check
just security
just test-fuzz
just bench
```

## Step 3 — Report Results

For each command:
- ✅ PASS — with output summary
- ❌ FAIL — with full error output, nothing truncated
- ⏭ SKIP — with reason

## Step 4 — Gate Summary

```
Gate [N] Status: PASS / FAIL / PARTIAL

Passing:  [list]
Failing:  [list with short description]
Blocked:  [anything that couldn't run and why]

Next step: [one sentence — what to address first]
```

Do not automatically fix anything.

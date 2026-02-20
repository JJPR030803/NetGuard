# NetGuard Implementation Guide
**Version:** 1.0
**Date:** February 2026
**Purpose:** Daily implementation reference — how to build each component
correctly, safely, and in the right order.

This document answers "how do I write this code" not "what code do I write."
For architectural decisions and rationale, see `ARCHITECTURE.md`.

---

## Table of Contents

1. [Phase Overview](#1-phase-overview)
2. [Project Scaffold](#2-project-scaffold)
3. [How to Write Rust in This Project](#3-how-to-write-rust-in-this-project)
4. [How to Write Python in This Project](#4-how-to-write-python-in-this-project)
5. [How to Write Tests](#5-how-to-write-tests)
6. [How to Add an IPC Action](#6-how-to-add-an-ipc-action)
7. [How to Add a New State Transition](#7-how-to-add-a-new-state-transition)
8. [How to Add a CLI Command](#8-how-to-add-a-cli-command)
9. [Security Tooling Setup](#9-security-tooling-setup)
10. [Justfile Reference](#10-justfile-reference)
11. [Phase 1 Checklist — Foundation](#11-phase-1-checklist--foundation)
12. [Phase 2 Checklist — Sidecar + IPC](#12-phase-2-checklist--sidecar--ipc)
13. [Phase 3 Checklist — CLI](#13-phase-3-checklist--cli)
14. [Phase 4 Checklist — Hardening + MVP](#14-phase-4-checklist--hardening--mvp)
15. [Validation Gates](#15-validation-gates)

---

## 1. Phase Overview

```
Phase 1 (Week 1): Foundation
    Rust project scaffold, error types, state machine,
    config manager, environment checker, panic hook.
    Goal: cargo test passes, just doctor runs.

Phase 2 (Week 2): Sidecar + IPC
    IPC server, envelope, framing, supervisor, heartbeat,
    Python sidecar, handshake, sidecar tests.
    Goal: Rust and Python can talk, supervisor restarts work.

Phase 3 (Week 3): CLI
    Orchestrator run loop, OrchestratorHandle, CLI commands,
    display layer, permissions, first-run wizard.
    Goal: netguard capture --interface eth0 runs a real capture.

Phase 4 (Week 4): Hardening + MVP
    Property tests, benchmarks, security audit, full just
    pre-commit pipeline passing, end-to-end test.
    Goal: MVP that can run any NetGuard workflow cleanly.
```

The phases are sequential. Do not start Phase 2 until Phase 1's validation
gate passes. A working foundation is worth more than half-working features.

---

## 2. Project Scaffold

### Directory Structure

```
netguard-launcher/          ← Rust crate (new)
├── Cargo.toml
├── Cargo.lock
├── deny.toml               ← cargo-deny policy
├── rustfmt.toml
├── .cargo/
│   └── config.toml
├── src/
│   ├── main.rs             ← orchestration only, no logic
│   ├── lib.rs              ← all public exports
│   ├── error.rs            ← error hierarchy
│   ├── orchestrator/
│   │   ├── mod.rs
│   │   ├── state.rs
│   │   ├── handle.rs
│   │   ├── supervisor.rs
│   │   ├── environment.rs
│   │   └── commands.rs
│   ├── cli/
│   │   ├── mod.rs
│   │   ├── args.rs
│   │   └── handlers.rs
│   ├── tui/                ← stub only in Phase 1-3
│   │   └── mod.rs
│   ├── core/
│   │   ├── mod.rs
│   │   ├── models/
│   │   │   ├── mod.rs
│   │   │   ├── interface.rs
│   │   │   ├── capture.rs
│   │   │   └── workflow.rs
│   │   ├── operations/
│   │   │   ├── mod.rs
│   │   │   ├── interface_ops.rs
│   │   │   ├── capture_ops.rs
│   │   │   └── workflow_ops.rs
│   │   └── validation.rs
│   ├── infra/
│   │   ├── mod.rs
│   │   ├── ipc/
│   │   │   ├── mod.rs
│   │   │   ├── server.rs
│   │   │   ├── envelope.rs
│   │   │   └── health.rs
│   │   ├── permissions/
│   │   │   ├── mod.rs
│   │   │   ├── linux.rs
│   │   │   ├── macos.rs
│   │   │   └── windows.rs
│   │   ├── python/
│   │   │   ├── mod.rs
│   │   │   ├── env.rs
│   │   │   └── executor.rs
│   │   ├── config/
│   │   │   └── mod.rs
│   │   └── logging/
│   │       └── mod.rs
│   └── display/
│       ├── mod.rs
│       ├── terminal.rs
│       ├── tables.rs
│       └── progress.rs
├── tests/
│   ├── common/
│   │   └── mod.rs
│   ├── ipc/
│   │   └── roundtrip.rs
│   ├── orchestrator/
│   │   └── state_machine.rs
│   └── cli/
│       └── commands.rs
├── benches/
│   └── ipc_latency.rs
└── docs/
    └── adr/

netguard/                   ← existing Python project (unchanged root)
└── src/
    └── netguard/
        ├── ipc_sidecar.py  ← NEW: add here
        ├── ipc/
        │   ├── __init__.py
        │   ├── framing.py  ← NEW: FramedSocket
        │   └── envelope.py ← NEW: envelope helpers
        └── capture/
            └── checkpointed_writer.py  ← NEW
```

### Cargo.toml Key Dependencies

```toml
[dependencies]
# Async runtime
tokio = { version = "1", features = ["full"] }

# CLI parsing
clap = { version = "4", features = ["derive"] }

# TUI (stub phase 1-3, implement phase 4+)
ratatui = "0.26"
crossterm = "0.27"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"

# Error handling
thiserror = "1"
anyhow = "1"      # only in main.rs and test code, never in library code

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
tracing-appender = "0.2"

# IPC
uuid = { version = "1", features = ["v4"] }

# Config
dirs = "5"

# Resource limits (Unix only)
[target.'cfg(unix)'.dependencies]
nix = { version = "0.27", features = ["resource", "process"] }

[dev-dependencies]
proptest = "1"
criterion = { version = "0.5", features = ["async_tokio"] }
tokio-test = "0.4"

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true
```

---

## 3. How to Write Rust in This Project

### Error Handling Rules

**Never use `unwrap()` or `expect()` in library code.** Clippy is configured with
`-D clippy::unwrap_used` and `-D clippy::expect_used` — these will fail the build.
Every `Option` and `Result` must be handled explicitly.

For `Option` use `ok_or_else` to convert to `Result` with a meaningful error:
```
option.ok_or_else(|| Error::Config(ConfigError::MissingField("field_name")))
```

For `Result` use `?` to propagate with context, or `map_err` to convert error
types at layer boundaries.

**In `main.rs` and test code**, `unwrap()` and `expect()` are acceptable. The
`anyhow` crate is allowed in `main.rs` only.

**Error messages must be actionable.** Every error variant must implement
`user_message()` and optionally `suggestion()`. The user always sees a message
that tells them what happened and what to do about it, never a raw Rust error.

### Async Rules

Use `tokio::spawn` for concurrent tasks that run independently of the caller.
Use `.await` for sequential async operations within a task.
Never use `std::thread::sleep` in async code — use `tokio::time::sleep`.
Never call synchronous blocking code directly in an async context — use
`tokio::task::spawn_blocking` for CPU-heavy or blocking operations.

All functions that do I/O are `async`. Functions that are purely computational
are sync. This boundary is strict — do not make sync functions async "just in case."

### State Mutation Rules

`SystemState` is mutated only inside `Orchestrator::transition_to()`.
`BackendState` is mutated only inside the orchestrator's IPC message handler.
No other code mutates these types. If you find yourself wanting to mutate state
from a handler or a frontend, the correct answer is to send a message to the
orchestrator instead.

### Struct Design Rules

Prefer builder patterns for structs with more than 3 fields. Builders enforce
that required fields are provided at compile time. Derive `Debug` on all structs.
Derive `Clone` only when the type actually needs to be cloned — not speculatively.

All public types must have doc comments. Doc comments on functions explain what
the function does from the caller's perspective, not how it is implemented.
Include examples in doc comments for validation functions and builders.

### Module Visibility Rules

Keep things private by default. Only make items `pub` when they need to be
accessible from another module. Use `pub(crate)` for items that are crate-internal
but cross module boundaries. The public API of the crate is what is exported from
`lib.rs` — nothing else should be `pub` if it is not in `lib.rs`.

---

## 4. How to Write Python in This Project

### Type Annotations

All functions in `ipc_sidecar.py` and the new `ipc/` module must have complete
type annotations. Use `from __future__ import annotations` at the top of every
new file for forward reference support. Use `X | Y` union syntax (Python 3.10+).

Run `mypy` with `--strict` on all new code before committing. Existing Python core
code is exempt from strict mypy but new sidecar code is not.

### Error Handling Rules

The sidecar wraps every core call in try/except. Catch specific exceptions where
possible (`ValueError`, `OSError`, etc.) and the broad `Exception` only as a last
resort. Never use bare `except:` without `Exception` — this catches `SystemExit`
and `KeyboardInterrupt`.

Never silence exceptions with `pass`. Either handle them, log them, or re-raise.
The only acceptable silent except is in signal handlers and `__del__` methods
where raising would cause worse problems.

### New File Checklist

Every new Python file in the sidecar layer must have:
- Module-level docstring explaining the file's purpose
- `from __future__ import annotations`
- All imports sorted (ruff handles this)
- Type annotations on all function signatures
- Google-style docstrings on public functions and classes
- No `print()` statements — use `logging` only

### Logging Rules

Use the `netguard` logger hierarchy:
- `netguard.ipc` for socket/framing events
- `netguard.ipc.sidecar` for sidecar lifecycle events
- `netguard.ipc.dispatch` for command routing events

Never log sensitive data (packet payloads, credentials, IP addresses of internal
hosts) at INFO or above. DEBUG level only for sensitive data, with a comment
explaining why it is acceptable at debug level.

---

## 5. How to Write Tests

### Rust Test Principles

Tests live close to the code they test. Unit tests are in `#[cfg(test)]` blocks
at the bottom of the file being tested. Integration tests are in `tests/`.

Every test has a comment explaining what property or behavior it verifies, not
just what it does mechanically. A future reader should understand why the test
exists, not just what it checks.

Test names follow the pattern: `given_context_when_action_then_result`. For
example: `given_degraded_state_when_start_capture_then_rejected`.

Use `tokio::test` for async tests. Use `#[ignore]` for tests that require
hardware, root, or external services. Tag ignored tests with a comment explaining
what they require.

Avoid `assert!(result.is_ok())` — prefer `result.unwrap()` in tests (unwrap is
allowed in test code) so failures show the actual error value.

### Python Test Principles

All test files have a module docstring explaining what layer is being tested and
what is mocked vs real.

Use `pytest.fixture` for all shared setup. Fixtures that create real resources
(sockets, temp files) use `yield` and clean up in the finally block, not in a
separate teardown.

Test parametrize with `@pytest.mark.parametrize` for testing multiple valid/invalid
inputs. This is preferred over multiple nearly-identical test functions.

Never test implementation details — test observable behavior. If a test breaks
because you renamed a private method, the test is testing the wrong thing.

### Property Test Rules (Rust)

Property tests live in `tests/fuzz/` and are tagged `#[ignore]` (they are run
separately via `just test-fuzz`). Each property test documents which mathematical
property it is verifying. The three required properties for every validator:
1. Never panics on any input
2. Deterministic (same input always gives same output)
3. Correct (valid inputs accepted, invalid inputs rejected)

---

## 6. How to Add an IPC Action

Follow these steps in order. Do not skip steps.

**Step 1 — Update `ARCHITECTURE.md`**
Add the new action to the "Defined Actions" table. Document: action name,
direction (Rust→Python or Python→Rust), type (REQUEST/EVENT/etc.), description.
Commit this before writing any code.

**Step 2 — Define the payload schema**
Write the payload schema as a comment or doc struct. What fields does it require?
What fields are optional? What are the valid values? This is the contract between
Rust and Python.

**Step 3 — Add the Rust side**
In `orchestrator/commands.rs`, add the new `OrchestratorCommand` variant if this
is user-initiated. In the orchestrator's `handle_command()`, add the dispatch
case. Create the `Envelope::request()` with the correct action string.

**Step 4 — Add the Python side**
In `ipc_sidecar.py`, add the handler branch in `handle_command()`. Call the
correct Python core function. Return the response envelope. Handle exceptions.

**Step 5 — Write tests first (TDD)**
Write the Layer 3 (core translation) test before implementing the handler.
The test defines the expected call signature. Then implement until the test passes.

**Step 6 — Update the Justfile action table**
If the action is user-visible, add it to the CLI commands reference in the Justfile
documentation comment.

---

## 7. How to Add a New State Transition

**Step 1 — Justify the transition**
Write one sentence explaining why this transition is needed. If you cannot explain
it clearly, the transition may not be needed or may indicate a design issue.

**Step 2 — Update `can_transition_to()` in `state.rs`**
Add the new `(from, to)` pair to the match expression. Be precise — only add
exactly the transitions that should be allowed.

**Step 3 — Update `allowed_commands()` if needed**
If the new state has different command permissions, update the match in
`allowed_commands()`.

**Step 4 — Add a unit test**
Test that the new transition is allowed. Test that adjacent transitions that
should NOT be allowed are still rejected. Always test both directions.

**Step 5 — Update `ARCHITECTURE.md`**
Update the state transition diagram if the new state or transition changes the
overall flow.

---

## 8. How to Add a CLI Command

**Step 1 — Define the subcommand in `cli/args.rs`**
Add the new variant to the `Commands` enum with Clap derive attributes.
Include `#[command(about = "...")]` with a one-line description.
Include `#[arg(long, help = "...")]` on every argument.

**Step 2 — Write the handler in `cli/handlers.rs`**
The handler receives an `OrchestratorHandle` and the parsed arguments.
It sends an `OrchestratorCommand` and waits for a `SystemSnapshot` response.
It then calls the display layer to render the result.
It never calls any other layer directly.

**Step 3 — Add to the display layer**
If the command produces output, add the rendering function to `display/`.
Keep rendering separate from business logic — the handler decides what to show,
the display layer decides how to show it.

**Step 4 — Write an integration test**
Test the full path: CLI args → handler → OrchestratorHandle (mocked) →
display output. Use `assert_cmd` crate for CLI output testing.

---

## 9. Security Tooling Setup

### Installation

```bash
# Rust security tools
cargo install cargo-audit
cargo install cargo-deny
cargo install cargo-geiger

# Python security tools are already in dev dependencies
# bandit, pip-audit, safety are in requirements-dev.txt
```

### Configuration Files

`deny.toml` at project root — cargo-deny policy. See ARCHITECTURE.md section 16
for the configured policy. Never add entries to `[advisories] ignore` without
a comment explaining why the advisory does not apply to this project.

`.cargo/audit.toml` — cargo-audit configuration. Keep empty unless a specific
advisory has been reviewed and determined non-applicable.

`pyproject.toml [tool.bandit]` — Bandit configuration. `exclude_dirs = ["tests"]`
is the only default exclusion. Never add `skips` without a comment.

### Running Security Checks

Run `just security` before any release or thesis demo. This runs:
- `cargo audit` — Rust dependency vulnerabilities
- `cargo deny check` — license and ban policy
- `uv run bandit -r src/netguard/ -ll` — Python security lints
- `uv run pip-audit` — Python dependency vulnerabilities
- `uv run safety check` — additional Python vulnerability database

Run `cargo geiger` quarterly (it is slow) to track unsafe code surface area.
Document the output in the thesis as evidence of security awareness.

### Handling Audit Findings

When `cargo audit` or `pip-audit` reports a vulnerability:
1. Read the advisory in full
2. Determine if the vulnerable code path is reachable in NetGuard
3. If not reachable: add to ignore list with a comment explaining why
4. If reachable but no fix available: document in `TODO.md` security section
5. If reachable and fix available: update the dependency immediately

Never ignore a finding without a documented reason. "It's fine" is not a reason.

### Clippy Security Lints

The following clippy lints are configured as errors (`-D`). These will fail the
build:

- `clippy::unwrap_used` — forces explicit error handling
- `clippy::expect_used` — same
- `clippy::panic` — prevents silent panics in library code
- `clippy::integer_arithmetic` — overflow awareness in security-sensitive code

The following are configured as warnings (`-W`). These appear in output but do
not fail the build. Warnings should be reviewed and either fixed or suppressed
with a `#[allow(...)]` and a comment:

- `clippy::pedantic` — comprehensive code quality checks
- `clippy::nursery` — experimental but useful lints
- `clippy::mod_module_files` — enforce module file naming consistency

---

## 10. Justfile Reference

Commands are added to the Justfile as they are implemented. This section defines
the intended final command set. Implement each command when the underlying
functionality exists — do not add stub commands.

```just
# ── Setup ─────────────────────────────────────────────────

# One-time: install all tools and set up environments
setup:
    cargo build
    uv venv
    uv pip sync requirements.txt requirements-dev.txt

# Run the first-run setup wizard
setup-wizard:
    cargo run -- setup

# Set packet capture capabilities (Linux only)
setup-caps:
    sudo setcap cap_net_raw,cap_net_admin=eip .venv/bin/python3

# ── Development ───────────────────────────────────────────

# Run NetGuard with arguments
run *ARGS:
    cargo run -- {{ARGS}}

# Watch mode: run tests on file change
dev:
    cargo watch -x "test --lib" -x "clippy"

# ── Testing ───────────────────────────────────────────────

# Run all tests (Rust + Python, excludes slow + e2e)
test:
    cargo test
    uv run pytest -m "not slow and not e2e"

# Run including slow tests (lifecycle, integration)
test-all:
    cargo test
    uv run pytest -m "not e2e"

# Property-based fuzz tests (slow, run before release)
test-fuzz:
    cargo test --release -- --ignored

# End-to-end tests (requires root and real hardware)
test-e2e:
    cargo test --ignored --test e2e
    uv run pytest -m "e2e"

# Rust tests only
test-rust:
    cargo test

# Python tests only
test-python:
    uv run pytest -m "not slow and not e2e"

# ── Code Quality ──────────────────────────────────────────

# Format all code
fmt:
    cargo fmt
    uv run ruff format .

# Lint all code
lint:
    cargo clippy -- \
        -D warnings \
        -D clippy::unwrap_used \
        -D clippy::expect_used \
        -D clippy::panic \
        -W clippy::pedantic \
        -W clippy::nursery
    uv run ruff check .
    uv run mypy src/netguard/ipc/ src/netguard/ipc_sidecar.py

# Fix auto-fixable lint issues
fix:
    cargo clippy --fix --allow-dirty
    uv run ruff check --fix .

# ── Security ──────────────────────────────────────────────

# Full security audit (run before every release)
security:
    cargo audit
    cargo deny check
    uv run bandit -r src/netguard/ -ll
    uv run pip-audit
    uv run safety check

# Check unsafe code surface area (slow, run quarterly)
security-geiger:
    cargo geiger --quiet

# ── Documentation ─────────────────────────────────────────

# Serve docs locally
docs:
    uv run mkdocs serve

# Build docs site
docs-build:
    uv run mkdocs build
    cargo doc --no-deps
    cp -r target/doc site/rust-api

# Open Rust API docs
docs-rust:
    cargo doc --no-deps --open

# Deploy docs to GitHub Pages
docs-deploy:
    just docs-build
    uv run mkdocs gh-deploy

# ── Benchmarks ────────────────────────────────────────────

# Run performance benchmarks
bench:
    cargo bench

# ── Environment Check ─────────────────────────────────────

# Check all prerequisites and environment health
doctor:
    cargo run -- doctor

# ── Pre-commit Gate ───────────────────────────────────────

# Full check: format + lint + test (run before every commit)
check: fmt lint test
    @echo "✓ All checks passed — ready to commit"

# Install git pre-commit hook
install-hooks:
    @echo "#!/bin/sh\njust check" > .git/hooks/pre-commit
    @chmod +x .git/hooks/pre-commit
    @echo "✓ Pre-commit hook installed"

# ── Build ─────────────────────────────────────────────────

# Build release binary
build:
    cargo build --release
    @echo "Binary: target/release/netguard"

# Clean all build artifacts
clean:
    cargo clean
    rm -rf .venv site target/doc
```

---

## 11. Phase 1 Checklist — Foundation

Goal: `cargo test` passes, `just doctor` runs (even if it reports missing deps).

### Project Setup
- [ ] `cargo new netguard-launcher --lib`
- [ ] Add `src/main.rs` with stub `main()`
- [ ] Configure `Cargo.toml` with all dependencies from Section 2
- [ ] Create `deny.toml` with license and advisory policy
- [ ] Create `rustfmt.toml` with formatting preferences
- [ ] Create `Justfile` with setup, test, fmt, lint, doctor stubs
- [ ] Initialize git hooks with `just install-hooks`
- [ ] Create `docs/adr/` directory with ADR template file

### Error Types (`src/error.rs`)
- [ ] `Error` top-level enum with all variants
- [ ] `PermissionError`, `IpcError`, `PythonError`, `ConfigError`, `ValidationError`
- [ ] `user_message()` — human-readable explanation for every variant
- [ ] `suggestion()` — optional fix suggestion for every variant
- [ ] `severity()` — `Critical | High | Medium | Low`
- [ ] `recoverable()` — boolean, used by supervisor and frontend
- [ ] Unit tests for all `user_message()` and `suggestion()` outputs

### State Machine (`src/orchestrator/state.rs`)
- [ ] `SystemState` enum with all variants and fields
- [ ] `DegradedReason` enum with all variants
- [ ] `ActiveOperation` enum with all variants
- [ ] `can_transition_to()` with complete transition table
- [ ] `allowed_commands()` for every state
- [ ] `CommandKind` enum for all command types
- [ ] Unit tests: every valid transition accepted
- [ ] Unit tests: every invalid transition rejected
- [ ] Unit tests: `allowed_commands()` for every state

### Configuration (`src/infra/config/mod.rs`)
- [ ] `UserPreferences` struct with all sections
- [ ] `UserPreferences::default()` — all defaults defined here
- [ ] `ConfigManager::read()` — reads TOML, fills missing with defaults
- [ ] `ConfigManager::write()` — writes complete TOML with comments
- [ ] `ConfigManager::migrate()` — handles older config versions
- [ ] Unit tests: missing fields use defaults
- [ ] Unit tests: unknown fields are ignored with warning
- [ ] Unit tests: version migration is idempotent

### Environment Checker (`src/orchestrator/environment.rs`)
- [ ] `EnvironmentChecker` struct
- [ ] `EnvironmentReport` and `CheckResult` types
- [ ] `CheckStatus` enum: `Ok | Warning | Fatal`
- [ ] `check_all()` runs all checks and returns report
- [ ] Individual checks: uv available, Python version, venv exists,
  deps synced, capture capabilities, socket permissions, output dir
- [ ] `display()` — pretty-print for CLI and TUI
- [ ] `is_fatal()` and `has_warnings()` convenience methods
- [ ] Unit tests: each check with mocked system calls

### Panic Hook (`src/main.rs`)
- [ ] `setup_panic_hook()` called before anything else in `main()`
- [ ] Hook disables terminal raw mode
- [ ] Hook leaves alternate screen
- [ ] Hook prints clean error message before delegating to original hook
- [ ] Manual test: cause a panic in TUI mode, verify terminal is restored

### Validation (`src/core/validation.rs`)
- [ ] `validate_interface_name()` — whitelist: alphanumeric, dash, underscore, max 15
- [ ] `validate_duration()` — 1 to 3600 seconds
- [ ] `validate_bpf_filter()` — no shell metacharacters, max 500 chars
- [ ] `validate_output_path()` — `.parquet` extension, no `..`, create parent
- [ ] `validate_ip_address()` — valid IPv4 or IPv6
- [ ] Unit tests: known valid inputs
- [ ] Unit tests: known invalid inputs including injection attempts
- [ ] Property tests: never panics on arbitrary input
- [ ] Property tests: valid range always accepted
- [ ] Property tests: idempotent

**Phase 1 Validation Gate:**
- `cargo test` passes with zero failures
- `cargo clippy -- -D warnings -D clippy::unwrap_used` passes
- `cargo fmt --check` passes
- `just doctor` runs and produces output (even if checks fail)

---

## 12. Phase 2 Checklist — Sidecar + IPC

Goal: Rust and Python can exchange messages, supervisor restarts work.

### IPC Framing (`src/infra/ipc/`)
- [ ] `FramedWriter` — async write with length prefix
- [ ] `FramedReader` — async read with length prefix
- [ ] `MAX_MESSAGE_SIZE` constant (10MB), enforced on recv
- [ ] Clean close detection — `recv` returns `None` on clean close
- [ ] Partial message handling — reads exact bytes, no short reads
- [ ] Unit tests: roundtrip small message
- [ ] Unit tests: roundtrip large message (near limit)
- [ ] Unit tests: message over limit is rejected
- [ ] Unit tests: fragmented delivery (send in two parts)
- [ ] Unit tests: 100 sequential messages without bleed

### IPC Envelope (`src/infra/ipc/envelope.rs`)
- [ ] `Envelope` struct with all fields
- [ ] `MessageType` enum: Request, Response, Event, Heartbeat, Handshake
- [ ] `ResponseStatus` enum: Ok, Error, Partial, Rejected
- [ ] `IpcError` struct with code, message, recoverable, suggestion
- [ ] `Envelope::request()` constructor
- [ ] `Envelope::respond_to()` constructor (preserves id)
- [ ] `Envelope::error_response()` constructor
- [ ] `Envelope::heartbeat()` constructor
- [ ] `Envelope::event()` constructor
- [ ] Unit tests: response preserves request id
- [ ] Unit tests: all constructors produce valid envelopes
- [ ] Unit tests: serde roundtrip (serialize then deserialize = identity)

### IPC Server (`src/infra/ipc/server.rs`)
- [ ] `IpcServer::new()` — creates socket, sets permissions to 0o600
- [ ] `IpcServer::socket_path()` — returns path for passing to sidecar
- [ ] `IpcServer::accept()` — returns `IpcConnection`
- [ ] `IpcConnection::send()` — sends envelope with framing
- [ ] `IpcConnection::recv()` — receives envelope with framing
- [ ] `Drop` for `IpcServer` — removes socket file
- [ ] Integration test: server + client roundtrip
- [ ] Integration test: verify socket file permissions are 0600

### Supervisor (`src/orchestrator/supervisor.rs`)
- [ ] `SidecarSupervisor` struct with config
- [ ] `SupervisorConfig` with max_restarts, window, timeout, backoff
- [ ] `SupervisorEvent` enum: Crashed, Unresponsive, Recovered, RecoveryFailed
- [ ] `DataLossAssessment` enum: None, Partial, Complete
- [ ] `spawn()` — starts Python sidecar process
- [ ] `kill()` — sends SIGTERM, waits, then SIGKILL on timeout
- [ ] `perform_handshake()` — sends HANDSHAKE, populates BackendState
- [ ] `attempt_restart()` — respects restart policy with backoff
- [ ] `next_message()` — async stream of IPC envelopes from Python
- [ ] `next_event()` — async stream of supervisor lifecycle events
- [ ] Heartbeat monitoring loop
- [ ] Unit tests: restart policy (max retries, window, backoff)
- [ ] Unit tests: handshake success and version mismatch
- [ ] Integration test: spawn → communicate → kill → restart

### Python Sidecar
- [ ] `src/netguard/ipc/framing.py` — `FramedSocket` class
    - [ ] `send_message(dict)` — length-prefix + JSON
    - [ ] `recv_message()` — length-prefix read, returns dict or None
    - [ ] `_recv_exactly(n)` — guaranteed exact byte read
- [ ] `src/netguard/ipc/envelope.py` — envelope helpers
    - [ ] `make_response(request, payload)` — preserves id
    - [ ] `make_error(request, code, message, recoverable)`
    - [ ] `make_event(action, payload)`
    - [ ] `make_heartbeat()`
- [ ] `src/netguard/ipc_sidecar.py` — main sidecar
    - [ ] `IpcSidecar` class with injected dependencies
    - [ ] `run()` — main event loop
    - [ ] `handle_message(envelope)` — dispatch + error wrapping
    - [ ] `_handle_sigterm()` — emergency finalize + clean exit
    - [ ] `_heartbeat_loop()` — sends heartbeat every 5 seconds in background thread
    - [ ] All defined action handlers (see ARCHITECTURE.md Section 9)
- [ ] Python sidecar tests (all four layers — see ARCHITECTURE.md Section 17)
    - [ ] Layer 1: socket mechanics tests
    - [ ] Layer 2: dispatch tests
    - [ ] Layer 3: core translation tests
    - [ ] Layer 4: lifecycle tests

### Checkpointed Writer
- [ ] `src/netguard/capture/checkpointed_writer.py`
    - [ ] Dual trigger: N packets OR N seconds
    - [ ] `_flush_checkpoint()` — writes row group, clears buffer
    - [ ] `_report_checkpoint()` — sends IPC event via callback
    - [ ] `finalize()` — clean flush + close
    - [ ] `emergency_finalize()` — best-effort, safe in signal handler
    - [ ] Thread safety: `threading.Lock` around buffer access
- [ ] Tests: checkpoint triggers
- [ ] Tests: row group validity (readable by Polars after each checkpoint)
- [ ] Tests: emergency_finalize on partial buffer
- [ ] Tests: thread safety (concurrent add_packet calls)

**Phase 2 Validation Gate:**
- Rust ↔ Python roundtrip test passes with a real socket
- Handshake succeeds and BackendState is populated
- Supervisor restart test: kill Python, verify auto-restart
- All four sidecar test layers pass with `uv run pytest tests/ipc/`

---

## 13. Phase 3 Checklist — CLI

Goal: `netguard capture --interface eth0` runs a real capture.

### Orchestrator Run Loop (`src/orchestrator/mod.rs`)
- [ ] `Orchestrator` struct with all owned subsystems
- [ ] `OrchestratorHandle` with command_tx and state_rx
- [ ] `Orchestrator::new()` — constructor with channel setup
- [ ] `Orchestrator::run()` — main tokio::select! loop
- [ ] `handle_command()` — validates against allowed_commands, dispatches
- [ ] `handle_backend_message()` — updates BackendState, broadcasts
- [ ] `handle_supervisor_event()` — state transitions on crash/recovery
- [ ] `transition_to()` — validates transition, updates state, broadcasts
- [ ] `broadcast_current_snapshot()` — sends SystemSnapshot to all frontends
- [ ] Integration test: command routing end-to-end
- [ ] Integration test: state transitions on supervisor events

### CLI (`src/cli/`)
- [ ] `args.rs` — Clap Commands enum with all subcommands
    - [ ] `capture` with interface, duration, filter, output, promiscuous args
    - [ ] `interfaces` — list available interfaces
    - [ ] `workflow` with subcommands: daily-audit, ip-investigation, threat-hunt
    - [ ] `analyze` — run analysis on existing Parquet file
    - [ ] `doctor` — run environment check
    - [ ] `setup` — run setup wizard
    - [ ] Global flags: `--verbose` / `-v`, `--quiet` / `-q`, `--config`
- [ ] `handlers.rs` — one handler per subcommand, uses OrchestratorHandle only
- [ ] Integration tests for each CLI command

### Display Layer (`src/display/`)
- [ ] `terminal.rs` — ANSI color support, detect no-color environments
- [ ] `tables.rs` — interface list, workflow results, stats display
- [ ] `progress.rs` — capture progress bar with live packet count
- [ ] `sanitization.rs` — strip control characters from packet-derived strings
- [ ] All display functions take `&DisplayConfig` for testability

### Permissions (`src/infra/permissions/`)
- [ ] `linux.rs` — check and explain `cap_net_raw`/`cap_net_admin`
- [ ] `macos.rs` — check `access_bpf` group or sudo
- [ ] `windows.rs` — check admin or Npcap
- [ ] Platform dispatch in `mod.rs` via `#[cfg(target_os)]`

### First-Run Wizard
- [ ] Detect missing `netguard.toml` in Orchestrator startup
- [ ] Launch wizard TUI before normal startup
- [ ] Wizard step 1: welcome screen
- [ ] Wizard step 2: environment checks with fix suggestions
- [ ] Wizard step 3: preference prompts with detected defaults
- [ ] Wizard step 4: write `netguard.toml`
- [ ] `netguard setup` command re-runs wizard

**Phase 3 Validation Gate:**
- `netguard interfaces` lists real interfaces
- `netguard doctor` shows correct pass/fail for current environment
- `netguard capture --interface lo --duration 5` produces a Parquet file
- `netguard workflow daily-audit --file capture.parquet` produces a report
- All CLI integration tests pass

---

## 14. Phase 4 Checklist — Hardening + MVP

Goal: MVP complete, pre-commit gate clean, benchmarks documented.

### Property Tests
- [ ] `validate_interface_name` — never panics, correct whitelist
- [ ] `validate_duration` — all valid values accepted, all invalid rejected
- [ ] `validate_bpf_filter` — never panics, rejects all metacharacters
- [ ] `validate_output_path` — no path traversal possible
- [ ] Envelope serde — roundtrip preserves all fields
- [ ] Config TOML — roundtrip preserves all preferences

### Benchmarks
- [ ] IPC roundtrip latency — target < 1ms
- [ ] Envelope serialize/deserialize throughput
- [ ] Checkpoint write throughput (packets/second before checkpoint overhead)
- [ ] Document results in thesis-ready format

### Security Audit
- [ ] `cargo audit` — zero unaddressed vulnerabilities
- [ ] `cargo deny check` — all licenses compliant, no banned crates
- [ ] `cargo geiger` — document unsafe surface area
- [ ] `uv run bandit -r src/netguard/ -ll` — zero medium+ findings
- [ ] `uv run pip-audit` — zero unaddressed vulnerabilities
- [ ] Manual review: socket permissions verified in production build
- [ ] Manual review: terminal sanitization verified with crafted test packets

### Documentation
- [ ] All Rust public types have doc comments
- [ ] All Python public functions have Google-style docstrings
- [ ] `docs/adr/` contains all 18 ADR files
- [ ] MkDocs `getting-started/installation.md` is accurate
- [ ] MkDocs `user-guide/configuration.md` covers all `netguard.toml` fields
- [ ] `README.md` is accurate with correct install instructions

### Final Validation Gate (MVP Complete)
- [ ] `just check` passes (fmt + lint + test) with zero warnings
- [ ] `just security` passes with zero unaddressed findings
- [ ] `just test-fuzz` passes
- [ ] `just bench` produces documented results
- [ ] End-to-end: fresh machine, `just setup`, capture, workflow, doctor — all work
- [ ] `just doctor` correctly identifies missing capabilities on unconfigured machine
- [ ] Supervisor restart verified: kill Python mid-capture, verify recovery + partial file

---

## 15. Validation Gates

Each gate must pass before proceeding to the next phase. These are not optional.

### Gate 1 (End of Phase 1)
```bash
cargo test               # zero failures
cargo clippy -- -D warnings -D clippy::unwrap_used -D clippy::expect_used
                         # zero errors
cargo fmt --check        # no formatting changes needed
just doctor              # runs and produces structured output
```

### Gate 2 (End of Phase 2)
```bash
just test                # Rust + Python, zero failures
cargo test --test ipc    # IPC integration tests pass
uv run pytest tests/ipc/ # all four sidecar test layers pass
# Manual: kill Python sidecar mid-run, verify supervisor restarts it
```

### Gate 3 (End of Phase 3)
```bash
just check               # fmt + lint + test, zero failures
netguard interfaces      # lists real interfaces
netguard doctor          # correct output for current environment
netguard capture --interface lo --duration 5 --output /tmp/test.parquet
uv run python -c "import polars; print(polars.read_parquet('/tmp/test.parquet').shape)"
                         # Parquet file is valid and readable
```

### Gate 4 (MVP Complete)
```bash
just check               # zero failures, zero warnings
just security            # zero unaddressed findings
just test-fuzz           # property tests pass
just bench               # results documented
# End-to-end on clean machine: just setup → capture → workflow → all work
```
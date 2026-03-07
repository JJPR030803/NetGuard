# NetGuard Launcher — Claude Code Context

> **Before doing anything:** Read this file fully. Do not scan the project
> directory unless explicitly asked. Do not edit any file without confirming
> the intent with the user first. When in doubt, ask.

---

## 1. What This Project Is

`netguard-launcher` is the **Rust crate** that orchestrates a hybrid Rust/Python
network security analysis tool, built as a Master's thesis project. Rust owns
orchestration, system lifecycle, CLI, and IPC. Python owns packet capture,
protocol analysis, and ML — and is **not touched here** (see Python Boundary
Rules below).

This is a thesis-quality engineering project. Correctness and architecture
integrity matter more than speed of implementation.

---

## 2. Current Working Context

> **Update this block at the start of every session. Do not skip it.**

```
Phase:            1 — Foundation
Gate status:      Not yet run
Last file worked: —
Active task:      —
Blocked on:       —
```

To refresh this block from project state, run: `/update-context`

---

## 3. Project Layout (What Claude May Read)

Claude Code may freely read these paths:

```
netguard-launcher/
├── src/
│   ├── error.rs
│   ├── lib.rs
│   ├── main.rs
│   ├── orchestrator/      (state.rs, handle.rs, supervisor.rs, environment.rs, commands.rs)
│   ├── cli/               (args.rs, handlers.rs)
│   ├── core/              (models/, operations/, validation.rs)
│   ├── infra/             (ipc/, permissions/, python/, config/, logging/)
│   └── display/
├── tests/
├── benches/
├── Cargo.toml
├── Justfile
├── deny.toml
├── ARCHITECTURE.md        ← authoritative rationale for all decisions
├── IMPLEMENTATION.md      ← how to build each component
└── IMPLEMENTATION_TODO.md ← phase checklists
```

**Do not read unless explicitly asked:**
- `../netguard/` — the existing Python core (off-limits unless user says otherwise)
- `target/` — build artifacts
- `.git/` — git internals
- Any file not listed above

---

## 4. Confirm Before Acting

Claude Code **must confirm with the user before:**

- Creating any new file
- Editing any existing file (state the file path and what will change)
- Adding a new dependency to `Cargo.toml`
- Adding a new state transition to `state.rs`
- Adding a new IPC action (requires `ARCHITECTURE.md` update first)
- Running any command that is not in the approved list below

**Approved commands (no confirmation needed):**
```
cargo check
cargo test
cargo clippy
cargo fmt --check
cargo doc
just check
just test
just lint
just fmt
just doctor
```

---

## 5. Architecture in One Page

```
CLI / TUI  →  OrchestratorHandle  →  Orchestrator  →  SidecarSupervisor
                                           │
                                    SystemState (single source of truth)
                                           │
                                    IPC (Unix Domain Socket, length-prefix + JSON)
                                           │
                                    Python Sidecar (ipc_sidecar.py)
                                           │
                                    Python Core (Scapy, Polars, TensorFlow — UNCHANGED)
```

**The one rule that governs everything:**
Frontends hold only `OrchestratorHandle`. They have no path to the sidecar,
no path to Python, and no path to `SystemState`. All state mutations happen
inside `Orchestrator::transition_to()` only.

---

## 6. Build & Validation Commands

```bash
# Daily development
cargo check                     # fast syntax + type check
cargo test                      # run all unit + integration tests
cargo clippy -- \
  -D warnings \
  -D clippy::unwrap_used \
  -D clippy::expect_used \
  -D clippy::panic              # full lint — must pass clean

# Pre-commit gate (run before every commit)
just check                      # fmt + lint + test

# Phase validation gates
just doctor                     # environment health check
just test                       # Rust + Python (excludes slow/e2e)
just test-all                   # includes slow lifecycle tests
just security                   # cargo audit + bandit + pip-audit

# Python side
uv run pytest tests/ipc/        # sidecar four-layer tests
uv run pytest -m "not slow and not e2e"
```

---

## 7. Phase Status

| Phase | Goal | Gate | Status |
|-------|------|------|--------|
| 1 — Foundation | error.rs, state machine, config, validation, env checker | `cargo test` clean, `just doctor` runs | 🔲 Not started |
| 2 — IPC + Sidecar | IPC framing, envelope, supervisor, Python sidecar | Rust↔Python roundtrip, supervisor restart | 🔲 Not started |
| 3 — CLI | Orchestrator run loop, CLI commands, display, permissions | `netguard capture` produces valid Parquet | 🔲 Not started |
| 4 — Hardening | Property tests, benchmarks, security audit | `just check` + `just security` clean | 🔲 Not started |

**Do not work on Phase N+1 until Phase N gate passes.**

---

## 8. Hard Rules (Enforced by Clippy — Will Break the Build)

These are not style preferences. Violating them will fail CI.

| Rule | Reason |
|------|--------|
| No `unwrap()` in library code | `-D clippy::unwrap_used` |
| No `expect()` in library code | `-D clippy::expect_used` |
| No `panic!()` in library code | `-D clippy::panic` |
| `anyhow` only in `main.rs` and test code | Library code uses typed errors |
| `SystemState` mutated only in `Orchestrator::transition_to()` | Single source of truth |
| `BackendState` mutated only in orchestrator IPC handler | Same principle |
| No shell execution for Python — always argument arrays | Eliminates injection surface |
| All public types must have doc comments | Enforced via `cargo doc` |

**In test code:** `unwrap()` and `expect()` are acceptable.

---

## 9. Thesis & Portfolio Context

This project is a Master's thesis demonstrating:
- Hybrid systems architecture (Rust orchestration + Python ecosystem)
- Bounded failure design (every failure mode has a documented max impact)
- Security-first engineering (least privilege, no shell injection, IPC socket scoped to owner)
- Testability at every layer (no test requires root or real hardware)

**Thesis-quality claims that must be measurable:**
- IPC roundtrip latency < 1ms (via `criterion` benchmarks)
- Max data loss on crash ≤ 10 seconds / 1000 packets (via checkpoint tests)
- Zero unsafe code in first-party Rust (via `cargo geiger`)
- All input validators covered by property tests (via `proptest`)

When implementing anything, ask: *"Can I produce a measurement or test output
that supports one of these claims?"* If yes, do it that way.

---

## 10. Further Reading (Load Only When Needed)

| File | When to read it |
|------|----------------|
| `.claude/rules/error-handling.md` | Before touching `error.rs` or adding error variants |
| `.claude/rules/state-machine.md` | Before touching `state.rs` or adding transitions |
| `.claude/rules/ipc-protocol.md` | Before any IPC work (framing, envelope, supervisor) |
| `.claude/rules/python-boundary.md` | Any time Python files come up |
| `.claude/rules/adr-decisions.md` | Before suggesting any architectural alternative |

---

*ARCHITECTURE.md is the authoritative source for all architectural decisions.
When this file and ARCHITECTURE.md conflict, ARCHITECTURE.md wins.*

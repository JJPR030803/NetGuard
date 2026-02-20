# NetGuard TODO & Future Work
**Version:** 1.0
**Date:** February 2026
**Purpose:** Everything explicitly deferred, with the reason why it was deferred
and when it should be revisited. Nothing in this file is forgotten — it is
intentionally parked.

Review this file at the start of each new project phase and after the MVP is
complete. Move items to `IMPLEMENTATION.md` when they are ready to be worked on.

---

## Table of Contents

1. [Deferred Architecture Decisions](#1-deferred-architecture-decisions)
2. [Deferred Implementation Work](#2-deferred-implementation-work)
3. [Polish Phase — Documentation](#3-polish-phase--documentation)
4. [Polish Phase — Developer Experience](#4-polish-phase--developer-experience)
5. [Polish Phase — Security & Observability](#5-polish-phase--security--observability)
6. [Future Features](#6-future-features)
7. [Thesis & Portfolio](#7-thesis--portfolio)
8. [Known Unknowns](#8-known-unknowns)

---

## 1. Deferred Architecture Decisions

These are formal ADRs that have been opened but not resolved. They must be
resolved before implementing the features they govern.

---

### ADR 010 — Command::Async Concurrency in MVU
**Status:** Deferred
**Deferred Until:** TUI phase begins

**The question:**
The current `Command::Async` design in MVU is single-threaded sequential —
the event loop processes one async command at a time. When a capture is running
and the user navigates to a different tab, concurrent async operations are needed:
stats updating, keyboard events, and IPC messages all happening simultaneously.

**Options to evaluate when TUI phase begins:**
1. Named task registry — each async operation is registered by name and can be
   cancelled by name. The event loop polls all active tasks each tick.
2. `tokio::JoinSet` — spawn all commands as tasks, collect results as they
   complete, inject the resulting messages back into the event loop.
3. `Command::Batch` improvement — process all commands and collect all resulting
   messages, not just the first.
4. External prior art: study how `elm-land`, `tui-realm`, and `Cursive` solve
   concurrent TUI state management before deciding.

**Why deferred:**
The current sequential design is sufficient for the CLI phase. The concurrency
requirements only become clear when the TUI is being implemented and the actual
concurrent operation patterns are observable.

---

### ADR 009 — PyO3 vs Sidecar + Socket
**Status:** Accepted (sidecar wins), documented for reference

**Summary of decision:**
Sidecar + Unix Domain Sockets was chosen over PyO3 embedding.

**Primary reasons:**
- The GIL conflicts with Tokio's async runtime in non-trivial ways. Long-running
  Python operations (60-second captures) would block Tokio worker threads.
- Crash containment: a Python segfault (possible with Scapy's low-level network
  access) kills the entire process with PyO3, but only kills the sidecar with
  the external process approach. The supervisor then restarts it gracefully.
- Process isolation enables independent versioning and independent deployment.
- The IPC architecture is a stronger thesis contribution than embedding.

**When to revisit:**
If a hot path is discovered where IPC latency is genuinely a bottleneck (unlikely
given Scapy's own overhead), PyO3 for that specific call only can be evaluated as
a targeted optimization. This would not change the overall architecture.

---

## 2. Deferred Implementation Work

Items that are planned but intentionally not in the MVP scope.

---

### TUI Implementation (Post-MVP)
**Deferred Until:** CLI MVP is working and validated

The full TUI (Ratatui + MVU) is planned but requires ADR 010 to be resolved first.
The TUI presents the same functionality as the CLI but interactively.

**Minimum TUI screens:**
- Interface selection screen (table with interface details and recommendation)
- Capture screen (live stats, packet count, progress bar, stop button)
- Workflow screen (file picker, workflow selector, results display)
- Doctor screen (environment check results with fix actions)
- Settings screen (preferences editor writing to netguard.toml)

**State management approach:**
MVU (Elm Architecture). Model = `AppModel`. Message = `Msg` enum. Update = pure
function `update(model, msg) -> Command`. View = pure function `render(frame, model)`.

Resolve ADR 010 before beginning TUI state management implementation.

---

### Windows Named Pipes Fallback
**Deferred Until:** After Linux/macOS IPC is stable

The `IpcMode::detect_best()` fallback chain includes Named Pipes for Windows.
This has not been implemented — the fallback to stdio IPC is the current Windows
path. Named Pipes should be implemented when Windows is a primary target.

**Implementation notes when ready:**
- Use `tokio::net::windows::named_pipe`
- Pipe name format: `\\.\pipe\netguard_{pid}`
- The framing protocol is identical to Unix sockets
- The envelope format is identical — no changes needed there

---

### No-Config Operation
**Deferred Until:** After netguard.toml is stable and well-documented

Currently `netguard.toml` is required. A future mode where NetGuard operates
with all defaults and no config file would improve onboarding for quick one-off
use.

**Design consideration when ready:**
- CLI args can override everything, so no-config is mostly about defaults
- The setup wizard is the preferred onboarding path — no-config is secondary
- No-config should be explicit (`netguard --no-config ...`) not the default

---

### Plugin System
**Deferred Until:** Post-thesis

The handshake already supports dynamic workflow discovery — Python reports what
workflows are available, Rust learns at runtime. The plugin system extends this
so third-party Python scripts can be discovered and exposed as workflows.

**Design sketch when ready:**
- Plugin directory: `~/.config/netguard/plugins/`
- Plugin contract: Python file with a class extending `AnalyzerPlugin`
- Discovery: Python scans plugin directory at startup, reports in handshake
- Rust side: no changes needed — dynamic workflows already designed in

---

### FastAPI Web Interface
**Deferred Until:** Post-thesis, portfolio phase

The Python core already has FastAPI in its dependencies. A web interface using
the existing REST API (and potentially WebSockets for real-time capture data)
is planned as a portfolio addition after the thesis defense.

**Architecture consideration:**
The Rust orchestrator does not need to know about the web interface. The web
interface communicates with the Python core's existing FastAPI layer directly.
The Orchestrator remains the CLI/TUI entry point only.

---

### `cargo-semver-checks`
**Deferred Until:** If/when the Rust launcher becomes a public library

If the Rust launcher's API is published as a crate for other tools to build on,
`cargo-semver-checks` should be added to the CI pipeline to prevent accidental
breaking changes. Not relevant until there are external consumers.

---

## 3. Polish Phase — Documentation

These items improve documentation quality but are not required for the MVP.
Revisit after the tool is working and the public documentation site is live.

---

### Versioning and Changelog Strategy

**The question:**
How is NetGuard versioned? Who owns the canonical version? How is the changelog
maintained?

**Recommendation when ready:**
- Semantic versioning (semver): MAJOR.MINOR.PATCH
- Canonical version lives in `Cargo.toml` (Rust is the launcher)
- Python core has its own version tracked in `pyproject.toml`
- Versions are reconciled during handshake (see ADR 008)
- Changelog: `CHANGELOG.md` at project root, updated on every release
  using Keep a Changelog format (https://keepachangelog.com)
- Consider `git-cliff` for automated changelog generation from commit messages

---

### Search Optimization for Troubleshooting Page

The `user-guide/troubleshooting.md` page should have headings that match exact
error strings users will search for. When the error messages are finalized in
code, audit them and ensure every user-visible error string appears as a heading
in the troubleshooting page.

Example format:
```markdown
## "Packet capture requires elevated permissions"

**What happened:** ...
**How to fix:** ...
```

---

### Thesis Research Context Page

A page in MkDocs (suggested location: `docs/about.md` or `docs/research.md`)
that contextualizes NetGuard as a thesis project. Audience: committee members
and academic peers who visit the public site.

**Contents when ready:**
- Problem statement (brief)
- Research contributions (what NetGuard demonstrates)
- Link to thesis paper when published
- Institution and supervisor acknowledgment
- How to cite this work

---

### Configuration Reference Auto-Generation

The `user-guide/configuration.md` page should ideally be auto-generated from the
`UserPreferences` Rust struct doc comments so it cannot drift from the actual
config schema.

**Approach when ready:**
- Write thorough doc comments on every field in `UserPreferences`
- Write a small `build.rs` script that generates a Markdown table from the struct
- Include in the MkDocs build pipeline

---

### API Reference Separation

The current API docs structure has Python and Rust as siblings under `/api/`.
This misrepresents the architecture — Rust is the entry point, Python is internal.

**Rename when ready:**
- `/api/cli-reference/` — command-line interface documentation
- `/api/internals/` — Python core API for contributors

---

## 4. Polish Phase — Developer Experience

---

### Justfile Full Workflow Documentation

The Justfile grows as features are implemented (by design — scripts first, then
bundle). When the MVP is complete, add a `default` recipe that prints a
well-formatted command reference:

```just
default:
    @just --list --unsorted
```

Also add a `CONTRIBUTING.md` that references the Justfile as the primary
development interface.

---

### `cargo-watch` Development Mode

When active development begins on the TUI, a watch mode that reruns tests and
clippy on file change improves the feedback loop:

```just
dev:
    cargo watch -x "test --lib" -x "clippy -- -D warnings"
```

Add `cargo-watch` to the setup instructions when the TUI phase begins.

---

### Commit Message Convention

Adopt Conventional Commits (https://conventionalcommits.org) for consistent
git history. Add a commit message template to `.git/commit-template` during
`just install-hooks`:

```
type(scope): description

# Types: feat, fix, docs, test, refactor, perf, chore
# Scopes: orchestrator, ipc, sidecar, cli, tui, config, docs
```

This enables automated changelog generation with `git-cliff` when versioning
is addressed.

---

## 5. Polish Phase — Security & Observability

---

### Prometheus Metrics

The original architecture sketched Prometheus metrics. This is useful for
demonstrating observability during the thesis defense but is not required for
the MVP.

**Metrics to implement when ready:**
- `netguard_packets_captured_total` — counter
- `netguard_ipc_latency_seconds` — histogram (per action)
- `netguard_python_restarts_total` — counter
- `netguard_capture_bytes_total` — counter
- `netguard_checkpoints_written_total` — counter

**Exposure:** HTTP endpoint at `localhost:9090/metrics` when
`netguard.toml [observability].metrics = true`.

---

### Output Directory Permissions Check

Parquet capture files contain potentially sensitive network traffic. The
environment checker should verify that the configured output directory is not
world-readable and warn if it is.

Add to `EnvironmentChecker::check_all()`:
```rust
async fn check_output_dir_permissions(&self) -> CheckResult
```

---

### Quarterly Security Posture Review

Add to the project calendar (or README):
- Run `cargo geiger` quarterly — document unsafe surface area
- Review `deny.toml` exemptions quarterly — re-evaluate if any still apply
- Update all dependencies quarterly with `cargo update` + `uv pip sync`
- Run `just test-all` after updates to catch regressions

---

### Rate Limiting on IPC Commands

Currently there is no rate limiting on how fast the frontend can send commands
to the sidecar. A malfunctioning frontend could flood the sidecar with requests.

**When ready:** Add a token bucket rate limiter in the orchestrator's
`handle_command()` — separate limits for different command types. High-frequency
commands like `GET_STATS` should have a lower limit than `START_CAPTURE`.

---

## 6. Future Features

Items that are not currently planned but are worth capturing for later evaluation.

---

### Real-Time Streaming Data Plane

Currently the data plane is files — Python writes Parquet, Rust reads when
requested. A future streaming mode would push packet data in real-time to
the TUI (and eventually a web dashboard) using WebSockets or a dedicated
high-throughput socket.

**Design note:** Use the existing `PARTIAL` status and `EVENT` message type
in the IPC envelope — a stream is a sequence of `EVENT` envelopes followed by
a final `RESPONSE`. No envelope format changes needed.

---

### TimescaleDB Backend

For long-running deployments (not typical for thesis use case but relevant for
portfolio), a TimescaleDB backend would replace Parquet files as the primary
storage for historical packet data. Polars can query PostgreSQL/TimescaleDB
directly so the analysis layer is largely unchanged.

---

### Multi-Interface Capture

Currently one capture session = one interface. Supporting simultaneous capture
on multiple interfaces requires changes to `ActiveOperation` and the
`CheckpointedParquetWriter` (one per interface, merged at analysis time).

---

### Distributed Mode

Running the Python core on a remote machine (via SSH or a network socket)
with the Rust launcher running locally. The IPC layer is already designed to
support this — the `IpcMode` enum could add `TcpSocket(SocketAddr)` as a
variant. The envelope format and framing protocol are identical over TCP.

---

## 7. Thesis & Portfolio

---

### LaTeX Thesis Paper

After the tool is working and the MkDocs documentation site is complete and
accurate, write the LaTeX thesis paper.

**Approach:** Write for humans in MkDocs first. Extract the narrative for LaTeX.
Going MkDocs-first produces better thesis prose because you have already explained
the concepts clearly once.

**Chapter structure (suggested):**
1. Introduction — problem statement, motivation, contributions
2. Background — network security tools, related work, technology survey
3. Architecture — the hybrid Rust/Python design, ADR rationale
4. Implementation — key components, challenges, solutions
5. Evaluation — performance benchmarks, security analysis, testing coverage
6. Conclusions — contributions, limitations, future work

**Thesis-quality claims to make (with evidence):**
- IPC latency < 1ms (backed by `criterion` benchmarks)
- Maximum data loss bounded to 10 seconds on crash (backed by checkpoint tests)
- Zero unsafe code in first-party Rust (backed by `cargo geiger` output)
- 100% property test coverage on input validators (backed by proptest results)
- Security vulnerability surface reduced vs full-sudo approach (backed by
  capabilities analysis)

---

### Portfolio Presentation Preparation

After thesis defense, prepare NetGuard for public portfolio presentation:

- [ ] Ensure README has a compelling 30-second pitch
- [ ] Create a demo GIF or video showing the TUI in action
- [ ] Add the "research context" page to MkDocs
- [ ] Tag a `v1.0.0` release on GitHub
- [ ] Ensure the GitHub Actions CI badge is green
- [ ] Write a blog post explaining the architecture decisions (optional but valuable)

---

## 8. Known Unknowns

Things we know we don't know. These may surface during implementation and require
new ADRs.

---

### Scapy Performance at Scale

Scapy is not optimized for high-throughput capture. At busy network interfaces
(100Mbit+), Scapy may not be able to keep up with packet rates. This is a known
limitation of Scapy's pure-Python packet parsing.

**If this becomes a problem during implementation:**
Consider `tshark` (CLI Wireshark) as a capture backend with Scapy remaining for
protocol analysis. Tshark can write Parquet directly via `editcap`/`tshark -F`.
This would require a new sidecar handler and a new ADR.

---

### macOS Entitlement Complexity

macOS 10.15+ requires entitlements for BPF access even with group membership.
The exact entitlement requirements for distributing a signed macOS app with
packet capture are not fully researched.

**If distributing a signed macOS binary becomes a requirement:**
Research `com.apple.security.network.packet-filter` entitlement and notarization
requirements. This may require an Apple Developer account.

---

### Windows Npcap Licensing

Npcap is required for packet capture on Windows. The Npcap OEM license must be
purchased for commercial distribution. The free license is for personal and
open-source use only.

**Clarify before any commercial distribution of NetGuard on Windows.**

---

### TensorFlow Memory Behavior Under Resource Limits

The `RLIMIT_AS` memory limit set on the Python sidecar (1GB default) may conflict
with TensorFlow's memory allocation patterns. TensorFlow pre-allocates GPU/CPU
memory aggressively.

**Test during Phase 4 hardening:** Run a TensorFlow-based workflow inside the
resource-limited sidecar and verify it completes without hitting the limit. Adjust
the default limit in `netguard.toml` if needed, and document the minimum memory
requirement for ML workflows.
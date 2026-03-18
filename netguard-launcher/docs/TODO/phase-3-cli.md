# Phase 3 — CLI

**Goal:** Orchestrator run loop, CLI commands, display, permissions
**Gate:** `netguard capture` produces valid Parquet output
**Prerequisite:** Phase 2 gate passed

---

## CLI Argument Parsing

- [ ] `Commands` enum with clap derive
- [ ] `capture` subcommand (interface, duration, filter, output)
- [ ] `analyze` subcommand (input file, workflow)
- [ ] `doctor` subcommand (environment health check)
- [ ] `workflows` subcommand (list available workflows)
- [ ] Global flags (config path, verbosity, color)

## CLI Handlers

- [ ] `handle_capture()` — validate → orchestrate → display progress
- [ ] `handle_analyze()` — validate → orchestrate → display results
- [ ] `handle_doctor()` — run environment checker → display report
- [ ] `handle_workflows()` — query sidecar → display table

## Orchestrator Run Loop

- [ ] Tokio runtime setup in `main.rs`
- [ ] Orchestrator spawn with channel-based handle
- [ ] State transition logging
- [ ] Graceful shutdown on SIGTERM/SIGINT (10s bounded)
- [ ] Emergency checkpoint event forwarding

## Permissions (Platform-Specific)

- [ ] Linux: `CAP_NET_RAW` / `CAP_NET_ADMIN` check via `/proc/self/status`
- [ ] macOS: `/dev/bpf*` device access check
- [ ] Windows: admin elevation check
- [ ] Capability suggestion messages per platform

## Display Layer

- [ ] Progress bar for active captures
- [ ] Table rendering for workflow lists / stats
- [ ] Terminal size detection and minimum check
- [ ] Color support detection

## Logging Setup

- [ ] `tracing` subscriber initialization
- [ ] Log file rotation setup
- [ ] Python log forwarding (via IPC LOG events)
- [ ] Unified log stream

## Phase 3 Gate Checklist

- [ ] `netguard capture --interface lo --duration 5` produces valid Parquet
- [ ] `netguard doctor` runs and reports environment status
- [ ] `netguard workflows` lists available workflows from sidecar
- [ ] Graceful shutdown completes within 10s
- [ ] All Phase 1 + Phase 2 tests still pass
- [ ] Clippy clean

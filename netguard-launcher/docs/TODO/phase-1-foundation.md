# Phase 1 — Foundation

**Goal:** error.rs, state machine, config, validation, env checker
**Gate:** `cargo test` clean, `just doctor` runs

---

## Error System

- [x] Top-level `NetGuardError` enum with domain variants
- [x] `OrchestratorError` — state transition + supervisor errors
- [x] `EnvironmentError` — pre-flight check errors
- [x] `ValidationError` — input validation errors
- [x] `ConfigError` — configuration errors
- [x] `IpcError` — IPC communication errors
- [x] `PermissionError` — platform capability errors
- [x] `PythonError` — Python lifecycle errors
- [x] `LoggingError` — logging setup errors
- [x] `DisplayError` — terminal/rendering errors
- [x] All variants implement `user_message()`, `suggestion()`, `severity()`, `recoverable()`
- [x] `IntoIpcError` trait for Python serialization
- [x] 53 unit tests passing
- [x] Zero clippy warnings

## State Machine

- [ ] Redesign `SystemState` enum to match spec:
  - [ ] `Initializing`
  - [ ] `CheckingEnvironment`
  - [ ] `Connecting`
  - [ ] `Ready`
  - [ ] `Operating { operation: ActiveOperation }`
  - [ ] `Degraded { reason: DegradedReason, recovering: bool }`
  - [ ] `ShuttingDown`
  - [ ] `Fatal { reason: String }`
- [ ] Implement `ActiveOperation` enum
- [ ] Implement `DegradedReason` enum (6 variants)
- [ ] Implement `can_transition_to()` guard function
- [ ] Implement `allowed_commands()` per-state function
- [ ] Write transition tests (valid transitions)
- [ ] Write transition tests (invalid transitions — must be blocked)
- [ ] Update `ARCHITECTURE.md` if any changes to transition table

## Configuration

- [ ] `UserPreferences` struct with `Default` impl
- [ ] TOML read/write with `toml` crate
- [ ] Priority merging: CLI args > TOML > defaults
- [ ] Config file discovery (`~/.config/netguard/netguard.toml`)
- [ ] Unit tests for defaults, parsing, merging

## Validation

- [ ] Interface name validator (whitelist characters)
- [ ] BPF filter validator (syntax check)
- [ ] Output path validator (parent exists, writable)
- [ ] Duration parser (human-friendly input)
- [ ] IP address validator
- [ ] Range checker (generic numeric bounds)
- [ ] Unit tests for all validators (valid + invalid inputs)

## Environment Checker

- [ ] `EnvironmentChecker` struct
- [ ] Python binary discovery + version check
- [ ] Virtual environment existence check
- [ ] Dependency validation (requirements hash)
- [ ] Capture capabilities check (platform-specific)
- [ ] Socket directory writability check
- [ ] Output directory check
- [ ] Unit tests (mocked filesystem/process checks)

## Main Entry Point

- [ ] Panic hook for terminal state restoration
- [ ] Basic error display loop
- [ ] Wire CLI argument parsing (minimal — full CLI is Phase 3)

## Phase 1 Gate Checklist

- [ ] `cargo check` — clean
- [ ] `cargo test` — all pass
- [ ] `cargo clippy -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic` — clean
- [ ] `cargo fmt --check` — clean
- [ ] State machine tests cover all valid transitions
- [ ] State machine tests cover invalid transition rejection
- [ ] All new public types documented

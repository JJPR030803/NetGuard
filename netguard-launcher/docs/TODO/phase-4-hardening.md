# Phase 4 — Hardening

**Goal:** Property tests, benchmarks, security audit
**Gate:** `just check` + `just security` clean
**Prerequisite:** Phase 3 gate passed

---

## Property Tests (proptest)

- [ ] Interface name validator: arbitrary strings never panic
- [ ] BPF filter validator: arbitrary strings never panic
- [ ] Duration parser: arbitrary strings → valid duration or error (never panic)
- [ ] Output path validator: arbitrary paths → valid or error
- [ ] IP address validator: arbitrary strings → valid or error
- [ ] IPC envelope: roundtrip serialization for arbitrary payloads
- [ ] State machine: random transition sequences never reach invalid state

## Benchmarks (criterion)

- [ ] IPC roundtrip latency benchmark (target: < 1ms)
- [ ] Envelope serialization/deserialization benchmark
- [ ] Frame codec throughput benchmark
- [ ] State transition overhead benchmark

## Security Audit

- [ ] `cargo audit` — no known vulnerabilities
- [ ] `cargo geiger` — zero unsafe in first-party code
- [ ] `cargo deny` — license + advisory check clean
- [ ] Socket permission verification test (0o600)
- [ ] No shell execution anywhere (argument arrays only)
- [ ] Input validation coverage review

## Thesis Measurements

- [ ] IPC roundtrip latency < 1ms (criterion output)
- [ ] Max data loss on crash <= 10s / 1000 packets (checkpoint test)
- [ ] Zero unsafe in first-party Rust (cargo geiger report)
- [ ] All validators covered by property tests (proptest output)

## Phase 4 Gate Checklist

- [ ] `just check` — clean (fmt + lint + test)
- [ ] `just security` — clean (audit + deny)
- [ ] `cargo geiger` — zero unsafe
- [ ] All benchmarks produce measurable results
- [ ] Property tests pass with default case count (256)
- [ ] All previous phase tests still pass

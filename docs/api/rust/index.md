# Rust API Reference

The Rust launcher is documented via cargo doc.

## View Locally
```bash
just docs-rust
```

## Key Modules

| Module | Purpose |
|--------|---------|
| `orchestrator` | System state machine and lifecycle |
| `orchestrator::supervisor` | Sidecar process management |
| `infra::ipc` | IPC framing and envelope handling |
| `core::validation` | Input validation |
| `display` | Terminal output formatting |

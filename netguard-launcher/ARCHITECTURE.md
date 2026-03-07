# NetGuard Launcher Architecture

> This document is the authoritative source for all architectural decisions.
> When CLAUDE.md and this file conflict, this file wins.

## 1. Overview

NetGuard Launcher is the Rust orchestration layer for the hybrid Rust/Python
network security analysis tool.

## 2-8. [To be documented]

Reserved sections for detailed architecture documentation.

## 9. IPC Actions

| Action | Direction | Type | Description |
|--------|-----------|------|-------------|
| HANDSHAKE | Rust→Python | HANDSHAKE/RESPONSE | Version + capability exchange |
| START_CAPTURE | Rust→Python | REQUEST/RESPONSE | Begin packet capture |
| STOP_CAPTURE | Rust→Python | REQUEST/RESPONSE | Stop active capture |
| GET_STATS | Rust→Python | REQUEST/RESPONSE | Current capture statistics |
| RUN_WORKFLOW | Rust→Python | REQUEST/RESPONSE | Execute analysis workflow |
| GET_WORKFLOWS | Rust→Python | REQUEST/RESPONSE | List available workflows |
| CHECKPOINT_WRITTEN | Python→Rust | EVENT | Parquet checkpoint completed |
| EMERGENCY_CHECKPOINT | Python→Rust | EVENT | Final checkpoint on SIGTERM |
| CAPTURE_COMPLETE | Python→Rust | EVENT | Normal capture completion |
| LOG | Python→Rust | EVENT | Python log forwarding |
| HEARTBEAT | Python→Rust | HEARTBEAT | Liveness signal every 5s |

---

*Stub created for pre-commit compliance. Full documentation to follow.*

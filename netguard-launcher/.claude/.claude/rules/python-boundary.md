# Rule: Python Boundary

> Load this file any time Python files are mentioned, before suggesting any
> changes to the Python side, or when debugging involves the sidecar.

---

## The Fundamental Boundary

```
netguard-launcher/src/                        ← Rust crate (always fair game)
netguard/src/netguard/ipc/                    ← New IPC layer (Phase 2+)
netguard/src/netguard/ipc_sidecar.py          ← New sidecar (Phase 2+)
netguard/src/netguard/capture/checkpointed_writer.py  ← New (Phase 2+)
══════════════════════════════════════════════════════════════════
DO NOT TOUCH without explicit user instruction:
netguard/src/netguard/workflows/
netguard/src/netguard/capture/   (except checkpointed_writer.py)
netguard/src/netguard/analysis/
netguard/src/netguard/api.py
```

---

## What "Do Not Touch" Means

- Do not read these files to answer a question unless the user asks
- Do not suggest changes to these files
- Do not reference them in new sidecar code beyond what already exists
- Do not refactor them even if you see obvious improvements

The Python core is **unchanged by design**. The sidecar adapts to it.

---

## The Sidecar's One Job

```python
# ✅ CORRECT — thin translation only
def _handle_start_capture(self, payload: dict) -> dict:
    config = CaptureConfig(
        interface=payload["interface"],
        duration=payload.get("duration"),
        bpf_filter=payload.get("filter"),
    )
    result = self.capture_manager.start(config)
    return {"status": "started", "session_id": result.session_id}

# ❌ WRONG — sidecar contains logic it shouldn't own
def _handle_start_capture(self, payload: dict) -> dict:
    if payload["duration"] > 3600:   # validation belongs in Rust
        raise ValueError("too long")
```

---

## Python Files Claude May Write (Phase 2 Only)

| File | Purpose |
|------|---------|
| `netguard/src/netguard/ipc/framing.py` | `FramedSocket` |
| `netguard/src/netguard/ipc/envelope.py` | Envelope helpers |
| `netguard/src/netguard/ipc_sidecar.py` | `IpcSidecar` class |
| `netguard/src/netguard/capture/checkpointed_writer.py` | `CheckpointedParquetWriter` |

Do not create these files during Phase 1.

---

## Python Code Standards (New Files Only)

- `from __future__ import annotations` at the top of every file
- Module-level docstring
- Full type annotations on all function signatures
- Google-style docstrings on public functions
- No `print()` — `logging` module only
- No bare `except:` — always `except Exception:`
- Passes `mypy --strict`

---

## Sidecar Error Contract

On any Python core exception:
- Log full traceback to stderr
- Return `ERROR` response with `recoverable: true`
- **Continue processing the next command**
- The sidecar must never crash due to a Python core error

---

## Sidecar Test Layers

| Layer | What it tests | What is mocked |
|-------|--------------|----------------|
| 1 — Socket Mechanics | `FramedSocket` framing | Nothing — real socket pairs |
| 2 — Dispatch | `handle_message()` routing | All Python core dependencies |
| 3 — Core Translation | Payload → correct function args | Python core return values |
| 4 — Lifecycle | Startup, shutdown, signals | Threading, real socket |

No layer requires root, a real network interface, or a live capture.

# Rule: Error Handling

> Load this file when working on `error.rs`, adding error variants, or
> writing any code that handles or propagates errors.

---

## Error Hierarchy

```
Error (top-level, in error.rs)
├── Ipc(IpcError)
├── Config(ConfigError)
├── Permission(PermissionError)
├── Validation(ValidationError)
└── Python(PythonError)
```

Every variant of every sub-enum must implement all four methods below.
Do not add a variant without implementing all four.

---

## Required Methods on Every Error Variant

```rust
// What the user sees — no Rust jargon, no technical internals
fn user_message(&self) -> String;

// What the user should do — None is acceptable if no action exists
fn suggestion(&self) -> Option<String>;

// How serious is this?
fn severity(&self) -> Severity;  // Critical | High | Medium | Low

// Can the system continue, or must it stop?
fn recoverable(&self) -> bool;
```

---

## Correct Pattern vs Wrong Pattern

### Converting Option to Result

```rust
// ✅ CORRECT
let value = some_option
    .ok_or_else(|| Error::Config(ConfigError::MissingField("interface")))?;

// ❌ WRONG — breaks the build
let value = some_option.unwrap();

// ❌ WRONG — anyhow not allowed in library code
let value = some_option.context("missing field")?;
```

### Propagating Across Layer Boundaries

```rust
// ✅ CORRECT — convert at the boundary with map_err
fn orchestrator_thing() -> Result<(), Error> {
    infra_thing().map_err(|e| Error::Ipc(IpcError::from(e)))?;
    Ok(())
}

// ❌ WRONG — leaks internal error type through layer
fn orchestrator_thing() -> Result<(), infra::Error> { ... }
```

### Error Messages

```rust
// ✅ CORRECT — actionable, no Rust jargon
fn user_message(&self) -> String {
    match self {
        Self::SocketPermissions { path } =>
            format!("Cannot access IPC socket at {}. Check file permissions.", path),
        Self::MaxRetriesExceeded =>
            "Python sidecar failed to restart after 3 attempts.".to_string(),
    }
}

fn suggestion(&self) -> Option<String> {
    match self {
        Self::SocketPermissions { .. } =>
            Some("Run `just setup` to recreate the socket with correct permissions.".to_string()),
        Self::MaxRetriesExceeded =>
            Some("Check logs with `netguard doctor` for the root cause.".to_string()),
    }
}

// ❌ WRONG — raw Rust error, no fix guidance
fn user_message(&self) -> String {
    format!("Os error: {}", self.inner)
}
```

---

## Severity Guide

| Situation | Severity | Recoverable |
|-----------|----------|-------------|
| Sidecar crashed, supervisor restarting | High | true |
| Capabilities missing (capture disabled) | Medium | true |
| Config file missing a field (using default) | Low | true |
| Version mismatch between Rust and Python | Critical | false |
| Socket could not be created | High | false |
| Invalid user input (bad interface name) | Low | true |

---

## Testing Error Variants

Every new error variant needs a unit test that verifies:
1. `user_message()` returns a non-empty, readable string
2. `suggestion()` returns `Some(...)` for errors where a fix exists
3. `recoverable()` matches the expected value

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn given_socket_permissions_error_then_message_is_actionable() {
        let err = IpcError::SocketPermissions { path: "/tmp/test.sock".into() };
        assert!(!err.user_message().is_empty());
        assert!(err.suggestion().is_some());
        assert!(!err.recoverable());
    }
}
```

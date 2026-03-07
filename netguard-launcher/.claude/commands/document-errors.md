Add construction documentation to every error enum variant in the specified file(s).

For each variant, apply this rule:
- If it is a **tuple variant wrapping another error type**: add a `# Example` section showing the full nested construction chain, including how to construct the inner type.
- If it has a **`String` field with a non-obvious format convention** (capability names, version strings, package names, key paths, command names, IPC codes, etc.): document the convention explicitly in both prose and with an inline comment in the example code.
- If it has a **`suggestion: String` or similar field embedded in the struct** (i.e. a field that holds user-facing advice rather than an error value): show a complete, runnable example value.

**Example section format** (use `rust,no_run`):

```rust
/// # Example
///
/// ```rust,no_run
/// use my_crate::module::error::MyError;
///
/// let err = MyError::VariantName {
///     string_field: "concrete-value".to_string(), // format: what it must look like
///     other_field: 42,
/// };
/// ```
```

**Import path rules:**
- Doc tests compile as external crates — use the full external crate path (`use my_crate::...`), never `use crate::...`.
- Check each module's `mod.rs` for `pub mod` declarations to confirm the path is accessible.
- If a required type is `pub(crate)` only, omit it from the example or use a hidden `#` line.

Do NOT add examples to variants where all fields are self-evident from their types (`PathBuf`, `std::io::Error`, `Duration`, numeric types, known library error types, unit variants).

After editing, run `cargo test --doc` to verify all `no_run` examples are syntactically valid.

#!/usr/bin/env bash
# Pre-commit hook — runs on every commit
# Checks: Rust fmt, Rust clippy, Python ruff format, Python ruff lint, mypy
# Does NOT run tests (too slow for pre-commit) — tests run pre-push
# Does NOT run security audit — runs pre-push

# shellcheck source=.githooks/common.sh
source "$(git rev-parse --show-toplevel)/.githooks/common.sh"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  NetGuard pre-commit quality gate"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

FAILED=0

# ── Rust checks ──────────────────────────────────────────────────────────────

if path_exists "netguard-launcher/Cargo.toml"; then
  step "Rust — format check"
  cd "$RUST_CRATE"

  run_check "cargo fmt --check" cargo fmt --check || FAILED=1

  step "Rust — clippy (hard lints)"
  run_check_verbose "cargo clippy" cargo clippy --all-targets --all-features -- \
    -D warnings \
    -D clippy::unwrap_used \
    -D clippy::expect_used \
    -D clippy::panic \
    -W clippy::pedantic \
    -W clippy::nursery \
    2>&1 | grep -E "^error|^warning\[" | head -30 || FAILED=1

  cd "$REPO_ROOT"
else
  skip "Rust crate (netguard-launcher not found)"
fi

# ── Python checks ─────────────────────────────────────────────────────────────

activate_venv || { skip "Python venv not found — run: uv venv && uv pip sync requirements-dev.txt"; }

SIDECAR_FILES=(
  "netguard/src/netguard/ipc_sidecar.py"
  "netguard/src/netguard/ipc/"
  "netguard/src/netguard/capture/checkpointed_writer.py"
)

# Only check Python files that actually exist
EXISTING_PY_TARGETS=()
for f in "${SIDECAR_FILES[@]}"; do
  path_exists "$f" && EXISTING_PY_TARGETS+=("$REPO_ROOT/$f")
done

if [ ${#EXISTING_PY_TARGETS[@]} -gt 0 ]; then
  step "Python — ruff format check"
  run_check "ruff format --check" uv run ruff format --check "${EXISTING_PY_TARGETS[@]}" || FAILED=1

  step "Python — ruff lint"
  run_check_verbose "ruff lint" uv run ruff check "${EXISTING_PY_TARGETS[@]}" || FAILED=1

  step "Python — mypy (--strict on sidecar code)"
  if path_exists "netguard/src/netguard/ipc"; then
    run_check_verbose "mypy strict" uv run mypy \
      --strict \
      "$REPO_ROOT/netguard/src/netguard/ipc/" \
      "$REPO_ROOT/netguard/src/netguard/ipc_sidecar.py" \
      2>/dev/null || FAILED=1
  else
    skip "mypy (ipc module not yet created — Phase 2)"
  fi
else
  skip "Python sidecar files (not yet created — Phase 1 or 2)"
fi

# ── Guard: ARCHITECTURE.md must be updated when IPC actions change ────────────

step "Architecture consistency check"
STAGED=$(git diff --cached --name-only 2>/dev/null)

IPC_CHANGED=0
ARCH_CHANGED=0
echo "$STAGED" | grep -qE "(envelope\.(rs|py)|ipc_sidecar\.py)" && IPC_CHANGED=1
echo "$STAGED" | grep -q "ARCHITECTURE.md" && ARCH_CHANGED=1

if [ "$IPC_CHANGED" -eq 1 ] && [ "$ARCH_CHANGED" -eq 0 ]; then
  fail "IPC files changed but ARCHITECTURE.md was not updated"
  echo "    Per project rules: update the Defined Actions table in"
  echo "    ARCHITECTURE.md before committing IPC changes."
  echo "    (If no new actions were added, add ARCHITECTURE.md with no"
  echo "     content change to acknowledge this check.)"
  FAILED=1
else
  pass "Architecture consistency"
fi

# ── Trailing whitespace / merge conflict markers ───────────────────────────────

step "Hygiene checks"
if git diff --cached --check >/dev/null 2>&1; then
  pass "No trailing whitespace or conflict markers"
else
  fail "Trailing whitespace or conflict markers found"
  git diff --cached --check 2>&1 | head -20
  FAILED=1
fi

# ── Result ────────────────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ "$FAILED" -eq 0 ]; then
  echo -e "  ${GREEN}✓ Pre-commit gate passed — proceeding${NC}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  exit 0
else
  echo -e "  ${RED}✗ Pre-commit gate failed — commit blocked${NC}"
  echo ""
  echo "  Run  just fmt   to auto-fix formatting issues"
  echo "  Run  just fix   to auto-fix lint issues"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  exit 1
fi

#!/usr/bin/env bash
# =============================================================================
# NetGuard — Git Quality Hooks Installer
# Run this once from the repo root: bash install-hooks.sh
# Requires: cargo, uv, git
# =============================================================================

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOKS_DIR="$REPO_ROOT/.git/hooks"
SCRIPTS_DIR="$REPO_ROOT/.githooks"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${BLUE}[hooks]${NC} $*"; }
success() { echo -e "${GREEN}[hooks]${NC} $*"; }
warn()    { echo -e "${YELLOW}[hooks]${NC} $*"; }
error()   { echo -e "${RED}[hooks]${NC} $*" >&2; }

# =============================================================================
# Preflight
# =============================================================================

info "Installing NetGuard git quality hooks..."

command -v cargo >/dev/null 2>&1 || { error "cargo not found — install Rust first"; exit 1; }
command -v uv    >/dev/null 2>&1 || { error "uv not found — install uv first"; exit 1; }
command -v just  >/dev/null 2>&1 || { warn "just not found — some gates will run commands directly"; }

mkdir -p "$SCRIPTS_DIR"

# =============================================================================
# Shared helpers — sourced by every hook
# =============================================================================

cat > "$SCRIPTS_DIR/common.sh" << 'COMMON'
#!/usr/bin/env bash
# Sourced by all hooks — do not execute directly

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

pass()  { echo -e "  ${GREEN}✓${NC} $*"; }
fail()  { echo -e "  ${RED}✗${NC} $*"; }
skip()  { echo -e "  ${YELLOW}–${NC} $* (skipped)"; }
step()  { echo -e "\n${BLUE}▶${NC} $*"; }

REPO_ROOT="$(git rev-parse --show-toplevel)"
RUST_CRATE="$REPO_ROOT/netguard-launcher"
PYTHON_SRC="$REPO_ROOT/netguard/src/netguard"

# Activate uv venv if it exists
activate_venv() {
  if [ -f "$REPO_ROOT/.venv/bin/activate" ]; then
    # shellcheck source=/dev/null
    source "$REPO_ROOT/.venv/bin/activate"
    return 0
  elif [ -f "$REPO_ROOT/netguard/.venv/bin/activate" ]; then
    # shellcheck source=/dev/null
    source "$REPO_ROOT/netguard/.venv/bin/activate"
    return 0
  else
    return 1
  fi
}

# Check if a path exists in the repo (skip gracefully if not yet implemented)
path_exists() { [ -e "$REPO_ROOT/$1" ]; }

# Run a command and report pass/fail without aborting the whole hook
run_check() {
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then
    pass "$label"
    return 0
  else
    fail "$label"
    "$@" 2>&1 | sed 's/^/    /'
    return 1
  fi
}

# Same but always show output (for tests)
run_check_verbose() {
  local label="$1"; shift
  if "$@"; then
    pass "$label"
    return 0
  else
    fail "$label"
    return 1
  fi
}
COMMON

chmod +x "$SCRIPTS_DIR/common.sh"

# =============================================================================
# HOOK 1: commit-msg — Conventional Commits enforcement
# =============================================================================

cat > "$SCRIPTS_DIR/commit-msg.sh" << 'COMMITMSG'
#!/usr/bin/env bash
# Enforces Conventional Commits format
# Types:  feat|fix|docs|test|refactor|perf|chore|wip
# Scopes: orchestrator|ipc|sidecar|cli|tui|config|docs|validation|permissions|all
# Examples:
#   feat(ipc): add heartbeat timeout supervisor event
#   fix(sidecar): handle SIGTERM during active checkpoint
#   docs(architecture): update IPC action table for STOP_CAPTURE
#   wip(cli): partial capture command handler — gate 3 in progress

COMMIT_MSG_FILE="$1"
COMMIT_MSG=$(cat "$COMMIT_MSG_FILE")

# Allow merge commits and fixups
if echo "$COMMIT_MSG" | grep -qE "^(Merge|Revert|fixup!|squash!)"; then
  exit 0
fi

TYPES="feat|fix|docs|test|refactor|perf|chore|wip|build|ci"
SCOPES="orchestrator|ipc|sidecar|cli|tui|config|docs|validation|permissions|all|state|supervisor|env|infra"

PATTERN="^(${TYPES})(\((${SCOPES})\))?(!)?: .{1,100}$"

if ! echo "$COMMIT_MSG" | head -1 | grep -qE "$PATTERN"; then
  echo ""
  echo "  ✗ Commit message does not follow Conventional Commits format"
  echo ""
  echo "  Required format:"
  echo "    type(scope): description"
  echo ""
  echo "  Valid types:  feat fix docs test refactor perf chore wip build ci"
  echo "  Valid scopes: orchestrator ipc sidecar cli tui config docs"
  echo "                validation permissions all state supervisor env infra"
  echo ""
  echo "  Your message: $(head -1 "$COMMIT_MSG_FILE")"
  echo ""
  echo "  Examples:"
  echo "    feat(ipc): add length-prefix framing for socket messages"
  echo "    fix(supervisor): clamp restart backoff to 60s maximum"
  echo "    test(sidecar): add layer 2 dispatch tests for all actions"
  echo "    wip(cli): capture handler — IPC roundtrip not yet wired"
  echo ""
  exit 1
fi

exit 0
COMMITMSG

chmod +x "$SCRIPTS_DIR/commit-msg.sh"

# =============================================================================
# HOOK 2: pre-commit — Fast quality gates (target: <30s)
# =============================================================================

cat > "$SCRIPTS_DIR/pre-commit.sh" << 'PRECOMMIT'
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
PRECOMMIT

chmod +x "$SCRIPTS_DIR/pre-commit.sh"

# =============================================================================
# HOOK 3: pre-push — Full quality gate (target: <2min)
# =============================================================================

cat > "$SCRIPTS_DIR/pre-push.sh" << 'PREPUSH'
#!/usr/bin/env bash
# Pre-push hook — runs on every git push
# Checks: full test suite (Rust + Python), security audit
# This is the gate that enforces the phase validation conditions from
# IMPLEMENTATION_TODO.md before code reaches the remote.

# shellcheck source=.githooks/common.sh
source "$(git rev-parse --show-toplevel)/.githooks/common.sh"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  NetGuard pre-push quality gate"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

FAILED=0
START_TIME=$(date +%s)

# ── Detect current phase from what exists ──────────────────────────────────────
# Phase 1: error.rs and state.rs exist
# Phase 2: ipc/server.rs and ipc_sidecar.py exist
# Phase 3: cli/args.rs exists
# Phase 4: benches/ exists

PHASE=0
path_exists "netguard-launcher/src/error.rs"          && PHASE=1
path_exists "netguard-launcher/src/infra/ipc/server.rs" && PHASE=2
path_exists "netguard-launcher/src/cli/args.rs"        && PHASE=3
path_exists "netguard-launcher/benches"                && PHASE=4

echo ""
echo "  Detected project phase: $PHASE"
echo ""

# ── Rust tests ────────────────────────────────────────────────────────────────

if path_exists "netguard-launcher/Cargo.toml"; then
  step "Rust — full test suite"
  cd "$RUST_CRATE"
  run_check_verbose "cargo test (all targets)" cargo test --all-targets 2>&1 || FAILED=1
  cd "$REPO_ROOT"
fi

# ── Python tests ──────────────────────────────────────────────────────────────

activate_venv || true

if path_exists "netguard/tests"; then
  step "Python — unit + integration tests (excludes slow + e2e)"

  if [ "$PHASE" -ge 2 ] && path_exists "netguard/tests/ipc"; then
    step "Python — sidecar IPC tests (all four layers)"
    run_check_verbose "pytest tests/ipc" \
      uv run pytest "$REPO_ROOT/netguard/tests/ipc/" -v --tb=short 2>&1 || FAILED=1
  fi

  run_check_verbose "pytest (not slow, not e2e)" \
    uv run pytest "$REPO_ROOT/netguard/tests/" \
    -m "not slow and not e2e" \
    --tb=short \
    --ignore="$REPO_ROOT/netguard/tests/ipc" \
    2>&1 || FAILED=1
else
  skip "Python tests (tests/ directory not yet created)"
fi

# ── Security audit (runs on push, not commit) ──────────────────────────────────

step "Security — cargo audit"
if command -v cargo-audit >/dev/null 2>&1; then
  run_check_verbose "cargo audit" cargo audit 2>&1 || FAILED=1
else
  skip "cargo audit (not installed — run: cargo install cargo-audit)"
fi

step "Security — cargo deny"
if path_exists "netguard-launcher/deny.toml"; then
  if command -v cargo-deny >/dev/null 2>&1; then
    cd "$RUST_CRATE"
    run_check_verbose "cargo deny check" cargo deny check 2>&1 || FAILED=1
    cd "$REPO_ROOT"
  else
    skip "cargo deny (not installed — run: cargo install cargo-deny)"
  fi
fi

if command -v uv >/dev/null 2>&1 && activate_venv 2>/dev/null; then
  step "Security — Python bandit"
  if path_exists "netguard/src/netguard/ipc_sidecar.py"; then
    run_check_verbose "bandit" \
      uv run bandit -r "$REPO_ROOT/netguard/src/netguard/" -ll -q 2>&1 || FAILED=1
  else
    skip "bandit (sidecar not yet created — Phase 2)"
  fi

  step "Security — pip-audit"
  if path_exists "netguard/requirements.txt"; then
    run_check_verbose "pip-audit" uv run pip-audit -r "$REPO_ROOT/netguard/requirements.txt" 2>&1 || FAILED=1
  else
    skip "pip-audit (requirements.txt not found)"
  fi
fi

# ── Phase-specific gate check ──────────────────────────────────────────────────
# Mirrors IMPLEMENTATION_TODO.md validation gates exactly

step "Phase $PHASE validation gate"

check_phase_1_gate() {
  local ok=0
  path_exists "netguard-launcher/src/error.rs"               || { fail "error.rs missing"; ok=1; }
  path_exists "netguard-launcher/src/orchestrator/state.rs"  || { fail "state.rs missing"; ok=1; }
  path_exists "netguard-launcher/src/core/validation.rs"     || { fail "validation.rs missing"; ok=1; }
  path_exists "netguard-launcher/src/infra/config/mod.rs"    || { fail "config/mod.rs missing"; ok=1; }
  [ $ok -eq 0 ] && pass "Phase 1 gate — all required files present"
  return $ok
}

check_phase_2_gate() {
  local ok=0
  path_exists "netguard-launcher/src/infra/ipc/server.rs"    || { fail "ipc/server.rs missing"; ok=1; }
  path_exists "netguard-launcher/src/infra/ipc/envelope.rs"  || { fail "ipc/envelope.rs missing"; ok=1; }
  path_exists "netguard-launcher/src/orchestrator/supervisor.rs" || { fail "supervisor.rs missing"; ok=1; }
  path_exists "netguard/src/netguard/ipc_sidecar.py"         || { fail "ipc_sidecar.py missing"; ok=1; }
  path_exists "netguard/src/netguard/ipc/framing.py"         || { fail "ipc/framing.py missing"; ok=1; }
  [ $ok -eq 0 ] && pass "Phase 2 gate — all required files present"
  return $ok
}

check_phase_3_gate() {
  local ok=0
  path_exists "netguard-launcher/src/cli/args.rs"            || { fail "cli/args.rs missing"; ok=1; }
  path_exists "netguard-launcher/src/orchestrator/handle.rs" || { fail "orchestrator/handle.rs missing"; ok=1; }
  path_exists "netguard-launcher/src/display/mod.rs"         || { fail "display/mod.rs missing"; ok=1; }
  [ $ok -eq 0 ] && pass "Phase 3 gate — all required files present"
  return $ok
}

case "$PHASE" in
  1) check_phase_1_gate || FAILED=1 ;;
  2) check_phase_1_gate || FAILED=1; check_phase_2_gate || FAILED=1 ;;
  3) check_phase_2_gate || FAILED=1; check_phase_3_gate || FAILED=1 ;;
  4) check_phase_3_gate || FAILED=1 ;;
  0) skip "Phase gate (Phase 1 not yet started)" ;;
esac

# ── Timing ────────────────────────────────────────────────────────────────────

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

# ── Result ────────────────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Completed in ${ELAPSED}s"
if [ "$FAILED" -eq 0 ]; then
  echo -e "  ${GREEN}✓ Pre-push gate passed — pushing${NC}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  exit 0
else
  echo -e "  ${RED}✗ Pre-push gate failed — push blocked${NC}"
  echo ""
  echo "  Fix the issues above, then re-run: git push"
  echo "  To push anyway (emergency only): git push --no-verify"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  exit 1
fi
PREPUSH

chmod +x "$SCRIPTS_DIR/pre-push.sh"

# =============================================================================
# Install hooks by symlinking into .git/hooks
# =============================================================================

ln -sf "../../.githooks/commit-msg.sh"  "$HOOKS_DIR/commit-msg"
ln -sf "../../.githooks/pre-commit.sh"  "$HOOKS_DIR/pre-commit"
ln -sf "../../.githooks/pre-push.sh"    "$HOOKS_DIR/pre-push"

chmod +x "$HOOKS_DIR/commit-msg"
chmod +x "$HOOKS_DIR/pre-commit"
chmod +x "$HOOKS_DIR/pre-push"

# =============================================================================
# Commit message template
# =============================================================================

cat > "$REPO_ROOT/.git/commit-template" << 'TEMPLATE'
# type(scope): short description (max 100 chars)
#
# Types:  feat fix docs test refactor perf chore wip build ci
# Scopes: orchestrator ipc sidecar cli tui config docs
#         validation permissions state supervisor env infra all
#
# Optional body — explain WHY, not WHAT (what is in the diff):
#
#
# Optional footer (breaking changes, closes issues):
# BREAKING CHANGE: description
# Closes #123
TEMPLATE

git config commit.template .git/commit-template

# =============================================================================
# Summary
# =============================================================================

echo ""
success "Hooks installed successfully:"
echo ""
echo "  commit-msg  → Conventional Commits format enforcement"
echo "  pre-commit  → fmt + clippy + ruff + mypy  (fast, every commit)"
echo "  pre-push    → full tests + security audit  (thorough, on push)"
echo ""
echo "  Scripts stored in: .githooks/ (commit these to the repo)"
echo "  Linked into:       .git/hooks/ (git uses these)"
echo ""
echo "  To skip hooks in an emergency: git push --no-verify"
echo "  To re-run pre-push manually:   bash .githooks/pre-push.sh"
echo ""
success "Done."
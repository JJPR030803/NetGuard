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

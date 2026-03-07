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

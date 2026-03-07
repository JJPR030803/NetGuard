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

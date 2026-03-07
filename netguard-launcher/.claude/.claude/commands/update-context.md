# Update Working Context

Refresh the "Current Working Context" block in `CLAUDE.md`.
Confirm the proposed update with the user before writing.

## Step 1 — Gather State

Run silently:
```bash
cargo check 2>&1 | tail -5
cargo test 2>&1 | tail -10
git status --short 2>/dev/null | head -10
git log --oneline -3 2>/dev/null
```

Read `IMPLEMENTATION_TODO.md` to find current phase and checked-off items.

## Step 2 — Determine Each Field

**Phase:** Current phase number and name
**Gate status:** "Not yet run" / "PASS — [note]" / "FAIL — [what]" / "PARTIAL — [detail]"
**Last file worked:** Most recently modified source file (from git status or conversation)
**Active task:** One sentence on what is currently being worked on
**Blocked on:** Any known blocker, or "—"

## Step 3 — Propose Update

Present the proposed block:
```
Phase:            [value]
Gate status:      [value]
Last file worked: [value]
Active task:      [value]
Blocked on:       [value]
```

Ask: "Should I update the Current Working Context block in CLAUDE.md with this?"

## Step 4 — Write (After Confirmation)

Update only the "Current Working Context" block in `CLAUDE.md`.
Do not change any other part of the file.
Confirm the write and show the final block.

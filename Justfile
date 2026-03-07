# NetGuard — Project jf
# Run `just` to see all available commands.
# Run `just setup` on a fresh clone before anything else.
#
# Prerequisites: just, cargo, uv, python 3.11+
# Install just: cargo install just  OR  snap install just

# ── Default ──────────────────────────────────────────────────────────────────

# Show all available recipes
default:
    @just --list --unsorted

# ── Setup ────────────────────────────────────────────────────────────────────

# One-time: build Rust crate, create Python venv, install all deps
setup:
    @echo "→ Building Rust crate..."
    cd netguard-launcher && cargo build
    @echo "→ Creating Python venv with uv..."
    uv venv
    @echo "→ Installing Python dependencies..."
    uv pip sync pyproject.toml --all-extras
    @echo "✓ Setup complete. Run 'just doctor' to verify your environment."

# Install git quality hooks (run once after cloning)
install-hooks:
    bash scripts/dev/init_githooks.sh

# Set packet capture capabilities on Python binary (Linux only, requires sudo)
setup-caps:
    @echo "→ Setting cap_net_raw and cap_net_admin on Python binary..."
    sudo setcap cap_net_raw,cap_net_admin=eip $(uv run which python)
    @echo "✓ Capture capabilities set."

# Run the first-run setup wizard
setup-wizard:
    cd netguard-launcher && cargo run -- setup

# ── Development ──────────────────────────────────────────────────────────────

# Run NetGuard with arguments (e.g. just run -- doctor)
run *ARGS:
    cd netguard-launcher && cargo run -- {{ARGS}}

# Watch mode: re-run lib tests + clippy on every file save (requires cargo-watch)
dev:
    cd netguard-launcher && cargo watch -x "test --lib" -x "clippy -- -D warnings"

# ── Testing ──────────────────────────────────────────────────────────────────

# Run all tests — Rust + Python (excludes slow and e2e)
test:
    @echo "→ Rust tests..."
    cd netguard-launcher && cargo test
    @echo "→ Python tests (unit + integration, no slow/e2e)..."
    uv run pytest -m "not slow and not e2e" -q

# Run including slow lifecycle/integration tests
test-all:
    cd netguard-launcher && cargo test
    uv run pytest -m "not e2e" -q

# Property-based fuzz tests — run before release (slow)
test-fuzz:
    cd netguard-launcher && cargo test --release -- --ignored

# End-to-end tests — requires root and real network hardware
test-e2e:
    cd netguard-launcher && cargo test --ignored --test e2e
    uv run pytest -m "e2e" -v

# Rust tests only
test-rust:
    cd netguard-launcher && cargo test

# Python tests only
test-python:
    uv run pytest -m "not slow and not e2e" -q

# Python tests with coverage report
test-coverage:
    uv run pytest --cov=src/netguard --cov-report=html --cov-report=term-missing -q
    @echo "→ HTML report: htmlcov/index.html"

# ── Code Quality ─────────────────────────────────────────────────────────────

# Format all code (Rust + Python)
fmt:
    cd netguard-launcher && PATH="$HOME/.cargo/bin:$PATH" cargo fmt
    uv run ruff format .

# Lint all code (Rust + Python)
lint:
    cd netguard-launcher && cargo clippy -- \
        -D warnings \
        -D clippy::unwrap_used \
        -D clippy::expect_used \
        -D clippy::panic \
        -W clippy::pedantic \
        -W clippy::nursery
    uv run ruff check .
    uv run mypy src/netguard/

# Fix auto-fixable lint issues
fix:
    cd netguard-launcher && cargo clippy --fix --allow-dirty
    uv run ruff check --fix .

# Check formatting without modifying files (used in pre-commit)
fmt-check:
    cd netguard-launcher && PATH="$HOME/.cargo/bin:$PATH" cargo fmt --check
    uv run ruff format --check .

# ── Security ─────────────────────────────────────────────────────────────────

# Full security audit — run before every release and thesis demo
security:
    @echo "→ cargo audit..."
    cd netguard-launcher && cargo audit
    @echo "→ cargo deny..."
    cd netguard-launcher && cargo deny check
    @echo "→ bandit (Python)..."
    uv run bandit -r src/netguard/ -ll
    @echo "→ pip-audit..."
    uv run pip-audit
    @echo "✓ Security audit complete."

# Check unsafe code surface area (slow — run quarterly)
security-geiger:
    cd netguard-launcher && cargo geiger --quiet

# ── Documentation ────────────────────────────────────────────────────────────

# Serve MkDocs documentation locally at http://127.0.0.1:8000
docs:
    uv run mkdocs serve

# Build static docs site
docs-build:
    uv run mkdocs build
    cd netguard-launcher && cargo doc --no-deps
    cp -r netguard-launcher/target/doc site/rust-api
    @echo "✓ Docs built: site/"

# Open Rust API docs in browser
docs-rust:
    cd netguard-launcher && cargo doc --no-deps --open

# Deploy docs to GitHub Pages
docs-deploy:
    just docs-build
    uv run mkdocs gh-deploy

# ── Benchmarks ───────────────────────────────────────────────────────────────

# Run performance benchmarks (IPC latency target: <1ms)
bench:
    cd netguard-launcher && cargo bench
    @echo "→ Results saved to netguard-launcher/target/criterion/"

# ── Environment Check ────────────────────────────────────────────────────────

# Check all prerequisites and environment health
doctor:
    cd netguard-launcher && cargo run -- doctor

# ── Build ─────────────────────────────────────────────────────────────────────

# Build optimised release binary
build:
    cd netguard-launcher && cargo build --release
    @echo "✓ Binary: netguard-launcher/target/release/netguard-launcher"

# Clean all build artifacts (Rust target dir + Python caches)
clean:
    cd netguard-launcher && cargo clean
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
    rm -rf htmlcov .coverage site
    @echo "✓ Clean complete."

# ── Pre-commit Gate ───────────────────────────────────────────────────────────

# Full quality gate: format-check + lint + test (run before every commit)
check: fmt-check lint test
    @echo "✓ All checks passed — ready to commit."

# Quick check: format-check + lint only (no tests, for fast iteration)
check-fast: fmt-check lint
    @echo "✓ Fast checks passed."

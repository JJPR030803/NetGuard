# Development Setup

Complete guide to setting up your development environment for NetGuard.

## Prerequisites

### Required Software

- **Python**: 3.9 - 3.13
- **uv**: Modern Python package manager
- **git**: Version control
- **make**: Build automation
- **libpcap**: Packet capture library (system-level)

### Operating System Support

- ✅ Linux (recommended)
- ✅ macOS
- ⚠️ Windows (WSL2 required)

## Installation

### 1. Install uv

```bash
# Linux/macOS
curl -LsSf https://astral.sh/uv/install.sh | sh

# Or with pip
pip install uv
```

### 2. Install System Dependencies

#### Linux (Debian/Ubuntu)
```bash
sudo apt-get update
sudo apt-get install -y \
    python3-dev \
    libpcap-dev \
    build-essential \
    git \
    make
```

#### Linux (Arch)
```bash
sudo pacman -S python libpcap base-devel git make
```

#### macOS
```bash
brew install libpcap
# Xcode Command Line Tools (includes make)
xcode-select --install
```

### 3. Clone Repository

```bash
git clone https://github.com/yourusername/netguard.git
cd netguard
```

### 4. Install Python Dependencies

```bash
# Install all dependencies including dev tools
make install

# Or manually
uv sync --all-extras
```

This installs:
- Core dependencies (scapy, fastapi, polars, etc.)
- Dev tools (pytest, black, ruff, pylint, mypy)
- Documentation tools (mkdocs-material)
- Pre-commit hooks

## Verification

### Check Installation

```bash
# Verify Python version
python --version  # Should be 3.9+

# Verify uv
uv --version

# Verify dependencies
uv pip list | grep -E "(scapy|polars|fastapi)"
```

### Run Quick Test

```bash
# Run tests
make test-quick

# Expected output:
# ============ test session starts ============
# collected X items
# tests/unit/test_packet_capture.py ....  [100%]
# ============ X passed in 0.XXs =============
```

## Development Environment

### IDE Setup

#### VS Code (Recommended)

Install extensions:
```json
{
  "recommendations": [
    "ms-python.python",
    "ms-python.vscode-pylance",
    "charliermarsh.ruff",
    "ms-python.black-formatter",
    "matangover.mypy"
  ]
}
```

Settings (`.vscode/settings.json`):
```json
{
  "python.defaultInterpreterPath": ".venv/bin/python",
  "python.linting.enabled": true,
  "python.linting.pylintEnabled": true,
  "python.formatting.provider": "black",
  "editor.formatOnSave": true,
  "[python]": {
    "editor.codeActionsOnSave": {
      "source.organizeImports": true
    }
  }
}
```

#### PyCharm

1. Open project
2. Settings → Project → Python Interpreter
3. Select `.venv/bin/python`
4. Enable "External Tools":
   - Black formatter
   - Ruff linter
   - MyPy type checker

### Pre-commit Hooks

Pre-commit hooks run automatically on every commit:

```bash
# Installed automatically with `make install`
# Or manually:
uv run pre-commit install

# Run manually on all files
make pre-commit
```

Hooks include:
- ✅ Black (formatting)
- ✅ isort (import sorting)
- ✅ Ruff (linting)
- ✅ MyPy (type checking)
- ✅ Pylint (code quality)
- ✅ Bandit (security)
- ✅ YAML/JSON validation
- ✅ Trailing whitespace removal

## Configuration Files

### pyproject.toml

Main configuration file:
```toml
[project]
name = "network-security-suite"
version = "0.1.0"
requires-python = ">=3.9,<3.14"

[tool.black]
line-length = 88

[tool.ruff]
line-length = 130

[tool.mypy]
strict = true

[tool.pytest.ini_options]
testpaths = ["tests"]
```

### Makefile

Development commands:
```makefile
make install      # Setup environment
make format       # Format code
make lint         # Run linters
make test         # Run tests
make docs-serve   # Serve documentation
```

## Network Capture Setup

### Linux Capabilities (Recommended)

Allow packet capture without root:

```bash
# Set capabilities on Python binary
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

# Or on specific script
sudo setcap cap_net_raw,cap_net_admin=eip .venv/bin/python
```

### Alternative: Run with sudo

```bash
sudo python src/network_security_suite/sniffer/packet_capture.py
```

### Verify Capture Permissions

```bash
# List network interfaces
python -c "from scapy.all import get_if_list; print(get_if_list())"

# Test capture (captures 5 packets)
sudo python -c "from scapy.all import sniff; sniff(count=5)"
```

## Development Workflow

### 1. Create Feature Branch

```bash
git checkout -b feature/my-feature
```

### 2. Make Changes

```bash
# Edit code
vim src/network_security_suite/sniffer/packet_capture.py
```

### 3. Format and Lint

```bash
# Format code
make format

# Check linting
make lint

# Type check
make type-check

# All checks
make check
```

### 4. Run Tests

```bash
# Run all tests
make test

# Quick test (no coverage)
make test-quick

# Specific test file
uv run pytest tests/unit/test_packet_capture.py -v
```

### 5. Commit Changes

```bash
git add .
git commit -m "feat: Add new feature"

# Pre-commit hooks run automatically
# If they fail, fix issues and re-commit
```

### 6. Push and Create PR

```bash
git push origin feature/my-feature
# Create pull request on GitHub
```

## Common Tasks

### Running the Sniffer

```bash
# With default config
python src/network_security_suite/sniffer/packet_capture.py

# With custom config
python src/network_security_suite/sniffer/packet_capture.py \
    --config configs/sniffer_config.yaml

# With specific interface
python src/network_security_suite/sniffer/packet_capture.py \
    --interface eth0 \
    --count 1000
```

### Running ML Analysis

```bash
# Daily audit workflow
python src/network_security_suite/ml/preprocessing/examples/daily_audit_example.py

# IP investigation
python src/network_security_suite/ml/preprocessing/examples/ip_investigation_example.py

# Threat hunting
python src/network_security_suite/ml/preprocessing/examples/threat_hunting_example.py
```

### Building Documentation

```bash
# Serve locally (auto-reload)
make docs-serve
# Visit http://127.0.0.1:8000

# Build static site
make docs-build
# Output in site/

# Deploy to GitHub Pages
make docs-deploy
```

## Troubleshooting

### Permission Denied (Packet Capture)

**Error**: `PermissionError: [Errno 1] Operation not permitted`

**Solution**:
```bash
# Option 1: Set capabilities (recommended)
sudo setcap cap_net_raw,cap_net_admin=eip .venv/bin/python

# Option 2: Run with sudo
sudo python script.py

# Option 3: Add user to group (varies by distro)
sudo usermod -a -G wireshark $USER
```

### Module Not Found

**Error**: `ModuleNotFoundError: No module named 'network_security_suite'`

**Solution**:
```bash
# Ensure you're in project root
cd /path/to/netguard

# Reinstall dependencies
uv sync --all-extras

# Set PYTHONPATH
export PYTHONPATH="$PWD/src:$PYTHONPATH"
```

### Pre-commit Hooks Failing

**Error**: Pre-commit hook failures

**Solution**:
```bash
# Update hooks
uv run pre-commit autoupdate

# Run manually to see errors
make pre-commit

# Skip hooks temporarily (not recommended)
git commit --no-verify
```

### MyPy Type Errors

**Error**: Type checking failures

**Solution**:
```bash
# Check specific file
uv run mypy src/network_security_suite/sniffer/packet_capture.py

# Ignore specific import
# Add to pyproject.toml:
[[tool.mypy.overrides]]
module = ["problematic_module.*"]
ignore_missing_imports = true
```

### Slow Tests

**Issue**: Tests taking too long

**Solution**:
```bash
# Run specific test
uv run pytest tests/unit/test_packet_capture.py::test_specific

# Run without coverage
make test-quick

# Run in parallel
uv run pytest -n auto
```

## Performance Tips

### Development Mode

```bash
# Faster imports (less validation)
export PYTHONOPTIMIZE=1

# Skip slow tests
uv run pytest -m "not slow"
```

### Testing Performance

```bash
# Profile tests
uv run pytest --profile

# Benchmark tests
uv run pytest --benchmark-only
```

## Environment Variables

### Development Variables

```bash
# Set log level
export NETGUARD_LOG_LEVEL=DEBUG

# Set data directory
export NETGUARD_DATA_DIR=/tmp/netguard_data

# Disable ML features for faster testing
export NETGUARD_ML_ENABLED=false
```

### Configuration Priority

```
1. CLI arguments        (highest)
2. Environment variables
3. Config file
4. Defaults             (lowest)
```

## Docker Development (Optional)

### Build Development Image

```bash
docker build -t netguard:dev .
```

### Run with Volume Mount

```bash
docker run -it --rm \
    --net=host \
    --cap-add=NET_RAW \
    -v $(pwd):/app \
    netguard:dev \
    bash
```

### Docker Compose Development

```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## Next Steps

- Read [Architecture Overview](architecture.md) to understand the design
- Check [Testing Guide](testing.md) for testing best practices
- Review [Contributing Guide](contributing.md) before submitting PRs
- See [Project Review](project-review.md) for project status

## Getting Help

- **Documentation**: Check module-specific docs
- **Issues**: GitHub issues for bug reports
- **Discussions**: GitHub discussions for questions
- **Code Review**: Request review from maintainers

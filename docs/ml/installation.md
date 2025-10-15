# Installation

This guide walks you through installing and setting up the ML Network Analysis Module.

## Prerequisites

- **Python**: 3.10 or higher
- **UV**: Package manager (recommended) or pip
- **System**: Linux, macOS, or Windows (WSL recommended)

## Installation Methods

### Method 1: Using UV (Recommended)

UV is a fast Python package manager that handles dependencies efficiently.

```bash
# Navigate to project root
cd /path/to/netguard

# Sync dependencies (installs everything from pyproject.toml)
uv sync

# Verify installation
uv run python -m preprocessing.main --help
```

### Method 2: Using pip

```bash
# Navigate to project root
cd /path/to/netguard

# Install in editable mode
pip install -e .

# Verify installation
python -m src.network_security_suite.ml.preprocessing.main --help
```

## Dependencies

The module requires the following key dependencies (automatically installed):

### Core Dependencies

- **polars** (>=0.20.0): Fast DataFrame library for data processing
- **pyarrow** (>=14.0.0): Parquet file support
- **numpy** (>=1.24.0): Numerical computing

### Optional Dependencies

- **pandas** (for compatibility with existing tools)
- **scikit-learn** (for ML feature extraction)

### Documentation Dependencies

- **mkdocs-material**: Documentation framework (for building docs)
- **mkdocstrings[python]**: API documentation generation

All dependencies are defined in `pyproject.toml`.

## Verifying Installation

### 1. Check Module Import

```python
# Test imports
python -c "from network_security_suite.ml.preprocessing.parquet_analysis import NetworkParquetAnalysis; print('✓ Import successful')"
```

### 2. Check CLI

```bash
# Should show help text
uv run python -m preprocessing.main --help
```

Expected output:
```
usage: main.py [-h] [-v] [-q] {analyze,info,schema,daily-audit,investigate-ip,threat-hunt} ...

Network Traffic Parquet Analysis Tool

positional arguments:
  {analyze,info,schema,daily-audit,investigate-ip,threat-hunt}
    analyze             Analyze a parquet file
    info                Display basic file information
    schema              Display parquet file schema
    daily-audit         Run automated daily security audit
    investigate-ip      Investigate specific IP address
    threat-hunt         Proactive threat hunting
...
```

### 3. Run Test Analysis

Create a test script to verify everything works:

```python
# test_install.py
from network_security_suite.ml.preprocessing.workflows import DailyAudit

print("✓ Imports successful")
print("✓ Installation complete!")
```

```bash
uv run python test_install.py
```

## Development Installation

For contributing or development:

```bash
# Clone repository
git clone https://github.com/yourusername/netguard.git
cd netguard

# Install with dev dependencies
uv sync --dev

# Install pre-commit hooks (optional)
pre-commit install

# Run tests
uv run pytest tests/
```

## Troubleshooting

### ImportError: No module named 'polars'

**Solution**: Dependencies not installed

```bash
# With UV
uv sync

# With pip
pip install -e .
```

### ModuleNotFoundError: No module named 'network_security_suite'

**Solution**: Not running from correct directory or package not installed

```bash
# Make sure you're in the project root
cd /path/to/netguard

# Install in editable mode
pip install -e .
```

### UnicodeDecodeError when running

**Solution**: This was fixed in the logger.py file (replaced invalid character)

```bash
# Pull latest changes
git pull

# Or manually verify logger.py line 113 has proper × character
```

### "File not found" when running CLI

**Solution**: Provide full path to parquet file

```bash
# Use absolute path
uv run python -m preprocessing.main daily-audit /full/path/to/capture.parquet
```

### Memory errors with large files

**Solution**: Use lazy loading

```bash
# Add --lazy flag
uv run python -m preprocessing.main daily-audit large_file.parquet --lazy
```

## Configuration

### Environment Variables

You can set these environment variables for customization:

```bash
# Set custom log level
export NETGUARD_LOG_LEVEL=DEBUG

# Set custom output directory
export NETGUARD_OUTPUT_DIR=/path/to/reports
```

### Config File (Future)

Configuration file support is planned for `config.yaml`:

```yaml
# .netguard/config.yaml (planned)
business_hours:
  start: "09:00"
  end: "17:00"

thresholds:
  port_scan: 100
  syn_flood: 1000
  dns_tunneling: 100

output:
  format: json
  directory: ./reports
```

## Next Steps

1. **[Quick Start](quickstart.md)**: Run your first analysis
2. **[User Guide](user-guide/getting-started.md)**: Learn the workflows
3. **[CLI Reference](user-guide/cli-reference.md)**: Explore all commands
4. **[Examples](examples/index.md)**: See real-world usage

## Updating

### Update with UV

```bash
# Pull latest changes
git pull

# Update dependencies
uv sync
```

### Update with pip

```bash
# Pull latest changes
git pull

# Reinstall
pip install -e . --upgrade
```

## Uninstalling

```bash
# With pip
pip uninstall network-security-suite

# With UV (remove from project)
uv remove network-security-suite
```

## Docker Installation (Optional)

For isolated environments:

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install UV
RUN pip install uv

# Copy project files
COPY . .

# Install dependencies
RUN uv sync

# Run analysis
ENTRYPOINT ["uv", "run", "python", "-m", "preprocessing.main"]
```

Build and run:

```bash
# Build image
docker build -t netguard-ml .

# Run analysis
docker run -v $(pwd)/data:/data netguard-ml daily-audit /data/capture.parquet
```

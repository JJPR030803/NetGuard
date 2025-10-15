# Getting Started

This guide will get you from zero to analyzing network traffic in 5 minutes.

## Prerequisites

- Python 3.10+
- Network capture in Parquet format
- UV or pip installed

## Installation

```bash
# Navigate to project
cd /path/to/netguard

# Install dependencies
uv sync
```

[See full installation guide →](../installation.md)

## Your First Analysis

### Step 1: Prepare Your Data

You need a Parquet file containing network captures. This typically comes from your packet sniffer.

**Expected columns:**
- `timestamp`
- `source_ip`, `destination_ip`
- `source_port`, `destination_port`
- `protocol`
- Other packet metadata

### Step 2: Run Daily Audit

```bash
uv run python -m preprocessing.main daily-audit your_capture.parquet
```

You'll see a report like:

```
==============================================================================
  Daily Security Audit Report
================================================================================

FINDINGS SUMMARY:
  🔴 Critical: 0
  🟠 High:     2
  🟡 Medium:   5
  🔵 Low:      3
  ⚪ Info:     8

✓ Analysis complete
```

### Step 3: Investigate Findings

If the audit found something suspicious, investigate:

```bash
# Investigate a specific IP from the report
uv run python -m preprocessing.main investigate-ip your_capture.parquet 192.168.1.100
```

## What's Next?

- **[Learn the workflows](workflows/index.md)**: Understand the three main workflows
- **[CLI Reference](cli-reference.md)**: Explore all commands
- **[Examples](../examples/index.md)**: See real-world usage

## Common Workflows

### Daily Security Monitoring

```bash
# 1. Your sniffer captures traffic → saves to daily_capture.parquet
# 2. Run audit
uv run python -m preprocessing.main daily-audit daily_capture.parquet --export daily_report.json

# 3. Check for critical findings
cat daily_report.json | jq '.severity_counts.critical'
```

### Incident Investigation

```bash
# 1. Find suspicious IP from alerts
# 2. Deep dive investigation
uv run python -m preprocessing.main investigate-ip capture.parquet 10.0.0.50

# 3. Hunt for related threats
uv run python -m preprocessing.main threat-hunt capture.parquet --type lateral
```

### ML Feature Extraction

```python
from network_security_suite.ml.preprocessing.parquet_analysis import NetworkParquetAnalysis

# Load data
analysis = NetworkParquetAnalysis("capture.parquet")

# Extract behavioral features
features = analysis.behavioral_summary(
    time_window="1m",
    group_by_col="source_ip"
)

# Export for ML training
features.write_parquet("ml_features.parquet")
```

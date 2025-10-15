# Workflows Overview

Workflows are high-level interfaces that simplify common network analysis tasks. Instead of manually calling individual analyzer methods, workflows **orchestrate multiple analyzers** to solve specific problems.

## The Three Main Workflows

### 1. Daily Security Audit

**Purpose**: Automated comprehensive security check

**Use When**:
- Running daily/periodic security scans
- After capturing network traffic
- Monitoring for threats automatically

**What It Does**:
- Runs 15+ security checks automatically
- Detects port scans, floods, tunneling, spoofing
- Generates severity-rated reports (Critical/High/Medium/Low)
- Returns exit codes for automation

[Learn more →](daily-audit.md)

---

### 2. IP Investigation

**Purpose**: Deep dive into specific IP behavior

**Use When**:
- Investigating suspicious IP addresses
- Incident response
- Understanding what a host is doing

**What It Does**:
- Shows all activity for an IP
- Analyzes traffic patterns
- Checks for attack indicators
- Generates investigation report

[Learn more →](ip-investigation.md)

---

### 3. Threat Hunting

**Purpose**: Proactive threat detection

**Use When**:
- Searching for advanced threats
- Looking for C2 communication
- Detecting data exfiltration
- Finding lateral movement

**What It Does**:
- Hunts for C2 beaconing
- Detects data theft patterns
- Finds lateral movement indicators
- Targeted threat searches

[Learn more →](threat-hunting.md)

---

## Why Use Workflows?

### Without Workflows (Complex)

```python
# Manual approach - lots of boilerplate
analysis = NetworkParquetAnalysis("capture.parquet")

# Port scanning
port_scans = analysis.anomaly.detect_port_scanning(threshold=100, time_window="1m")

# SYN floods
syn_floods = analysis.anomaly.detect_syn_flood(threshold=1000, time_window="1m")

# DNS tunneling
dns_tunneling = analysis.dns.detect_dns_tunneling(length_threshold=100)

# DGA domains
dga = analysis.dns.identify_dga_domains()

# ... 10+ more checks ...

# Manually aggregate results
findings = []
if len(port_scans) > 0:
    findings.append({"severity": "high", "type": "port_scan", "count": len(port_scans)})
# ... etc for each check

# Format report manually
print(json.dumps(findings, indent=2))
```

### With Workflows (Simple)

```python
# Workflow approach - handles everything
audit = DailyAudit("capture.parquet")
report = audit.run()

# Human-readable report
print(report.summary())

# Or export to JSON
report.to_json("audit.json")
```

## Workflow vs Analyzer

| Aspect | Workflows | Analyzers |
|--------|-----------|-----------|
| **Level** | High-level | Low-level |
| **Purpose** | Solve complete tasks | Provide specific analysis |
| **Complexity** | Simple to use | More control, more complex |
| **Use Case** | 90% of tasks | Custom/advanced analysis |
| **Output** | Formatted reports | Raw DataFrames |
| **Examples** | DailyAudit, IPInvestigation | TCPAnalyzer, DNSAnalyzer |

## When to Use Each

### Use Workflows When:

- ✅ You want quick results
- ✅ Running routine checks
- ✅ Automating security audits
- ✅ You need formatted reports
- ✅ Investigating common scenarios

### Use Analyzers When:

- ✅ Building custom analysis
- ✅ Need fine-grained control
- ✅ Researching specific protocols
- ✅ Creating new workflows
- ✅ ML feature extraction

## Creating Custom Workflows

You can create your own workflows by extending the base pattern:

```python
from network_security_suite.ml.preprocessing.workflows import WorkflowReport
from network_security_suite.ml.preprocessing.parquet_analysis import NetworkParquetAnalysis

class ComplianceAudit:
    """Custom workflow for compliance checking."""

    def __init__(self, parquet_file):
        self.analysis = NetworkParquetAnalysis(parquet_file)
        self.logger = get_logger()

    def run(self):
        report = WorkflowReport("Compliance Audit Report")

        # Your custom checks
        self._check_encryption(report)
        self._check_allowed_protocols(report)
        self._check_authorized_ips(report)

        return report

    def _check_encryption(self, report):
        # Find unencrypted traffic
        unencrypted = self.analysis.df.filter(
            pl.col("port").is_in([80, 21, 23])  # HTTP, FTP, Telnet
        )

        if len(unencrypted) > 0:
            report.add_finding(
                severity="high",
                category="Unencrypted Traffic",
                description=f"Found {len(unencrypted)} unencrypted packets"
            )

    # ... more methods ...
```

[See examples →](../../examples/custom-analysis.md)

## CLI vs Python API

All workflows can be used via CLI or Python API:

=== "CLI"

    ```bash
    # Daily audit
    uv run python -m preprocessing.main daily-audit capture.parquet

    # IP investigation
    uv run python -m preprocessing.main investigate-ip capture.parquet 192.168.1.100

    # Threat hunting
    uv run python -m preprocessing.main threat-hunt capture.parquet --type c2
    ```

=== "Python API"

    ```python
    from network_security_suite.ml.preprocessing.workflows import (
        DailyAudit,
        IPInvestigation,
        ThreatHunting
    )

    # Daily audit
    audit = DailyAudit("capture.parquet")
    report = audit.run()

    # IP investigation
    inv = IPInvestigation("capture.parquet", ip="192.168.1.100")
    report = inv.run()

    # Threat hunting
    hunter = ThreatHunting("capture.parquet")
    report = hunter.hunt_for_c2()
    ```

## Report Format

All workflows return `WorkflowReport` objects with:

- **Title**: Report name
- **Timestamp**: When generated
- **Findings**: List of security findings with severity
- **Sections**: Additional data sections
- **Severity Counts**: Count by severity level

### Example Report Structure

```json
{
  "title": "Daily Security Audit Report",
  "timestamp": "2025-10-15T14:30:00",
  "severity_counts": {
    "critical": 1,
    "high": 3,
    "medium": 5,
    "low": 2,
    "info": 10
  },
  "findings": [
    {
      "severity": "critical",
      "category": "SYN Flood",
      "description": "Detected 5 potential SYN flood attacks",
      "details": "Affected targets: 5",
      "timestamp": "2025-10-15T14:30:01"
    }
  ]
}
```

## Next Steps

- [Daily Security Audit →](daily-audit.md)
- [IP Investigation →](ip-investigation.md)
- [Threat Hunting →](threat-hunting.md)
- [Custom Workflows →](custom-workflows.md)

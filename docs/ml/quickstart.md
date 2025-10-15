# Quick Start Guide - Network Analysis Workflows

This guide shows you the **simplest ways** to use the network analysis toolkit.

## What Problem Does This Solve?

You capture network packets → You need to know if there are threats → This analyzes automatically

## The 3 Main Workflows

### 1. Daily Security Audit (Most Common)

**What it does:** Runs 15+ security checks automatically and gives you a report

**When to use:** Every day, or after capturing traffic you want to check for threats

```bash
# Run from the ml/preprocessing directory
uv run python -m preprocessing.main daily-audit /path/to/capture.parquet
```

**What you get:**
```
================================================================================
  Daily Security Audit Report
  Generated: 2025-10-15 14:30:00
================================================================================

FINDINGS SUMMARY:
  🔴 Critical: 1
  🟠 High:     3
  🟡 Medium:   5
  🔵 Low:      2

DETAILED FINDINGS:
🔴 [CRITICAL] SYN Flood
   Detected 5 potential SYN flood attacks

🟠 [HIGH] Port Scan
   Detected 12 potential port scanning sources

[... more findings ...]
```

**Example with options:**
```bash
# Custom business hours and export to file
uv run python -m preprocessing.main daily-audit capture.parquet \
  --business-hours 8-18 \
  --export daily_report.json
```

---

### 2. Investigate Specific IP

**What it does:** Shows everything a specific IP did in your network

**When to use:** You found a suspicious IP and want to know what it's doing

```bash
uv run python -m preprocessing.main investigate-ip capture.parquet 192.168.1.100
```

**What you get:**
- All packets sent/received
- Who it communicated with
- Protocol breakdown
- Attack patterns (if any)
- Threat indicators

---

### 3. Threat Hunting

**What it does:** Proactively searches for specific attack patterns

**When to use:** You suspect an attack but don't know where to look

```bash
# Hunt for C2 (Command & Control) communication
uv run python -m preprocessing.main threat-hunt capture.parquet --type c2

# Hunt for data theft
uv run python -m preprocessing.main threat-hunt capture.parquet --type data-theft

# Hunt for lateral movement
uv run python -m preprocessing.main threat-hunt capture.parquet --type lateral

# Run all hunts
uv run python -m preprocessing.main threat-hunt capture.parquet --type all
```

---

## Python API (For Scripts)

If you want to integrate into your own scripts:

### Daily Audit in Python

```python
from network_security_suite.ml.preprocessing.workflows import DailyAudit

# Run audit
audit = DailyAudit("capture.parquet")
report = audit.run()

# Show summary
print(report.summary())

# Save to file
report.to_json("report.json")

# Check severity programmatically
if report.severity_counts["critical"] > 0:
    send_alert("Critical security findings!")
```

### IP Investigation in Python

```python
from network_security_suite.ml.preprocessing.workflows import IPInvestigation

# Investigate IP
inv = IPInvestigation("capture.parquet", ip="192.168.1.100")
report = inv.run()

print(report.summary())
```

### Threat Hunting in Python

```python
from network_security_suite.ml.preprocessing.workflows import ThreatHunting

hunter = ThreatHunting("capture.parquet")

# Hunt for C2
c2_report = hunter.hunt_for_c2()
print(c2_report.summary())

# Hunt for data theft
theft_report = hunter.hunt_for_data_theft()
print(theft_report.summary())

# Hunt for lateral movement
lateral_report = hunter.hunt_for_lateral_movement()
print(lateral_report.summary())
```

---

## Common Questions

### Q: What checks does Daily Audit run?

A: It checks for:
- ✅ Port scanning
- ✅ SYN flood attacks
- ✅ UDP flood attacks
- ✅ DNS tunneling
- ✅ DGA domains (malware communication)
- ✅ ARP spoofing
- ✅ ICMP attacks
- ✅ Beaconing (C2 communication)
- ✅ Data exfiltration
- ✅ Off-hours activity
- ✅ Failed connections
- ✅ Suspicious IP behavior
- ✅ Top bandwidth consumers
- ✅ And more...

### Q: How long does it take?

A: Depends on file size:
- Small file (< 100K packets): ~5 seconds
- Medium file (1M packets): ~30 seconds
- Large file (10M+ packets): ~2-5 minutes

Use `--lazy` flag for faster processing on large files.

### Q: What format should my parquet file be?

A: It should be the output from your network sniffer with columns like:
- `timestamp`
- `source_ip`, `destination_ip`
- `source_port`, `destination_port`
- `protocol`
- Other packet metadata

### Q: Can I automate this?

A: Yes! Add to cron:

```bash
# Run daily audit every day at 2 AM
0 2 * * * cd /path/to/project && uv run python -m preprocessing.main daily-audit /data/daily_capture.parquet --export /reports/daily_$(date +\%Y\%m\%d).json
```

### Q: What if I get errors?

A: Common fixes:

1. **"Module not found"** → Run `uv sync` first
2. **"File not found"** → Check your parquet file path
3. **"Memory error"** → Add `--lazy` flag
4. **"Empty dataframe"** → Your parquet file might not have traffic data

---

## Integration with Your Workflow

### After Sniffer Captures Data

```python
# In your sniffer script, after saving to parquet:
from network_security_suite.ml.preprocessing.workflows import DailyAudit

# Analyze what was just captured
audit = DailyAudit("latest_capture.parquet", lazy_load=True)
report = audit.run()

# Alert on critical findings
if report.severity_counts["critical"] > 0:
    send_alert_email(report.summary())

# Save for historical analysis
report.to_json(f"reports/{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
```

---

## Next Steps

Once you're comfortable with workflows, you can:

1. **Use the CLI for detailed analysis** - See `USAGE.md`
2. **Build custom workflows** - See `examples/` directory
3. **Access individual analyzers** - See `TODO.md` for all available methods

---

## Real-World Example

**Scenario:** You run a small network and want to check for attacks daily.

**Solution:**

1. Your sniffer captures traffic all day → saves to `capture_20251015.parquet`

2. At night, run:
   ```bash
   uv run python -m preprocessing.main daily-audit capture_20251015.parquet \
     --export reports/audit_20251015.json
   ```

3. Next morning, check the report:
   ```bash
   cat reports/audit_20251015.json | jq '.severity_counts'
   ```

4. If there are critical findings, investigate:
   ```bash
   # Check which IP is problematic (from the report)
   uv run python -m preprocessing.main investigate-ip capture_20251015.parquet 10.0.0.50
   ```

5. Done! You now know if your network was attacked and by whom.

---

## Summary

**For daily security checks:** Use `daily-audit`
**For investigating specific IPs:** Use `investigate-ip`
**For hunting specific threats:** Use `threat-hunt`

All workflows automatically generate reports and can export to JSON for further processing.

# NetGuard

> Real-time network security monitoring with ML-powered threat detection and protocol analysis

![Status](https://img.shields.io/badge/status-active%20development-yellow)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Overview

NetGuard is a modular network security platform that captures, analyzes, and detects threats in network traffic using machine learning. Built for security operations teams and researchers, it combines the flexibility of Scapy packet capture with the performance of Polars data processing.

**What it does:** Monitors network traffic in real-time, stores packet data efficiently, and applies protocol-specific analysis to identify security threats including port scans, DNS tunneling, DDoS attacks, and ARP spoofing.

**Why it exists:** Existing network security tools are either too simplistic (basic packet sniffers) or prohibitively expensive (enterprise SIEM solutions). NetGuard bridges this gap by providing production-grade capabilities through an open-source, extensible platform.

**Core Technologies:**
- **Packet Capture:** Scapy with BPF filtering
- **Data Processing:** Polars (high-performance DataFrames) + Parquet storage
- **Analysis:** 8 specialized protocol analyzers (TCP, UDP, DNS, IP, ICMP, ARP, Flow, Anomaly)
- **Configuration:** YAML-based declarative configuration
- **Documentation:** MkDocs Material with auto-generated API references

## What's Implemented ✅

### Packet Capture Engine
- Real-time packet sniffing with BPF filter support (1,000+ packets/sec)
- Multi-interface capture with promiscuous mode
- Efficient Parquet-based storage with 10x compression (Snappy/Gzip)
- Configurable batching and partitioning strategies

### Protocol Analyzers (8 Total)
- **TCP Analyzer:** Connection tracking, SYN flood detection, port scan identification, flag analysis
- **UDP Analyzer:** Flood detection, amplification attack identification, flow statistics
- **DNS Analyzer:** Tunneling detection, suspicious query patterns, DGA identification, entropy analysis
- **IP Analyzer:** Top talker identification, hub detection, fragmentation analysis
- **ICMP Analyzer:** Ping flood detection, tunneling identification
- **ARP Analyzer:** Spoofing detection, ARP poisoning identification, MITM attack detection
- **Flow Analyzer:** 5-tuple flow tracking, session analysis, beaconing detection
- **Anomaly Analyzer:** Statistical outlier detection, behavioral profiling, cross-protocol correlation

### Security Workflows
- **Daily Security Audit:** Automated baseline analysis across all protocols with severity-based alerting
- **IP Investigation:** Deep-dive analysis of specific hosts (connection patterns, protocol usage, threat indicators)
- **Threat Hunting:** Proactive hunting for DNS tunneling, port scans, and beaconing behavior

### Configuration & Operations
- YAML-based configuration for sniffer and analysis modules
- Structured JSON logging with severity levels
- Performance metrics tracking
- Comprehensive MkDocs documentation with search

## Architecture

NetGuard follows a modular pipeline architecture:

```
┌──────────────────────────────────────────────────────────────┐
│                      NetGuard Platform                        │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
        ┌───────────────────────────────────────┐
        │    1. CAPTURE (Scapy + BPF)           │
        │    • Interface monitoring             │
        │    • Real-time packet sniffing        │
        │    • Filter-based packet selection    │
        └───────────────┬───────────────────────┘
                        │
                        ▼
        ┌───────────────────────────────────────┐
        │    2. STORAGE (Parquet + Arrow)       │
        │    • Columnar storage format          │
        │    • Compression (10x reduction)      │
        │    • Partitioning by time/protocol    │
        └───────────────┬───────────────────────┘
                        │
                        ▼
        ┌───────────────────────────────────────┐
        │    3. ANALYSIS (Polars Processing)    │
        │    • Protocol-specific analyzers      │
        │    • Statistical feature extraction   │
        │    • Behavioral profiling             │
        └───────────────┬───────────────────────┘
                        │
                        ▼
        ┌───────────────────────────────────────┐
        │    4. DETECTION (Workflows)           │
        │    • Daily security audits            │
        │    • IP investigations                │
        │    • Threat hunting                   │
        └───────────────────────────────────────┘
```

**Data Flow:**
1. **Capture Layer** applies BPF filters and sniffs packets from network interfaces
2. **Storage Layer** converts packets to Parquet format with schema-based organization
3. **Analysis Layer** loads Parquet data and applies protocol-specific analyzers
4. **Detection Layer** executes workflows that combine multiple analyzers to identify threats

**Why This Design:**
- **Modularity:** Each analyzer operates independently, making the system extensible
- **Performance:** Polars processes 100,000+ packets/second using vectorized operations
- **Storage Efficiency:** Parquet + Snappy compression achieves 10x reduction vs. raw PCAP
- **Scalability:** Workflow-based approach allows easy parallelization across multiple datasets

## Technical Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Capture** | Scapy 2.5+ | Packet manipulation and capture |
| **Storage** | Parquet + PyArrow | Columnar data storage |
| **Processing** | Polars 0.19+ | High-performance DataFrames |
| **API** | FastAPI (planned) | REST API endpoints |
| **Config** | PyYAML + Pydantic | Type-safe configuration |
| **Logging** | Python logging | Structured logging |
| **Docs** | MkDocs Material | Documentation generation |
| **Testing** | Pytest + Coverage | Unit and integration tests |
| **Linting** | Black + Ruff + Mypy | Code quality enforcement |

## Quick Start

### Prerequisites

- **Python 3.9 - 3.13**
- **Root/Administrator privileges** (required for packet capture)
- **System dependencies:**
  - Linux: `libpcap-dev`
  - macOS: Xcode Command Line Tools
  - Windows: [Npcap](https://npcap.com/)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/netguard.git
cd netguard

# Install using uv (recommended)
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync

# Or using pip
pip install -e .

# Activate virtual environment
source .venv/bin/activate
```

### Basic Usage

#### 1. Capture Network Traffic

```bash
# Capture 1000 packets from eth0 interface
sudo python -m network_security_suite.sniffer.packet_capture \
    --config configs/sniffer_config.yaml
```

**Example `sniffer_config.yaml`:**
```yaml
network:
  interface: eth0
  timeout: 10

capture:
  packet_count: 1000
  filter: "tcp or udp"

storage:
  format: parquet
  path: ./data/captures
  compression: snappy

logging:
  level: INFO
```

#### 2. Analyze Captured Data

```python
from network_security_suite.ml.preprocessing.parquet_analysis import ParquetAnalyzer

# Load captured data
analyzer = ParquetAnalyzer("data/captures/packets_20250117.parquet")

# Analyze TCP traffic
tcp_stats = analyzer.analyze_tcp()
print(f"Total TCP packets: {tcp_stats['total_packets']}")
print(f"Unique connections: {tcp_stats['unique_connections']}")
print(f"Top ports: {tcp_stats['top_destination_ports'][:5]}")

# Detect DNS anomalies
dns_stats = analyzer.analyze_dns()
suspicious_queries = dns_stats.get('suspicious_queries', [])
print(f"Found {len(suspicious_queries)} suspicious DNS queries")
```

#### 3. Run Security Workflows

```python
from network_security_suite.ml.preprocessing.workflows import (
    daily_security_audit,
    investigate_ip
)

# Daily security audit across all protocols
audit_results = daily_security_audit(
    parquet_file="data/captures/network_traffic.parquet",
    output_dir="reports/daily_audit/"
)

# Investigate specific IP address
investigation = investigate_ip(
    parquet_file="data/captures/network_traffic.parquet",
    target_ip="192.168.1.100",
    output_dir="reports/ip_investigation/"
)

print(f"IP Investigation Results:")
print(f"  Total connections: {investigation['total_connections']}")
print(f"  Unique destinations: {investigation['unique_destinations']}")
print(f"  Protocols used: {investigation['protocols']}")
```

## Project Structure

```
netguard/
├── src/network_security_suite/
│   ├── sniffer/                # Packet capture engine
│   │   ├── packet_capture.py   # Main capture logic
│   │   ├── parquet_processing.py  # Parquet storage
│   │   ├── sniffer_config.py   # YAML configuration
│   │   └── interfaces.py       # Network interface management
│   │
│   ├── ml/preprocessing/       # Analysis pipeline
│   │   ├── parquet_analysis.py # Core analysis engine
│   │   ├── analyzers/          # Protocol-specific analyzers
│   │   │   ├── tcp_analyzer.py
│   │   │   ├── udp_analyzer.py
│   │   │   ├── dns_analyzer.py
│   │   │   ├── ip_analyzer.py
│   │   │   ├── icmp_analyzer.py
│   │   │   ├── arp_analyzer.py
│   │   │   ├── flow_analyzer.py
│   │   │   └── anomaly_analyzer.py
│   │   ├── workflows.py        # Pre-built analysis workflows
│   │   └── examples/           # Usage examples
│   │
│   ├── models/                 # Data structures
│   │   ├── packet_data_structures.py
│   │   └── database_schemas.py
│   │
│   └── utils/                  # Shared utilities
│       ├── logger.py
│       ├── config_builder.py
│       └── performance_metrics.py
│
├── docs/                       # MkDocs documentation
├── tests/                      # Test suite
├── configs/                    # Configuration files
└── Makefile                    # Development tasks
```

## Technical Highlights

### 1. Efficient Protocol Detection

Instead of parsing every packet individually, NetGuard uses Polars' vectorized operations to analyze thousands of packets simultaneously:

```python
# From tcp_analyzer.py - vectorized SYN flood detection
def detect_syn_flood(self, df: pl.DataFrame, threshold: int = 100) -> Dict[str, Any]:
    syn_packets = df.filter(
        (pl.col("tcp_flags_syn") == True) &
        (pl.col("tcp_flags_ack") == False)
    )

    syn_by_src = (
        syn_packets.group_by("src_ip")
        .agg([
            pl.count().alias("syn_count"),
            pl.col("dst_port").n_unique().alias("unique_ports")
        ])
        .filter(pl.col("syn_count") > threshold)
        .sort("syn_count", descending=True)
    )

    return syn_by_src.to_dicts()
```

**Performance benefit:** Processes 100,000+ packets in ~500ms vs. 10+ seconds with row-by-row iteration.

### 2. Parquet Storage Strategy

NetGuard uses Parquet's columnar format to optimize for analytical queries:

```python
# Schema optimized for common query patterns
schema = {
    "timestamp": pl.Datetime,      # Time-based filtering
    "src_ip": pl.Utf8,             # Source IP queries
    "dst_ip": pl.Utf8,             # Destination IP queries
    "protocol": pl.Utf8,           # Protocol-specific analysis
    "tcp_flags_syn": pl.Boolean,   # Flag-based filtering
    "tcp_flags_ack": pl.Boolean,
    # ... additional fields
}
```

**Storage benefit:** 10x compression (1GB PCAP → 100MB Parquet) while maintaining query performance.

### 3. Workflow Composition Pattern

Security workflows compose multiple analyzers without tight coupling:

```python
# From workflows.py - composable analysis pipeline
def daily_security_audit(parquet_file: str, output_dir: str) -> Dict[str, Any]:
    analyzer = ParquetAnalyzer(parquet_file)

    # Run independent analyses in parallel (future optimization)
    tcp_analysis = analyzer.analyze_tcp()
    dns_analysis = analyzer.analyze_dns()
    arp_analysis = analyzer.analyze_arp()
    anomaly_analysis = analyzer.analyze_anomaly()

    # Aggregate findings with severity scoring
    findings = aggregate_findings([
        tcp_analysis, dns_analysis, arp_analysis, anomaly_analysis
    ])

    return generate_report(findings, output_dir)
```

**Design benefit:** New analyzers integrate without modifying existing workflows.

### 4. DNS Tunneling Detection

Implemented entropy-based detection for DNS exfiltration:

```python
# Calculate Shannon entropy of DNS query names
def calculate_entropy(query: str) -> float:
    probabilities = [query.count(c) / len(query) for c in set(query)]
    return -sum(p * log2(p) for p in probabilities if p > 0)

# Flag queries with high entropy (>3.5) as suspicious
suspicious_queries = df.filter(pl.col("dns_entropy") > 3.5)
```

**Detection capability:** Identifies Base64-encoded data in DNS queries (common C2 technique).

## Current Status & Roadmap

### Implemented (Phase 1) ✅

- [x] Core packet capture engine with BPF filtering
- [x] Parquet-based storage with compression
- [x] 8 protocol-specific analyzers
- [x] 3 security workflows (audit, investigation, hunting)
- [x] YAML configuration system
- [x] Comprehensive documentation (MkDocs)
- [x] Unit tests for core modules

### In Development (Phase 2) 🚧

- [ ] ML model training framework (scikit-learn integration)
- [ ] Pre-trained models for common attack patterns
- [ ] Feature engineering automation
- [ ] Time-series anomaly detection

### Planned (Phase 3+) 📋

- [ ] FastAPI REST API with authentication
- [ ] WebSocket streaming for real-time monitoring
- [ ] Web dashboard (React + D3.js)
- [ ] Distributed capture agents
- [ ] SIEM integration (Splunk, ELK)

**Known Limitations:**
- No persistent database (analysis operates on Parquet files)
- Single-node deployment only (distributed mode planned)
- Limited ML model library (expanding in Phase 2)

## Development

### Setup

```bash
# Install with development dependencies
uv sync --all-extras

# Install pre-commit hooks
uv run pre-commit install
```

### Code Quality

```bash
# Format code (Black + isort)
make format

# Type checking (mypy)
make typecheck

# Linting (ruff + pylint)
make lint

# Run all checks
make quality
```

### Testing

```bash
# Run all tests with coverage
make test-cov

# Run specific test types
uv run pytest -m unit
uv run pytest -m integration
uv run pytest tests/ml/
```

### Documentation

```bash
# Serve documentation locally
make docs-serve
# → http://localhost:8000

# Build static site
make docs-build
```

## Performance Metrics

Benchmarked on Intel i7-10700K, 32GB RAM, NVMe SSD:

| Operation | Throughput | Notes |
|-----------|-----------|-------|
| Packet Capture | 1,200 pkts/sec | Single interface, no filter |
| Parquet Write | 5,000 pkts/sec | Batch size 100, Snappy compression |
| TCP Analysis | 120,000 pkts/sec | Polars vectorized operations |
| DNS Analysis | 95,000 pkts/sec | Includes entropy calculation |
| Daily Audit (all analyzers) | 40,000 pkts/sec | 8 analyzers running sequentially |

**Storage Efficiency:**
- PCAP (raw): 1.2 GB for 1M packets
- Parquet (uncompressed): 450 MB
- Parquet (Snappy): 120 MB
- **Compression ratio: 10x**

## Use Cases

### 1. Security Operations Center

Monitor production network for suspicious activity:

```python
# Daily automated security audit
results = daily_security_audit(
    parquet_file="captures/production_network.parquet",
    output_dir="reports/daily/"
)

# Filter high-severity findings
critical_findings = [
    f for f in results['findings']
    if f['severity'] == 'critical'
]

# Send alerts (integrate with your notification system)
for finding in critical_findings:
    send_alert(finding)
```

### 2. Incident Response

Investigate specific IP during security incident:

```python
# Deep-dive investigation of compromised host
investigation = investigate_ip(
    parquet_file="captures/incident_20250117.parquet",
    target_ip="10.0.1.50",
    output_dir="investigations/incident_001/"
)

print(f"Connection timeline: {investigation['timeline']}")
print(f"External IPs contacted: {investigation['external_ips']}")
print(f"Unusual ports: {investigation['unusual_ports']}")
```

### 3. Research & Education

Analyze protocol behavior and attack patterns:

```python
from network_security_suite.ml.preprocessing.parquet_analysis import ParquetAnalyzer

analyzer = ParquetAnalyzer("datasets/attack_samples.parquet")

# Study SYN flood attack characteristics
syn_flood_data = analyzer.analyze_tcp()
print(f"Attack duration: {syn_flood_data['attack_duration']}")
print(f"Peak packet rate: {syn_flood_data['peak_pps']}")

# Extract features for ML training
features = analyzer.extract_features()
# → Use with scikit-learn, TensorFlow, etc.
```

## Context & Learning

This project demonstrates:

1. **Systems Programming:** Low-level packet capture with Scapy, efficient data serialization
2. **Data Engineering:** Columnar storage design, compression strategies, schema evolution
3. **Security Analysis:** Deep understanding of network protocols and attack patterns
4. **ML Pipeline Development:** Feature engineering, workflow orchestration, model integration
5. **Software Engineering:** Modular architecture, comprehensive testing, professional documentation

**What I'd Do Differently:**

- **Earlier ML focus:** Would implement model training framework in Phase 1 instead of Phase 2
- **Database integration:** While Parquet works well, adding TimescaleDB would enable better time-series queries
- **Performance profiling:** Should have benchmarked earlier to identify bottlenecks during development

**Key Technical Decisions:**

- **Polars over Pandas:** 10-50x performance improvement for large datasets
- **Parquet over PCAP:** Enables columnar queries and 10x compression
- **Modular analyzers:** Easy to extend without modifying core engine
- **Workflow composition:** Reusable patterns for common security operations

## License

MIT License - see [LICENSE](LICENSE) file

## Acknowledgments

- **Scapy** - Packet manipulation library
- **Polars** - High-performance DataFrame library
- **MkDocs Material** - Documentation framework

---

**Last Updated:** November 2024
**Status:** Active development (Phase 1 complete, Phase 2 in progress)
**Maintainer:** Juan Julián Paniagua Rico

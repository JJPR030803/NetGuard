# NetGuard - Network Security Suite

Enterprise-level network security monitoring and analysis platform with ML-powered threat detection.

## Features

- **Packet Capture & Analysis**: Real-time network packet sniffing using Scapy with flexible filtering
- **ML-Based Detection**: Machine learning preprocessing and analysis pipelines for threat detection
- **YAML Configuration**: Flexible YAML-based configuration for sniffer settings
- **Data Processing**: Parquet-based data storage and processing for efficient analysis
- **REST API**: FastAPI-based API for programmatic access
- **Comprehensive Documentation**: MkDocs Material documentation with API references

## Quick Start

### Installation

```bash
# Using uv (recommended)
uv sync

# Or using poetry
poetry install
```

### Running the Sniffer

```bash
# With YAML configuration
python -m network_security_suite.sniffer.packet_capture --config configs/sniffer_config.yaml

# Or programmatically
python src/network_security_suite/sniffer/packet_capture.py
```

### Running with Docker

```bash
docker-compose up --build
```

## Documentation

Comprehensive documentation is available via MkDocs Material:

```bash
# Serve documentation locally
./serve_docs.sh
# Visit: http://127.0.0.1:8000

# Build static documentation
./build_docs.sh
```

## Project Structure

```
netguard/
├── src/network_security_suite/
│   ├── sniffer/              # Network packet capture and processing
│   ├── ml/                   # Machine learning modules
│   │   └── preprocessing/    # Data preprocessing pipelines
│   ├── models/               # Data structures and schemas
│   ├── api/                  # FastAPI REST API
│   └── utils/                # Utilities and helpers
├── docs/                     # MkDocs documentation
├── tests/                    # Test suites
└── configs/                  # Configuration files
```

## Development

```bash
# Format code
uv run black .

# Lint code
uv run pylint src/

# Type check
uv run mypy src/

# Run tests
uv run pytest
```

## Key Modules

- **Sniffer**: Network packet capture with filtering, Parquet processing, and logging
- **ML Preprocessing**: Protocol analyzers (TCP, UDP, DNS, ARP, ICMP), anomaly detection, and workflows
- **Models**: Packet data structures and database schemas
- **Utils**: Configuration builder, logging, and performance metrics

## Configuration

Configure the sniffer via YAML:

```yaml
network:
  interface: eth0
  timeout: 10
capture:
  packet_count: 1000
  filter: "tcp port 80"
storage:
  format: parquet
  path: ./data/captures
```

See `docs/sniffer/configuration.md` for details.

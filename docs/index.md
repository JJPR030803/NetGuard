# Network Security Suite Documentation

Welcome to the comprehensive documentation for the Network Security Suite - an enterprise-level network security monitoring and analysis platform with machine learning capabilities.

## Overview

The Network Security Suite is a complete security monitoring solution that combines real-time packet capture, advanced analysis, and machine learning-based threat detection. This documentation provides detailed information about all components of the suite.

## Key Features

- **Real-time Network Monitoring**: Capture and analyze network traffic in real-time using advanced packet sniffing capabilities
- **Machine Learning Analysis**: Leverage ML models for anomaly detection and threat identification
- **Flexible Architecture**: Modular design allowing easy extension and customization
- **Performance Optimized**: Efficient packet processing with Parquet-based storage
- **Comprehensive Logging**: Detailed logging system for debugging and auditing
- **REST API**: FastAPI-based API for integration with other tools

## Components

The suite consists of several main modules:

### [Sniffer Module](sniffer/index.md)
Network packet capture and processing engine. Handles real-time packet sniffing, filtering, and storage.

**Key Features:**
- Multi-interface support
- Customizable packet filtering
- Parquet-based storage for efficient analysis
- Real-time packet processing

### [ML Module](ml/index.md)
Machine learning and network traffic analysis components for advanced threat detection.

**Key Features:**
- Protocol-specific analyzers (TCP, UDP, DNS, etc.)
- Anomaly detection
- IP reputation analysis
- Flow analysis

### [Models Module](models/index.md)
Data structures and database schemas for packet and network data representation.

**Key Features:**
- Pydantic-based data models
- Type-safe data structures
- Database schema definitions

### [Utils Module](utils/index.md)
Shared utilities and helper functions used across the suite.

**Key Features:**
- Advanced logging system
- Performance metrics tracking
- Configuration management

### [API Module](api/index.md)
REST API for interacting with the network security suite.

**Key Features:**
- FastAPI-based endpoints
- OpenAPI documentation
- Authentication and authorization

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/netguard
cd netguard

# Install dependencies with uv
uv sync

# Or with poetry
poetry install
```

### Basic Usage

```python
from network_security_suite.sniffer import PacketCapture
from network_security_suite.ml.preprocessing import NetworkParquetAnalysis

# Start packet capture
capture = PacketCapture(interface="eth0")
capture.start()

# Analyze captured data
analyzer = NetworkParquetAnalysis("captured_data.parquet")
results = analyzer.tcp.analyze_connection_patterns()
```

## Development

### Setting Up Development Environment

```bash
# Install development dependencies
uv sync --dev

# Run tests
uv run pytest

# Format code
uv run ruff format

# Lint code
uv run ruff check
```

### Contributing

Contributions are welcome! Please see the [Development Guide](ml/development/contributing.md) for more information.

## Documentation Structure

- **User Guides**: Step-by-step instructions for common tasks
- **API Reference**: Detailed API documentation for all modules
- **Examples**: Practical examples and use cases
- **Development**: Information for contributors and developers

## Support

For questions, issues, or contributions:

- GitHub Issues: [Report a bug or request a feature](https://github.com/yourusername/netguard/issues)
- Discussions: [Join the community](https://github.com/yourusername/netguard/discussions)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Note**: This is a thesis project focused on network security monitoring and analysis. Use responsibly and only on networks you have permission to monitor.

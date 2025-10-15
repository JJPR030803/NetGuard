#TODO update readme
# Network Security Suite

Enterprise-level network security sniffer with ML capabilities.

## Features

- Real-time network packet analysis using Scapy
- Machine Learning-based threat detection
- FastAPI REST API
- React-based dashboard
- Docker containerization
- Comprehensive testing suite

## Quick Start

1. Install dependencies:
   ```bash
   poetry install
   ```

2. Run development server:
   ```bash
   poetry run uvicorn src.network_security_suite.main:app --reload
   ```

3. Run with Docker:
   ```bash
   docker-compose up --build
   ```

## Development

- Format code: `poetry run black .`
- Lint code: `poetry run pylint src/`
- Type check: `poetry run mypy src/`
- Run tests: `poetry run pytest`

## Project Structure

```
network-security-suite/
├── src/network_security_suite/  # Main application
├── tests/                       # Test suites
├── frontend/                    # React dashboard
├── docs/                        # Documentation
├── docker/                      # Docker configurations
└── scripts/                     # Utility scripts
```

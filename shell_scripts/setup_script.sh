#!/bin/bash
# Project Structure Setup Script

# Create main project structure
mkdir -p {src/network_security_suite,tests/{unit,integration,e2e},docs,scripts,docker,frontend,ml-models,configs}

# Create source code structure
mkdir -p src/network_security_suite/{api,core,ml,models,utils,sniffer}

# Create configuration files
touch src/network_security_suite/__init__.py
touch src/network_security_suite/main.py
touch src/network_security_suite/config.py

# Create API structure
mkdir -p src/network_security_suite/api/{endpoints,dependencies,middleware}
touch src/network_security_suite/api/__init__.py
touch src/network_security_suite/api/main.py

# Create core modules
touch src/network_security_suite/core/__init__.py
touch src/network_security_suite/sniffer/__init__.py
touch src/network_security_suite/sniffer/packet_capture.py
touch src/network_security_suite/ml/__init__.py
touch src/network_security_suite/models/__init__.py
touch src/network_security_suite/utils/__init__.py

# Create test structure
touch tests/__init__.py
touch tests/conftest.py
touch tests/unit/__init__.py
touch tests/integration/__init__.py
touch tests/e2e/__init__.py

# Create configuration files in root
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# Virtual environments
.env
.venv
env/
venv/
ENV/
env.bak/
venv.bak/

# IDEs
.vscode/
.idea/
*.swp
*.swo
*~

# Testing
.coverage
.pytest_cache/
htmlcov/
.tox/
.nox/

# MyPy
.mypy_cache/
.dmypy.json
dmypy.json

# Jupyter Notebook
.ipynb_checkpoints

# Docker
.dockerignore

# Logs
*.log
logs/

# Database
*.db
*.sqlite3

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Project specific
captured_packets/
ml_models_cache/
config/local.env
EOF

# Create docker-compose for development
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  app:
    build:
      context: .
      target: development
    ports:
      - "8000:8000"
    volumes:
      - .:/app
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - ENVIRONMENT=development
      - PYTHONPATH=/app/src
    depends_on:
      - redis
      - postgres
    networks:
      - app-network

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: network_security
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - app-network

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    networks:
      - app-network

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./configs/prometheus.yml:/etc/prometheus/prometheus.yml
    networks:
      - app-network

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    networks:
      - app-network

volumes:
  postgres_data:

networks:
  app-network:
    driver: bridge
EOF

# Create basic README
cat > README.md << 'EOF'
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
EOF

echo "Project structure created successfully!"
echo ""
echo "Next steps:"
echo "1. cd your-project-directory"
echo "2. poetry install"
echo "3. poetry run pre-commit install"
echo "4. Start coding!"
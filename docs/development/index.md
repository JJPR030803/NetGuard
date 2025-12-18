# Development Documentation

Welcome to the NetGuard developer documentation. This section contains information for developers working on or contributing to the NetGuard project.

## Quick Links

- [Project Review](project-review.md) - Comprehensive project assessment
- [Architecture Overview](architecture.md) - System design and patterns
- [Development Setup](setup.md) - Getting started with development
- [Contributing Guide](contributing.md) - How to contribute
- [Testing Guide](testing.md) - Testing practices and guidelines
- [Release Process](releases.md) - How releases are managed

## Development Resources

### Code Quality

NetGuard maintains high code quality standards through:

- **Black & isort**: Automatic code formatting
- **Ruff**: Fast linting with auto-fix
- **Pylint**: Comprehensive code analysis
- **MyPy**: Static type checking (strict mode)
- **Pre-commit hooks**: Automated quality checks

### Project Metrics

- **Lines of Code**: ~12,292 Python LOC
- **Modules**: 40+ Python modules
- **Test Files**: 9 test modules
- **Documentation Pages**: 32+ pages
- **Supported Python**: 3.9 - 3.13

### Key Technologies

- **Scapy**: Network packet capture
- **Polars**: High-performance data processing
- **FastAPI**: Modern API framework
- **Pydantic**: Data validation
- **MkDocs Material**: Documentation

## Development Workflow

```bash
# Setup
make install          # Install dependencies with uv

# Development
make format           # Format code
make lint             # Run linters
make type-check       # Type checking
make check            # All quality checks

# Testing
make test             # Run tests with coverage
make test-quick       # Quick test run

# Documentation
make docs-serve       # Serve docs locally
make docs-build       # Build static docs
```

## Project Structure

```
netguard/
├── src/network_security_suite/
│   ├── sniffer/              # Packet capture & processing
│   ├── ml/                   # ML preprocessing
│   │   └── preprocessing/    # Protocol analyzers
│   ├── models/               # Data structures
│   ├── api/                  # REST API
│   └── utils/                # Shared utilities
├── tests/                    # Test suites
├── docs/                     # MkDocs documentation
├── configs/                  # Configuration files
└── Makefile                  # Development commands
```

## Getting Help

- **Documentation**: Check the relevant module docs
- **Code Review**: See the [Project Review](project-review.md)
- **Issues**: Check GitHub issues for known problems
- **Architecture**: Review [Architecture Overview](architecture.md)

## Contributing

We welcome contributions! Please read the [Contributing Guide](contributing.md) before submitting pull requests.

### Contribution Areas

- 🧪 **Testing**: Expand test coverage
- 🔌 **API**: Implement REST endpoints
- 🤖 **ML Models**: Integrate ML models
- 📊 **Analyzers**: Enhance protocol analyzers
- 📖 **Documentation**: Improve docs
- 🐛 **Bug Fixes**: Fix issues

## Development Standards

### Code Style

- **Line Length**: 88 (Black) / 130 (Pylint/Ruff)
- **Imports**: isort with Black profile
- **Type Hints**: Required for all functions
- **Docstrings**: Google style

### Git Workflow

1. Create feature branch from `main`
2. Write code with tests
3. Run `make check` and `make test`
4. Commit with descriptive messages
5. Push and create pull request
6. Address review feedback

### Commit Messages

```
feat: Add new TCP connection tracking
fix: Resolve memory leak in packet capture
docs: Update sniffer configuration guide
test: Add tests for UDP analyzer
refactor: Simplify workflow report generation
```

## Next Steps

- Read the [Project Review](project-review.md) for a comprehensive overview
- Check [Development Setup](setup.md) for environment configuration
- Review [Architecture Overview](architecture.md) to understand the design
- See [Contributing Guide](contributing.md) to start contributing

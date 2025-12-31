# Contributing Guide

Thank you for your interest in contributing to NetGuard! This guide will help you get started.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally
3. **Set up development environment** (see [Development Setup](setup.md))
4. **Create a feature branch** for your changes
5. **Make your changes** with tests
6. **Submit a pull request**

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Follow project standards and conventions

## Types of Contributions

### 🐛 Bug Fixes

Found a bug? Great! Here's how to fix it:

1. Check if issue already exists
2. Create an issue if it doesn't
3. Reference the issue in your PR
4. Include test that reproduces the bug
5. Verify fix doesn't break existing tests

### ✨ New Features

Want to add a feature?

1. **Discuss first**: Open an issue to discuss the feature
2. **Get approval**: Wait for maintainer feedback
3. **Design**: Document your approach
4. **Implement**: Write code + tests
5. **Document**: Update relevant docs
6. **Submit PR**: Reference the discussion issue

### 📖 Documentation

Documentation improvements are always welcome:

- Fix typos and grammar
- Improve clarity and examples
- Add missing documentation
- Update outdated information

### 🧪 Tests

Expanding test coverage is highly valuable:

- Add unit tests for untested code
- Create integration tests
- Write property-based tests
- Add performance benchmarks

## Development Workflow

### 1. Fork and Clone

```bash
# Fork on GitHub, then:
git clone https://github.com/YOUR_USERNAME/netguard.git
cd netguard

# Add upstream remote
git remote add upstream https://github.com/ORIGINAL_OWNER/netguard.git
```

### 2. Create Branch

```bash
# Update main
git checkout main
git pull upstream main

# Create feature branch
git checkout -b feature/my-feature
```

Branch naming:
- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation
- `test/description` - Tests
- `refactor/description` - Refactoring

### 3. Make Changes

```bash
# Install dependencies
make install

# Make your changes
vim src/netguard/...

# Format code
make format

# Run linters
make lint

# Type check
make type-check
```

### 4. Write Tests

All code changes should include tests:

```python
# tests/unit/test_my_feature.py
import pytest
from netguard.module import MyFeature

def test_my_feature():
    """Test that my feature works correctly."""
    feature = MyFeature()
    result = feature.do_something()
    assert result == expected_value

def test_my_feature_edge_case():
    """Test edge case handling."""
    feature = MyFeature()
    with pytest.raises(ValueError):
        feature.do_something(invalid_input)
```

Run tests:
```bash
make test
```

### 5. Update Documentation

If your change affects user-facing behavior:

```bash
# Update relevant docs
vim docs/sniffer/configuration.md

# Test documentation build
make docs-build

# Preview locally
make docs-serve
```

### 6. Commit Changes

Follow conventional commit format:

```bash
git add .
git commit -m "type: Brief description

Optional longer description explaining the change,
why it was needed, and any important details.

Fixes #123
"
```

Commit types:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation
- `test:` - Tests
- `refactor:` - Code refactoring
- `perf:` - Performance improvement
- `style:` - Code style (formatting, etc.)
- `chore:` - Build process, dependencies

Examples:
```bash
git commit -m "feat: Add TCP connection tracking to analyzer"
git commit -m "fix: Resolve memory leak in packet capture"
git commit -m "docs: Update sniffer configuration examples"
git commit -m "test: Add tests for UDP analyzer"
```

### 7. Push and Create PR

```bash
# Push to your fork
git push origin feature/my-feature

# Create Pull Request on GitHub
```

## Pull Request Guidelines

### PR Title

Use conventional commit format:
```
feat: Add new TCP connection tracking
fix: Resolve memory leak in packet capture
docs: Update API documentation
test: Add integration tests for analyzers
```

### PR Description

Include:
1. **What** changed
2. **Why** it changed
3. **How** to test it
4. **Related issues** (Fixes #123)

Template:
```markdown
## Summary
Brief description of changes

## Motivation
Why is this change needed?

## Changes
- Change 1
- Change 2
- Change 3

## Testing
How to test these changes:
1. Step 1
2. Step 2
3. Expected result

## Checklist
- [ ] Tests pass locally
- [ ] Code is formatted (`make format`)
- [ ] Linting passes (`make lint`)
- [ ] Type checking passes (`make type-check`)
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] CHANGELOG updated (if applicable)

Fixes #issue_number
```

### PR Review Process

1. **Automated Checks**: CI runs tests, linting, type checking
2. **Code Review**: Maintainers review your code
3. **Feedback**: Address review comments
4. **Approval**: Once approved, PR is merged

### Addressing Review Comments

```bash
# Make changes based on feedback
vim src/netguard/...

# Commit changes
git add .
git commit -m "fix: Address review feedback"

# Push to update PR
git push origin feature/my-feature
```

## Code Standards

### Code Style

Follow PEP 8 with project modifications:

```python
# Good
def analyze_packet(packet: Packet, config: Config) -> dict[str, Any]:
    """
    Analyze a network packet.

    Args:
        packet: The packet to analyze
        config: Analysis configuration

    Returns:
        Analysis results as a dictionary
    """
    result = perform_analysis(packet, config)
    return result


# Bad
def analyzePacket(pkt,cfg):
    result=perform_analysis(pkt,cfg)
    return result
```

### Type Hints

Use type hints for all functions:

```python
from typing import Optional, Union
from pathlib import Path

def load_config(
    path: Union[str, Path],
    validate: bool = True
) -> Optional[Config]:
    """Load configuration from file."""
    ...
```

### Docstrings

Use Google style docstrings:

```python
def calculate_metrics(
    data: pl.DataFrame,
    window: int = 60
) -> dict[str, float]:
    """
    Calculate network metrics from packet data.

    Args:
        data: DataFrame containing packet information
        window: Time window in seconds for calculations

    Returns:
        Dictionary of metric names to values

    Raises:
        ValueError: If data is empty or window is invalid

    Example:
        ```python
        df = pl.read_parquet("capture.parquet")
        metrics = calculate_metrics(df, window=300)
        print(metrics["packets_per_second"])
        ```
    """
    ...
```

### Error Handling

Use specific exceptions:

```python
# Good
try:
    config = load_config(path)
except FileNotFoundError as e:
    logger.error(f"Config file not found: {e}")
    raise ConfigError(f"Cannot load config from {path}") from e

# Bad
try:
    config = load_config(path)
except Exception as e:
    print(f"Error: {e}")
```

### Logging

Use structured logging:

```python
from netguard.utils.logger import get_logger

logger = get_logger(__name__)

# Good
logger.info(
    "Packet captured",
    extra={
        "interface": "eth0",
        "packet_count": 1000,
        "duration_ms": 543.2
    }
)

# Bad
print(f"Captured 1000 packets on eth0 in 543.2ms")
```

## Testing Standards

### Test Structure

```python
# Arrange
setup_test_data()
config = create_test_config()

# Act
result = function_under_test(config)

# Assert
assert result.status == "success"
assert len(result.items) == 5
```

### Test Coverage

Aim for 80%+ coverage:

```bash
# Check coverage
make test

# View HTML report
open htmlcov/index.html
```

### Test Types

1. **Unit Tests**: Test individual functions/classes
2. **Integration Tests**: Test module interactions
3. **E2E Tests**: Test complete workflows

### Fixtures

Use pytest fixtures for reusable test data:

```python
# conftest.py
import pytest

@pytest.fixture
def sample_packet():
    """Create a sample packet for testing."""
    return Packet(
        timestamp=datetime.now(),
        src_ip="192.168.1.1",
        dst_ip="192.168.1.2",
        protocol="TCP"
    )

# test_analyzer.py
def test_tcp_analyzer(sample_packet):
    """Test TCP analyzer with sample packet."""
    analyzer = TCPAnalyzer()
    result = analyzer.analyze(sample_packet)
    assert result["protocol"] == "TCP"
```

## Documentation Standards

### Module Documentation

Every module should have:
- Overview of purpose
- Usage examples
- API reference (auto-generated)

### Inline Comments

```python
# Good: Explain why, not what
# Use exponential backoff to avoid overwhelming the server
for attempt in range(3):
    wait_time = 2 ** attempt
    sleep(wait_time)

# Bad: Explain what (obvious from code)
# Set x to 10
x = 10
```

### README Updates

Update README.md if:
- Adding new major feature
- Changing installation process
- Modifying configuration options
- Adding new commands

## Common Tasks

### Adding a New Analyzer

1. Create analyzer file:
```python
# src/netguard/ml/preprocessing/analyzers/my_analyzer.py
import polars as pl
from .base import BaseAnalyzer

class MyAnalyzer(BaseAnalyzer):
    """Analyze specific protocol behavior."""

    def analyze(self, df: pl.DataFrame) -> dict:
        """Perform analysis."""
        ...
```

2. Add tests:
```python
# tests/unit/test_my_analyzer.py
def test_my_analyzer():
    ...
```

3. Update documentation:
```markdown
<!-- docs/ml/analyzers/my-analyzer.md -->
# My Analyzer
...
```

4. Add to workflow if needed

### Adding Configuration Option

1. Update schema:
```python
# src/netguard/sniffer/sniffer_config.py
class SnifferConfig(BaseModel):
    new_option: str = "default"
```

2. Update YAML:
```yaml
# configs/sniffer_config.yaml
sniffer:
  new_option: value
```

3. Document:
```markdown
<!-- docs/sniffer/configuration.md -->
### new_option
Description of option...
```

## Release Process

(For maintainers)

1. Update version in `pyproject.toml`
2. Update CHANGELOG.md
3. Create release tag
4. Build and publish to PyPI
5. Create GitHub release

## Getting Help

- 💬 **Discussions**: Ask questions
- 🐛 **Issues**: Report bugs
- 📖 **Docs**: Read documentation
- 👥 **Code Review**: Request feedback

## Thank You!

Your contributions make NetGuard better for everyone. We appreciate your time and effort!

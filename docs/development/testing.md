# Testing Guide

Comprehensive guide to testing in NetGuard.

## Test Philosophy

- **Tests are documentation**: They show how code should be used
- **Fast feedback**: Tests should run quickly
- **Reliable**: No flaky tests
- **Comprehensive**: Cover edge cases and errors
- **Maintainable**: Easy to understand and modify

## Test Structure

```
tests/
├── unit/                   # Unit tests (fast, isolated)
│   ├── test_packet_capture.py
│   ├── test_packet_methods.py
│   └── test_sniffer_exceptions.py
├── integration/            # Integration tests (slower)
│   └── test_full_pipeline.py
├── e2e/                    # End-to-end tests (slowest)
│   └── test_complete_workflow.py
├── conftest.py             # Shared fixtures
└── __init__.py
```

## Running Tests

### Quick Commands

```bash
# All tests with coverage
make test

# Quick run (no coverage)
make test-quick

# Specific test file
uv run pytest tests/unit/test_packet_capture.py

# Specific test function
uv run pytest tests/unit/test_packet_capture.py::test_capture_init

# With verbose output
uv run pytest -v

# Stop on first failure
uv run pytest -x
```

### Test Selection

```bash
# Run only unit tests
uv run pytest tests/unit/

# Run only integration tests
uv run pytest tests/integration/

# Run tests matching pattern
uv run pytest -k "test_tcp"

# Run tests by marker
uv run pytest -m "slow"
uv run pytest -m "not slow"
```

## Writing Tests

### Test Anatomy

```python
import pytest
from network_security_suite.module import Feature

def test_feature_basic():
    """Test basic feature functionality."""
    # Arrange: Set up test data
    input_data = create_test_data()
    feature = Feature()

    # Act: Execute the functionality
    result = feature.process(input_data)

    # Assert: Verify the outcome
    assert result.status == "success"
    assert len(result.items) == 5
```

### Naming Conventions

```python
# Good test names (descriptive)
def test_packet_capture_filters_by_protocol():
    ...

def test_tcp_analyzer_detects_syn_flood():
    ...

def test_config_raises_error_on_invalid_interface():
    ...

# Bad test names (vague)
def test_capture():
    ...

def test_analyzer():
    ...
```

### Test Organization

```python
class TestPacketCapture:
    """Group related tests for PacketCapture."""

    def test_init_with_valid_interface(self):
        """Test initialization with valid interface."""
        ...

    def test_init_with_invalid_interface(self):
        """Test initialization with invalid interface raises error."""
        ...

    def test_capture_stops_at_count(self):
        """Test capture stops at specified count."""
        ...
```

## Fixtures

### Built-in Fixtures

```python
import pytest

def test_with_tmp_path(tmp_path):
    """Test using temporary directory."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text("key: value")
    assert config_file.exists()

def test_with_monkeypatch(monkeypatch):
    """Test with environment variable."""
    monkeypatch.setenv("NETGUARD_LOG_LEVEL", "DEBUG")
    assert os.getenv("NETGUARD_LOG_LEVEL") == "DEBUG"
```

### Custom Fixtures

```python
# conftest.py
import pytest
import polars as pl
from datetime import datetime

@pytest.fixture
def sample_packet():
    """Create a sample packet for testing."""
    return Packet(
        timestamp=datetime.now(),
        src_ip="192.168.1.1",
        dst_ip="192.168.1.2",
        src_port=12345,
        dst_port=80,
        protocol="TCP",
        length=1500
    )

@pytest.fixture
def sample_dataframe():
    """Create a sample DataFrame with packet data."""
    return pl.DataFrame({
        "timestamp": [datetime.now()] * 100,
        "src_ip": ["192.168.1.1"] * 100,
        "dst_ip": ["192.168.1.2"] * 100,
        "protocol": ["TCP"] * 100,
    })

@pytest.fixture
def mock_config():
    """Create a mock configuration."""
    return SnifferConfig(
        interface="eth0",
        packet_count=100,
        timeout=10
    )
```

### Fixture Scopes

```python
@pytest.fixture(scope="function")  # Default: new for each test
def function_fixture():
    return create_resource()

@pytest.fixture(scope="class")  # Shared within test class
def class_fixture():
    return create_resource()

@pytest.fixture(scope="module")  # Shared within test module
def module_fixture():
    return create_expensive_resource()

@pytest.fixture(scope="session")  # Created once per test session
def session_fixture():
    return create_very_expensive_resource()
```

### Fixture Cleanup

```python
@pytest.fixture
def database_connection():
    """Fixture with cleanup."""
    # Setup
    conn = create_connection()
    yield conn
    # Teardown (runs after test)
    conn.close()
```

## Mocking

### Mock External Dependencies

```python
from unittest.mock import Mock, patch

def test_packet_capture_with_mock():
    """Test packet capture with mocked scapy."""
    with patch("scapy.all.sniff") as mock_sniff:
        # Configure mock
        mock_sniff.return_value = [create_mock_packet()]

        # Test
        capture = PacketCapture("eth0")
        packets = capture.capture(count=1)

        # Verify
        assert len(packets) == 1
        mock_sniff.assert_called_once()
```

### Mock File System

```python
def test_config_loading(tmp_path):
    """Test configuration loading from file."""
    # Create temporary config file
    config_file = tmp_path / "config.yaml"
    config_file.write_text("""
    interface: eth0
    packet_count: 1000
    """)

    # Test loading
    config = load_config(config_file)
    assert config.interface == "eth0"
```

### Mock Network Interfaces

```python
@pytest.fixture
def mock_interfaces(monkeypatch):
    """Mock network interfaces."""
    def mock_get_if_list():
        return ["lo", "eth0", "wlan0"]

    monkeypatch.setattr(
        "scapy.all.get_if_list",
        mock_get_if_list
    )
```

## Parametrized Tests

### Single Parameter

```python
@pytest.mark.parametrize("protocol", ["TCP", "UDP", "ICMP"])
def test_analyzer_supports_protocol(protocol):
    """Test analyzer supports various protocols."""
    analyzer = ProtocolAnalyzer()
    assert analyzer.supports(protocol)
```

### Multiple Parameters

```python
@pytest.mark.parametrize(
    "src_ip,dst_ip,expected",
    [
        ("192.168.1.1", "192.168.1.2", True),
        ("10.0.0.1", "10.0.0.2", True),
        ("invalid", "192.168.1.1", False),
    ]
)
def test_ip_validation(src_ip, dst_ip, expected):
    """Test IP address validation."""
    result = validate_ips(src_ip, dst_ip)
    assert result == expected
```

### Complex Parameters

```python
@pytest.mark.parametrize(
    "packet_data",
    [
        {"protocol": "TCP", "port": 80},
        {"protocol": "UDP", "port": 53},
        {"protocol": "ICMP", "type": 8},
    ],
    ids=["http", "dns", "ping"]
)
def test_packet_parsing(packet_data):
    """Test packet parsing for different protocols."""
    packet = parse_packet(packet_data)
    assert packet.protocol == packet_data["protocol"]
```

## Exception Testing

### Assert Raises

```python
def test_invalid_interface_raises_error():
    """Test that invalid interface raises InterfaceError."""
    with pytest.raises(InterfaceError):
        PacketCapture("invalid_interface")

def test_error_message():
    """Test error message content."""
    with pytest.raises(ConfigError, match="Invalid interface"):
        load_config({"interface": None})
```

### Testing Exception Details

```python
def test_exception_details():
    """Test exception attributes."""
    with pytest.raises(CaptureError) as exc_info:
        capture_packets("invalid")

    assert exc_info.value.interface == "invalid"
    assert "not found" in str(exc_info.value)
```

## Property-Based Testing

Use Hypothesis for property-based testing:

```python
from hypothesis import given, strategies as st

@given(
    src_ip=st.ip_addresses(v=4),
    dst_ip=st.ip_addresses(v=4),
    port=st.integers(min_value=1, max_value=65535)
)
def test_packet_properties(src_ip, dst_ip, port):
    """Test packet creation with random valid inputs."""
    packet = create_packet(
        src_ip=str(src_ip),
        dst_ip=str(dst_ip),
        port=port
    )
    assert packet.is_valid()
    assert 1 <= packet.port <= 65535
```

## Performance Testing

### Timing Tests

```python
import time

def test_packet_capture_performance():
    """Test packet capture performance."""
    capture = PacketCapture("eth0")

    start = time.time()
    packets = capture.capture(count=1000)
    duration = time.time() - start

    # Should capture 1000 packets in under 10 seconds
    assert duration < 10.0
    assert len(packets) == 1000
```

### Memory Testing

```python
import tracemalloc

def test_memory_usage():
    """Test memory usage stays within limits."""
    tracemalloc.start()

    # Perform memory-intensive operation
    capture = PacketCapture("eth0")
    packets = capture.capture(count=10000)

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Peak memory should be under 100MB
    assert peak < 100 * 1024 * 1024
```

### Benchmark Tests

```bash
# Install pytest-benchmark
uv pip install pytest-benchmark

# Run benchmarks
uv run pytest --benchmark-only
```

```python
def test_analyzer_benchmark(benchmark, sample_dataframe):
    """Benchmark analyzer performance."""
    analyzer = TCPAnalyzer()

    result = benchmark(analyzer.analyze, sample_dataframe)

    assert result is not None
```

## Integration Tests

### Testing Module Integration

```python
def test_capture_to_parquet_pipeline(tmp_path):
    """Test complete capture-to-storage pipeline."""
    # Capture packets
    capture = PacketCapture("eth0")
    packets = capture.capture(count=100)

    # Convert to DataFrame
    df = packets_to_dataframe(packets)

    # Write to Parquet
    output_file = tmp_path / "capture.parquet"
    df.write_parquet(output_file)

    # Verify
    assert output_file.exists()
    loaded_df = pl.read_parquet(output_file)
    assert len(loaded_df) == 100
```

### Testing Analyzer Pipeline

```python
def test_analyzer_pipeline():
    """Test complete analysis pipeline."""
    # Load data
    df = pl.read_parquet("test_data.parquet")

    # Run multiple analyzers
    tcp_results = TCPAnalyzer().analyze(df)
    udp_results = UDPAnalyzer().analyze(df)
    dns_results = DNSAnalyzer().analyze(df)

    # Verify results
    assert tcp_results["connection_count"] > 0
    assert udp_results["packet_count"] > 0
    assert dns_results["query_count"] > 0
```

## Test Markers

### Define Markers

```toml
# pyproject.toml
[tool.pytest.ini_options]
markers = [
    "slow: marks tests as slow (deselect with '-m \"not slow\"')",
    "integration: marks tests as integration tests",
    "unit: marks tests as unit tests",
    "requires_root: marks tests that require root privileges",
    "network: marks tests that require network access",
]
```

### Use Markers

```python
import pytest

@pytest.mark.slow
def test_large_dataset_analysis():
    """Test with large dataset (slow)."""
    ...

@pytest.mark.integration
def test_full_pipeline():
    """Integration test for full pipeline."""
    ...

@pytest.mark.requires_root
def test_packet_capture_privileged():
    """Test packet capture (requires root)."""
    ...

@pytest.mark.skip(reason="Not implemented yet")
def test_future_feature():
    """Placeholder for future feature."""
    ...

@pytest.mark.skipif(sys.platform == "win32", reason="Linux only")
def test_linux_specific():
    """Test Linux-specific functionality."""
    ...
```

### Run by Marker

```bash
# Run only fast tests
uv run pytest -m "not slow"

# Run only integration tests
uv run pytest -m integration

# Run unit tests only
uv run pytest -m unit

# Skip network tests
uv run pytest -m "not network"
```

## Coverage

### Generate Coverage Report

```bash
# Run with coverage
make test

# View in terminal
uv run pytest --cov=src --cov-report=term-missing

# Generate HTML report
uv run pytest --cov=src --cov-report=html

# View HTML report
open htmlcov/index.html
```

### Coverage Configuration

```toml
# pyproject.toml
[tool.coverage.run]
source = ["src"]
omit = [
    "*/tests/*",
    "*/.venv/*",
]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "raise NotImplementedError",
    "if __name__ == .__main__.:",
]
```

### Coverage Goals

- **Overall**: 80%+
- **Critical paths**: 95%+
- **Utilities**: 90%+
- **Examples**: 50%+ (optional)

## Continuous Integration

### GitHub Actions Workflow

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.9, 3.10, 3.11, 3.12]

    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install dependencies
        run: |
          pip install uv
          uv sync --all-extras
      - name: Run tests
        run: make test
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

## Testing Best Practices

### DO

✅ Test one thing per test
✅ Use descriptive test names
✅ Keep tests independent
✅ Use fixtures for setup
✅ Test edge cases and errors
✅ Write tests before fixing bugs
✅ Keep tests fast
✅ Mock external dependencies

### DON'T

❌ Test implementation details
❌ Share state between tests
❌ Use sleep() for timing
❌ Test third-party libraries
❌ Write flaky tests
❌ Skip writing tests
❌ Leave commented-out tests

## Common Patterns

### Testing Async Code

```python
import pytest

@pytest.mark.asyncio
async def test_async_capture():
    """Test asynchronous packet capture."""
    capture = AsyncPacketCapture("eth0")
    packets = await capture.capture_async(count=10)
    assert len(packets) == 10
```

### Testing Context Managers

```python
def test_resource_cleanup():
    """Test resource cleanup with context manager."""
    with PacketCapture("eth0") as capture:
        packets = capture.capture(count=10)
        assert len(packets) == 10
    # Verify cleanup happened
    assert capture.is_closed()
```

### Testing Decorators

```python
def test_performance_decorator():
    """Test performance timing decorator."""
    @perf("test_function")
    def slow_function():
        time.sleep(0.1)
        return "done"

    result = slow_function()
    assert result == "done"
    # Verify timing was recorded
```

## Debugging Tests

### Print Debug Info

```python
def test_with_debug():
    """Test with debug output."""
    result = complex_function()
    print(f"Debug: result = {result}")  # Shown with pytest -s
    assert result.is_valid()
```

### Use pdb

```python
def test_with_debugger():
    """Test with debugger."""
    result = complex_function()
    import pdb; pdb.set_trace()  # Breakpoint
    assert result.is_valid()
```

### pytest Options

```bash
# Show print statements
pytest -s

# Stop on first failure
pytest -x

# Show local variables on failure
pytest -l

# Verbose output
pytest -vv

# Show test duration
pytest --durations=10
```

## Next Steps

- Read [Contributing Guide](contributing.md) for PR workflow
- Check [Project Review](project-review.md) for areas needing tests
- Review [Architecture](architecture.md) to understand test boundaries

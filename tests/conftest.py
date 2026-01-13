"""
NetGuard Test Configuration - Root conftest.py

This file provides global pytest configuration and fixtures available
to all test modules in the project.

Fixture Hierarchy:
    conftest.py (root)           # Global config + shared fixtures
    ├── unit/conftest.py         # Unit test fixtures
    │   └── preprocessing/conftest.py  # Preprocessing fixtures
    ├── integration/conftest.py  # Integration test fixtures
    └── e2e/conftest.py         # E2E test fixtures
"""

import contextlib
import os
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import polars as pl
import pytest

# ============================================================================
# PYTEST CONFIGURATION
# ============================================================================


def pytest_configure(config):
    """Configure pytest with custom markers and settings."""
    # Register custom markers
    config.addinivalue_line("markers", "unit: marks tests as unit tests (fast, isolated)")
    config.addinivalue_line(
        "markers",
        "integration: marks tests as integration tests (medium speed, multiple components)",
    )
    config.addinivalue_line("markers", "e2e: marks tests as end-to-end tests (slow, full system)")
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line("markers", "performance: marks tests as performance/benchmark tests")


def pytest_collection_modifyitems(config, items):
    """Automatically mark tests based on their location."""
    for item in items:
        # Get the test file path relative to tests directory
        rel_path = Path(item.fspath).relative_to(Path(__file__).parent)

        # Auto-mark based on directory
        if "unit" in rel_path.parts:
            item.add_marker(pytest.mark.unit)
        elif "integration" in rel_path.parts:
            item.add_marker(pytest.mark.integration)
        elif "e2e" in rel_path.parts:
            item.add_marker(pytest.mark.e2e)
        elif "performance" in rel_path.parts:
            item.add_marker(pytest.mark.performance)
            item.add_marker(pytest.mark.slow)


# ============================================================================
# GLOBAL FIXTURES - PATHS AND DIRECTORIES
# ============================================================================


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Return the project root directory."""
    return Path(__file__).parent.parent


@pytest.fixture(scope="session")
def tests_dir() -> Path:
    """Return the tests directory."""
    return Path(__file__).parent


@pytest.fixture(scope="session")
def fixtures_dir(tests_dir) -> Path:
    """Return the fixtures directory."""
    return tests_dir / "fixtures"


@pytest.fixture(scope="session")
def sample_data_dir(fixtures_dir) -> Path:
    """Return the sample data directory."""
    data_dir = fixtures_dir / "sample_data"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def temp_parquet_path(temp_dir):
    """Create a temporary path for parquet files."""
    return temp_dir / "test_data.parquet"


# ============================================================================
# GLOBAL FIXTURES - COMMON TEST DATA
# ============================================================================


@pytest.fixture
def base_timestamp() -> datetime:
    """Standard base timestamp for tests."""
    return datetime(2024, 1, 1, 10, 0, 0)


@pytest.fixture
def sample_ip_addresses() -> dict:
    """Common IP addresses used in tests."""
    return {
        "internal": {
            "host1": "192.168.1.100",
            "host2": "192.168.1.101",
            "host3": "192.168.1.102",
        },
        "external": {
            "google": "142.250.185.46",
            "cloudflare": "1.1.1.1",
            "example": "93.184.216.34",
        },
        "attackers": {
            "scanner1": "10.0.0.50",
            "scanner2": "10.0.0.51",
            "scanner3": "10.0.0.52",
        },
    }


@pytest.fixture
def common_ports() -> dict:
    """Common port numbers used in tests."""
    return {
        "web": [80, 443, 8080, 8443],
        "mail": [25, 110, 143, 587, 993, 995],
        "database": [3306, 5432, 27017, 6379],
        "remote": [22, 23, 3389, 5900],
        "dns": [53],
        "ephemeral": list(range(49152, 49200)),
    }


# ============================================================================
# GLOBAL FIXTURES - DATAFRAME HELPERS
# ============================================================================


@pytest.fixture
def empty_packet_dataframe() -> pl.DataFrame:
    """
    Empty DataFrame with correct packet schema.

    Useful for testing error handling and edge cases.
    """
    return pl.DataFrame(
        {
            "timestamp": [],
            "IP_src": [],
            "IP_dst": [],
            "IP_proto": [],
            "IP_len": [],
            "TCP_sport": [],
            "TCP_dport": [],
            "TCP_flags": [],
            "UDP_sport": [],
            "UDP_dport": [],
        }
    )


@pytest.fixture
def minimal_tcp_packet(base_timestamp) -> dict:
    """
    Minimal valid TCP packet data.

    Returns a dict that can be used to create a single-row DataFrame.
    """
    return {
        "timestamp": base_timestamp,
        "IP_src": "192.168.1.100",
        "IP_dst": "93.184.216.34",
        "IP_proto": 6,  # TCP
        "IP_len": 60,
        "TCP_sport": 50000,
        "TCP_dport": 80,
        "TCP_flags": "S",
    }


@pytest.fixture
def minimal_udp_packet(base_timestamp) -> dict:
    """
    Minimal valid UDP packet data.

    Returns a dict that can be used to create a single-row DataFrame.
    """
    return {
        "timestamp": base_timestamp,
        "IP_src": "192.168.1.100",
        "IP_dst": "8.8.8.8",
        "IP_proto": 17,  # UDP
        "IP_len": 60,
        "UDP_sport": 50000,
        "UDP_dport": 53,
    }


# ============================================================================
# GLOBAL FIXTURES - ASSERTION HELPERS
# ============================================================================


@pytest.fixture
def assert_dataframe_equal():
    """
    Helper to compare Polars DataFrames with better error messages.

    Example:
        >>> assert_dataframe_equal(result, expected)
        >>> assert_dataframe_equal(result, expected, check_row_order=False)
    """

    def _assert_equal(
        df1: pl.DataFrame,
        df2: pl.DataFrame,
        check_row_order: bool = True,
        check_dtypes: bool = True,
    ):
        """Compare two Polars DataFrames."""
        # Check shapes
        if df1.shape != df2.shape:
            raise AssertionError(f"Shape mismatch:\n  df1: {df1.shape}\n  df2: {df2.shape}")

        # Check columns
        if df1.columns != df2.columns:
            raise AssertionError(f"Column mismatch:\n  df1: {df1.columns}\n  df2: {df2.columns}")

        # Check dtypes
        if check_dtypes:
            for col in df1.columns:
                if df1[col].dtype != df2[col].dtype:
                    raise AssertionError(
                        f"Dtype mismatch in column '{col}':\n"
                        f"  df1: {df1[col].dtype}\n  df2: {df2[col].dtype}"
                    )

        # Check values
        if check_row_order:
            if not df1.frame_equal(df2):
                raise AssertionError("DataFrames are not equal")
        else:
            # Sort both before comparing
            df1_sorted = df1.sort(df1.columns)
            df2_sorted = df2.sort(df2.columns)
            if not df1_sorted.frame_equal(df2_sorted):
                raise AssertionError("DataFrames are not equal (ignoring row order)")

    return _assert_equal


@pytest.fixture
def assert_has_columns():
    """
    Helper to assert DataFrame has required columns.

    Example:
        >>> assert_has_columns(df, ["timestamp", "IP_src"])
    """

    def _assert_has_columns(df: pl.DataFrame, required_columns: list):
        """Check if DataFrame has all required columns."""
        missing = [col for col in required_columns if col not in df.columns]
        if missing:
            raise AssertionError(
                f"Missing required columns: {missing}\nAvailable columns: {df.columns}"
            )

    return _assert_has_columns


# ============================================================================
# GLOBAL FIXTURES - FILE OPERATIONS
# ============================================================================


@pytest.fixture
def create_test_parquet():
    """
    Factory fixture to create parquet files for testing.

    Example:
        >>> parquet_path = create_test_parquet(df, "test.parquet")
    """
    created_files = []

    def _create(df: pl.DataFrame, filename: str, temp_dir: Optional[Path] = None) -> Path:
        """Create a parquet file from DataFrame."""
        if temp_dir is None:
            temp_dir = Path(tempfile.mkdtemp())

        path = temp_dir / filename
        df.write_parquet(path)
        created_files.append(path)
        return path

    yield _create

    # Cleanup
    for path in created_files:
        if path.exists():
            path.unlink()


# ============================================================================
# GLOBAL FIXTURES - PERFORMANCE TESTING
# ============================================================================


@pytest.fixture
def timer():
    """
    Context manager for timing code execution.

    Example:
        >>> with timer() as t:
        ...     slow_function()
        >>> assert t.elapsed < 1.0, "Function took too long"
    """

    class Timer:
        def __init__(self):
            self.start = None
            self.end = None
            self.elapsed = None

        def __enter__(self):
            self.start = time.time()
            return self

        def __exit__(self, *args):
            self.end = time.time()
            self.elapsed = self.end - self.start

    return Timer


# ============================================================================
# GLOBAL FIXTURES - ENVIRONMENT
# ============================================================================


@pytest.fixture
def mock_env_vars():
    """
    Temporarily set environment variables for testing.

    Example:
        >>> with mock_env_vars({"DEBUG": "1"}):
        ...     # Test code here
    """

    @contextlib.contextmanager
    def _mock_env(**env_vars):
        old_env = {}
        for key, value in env_vars.items():
            old_env[key] = os.environ.get(key)
            os.environ[key] = value

        try:
            yield
        finally:
            for key, value in old_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    return _mock_env


# ============================================================================
# PYTEST PLUGINS - AUTO-IMPORT FIXTURES FROM SUBMODULES
# ============================================================================

# Automatically import fixtures from specialized conftest files
pytest_plugins = [
    # Unit test fixtures will be imported when they exist
    # "tests.unit.conftest",
    # "tests.unit.preprocessing.analyzers.fixtures.tcp_fixtures",
]


# ============================================================================
# HOOKS - CUSTOM PYTEST BEHAVIOR
# ============================================================================


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """
    Make test results available to fixtures.

    Allows fixtures to access test outcome (pass/fail).
    """
    outcome = yield
    rep = outcome.get_result()

    # Store result for teardown fixtures
    setattr(item, f"rep_{rep.when}", rep)


# ============================================================================
# CUSTOM ASSERTIONS
# ============================================================================


def pytest_assertrepr_compare(op, left, right):
    """
    Provide custom assertion messages for common types.
    """
    if isinstance(left, pl.DataFrame) and isinstance(right, pl.DataFrame) and op == "==":
        return [
            "DataFrame comparison failed:",
            f"Left shape:  {left.shape}",
            f"Right shape: {right.shape}",
            f"Left columns:  {left.columns}",
            f"Right columns: {right.columns}",
        ]

"""Unit tests for BaseAnalyzer class.

This module tests the base analyzer class that all protocol-specific
analyzers inherit from.
"""

import pytest
import polars as pl
from datetime import datetime

from netguard.analysis.base_analyzer import BaseAnalyzer


# ============================================================================
# TEST FIXTURES
# ============================================================================


@pytest.fixture
def sample_df(base_timestamp) -> pl.DataFrame:
    """Create a sample DataFrame for testing."""
    return pl.DataFrame({
        "timestamp": [base_timestamp] * 5,
        "IP_src": ["192.168.1.100", "192.168.1.101", "10.0.0.1", "172.16.0.1", "8.8.8.8"],
        "IP_dst": ["8.8.8.8", "1.1.1.1", "192.168.1.100", "192.168.1.101", "192.168.1.100"],
        "IP_proto": [6, 6, 17, 17, 1],
        "IP_len": [60, 120, 80, 45, 64],
    })


@pytest.fixture
def empty_df() -> pl.DataFrame:
    """Create an empty DataFrame for testing edge cases."""
    return pl.DataFrame({
        "timestamp": [],
        "IP_src": [],
        "IP_dst": [],
    })


@pytest.fixture
def df_with_timestamps() -> pl.DataFrame:
    """Create DataFrame with varied timestamps."""
    base = datetime(2024, 1, 1, 10, 0, 0)
    return pl.DataFrame({
        "timestamp": [
            datetime(2024, 1, 1, 10, 0, 0),
            datetime(2024, 1, 1, 10, 0, 30),
            datetime(2024, 1, 1, 10, 1, 0),
            datetime(2024, 1, 1, 10, 5, 0),
            datetime(2024, 1, 1, 11, 0, 0),
        ],
        "IP_src": ["192.168.1.100"] * 5,
        "IP_dst": ["8.8.8.8"] * 5,
    })


@pytest.fixture
def base_analyzer(sample_df) -> BaseAnalyzer:
    """Create a BaseAnalyzer instance."""
    return BaseAnalyzer(sample_df)


# ============================================================================
# TEST CLASS: BaseAnalyzer Initialization
# ============================================================================


class TestBaseAnalyzerInitialization:
    """Test BaseAnalyzer initialization."""

    def test_init_with_valid_dataframe(self, sample_df):
        """Test initialization with a valid DataFrame."""
        analyzer = BaseAnalyzer(sample_df)

        assert analyzer.df is not None
        assert len(analyzer.df) == 5

    def test_init_stores_dataframe(self, sample_df):
        """Test that initialization stores the DataFrame."""
        analyzer = BaseAnalyzer(sample_df)

        assert analyzer.df.shape == sample_df.shape

    def test_init_sets_packet_count(self, sample_df):
        """Test that initialization sets _packet_count."""
        analyzer = BaseAnalyzer(sample_df)

        assert analyzer._packet_count == 5

    def test_init_with_empty_dataframe(self, empty_df):
        """Test initialization with empty DataFrame."""
        analyzer = BaseAnalyzer(empty_df)

        assert analyzer._packet_count == 0
        assert analyzer.is_empty


# ============================================================================
# TEST CLASS: BaseAnalyzer Properties
# ============================================================================


class TestBaseAnalyzerProperties:
    """Test BaseAnalyzer properties."""

    def test_packet_count_property(self, base_analyzer):
        """Test packet_count property."""
        assert base_analyzer.packet_count == 5

    def test_is_empty_property_with_data(self, base_analyzer):
        """Test is_empty returns False when data exists."""
        assert base_analyzer.is_empty is False

    def test_is_empty_property_empty(self, empty_df):
        """Test is_empty returns True for empty DataFrame."""
        analyzer = BaseAnalyzer(empty_df)
        assert analyzer.is_empty is True

    def test_columns_property(self, base_analyzer):
        """Test columns property returns column list."""
        columns = base_analyzer.columns

        assert isinstance(columns, list)
        assert "IP_src" in columns
        assert "IP_dst" in columns

    def test_shape_property(self, base_analyzer):
        """Test shape property returns tuple."""
        shape = base_analyzer.shape

        assert isinstance(shape, tuple)
        assert len(shape) == 2
        assert shape[0] == 5  # rows


# ============================================================================
# TEST CLASS: BaseAnalyzer Dunder Methods
# ============================================================================


class TestBaseAnalyzerDunderMethods:
    """Test BaseAnalyzer dunder/magic methods."""

    def test_len(self, base_analyzer):
        """Test __len__ returns packet count."""
        assert len(base_analyzer) == 5

    def test_bool_with_data(self, base_analyzer):
        """Test __bool__ returns True when data exists."""
        assert bool(base_analyzer) is True

    def test_bool_empty(self, empty_df):
        """Test __bool__ returns False for empty analyzer."""
        analyzer = BaseAnalyzer(empty_df)
        assert bool(analyzer) is False

    def test_repr(self, base_analyzer):
        """Test __repr__ returns technical representation."""
        repr_str = repr(base_analyzer)

        assert "BaseAnalyzer" in repr_str
        assert "packets=5" in repr_str

    def test_str(self, base_analyzer):
        """Test __str__ returns human-readable string."""
        str_output = str(base_analyzer)

        assert "BaseAnalyzer" in str_output
        assert "5 packets" in str_output

    def test_eq_same_data(self, sample_df):
        """Test __eq__ returns True for same data."""
        analyzer1 = BaseAnalyzer(sample_df)
        analyzer2 = BaseAnalyzer(sample_df)

        assert analyzer1 == analyzer2

    def test_eq_different_data(self, sample_df, empty_df):
        """Test __eq__ returns False for different data."""
        analyzer1 = BaseAnalyzer(sample_df)
        analyzer2 = BaseAnalyzer(empty_df)

        assert analyzer1 != analyzer2

    def test_eq_different_type(self, base_analyzer):
        """Test __eq__ returns False for different types."""
        assert base_analyzer != "not an analyzer"
        assert base_analyzer != 42


# ============================================================================
# TEST CLASS: BaseAnalyzer Date Range Methods
# ============================================================================


class TestBaseAnalyzerDateRange:
    """Test BaseAnalyzer date range methods."""

    def test_get_date_range_with_timestamps(self, df_with_timestamps):
        """Test get_date_range returns correct range."""
        analyzer = BaseAnalyzer(df_with_timestamps)
        date_range = analyzer.get_date_range()

        assert "start" in date_range
        assert "end" in date_range
        assert "duration" in date_range
        assert date_range["start"] is not None
        assert date_range["end"] is not None

    def test_get_date_range_without_timestamp_column(self):
        """Test get_date_range handles missing timestamp column."""
        df = pl.DataFrame({"IP_src": ["192.168.1.1"], "IP_dst": ["8.8.8.8"]})
        analyzer = BaseAnalyzer(df)

        date_range = analyzer.get_date_range()

        assert date_range["start"] is None
        assert date_range["end"] is None
        assert date_range["duration"] is None

    def test_get_date_range_empty(self, empty_df):
        """Test get_date_range handles empty DataFrame."""
        analyzer = BaseAnalyzer(empty_df)
        date_range = analyzer.get_date_range()

        assert date_range["start"] is None
        assert date_range["end"] is None


# ============================================================================
# TEST CLASS: BaseAnalyzer Memory Usage Methods
# ============================================================================


class TestBaseAnalyzerMemoryUsage:
    """Test BaseAnalyzer memory usage methods."""

    def test_get_memory_usage_returns_dict(self, base_analyzer):
        """Test get_memory_usage returns a dictionary."""
        memory = base_analyzer.get_memory_usage()

        assert isinstance(memory, dict)
        assert "bytes" in memory
        assert "mb" in memory

    def test_get_memory_usage_positive_values(self, base_analyzer):
        """Test memory usage values are positive."""
        memory = base_analyzer.get_memory_usage()

        assert memory["bytes"] >= 0
        assert memory["mb"] >= 0

    def test_get_memory_usage_conversion(self, base_analyzer):
        """Test MB is correctly calculated from bytes."""
        memory = base_analyzer.get_memory_usage()

        assert memory["mb"] == memory["bytes"] / (1024 * 1024)


# ============================================================================
# TEST CLASS: BaseAnalyzer Column Methods
# ============================================================================


class TestBaseAnalyzerColumnMethods:
    """Test BaseAnalyzer column-related methods."""

    def test_has_column_exists(self, base_analyzer):
        """Test has_column returns True for existing column."""
        assert base_analyzer.has_column("IP_src") is True

    def test_has_column_not_exists(self, base_analyzer):
        """Test has_column returns False for non-existent column."""
        assert base_analyzer.has_column("nonexistent_column") is False

    def test_get_column_types_returns_dict(self, base_analyzer):
        """Test get_column_types returns a dictionary."""
        types = base_analyzer.get_column_types()

        assert isinstance(types, dict)

    def test_get_column_types_all_columns(self, base_analyzer):
        """Test get_column_types includes all columns."""
        types = base_analyzer.get_column_types()

        assert set(types.keys()) == set(base_analyzer.columns)

    def test_get_column_types_string_values(self, base_analyzer):
        """Test get_column_types values are strings."""
        types = base_analyzer.get_column_types()

        for dtype in types.values():
            assert isinstance(dtype, str)


# ============================================================================
# TEST CLASS: BaseAnalyzer Data Access Methods
# ============================================================================


class TestBaseAnalyzerDataAccess:
    """Test BaseAnalyzer data access methods."""

    def test_sample_returns_dataframe(self, base_analyzer):
        """Test sample returns a DataFrame."""
        sample = base_analyzer.sample(3)

        assert isinstance(sample, pl.DataFrame)

    def test_sample_correct_size(self, base_analyzer):
        """Test sample returns correct number of rows."""
        sample = base_analyzer.sample(3)

        assert len(sample) == 3

    def test_sample_larger_than_data(self, base_analyzer):
        """Test sample handles n larger than data size."""
        sample = base_analyzer.sample(100)

        assert len(sample) == 5  # Only 5 rows in data

    def test_head_returns_dataframe(self, base_analyzer):
        """Test head returns a DataFrame."""
        head = base_analyzer.head(3)

        assert isinstance(head, pl.DataFrame)
        assert len(head) == 3

    def test_tail_returns_dataframe(self, base_analyzer):
        """Test tail returns a DataFrame."""
        tail = base_analyzer.tail(3)

        assert isinstance(tail, pl.DataFrame)
        assert len(tail) == 3

    def test_describe_returns_dataframe(self, base_analyzer):
        """Test describe returns statistics DataFrame."""
        desc = base_analyzer.describe()

        assert isinstance(desc, pl.DataFrame)


# ============================================================================
# TEST CLASS: BaseAnalyzer Serialization Methods
# ============================================================================


class TestBaseAnalyzerSerialization:
    """Test BaseAnalyzer serialization methods."""

    def test_to_dict_returns_dict(self, base_analyzer):
        """Test to_dict returns a dictionary."""
        result = base_analyzer.to_dict()

        assert isinstance(result, dict)

    def test_to_dict_contains_required_keys(self, base_analyzer):
        """Test to_dict contains all required keys."""
        result = base_analyzer.to_dict()

        required_keys = [
            "analyzer_type",
            "packet_count",
            "shape",
            "columns",
            "date_range",
            "memory_usage",
        ]
        for key in required_keys:
            assert key in result, f"Missing key: {key}"

    def test_to_dict_correct_analyzer_type(self, base_analyzer):
        """Test to_dict has correct analyzer type."""
        result = base_analyzer.to_dict()

        assert result["analyzer_type"] == "BaseAnalyzer"

    def test_to_dict_correct_packet_count(self, base_analyzer):
        """Test to_dict has correct packet count."""
        result = base_analyzer.to_dict()

        assert result["packet_count"] == 5


# ============================================================================
# TEST CLASS: BaseAnalyzer Inheritance
# ============================================================================


class TestBaseAnalyzerInheritance:
    """Test that BaseAnalyzer can be inherited properly."""

    def test_subclass_inherits_methods(self, sample_df):
        """Test that subclasses inherit all methods."""

        class CustomAnalyzer(BaseAnalyzer):
            def __init__(self, df):
                super().__init__(df)

        analyzer = CustomAnalyzer(sample_df)

        # Verify inherited methods work
        assert analyzer.packet_count == 5
        assert analyzer.has_column("IP_src")
        assert len(analyzer) == 5

    def test_subclass_can_override_methods(self, sample_df):
        """Test that subclasses can override methods."""

        class CustomAnalyzer(BaseAnalyzer):
            def __init__(self, df):
                super().__init__(df)
                self.custom_value = "custom"

            def __str__(self):
                return f"CustomAnalyzer: {self.custom_value}"

        analyzer = CustomAnalyzer(sample_df)

        assert "CustomAnalyzer" in str(analyzer)
        assert "custom" in str(analyzer)

    def test_subclass_filter_in_init(self, sample_df):
        """Test subclass can filter data in __init__."""

        class TcpOnlyAnalyzer(BaseAnalyzer):
            def __init__(self, df):
                # Filter to TCP only (proto 6)
                filtered_df = df.filter(pl.col("IP_proto") == 6)
                super().__init__(filtered_df)

        analyzer = TcpOnlyAnalyzer(sample_df)

        # Should only have TCP packets (2 in sample_df)
        assert analyzer.packet_count == 2

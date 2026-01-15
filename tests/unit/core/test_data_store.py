"""Unit tests for DataStore class.

This module tests the centralized parquet I/O operations
provided by the DataStore class.
"""

import random
from typing import Literal

import polars as pl
import pytest

from netguard.core.data_store import DataStore
from netguard.core.exceptions import DataImportError

# Type alias for compression options
CompressionType = Literal["lz4", "uncompressed", "snappy", "gzip", "lzo", "brotli", "zstd"]

# ============================================================================
# TEST FIXTURES
# ============================================================================


@pytest.fixture
def sample_packet_df(base_timestamp) -> pl.DataFrame:
    """Create a sample packet DataFrame for testing."""
    return pl.DataFrame(
        {
            "timestamp": [base_timestamp] * 5,
            "IP_src": ["192.168.1.100", "192.168.1.101", "10.0.0.1", "172.16.0.1", "8.8.8.8"],
            "IP_dst": ["8.8.8.8", "1.1.1.1", "192.168.1.100", "192.168.1.101", "192.168.1.100"],
            "IP_proto": [6, 6, 17, 17, 1],  # TCP, TCP, UDP, UDP, ICMP
            "IP_len": [60, 120, 80, 45, 64],
            "TCP_sport": [50000, 50001, None, None, None],
            "TCP_dport": [80, 443, None, None, None],
            "UDP_sport": [None, None, 53, 123, None],
            "UDP_dport": [None, None, 53, 123, None],
        }
    )


@pytest.fixture
def large_packet_df(base_timestamp) -> pl.DataFrame:
    """Create a larger packet DataFrame for performance testing."""
    n_packets = 1000

    return pl.DataFrame(
        {
            "timestamp": [base_timestamp] * n_packets,
            "IP_src": [f"192.168.1.{i % 255}" for i in range(n_packets)],
            "IP_dst": [f"10.0.0.{i % 255}" for i in range(n_packets)],
            "IP_proto": [random.choice([6, 17, 1]) for _ in range(n_packets)],
            "IP_len": [random.randint(40, 1500) for _ in range(n_packets)],
        }
    )


# ============================================================================
# TEST CLASS: DataStore Save Operations
# ============================================================================


class TestDataStoreSavePackets:
    """Test DataStore.save_packets() method."""

    def test_save_packets_creates_file(self, sample_packet_df, temp_dir):
        """Test that save_packets creates a parquet file."""
        filepath = temp_dir / "test_packets.parquet"

        DataStore.save_packets(sample_packet_df, str(filepath))

        assert filepath.exists()
        assert filepath.stat().st_size > 0

    def test_save_packets_creates_parent_directories(self, sample_packet_df, temp_dir):
        """Test that save_packets creates parent directories if needed."""
        filepath = temp_dir / "nested" / "dir" / "test_packets.parquet"

        DataStore.save_packets(sample_packet_df, str(filepath))

        assert filepath.exists()

    def test_save_packets_preserves_data(self, sample_packet_df, temp_dir):
        """Test that saved data can be loaded back correctly."""
        filepath = temp_dir / "test_packets.parquet"

        DataStore.save_packets(sample_packet_df, str(filepath))
        loaded_df = pl.read_parquet(filepath)

        assert loaded_df.shape == sample_packet_df.shape
        assert loaded_df.columns == sample_packet_df.columns

    def test_save_packets_with_compression(self, sample_packet_df, temp_dir):
        """Test saving with different compression algorithms."""
        compressions: list[CompressionType] = ["snappy", "gzip", "lz4", "zstd"]

        for compression in compressions:
            filepath = temp_dir / f"test_{compression}.parquet"
            DataStore.save_packets(sample_packet_df, str(filepath), compression=compression)

            assert filepath.exists(), f"File not created with {compression} compression"

    def test_save_packets_overwrites_existing(self, sample_packet_df, temp_dir):
        """Test that save_packets overwrites existing files."""
        filepath = temp_dir / "test_packets.parquet"

        # Create initial file with 5 rows
        DataStore.save_packets(sample_packet_df, str(filepath))

        # Overwrite with smaller data
        small_df = sample_packet_df.head(2)
        DataStore.save_packets(small_df, str(filepath))

        # Verify overwrite
        loaded_df = pl.read_parquet(filepath)
        assert len(loaded_df) == 2

    def test_save_packets_empty_dataframe(self, temp_dir):
        """Test saving an empty DataFrame."""
        filepath = temp_dir / "empty.parquet"
        empty_df = pl.DataFrame()

        DataStore.save_packets(empty_df, str(filepath))

        assert filepath.exists()
        loaded_df = pl.read_parquet(filepath)
        assert len(loaded_df) == 0


# ============================================================================
# TEST CLASS: DataStore Load Operations
# ============================================================================


class TestDataStoreLoadPackets:
    """Test DataStore.load_packets() method."""

    def test_load_packets_success(self, sample_packet_df, temp_dir):
        """Test loading a valid parquet file."""
        filepath = temp_dir / "test_packets.parquet"
        sample_packet_df.write_parquet(filepath)

        loaded_df = DataStore.load_packets(str(filepath))

        assert isinstance(loaded_df, pl.DataFrame)
        assert loaded_df.shape == sample_packet_df.shape

    def test_load_packets_preserves_columns(self, sample_packet_df, temp_dir):
        """Test that loading preserves all columns."""
        filepath = temp_dir / "test_packets.parquet"
        sample_packet_df.write_parquet(filepath)

        loaded_df = DataStore.load_packets(str(filepath))

        assert set(loaded_df.columns) == set(sample_packet_df.columns)

    def test_load_packets_file_not_found(self):
        """Test that loading non-existent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            DataStore.load_packets("/nonexistent/path/file.parquet")

    def test_load_packets_invalid_file(self, temp_dir):
        """Test that loading invalid file raises DataImportError."""
        filepath = temp_dir / "invalid.parquet"
        filepath.write_text("This is not a parquet file")

        with pytest.raises(DataImportError):
            DataStore.load_packets(str(filepath))


# ============================================================================
# TEST CLASS: DataStore Schema Operations
# ============================================================================


class TestDataStoreGetSchema:
    """Test DataStore.get_schema() method."""

    def test_get_schema_returns_dict(self, sample_packet_df, temp_dir):
        """Test that get_schema returns a dictionary."""
        filepath = temp_dir / "test_packets.parquet"
        sample_packet_df.write_parquet(filepath)

        schema = DataStore.get_schema(str(filepath))

        assert isinstance(schema, dict)

    def test_get_schema_contains_all_columns(self, sample_packet_df, temp_dir):
        """Test that schema contains all DataFrame columns."""
        filepath = temp_dir / "test_packets.parquet"
        sample_packet_df.write_parquet(filepath)

        schema = DataStore.get_schema(str(filepath))

        assert set(schema.keys()) == set(sample_packet_df.columns)

    def test_get_schema_values_are_strings(self, sample_packet_df, temp_dir):
        """Test that schema values are string representations of types."""
        filepath = temp_dir / "test_packets.parquet"
        sample_packet_df.write_parquet(filepath)

        schema = DataStore.get_schema(str(filepath))

        for _col, dtype in schema.items():
            assert isinstance(dtype, str)


# ============================================================================
# TEST CLASS: DataStore File Info Operations
# ============================================================================


class TestDataStoreGetFileInfo:
    """Test DataStore.get_file_info() method."""

    def test_get_file_info_returns_dict(self, sample_packet_df, temp_dir):
        """Test that get_file_info returns a dictionary."""
        filepath = temp_dir / "test_packets.parquet"
        sample_packet_df.write_parquet(filepath)

        info = DataStore.get_file_info(str(filepath))

        assert isinstance(info, dict)

    def test_get_file_info_contains_required_keys(self, sample_packet_df, temp_dir):
        """Test that file info contains all required keys."""
        filepath = temp_dir / "test_packets.parquet"
        sample_packet_df.write_parquet(filepath)

        info = DataStore.get_file_info(str(filepath))

        required_keys = [
            "path",
            "filename",
            "size_bytes",
            "size_mb",
            "columns",
            "column_count",
            "schema",
        ]
        for key in required_keys:
            assert key in info, f"Missing required key: {key}"

    def test_get_file_info_correct_values(self, sample_packet_df, temp_dir):
        """Test that file info values are correct."""
        filepath = temp_dir / "test_packets.parquet"
        sample_packet_df.write_parquet(filepath)

        info = DataStore.get_file_info(str(filepath))

        assert info["filename"] == "test_packets.parquet"
        assert info["column_count"] == len(sample_packet_df.columns)
        assert info["size_bytes"] > 0
        assert info["size_mb"] == info["size_bytes"] / (1024 * 1024)

    def test_get_file_info_file_not_found(self):
        """Test that get_file_info raises FileNotFoundError for missing files."""
        with pytest.raises(FileNotFoundError):
            DataStore.get_file_info("/nonexistent/file.parquet")


# ============================================================================
# TEST CLASS: DataStore Append Operations
# ============================================================================


class TestDataStoreAppendPackets:
    """Test DataStore.append_packets() method."""

    def test_append_to_nonexistent_file(self, sample_packet_df, temp_dir):
        """Test appending to a file that doesn't exist creates it."""
        filepath = temp_dir / "new_file.parquet"

        DataStore.append_packets(sample_packet_df, str(filepath))

        assert filepath.exists()
        loaded_df = pl.read_parquet(filepath)
        assert len(loaded_df) == len(sample_packet_df)

    def test_append_to_existing_file(self, sample_packet_df, temp_dir):
        """Test appending to an existing file combines data."""
        filepath = temp_dir / "existing.parquet"

        # Create initial file
        DataStore.save_packets(sample_packet_df, str(filepath))

        # Append more data
        DataStore.append_packets(sample_packet_df, str(filepath))

        loaded_df = pl.read_parquet(filepath)
        assert len(loaded_df) == len(sample_packet_df) * 2

    def test_append_preserves_original_data(self, sample_packet_df, temp_dir):
        """Test that append preserves original data."""
        filepath = temp_dir / "test.parquet"

        # Create initial file with first 2 rows
        initial_df = sample_packet_df.head(2)
        DataStore.save_packets(initial_df, str(filepath))

        # Append remaining rows
        append_df = sample_packet_df.tail(3)
        DataStore.append_packets(append_df, str(filepath))

        loaded_df = pl.read_parquet(filepath)
        assert len(loaded_df) == len(sample_packet_df)


# ============================================================================
# TEST CLASS: DataStore Validation Operations
# ============================================================================


class TestDataStoreValidateParquet:
    """Test DataStore.validate_parquet() method."""

    def test_validate_valid_parquet(self, sample_packet_df, temp_dir):
        """Test that valid parquet files return True."""
        filepath = temp_dir / "valid.parquet"
        sample_packet_df.write_parquet(filepath)

        assert DataStore.validate_parquet(str(filepath)) is True

    def test_validate_nonexistent_file(self):
        """Test that non-existent files return False."""
        assert DataStore.validate_parquet("/nonexistent/file.parquet") is False

    def test_validate_invalid_file(self, temp_dir):
        """Test that invalid files return False."""
        filepath = temp_dir / "invalid.parquet"
        filepath.write_text("Not a parquet file")

        assert DataStore.validate_parquet(str(filepath)) is False

    def test_validate_empty_parquet(self, temp_dir):
        """Test that empty parquet files are valid."""
        filepath = temp_dir / "empty.parquet"
        pl.DataFrame().write_parquet(filepath)

        assert DataStore.validate_parquet(str(filepath)) is True


# ============================================================================
# TEST CLASS: DataStore Round-Trip Operations
# ============================================================================


class TestDataStoreRoundTrip:
    """Test save/load round-trip data integrity."""

    def test_round_trip_preserves_shape(self, sample_packet_df, temp_dir):
        """Test that round-trip preserves DataFrame shape."""
        filepath = temp_dir / "test.parquet"

        DataStore.save_packets(sample_packet_df, str(filepath))
        loaded_df = DataStore.load_packets(str(filepath))

        assert loaded_df.shape == sample_packet_df.shape

    def test_round_trip_preserves_columns(self, sample_packet_df, temp_dir):
        """Test that round-trip preserves column names."""
        filepath = temp_dir / "test.parquet"

        DataStore.save_packets(sample_packet_df, str(filepath))
        loaded_df = DataStore.load_packets(str(filepath))

        assert loaded_df.columns == sample_packet_df.columns

    def test_round_trip_large_file(self, large_packet_df, temp_dir):
        """Test round-trip with larger files."""
        filepath = temp_dir / "large.parquet"

        DataStore.save_packets(large_packet_df, str(filepath))
        loaded_df = DataStore.load_packets(str(filepath))

        assert loaded_df.shape == large_packet_df.shape

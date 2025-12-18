"""Tests for preprocessing error classes."""

import pytest

from network_security_suite.ml.preprocessing.errors import (
    AnalyzerNotInitializedError,
    EmptyDataFrameError,
    FileNotFoundError,
    InvalidFileFormatError,
    InvalidIPAddressError,
    InvalidProtocolError,
    InvalidThresholdError,
    InvalidTimeWindowError,
    MissingColumnError,
    ParquetAnalysisError,
)


class TestParquetAnalysisError:
    """Test base ParquetAnalysisError class."""

    def test_base_exception_creation(self):
        """Test that base exception can be created."""
        error = ParquetAnalysisError("Test error")
        assert str(error) == "Test error"
        assert isinstance(error, Exception)


class TestInvalidProtocolError:
    """Test InvalidProtocolError exception."""

    def test_invalid_protocol_error_creation(self):
        """Test InvalidProtocolError with protocol and valid protocols."""
        valid_protocols = {"TCP", "UDP", "ICMP"}
        error = InvalidProtocolError("HTTP", valid_protocols)
        assert error.protocol == "HTTP"
        assert error.valid_protocols == valid_protocols
        assert "Invalid protocol: 'HTTP'" in str(error)
        assert "ICMP" in str(error)
        assert "TCP" in str(error)
        assert "UDP" in str(error)

    def test_invalid_protocol_error_message_format(self):
        """Test error message formatting."""
        valid_protocols = {"TCP", "UDP"}
        error = InvalidProtocolError("INVALID", valid_protocols)
        error_msg = str(error)
        assert "INVALID" in error_msg
        assert "Valid protocols are:" in error_msg


class TestMissingColumnError:
    """Test MissingColumnError exception."""

    def test_missing_column_error_without_available_columns(self):
        """Test MissingColumnError without available columns list."""
        error = MissingColumnError("timestamp")
        assert error.column == "timestamp"
        assert error.available_columns is None
        assert "Required column 'timestamp' not found" in str(error)

    def test_missing_column_error_with_few_columns(self):
        """Test MissingColumnError with few available columns."""
        available = ["col1", "col2", "col3"]
        error = MissingColumnError("timestamp", available)
        assert error.column == "timestamp"
        assert error.available_columns == available
        error_msg = str(error)
        assert "timestamp" in error_msg
        assert "col1" in error_msg
        assert "col2" in error_msg
        assert "col3" in error_msg

    def test_missing_column_error_with_many_columns(self):
        """Test MissingColumnError with many columns (should truncate)."""
        available = [f"col{i}" for i in range(20)]
        error = MissingColumnError("timestamp", available)
        error_msg = str(error)
        assert "timestamp" in error_msg
        assert "(20 total)" in error_msg


class TestInvalidTimeWindowError:
    """Test InvalidTimeWindowError exception."""

    def test_invalid_time_window_error(self):
        """Test InvalidTimeWindowError creation and message."""
        error = InvalidTimeWindowError("invalid")
        assert error.time_window == "invalid"
        error_msg = str(error)
        assert "Invalid time window format: 'invalid'" in error_msg
        assert "ms" in error_msg
        assert "s" in error_msg
        assert "m" in error_msg
        assert "h" in error_msg
        assert "d" in error_msg
        assert "Examples:" in error_msg


class TestEmptyDataFrameError:
    """Test EmptyDataFrameError exception."""

    def test_empty_dataframe_error_without_operation(self):
        """Test EmptyDataFrameError without specific operation."""
        error = EmptyDataFrameError()
        assert "Cannot perform operation on empty DataFrame" in str(error)

    def test_empty_dataframe_error_with_operation(self):
        """Test EmptyDataFrameError with specific operation."""
        error = EmptyDataFrameError("aggregation")
        assert "Cannot perform 'aggregation' on empty DataFrame" in str(error)


class TestInvalidThresholdError:
    """Test InvalidThresholdError exception."""

    def test_invalid_threshold_error_without_message(self):
        """Test InvalidThresholdError without custom message."""
        error = InvalidThresholdError(-1)
        assert error.threshold == -1
        assert "Invalid threshold: -1" in str(error)

    def test_invalid_threshold_error_with_message(self):
        """Test InvalidThresholdError with custom message."""
        error = InvalidThresholdError(150, "Must be between 0 and 100")
        assert error.threshold == 150
        error_msg = str(error)
        assert "Invalid threshold: 150" in error_msg
        assert "Must be between 0 and 100" in error_msg


class TestInvalidIPAddressError:
    """Test InvalidIPAddressError exception."""

    def test_invalid_ip_address_error(self):
        """Test InvalidIPAddressError creation and message."""
        error = InvalidIPAddressError("not.an.ip")
        assert error.ip_address == "not.an.ip"
        assert "Invalid IP address format: 'not.an.ip'" in str(error)


class TestAnalyzerNotInitializedError:
    """Test AnalyzerNotInitializedError exception."""

    def test_analyzer_not_initialized_error(self):
        """Test AnalyzerNotInitializedError creation and message."""
        error = AnalyzerNotInitializedError("tcp")
        assert error.analyzer_name == "tcp"
        error_msg = str(error)
        assert "Analyzer 'tcp' not initialized" in error_msg
        assert "required protocol columns" in error_msg


class TestFileNotFoundError:
    """Test FileNotFoundError exception."""

    def test_file_not_found_error(self):
        """Test FileNotFoundError creation and message."""
        error = FileNotFoundError("/path/to/file.parquet")
        assert error.file_path == "/path/to/file.parquet"
        assert "Parquet file not found: '/path/to/file.parquet'" in str(error)


class TestInvalidFileFormatError:
    """Test InvalidFileFormatError exception."""

    def test_invalid_file_format_error_without_original_error(self):
        """Test InvalidFileFormatError without original error."""
        error = InvalidFileFormatError("/path/to/file.parquet")
        assert error.file_path == "/path/to/file.parquet"
        assert error.original_error is None
        assert "Invalid parquet file format: '/path/to/file.parquet'" in str(error)

    def test_invalid_file_format_error_with_original_error(self):
        """Test InvalidFileFormatError with original error."""
        original = ValueError("Not a parquet file")
        error = InvalidFileFormatError("/path/to/file.parquet", original)
        assert error.file_path == "/path/to/file.parquet"
        assert error.original_error == original
        error_msg = str(error)
        assert "/path/to/file.parquet" in error_msg
        assert "Not a parquet file" in error_msg

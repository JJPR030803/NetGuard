"""Tests for ParquetAnalysisFacade class.

Note: This tests the backwards-compatible NetworkParquetAnalysis alias
as well as the new ParquetAnalysisFacade class.
"""

import json
import unittest
from datetime import datetime

import polars as pl
import pytest

from netguard.analysis.facade import ParquetAnalysisFacade
from netguard.core.errors import (
    FileNotFoundError,
    InvalidFileFormatError,
)
from netguard.workflows import NetworkParquetAnalysis  # Backwards compatibility alias


@pytest.fixture
def sample_parquet_file(tmp_path):
    """Create a sample parquet file for testing."""
    df = pl.DataFrame(
        {
            "timestamp": [
                datetime(2021, 1, 1, 12, 0, 0),
                datetime(2021, 1, 1, 12, 0, 1),
                datetime(2021, 1, 1, 12, 0, 2),
            ],
            "IP_src": ["192.168.1.1", "192.168.1.2", "192.168.1.1"],
            "IP_dst": ["8.8.8.8", "1.1.1.1", "8.8.8.8"],
            "IP_proto": [6, 17, 6],
            "IP_len": [100, 200, 150],
            "TCP_sport": [12345, None, 12346],
            "TCP_dport": [80, None, 443],
            "TCP_flags": ["S", None, "SA"],
            "UDP_sport": [None, 53000, None],
            "UDP_dport": [None, 53, None],
        }
    )

    file_path = tmp_path / "test.parquet"
    df.write_parquet(file_path)
    return str(file_path)


class TestParquetAnalysisFacadeInitialization:
    """Test ParquetAnalysisFacade initialization."""

    def test_file_not_found_error(self):
        """Test FileNotFoundError when file doesn't exist."""
        with pytest.raises(FileNotFoundError) as exc_info:
            ParquetAnalysisFacade("/nonexistent/file.parquet")
        assert "/nonexistent/file.parquet" in str(exc_info.value)

    def test_invalid_file_format(self, tmp_path):
        """Test InvalidFileFormatError with non-parquet file."""
        text_file = tmp_path / "test.txt"
        text_file.write_text("not a parquet file")

        with pytest.raises(InvalidFileFormatError):
            ParquetAnalysisFacade(str(text_file))

    def test_successful_initialization(self, sample_parquet_file):
        """Test successful initialization with valid parquet file."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        assert analysis.path == sample_parquet_file
        assert isinstance(analysis.df, pl.DataFrame)
        assert len(analysis.df) == 3

    def test_analyzers_initialized_eagerly(self, sample_parquet_file):
        """Test that analyzers are initialized eagerly (no lazy loading)."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        # TCP analyzer should be initialized during __init__
        # since we have TCP packets in sample data
        assert analysis._tcp is not None


class TestBackwardsCompatibilityAlias:
    """Test NetworkParquetAnalysis backwards compatibility alias."""

    def test_alias_is_same_class(self):
        """Test that NetworkParquetAnalysis is ParquetAnalysisFacade."""
        assert NetworkParquetAnalysis is ParquetAnalysisFacade

    def test_alias_works(self, sample_parquet_file):
        """Test that alias can be used to create instances."""
        analysis = NetworkParquetAnalysis(sample_parquet_file)
        assert isinstance(analysis, ParquetAnalysisFacade)
        assert len(analysis.df) == 3


class TestParquetAnalysisFacadeProtocols:
    """Test protocol filtering methods."""

    def test_get_by_protocol_tcp(self, sample_parquet_file):
        """Test filtering by TCP protocol."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        tcp_data = analysis.get_by_protocol("TCP")
        assert isinstance(tcp_data, pl.DataFrame)

    def test_get_by_protocol_udp(self, sample_parquet_file):
        """Test filtering by UDP protocol."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        udp_data = analysis.get_by_protocol("UDP")
        assert isinstance(udp_data, pl.DataFrame)

    def test_get_by_protocol_invalid(self, sample_parquet_file):
        """Test invalid protocol raises ValueError."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        with pytest.raises(ValueError, match="Invalid protocol"):
            analysis.get_by_protocol("INVALID")


class TestParquetAnalysisFacadeIPMethods:
    """Test IP-related methods."""

    def test_find_ip_information(self, sample_parquet_file):
        """Test finding IP information."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        ip_data = analysis.find_ip_information("192.168.1.1")
        assert isinstance(ip_data, pl.DataFrame)
        assert len(ip_data) == 2  # 192.168.1.1 appears twice in sample

    def test_find_nonexistent_ip(self, sample_parquet_file):
        """Test finding non-existent IP returns empty DataFrame."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        ip_data = analysis.find_ip_information("10.0.0.1")
        assert len(ip_data) == 0


class TestParquetAnalysisFacadeTimestamps:
    """Test timestamp-related methods."""

    def test_get_timestamps(self, sample_parquet_file):
        """Test getting all timestamps."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        timestamps = analysis.get_timestamps()
        assert isinstance(timestamps, pl.DataFrame)
        assert "timestamp" in timestamps.columns
        assert len(timestamps) == 3

    def test_get_timestamps_by_ip(self, sample_parquet_file):
        """Test getting timestamps for specific IP."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        timestamps = analysis.get_timestamps_by_ip("192.168.1.1")
        assert isinstance(timestamps, pl.DataFrame)
        assert len(timestamps) == 2


class TestParquetAnalysisFacadeBehavioralSummary:
    """Test behavioral summary methods."""

    def test_behavioral_summary_by_source_ip(self, sample_parquet_file):
        """Test behavioral summary grouped by source IP."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        summary = analysis.behavioral_summary(time_window="1m", group_by_col="source_ip")
        assert isinstance(summary, pl.DataFrame)

    def test_behavioral_summary_by_destination_ip(self, sample_parquet_file):
        """Test behavioral summary grouped by destination IP."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        summary = analysis.behavioral_summary(time_window="1m", group_by_col="destination_ip")
        assert isinstance(summary, pl.DataFrame)

    def test_behavioral_summary_invalid_column(self, sample_parquet_file):
        """Test behavioral summary with invalid column raises error."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        with pytest.raises(ValueError, match="must be"):
            analysis.behavioral_summary(group_by_col="invalid")


class TestParquetAnalysisFacadeGetters:
    """Test getter methods."""

    def test_get_dataframe(self, sample_parquet_file):
        """Test getting the underlying DataFrame."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        df = analysis.get_dataframe()
        assert isinstance(df, pl.DataFrame)
        assert len(df) == 3

    def test_get_schema(self, sample_parquet_file):
        """Test getting DataFrame schema."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        schema = analysis.get_schema()
        assert isinstance(schema, dict)
        assert "timestamp" in schema
        assert "IP_src" in schema

    def test_get_packet_count(self, sample_parquet_file):
        """Test getting packet count."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        count = analysis.get_packet_count()
        assert count == 3

    def test_get_date_range(self, sample_parquet_file):
        """Test getting date range."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        date_range = analysis.get_date_range()
        assert isinstance(date_range, dict)
        assert "start" in date_range
        assert "end" in date_range
        assert "duration" in date_range


class TestParquetAnalysisFacadeAnalyzers:
    """Test analyzer property access."""

    def test_tcp_analyzer_access(self, sample_parquet_file):
        """Test accessing TCP analyzer."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        # TCP analyzer should be initialized since we have TCP data
        assert analysis.tcp is not None

    def test_analyzer_none_when_no_data(self, tmp_path):
        """Test analyzer is None when no matching protocol data exists."""
        # Create a DataFrame without TCP packets
        df = pl.DataFrame(
            {
                "timestamp": [datetime(2021, 1, 1)],
                "IP_src": ["192.168.1.1"],
                "IP_dst": ["8.8.8.8"],
                "IP_proto": [1],  # ICMP, not TCP
            }
        )
        file_path = tmp_path / "no_tcp.parquet"
        df.write_parquet(file_path)

        analysis = ParquetAnalysisFacade(str(file_path))
        # TCP analyzer should be None since no TCP packets
        assert analysis.tcp is None

    def test_get_analyzers_available(self, sample_parquet_file):
        """Test getting available analyzers."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        available = analysis.get_analyzers_available()

        assert isinstance(available, dict)
        assert "tcp" in available
        assert "udp" in available
        assert "dns" in available
        assert "arp" in available
        assert "icmp" in available
        assert "flow" in available
        assert "ip" in available
        assert "anomaly" in available


class TestParquetAnalysisFacadeSummary:
    """Test summary generation methods."""

    def test_generate_summary(self, sample_parquet_file):
        """Test generating network summary."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        summary = analysis.generate_summary()

        assert isinstance(summary, dict)
        assert "file_info" in summary
        assert "date_range" in summary
        assert "packet_counts" in summary
        assert "analyzers_available" in summary

    def test_export_summary_json_string(self, sample_parquet_file):
        """Test exporting summary as JSON string."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        json_str = analysis.export_summary_report(format="json")

        assert isinstance(json_str, str)
        data = json.loads(json_str)
        assert "file_info" in data

    def test_export_summary_json_file(self, sample_parquet_file, tmp_path):
        """Test exporting summary to JSON file."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        output_file = tmp_path / "summary.json"

        result = analysis.export_summary_report(format="json", output=str(output_file))

        assert result is None
        assert output_file.exists()

    def test_export_summary_csv(self, sample_parquet_file, tmp_path):
        """Test exporting summary to CSV."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        output_file = tmp_path / "summary.csv"

        analysis.export_summary_report(format="csv", output=str(output_file))

        assert output_file.exists()

    def test_export_summary_parquet(self, sample_parquet_file, tmp_path):
        """Test exporting summary to parquet."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        output_file = tmp_path / "summary.parquet"

        analysis.export_summary_report(format="parquet", output=str(output_file))

        assert output_file.exists()

    def test_export_summary_invalid_format(self, sample_parquet_file):
        """Test exporting with invalid format raises error."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        with pytest.raises(ValueError, match="Unsupported format"):
            analysis.export_summary_report(format="invalid")


class TestParquetAnalysisFacadeDunderMethods:
    """Test dunder/magic methods."""

    def test_len(self, sample_parquet_file):
        """Test __len__ returns packet count."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        assert len(analysis) == 3

    def test_repr(self, sample_parquet_file):
        """Test __repr__ method."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        repr_str = repr(analysis)
        assert "ParquetAnalysisFacade" in repr_str
        assert "packets=3" in repr_str

    def test_str(self, sample_parquet_file):
        """Test __str__ method."""
        analysis = ParquetAnalysisFacade(sample_parquet_file)
        str_repr = str(analysis)
        assert "Network Analysis" in str_repr
        assert "3 packets" in str_repr

if __name__=="__main__":
    unittest.main()

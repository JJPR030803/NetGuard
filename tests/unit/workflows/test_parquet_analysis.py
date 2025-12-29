"""Tests for NetworkParquetAnalysis class."""

import json
from datetime import datetime

import polars as pl
import pytest

from netguard.core.errors import (
    AnalyzerNotInitializedError,
    FileNotFoundError,
    InvalidFileFormatError,
)
from netguard.workflows.parquet_analysis import (
    NetworkParquetAnalysis,
)


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


class TestNetworkParquetAnalysisInitialization:
    """Test NetworkParquetAnalysis initialization."""

    def test_file_not_found_error(self):
        """Test FileNotFoundError when file doesn't exist."""
        with pytest.raises(FileNotFoundError) as exc_info:
            NetworkParquetAnalysis("/nonexistent/file.parquet")
        assert "/nonexistent/file.parquet" in str(exc_info.value)

    def test_invalid_file_format(self, tmp_path):
        """Test InvalidFileFormatError with non-parquet file."""
        text_file = tmp_path / "test.txt"
        text_file.write_text("not a parquet file")

        with pytest.raises(InvalidFileFormatError):
            NetworkParquetAnalysis(str(text_file))

    def test_successful_initialization(self, sample_parquet_file):
        """Test successful initialization with valid parquet file."""
        analysis = NetworkParquetAnalysis(sample_parquet_file)
        assert analysis.path == sample_parquet_file
        assert isinstance(analysis.df, pl.DataFrame)
        assert len(analysis.df) == 3

    def test_lazy_load_initialization(self, sample_parquet_file):
        """Test initialization with lazy loading."""
        analysis = NetworkParquetAnalysis(sample_parquet_file, lazy_load=True)
        assert analysis._lazy_load is True
        # Analyzers should not be initialized yet
        assert analysis._tcp is None
        assert analysis._udp is None


class TestNetworkParquetAnalysisProtocols:
    """Test protocol filtering methods."""

    def test_get_by_protocol_tcp(self, sample_parquet_file):
        """Test filtering by TCP protocol."""
        analysis = NetworkParquetAnalysis(sample_parquet_file)
        tcp_data = analysis.get_by_protocol("TCP")
        assert isinstance(tcp_data, pl.DataFrame)

    def test_get_by_protocol_udp(self, sample_parquet_file):
        """Test filtering by UDP protocol."""
        analysis = NetworkParquetAnalysis(sample_parquet_file)
        udp_data = analysis.get_by_protocol("UDP")
        assert isinstance(udp_data, pl.DataFrame)

    def test_get_by_protocol_invalid(self, sample_parquet_file):
        """Test invalid protocol raises ValueError."""
        analysis = NetworkParquetAnalysis(sample_parquet_file)
        with pytest.raises(ValueError, match="Invalid protocol"):
            analysis.get_by_protocol("INVALID")


class TestNetworkParquetAnalysisIPMethods:
    """Test IP-related methods."""

    def test_find_ip_information(self, sample_parquet_file):
        """Test finding IP information."""
        analysis = NetworkParquetAnalysis(sample_parquet_file)
        ip_data = analysis.find_ip_information("192.168.1.1")
        assert isinstance(ip_data, pl.DataFrame)
        assert len(ip_data) == 2  # 192.168.1.1 appears twice in sample

    def test_find_nonexistent_ip(self, sample_parquet_file):
        """Test finding non-existent IP returns empty DataFrame."""
        analysis = NetworkParquetAnalysis(sample_parquet_file)
        ip_data = analysis.find_ip_information("10.0.0.1")
        assert len(ip_data) == 0


class TestNetworkParquetAnalysisTimestamps:
    """Test timestamp-related methods."""

    def test_get_timestamps(self, sample_parquet_file):
        """Test getting all timestamps."""
        analysis = NetworkParquetAnalysis(sample_parquet_file)
        timestamps = analysis.get_timestamps()
        assert isinstance(timestamps, pl.DataFrame)
        assert "timestamp" in timestamps.columns
        assert len(timestamps) == 3

    def test_get_timestamps_by_ip(self, sample_parquet_file):
        """Test getting timestamps for specific IP."""
        analysis = NetworkParquetAnalysis(sample_parquet_file)
        timestamps = analysis.get_timestamps_by_ip("192.168.1.1")
        assert isinstance(timestamps, pl.DataFrame)
        assert len(timestamps) == 2


class TestNetworkParquetAnalysisBehavioralSummary:
    """Test behavioral summary methods."""

    def test_behavioral_summary_by_source_ip(self, sample_parquet_file):
        """Test behavioral summary grouped by source IP."""
        analysis = NetworkParquetAnalysis(sample_parquet_file)
        summary = analysis.behavioral_summary(time_window="1m", group_by_col="source_ip")
        assert isinstance(summary, pl.DataFrame)

    def test_behavioral_summary_by_destination_ip(self, sample_parquet_file):
        """Test behavioral summary grouped by destination IP."""
        analysis = NetworkParquetAnalysis(sample_parquet_file)
        summary = analysis.behavioral_summary(time_window="1m", group_by_col="destination_ip")
        assert isinstance(summary, pl.DataFrame)

    def test_behavioral_summary_invalid_column(self, sample_parquet_file):
        """Test behavioral summary with invalid column raises error."""
        analysis = NetworkParquetAnalysis(sample_parquet_file)
        with pytest.raises(ValueError, match="must be one of"):
            analysis.behavioral_summary(group_by_col="invalid")

    def test_service_behavioral_summary(self, sample_parquet_file):
        """Test service behavioral summary."""
        analysis = NetworkParquetAnalysis(sample_parquet_file)
        summary = analysis.service_behavioral_summary(time_window="1m")
        assert isinstance(summary, pl.DataFrame)


class TestNetworkParquetAnalysisGetters:
    """Test getter methods."""

    def test_get_dataframe(self, sample_parquet_file):
        """Test getting the underlying DataFrame."""
        analysis = NetworkParquetAnalysis(sample_parquet_file)
        df = analysis.get_dataframe()
        assert isinstance(df, pl.DataFrame)
        assert len(df) == 3

    def test_get_schema(self, sample_parquet_file):
        """Test getting DataFrame schema."""
        analysis = NetworkParquetAnalysis(sample_parquet_file)
        schema = analysis.get_schema()
        assert isinstance(schema, dict)
        assert "timestamp" in schema
        assert "IP_src" in schema

    def test_get_packet_count(self, sample_parquet_file):
        """Test getting packet count."""
        analysis = NetworkParquetAnalysis(sample_parquet_file)
        count = analysis.get_packet_count()
        assert count == 3

    def test_get_date_range(self, sample_parquet_file):
        """Test getting date range."""
        analysis = NetworkParquetAnalysis(sample_parquet_file)
        date_range = analysis.get_date_range()
        assert isinstance(date_range, dict)
        assert "start" in date_range
        assert "end" in date_range
        assert "duration" in date_range


class TestNetworkParquetAnalysisAnalyzers:
    """Test analyzer property access."""

    def test_tcp_analyzer_access_eager(self, sample_parquet_file):
        """Test accessing TCP analyzer with eager loading."""
        analysis = NetworkParquetAnalysis(sample_parquet_file, lazy_load=False)
        # TCP analyzer should be initialized during __init__
        assert analysis._tcp is not None

    def test_tcp_analyzer_access_lazy(self, sample_parquet_file):
        """Test accessing TCP analyzer with lazy loading."""
        analysis = NetworkParquetAnalysis(sample_parquet_file, lazy_load=True)
        # Access the property to trigger lazy initialization
        tcp_analyzer = analysis.tcp
        assert tcp_analyzer is not None

    def test_analyzer_not_initialized_error_lazy(self, tmp_path):
        """Test AnalyzerNotInitializedError with lazy load and no TCP data."""
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

        analysis = NetworkParquetAnalysis(str(file_path), lazy_load=True)
        # Accessing TCP analyzer should raise error since no TCP packets
        with pytest.raises(AnalyzerNotInitializedError, match="tcp"):
            _ = analysis.tcp


class TestNetworkParquetAnalysisSummary:
    """Test summary generation methods."""

    def test_generate_network_summary(self, sample_parquet_file):
        """Test generating network summary."""
        analysis = NetworkParquetAnalysis(sample_parquet_file)
        summary = analysis.generate_network_summary()

        assert isinstance(summary, dict)
        assert "file_info" in summary
        assert "temporal" in summary
        assert "packet_counts" in summary
        assert "protocols" in summary

    def test_export_summary_json_string(self, sample_parquet_file):
        """Test exporting summary as JSON string."""
        analysis = NetworkParquetAnalysis(sample_parquet_file)
        json_str = analysis.export_summary_report(format="json")

        assert isinstance(json_str, str)
        data = json.loads(json_str)
        assert "file_info" in data

    def test_export_summary_json_file(self, sample_parquet_file, tmp_path):
        """Test exporting summary to JSON file."""
        analysis = NetworkParquetAnalysis(sample_parquet_file)
        output_file = tmp_path / "summary.json"

        result = analysis.export_summary_report(format="json", output=str(output_file))

        assert result is None
        assert output_file.exists()

    def test_export_summary_csv(self, sample_parquet_file, tmp_path):
        """Test exporting summary to CSV."""
        analysis = NetworkParquetAnalysis(sample_parquet_file)
        output_file = tmp_path / "summary.csv"

        analysis.export_summary_report(format="csv", output=str(output_file))

        assert output_file.exists()

    def test_export_summary_parquet(self, sample_parquet_file, tmp_path):
        """Test exporting summary to parquet."""
        analysis = NetworkParquetAnalysis(sample_parquet_file)
        output_file = tmp_path / "summary.parquet"

        analysis.export_summary_report(format="parquet", output=str(output_file))

        assert output_file.exists()

    def test_export_summary_invalid_format(self, sample_parquet_file):
        """Test exporting with invalid format raises error."""
        analysis = NetworkParquetAnalysis(sample_parquet_file)
        with pytest.raises(ValueError, match="Unsupported format"):
            analysis.export_summary_report(format="invalid")

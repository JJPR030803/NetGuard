"""Unit tests for ParquetAnalysisFacade class.

This module tests the facade pattern implementation that provides
unified access to all protocol-specific analyzers.
"""

from datetime import datetime
from pathlib import Path

import polars as pl
import pytest

from netguard.analysis.analyzers.anomaly_analyzer import AnomalyAnalyzer
from netguard.analysis.analyzers.flow_analyzer import FlowAnalyzer
from netguard.analysis.analyzers.ip_analyzer import IpAnalyzer
from netguard.analysis.analyzers.tcp_analyzer import TcpAnalyzer
from netguard.analysis.analyzers.udp_analyzer import UdpAnalyzer
from netguard.analysis.base_analyzer import BaseAnalyzer
from netguard.analysis.facade import ParquetAnalysisFacade
from netguard.core.errors import InvalidFileFormatError

# ============================================================================
# TEST FIXTURES
# ============================================================================


@pytest.fixture
def mixed_protocol_df(base_timestamp) -> pl.DataFrame:
    """Create a DataFrame with multiple protocols for testing."""
    timestamps = [
        datetime(2024, 1, 1, 10, 0, 0),
        datetime(2024, 1, 1, 10, 0, 1),
        datetime(2024, 1, 1, 10, 0, 2),
        datetime(2024, 1, 1, 10, 0, 3),
        datetime(2024, 1, 1, 10, 0, 4),
        datetime(2024, 1, 1, 10, 0, 5),
        datetime(2024, 1, 1, 10, 0, 6),
        datetime(2024, 1, 1, 10, 0, 7),
    ]
    return pl.DataFrame(
        {
            "timestamp": timestamps,
            "IP_src": [
                "192.168.1.100",
                "192.168.1.101",
                "192.168.1.100",
                "192.168.1.102",
                "192.168.1.100",
                "192.168.1.101",
                "192.168.1.100",
                "192.168.1.103",
            ],
            "IP_dst": [
                "8.8.8.8",
                "1.1.1.1",
                "93.184.216.34",
                "8.8.4.4",
                "8.8.8.8",
                "1.1.1.1",
                "93.184.216.34",
                "8.8.4.4",
            ],
            "IP_proto": [6, 6, 17, 17, 6, 17, 1, 6],  # TCP, TCP, UDP, UDP, TCP, UDP, ICMP, TCP
            "IP_len": [60, 120, 80, 45, 64, 100, 64, 200],
            "IP_flags": ["DF", "DF", "", "", "MF", "", "", "DF"],
            "TCP_sport": [50000, 50001, None, None, 50002, None, None, 50003],
            "TCP_dport": [80, 443, None, None, 22, None, None, 8080],
            "TCP_flags": ["S", "SA", None, None, "A", None, None, "FA"],
            "UDP_sport": [None, None, 53, 123, None, 5353, None, None],
            "UDP_dport": [None, None, 53, 123, None, 5353, None, None],
        }
    )


@pytest.fixture
def tcp_only_df(base_timestamp) -> pl.DataFrame:
    """Create a DataFrame with only TCP traffic."""
    return pl.DataFrame(
        {
            "timestamp": [base_timestamp] * 3,
            "IP_src": ["192.168.1.100", "192.168.1.101", "192.168.1.102"],
            "IP_dst": ["8.8.8.8", "1.1.1.1", "93.184.216.34"],
            "IP_proto": [6, 6, 6],
            "IP_len": [60, 120, 80],
            "TCP_sport": [50000, 50001, 50002],
            "TCP_dport": [80, 443, 22],
            "TCP_flags": ["S", "SA", "A"],
        }
    )


@pytest.fixture
def test_parquet_file(mixed_protocol_df, temp_dir) -> Path:
    """Create a test parquet file."""
    filepath = temp_dir / "test_capture.parquet"
    mixed_protocol_df.write_parquet(filepath)
    return filepath


@pytest.fixture
def tcp_parquet_file(tcp_only_df, temp_dir) -> Path:
    """Create a test parquet file with only TCP traffic."""
    filepath = temp_dir / "tcp_capture.parquet"
    tcp_only_df.write_parquet(filepath)
    return filepath


@pytest.fixture
def empty_parquet_file(temp_dir) -> Path:
    """Create an empty parquet file."""
    filepath = temp_dir / "empty.parquet"
    empty_df = pl.DataFrame(
        {
            "timestamp": [],
            "IP_src": [],
            "IP_dst": [],
            "IP_proto": [],
        }
    )
    empty_df.write_parquet(filepath)
    return filepath


# ============================================================================
# TEST CLASS: ParquetAnalysisFacade Initialization
# ============================================================================


class TestParquetAnalysisFacadeInitialization:
    """Test ParquetAnalysisFacade initialization."""

    def test_init_with_valid_file(self, test_parquet_file):
        """Test initialization with a valid parquet file."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))

        assert facade.df is not None
        assert len(facade.df) == 8

    def test_init_stores_path(self, test_parquet_file):
        """Test that initialization stores the file path."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))

        assert facade.path == str(test_parquet_file)

    def test_init_file_not_found(self):
        """Test initialization with non-existent file raises error."""
        with pytest.raises(FileNotFoundError):
            ParquetAnalysisFacade("/nonexistent/file.parquet")

    def test_init_invalid_file(self, temp_dir):
        """Test initialization with invalid file raises error."""
        invalid_file = temp_dir / "invalid.parquet"
        invalid_file.write_text("Not a parquet file")

        with pytest.raises(InvalidFileFormatError):
            ParquetAnalysisFacade(str(invalid_file))

    def test_init_initializes_all_analyzers(self, test_parquet_file):
        """Test that initialization creates all analyzer instances."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))

        # At least some analyzers should be initialized
        assert facade.ip is not None
        assert facade.anomaly is not None
        assert facade.flow is not None


# ============================================================================
# TEST CLASS: ParquetAnalysisFacade Analyzer Properties
# ============================================================================


class TestParquetAnalysisFacadeAnalyzers:
    """Test ParquetAnalysisFacade analyzer properties."""

    def test_tcp_analyzer_property(self, test_parquet_file):
        """Test tcp property returns TcpAnalyzer or None."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))

        # Should have TCP traffic in mixed_protocol_df
        assert facade.tcp is not None
        assert isinstance(facade.tcp, TcpAnalyzer)

    def test_udp_analyzer_property(self, test_parquet_file):
        """Test udp property returns UdpAnalyzer or None."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))

        # Should have UDP traffic in mixed_protocol_df
        assert facade.udp is not None
        assert isinstance(facade.udp, UdpAnalyzer)

    def test_ip_analyzer_property(self, test_parquet_file):
        """Test ip property returns IpAnalyzer."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))

        assert facade.ip is not None
        assert isinstance(facade.ip, IpAnalyzer)

    def test_flow_analyzer_property(self, test_parquet_file):
        """Test flow property returns FlowAnalyzer."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))

        assert facade.flow is not None
        assert isinstance(facade.flow, FlowAnalyzer)

    def test_anomaly_analyzer_property(self, test_parquet_file):
        """Test anomaly property returns AnomalyAnalyzer."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))

        assert facade.anomaly is not None
        assert isinstance(facade.anomaly, AnomalyAnalyzer)

    def test_analyzer_none_when_no_protocol_data(self, tcp_parquet_file):
        """Test analyzer is None when no matching protocol data exists."""
        facade = ParquetAnalysisFacade(str(tcp_parquet_file))

        # No UDP traffic in tcp_only_df
        assert facade.udp is None


# ============================================================================
# TEST CLASS: ParquetAnalysisFacade Query Methods
# ============================================================================


class TestParquetAnalysisFacadeQueryMethods:
    """Test ParquetAnalysisFacade query methods."""

    def test_get_by_protocol_tcp(self, test_parquet_file):
        """Test get_by_protocol for TCP."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))
        result = facade.get_by_protocol("TCP")

        assert isinstance(result, pl.DataFrame)
        # Should contain TCP columns
        assert any("TCP" in col for col in result.columns)

    def test_get_by_protocol_invalid(self, test_parquet_file):
        """Test get_by_protocol with invalid protocol raises error."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))

        with pytest.raises(ValueError, match="Invalid protocol"):
            facade.get_by_protocol("INVALID")

    def test_find_ip_information(self, test_parquet_file):
        """Test find_ip_information returns matching packets."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))
        result = facade.find_ip_information("192.168.1.100")

        assert isinstance(result, pl.DataFrame)
        assert len(result) > 0

    def test_find_ip_information_no_match(self, test_parquet_file):
        """Test find_ip_information with non-existent IP."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))
        result = facade.find_ip_information("10.10.10.10")

        assert len(result) == 0

    def test_get_timestamps(self, test_parquet_file):
        """Test get_timestamps returns timestamp columns."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))
        result = facade.get_timestamps()

        assert isinstance(result, pl.DataFrame)
        assert "timestamp" in result.columns


# ============================================================================
# TEST CLASS: ParquetAnalysisFacade Metadata Methods
# ============================================================================


class TestParquetAnalysisFacadeMetadata:
    """Test ParquetAnalysisFacade metadata methods."""

    def test_get_dataframe(self, test_parquet_file, mixed_protocol_df):
        """Test get_dataframe returns the underlying DataFrame."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))
        df = facade.get_dataframe()

        assert isinstance(df, pl.DataFrame)
        assert df.shape == mixed_protocol_df.shape

    def test_get_schema(self, test_parquet_file):
        """Test get_schema returns column types."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))
        schema = facade.get_schema()

        assert isinstance(schema, dict)
        assert "timestamp" in schema
        assert "IP_src" in schema

    def test_get_packet_count(self, test_parquet_file):
        """Test get_packet_count returns correct count."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))
        count = facade.get_packet_count()

        assert count == 8

    def test_get_date_range(self, test_parquet_file):
        """Test get_date_range returns temporal info."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))
        date_range = facade.get_date_range()

        assert isinstance(date_range, dict)
        assert "start" in date_range
        assert "end" in date_range
        assert "duration" in date_range

    def test_get_analyzers_available(self, test_parquet_file):
        """Test get_analyzers_available returns availability dict."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))
        available = facade.get_analyzers_available()

        assert isinstance(available, dict)
        expected_keys = ["tcp", "udp", "dns", "arp", "icmp", "flow", "ip", "anomaly"]
        for key in expected_keys:
            assert key in available
            assert isinstance(available[key], bool)


# ============================================================================
# TEST CLASS: ParquetAnalysisFacade Summary Methods
# ============================================================================


class TestParquetAnalysisFacadeSummary:
    """Test ParquetAnalysisFacade summary methods."""

    def test_generate_summary_returns_dict(self, test_parquet_file):
        """Test generate_summary returns a dictionary."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))
        summary = facade.generate_summary()

        assert isinstance(summary, dict)

    def test_generate_summary_contains_required_sections(self, test_parquet_file):
        """Test generate_summary contains all required sections."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))
        summary = facade.generate_summary()

        required_sections = ["file_info", "packet_counts", "date_range", "analyzers_available"]
        for section in required_sections:
            assert section in summary, f"Missing section: {section}"

    def test_generate_summary_packet_counts(self, test_parquet_file):
        """Test generate_summary packet counts are correct."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))
        summary = facade.generate_summary()

        assert summary["packet_counts"]["total"] == 8

    def test_export_summary_report_json(self, test_parquet_file):
        """Test export_summary_report with JSON format."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))
        json_str = facade.export_summary_report(format="json")

        assert isinstance(json_str, str)
        assert "file_info" in json_str

    def test_export_summary_report_json_file(self, test_parquet_file, temp_dir):
        """Test export_summary_report saves JSON to file."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))
        output_path = temp_dir / "summary.json"

        facade.export_summary_report(format="json", output=str(output_path))

        assert output_path.exists()
        content = output_path.read_text()
        assert "file_info" in content

    def test_export_summary_report_csv(self, test_parquet_file, temp_dir):
        """Test export_summary_report with CSV format."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))
        output_path = temp_dir / "summary.csv"

        facade.export_summary_report(format="csv", output=str(output_path))

        assert output_path.exists()

    def test_export_summary_report_invalid_format(self, test_parquet_file):
        """Test export_summary_report with invalid format raises error."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))

        with pytest.raises(ValueError, match="Unsupported format"):
            facade.export_summary_report(format="invalid")


# ============================================================================
# TEST CLASS: ParquetAnalysisFacade Behavioral Analysis
# ============================================================================


class TestParquetAnalysisFacadeBehavioral:
    """Test ParquetAnalysisFacade behavioral analysis methods."""

    def test_behavioral_summary_returns_dataframe(self, test_parquet_file):
        """Test behavioral_summary returns a DataFrame."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))
        result = facade.behavioral_summary(time_window="1m", group_by_col="source_ip")

        assert isinstance(result, pl.DataFrame)

    def test_behavioral_summary_invalid_group_by(self, test_parquet_file):
        """Test behavioral_summary with invalid group_by raises error."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))

        with pytest.raises(ValueError, match="group_by_col must be"):
            facade.behavioral_summary(group_by_col="invalid")


# ============================================================================
# TEST CLASS: ParquetAnalysisFacade Dunder Methods
# ============================================================================


class TestParquetAnalysisFacadeDunderMethods:
    """Test ParquetAnalysisFacade dunder methods."""

    def test_repr(self, test_parquet_file):
        """Test __repr__ returns technical representation."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))
        repr_str = repr(facade)

        assert "ParquetAnalysisFacade" in repr_str
        assert "packets=8" in repr_str

    def test_str(self, test_parquet_file):
        """Test __str__ returns human-readable string."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))
        str_output = str(facade)

        assert "Network Analysis" in str_output
        assert "8 packets" in str_output

    def test_len(self, test_parquet_file):
        """Test __len__ returns packet count."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))

        assert len(facade) == 8


# ============================================================================
# TEST CLASS: ParquetAnalysisFacade Integration
# ============================================================================


class TestParquetAnalysisFacadeIntegration:
    """Test ParquetAnalysisFacade integration scenarios."""

    def test_facade_pattern_usage(self, test_parquet_file):
        """Test typical facade pattern usage."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))

        # Access multiple analyzers through facade
        assert facade.tcp is not None or facade.udp is not None
        assert facade.ip is not None

        # Generate summary
        summary = facade.generate_summary()
        assert summary["packet_counts"]["total"] == 8

    def test_empty_file_handling(self, empty_parquet_file):
        """Test handling of empty parquet files."""
        facade = ParquetAnalysisFacade(str(empty_parquet_file))

        assert len(facade) == 0
        assert facade.tcp is None  # No TCP traffic
        assert facade.udp is None  # No UDP traffic

        # Summary should still work
        summary = facade.generate_summary()
        assert summary["packet_counts"]["total"] == 0

    def test_analyzer_inheritance_from_base(self, test_parquet_file):
        """Test that all analyzers inherit from BaseAnalyzer."""
        facade = ParquetAnalysisFacade(str(test_parquet_file))

        analyzers = [facade.tcp, facade.udp, facade.ip, facade.flow, facade.anomaly]

        for analyzer in analyzers:
            if analyzer is not None:
                assert isinstance(analyzer, BaseAnalyzer)
                # Verify inherited methods work
                assert hasattr(analyzer, "packet_count")
                assert hasattr(analyzer, "is_empty")
                assert hasattr(analyzer, "has_column")

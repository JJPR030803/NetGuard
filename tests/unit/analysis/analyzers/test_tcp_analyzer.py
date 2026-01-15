"""Tests for TCP analyzer."""

import unittest
from datetime import datetime

import polars as pl
import pytest

from netguard.analysis.analyzers.tcp_analyzer import TcpAnalyzer
from netguard.core.errors import (
    EmptyDataFrameError,
    MissingColumnError,
)


@pytest.fixture
def tcp_dataframe():
    """Create a sample DataFrame with TCP packets."""
    return pl.DataFrame(
        {
            "timestamp": [
                datetime(2021, 1, 1, 12, 0, 0),
                datetime(2021, 1, 1, 12, 0, 1),
                datetime(2021, 1, 1, 12, 0, 2),
                datetime(2021, 1, 1, 12, 0, 3),
                datetime(2021, 1, 1, 12, 0, 4),
            ],
            "IP_proto": [6, 6, 6, 6, 6],
            "IP_src": [
                "192.168.1.1",
                "8.8.8.8",
                "192.168.1.1",
                "192.168.1.1",
                "8.8.8.8",
            ],
            "IP_dst": [
                "8.8.8.8",
                "192.168.1.1",
                "8.8.8.8",
                "8.8.8.8",
                "192.168.1.1",
            ],
            "IP_len": [60, 60, 100, 100, 60],
            "TCP_sport": [12345, 80, 12345, 12345, 80],
            "TCP_dport": [80, 12345, 80, 80, 12345],
            "TCP_flags": ["S", "SA", "A", "PA", "F"],
            "TCP_seq": [1000, 2000, 1001, 1002, 2001],
            "TCP_window": [65535, 65535, 65535, 32768, 32768],
        }
    )


@pytest.fixture
def mixed_dataframe():
    """Create a DataFrame with mixed protocols."""
    return pl.DataFrame(
        {
            "IP_proto": [6, 17, 6, 1],
            "IP_src": ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4"],
            "TCP_flags": ["S", None, "A", None],
        }
    )


class TestTcpAnalyzerInitialization:
    """Test TcpAnalyzer initialization."""

    def test_initialization_success(self, tcp_dataframe):
        """Test successful initialization with TCP data."""
        analyzer = TcpAnalyzer(tcp_dataframe)
        assert analyzer._packet_count == 5
        assert len(analyzer.df) == 5

    def test_empty_dataframe_error(self):
        """Test EmptyDataFrameError with empty DataFrame."""
        df = pl.DataFrame()
        with pytest.raises(EmptyDataFrameError, match="Input DataFrame is empty"):
            TcpAnalyzer(df)

    def test_missing_protocol_column_error(self):
        """Test MissingColumnError when IP_proto is missing."""
        df = pl.DataFrame({"IP_src": ["192.168.1.1"], "TCP_flags": ["S"]})
        with pytest.raises(MissingColumnError, match="IP_proto"):
            TcpAnalyzer(df)

    def test_no_tcp_packets_error(self):
        """Test EmptyDataFrameError when no TCP packets exist."""
        df = pl.DataFrame({"IP_proto": [17, 1]})  # UDP and ICMP only
        with pytest.raises(EmptyDataFrameError, match="No TCP packets found"):
            TcpAnalyzer(df)

    def test_filters_only_tcp(self, mixed_dataframe):
        """Test that analyzer only keeps TCP packets."""
        analyzer = TcpAnalyzer(mixed_dataframe)
        assert len(analyzer.df) == 2  # Only 2 TCP packets

    def test_repr(self, tcp_dataframe):
        """Test __repr__ method."""
        analyzer = TcpAnalyzer(tcp_dataframe)
        repr_str = repr(analyzer)
        assert "TcpAnalyzer" in repr_str
        assert "packets=5" in repr_str

    def test_str(self, tcp_dataframe):
        """Test __str__ method."""
        analyzer = TcpAnalyzer(tcp_dataframe)
        str_repr = str(analyzer)
        assert "TcpAnalyzer" in str_repr
        assert "5 packets" in str_repr

    def test_equality(self, tcp_dataframe):
        """Test __eq__ method."""
        analyzer1 = TcpAnalyzer(tcp_dataframe)
        analyzer2 = TcpAnalyzer(tcp_dataframe)
        assert analyzer1 == analyzer2


class TestTcpAnalyzerConnectionMethods:
    """Test connection analysis methods."""

    def test_get_connection_success_ratio(self, tcp_dataframe):
        """Test connection success ratio calculation."""
        analyzer = TcpAnalyzer(tcp_dataframe)
        ratio = analyzer.get_connection_success_ratio()
        assert isinstance(ratio, float)
        assert 0.0 <= ratio <= 1.0

    def test_get_connection_success_ratio_missing_flags(self):
        """Test success ratio with missing TCP_flags column."""
        df = pl.DataFrame({"IP_proto": [6], "IP_src": ["192.168.1.1"]})
        analyzer = TcpAnalyzer(df)
        with pytest.raises(MissingColumnError, match="TCP_flags"):
            analyzer.get_connection_success_ratio()

    def test_detect_incomplete_connections(self, tcp_dataframe):
        """Test detecting incomplete connections."""
        analyzer = TcpAnalyzer(tcp_dataframe)
        incomplete = analyzer.detect_incomplete_connections()
        assert isinstance(incomplete, pl.DataFrame)

    def test_get_connection_duration_stats(self, tcp_dataframe):
        """Test connection duration statistics."""
        analyzer = TcpAnalyzer(tcp_dataframe)
        stats = analyzer.get_connection_duration_stats()
        assert isinstance(stats, dict)

    def test_identify_long_lived_connections(self, tcp_dataframe):
        """Test identifying long-lived connections."""
        analyzer = TcpAnalyzer(tcp_dataframe)
        long_lived = analyzer.identify_long_lived_connections("1s")
        assert isinstance(long_lived, pl.DataFrame)

    def test_identify_short_lived_connections(self, tcp_dataframe):
        """Test identifying short-lived connections."""
        analyzer = TcpAnalyzer(tcp_dataframe)
        short_lived = analyzer.identify_short_lived_connections("10s")
        assert isinstance(short_lived, pl.DataFrame)

    def test_get_handshake_analysis(self, tcp_dataframe):
        """Test TCP handshake analysis."""
        analyzer = TcpAnalyzer(tcp_dataframe)
        stats = analyzer.get_handshake_analysis()
        assert isinstance(stats, dict)
        assert "total_syn" in stats
        assert "total_syn_ack" in stats
        assert "total_ack" in stats
        assert "complete_handshakes" in stats
        assert "incomplete_handshakes" in stats


class TestTcpAnalyzerFlagMethods:
    """Test TCP flag analysis methods."""

    def test_get_flag_distribution(self, tcp_dataframe):
        """Test getting flag distribution."""
        analyzer = TcpAnalyzer(tcp_dataframe)
        distribution = analyzer.get_flag_distribution()
        assert isinstance(distribution, pl.DataFrame)
        assert "flag" in distribution.columns
        assert "count" in distribution.columns

    def test_get_syn_count(self, tcp_dataframe):
        """Test getting SYN count."""
        analyzer = TcpAnalyzer(tcp_dataframe)
        count = analyzer.get_syn_count()
        assert isinstance(count, int)
        assert count >= 1  # At least one SYN in sample data

    def test_get_rst_count(self, tcp_dataframe):
        """Test getting RST count."""
        analyzer = TcpAnalyzer(tcp_dataframe)
        count = analyzer.get_rst_count()
        assert isinstance(count, int)

    def test_get_fin_count(self, tcp_dataframe):
        """Test getting FIN count."""
        analyzer = TcpAnalyzer(tcp_dataframe)
        count = analyzer.get_fin_count()
        assert isinstance(count, int)
        assert count >= 1  # One FIN in sample data

    def test_get_ack_count(self, tcp_dataframe):
        """Test getting ACK count."""
        analyzer = TcpAnalyzer(tcp_dataframe)
        count = analyzer.get_ack_count()
        assert isinstance(count, int)
        assert count >= 1  # Multiple ACKs in sample data

    def test_get_psh_count(self, tcp_dataframe):
        """Test getting PSH count."""
        analyzer = TcpAnalyzer(tcp_dataframe)
        count = analyzer.get_psh_count()
        assert isinstance(count, int)

    def test_analyze_flag_sequences(self, tcp_dataframe):
        """Test analyzing flag sequences."""
        analyzer = TcpAnalyzer(tcp_dataframe)
        sequences = analyzer.analyze_flag_sequences()
        assert isinstance(sequences, pl.DataFrame)


class TestTcpAnalyzerPerformanceMethods:
    """Test performance analysis methods."""

    def test_get_window_size_stats(self, tcp_dataframe):
        """Test window size statistics."""
        analyzer = TcpAnalyzer(tcp_dataframe)
        stats = analyzer.get_window_size_stats()
        assert isinstance(stats, dict)
        if stats:  # May be empty if no window data
            assert "min" in stats
            assert "max" in stats
            assert "mean" in stats

    def test_detect_retransmissions(self, tcp_dataframe):
        """Test retransmission detection."""
        analyzer = TcpAnalyzer(tcp_dataframe)
        retrans = analyzer.detect_retransmissions()
        assert isinstance(retrans, pl.DataFrame)

    def test_get_throughput_by_connection(self, tcp_dataframe):
        """Test throughput calculation by connection."""
        analyzer = TcpAnalyzer(tcp_dataframe)
        throughput = analyzer.get_throughput_by_connection()
        assert isinstance(throughput, pl.DataFrame)


class TestTcpAnalyzerPortMethods:
    """Test port analysis methods."""

    def test_get_most_used_ports(self, tcp_dataframe):
        """Test getting most used ports."""
        analyzer = TcpAnalyzer(tcp_dataframe)
        ports = analyzer.get_most_used_ports(n=5)
        assert isinstance(ports, pl.DataFrame)
        assert "TCP_dport" in ports.columns or "count" in ports.columns

    def test_get_most_used_ports_custom_n(self, tcp_dataframe):
        """Test getting top N ports with custom N."""
        analyzer = TcpAnalyzer(tcp_dataframe)
        ports = analyzer.get_most_used_ports(n=2)
        assert len(ports) <= 2

    def test_detect_non_standard_ports(self, tcp_dataframe):
        """Test detecting non-standard ports."""
        analyzer = TcpAnalyzer(tcp_dataframe)
        non_standard = analyzer.detect_non_standard_ports()
        assert isinstance(non_standard, pl.DataFrame)

    def test_get_ephemeral_vs_wellknown_ratio(self, tcp_dataframe):
        """Test ephemeral vs well-known port ratio."""
        analyzer = TcpAnalyzer(tcp_dataframe)
        ratio = analyzer.get_ephemeral_vs_wellknown_ratio()
        assert isinstance(ratio, dict)
        assert "well_known" in ratio
        assert "registered" in ratio
        assert "ephemeral" in ratio
        assert "total" in ratio
        assert "ratios" in ratio


class TestTcpAnalyzerEdgeCases:
    """Test edge cases and error handling."""

    def test_with_null_values(self):
        """Test analyzer handles null values correctly."""
        df = pl.DataFrame(
            {
                "IP_proto": [6, 6, 6],
                "TCP_flags": ["S", None, "A"],
                "TCP_sport": [12345, None, 12346],
                "TCP_dport": [80, None, 443],
            }
        )
        analyzer = TcpAnalyzer(df)
        # Should not raise errors
        count = analyzer.get_syn_count()
        assert isinstance(count, int)

    def test_with_minimum_columns(self):
        """Test analyzer with minimum required columns."""
        df = pl.DataFrame({"IP_proto": [6, 6]})
        analyzer = TcpAnalyzer(df)
        assert len(analyzer.df) == 2


if __name__ == "__main__":
    unittest.main()

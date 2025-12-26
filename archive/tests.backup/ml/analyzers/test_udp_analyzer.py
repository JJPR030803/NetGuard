"""Tests for UDP analyzer."""

from datetime import datetime

import polars as pl
import pytest

from netguard.preprocessing.analyzers.udp_analyzer import UdpAnalyzer
from netguard.preprocessing.errors import (
    EmptyDataFrameError,
    InvalidThresholdError,
    MissingColumnError,
)


@pytest.fixture
def udp_dataframe():
    """Create a sample DataFrame with UDP packets."""
    return pl.DataFrame(
        {
            "timestamp": [datetime(2021, 1, 1, 12, 0, i) for i in range(5)],
            "IP_proto": [17, 17, 17, 17, 17],
            "IP_src": ["192.168.1.1", "192.168.1.2", "192.168.1.1", "8.8.8.8", "192.168.1.3"],
            "IP_dst": ["8.8.8.8", "1.1.1.1", "8.8.8.8", "192.168.1.1", "8.8.8.8"],
            "IP_len": [100, 200, 150, 80, 120],
            "UDP_sport": [53000, 53001, 53002, 53, 53003],
            "UDP_dport": [53, 53, 80, 53000, 443],
        }
    )


class TestUdpAnalyzerInitialization:
    """Test UdpAnalyzer initialization."""

    def test_initialization_success(self, udp_dataframe):
        """Test successful initialization."""
        analyzer = UdpAnalyzer(udp_dataframe)
        assert analyzer._packet_count == 5
        assert len(analyzer.df) == 5

    def test_empty_dataframe_error(self):
        """Test EmptyDataFrameError."""
        df = pl.DataFrame()
        with pytest.raises(EmptyDataFrameError):
            UdpAnalyzer(df)

    def test_no_udp_packets_error(self):
        """Test EmptyDataFrameError when no UDP packets."""
        df = pl.DataFrame({"IP_proto": [6, 1]})  # TCP and ICMP only
        with pytest.raises(EmptyDataFrameError):
            UdpAnalyzer(df)


class TestUdpAnalyzerMethods:
    """Test UDP analyzer methods."""

    def test_detect_unidirectional_traffic(self, udp_dataframe):
        """Test unidirectional traffic detection."""
        analyzer = UdpAnalyzer(udp_dataframe)
        result = analyzer.detect_unidirectional_traffic()
        assert isinstance(result, pl.DataFrame)

    def test_get_most_used_ports(self, udp_dataframe):
        """Test getting most used ports."""
        analyzer = UdpAnalyzer(udp_dataframe)
        result = analyzer.get_most_used_ports(n=5)
        assert isinstance(result, pl.DataFrame)

    def test_get_most_used_ports_invalid_n(self, udp_dataframe):
        """Test invalid n parameter."""
        analyzer = UdpAnalyzer(udp_dataframe)
        with pytest.raises(InvalidThresholdError):
            analyzer.get_most_used_ports(n=0)

    def test_get_udp_flow_stats(self, udp_dataframe):
        """Test UDP flow statistics."""
        analyzer = UdpAnalyzer(udp_dataframe)
        result = analyzer.get_udp_flow_stats()
        assert isinstance(result, pl.DataFrame)

    def test_calculate_packet_rate(self, udp_dataframe):
        """Test packet rate calculation."""
        analyzer = UdpAnalyzer(udp_dataframe)
        result = analyzer.calculate_packet_rate(time_window="1m")
        assert isinstance(result, pl.DataFrame)

    def test_detect_udp_flood(self, udp_dataframe):
        """Test UDP flood detection."""
        analyzer = UdpAnalyzer(udp_dataframe)
        result = analyzer.detect_udp_flood(threshold=2, time_window="1m")
        assert isinstance(result, pl.DataFrame)

    def test_detect_udp_amplification(self, udp_dataframe):
        """Test UDP amplification detection."""
        analyzer = UdpAnalyzer(udp_dataframe)
        result = analyzer.detect_udp_amplification(min_amplification_ratio=10.0)
        assert isinstance(result, pl.DataFrame)

    def test_identify_udp_scan(self, udp_dataframe):
        """Test UDP scan identification."""
        analyzer = UdpAnalyzer(udp_dataframe)
        result = analyzer.identify_udp_scan(threshold=2)
        assert isinstance(result, pl.DataFrame)

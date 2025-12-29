"""Tests for IP analyzer."""

from datetime import datetime

import polars as pl
import pytest

from netguard.analysis.analyzers.ip_analyzer import IpAnalyzer
from netguard.core.errors import (
    EmptyDataFrameError,
    InvalidThresholdError,
)


@pytest.fixture
def ip_dataframe():
    """Create a sample DataFrame with IP packets."""
    return pl.DataFrame(
        {
            "timestamp": [datetime(2021, 1, 1, 12, 0, i) for i in range(5)],
            "IP_src": [
                "192.168.1.1",
                "192.168.1.2",
                "192.168.1.1",
                "8.8.8.8",
                "192.168.1.1",
            ],
            "IP_dst": ["8.8.8.8", "1.1.1.1", "192.168.1.2", "192.168.1.1", "8.8.8.8"],
            "IP_len": [100, 200, 150, 80, 120],
            "IP_proto": [6, 17, 6, 6, 17],
        }
    )


class TestIpAnalyzerInitialization:
    """Test IpAnalyzer initialization."""

    def test_initialization_success(self, ip_dataframe):
        """Test successful initialization."""
        analyzer = IpAnalyzer(ip_dataframe)
        assert analyzer._packet_count == 5
        assert len(analyzer.df) == 5

    def test_empty_dataframe_error(self):
        """Test EmptyDataFrameError."""
        df = pl.DataFrame()
        with pytest.raises(EmptyDataFrameError):
            IpAnalyzer(df)

    def test_repr(self, ip_dataframe):
        """Test __repr__ method."""
        analyzer = IpAnalyzer(ip_dataframe)
        repr_str = repr(analyzer)
        assert "IpAnalyzer" in repr_str

    def test_str(self, ip_dataframe):
        """Test __str__ method."""
        analyzer = IpAnalyzer(ip_dataframe)
        str_repr = str(analyzer)
        assert "IP Analyzer" in str_repr


class TestIpAnalyzerMethods:
    """Test IP analyzer methods."""

    def test_get_most_active_ips_by_packets(self, ip_dataframe):
        """Test getting most active IPs by packets."""
        analyzer = IpAnalyzer(ip_dataframe)
        result = analyzer.get_most_active_ips(n=5, by="packets")
        assert isinstance(result, pl.DataFrame)

    def test_get_most_active_ips_by_bytes(self, ip_dataframe):
        """Test getting most active IPs by bytes."""
        analyzer = IpAnalyzer(ip_dataframe)
        result = analyzer.get_most_active_ips(n=5, by="bytes")
        assert isinstance(result, pl.DataFrame)

    def test_get_most_active_ips_invalid_by(self, ip_dataframe):
        """Test invalid by parameter."""
        analyzer = IpAnalyzer(ip_dataframe)
        with pytest.raises(ValueError, match="must be 'packets' or 'bytes'"):
            analyzer.get_most_active_ips(n=5, by="invalid")

    def test_get_sender_only_ips(self, ip_dataframe):
        """Test getting sender-only IPs."""
        analyzer = IpAnalyzer(ip_dataframe)
        result = analyzer.get_sender_only_ips()
        assert isinstance(result, pl.DataFrame)

    def test_get_receiver_only_ips(self, ip_dataframe):
        """Test getting receiver-only IPs."""
        analyzer = IpAnalyzer(ip_dataframe)
        result = analyzer.get_receiver_only_ips()
        assert isinstance(result, pl.DataFrame)

    def test_get_asymmetric_ips(self, ip_dataframe):
        """Test getting asymmetric IPs."""
        analyzer = IpAnalyzer(ip_dataframe)
        result = analyzer.get_asymmetric_ips(threshold=0.9)
        assert isinstance(result, pl.DataFrame)

    def test_get_asymmetric_ips_invalid_threshold(self, ip_dataframe):
        """Test invalid threshold."""
        analyzer = IpAnalyzer(ip_dataframe)
        with pytest.raises(InvalidThresholdError):
            analyzer.get_asymmetric_ips(threshold=1.5)

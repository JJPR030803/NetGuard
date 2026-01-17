"""
Unit tests for the PacketCapture class.

This module contains self-contained tests for the PacketCapture class,
including all necessary fixtures and mocks.
"""

import tempfile
from collections.abc import Generator
from pathlib import Path
from queue import Queue
from threading import Thread
from time import sleep
from typing import ClassVar
from unittest.mock import MagicMock, patch

import pandas as pd
import polars as pl
import pytest
from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.l2 import Ether

from netguard.capture.packet_capture import PacketCapture
from netguard.core.config import SnifferConfig
from netguard.models.packet_data_structures import (
    POLARS_AVAILABLE,
    Packet,
    PacketLayer,
)

# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def temp_log_dir() -> Generator[str, None, None]:
    """Create a temporary directory for logs and exports."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def sniffer_config(temp_log_dir: str) -> SnifferConfig:
    """Create a SnifferConfig for testing."""
    return SnifferConfig(
        interface="eth0",
        log_dir=temp_log_dir,
        export_dir=temp_log_dir,
        performance_parquet_path=f"{temp_log_dir}/performance.parquet",
    )


@pytest.fixture
def packet_capture(sniffer_config: SnifferConfig) -> PacketCapture:
    """Create a PacketCapture instance for testing."""
    return PacketCapture(config=sniffer_config)


@pytest.fixture
def sample_ethernet_layer() -> PacketLayer:
    """Create a sample Ethernet layer for testing."""
    return PacketLayer(
        layer_name="Ethernet",
        fields={"src_mac": "00:11:22:33:44:55", "dst_mac": "aa:bb:cc:dd:ee:ff"},
    )


@pytest.fixture
def sample_ip_layer() -> PacketLayer:
    """Create a sample IP layer for testing."""
    return PacketLayer(
        layer_name="IP",
        fields={"src": "192.168.1.1", "dst": "10.0.0.1"},
    )


@pytest.fixture
def sample_tcp_layer() -> PacketLayer:
    """Create a sample TCP layer for testing."""
    return PacketLayer(
        layer_name="TCP",
        fields={"sport": 12345, "dport": 80},
    )


@pytest.fixture
def sample_packet(sample_ethernet_layer: PacketLayer, sample_ip_layer: PacketLayer) -> Packet:
    """Create a sample packet with Ethernet and IP layers."""
    return Packet(
        timestamp=1234567890.0,
        layers=[sample_ethernet_layer, sample_ip_layer],
        raw_size=100,
    )


def create_mock_scapy_packet(
    timestamp: float = 1234567890.0,
    size: int = 100,
    has_layers: list | None = None,
) -> MagicMock:
    """
    Helper to create a mock Scapy packet.

    Args:
        timestamp: Packet timestamp.
        size: Packet size in bytes.
        has_layers: List of layer classes (e.g., [IP, TCP]) the packet should have.

    Returns:
        A configured MagicMock representing a Scapy packet.
    """
    mock_packet = MagicMock()
    mock_packet.time = timestamp
    mock_packet.__len__.return_value = size
    mock_packet.layers.return_value = []

    if has_layers is None:
        has_layers = []

    mock_packet.haslayer.side_effect = lambda x: x in has_layers
    return mock_packet


# ============================================================================
# TEST CLASS
# ============================================================================


class TestPacketCapture:
    """Test suite for PacketCapture class."""

    def test_init_with_config(self, sniffer_config: SnifferConfig) -> None:
        """Test PacketCapture initialization with config."""
        capture = PacketCapture(config=sniffer_config)

        assert capture.interface == sniffer_config.interface
        assert capture.config == sniffer_config
        assert isinstance(capture.packets, list)
        assert len(capture.packets) == 0
        assert capture.stats["processed_packets"] == 0
        assert capture.stats["dropped_packets"] == 0

    def test_init_with_default_config(self, temp_log_dir: str) -> None:
        """Test PacketCapture initialization with default config values."""
        config = SnifferConfig(
            interface="lo",
            log_dir=temp_log_dir,
            export_dir=temp_log_dir,
        )
        capture = PacketCapture(config=config)

        assert capture.interface == "lo"
        assert capture.max_memory_packets == config.max_memory_packets

    @pytest.mark.parametrize("max_packets", [1, 10, 100])
    @patch("netguard.capture.packet_capture.sniff")
    def test_capture_with_different_counts(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture, max_packets: int
    ) -> None:
        """Test packet capture with different packet counts."""
        mock_sniff.return_value = []

        packet_capture.capture(max_packets=max_packets)

        mock_sniff.assert_called_once()
        call_kwargs = mock_sniff.call_args[1]
        assert call_kwargs["iface"] == packet_capture.interface
        assert call_kwargs["count"] == max_packets

    @patch("netguard.capture.packet_capture.sniff")
    def test_capture_icmp_packet(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture
    ) -> None:
        """Test capturing ICMP packet."""
        mock_packet = MagicMock()
        mock_packet.haslayer.side_effect = lambda x: x in [IP, ICMP]
        mock_packet.__getitem__.side_effect = lambda _: MagicMock(
            type=8, code=0, chksum=0x1234, id=1, seq=1
        )
        mock_packet.time = 1234567890.0
        mock_packet.__len__.return_value = 100
        mock_packet.layers.return_value = []

        def sniff_side_effect(**kwargs):
            # Call the prn callback with our mock packet to simulate capture
            prn = kwargs.get("prn")
            if prn:
                prn(mock_packet)

        mock_sniff.side_effect = sniff_side_effect

        packet_capture.capture(max_packets=1)

        assert len(packet_capture.packets) == 1
        assert isinstance(packet_capture.packets[0], Packet)
        assert packet_capture.packets[0].has_layer("ICMP")

    def test_show_packets(self, packet_capture: PacketCapture) -> None:
        """Test showing captured packets does not raise exceptions."""
        layer = PacketLayer(layer_name="Test", fields={"field1": "value1", "field2": "value2"})
        packet = Packet(timestamp=1234567890.0, layers=[layer], raw_size=100)
        packet_capture.packets = [packet]

        # Should not raise
        packet_capture.show_packets()

    def test_show_stats(
        self,
        packet_capture: PacketCapture,
        sample_ethernet_layer: PacketLayer,
        sample_ip_layer: PacketLayer,
        sample_tcp_layer: PacketLayer,
    ) -> None:
        """Test showing capture statistics does not raise exceptions."""
        packet_capture.stats = {
            "processed_packets": 100,
            "dropped_packets": 5,
            "processing_time": 2.5,
            "batch_count": 10,
        }

        packet1 = Packet(
            timestamp=1234567890.0,
            layers=[sample_ethernet_layer, sample_ip_layer],
            raw_size=100,
        )
        packet2 = Packet(
            timestamp=1234567891.0,
            layers=[sample_ethernet_layer, sample_ip_layer, sample_tcp_layer],
            raw_size=120,
        )
        packet_capture.packets = [packet1, packet2]

        # Should not raise
        packet_capture.show_stats()

    def test_process_packet_layers_none_raises(self, packet_capture: PacketCapture) -> None:
        """Test that processing None packet raises ValueError."""
        with pytest.raises(ValueError):
            packet_capture.process_packet_layers(None)

    def test_process_packet_layers_missing_time(self, packet_capture: PacketCapture) -> None:
        """Test processing packet missing time attribute uses default timestamp."""
        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = False
        mock_packet.__len__.return_value = 100
        mock_packet.layers.return_value = []
        del mock_packet.time

        processed = packet_capture.process_packet_layers(mock_packet)

        assert processed.timestamp == 0.0
        assert processed.raw_size == 100
        assert len(processed.layers) == 0

    def test_process_packet_layers_ethernet(self, packet_capture: PacketCapture) -> None:
        """Test processing packet with Ethernet layer."""
        mock_packet = MagicMock()
        mock_packet.haslayer.side_effect = lambda x: x == Ether
        mock_packet.__getitem__.side_effect = lambda x: (
            MagicMock(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff", type=0x0800)
            if x == Ether
            else None
        )
        mock_packet.time = 1234567890.0
        mock_packet.__len__.return_value = 100
        mock_packet.layers.return_value = []

        processed = packet_capture.process_packet_layers(mock_packet)

        assert processed.timestamp == 1234567890.0
        assert processed.raw_size == 100
        assert len(processed.layers) == 1
        assert processed.layers[0].layer_name == "Ethernet"
        assert processed.layers[0].fields["dst_mac"] == "00:11:22:33:44:55"
        assert processed.layers[0].fields["src_mac"] == "aa:bb:cc:dd:ee:ff"
        assert processed.layers[0].fields["type"] == 0x0800

    def test_process_packet_layers_ip(self, packet_capture: PacketCapture) -> None:
        """Test processing packet with IP layer."""
        mock_packet = MagicMock()
        mock_packet.haslayer.side_effect = lambda x: x == IP
        mock_packet.__getitem__.side_effect = lambda x: (
            MagicMock(
                version=4,
                ihl=5,
                tos=0,
                len=20,
                id=12345,
                flags=0,
                frag=0,
                ttl=64,
                proto=6,
                chksum=0xABCD,
                src="192.168.1.1",
                dst="10.0.0.1",
                options=[],
            )
            if x == IP
            else None
        )
        mock_packet.time = 1234567890.0
        mock_packet.__len__.return_value = 100
        mock_packet.layers.return_value = []

        processed = packet_capture.process_packet_layers(mock_packet)

        assert processed.timestamp == 1234567890.0
        assert len(processed.layers) == 1
        assert processed.layers[0].layer_name == "IP"
        assert processed.layers[0].fields["version"] == 4
        assert processed.layers[0].fields["src"] == "192.168.1.1"
        assert processed.layers[0].fields["dst"] == "10.0.0.1"

    def test_process_packet_layers_tcp(self, packet_capture: PacketCapture) -> None:
        """Test processing packet with TCP layer."""
        mock_packet = MagicMock()
        mock_packet.haslayer.side_effect = lambda x: x == TCP
        mock_packet.__getitem__.side_effect = lambda x: (
            MagicMock(
                sport=12345,
                dport=80,
                seq=1000,
                ack=2000,
                dataofs=5,
                reserved=0,
                flags="PA",
                window=8192,
                chksum=0x1234,
                urgptr=0,
                options=[],
            )
            if x == TCP
            else None
        )
        mock_packet.time = 1234567890.0
        mock_packet.__len__.return_value = 100
        mock_packet.layers.return_value = []

        processed = packet_capture.process_packet_layers(mock_packet)

        assert len(processed.layers) == 1
        assert processed.layers[0].layer_name == "TCP"
        assert processed.layers[0].fields["sport"] == 12345
        assert processed.layers[0].fields["dport"] == 80
        assert processed.layers[0].fields["flags"] == "PA"

    def test_process_packet_layers_multiple(self, packet_capture: PacketCapture) -> None:
        """Test processing packet with multiple layers (IP + TCP)."""
        mock_packet = MagicMock()
        mock_packet.haslayer.side_effect = lambda x: x in [IP, TCP]

        def get_layer(layer_type):
            if layer_type == IP:
                return MagicMock(
                    version=4,
                    ihl=5,
                    tos=0,
                    len=40,
                    id=54321,
                    flags=0,
                    frag=0,
                    ttl=64,
                    proto=6,
                    chksum=0xDCBA,
                    src="192.168.1.100",
                    dst="10.0.0.100",
                    options=[],
                )
            elif layer_type == TCP:
                return MagicMock(
                    sport=54321,
                    dport=443,
                    seq=5000,
                    ack=6000,
                    dataofs=5,
                    reserved=0,
                    flags="S",
                    window=8192,
                    chksum=0x5678,
                    urgptr=0,
                    options=[],
                )
            return None

        mock_packet.__getitem__.side_effect = get_layer
        mock_packet.time = 1234567890.0
        mock_packet.__len__.return_value = 100
        mock_packet.layers.return_value = []

        processed = packet_capture.process_packet_layers(mock_packet)

        assert processed.timestamp == 1234567890.0
        assert len(processed.layers) == 2

        ip_layer = next((layer for layer in processed.layers if layer.layer_name == "IP"), None)
        assert ip_layer is not None
        assert ip_layer.fields["src"] == "192.168.1.100"
        assert ip_layer.fields["dst"] == "10.0.0.100"

        tcp_layer = next((layer for layer in processed.layers if layer.layer_name == "TCP"), None)
        assert tcp_layer is not None
        assert tcp_layer.fields["sport"] == 54321
        assert tcp_layer.fields["dport"] == 443
        assert tcp_layer.fields["flags"] == "S"

    def test_process_packet_layers_error_skips_layer(self, packet_capture: PacketCapture) -> None:
        """Test that layer processing errors are handled gracefully."""

        # Create a class that raises an error when accessing 'src'
        class BrokenIPLayer:
            version = 4
            ihl = 5
            tos = 0
            len = 20
            id = 12345
            flags = 0
            frag = 0
            ttl = 64
            proto = 6
            chksum = 0xABCD

            @property
            def src(self):
                raise AttributeError("src not available")

        mock_packet = MagicMock()
        mock_packet.haslayer.side_effect = lambda x: x == IP
        mock_packet.__getitem__.side_effect = lambda x: BrokenIPLayer() if x == IP else None
        mock_packet.time = 1234567890.0
        mock_packet.__len__.return_value = 100
        mock_packet.layers.return_value = []

        # Should not raise exception
        processed = packet_capture.process_packet_layers(mock_packet)
        assert processed.timestamp == 1234567890.0
        assert processed.raw_size == 100
        # Layer should be skipped due to error
        assert len(processed.layers) == 0

    def test_get_session_info_interface_types(self, packet_capture: PacketCapture) -> None:
        """Test session info for different interface types."""
        with (
            patch("platform.system", return_value="Linux"),
            patch("platform.version", return_value="5.10.0"),
            patch("platform.machine", return_value="x86_64"),
            patch("platform.processor", return_value="Intel(R) Core(TM) i7"),
        ):
            test_cases = [
                ("eth0", "ethernet"),
                ("wlan0", "wireless"),
                ("docker0", "docker"),
                ("veth0", "virtual"),
                ("tun0", "vpn"),
                ("lo", "loopback"),
                ("unknown0", "unknown"),
            ]

            for interface, expected_type in test_cases:
                packet_capture.interface = interface
                session_info = packet_capture._get_session_info()

                assert session_info["os"] == "Linux"
                assert session_info["interface"] == interface
                assert session_info["interface_type"] == expected_type

    def test_update_stats(self, packet_capture: PacketCapture) -> None:
        """Test updating statistics."""
        assert packet_capture.stats["processed_packets"] == 0
        assert packet_capture.stats["dropped_packets"] == 0
        assert packet_capture.stats["processing_time"] == 0.0
        assert packet_capture.stats["batch_count"] == 0

        packet_capture.update_stats(processing_time=1.5, batch_size=10)

        assert packet_capture.stats["processed_packets"] == 10
        assert packet_capture.stats["processing_time"] == 1.5
        assert packet_capture.stats["batch_count"] == 1

        packet_capture.update_stats(processing_time=2.0, batch_size=20)

        assert packet_capture.stats["processed_packets"] == 30
        assert packet_capture.stats["processing_time"] == 3.5
        assert packet_capture.stats["batch_count"] == 2

    def test_packet_callback(self, packet_capture: PacketCapture) -> None:
        """Test packet callback function."""
        mock_packet = create_mock_scapy_packet()

        packet_capture.packet_callback(mock_packet)

        assert len(packet_capture.packets) == 1
        assert packet_capture.packets[0].timestamp == 1234567890.0
        assert packet_capture.packets[0].raw_size == 100

    def test_packet_callback_exception_increments_dropped(
        self, packet_capture: PacketCapture
    ) -> None:
        """Test that callback exceptions increment dropped_packets."""
        mock_packet = create_mock_scapy_packet()

        with patch.object(
            packet_capture, "process_packet_layers", side_effect=Exception("Test error")
        ):
            packet_capture.packet_callback(mock_packet)

            assert len(packet_capture.packets) == 0
            assert packet_capture.stats["dropped_packets"] == 1

    def test_process_queue(self, packet_capture: PacketCapture) -> None:
        """Test processing packets from queue."""
        mock_packet1 = create_mock_scapy_packet(timestamp=1234567890.0, size=100)
        mock_packet2 = create_mock_scapy_packet(timestamp=1234567891.0, size=200)

        packet_capture.packet_queue = Queue()
        packet_capture.packet_queue.put([mock_packet1, mock_packet2])
        # Set is_running to False so the loop exits after processing the queue
        # The condition `not self.packet_queue.empty()` will still process items
        packet_capture.is_running = False

        processed_packet1 = Packet(timestamp=1234567890.0, layers=[], raw_size=100)
        processed_packet2 = Packet(timestamp=1234567891.0, layers=[], raw_size=200)

        with patch.object(packet_capture, "process_packet_layers") as mock_process:
            mock_process.side_effect = [processed_packet1, processed_packet2]

            packet_capture.process_queue()

            assert len(packet_capture.packets) == 2
            assert packet_capture.packets[0].timestamp == 1234567890.0
            assert packet_capture.packets[1].timestamp == 1234567891.0
            assert mock_process.call_count == 2
            assert packet_capture.stats["processed_packets"] == 2
            assert packet_capture.stats["batch_count"] == 1
            assert packet_capture.stats["processing_time"] > 0

    def test_process_queue_with_exception(self, packet_capture: PacketCapture) -> None:
        """Test processing packets from queue with exception."""
        mock_packet = create_mock_scapy_packet()

        packet_capture.packet_queue = Queue()
        packet_capture.packet_queue.put([mock_packet])
        # Set is_running to False so the loop exits after processing the queue
        packet_capture.is_running = False

        with patch.object(
            packet_capture, "process_packet_layers", side_effect=Exception("Test error")
        ):
            packet_capture.process_queue()

            assert len(packet_capture.packets) == 0
            assert packet_capture.stats["dropped_packets"] == 1
            assert packet_capture.stats["batch_count"] == 1

    def test_packets_to_json(self, packet_capture: PacketCapture) -> None:
        """Test converting packets to JSON."""
        layer1 = PacketLayer(layer_name="Test1", fields={"field1": "value1"})
        layer2 = PacketLayer(layer_name="Test2", fields={"field2": "value2"})

        packet1 = Packet(timestamp=1234567890.0, layers=[layer1], raw_size=100)
        packet2 = Packet(timestamp=1234567891.0, layers=[layer2], raw_size=200)

        packet_capture.packets = [packet1, packet2]

        json_packets = packet_capture.packets_to_json()

        assert len(json_packets) == 2
        assert json_packets[0]["timestamp"] == 1234567890.0
        assert json_packets[0]["raw_size"] == 100
        assert json_packets[0]["layers"][0]["layer_name"] == "Test1"
        assert json_packets[0]["layers"][0]["fields"]["field1"] == "value1"

        assert json_packets[1]["timestamp"] == 1234567891.0
        assert json_packets[1]["raw_size"] == 200
        assert json_packets[1]["layers"][0]["layer_name"] == "Test2"

    @pytest.mark.skipif(not POLARS_AVAILABLE, reason="Polars not installed")
    def test_packets_to_polars(self, packet_capture: PacketCapture) -> None:
        """Test converting packets to Polars DataFrames."""

        layer1 = PacketLayer(layer_name="Test1", fields={"field1": "value1"})
        layer2 = PacketLayer(layer_name="Test2", fields={"field2": "value2"})

        packet1 = Packet(timestamp=1234567890.0, layers=[layer1], raw_size=100)
        packet2 = Packet(timestamp=1234567891.0, layers=[layer2], raw_size=200)

        packet_capture.packets = [packet1, packet2]

        polars_dfs = packet_capture.packets_to_polars()

        assert len(polars_dfs) == 2
        assert isinstance(polars_dfs[0], pl.DataFrame)
        assert isinstance(polars_dfs[1], pl.DataFrame)

        df1 = polars_dfs[0]
        assert df1.shape[0] == 1
        assert "timestamp" in df1.columns
        assert "raw_size" in df1.columns
        assert "Test1_field1" in df1.columns
        assert df1["timestamp"][0] == 1234567890.0
        assert df1["raw_size"][0] == 100
        assert df1["Test1_field1"][0] == "value1"

    def test_packets_to_pandas(self, packet_capture: PacketCapture) -> None:
        """Test converting packets to Pandas DataFrames."""
        layer1 = PacketLayer(layer_name="Test1", fields={"field1": "value1"})
        layer2 = PacketLayer(layer_name="Test2", fields={"field2": "value2"})

        packet1 = Packet(timestamp=1234567890.0, layers=[layer1], raw_size=100)
        packet2 = Packet(timestamp=1234567891.0, layers=[layer2], raw_size=200)

        packet_capture.packets = [packet1, packet2]

        pandas_dfs = packet_capture.packets_to_pandas()

        assert len(pandas_dfs) == 2
        assert isinstance(pandas_dfs[0], pd.DataFrame)
        assert isinstance(pandas_dfs[1], pd.DataFrame)

        df1 = pandas_dfs[0]
        assert df1.shape[0] == 1
        assert "timestamp" in df1.columns
        assert "raw_size" in df1.columns
        assert "Test1_field1" in df1.columns
        assert df1["timestamp"].iloc[0] == 1234567890.0
        assert df1["raw_size"].iloc[0] == 100
        assert df1["Test1_field1"].iloc[0] == "value1"

    def test_to_json(self, packet_capture: PacketCapture) -> None:
        """Test converting all packets to a single JSON object."""
        layer1 = PacketLayer(layer_name="Test1", fields={"field1": "value1"})
        layer2 = PacketLayer(layer_name="Test2", fields={"field2": "value2"})

        packet1 = Packet(timestamp=1234567890.0, layers=[layer1], raw_size=100)
        packet2 = Packet(timestamp=1234567891.0, layers=[layer2], raw_size=200)

        packet_capture.packets = [packet1, packet2]

        json_data = packet_capture.to_json()

        assert "packets" in json_data
        assert "total_packets" in json_data
        assert json_data["total_packets"] == 2

        json_packets = json_data["packets"]
        assert len(json_packets) == 2
        assert json_packets[0]["timestamp"] == 1234567890.0
        assert json_packets[1]["timestamp"] == 1234567891.0

    def test_to_json_empty(self, packet_capture: PacketCapture) -> None:
        """Test to_json returns empty dict for no packets."""
        packet_capture.packets = []
        assert packet_capture.to_json() == {}

    def test_to_pandas_df(self, packet_capture: PacketCapture) -> None:
        """Test converting all packets to a single pandas DataFrame."""
        layer1 = PacketLayer(layer_name="Test1", fields={"field1": "value1"})
        layer2 = PacketLayer(layer_name="Test2", fields={"field2": "value2"})

        packet1 = Packet(timestamp=1234567890.0, layers=[layer1], raw_size=100)
        packet2 = Packet(timestamp=1234567891.0, layers=[layer2], raw_size=200)

        packet_capture.packets = [packet1, packet2]

        df = packet_capture.to_pandas_df()

        assert isinstance(df, pd.DataFrame)
        assert df.shape[0] == 2
        assert "timestamp" in df.columns
        assert "raw_size" in df.columns
        assert "Test1_field1" in df.columns
        assert "Test2_field2" in df.columns

        assert df["timestamp"].iloc[0] == 1234567890.0
        assert df["raw_size"].iloc[0] == 100
        assert df["Test1_field1"].iloc[0] == "value1"
        assert pd.isna(df["Test2_field2"].iloc[0])

        assert df["timestamp"].iloc[1] == 1234567891.0
        assert df["raw_size"].iloc[1] == 200
        assert pd.isna(df["Test1_field1"].iloc[1])
        assert df["Test2_field2"].iloc[1] == "value2"

    def test_to_pandas_df_empty(self, packet_capture: PacketCapture) -> None:
        """Test to_pandas_df returns empty DataFrame for no packets."""
        packet_capture.packets = []
        df = packet_capture.to_pandas_df()
        assert isinstance(df, pd.DataFrame)
        assert df.empty

    @pytest.mark.skipif(not POLARS_AVAILABLE, reason="Polars not installed")
    def test_to_polars_df(self, packet_capture: PacketCapture) -> None:
        """Test converting all packets to a single polars DataFrame."""

        layer1 = PacketLayer(layer_name="Test1", fields={"field1": "value1"})
        layer2 = PacketLayer(layer_name="Test2", fields={"field2": "value2"})

        packet1 = Packet(timestamp=1234567890.0, layers=[layer1], raw_size=100)
        packet2 = Packet(timestamp=1234567891.0, layers=[layer2], raw_size=200)

        packet_capture.packets = [packet1, packet2]

        df = packet_capture.to_polars_df()

        assert isinstance(df, pl.DataFrame)
        assert df.shape[0] == 2
        assert "timestamp" in df.columns
        assert "raw_size" in df.columns
        assert "Test1_field1" in df.columns
        assert "Test2_field2" in df.columns

        assert df["timestamp"][0] == 1234567890.0
        assert df["raw_size"][0] == 100
        assert df["Test1_field1"][0] == "value1"
        assert df["Test2_field2"][0] is None

        assert df["timestamp"][1] == 1234567891.0
        assert df["raw_size"][1] == 200
        assert df["Test1_field1"][1] is None
        assert df["Test2_field2"][1] == "value2"

    @pytest.mark.skipif(not POLARS_AVAILABLE, reason="Polars not installed")
    def test_to_polars_df_empty(self, packet_capture: PacketCapture) -> None:
        """Test to_polars_df returns empty DataFrame for no packets."""

        packet_capture.packets = []
        df = packet_capture.to_polars_df()
        assert isinstance(df, pl.DataFrame)
        assert df.is_empty()


# ============================================================================
# TEST CLASS: Boundary Conditions
# ============================================================================


class TestBoundaryConditions:
    """Test boundary conditions and edge cases."""

    @patch("netguard.capture.packet_capture.sniff")
    def test_zero_packets_captured(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture
    ) -> None:
        """Test handling of zero packets captured."""
        # Configure sniff to not call the callback (no packets)
        mock_sniff.return_value = []

        # Capture with count=0
        packet_capture.capture(max_packets=0)

        # Verify no errors occurred
        assert not packet_capture.is_running

        # Verify empty packets list
        assert len(packet_capture.packets) == 0

        # Verify stats show 0 packets
        assert packet_capture.stats["processed_packets"] == 0
        assert packet_capture.stats["dropped_packets"] == 0

    @patch("netguard.capture.packet_capture.sniff")
    def test_single_packet_capture(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture
    ) -> None:
        """Test capturing exactly one packet."""
        # Create a single mock packet
        single_packet = create_mock_scapy_packet(timestamp=1234567890.0, size=150)

        def sniff_side_effect(**kwargs):
            prn = kwargs.get("prn")
            if prn:
                prn(single_packet)

        mock_sniff.side_effect = sniff_side_effect

        # Capture 1 packet
        packet_capture.capture(max_packets=1)

        # Verify packet processed correctly
        assert len(packet_capture.packets) == 1
        assert packet_capture.packets[0].timestamp == 1234567890.0
        assert packet_capture.packets[0].raw_size == 150

        # Verify stats accurate
        total = packet_capture.stats["processed_packets"] + packet_capture.stats["dropped_packets"]
        assert total == 1

    @patch("netguard.capture.packet_capture.sniff")
    def test_exact_memory_limit_packets(self, mock_sniff: MagicMock, temp_log_dir: str) -> None:
        """Test capturing exactly max_memory_packets."""
        # Create config with small max_memory_packets
        config = SnifferConfig(
            interface="lo",
            log_dir=temp_log_dir,
            export_dir=temp_log_dir,
            max_memory_packets=100,  # Minimum allowed value
            max_processing_batch_size=10,
        )
        capture = PacketCapture(config=config)

        # Create exactly 100 packets
        packets = [create_mock_scapy_packet(timestamp=float(i), size=100) for i in range(100)]

        packet_index = [0]

        def sniff_side_effect(**kwargs):
            prn = kwargs.get("prn")
            if prn:
                for pkt in packets:
                    prn(pkt)
                    packet_index[0] += 1

        mock_sniff.side_effect = sniff_side_effect

        # Capture packets
        capture.capture(max_packets=100)

        # Verify behavior is correct at boundary
        # Should have exactly 100 or less packets (trimming may occur)
        assert len(capture.packets) <= 100

        # Verify all packets were processed
        total = capture.stats["processed_packets"] + capture.stats["dropped_packets"]
        assert total == 100

    def test_packet_with_maximum_layers(self, packet_capture: PacketCapture) -> None:
        """Test processing packet with many layers."""
        mock_packet = MagicMock()
        mock_packet.time = 1234567890.0
        mock_packet.__len__.return_value = 500

        # Create packet with 10+ layers (all known layer types)
        known_layers = [Ether, IP, TCP]
        mock_packet.haslayer.side_effect = lambda x: x in known_layers

        def get_layer(layer_type):
            if layer_type == Ether:
                return MagicMock(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff", type=0x0800)
            elif layer_type == IP:
                return MagicMock(
                    version=4,
                    ihl=5,
                    tos=0,
                    len=500,
                    id=12345,
                    flags=0,
                    frag=0,
                    ttl=64,
                    proto=6,
                    chksum=0xABCD,
                    src="192.168.1.1",
                    dst="10.0.0.1",
                    options=[],
                )
            elif layer_type == TCP:
                return MagicMock(
                    sport=12345,
                    dport=80,
                    seq=1000,
                    ack=2000,
                    dataofs=5,
                    reserved=0,
                    flags="PA",
                    window=8192,
                    chksum=0x1234,
                    urgptr=0,
                    options=[],
                )
            return MagicMock()

        mock_packet.__getitem__.side_effect = get_layer

        # Create additional unknown layers to simulate 10+ layers
        class UnknownLayer1:
            __name__ = "Custom1"
            fields_desc: ClassVar[list] = []

        class UnknownLayer2:
            __name__ = "Custom2"
            fields_desc: ClassVar[list] = []

        # Add more layers via the layers() method
        mock_packet.layers.return_value = [
            UnknownLayer1,
            UnknownLayer2,
        ]

        # Process packet
        processed = packet_capture.process_packet_layers(mock_packet)

        # Verify all known layers captured
        assert processed is not None
        assert processed.timestamp == 1234567890.0
        assert processed.raw_size == 500

        # Should have at least the 3 known layers
        assert len(processed.layers) >= 3

        # Verify specific layers are present
        layer_names = [layer.layer_name for layer in processed.layers]
        assert "Ethernet" in layer_names
        assert "IP" in layer_names
        assert "TCP" in layer_names

    def test_packet_with_very_large_payload(self, packet_capture: PacketCapture) -> None:
        """Test processing packet with large payload (64KB)."""
        mock_packet = MagicMock()
        mock_packet.time = 1234567890.0
        # 64KB packet size
        large_size = 65535
        mock_packet.__len__.return_value = large_size
        mock_packet.haslayer.return_value = False
        mock_packet.layers.return_value = []

        # Process packet
        processed = packet_capture.process_packet_layers(mock_packet)

        # Verify handled correctly
        assert processed is not None
        assert processed.timestamp == 1234567890.0
        assert processed.raw_size == large_size

    def test_packet_with_empty_layers(self, packet_capture: PacketCapture) -> None:
        """Test processing packet with no recognizable layers."""
        mock_packet = MagicMock()
        mock_packet.time = 1234567890.0
        mock_packet.__len__.return_value = 64
        mock_packet.haslayer.return_value = False
        mock_packet.layers.return_value = []

        processed = packet_capture.process_packet_layers(mock_packet)

        assert processed is not None
        assert processed.timestamp == 1234567890.0
        assert processed.raw_size == 64
        assert len(processed.layers) == 0

    def test_packet_with_minimum_size(self, packet_capture: PacketCapture) -> None:
        """Test processing packet with minimum size (1 byte)."""
        mock_packet = MagicMock()
        mock_packet.time = 1234567890.0
        mock_packet.__len__.return_value = 1
        mock_packet.haslayer.return_value = False
        mock_packet.layers.return_value = []

        processed = packet_capture.process_packet_layers(mock_packet)

        assert processed is not None
        assert processed.raw_size == 1

    def test_packet_with_zero_timestamp(self, packet_capture: PacketCapture) -> None:
        """Test processing packet with zero timestamp."""
        mock_packet = MagicMock()
        mock_packet.time = 0.0
        mock_packet.__len__.return_value = 100
        mock_packet.haslayer.return_value = False
        mock_packet.layers.return_value = []

        processed = packet_capture.process_packet_layers(mock_packet)

        assert processed is not None
        assert processed.timestamp == 0.0

    def test_packet_with_negative_timestamp(self, packet_capture: PacketCapture) -> None:
        """Test processing packet with negative timestamp (shouldn't happen, but handle it)."""
        mock_packet = MagicMock()
        mock_packet.time = -1.0
        mock_packet.__len__.return_value = 100
        mock_packet.haslayer.return_value = False
        mock_packet.layers.return_value = []

        processed = packet_capture.process_packet_layers(mock_packet)

        assert processed is not None
        assert processed.timestamp == -1.0

    def test_batch_size_boundary(self, temp_log_dir: str) -> None:
        """Test processing with batch size exactly equal to packet count."""
        config = SnifferConfig(
            interface="lo",
            log_dir=temp_log_dir,
            export_dir=temp_log_dir,
            max_processing_batch_size=5,
        )
        capture = PacketCapture(config=config)

        # Create exactly batch_size packets
        packets = [create_mock_scapy_packet(timestamp=float(i)) for i in range(5)]

        # Add batch to queue
        capture.packet_queue.put(packets)
        capture.is_running = False

        capture.process_queue()

        # Verify all packets processed
        assert len(capture.packets) == 5
        assert capture.stats["batch_count"] == 1

    def test_empty_batch_in_queue(self, packet_capture: PacketCapture) -> None:
        """Test processing an empty batch from queue."""
        # Add empty batch to queue
        packet_capture.packet_queue.put([])
        packet_capture.is_running = False

        # Should not raise
        packet_capture.process_queue()

        # Verify stats
        assert packet_capture.stats["batch_count"] == 1
        assert packet_capture.stats["processed_packets"] == 0


# ============================================================================
# TEST CLASS: Concurrent Access Edge Cases
# ============================================================================


class TestConcurrentAccessEdgeCases:
    """Test edge cases in concurrent access scenarios."""

    def test_stop_during_active_processing(self, temp_log_dir: str) -> None:
        """Test stopping capture while packets are being processed."""
        config = SnifferConfig(
            interface="lo",
            log_dir=temp_log_dir,
            export_dir=temp_log_dir,
            max_processing_batch_size=10,
        )
        capture = PacketCapture(config=config)

        # Create a large batch of packets
        large_batch = [create_mock_scapy_packet(timestamp=float(i)) for i in range(100)]

        # Add multiple batches to queue
        for i in range(5):
            capture.packet_queue.put(large_batch[i * 20 : (i + 1) * 20])

        capture.is_running = True

        # Start processing in a separate thread
        process_thread = Thread(target=capture.process_queue)
        process_thread.start()

        # Allow some processing to happen
        sleep(0.1)

        # Stop capture mid-processing
        capture.is_running = False

        # Wait for thread to finish (with timeout)
        process_thread.join(timeout=5)

        # Verify graceful shutdown - thread should have stopped
        assert not process_thread.is_alive()

        # Verify no deadlocks - we reached this point
        # Some packets should have been processed
        total = capture.stats["processed_packets"] + capture.stats["dropped_packets"]
        assert total > 0

    def test_save_during_active_capture(self, temp_log_dir: str) -> None:
        """Test saving while capture is still active."""
        config = SnifferConfig(
            interface="lo",
            log_dir=temp_log_dir,
            export_dir=temp_log_dir,
            max_processing_batch_size=5,
        )
        capture = PacketCapture(config=config)

        # Add some packets directly to simulate active capture
        for i in range(10):
            layer = PacketLayer(layer_name="Test", fields={"id": i})
            capture.packets.append(Packet(timestamp=float(i), layers=[layer], raw_size=100))

        # Simulate active capture state
        capture.is_running = True

        # Save should succeed even while "capturing"
        if POLARS_AVAILABLE:
            save_path = Path(temp_log_dir) / "concurrent_save.parquet"
            result_path = capture.save_to_parquet(str(save_path))

            # Verify save succeeded
            assert Path(result_path).exists()

            # Verify capture state unchanged
            assert capture.is_running is True

            # Verify packets still in memory
            assert len(capture.packets) == 10

            # Cleanup
            Path(result_path).unlink()

        # Reset state
        capture.is_running = False

    def test_concurrent_stats_updates(self, packet_capture: PacketCapture) -> None:
        """Test that stats updates are thread-safe."""
        num_threads = 10
        updates_per_thread = 100

        def update_stats():
            for _ in range(updates_per_thread):
                packet_capture.update_stats(processing_time=0.001, batch_size=1)

        threads = [Thread(target=update_stats) for _ in range(num_threads)]

        # Start all threads
        for t in threads:
            t.start()

        # Wait for all threads to finish
        for t in threads:
            t.join()

        # Verify stats are consistent (no race conditions)
        expected_processed = num_threads * updates_per_thread
        assert packet_capture.stats["processed_packets"] == expected_processed
        assert packet_capture.stats["batch_count"] == expected_processed

    def test_multiple_queue_consumers(self, temp_log_dir: str) -> None:
        """Test multiple threads consuming from the same queue."""
        config = SnifferConfig(
            interface="lo",
            log_dir=temp_log_dir,
            export_dir=temp_log_dir,
            num_threads=4,
            max_processing_batch_size=5,
        )
        capture = PacketCapture(config=config)

        # Add packets to queue
        num_batches = 20
        packets_per_batch = 5
        for i in range(num_batches):
            batch = [
                create_mock_scapy_packet(timestamp=float(i * packets_per_batch + j))
                for j in range(packets_per_batch)
            ]
            capture.packet_queue.put(batch)

        capture.is_running = False

        # Start multiple consumer threads
        threads = [Thread(target=capture.process_queue) for _ in range(4)]
        for t in threads:
            t.start()

        # Wait for all threads
        for t in threads:
            t.join(timeout=10)

        # Verify all packets were processed without duplicates or loss
        total = capture.stats["processed_packets"] + capture.stats["dropped_packets"]
        assert total == num_batches * packets_per_batch

    def test_rapid_start_stop_cycles(self, temp_log_dir: str) -> None:
        """Test rapid start/stop cycles don't cause issues."""
        config = SnifferConfig(
            interface="lo",
            log_dir=temp_log_dir,
            export_dir=temp_log_dir,
        )

        for _ in range(5):
            capture = PacketCapture(config=config)

            # Add some packets
            batch = [create_mock_scapy_packet(timestamp=float(i)) for i in range(10)]
            capture.packet_queue.put(batch)

            # Start processing
            capture.is_running = True
            thread = Thread(target=capture.process_queue)
            thread.start()

            # Immediately stop
            sleep(0.01)
            capture.is_running = False

            # Wait for thread
            thread.join(timeout=2)

            # Verify clean state
            assert not thread.is_alive()

    def test_realtime_deque_concurrent_access(self, temp_log_dir: str) -> None:
        """Test concurrent access to realtime_packets deque."""
        config = SnifferConfig(
            interface="lo",
            log_dir=temp_log_dir,
            export_dir=temp_log_dir,
            enable_realtime_display=True,
        )
        capture = PacketCapture(config=config, realtime_display=True)

        errors = []

        def writer():
            """Write packets to deque."""
            try:
                for i in range(100):
                    layer = PacketLayer(layer_name="Test", fields={"id": i})
                    packet = Packet(timestamp=float(i), layers=[layer], raw_size=100)
                    capture.realtime_packets.append(packet)
                    sleep(0.001)
            except Exception as e:
                errors.append(e)

        def reader():
            """Read packets from deque."""
            try:
                for _ in range(100):
                    # Access deque safely
                    _ = len(capture.realtime_packets)
                    if capture.realtime_packets:
                        _ = list(capture.realtime_packets)[-1]
                    sleep(0.001)
            except Exception as e:
                errors.append(e)

        writer_thread = Thread(target=writer)
        reader_thread = Thread(target=reader)

        writer_thread.start()
        reader_thread.start()

        writer_thread.join()
        reader_thread.join()

        # Verify no errors occurred
        assert len(errors) == 0, f"Concurrent access errors: {errors}"

        # Deque should have packets (up to maxlen=50)
        assert len(capture.realtime_packets) <= 50


if __name__ == "__main__":
    pytest.main(["-v", __file__])

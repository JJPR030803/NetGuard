"""
Unit tests for the PacketCapture class.

This module contains self-contained tests for the PacketCapture class,
including all necessary fixtures and mocks.
"""

import tempfile
from queue import Queue
from typing import Generator
from unittest.mock import MagicMock, patch

import pandas as pd
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
        mock_packet.__getitem__.side_effect = lambda _: MagicMock()
        mock_packet.time = 1234567890.0
        mock_packet.__len__.return_value = 100

        mock_sniff.return_value = [mock_packet]

        packet_capture.capture(max_packets=1)

        assert len(packet_capture.packets) == 1
        assert isinstance(packet_capture.packets[0], Packet)
        assert packet_capture.packets[0].has_layer("ICMP")

    def test_show_packets(self, packet_capture: PacketCapture) -> None:
        """Test showing captured packets does not raise exceptions."""
        layer = PacketLayer(
            layer_name="Test", fields={"field1": "value1", "field2": "value2"}
        )
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

    def test_process_packet_layers_none_raises(
        self, packet_capture: PacketCapture
    ) -> None:
        """Test that processing None packet raises ValueError."""
        with pytest.raises(ValueError):
            packet_capture.process_packet_layers(None)

    def test_process_packet_layers_missing_time(
        self, packet_capture: PacketCapture
    ) -> None:
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

    def test_process_packet_layers_ethernet(
        self, packet_capture: PacketCapture
    ) -> None:
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

    def test_process_packet_layers_multiple(
        self, packet_capture: PacketCapture
    ) -> None:
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

        ip_layer = next(
            (layer for layer in processed.layers if layer.layer_name == "IP"), None
        )
        assert ip_layer is not None
        assert ip_layer.fields["src"] == "192.168.1.100"
        assert ip_layer.fields["dst"] == "10.0.0.100"

        tcp_layer = next(
            (layer for layer in processed.layers if layer.layer_name == "TCP"), None
        )
        assert tcp_layer is not None
        assert tcp_layer.fields["sport"] == 54321
        assert tcp_layer.fields["dport"] == 443
        assert tcp_layer.fields["flags"] == "S"

    def test_process_packet_layers_error_skips_layer(
        self, packet_capture: PacketCapture
    ) -> None:
        """Test that layer processing errors are handled gracefully."""
        mock_packet = MagicMock()
        mock_packet.haslayer.side_effect = lambda x: x == IP
        # Return a mock missing required attributes to trigger error
        mock_packet.__getitem__.side_effect = lambda x: (
            MagicMock(version=4, ihl=5, tos=0, len=20, id=12345, flags=0, frag=0, ttl=64, proto=6, chksum=0xABCD)
            if x == IP
            else None
        )
        mock_packet.time = 1234567890.0
        mock_packet.__len__.return_value = 100
        mock_packet.layers.return_value = []

        # Should not raise exception
        processed = packet_capture.process_packet_layers(mock_packet)
        assert processed.timestamp == 1234567890.0
        assert processed.raw_size == 100
        # Layer should be skipped due to error
        assert len(processed.layers) == 0

    def test_get_session_info_interface_types(
        self, packet_capture: PacketCapture
    ) -> None:
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
        packet_capture.is_running = True

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

    def test_process_queue_with_exception(
        self, packet_capture: PacketCapture
    ) -> None:
        """Test processing packets from queue with exception."""
        mock_packet = create_mock_scapy_packet()

        packet_capture.packet_queue = Queue()
        packet_capture.packet_queue.put([mock_packet])
        packet_capture.is_running = True

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
        import polars as pl

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
        import polars as pl

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
        import polars as pl

        packet_capture.packets = []
        df = packet_capture.to_polars_df()
        assert isinstance(df, pl.DataFrame)
        assert df.is_empty()


if __name__ == "__main__":
    pytest.main(["-v", __file__])

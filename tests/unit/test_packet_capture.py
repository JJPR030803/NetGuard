"""
Unit tests for the PacketCapture class
"""

import platform
from queue import Queue
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, STP, Ether

from src.network_security_suite.models.packet_data_structures import (
    POLARS_AVAILABLE,
    Packet,
    PacketLayer,
)
from src.network_security_suite.sniffer.packet_capture import PacketCapture


class TestPacketCapture:
    """Test suite for PacketCapture class"""

    def test_init(self, mock_interface: str) -> None:
        """Test PacketCapture initialization"""
        capture = PacketCapture(interface=mock_interface)
        assert capture.interface == mock_interface
        assert isinstance(capture.packets, list)
        assert len(capture.packets) == 0

    @pytest.mark.parametrize("max_packets", [1, 10, 100])
    @patch("scapy.all.sniff")
    def test_capture_with_different_counts(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture, max_packets: int
    ) -> None:
        """Test packet capture with different packet counts"""
        # Mock the sniff function to return empty list
        mock_sniff.return_value = []

        # Execute capture
        packet_capture.capture(max_packets=max_packets)

        # Verify sniff was called with correct parameters
        mock_sniff.assert_called_once_with(
            iface=packet_capture.interface, count=max_packets
        )

    @patch("scapy.all.sniff")
    def test_capture_icmp_packet(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture
    ) -> None:
        """Test capturing ICMP packet"""
        # Create mock ICMP packet
        mock_packet = MagicMock()
        mock_packet.haslayer.side_effect = lambda x: x in [IP, ICMP]
        mock_packet.__getitem__.side_effect = lambda x: MagicMock()
        mock_packet.time = 1234567890.0
        mock_packet.__len__.return_value = 100

        mock_sniff.return_value = [mock_packet]

        # Execute capture
        packet_capture.capture(max_packets=1)

        # Verify packet was processed
        assert len(packet_capture.packets) == 1
        assert isinstance(packet_capture.packets[0], Packet)

        # Verify the packet has ICMP layer
        assert packet_capture.packets[0].has_layer("ICMP")

    def test_show_packets(self, packet_capture: PacketCapture) -> None:
        """Test showing captured packets"""
        # Create a packet with layers
        layer = PacketLayer(
            layer_name="Test", fields={"field1": "value1", "field2": "value2"}
        )
        packet = Packet(timestamp=1234567890.0, layers=[layer], raw_size=100)
        packet_capture.packets = [packet]

        # Call show_packets (this just prints to console, so we're just testing it doesn't raise exceptions.md)
        packet_capture.show_packets()

    def test_show_stats(self, packet_capture: PacketCapture) -> None:
        """Test showing capture statistics"""
        # Set some statistics
        packet_capture.stats = {
            "processed_packets": 100,
            "dropped_packets": 5,
            "processing_time": 2.5,
            "batch_count": 10,
        }

        # Add some packets with different layers to test layer distribution
        ethernet_layer = PacketLayer(
            layer_name="Ethernet",
            fields={"src_mac": "00:11:22:33:44:55", "dst_mac": "aa:bb:cc:dd:ee:ff"},
        )
        ip_layer = PacketLayer(
            layer_name="IP", fields={"src": "192.168.1.1", "dst": "10.0.0.1"}
        )
        tcp_layer = PacketLayer(layer_name="TCP", fields={"sport": 12345, "dport": 80})

        packet1 = Packet(
            timestamp=1234567890.0, layers=[ethernet_layer, ip_layer], raw_size=100
        )
        packet2 = Packet(
            timestamp=1234567891.0,
            layers=[ethernet_layer, ip_layer, tcp_layer],
            raw_size=120,
        )

        packet_capture.packets = [packet1, packet2]

        # Call show_stats (this just prints to console, so we're just testing it doesn't raise exceptions.md)
        packet_capture.show_stats()

    def test_process_packet_layers(self, packet_capture: PacketCapture) -> None:
        """Test processing packet layers for different layer types"""
        # Test with None packet (should raise ValueError)
        with pytest.raises(ValueError):
            packet_capture.process_packet_layers(None)

        # Test with packet missing time attribute
        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = False
        mock_packet.__len__.return_value = 100
        # No time attribute set

        # Should use default timestamp of 0.0
        processed_packet = packet_capture.process_packet_layers(mock_packet)
        assert processed_packet.timestamp == 0.0
        assert processed_packet.raw_size == 100
        assert len(processed_packet.layers) == 0

        # Test with Ethernet layer
        mock_ether_packet = MagicMock()
        mock_ether_packet.haslayer.side_effect = lambda x: x == Ether
        mock_ether_packet.__getitem__.side_effect = lambda x: (
            MagicMock(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff", type=0x0800)
            if x == Ether
            else None
        )
        mock_ether_packet.time = 1234567890.0
        mock_ether_packet.__len__.return_value = 100
        mock_ether_packet.layers.return_value = []

        processed_ether = packet_capture.process_packet_layers(mock_ether_packet)
        assert processed_ether.timestamp == 1234567890.0
        assert processed_ether.raw_size == 100
        assert len(processed_ether.layers) == 1
        assert processed_ether.layers[0].layer_name == "Ethernet"
        assert processed_ether.layers[0].fields["dst_mac"] == "00:11:22:33:44:55"
        assert processed_ether.layers[0].fields["src_mac"] == "aa:bb:cc:dd:ee:ff"
        assert processed_ether.layers[0].fields["type"] == 0x0800

        # Test with IP layer
        mock_ip_packet = MagicMock()
        mock_ip_packet.haslayer.side_effect = lambda x: x == IP
        mock_ip_packet.__getitem__.side_effect = lambda x: (
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
        mock_ip_packet.time = 1234567890.0
        mock_ip_packet.__len__.return_value = 100
        mock_ip_packet.layers.return_value = []

        processed_ip = packet_capture.process_packet_layers(mock_ip_packet)
        assert processed_ip.timestamp == 1234567890.0
        assert processed_ip.raw_size == 100
        assert len(processed_ip.layers) == 1
        assert processed_ip.layers[0].layer_name == "IP"
        assert processed_ip.layers[0].fields["version"] == 4
        assert processed_ip.layers[0].fields["src"] == "192.168.1.1"
        assert processed_ip.layers[0].fields["dst"] == "10.0.0.1"

        # Test with TCP layer
        mock_tcp_packet = MagicMock()
        mock_tcp_packet.haslayer.side_effect = lambda x: x == TCP
        mock_tcp_packet.__getitem__.side_effect = lambda x: (
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
        mock_tcp_packet.time = 1234567890.0
        mock_tcp_packet.__len__.return_value = 100
        mock_tcp_packet.layers.return_value = []

        processed_tcp = packet_capture.process_packet_layers(mock_tcp_packet)
        assert processed_tcp.timestamp == 1234567890.0
        assert processed_tcp.raw_size == 100
        assert len(processed_tcp.layers) == 1
        assert processed_tcp.layers[0].layer_name == "TCP"
        assert processed_tcp.layers[0].fields["sport"] == 12345
        assert processed_tcp.layers[0].fields["dport"] == 80
        assert processed_tcp.layers[0].fields["flags"] == "PA"

        # Test with multiple layers (IP + TCP)
        mock_multi_packet = MagicMock()
        mock_multi_packet.haslayer.side_effect = lambda x: x in [IP, TCP]

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

        mock_multi_packet.__getitem__.side_effect = get_layer
        mock_multi_packet.time = 1234567890.0
        mock_multi_packet.__len__.return_value = 100
        mock_multi_packet.layers.return_value = []

        processed_multi = packet_capture.process_packet_layers(mock_multi_packet)
        assert processed_multi.timestamp == 1234567890.0
        assert processed_multi.raw_size == 100
        assert len(processed_multi.layers) == 2

        # Find IP layer
        ip_layer = next(
            (layer for layer in processed_multi.layers if layer.layer_name == "IP"),
            None,
        )
        assert ip_layer is not None
        assert ip_layer.fields["version"] == 4
        assert ip_layer.fields["src"] == "192.168.1.100"
        assert ip_layer.fields["dst"] == "10.0.0.100"

        # Find TCP layer
        tcp_layer = next(
            (layer for layer in processed_multi.layers if layer.layer_name == "TCP"),
            None,
        )
        assert tcp_layer is not None
        assert tcp_layer.fields["sport"] == 54321
        assert tcp_layer.fields["dport"] == 443
        assert tcp_layer.fields["flags"] == "S"

        # Test error handling during layer processing
        mock_error_packet = MagicMock()
        mock_error_packet.haslayer.side_effect = lambda x: x == IP
        mock_error_packet.__getitem__.side_effect = lambda x: (
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
                # Missing src and dst to trigger error
            )
            if x == IP
            else None
        )
        mock_error_packet.time = 1234567890.0
        mock_error_packet.__len__.return_value = 100
        mock_error_packet.layers.return_value = []

        # Should not raise exception but print error message
        processed_error = packet_capture.process_packet_layers(mock_error_packet)
        assert processed_error.timestamp == 1234567890.0
        assert processed_error.raw_size == 100
        # Layer should be skipped due to error
        assert len(processed_error.layers) == 0

    def test_get_session_info(self, packet_capture: PacketCapture) -> None:
        """Test getting session information"""
        # Mock platform information
        with (
            patch("platform.system", return_value="Linux"),
            patch("platform.version", return_value="5.10.0"),
            patch("platform.machine", return_value="x86_64"),
            patch("platform.processor", return_value="Intel(R) Core(TM) i7"),
        ):
            # Test with different interface types
            # Ethernet interface
            packet_capture.interface = "eth0"
            session_info = packet_capture._get_session_info()
            assert session_info["os"] == "Linux"
            assert session_info["os_version"] == "5.10.0"
            assert session_info["machine"] == "x86_64"
            assert session_info["processor"] == "Intel(R) Core(TM) i7"
            assert session_info["interface"] == "eth0"
            assert session_info["interface_type"] == "ethernet"

            # Wireless interface
            packet_capture.interface = "wlan0"
            session_info = packet_capture._get_session_info()
            assert session_info["interface"] == "wlan0"
            assert session_info["interface_type"] == "wireless"

            # Docker interface
            packet_capture.interface = "docker0"
            session_info = packet_capture._get_session_info()
            assert session_info["interface"] == "docker0"
            assert session_info["interface_type"] == "docker"

            # Virtual interface
            packet_capture.interface = "veth0"
            session_info = packet_capture._get_session_info()
            assert session_info["interface"] == "veth0"
            assert session_info["interface_type"] == "virtual"

            # VPN interface
            packet_capture.interface = "tun0"
            session_info = packet_capture._get_session_info()
            assert session_info["interface"] == "tun0"
            assert session_info["interface_type"] == "vpn"

            # Loopback interface
            packet_capture.interface = "lo"
            session_info = packet_capture._get_session_info()
            assert session_info["interface"] == "lo"
            assert session_info["interface_type"] == "loopback"

            # Unknown interface
            packet_capture.interface = "unknown0"
            session_info = packet_capture._get_session_info()
            assert session_info["interface"] == "unknown0"
            assert session_info["interface_type"] == "unknown"

    def test_update_stats(self, packet_capture: PacketCapture) -> None:
        """Test updating statistics"""
        # Initial stats should be empty or have default values
        assert packet_capture.stats["processed_packets"] == 0
        assert packet_capture.stats["dropped_packets"] == 0
        assert packet_capture.stats["processing_time"] == 0.0
        assert packet_capture.stats["batch_count"] == 0

        # Update stats
        packet_capture.update_stats(processing_time=1.5, batch_size=10)

        # Check updated stats
        assert packet_capture.stats["processed_packets"] == 10
        assert packet_capture.stats["processing_time"] == 1.5
        assert packet_capture.stats["batch_count"] == 1

        # Update stats again
        packet_capture.update_stats(processing_time=2.0, batch_size=20)

        # Check cumulative stats
        assert packet_capture.stats["processed_packets"] == 30
        assert packet_capture.stats["processing_time"] == 3.5
        assert packet_capture.stats["batch_count"] == 2

    def test_packet_callback(self, packet_capture: PacketCapture) -> None:
        """Test packet callback function"""
        # Create a mock packet
        mock_packet = MagicMock()
        mock_packet.time = 1234567890.0
        mock_packet.__len__.return_value = 100
        mock_packet.haslayer.return_value = False

        # Call packet_callback
        packet_capture.packet_callback(mock_packet)

        # Verify packet was processed and added to packets list
        assert len(packet_capture.packets) == 1
        assert packet_capture.packets[0].timestamp == 1234567890.0
        assert packet_capture.packets[0].raw_size == 100

        # Test with exception during processing
        with patch.object(
            packet_capture, "process_packet_layers", side_effect=Exception("Test error")
        ):
            # Reset packets list
            packet_capture.packets = []

            # Call packet_callback with a packet that will cause an exception
            packet_capture.packet_callback(mock_packet)

            # Verify no packets were added and dropped_packets was incremented
            assert len(packet_capture.packets) == 0
            assert packet_capture.stats["dropped_packets"] == 1

    def test_process_queue(self, packet_capture: PacketCapture) -> None:
        """Test processing packets from queue"""
        # Create mock packets
        mock_packet1 = MagicMock()
        mock_packet1.time = 1234567890.0
        mock_packet1.__len__.return_value = 100
        mock_packet1.haslayer.return_value = False

        mock_packet2 = MagicMock()
        mock_packet2.time = 1234567891.0
        mock_packet2.__len__.return_value = 200
        mock_packet2.haslayer.return_value = False

        # Set up the packet queue
        packet_capture.packet_queue = Queue()
        packet_capture.packet_queue.put([mock_packet1, mock_packet2])

        # Set is_running to True so the process_queue method will process the queue
        packet_capture.is_running = True

        # Mock the process_packet_layers method to return a known packet
        with patch.object(packet_capture, "process_packet_layers") as mock_process:
            # Create mock processed packets
            processed_packet1 = Packet(timestamp=1234567890.0, layers=[], raw_size=100)
            processed_packet1.id = "packet1"  # Add an id for the log
            processed_packet2 = Packet(timestamp=1234567891.0, layers=[], raw_size=200)
            processed_packet2.id = "packet2"  # Add an id for the log

            mock_process.side_effect = [processed_packet1, processed_packet2]

            # Call process_queue
            packet_capture.process_queue()

            # Verify packets were processed and added to packets list
            assert len(packet_capture.packets) == 2
            assert packet_capture.packets[0].timestamp == 1234567890.0
            assert packet_capture.packets[1].timestamp == 1234567891.0

            # Verify process_packet_layers was called for each packet
            assert mock_process.call_count == 2

            # Verify stats were updated
            assert packet_capture.stats["processed_packets"] == 2
            assert packet_capture.stats["batch_count"] == 1
            assert packet_capture.stats["processing_time"] > 0

    def test_process_queue_with_exception(self, packet_capture: PacketCapture) -> None:
        """Test processing packets from queue with exception"""
        # Create mock packets
        mock_packet1 = MagicMock()
        mock_packet1.time = 1234567890.0
        mock_packet1.__len__.return_value = 100
        mock_packet1.haslayer.return_value = False

        # Set up the packet queue
        packet_capture.packet_queue = Queue()
        packet_capture.packet_queue.put([mock_packet1])

        # Set is_running to True so the process_queue method will process the queue
        packet_capture.is_running = True

        # Mock the process_packet_layers method to raise an exception
        with patch.object(
            packet_capture, "process_packet_layers", side_effect=Exception("Test error")
        ):
            # Call process_queue
            packet_capture.process_queue()

            # Verify no packets were added and dropped_packets was incremented
            assert len(packet_capture.packets) == 0
            assert packet_capture.stats["dropped_packets"] == 1

            # Verify stats were still updated
            assert packet_capture.stats["processed_packets"] == 0
            assert packet_capture.stats["batch_count"] == 1
            assert packet_capture.stats["processing_time"] > 0

    def test_packets_to_json(self, packet_capture: PacketCapture) -> None:
        """Test converting packets to JSON"""
        # Create test packets
        layer1 = PacketLayer(layer_name="Test1", fields={"field1": "value1"})
        layer2 = PacketLayer(layer_name="Test2", fields={"field2": "value2"})

        packet1 = Packet(timestamp=1234567890.0, layers=[layer1], raw_size=100)
        packet2 = Packet(timestamp=1234567891.0, layers=[layer2], raw_size=200)

        packet_capture.packets = [packet1, packet2]

        # Convert to JSON
        json_packets = packet_capture.packets_to_json()

        # Verify JSON conversion
        assert len(json_packets) == 2
        assert json_packets[0]["timestamp"] == 1234567890.0
        assert json_packets[0]["raw_size"] == 100
        assert json_packets[0]["layers"][0]["layer_name"] == "Test1"
        assert json_packets[0]["layers"][0]["fields"]["field1"] == "value1"

        assert json_packets[1]["timestamp"] == 1234567891.0
        assert json_packets[1]["raw_size"] == 200
        assert json_packets[1]["layers"][0]["layer_name"] == "Test2"
        assert json_packets[1]["layers"][0]["fields"]["field2"] == "value2"

    @pytest.mark.skipif(not POLARS_AVAILABLE, reason="Polars not installed")
    def test_packets_to_polars(self, packet_capture: PacketCapture) -> None:
        """Test converting packets to Polars DataFrames"""
        # Import here to avoid issues if polars is not installed
        try:
            import polars as pl

            # Create test packets
            layer1 = PacketLayer(layer_name="Test1", fields={"field1": "value1"})
            layer2 = PacketLayer(layer_name="Test2", fields={"field2": "value2"})

            packet1 = Packet(timestamp=1234567890.0, layers=[layer1], raw_size=100)
            packet2 = Packet(timestamp=1234567891.0, layers=[layer2], raw_size=200)

            packet_capture.packets = [packet1, packet2]

            # Convert to Polars DataFrames
            polars_dfs = packet_capture.packets_to_polars()

            # Verify Polars conversion
            assert len(polars_dfs) == 2
            assert isinstance(polars_dfs[0], pl.DataFrame)
            assert isinstance(polars_dfs[1], pl.DataFrame)

            # Check first DataFrame
            df1 = polars_dfs[0]
            assert df1.shape[0] == 1  # One row
            assert "timestamp" in df1.columns
            assert "raw_size" in df1.columns
            assert "Test1_field1" in df1.columns
            assert df1["timestamp"][0] == 1234567890.0
            assert df1["raw_size"][0] == 100
            assert df1["Test1_field1"][0] == "value1"

            # Check second DataFrame
            df2 = polars_dfs[1]
            assert df2.shape[0] == 1  # One row
            assert "timestamp" in df2.columns
            assert "raw_size" in df2.columns
            assert "Test2_field2" in df2.columns
            assert df2["timestamp"][0] == 1234567891.0
            assert df2["raw_size"][0] == 200
            assert df2["Test2_field2"][0] == "value2"
        except ImportError:
            pytest.skip("Polars not installed")

    def test_packets_to_pandas(self, packet_capture: PacketCapture) -> None:
        """Test converting packets to Pandas DataFrames"""
        # Create test packets
        layer1 = PacketLayer(layer_name="Test1", fields={"field1": "value1"})
        layer2 = PacketLayer(layer_name="Test2", fields={"field2": "value2"})

        packet1 = Packet(timestamp=1234567890.0, layers=[layer1], raw_size=100)
        packet2 = Packet(timestamp=1234567891.0, layers=[layer2], raw_size=200)

        packet_capture.packets = [packet1, packet2]

        # Convert to Pandas DataFrames
        pandas_dfs = packet_capture.packets_to_pandas()

        # Verify Pandas conversion
        assert len(pandas_dfs) == 2
        assert isinstance(pandas_dfs[0], pd.DataFrame)
        assert isinstance(pandas_dfs[1], pd.DataFrame)

        # Check first DataFrame
        df1 = pandas_dfs[0]
        assert df1.shape[0] == 1  # One row
        assert "timestamp" in df1.columns
        assert "raw_size" in df1.columns
        assert "Test1_field1" in df1.columns
        assert df1["timestamp"].iloc[0] == 1234567890.0
        assert df1["raw_size"].iloc[0] == 100
        assert df1["Test1_field1"].iloc[0] == "value1"

        # Check second DataFrame
        df2 = pandas_dfs[1]
        assert df2.shape[0] == 1  # One row
        assert "timestamp" in df2.columns
        assert "raw_size" in df2.columns
        assert "Test2_field2" in df2.columns
        assert df2["timestamp"].iloc[0] == 1234567891.0
        assert df2["raw_size"].iloc[0] == 200
        assert df2["Test2_field2"].iloc[0] == "value2"

    def test_to_json(self, packet_capture: PacketCapture) -> None:
        """Test converting all packets to a single JSON object"""
        # Create test packets
        layer1 = PacketLayer(layer_name="Test1", fields={"field1": "value1"})
        layer2 = PacketLayer(layer_name="Test2", fields={"field2": "value2"})

        packet1 = Packet(timestamp=1234567890.0, layers=[layer1], raw_size=100)
        packet2 = Packet(timestamp=1234567891.0, layers=[layer2], raw_size=200)

        packet_capture.packets = [packet1, packet2]

        # Convert to JSON
        json_data = packet_capture.to_json()

        # Verify JSON conversion
        assert "packets" in json_data
        assert "total_packets" in json_data
        assert json_data["total_packets"] == 2

        json_packets = json_data["packets"]
        assert len(json_packets) == 2

        assert json_packets[0]["timestamp"] == 1234567890.0
        assert json_packets[0]["raw_size"] == 100
        assert json_packets[0]["layers"][0]["layer_name"] == "Test1"
        assert json_packets[0]["layers"][0]["fields"]["field1"] == "value1"

        assert json_packets[1]["timestamp"] == 1234567891.0
        assert json_packets[1]["raw_size"] == 200
        assert json_packets[1]["layers"][0]["layer_name"] == "Test2"
        assert json_packets[1]["layers"][0]["fields"]["field2"] == "value2"

        # Test with empty packets list
        packet_capture.packets = []
        empty_json = packet_capture.to_json()
        assert empty_json == {}

    def test_to_pandas_df(self, packet_capture: PacketCapture) -> None:
        """Test converting all packets to a single pandas DataFrame"""
        # Create test packets
        layer1 = PacketLayer(layer_name="Test1", fields={"field1": "value1"})
        layer2 = PacketLayer(layer_name="Test2", fields={"field2": "value2"})

        packet1 = Packet(timestamp=1234567890.0, layers=[layer1], raw_size=100)
        packet2 = Packet(timestamp=1234567891.0, layers=[layer2], raw_size=200)

        packet_capture.packets = [packet1, packet2]

        # Convert to pandas DataFrame
        df = packet_capture.to_pandas_df()

        # Verify pandas conversion
        assert isinstance(df, pd.DataFrame)
        assert df.shape[0] == 2  # Two rows
        assert "timestamp" in df.columns
        assert "raw_size" in df.columns
        assert "Test1_field1" in df.columns
        assert "Test2_field2" in df.columns

        # Check values
        assert df["timestamp"].iloc[0] == 1234567890.0
        assert df["raw_size"].iloc[0] == 100
        assert df["Test1_field1"].iloc[0] == "value1"
        assert pd.isna(df["Test2_field2"].iloc[0])  # Should be NaN for first packet

        assert df["timestamp"].iloc[1] == 1234567891.0
        assert df["raw_size"].iloc[1] == 200
        assert pd.isna(df["Test1_field1"].iloc[1])  # Should be NaN for second packet
        assert df["Test2_field2"].iloc[1] == "value2"

        # Test with empty packets list
        packet_capture.packets = []
        empty_df = packet_capture.to_pandas_df()
        assert isinstance(empty_df, pd.DataFrame)
        assert empty_df.empty

    @pytest.mark.skipif(not POLARS_AVAILABLE, reason="Polars not installed")
    def test_to_polars_df(self, packet_capture: PacketCapture) -> None:
        """Test converting all packets to a single polars DataFrame"""
        # Import here to avoid issues if polars is not installed
        try:
            import polars as pl

            # Create test packets
            layer1 = PacketLayer(layer_name="Test1", fields={"field1": "value1"})
            layer2 = PacketLayer(layer_name="Test2", fields={"field2": "value2"})

            packet1 = Packet(timestamp=1234567890.0, layers=[layer1], raw_size=100)
            packet2 = Packet(timestamp=1234567891.0, layers=[layer2], raw_size=200)

            packet_capture.packets = [packet1, packet2]

            # Convert to polars DataFrame
            df = packet_capture.to_polars_df()

            # Verify polars conversion
            assert isinstance(df, pl.DataFrame)
            assert df.shape[0] == 2  # Two rows
            assert "timestamp" in df.columns
            assert "raw_size" in df.columns
            assert "Test1_field1" in df.columns
            assert "Test2_field2" in df.columns

            # Check values (note: polars uses empty strings instead of NaN for missing values)
            assert df["timestamp"][0] == 1234567890.0
            assert df["raw_size"][0] == "100"
            assert df["Test1_field1"][0] == "value1"
            assert df["Test2_field2"][0] == ""  # Empty string for missing value

            assert df["timestamp"][1] == 1234567891.0
            assert df["raw_size"][1] == "200"
            assert df["Test1_field1"][1] == ""  # Empty string for missing value
            assert df["Test2_field2"][1] == "value2"

            # Test with empty packets list
            packet_capture.packets = []
            empty_df = packet_capture.to_polars_df()
            assert isinstance(empty_df, pl.DataFrame)
            assert empty_df.is_empty()
        except ImportError:
            pytest.skip("Polars not installed")


if __name__ == "__main__":
    pytest.main(["-v"])

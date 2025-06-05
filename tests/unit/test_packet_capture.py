"""
Unit tests for the PacketCapture class
"""

from unittest.mock import MagicMock, patch

import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, STP, Ether

from src.network_security_suite.models.packet_data_structures import Packet, PacketLayer
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

        # Call show_packets (this just prints to console, so we're just testing it doesn't raise exceptions)
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
            fields={"src_mac": "00:11:22:33:44:55", "dst_mac": "aa:bb:cc:dd:ee:ff"}
        )
        ip_layer = PacketLayer(
            layer_name="IP", 
            fields={"src": "192.168.1.1", "dst": "10.0.0.1"}
        )
        tcp_layer = PacketLayer(
            layer_name="TCP", 
            fields={"sport": 12345, "dport": 80}
        )

        packet1 = Packet(timestamp=1234567890.0, layers=[ethernet_layer, ip_layer], raw_size=100)
        packet2 = Packet(timestamp=1234567891.0, layers=[ethernet_layer, ip_layer, tcp_layer], raw_size=120)

        packet_capture.packets = [packet1, packet2]

        # Call show_stats (this just prints to console, so we're just testing it doesn't raise exceptions)
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


if __name__ == "__main__":
    pytest.main(["-v"])

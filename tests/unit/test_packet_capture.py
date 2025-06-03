"""
Unit tests for the PacketCapture class
"""
from unittest.mock import MagicMock, patch

import pytest
from scapy.layers.inet import ICMP, IP

from src.network_security_suite.models.data_structures import Packet, PacketLayer
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
        layer = PacketLayer(layer_name="Test", fields={"field1": "value1", "field2": "value2"})
        packet = Packet(timestamp=1234567890.0, layers=[layer], raw_size=100)
        packet_capture.packets = [packet]

        # Call show_packets (this just prints to console, so we're just testing it doesn't raise exceptions)
        packet_capture.show_packets()


if __name__ == "__main__":
    pytest.main(["-v"])

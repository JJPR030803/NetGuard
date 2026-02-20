"""
Tests for packet data structures.

This module tests the Pydantic models defined in netguard.models.packet_data_structures.
"""

import unittest
from typing import Any

import pandas as pd
import pytest
from pydantic import ValidationError
from pydantic_extra_types.mac_address import MacAddress

from netguard.models.packet_data_structures import (
    ARPPacket,
    EthernetPacket,
    ICMPPacket,
    IPPacket,
    Packet,
    PacketLayer,
    STPPacket,
    TCPPacket,
    UDPPacket,
)

# Try to import polars, but don't fail if it's not installed
try:
    import polars as pl

    POLARS_AVAILABLE = True
except ImportError:
    POLARS_AVAILABLE = False


class TestPacketLayer(unittest.TestCase):
    """Test PacketLayer model."""

    def test_creation(self):
        """Test creating a PacketLayer."""
        layer = PacketLayer(layer_name="Test", fields={"key": "value"})
        self.assertEqual(layer.layer_name, "Test")
        self.assertEqual(layer.fields, {"key": "value"})

    def test_show(self):
        """Test show method (just ensure it runs)."""
        layer = PacketLayer(layer_name="Test", fields={"key": "value"})
        # Capture stdout to verify output if needed, but mainly checking for no errors
        layer.show()


class TestPacket(unittest.TestCase):
    """Test Packet model."""

    def setUp(self):
        self.layer1 = PacketLayer(layer_name="L1", fields={"a": 1})
        self.layer2 = PacketLayer(layer_name="L2", fields={"b": 2})
        self.packet = Packet(timestamp=123.456, layers=[self.layer1, self.layer2], raw_size=100)

    def test_creation(self):
        """Test creating a Packet."""
        self.assertEqual(self.packet.timestamp, 123.456)
        self.assertEqual(len(self.packet.layers), 2)
        self.assertEqual(self.packet.raw_size, 100)

    def test_has_layer(self):
        """Test has_layer method."""
        self.assertTrue(self.packet.has_layer("L1"))
        self.assertTrue(self.packet.has_layer("L2"))
        self.assertFalse(self.packet.has_layer("L3"))

    def test_get_layer(self):
        """Test get_layer method."""
        l1 = self.packet.get_layer("L1")
        self.assertIsNotNone(l1)
        self.assertEqual(l1.layer_name, "L1")

        l3 = self.packet.get_layer("L3")
        self.assertIsNone(l3)

    def test_to_json(self):
        """Test to_json method."""
        data = self.packet.to_json()
        self.assertEqual(data["timestamp"], 123.456)
        self.assertEqual(data["raw_size"], 100)
        self.assertEqual(len(data["layers"]), 2)


class TestBasePacket(unittest.TestCase):
    """Test BasePacket functionality via a concrete subclass."""

    def test_base_methods(self):
        """Test methods defined in BasePacket."""
        # Using UDPPacket as a concrete implementation
        packet = UDPPacket(
            sport=123,
            dport=456,
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            timestamp=1000.0,
            payload="test payload",
            layers=["Ethernet", "IP", "UDP"],
        )

        self.assertEqual(packet.get_payload(), "test payload")
        self.assertEqual(packet.get_layers(), ["Ethernet", "IP", "UDP"])
        self.assertEqual(packet.get_timestamp(), 1000.0)
        self.assertEqual(packet.get_src_ip(), "192.168.1.1")
        self.assertEqual(packet.get_dst_ip(), "10.0.0.1")

        # Test to_json
        json_data = packet.to_json()
        self.assertEqual(json_data["sport"], 123)
        self.assertEqual(str(json_data["src_ip"]), "192.168.1.1")

        # Test to_pandas
        df = packet.to_pandas()
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(len(df), 1)
        self.assertEqual(df["sport"][0], 123)

        # Test to_polars
        if POLARS_AVAILABLE:
            pl_df = packet.to_polars()
            self.assertIsInstance(pl_df, pl.DataFrame)
            self.assertEqual(len(pl_df), 1)
            self.assertEqual(pl_df["sport"][0], 123)


class TestSpecificPackets(unittest.TestCase):
    """Test specific packet types."""

    def test_ethernet_packet(self):
        """Test EthernetPacket."""
        packet = EthernetPacket(
            src_mac="00:11:22:33:44:55",
            dst_mac="aa:bb:cc:dd:ee:ff",
            type=0x0800,
        )
        self.assertEqual(str(packet.src_mac), "00:11:22:33:44:55")
        self.assertEqual(str(packet.dst_mac), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(packet.type, 0x0800)

    def test_arp_packet(self):
        """Test ARPPacket."""
        packet = ARPPacket(
            hw_type=1,
            proto_type=0x0800,
            sender_mac="00:11:22:33:44:55",
            sender_ip="192.168.1.1",
            target_mac="aa:bb:cc:dd:ee:ff",
            target_ip="10.0.0.1",
            opcode=1,
        )
        self.assertEqual(packet.opcode, 1)
        self.assertEqual(str(packet.sender_ip), "192.168.1.1")
        self.assertEqual(packet.get_src_ip(), "192.168.1.1")
        self.assertEqual(packet.get_dst_ip(), "10.0.0.1")

    def test_ip_packet(self):
        """Test IPPacket."""
        packet = IPPacket(
            version=4,
            src="192.168.1.1",
            dst="10.0.0.1",
            ttl=64,
            proto=6,
        )
        self.assertEqual(packet.version, 4)
        self.assertEqual(str(packet.src), "192.168.1.1")
        self.assertEqual(packet.get_src_ip(), "192.168.1.1")
        self.assertEqual(packet.get_dst_ip(), "10.0.0.1")

    def test_tcp_packet(self):
        """Test TCPPacket."""
        packet = TCPPacket(
            sport=80,
            dport=12345,
            flags="SA",
            seq=1000,
            ack=500,
        )
        self.assertEqual(packet.sport, 80)
        self.assertEqual(packet.dport, 12345)
        self.assertEqual(packet.flags, "SA")

    def test_udp_packet(self):
        """Test UDPPacket."""
        packet = UDPPacket(
            sport=53,
            dport=5353,
            len=100,
        )
        self.assertEqual(packet.sport, 53)
        self.assertEqual(packet.dport, 5353)
        self.assertEqual(packet.len, 100)

    def test_icmp_packet(self):
        """Test ICMPPacket."""
        packet = ICMPPacket(
            type=8,
            code=0,
            id=123,
            seq=1,
        )
        self.assertEqual(packet.type, 8)
        self.assertEqual(packet.code, 0)
        self.assertEqual(packet.id, 123)

    def test_stp_packet(self):
        """Test STPPacket."""
        packet = STPPacket(
            protocol_id=0,
            version=2,
            root_bridge_id="32768.00:11:22:33:44:55",
        )
        self.assertEqual(packet.protocol_id, 0)
        self.assertEqual(packet.version, 2)
        self.assertEqual(packet.root_bridge_id, "32768.00:11:22:33:44:55")


class TestValidation(unittest.TestCase):
    """Test Pydantic validation."""

    def test_invalid_ip(self):
        """Test invalid IP address validation."""
        with self.assertRaises(ValidationError):
            IPPacket(src="not.an.ip")

    def test_invalid_mac(self):
        """Test invalid MAC address validation."""
        with self.assertRaises(ValidationError):
            EthernetPacket(src_mac="invalid-mac")


if __name__ == "__main__":
    unittest.main()

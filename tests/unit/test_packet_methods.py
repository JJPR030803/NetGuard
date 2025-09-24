import os
import sys

import pandas as pd
import pytest

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from network_security_suite.models.packet_data_structures import (
    ARPPacketModel,
    EthernetPacketModel,
    ICMPPacketModel,
    IPPacketModel,
    NetworkPacketModel,
    STPPacketModel,
    TCPPacketModel,
    UDPPacketModel,
)

# Try to import polars, but don't fail if it's not installed
try:
    import polars as pl

    POLARS_AVAILABLE = True
except ImportError:
    POLARS_AVAILABLE = False


def test_to_json_method():
    """Test the to_json method for all packet types."""
    # Create instances of each packet type
    network_packet = NetworkPacketModel(
        payload="test", layers=["L2", "L3"], timestamp="2023-01-01"
    )
    arp_packet = ARPPacketModel(
        hw_type=1, proto_type=0x0800, sender_mac="00:11:22:33:44:55"
    )
    stp_packet = STPPacketModel(protocol_id=0, version=2, bpdutype=0x00)
    ethernet_packet = EthernetPacketModel(
        dst_mac="00:11:22:33:44:55", src_mac="55:44:33:22:11:00"
    )
    ip_packet = IPPacketModel(version=4, ttl=64, src="192.168.1.1", dst="192.168.1.2")
    icmp_packet = ICMPPacketModel(
        type=8, code=0, src_ip="192.168.1.1", dst_ip="192.168.1.2"
    )
    tcp_packet = TCPPacketModel(sport=80, dport=443, flags="SYN")
    udp_packet = UDPPacketModel(sport=53, dport=5353, len=8)

    # Test to_json method for each packet type
    assert isinstance(network_packet.to_json(), dict)
    assert isinstance(arp_packet.to_json(), dict)
    assert isinstance(stp_packet.to_json(), dict)
    assert isinstance(ethernet_packet.to_json(), dict)
    assert isinstance(ip_packet.to_json(), dict)
    assert isinstance(icmp_packet.to_json(), dict)
    assert isinstance(tcp_packet.to_json(), dict)
    assert isinstance(udp_packet.to_json(), dict)

    # Check specific fields
    assert arp_packet.to_json()["hw_type"] == 1
    assert ethernet_packet.to_json()["dst_mac"] == "00:11:22:33:44:55"
    assert ip_packet.to_json()["version"] == 4


def test_to_pandas_method():
    """Test the to_pandas method for all packet types."""
    # Create instances of each packet type
    network_packet = NetworkPacketModel(
        payload="test", layers=["L2", "L3"], timestamp="2023-01-01"
    )
    arp_packet = ARPPacketModel(
        hw_type=1, proto_type=0x0800, sender_mac="00:11:22:33:44:55"
    )

    # Test to_pandas method for each packet type
    assert isinstance(network_packet.to_pandas(), pd.DataFrame)
    assert isinstance(arp_packet.to_pandas(), pd.DataFrame)

    # Check DataFrame properties
    assert len(network_packet.to_pandas()) == 1
    assert "payload" in network_packet.to_pandas().columns
    assert "hw_type" in arp_packet.to_pandas().columns


@pytest.mark.skipif(not POLARS_AVAILABLE, reason="polars package not available")
def test_to_polars_method():
    """Test the to_polars method for all packet types."""
    # Create instances of each packet type
    network_packet = NetworkPacketModel(
        payload="test", layers=["L2", "L3"], timestamp="2023-01-01"
    )
    arp_packet = ARPPacketModel(
        hw_type=1, proto_type=0x0800, sender_mac="00:11:22:33:44:55"
    )

    # Test to_polars method for each packet type
    assert isinstance(network_packet.to_polars(), pl.DataFrame)
    assert isinstance(arp_packet.to_polars(), pl.DataFrame)

    # Check DataFrame properties
    assert network_packet.to_polars().height == 1
    assert "payload" in network_packet.to_polars().columns
    assert "hw_type" in arp_packet.to_polars().columns


def test_network_packet_model_creation():
    """Test NetworkPacketModel creation and basic properties."""
    packet = NetworkPacketModel(
        payload="test_payload",
        layers=["Ethernet", "IP", "TCP"],
        timestamp="2023-01-01T12:00:00",
    )

    assert packet.payload == "test_payload"
    assert packet.layers == ["Ethernet", "IP", "TCP"]
    assert packet.timestamp == "2023-01-01T12:00:00"


def test_arp_packet_model_creation():
    """Test ARPPacketModel creation and basic properties."""
    packet = ARPPacketModel(
        hw_type=1,
        proto_type=0x0800,
        sender_mac="00:11:22:33:44:55",
        sender_ip="192.168.1.1",
        target_mac="00:00:00:00:00:00",
        target_ip="192.168.1.2",
    )

    assert packet.hw_type == 1
    assert packet.proto_type == 0x0800
    assert packet.sender_mac == "00:11:22:33:44:55"
    assert packet.sender_ip == "192.168.1.1"


def test_tcp_packet_model_creation():
    """Test TCPPacketModel creation and basic properties."""
    packet = TCPPacketModel(sport=80, dport=443, flags="SYN", seq=1000, ack=0)

    assert packet.sport == 80
    assert packet.dport == 443
    assert packet.flags == "SYN"
    assert packet.seq == 1000
    assert packet.ack == 0


def test_udp_packet_model_creation():
    """Test UDPPacketModel creation and basic properties."""
    packet = UDPPacketModel(sport=53, dport=5353, len=8, chksum=0x1234)

    assert packet.sport == 53
    assert packet.dport == 5353
    assert packet.len == 8
    assert packet.chksum == 0x1234


def test_ip_packet_model_creation():
    """Test IPPacketModel creation and basic properties."""
    packet = IPPacketModel(
        version=4, ttl=64, src="192.168.1.1", dst="192.168.1.2", proto=6
    )

    assert packet.version == 4
    assert packet.ttl == 64
    assert packet.src == "192.168.1.1"
    assert packet.dst == "192.168.1.2"
    assert packet.proto == 6

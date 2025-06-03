"""
Sniffer package for network packet capture and analysis.

This package provides components for capturing, parsing, and analyzing network packets.
It uses low-level packet capture libraries to intercept network traffic and provides
a high-level API for working with the captured packets.

Components:
    packet.py: Defines packet data structures for different network protocols
    packet_capture.py: Provides the PacketCapture class for capturing network packets
    interfaces.py: Utilities for working with network interfaces
    testing.py: Tools for testing packet capture functionality

Classes:
    PacketCapture: Main class for capturing network packets
    NetworkPacket: Base class for network packet representations
    ARPPacket: Class for ARP protocol packets
    STPPacket: Class for Spanning Tree Protocol packets
    EthernetPacket: Class for Ethernet frame packets
"""

from .packet import ARPPacket, EthernetPacket, NetworkPacket, STPPacket
from .packet_capture import PacketCapture

__all__ = ["PacketCapture", "NetworkPacket", "ARPPacket", "STPPacket", "EthernetPacket"]

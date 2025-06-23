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
    loggers.py: Specialized logger classes for different handler types

Classes:
    PacketCapture: Main class for capturing network packets
    NetworkPacket: Base class for network packet representations
    ARPPacket: Class for ARP protocol packets
    STPPacket: Class for Spanning Tree Protocol packets
    EthernetPacket: Class for Ethernet frame packets
    ConsoleLogger: Logger for console output
    SecurityLogger: Logger for security-related events
    PacketLogger: Logger for packet-related information
    FileLogger: Logger for general file-based logging
    RotatingFileLogger: Logger with rotating file capability
    TimedRotatingFileLogger: Logger with time-based file rotation
    ErrorLogger: Logger for error messages
    DebugLogger: Logger for debug messages
    CriticalLogger: Logger for critical messages
    WarningLogger: Logger for warning messages
    InfoLogger: Logger for informational messages
"""

from ..models.packet_data_structures import ARPPacket, EthernetPacket, STPPacket
from .loggers import (
    ConsoleLogger,
    CriticalLogger,
    DebugLogger,
    ErrorLogger,
    FileLogger,
    InfoLogger,
    PacketLogger,
    RotatingFileLogger,
    SecurityLogger,
    TimedRotatingFileLogger,
    WarningLogger,
)
from .packet_capture import PacketCapture

__all__ = [
    "PacketCapture",
    "ARPPacket",
    "STPPacket",
    "EthernetPacket",
    "ConsoleLogger",
    "SecurityLogger",
    "PacketLogger",
    "FileLogger",
    "RotatingFileLogger",
    "TimedRotatingFileLogger",
    "ErrorLogger",
    "DebugLogger",
    "CriticalLogger",
    "WarningLogger",
    "InfoLogger",
]

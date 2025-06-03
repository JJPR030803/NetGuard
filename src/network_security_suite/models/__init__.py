"""
Models package containing data structure definitions for the Network Security Suite.

This package provides Pydantic models and data structures used throughout the application
for representing network packets, database schemas, and other data entities. These models
ensure type safety, validation, and serialization/deserialization capabilities.

Components:
    data_structures.py: Defines Pydantic models for network packets and related data
    database_schemas.py: Defines SQLAlchemy ORM models for database persistence

Classes:
    Packet: Base model for network packets with multiple protocol layers
    PacketLayer: Model representing a single protocol layer in a packet
    ARPPacketModel: Model for ARP protocol packets
    EthernetPacketModel: Model for Ethernet frame packets
    STPPacketModel: Model for Spanning Tree Protocol packets
    IPPacketModel: Model for IP protocol packets
    ICMPPacketModel: Model for ICMP protocol packets
    TCPPacketModel: Model for TCP protocol packets
    UDPPacketModel: Model for UDP protocol packets
"""
from .data_structures import (
    ARPPacketModel,
    EthernetPacketModel,
    ICMPPacketModel,
    IPPacketModel,
    Packet,
    PacketLayer,
    STPPacketModel,
    TCPPacketModel,
    UDPPacketModel,
)

__all__ = [
    "Packet",
    "PacketLayer",
    "ARPPacketModel",
    "EthernetPacketModel",
    "STPPacketModel",
    "IPPacketModel",
    "ICMPPacketModel",
    "TCPPacketModel",
    "UDPPacketModel",
]

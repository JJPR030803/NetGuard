"""
Data structures for network packet representation and processing.

This module defines Pydantic models for representing network packets and their layers,
providing structured data models with validation and serialization capabilities.
It includes models for various packet types (Ethernet, IP, TCP, UDP, ICMP, ARP, STP)
and utilities for converting packets to different formats (JSON, pandas, polars).
"""

from typing import Any, Dict, List, Optional

import pandas as pd
import pydantic as pyd
from pydantic import BaseModel, IPvAnyAddress
from pydantic_extra_types.mac_address import MacAddress

# Try to import polars, but don't fail if it's not installed
try:
    import polars as pl

    POLARS_AVAILABLE = True
except ImportError:
    POLARS_AVAILABLE = False


class PacketLayer(BaseModel):
    """
    Pydantic model for a network packet layer.

    This model represents a single layer in a network packet, containing
    the layer name and a dictionary of fields specific to that layer.

    Attributes:
        layer_name (str): The name of the layer (e.g., "Ethernet", "IP", "TCP").
        fields (dict[str, Any]): A dictionary of fields specific to the layer.
    """

    layer_name: str  # "Ethernet", "IP", "TCP", etc.
    fields: dict[str, Any]

    def show(self) -> None:
        """
        Display the layer information in a human-readable format.
        """
        print(f"Layer: {self.layer_name}")
        for key, value in self.fields.items():
            print(f"  {key}: {value}")


class Packet(BaseModel):
    """
    Base Pydantic model for network packets.

    This model represents a network packet with multiple protocol layers
    and is used for data processing and conversion to other formats (JSON, pandas, etc.).

    Attributes:
        timestamp (float): The timestamp when the packet was captured.
        layers (List[PacketLayer]): List of protocol layers in the packet.
        raw_size (int): The raw size of the packet in bytes.
    """

    timestamp: float
    layers: List[PacketLayer]
    raw_size: int

    def has_layer(self, layer_name: str) -> bool:
        """
        Check if the packet has a specific layer.

        Args:
            layer_name (str): The name of the layer to check for.

        Returns:
            bool: True if the packet has the specified layer, False otherwise.
        """
        return any(layer.layer_name == layer_name for layer in self.layers)

    def get_layer(self, layer_name: str) -> Optional[PacketLayer]:
        """
        Get a specific layer from the packet.

        Args:
            layer_name (str): The name of the layer to get.

        Returns:
            Optional[PacketLayer]: The layer if found, None otherwise.
        """
        for layer in self.layers:
            if layer.layer_name == layer_name:
                return layer
        return None

    def to_json(self) -> Dict[str, Any]:
        """
        Convert the packet to a JSON representation.
        """
        return self.model_dump()

    def show(self) -> None:
        """
        Display the packet information in a human-readable format.
        """
        print("Packet:")
        print(f"  Timestamp: {self.timestamp}")
        print(f"  Raw Size: {self.raw_size}")
        for layer in self.layers:
            layer.show()


class NetworkPacketModel(pyd.BaseModel):
    """
    Base Pydantic model for network packet representations.

    This model serves as the base for all specific packet type models
    and contains common fields shared by all network packets.

    Attributes:
        payload (Optional[str]): The packet payload data.
        layers (List[str]): List of protocol layers in the packet.
        timestamp (Optional[str]): The timestamp when the packet was captured.
        dst_ip (Optional[IPvAnyAddress]): Destination IP address.
        src_ip (Optional[IPvAnyAddress]): Source IP address.
    """

    payload: Optional[str] = None
    layers: List[str] = []
    timestamp: Optional[str] = None
    dst_ip: Optional[IPvAnyAddress] = None
    src_ip: Optional[IPvAnyAddress] = None

    def to_json(self) -> Dict[str, Any]:
        """
        Convert the packet model to a JSON-serializable dictionary.

        Returns:
            Dict[str, Any]: A dictionary representation of the packet.
        """
        return self.model_dump()

    def to_pandas(self) -> pd.DataFrame:
        """
        Convert the packet model to a pandas DataFrame.

        Returns:
            pd.DataFrame: A DataFrame containing the packet data.
        """
        return pd.DataFrame([self.to_json()])

    def to_polars(self) -> pl.DataFrame:
        """
        Convert the packet model to a polars DataFrame.

        Returns:
            pl.DataFrame: A DataFrame containing the packet data.

        Raises:
            ImportError: If the polars package is not installed.
        """
        if not POLARS_AVAILABLE:
            raise ImportError(
                "The polars package is not installed. "
                "Please install it with 'pip install polars' or 'poetry add polars'."
            )

        try:
            # Convert the model to a dictionary
            data = self.model_dump()

            # Pre-process special fields
            for key, value in data.items():
                # Convert IP addresses and MAC addresses to strings
                if hasattr(value, "__str__") and (
                    type(value).__name__ in ("IPvAnyAddress", "MacAddress")
                ):
                    data[key] = str(value)
                # Convert bytes to hex strings
                elif isinstance(value, bytes):
                    data[key] = value.hex()
                # Convert lists to string representation
                elif isinstance(value, list):
                    data[key] = str(value)

            # Create DataFrame
            return pl.DataFrame([data])

        except Exception as e:
            print(f"Error converting model to Polars DataFrame: {e}")
            return pl.DataFrame()


class ARPPacketModel(NetworkPacketModel):
    """
    Pydantic model for Address Resolution Protocol (ARP) packets.

    ARP is used for mapping an IP address to a physical MAC address on a local network.

    Attributes:
        hw_type (Optional[int]): Hardware type (1 for Ethernet).
        proto_type (Optional[int]): Protocol type (0x0800 for IPv4).
        hw_len (Optional[int]): Hardware address length (6 for MAC address).
        proto_len (Optional[int]): Protocol address length (4 for IPv4 address).
        opcode (Optional[int]): Operation code (1 for request, 2 for reply).
        sender_mac (Optional[MacAddress]): MAC address of the sender.
        sender_ip (Optional[IPvAnyAddress]): IP address of the sender.
        target_mac (Optional[MacAddress]): MAC address of the target.
        target_ip (Optional[IPvAnyAddress]): IP address of the target.
    """

    hw_type: Optional[int] = None  # 1 para ethernet
    proto_type: Optional[int] = None  # 0x0800 para IPv4
    hw_len: Optional[int] = None  # Tamaño de direccion MAC(6)
    proto_len: Optional[int] = None  # Tamaño de direccion IP(4)
    opcode: Optional[int] = None  # 1 para request 2 para reply
    sender_mac: Optional[MacAddress] = None
    sender_ip: Optional[IPvAnyAddress] = None
    target_mac: Optional[MacAddress] = None
    target_ip: Optional[IPvAnyAddress] = None

    @classmethod
    def new(cls, **data: Any) -> "ARPPacketModel":
        """
        Create a new ARPPacketModel instance from keyword arguments.

        Args:
            **data: Keyword arguments corresponding to the model's fields.

        Returns:
            ARPPacketModel: A new instance of the ARPPacketModel.
        """
        return ARPPacketModel(**data)

    def show(self) -> None:
        """
        Display the packet information in a human-readable format.

        This method prints out all relevant ARP packet information,
        including hardware type, protocol type, addresses, and operation.
        """
        print("ARP Packet:")
        print(f"  Hardware Type: {self.hw_type}")
        print(f"  Protocol Type: {self.proto_type}")
        print(f"  Hardware Length: {self.hw_len}")
        print(f"  Protocol Length: {self.proto_len}")
        print(f"  Operation: {self.opcode}")
        print(f"  Sender MAC: {self.sender_mac}")
        print(f"  Sender IP: {self.sender_ip}")
        print(f"  Target MAC: {self.target_mac}")
        print(f"  Target IP: {self.target_ip}")
        print(f"  Timestamp: {self.timestamp}")


class STPPacketModel(NetworkPacketModel):
    """
    Pydantic model for Spanning Tree Protocol (STP) packets.

    STP is used to prevent loops in network topologies with redundant paths.

    Attributes:
        protocol_id (Optional[int]): Protocol identifier.
        version (Optional[int]): STP version.
        bpdutype (Optional[int]): Bridge Protocol Data Unit type (0x00 for Configuration, 0x80 for TCN).
        flags (Optional[bytes]): Flag bits, including Topology Change Notification (0x01).
        root_bridge_id (Optional[str]): ID of the root bridge.
        sender_bridge_id (Optional[str]): ID of the sender bridge.
        root_path_cost (Optional[int]): Cost of the path to the root bridge.
        port_id (Optional[int]): ID of the sending port.
        message_age (Optional[int]): Time since the message was generated.
        max_age (Optional[int]): Maximum lifetime of the message.
        hello_time (Optional[int]): Interval between BPDUs.
        forward_delay (Optional[int]): Time to wait before forwarding.
    """

    protocol_id: Optional[int] = None
    version: Optional[int] = None
    bpdutype: Optional[int] = None  # 0x00(Configuracion) 0x80(TCN)
    flags: Optional[bytes] = None  # Bit topology channel 0x01(TCN)
    root_bridge_id: Optional[str] = None
    sender_bridge_id: Optional[str] = None
    root_path_cost: Optional[int] = None
    port_id: Optional[int] = None  # ID del puerto emisor
    message_age: Optional[int] = (
        None  # Tiempo de vida del mensaje desde que fue generado
    )
    max_age: Optional[int] = None  # Tiempo de vida maximo del mensaje
    hello_time: Optional[int] = None  # Intervalo entre BPDUs
    forward_delay: Optional[int] = None  # Tiempo de espera antes del forwarding

    @classmethod
    def new(cls, **data: Any) -> "STPPacketModel":
        """
        Create a new STPPacketModel instance from keyword arguments.

        Args:
            **data: Keyword arguments corresponding to the model's fields.

        Returns:
            STPPacketModel: A new instance of the STPPacketModel.
        """
        return STPPacketModel(**data)

    def show(self) -> None:
        """
        Display the packet information in a human-readable format.

        This method prints out all relevant STP packet information,
        including protocol ID, version, BPDU type, flags, and bridge IDs.
        """
        print("STP Packet:")
        print(f"  Protocol ID: {self.protocol_id}")
        print(f"  Version: {self.version}")
        print(f"  BPDU Type: {self.bpdutype}")
        print(f"  Flags: {self.flags!r}")
        print(f"  Root Bridge ID: {self.root_bridge_id}")
        print(f"  Sender Bridge ID: {self.sender_bridge_id}")
        print(f"  Root Path Cost: {self.root_path_cost}")
        print(f"  Port ID: {self.port_id}")
        print(f"  Message Age: {self.message_age}")
        print(f"  Max Age: {self.max_age}")
        print(f"  Hello Time: {self.hello_time}")
        print(f"  Forward Delay: {self.forward_delay}")
        print(f"  Timestamp: {self.timestamp}")


class EthernetPacketModel(NetworkPacketModel):
    """
    Pydantic model for Ethernet frames (Layer 2 of the OSI model).

    Ethernet is the most common Layer 2 protocol used in local area networks (LANs).

    Attributes:
        preamble (Optional[int]): Synchronization pattern (typically 0xAA).
        sfd (Optional[int]): Start Frame Delimiter, marks the beginning of the frame.
        dst_mac (Optional[MacAddress]): Destination MAC address.
        src_mac (Optional[MacAddress]): Source MAC address.
        type (Optional[int]): EtherType field indicating the protocol of the payload (e.g., 0x0800 for IPv4).
        crc (Optional[str]): Cyclic Redundancy Check for error detection.
    """

    preamble: Optional[int] = None  # Patron de sincronizacion (0xAA)
    sfd: Optional[int] = None  # Marca de inicio de la trama
    dst_mac: Optional[MacAddress] = None
    src_mac: Optional[MacAddress] = None
    type: Optional[int] = None  # Ej: 0x0800 IPv4
    crc: Optional[str] = None  # checksum de la trama

    @classmethod
    def new(cls, **data: Any) -> "EthernetPacketModel":
        """
        Create a new EthernetPacketModel instance from keyword arguments.

        Args:
            **data: Keyword arguments corresponding to the model's fields.

        Returns:
            EthernetPacketModel: A new instance of the EthernetPacketModel.
        """
        return EthernetPacketModel(**data)

    def show(self) -> None:
        """
        Display the packet information in a human-readable format.

        This method prints out all relevant Ethernet frame information,
        including MAC addresses, EtherType, and CRC.
        """
        print("Ethernet Packet:")
        print(f"  Preamble: {self.preamble}")
        print(f"  Start Frame Delimiter: {self.sfd}")
        print(f"  Destination MAC: {self.dst_mac}")
        print(f"  Source MAC: {self.src_mac}")
        print(f"  EtherType: {self.type}")
        print(f"  CRC: {self.crc}")
        print(f"  Timestamp: {self.timestamp}")


class IPPacketModel(NetworkPacketModel):
    """
    Pydantic model for Internet Protocol (IP) packets.

    IP is the principal communications protocol for relaying packets across network boundaries.

    Attributes:
        version (Optional[int]): IP version (4 for IPv4, 6 for IPv6).
        ihl (Optional[int]): Internet Header Length (number of 32-bit words in the header).
        tos (Optional[int]): Type of Service, specifies priority and handling.
        len (Optional[int]): Total Length of the packet.
        id (Optional[int]): Identification field for uniquely identifying fragments.
        flags (Optional[int]): Flags for controlling fragmentation.
        frag (Optional[int]): Fragment Offset, indicates position of fragment in original packet.
        ttl (Optional[int]): Time to Live, prevents packets from circulating indefinitely.
        proto (Optional[int]): Protocol field, indicates the next level protocol.
        chksum (Optional[int]): Header Checksum for error detection.
        src (Optional[IPvAnyAddress]): Source IP address.
        dst (Optional[IPvAnyAddress]): Destination IP address.
        options (Optional[List[dict]]): IP options.
    """

    version: Optional[int] = None  # 4 para IPv4, 6 para IPv6
    ihl: Optional[int] = None  # Internet Header Length
    tos: Optional[int] = None  # Type of Service
    len: Optional[int] = None  # Total Length
    id: Optional[int] = None  # Identification
    flags: Optional[int] = None  # Flags
    frag: Optional[int] = None  # Fragment Offset
    ttl: Optional[int] = None  # Time to Live
    proto: Optional[int] = None  # Protocol
    chksum: Optional[int] = None  # Header Checksum
    src: Optional[IPvAnyAddress] = None  # Source Address
    dst: Optional[IPvAnyAddress] = None  # Destination Address
    options: Optional[List[dict]] = None  # Options

    @classmethod
    def new(cls, **data: Any) -> "IPPacketModel":
        """
        Create a new IPPacketModel instance from keyword arguments.

        Args:
            **data: Keyword arguments corresponding to the model's fields.

        Returns:
            IPPacketModel: A new instance of the IPPacketModel.
        """
        return IPPacketModel(**data)

    def show(self) -> None:
        """
        Display the packet information in a human-readable format.

        This method prints out all relevant IP packet information,
        including version, header length, addresses, and protocol.
        """
        print("IP Packet:")
        print(f"  Version: {self.version}")
        print(f"  Internet Header Length: {self.ihl}")
        print(f"  Type of Service: {self.tos}")
        print(f"  Total Length: {self.len}")
        print(f"  Identification: {self.id}")
        print(f"  Flags: {self.flags}")
        print(f"  Fragment Offset: {self.frag}")
        print(f"  Time to Live: {self.ttl}")
        print(f"  Protocol: {self.proto}")
        print(f"  Header Checksum: {self.chksum}")
        print(f"  Source Address: {self.src}")
        print(f"  Destination Address: {self.dst}")
        print(f"  Options: {self.options}")
        print(f"  Timestamp: {self.timestamp}")


class ICMPPacketModel(NetworkPacketModel):
    """
    Pydantic model for Internet Control Message Protocol (ICMP) packets.

    ICMP is used by network devices to send error messages and operational information.
    Common uses include ping and traceroute.

    Attributes:
        type (Optional[int]): Type of message (e.g., 0 for Echo Reply, 8 for Echo Request).
        code (Optional[int]): Subtype of the message, providing additional context.
        chksum (Optional[int]): Checksum for error detection.
        id (Optional[int]): Identifier to help match requests with replies.
        seq (Optional[int]): Sequence number to help match requests with replies.
        data (Optional[bytes]): Payload data of the ICMP message.
    """

    type: Optional[int] = None  # Type of message
    code: Optional[int] = None  # Code
    chksum: Optional[int] = None  # Checksum
    id: Optional[int] = None  # Identifier
    seq: Optional[int] = None  # Sequence Number
    data: Optional[bytes] = None  # Data

    @classmethod
    def new(cls, **data: Any) -> "ICMPPacketModel":
        """
        Create a new ICMPPacketModel instance from keyword arguments.

        Args:
            **data: Keyword arguments corresponding to the model's fields.

        Returns:
            ICMPPacketModel: A new instance of the ICMPPacketModel.
        """
        return ICMPPacketModel(**data)

    def show(self) -> None:
        """
        Display the packet information in a human-readable format.

        This method prints out all relevant ICMP packet information,
        including type, code, checksum, and data.
        """
        print("ICMP Packet:")
        print(f"  Type: {self.type}")
        print(f"  Code: {self.code}")
        print(f"  Checksum: {self.chksum}")
        print(f"  Identifier: {self.id}")
        print(f"  Sequence Number: {self.seq}")
        print(f"  Data: {self.data!r}")
        print(f"  Source IP: {self.src_ip}")
        print(f"  Destination IP: {self.dst_ip}")
        print(f"  Timestamp: {self.timestamp}")


class TCPPacketModel(NetworkPacketModel):
    """
    Pydantic model for Transmission Control Protocol (TCP) packets.

    TCP is one of the main protocols of the Internet protocol suite, providing
    reliable, ordered, and error-checked delivery of data between applications.

    Attributes:
        sport (Optional[int]): Source port number.
        dport (Optional[int]): Destination port number.
        seq (Optional[int]): Sequence number, used for ordering segments.
        ack (Optional[int]): Acknowledgment number, indicates next expected sequence number.
        dataofs (Optional[int]): Data offset, specifies the size of the TCP header.
        reserved (Optional[int]): Reserved bits, should be zero.
        flags (Optional[str]): Control flags (e.g., SYN, ACK, FIN).
        window (Optional[int]): Window size, for flow control.
        chksum (Optional[int]): Checksum for error detection.
        urgptr (Optional[int]): Urgent pointer, indicates important data.
        options (Optional[List[tuple]]): TCP options.
    """

    sport: Optional[int] = None  # Source Port
    dport: Optional[int] = None  # Destination Port
    seq: Optional[int] = None  # Sequence Number
    ack: Optional[int] = None  # Acknowledgment Number
    dataofs: Optional[int] = None  # Data Offset
    reserved: Optional[int] = None  # Reserved
    flags: Optional[str] = None  # Flags
    window: Optional[int] = None  # Window Size
    chksum: Optional[int] = None  # Checksum
    urgptr: Optional[int] = None  # Urgent Pointer
    options: Optional[List[tuple]] = None  # Options

    @classmethod
    def new(cls, **data: Any) -> "TCPPacketModel":
        """
        Create a new TCPPacketModel instance from keyword arguments.

        Args:
            **data: Keyword arguments corresponding to the model's fields.

        Returns:
            TCPPacketModel: A new instance of the TCPPacketModel.
        """
        return TCPPacketModel(**data)

    def show(self) -> None:
        """
        Display the packet information in a human-readable format.

        This method prints out all relevant TCP packet information,
        including ports, sequence numbers, flags, and options.
        """
        print("TCP Packet:")
        print(f"  Source Port: {self.sport}")
        print(f"  Destination Port: {self.dport}")
        print(f"  Sequence Number: {self.seq}")
        print(f"  Acknowledgment Number: {self.ack}")
        print(f"  Data Offset: {self.dataofs}")
        print(f"  Reserved: {self.reserved}")
        print(f"  Flags: {self.flags}")
        print(f"  Window Size: {self.window}")
        print(f"  Checksum: {self.chksum}")
        print(f"  Urgent Pointer: {self.urgptr}")
        print(f"  Options: {self.options}")
        print(f"  Source IP: {self.src_ip}")
        print(f"  Destination IP: {self.dst_ip}")
        print(f"  Timestamp: {self.timestamp}")


class UDPPacketModel(NetworkPacketModel):
    """
    Pydantic model for User Datagram Protocol (UDP) packets.

    UDP is a connectionless protocol that provides a simple but unreliable message service.
    It's often used for real-time applications where speed is more important than reliability.

    Attributes:
        sport (Optional[int]): Source port number.
        dport (Optional[int]): Destination port number.
        len (Optional[int]): Length of the UDP header and data.
        chksum (Optional[int]): Checksum for error detection.
    """

    sport: Optional[int] = None  # Source Port
    dport: Optional[int] = None  # Destination Port
    len: Optional[int] = None  # Length
    chksum: Optional[int] = None  # Checksum

    @classmethod
    def new(cls, **data: Any) -> "UDPPacketModel":
        """
        Create a new UDPPacketModel instance from keyword arguments.

        Args:
            **data: Keyword arguments corresponding to the model's fields.

        Returns:
            UDPPacketModel: A new instance of the UDPPacketModel.
        """
        return UDPPacketModel(**data)

    def show(self) -> None:
        """
        Display the packet information in a human-readable format.

        This method prints out all relevant UDP packet information,
        including ports, length, and checksum.
        """
        print("UDP Packet:")
        print(f"  Source Port: {self.sport}")
        print(f"  Destination Port: {self.dport}")
        print(f"  Length: {self.len}")
        print(f"  Checksum: {self.chksum}")
        print(f"  Source IP: {self.src_ip}")
        print(f"  Destination IP: {self.dst_ip}")
        print(f"  Timestamp: {self.timestamp}")

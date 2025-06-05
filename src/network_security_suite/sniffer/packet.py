"""
Network packet representation module.

This module defines classes for representing different types of network packets,
including Ethernet, IP, TCP, UDP, ICMP, ARP, and STP packets. Each packet type
is implemented as a class that inherits from the NetworkPacket abstract base class.
"""

from abc import ABC, abstractmethod
from typing import List, Optional


class NetworkPacket(ABC):
    """
    Abstract base class for network packet representations.

    This class defines the common interface and properties for all network packet types.
    Concrete packet classes should inherit from this class and implement its abstract methods.

    Attributes:
        payload (Optional[str]): The packet payload data.
        layers (List): List of protocol layers in the packet.
        timestamp (Optional[str]): The timestamp when the packet was captured.
        dst_ip (Optional[str]): Destination IP address.
        src_ip (Optional[str]): Source IP address.
    """

    def __init__(self) -> None:
        """
        Initialize a new NetworkPacket instance.

        Sets up the basic attributes common to all network packets.
        """
        self.payload: Optional[str] = None
        self.layers: List = []
        self.timestamp: Optional[str] = None
        self.dst_ip: Optional[str] = None
        self.src_ip: Optional[str] = None

    @abstractmethod
    def get_payload(self) -> Optional[str]:
        """
        Get the payload data of the packet.

        Returns:
            Optional[str]: The payload data of the packet.
        """

    @abstractmethod
    def get_layers(self) -> List:
        """
        Get the list of protocol layers in the packet.

        Returns:
            List: A list of protocol layers in the packet.
        """

    @abstractmethod
    def get_timestamp(self) -> Optional[str]:
        """
        Get the timestamp when the packet was captured.

        Returns:
            Optional[str]: The timestamp of the packet capture.
        """

    @abstractmethod
    def get_dst_ip(self) -> Optional[str]:
        """
        Get the destination IP address of the packet.

        Returns:
            Optional[str]: The destination IP address.
        """

    @abstractmethod
    def get_src_ip(self) -> Optional[str]:
        """
        Get the source IP address of the packet.

        Returns:
            Optional[str]: The source IP address.
        """

    @abstractmethod
    def show(self) -> None:
        """
        Display the packet information in a human-readable format.

        This method should print out all relevant packet information,
        including headers, addresses, and payload summary.
        """


# Capa 2  del modelo OSI


class ARPPacket(NetworkPacket):
    """
    Class representing an Address Resolution Protocol (ARP) packet.

    ARP is used for mapping an IP address to a physical MAC address on a local network.

    Attributes:
        hw_type (Optional[int]): Hardware type (1 for Ethernet).
        proto_type (Optional[int]): Protocol type (0x0800 for IPv4).
        hw_len (Optional[int]): Hardware address length (6 for MAC address).
        proto_len (Optional[int]): Protocol address length (4 for IPv4 address).
        opcode (Optional[int]): Operation code (1 for request, 2 for reply).
        sender_mac (Optional[str]): MAC address of the sender.
        sender_ip (Optional[str]): IP address of the sender.
        target_mac (Optional[str]): MAC address of the target.
        target_ip (Optional[str]): IP address of the target.
    """

    def __init__(self) -> None:
        """
        Initialize a new ARPPacket instance.

        Sets up the basic attributes for an ARP packet.
        """
        super().__init__()
        self.hw_type: Optional[int] = None  # 1 para ethernet
        self.proto_type: Optional[int] = None  # 0x0800 para IPv4
        self.hw_len: Optional[int] = None  # Tamaño de direccion MAC(6)
        self.proto_len: Optional[int] = None  # Tamaño de direccion IP(4)
        self.opcode: Optional[int] = None  # 1 para request 2 para reply
        self.sender_mac: Optional[str] = None
        self.sender_ip: Optional[str] = None
        self.target_mac: Optional[str] = None
        self.target_ip: Optional[str] = None

    def get_payload(self) -> Optional[str]:
        """
        Get the payload data of the packet.

        Returns:
            Optional[str]: The payload data of the packet.
        """
        return self.payload

    def get_layers(self) -> List:
        """
        Get the list of protocol layers in the packet.

        Returns:
            List: A list of protocol layers in the packet.
        """
        return self.layers

    def get_timestamp(self) -> Optional[str]:
        """
        Get the timestamp when the packet was captured.

        Returns:
            Optional[str]: The timestamp of the packet capture.
        """
        return self.timestamp

    def get_dst_ip(self) -> Optional[str]:
        """
        Get the destination IP address of the packet.

        Returns:
            Optional[str]: The destination IP address (target_ip for ARP).
        """
        return self.target_ip

    def get_src_ip(self) -> Optional[str]:
        """
        Get the source IP address of the packet.

        Returns:
            Optional[str]: The source IP address (sender_ip for ARP).
        """
        return self.sender_ip

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


class STPPacket(NetworkPacket):
    """
    Class representing a Spanning Tree Protocol (STP) packet.

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

    def __init__(self) -> None:
        """
        Initialize a new STPPacket instance.

        Sets up the basic attributes for an STP packet.
        """
        super().__init__()
        self.protocol_id: Optional[int] = None
        self.version: Optional[int] = None
        self.bpdutype: Optional[int] = None  # 0x00(Configuracion) 0x80(TCN)
        self.flags: Optional[bytes] = None  # Bit topology channel 0x01(TCN)
        self.root_bridge_id: Optional[str] = None
        self.sender_bridge_id: Optional[str] = None
        self.root_path_cost: Optional[int] = None
        self.port_id: Optional[int] = None  # ID del puerto emisor
        self.message_age: Optional[int] = (
            None  # Tiempo de vida del mensaje desde que fue generado
        )
        self.max_age: Optional[int] = None  # Tiempo de vida maximo del mensaje
        self.hello_time: Optional[int] = None  # Intervalo entre BPDUs
        self.forward_delay: Optional[int] = None  # Tiempo espera antes de forwarding

    def get_payload(self) -> Optional[str]:
        """
        Get the payload data of the packet.

        Returns:
            Optional[str]: The payload data of the packet.
        """
        return self.payload

    def get_layers(self) -> List:
        """
        Get the list of protocol layers in the packet.

        Returns:
            List: A list of protocol layers in the packet.
        """
        return self.layers

    def get_timestamp(self) -> Optional[str]:
        """
        Get the timestamp when the packet was captured.

        Returns:
            Optional[str]: The timestamp of the packet capture.
        """
        return self.timestamp

    def get_dst_ip(self) -> Optional[str]:
        """
        Get the destination IP address of the packet.

        Returns:
            Optional[str]: The destination IP address.
            Note: STP operates at Layer 2 and doesn't have IP addresses.
        """
        return self.dst_ip

    def get_src_ip(self) -> Optional[str]:
        """
        Get the source IP address of the packet.

        Returns:
            Optional[str]: The source IP address.
            Note: STP operates at Layer 2 and doesn't have IP addresses.
        """
        return self.src_ip

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
        print(f"  Flags: {self.flags!r}")  # Use !r to safely format bytes
        print(f"  Root Bridge ID: {self.root_bridge_id}")
        print(f"  Sender Bridge ID: {self.sender_bridge_id}")
        print(f"  Root Path Cost: {self.root_path_cost}")
        print(f"  Port ID: {self.port_id}")
        print(f"  Message Age: {self.message_age}")
        print(f"  Max Age: {self.max_age}")
        print(f"  Hello Time: {self.hello_time}")
        print(f"  Forward Delay: {self.forward_delay}")
        print(f"  Timestamp: {self.timestamp}")


class EthernetPacket(NetworkPacket):
    """
    Class representing an Ethernet frame (Layer 2 of the OSI model).

    Ethernet is the most common Layer 2 protocol used in local area networks (LANs).

    Attributes:
        preamble (Optional[int]): Synchronization pattern (typically 0xAA).
        sfd (Optional[int]): Start Frame Delimiter, marks the beginning of the frame.
        dst_mac (Optional[str]): Destination MAC address.
        src_mac (Optional[str]): Source MAC address.
        type (Optional[int]): EtherType field indicating the protocol of the payload (e.g., 0x0800 for IPv4).
        payload (Optional[str]): The data being carried by the frame.
        crc (Optional[str]): Cyclic Redundancy Check for error detection.
    """

    def __init__(self) -> None:
        """
        Initialize a new EthernetPacket instance.

        Sets up the basic attributes for an Ethernet frame.
        """
        super().__init__()
        self.preamble: Optional[int] = None  # Patron de sincronizacion (0xAA)
        self.sfd: Optional[int] = None  # Marca de inicio de la trama
        self.dst_mac: Optional[str] = None
        self.src_mac: Optional[str] = None
        self.type: Optional[int] = None  # Ej: 0x0800 IPv4
        self.payload: Optional[str] = None
        self.crc: Optional[str] = None  # checksum de la trama

    def get_payload(self) -> Optional[str]:
        """
        Get the payload data of the packet.

        Returns:
            Optional[str]: The payload data of the packet.
        """
        return self.payload

    def get_layers(self) -> List:
        """
        Get the list of protocol layers in the packet.

        Returns:
            List: A list of protocol layers in the packet.
        """
        return self.layers

    def get_timestamp(self) -> Optional[str]:
        """
        Get the timestamp when the packet was captured.

        Returns:
            Optional[str]: The timestamp of the packet capture.
        """
        return self.timestamp

    def get_dst_ip(self) -> Optional[str]:
        """
        Get the destination IP address of the packet.

        Returns:
            Optional[str]: The destination IP address.
            Note: Ethernet frames themselves don't contain IP addresses,
            but this method returns the dst_ip attribute which might be
            populated from higher layer protocols.
        """
        return self.dst_ip

    def get_src_ip(self) -> Optional[str]:
        """
        Get the source IP address of the packet.

        Returns:
            Optional[str]: The source IP address.
            Note: Ethernet frames themselves don't contain IP addresses,
            but this method returns the src_ip attribute which might be
            populated from higher layer protocols.
        """
        return self.src_ip

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


# ##################TODO implementar siguientes capas ######################

# TODO

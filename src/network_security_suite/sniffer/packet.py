from abc import ABC, abstractmethod

# TODO crear packet class para manejar los paquetes
# TODO pensar en estructura de datos


class NetworkPacket(ABC):
    """
    Abstract base class for network packet representations.

    This class defines the common interface and properties for all network packet types.
    Concrete packet classes should inherit from this class and implement its abstract methods.

    Attributes:
        payload (str | None): The packet payload data.
        layers (list): List of protocol layers in the packet.
        timestamp (str | None): The timestamp when the packet was captured.
        dst_ip (str | None): Destination IP address.
        src_ip (str | None): Source IP address.
    """

    def __init__(self):
        """
        Initialize a new NetworkPacket instance.

        Sets up the basic attributes common to all network packets.
        """
        self.payload: str | None = None
        self.layers: list = []
        self.timestamp: str | None = None
        self.dst_ip: str | None = None
        self.src_ip: str | None = None

    @abstractmethod
    def get_payload(self):
        """
        Get the payload data of the packet.

        Returns:
            str: The payload data of the packet.
        """
        pass

    @abstractmethod
    def get_layers(self):
        """
        Get the list of protocol layers in the packet.

        Returns:
            list: A list of protocol layers in the packet.
        """
        pass

    @abstractmethod
    def get_timestamp(self):
        """
        Get the timestamp when the packet was captured.

        Returns:
            str: The timestamp of the packet capture.
        """
        pass

    @abstractmethod
    def get_dst_ip(self):
        """
        Get the destination IP address of the packet.

        Returns:
            str: The destination IP address.
        """
        pass

    @abstractmethod
    def get_src_ip(self):
        """
        Get the source IP address of the packet.

        Returns:
            str: The source IP address.
        """
        pass

    @abstractmethod
    def show(self):
        """
        Display the packet information in a human-readable format.

        This method should print out all relevant packet information,
        including headers, addresses, and payload summary.
        """
        pass


# Capa 2  del modelo OSI


class ARPPacket(NetworkPacket):
    """
    Class representing an Address Resolution Protocol (ARP) packet.

    ARP is used for mapping an IP address to a physical MAC address on a local network.

    Attributes:
        hw_type (int | None): Hardware type (1 for Ethernet).
        proto_type (int | None): Protocol type (0x0800 for IPv4).
        hw_len (int | None): Hardware address length (6 for MAC address).
        proto_len (int | None): Protocol address length (4 for IPv4 address).
        opcode (int | None): Operation code (1 for request, 2 for reply).
        sender_mac (str | None): MAC address of the sender.
        sender_ip (str | None): IP address of the sender.
        target_mac (str | None): MAC address of the target.
        target_ip (str | None): IP address of the target.
    """

    def __init__(self):
        """
        Initialize a new ARPPacket instance.

        Sets up the basic attributes for an ARP packet.
        """
        super().__init__()
        self.hw_type: int | None = None  # 1 para ethernet
        self.proto_type: int | None = None  # 0x0800 para IPv4
        self.hw_len: int | None = None  # Tamaño de direccion MAC(6)
        self.proto_len: int | None = None  # Tamaño de direccion IP(4)
        self.opcode: int | None = None  # 1 para request 2 para reply
        self.sender_mac: str | None = None
        self.sender_ip: str | None = None
        self.target_mac: str | None = None
        self.target_ip: str | None = None

    def get_payload(self):
        """
        Get the payload data of the packet.

        Returns:
            str: The payload data of the packet.
        """
        return self.payload

    def get_layers(self):
        """
        Get the list of protocol layers in the packet.

        Returns:
            list: A list of protocol layers in the packet.
        """
        return self.layers

    def get_timestamp(self):
        """
        Get the timestamp when the packet was captured.

        Returns:
            str: The timestamp of the packet capture.
        """
        return self.timestamp

    def get_dst_ip(self):
        """
        Get the destination IP address of the packet.

        Returns:
            str: The destination IP address (target_ip for ARP).
        """
        return self.target_ip

    def get_src_ip(self):
        """
        Get the source IP address of the packet.

        Returns:
            str: The source IP address (sender_ip for ARP).
        """
        return self.sender_ip

    def show(self):
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
        protocol_id (int | None): Protocol identifier.
        version (int | None): STP version.
        bpdutype (int | None): Bridge Protocol Data Unit type (0x00 for Configuration, 0x80 for TCN).
        flags (bytes | None): Flag bits, including Topology Change Notification (0x01).
        root_bridge_id (str | None): ID of the root bridge.
        sender_bridge_id (str | None): ID of the sender bridge.
        root_path_cost (int | None): Cost of the path to the root bridge.
        port_id (int | None): ID of the sending port.
        message_age (int | None): Time since the message was generated.
        max_age (int | None): Maximum lifetime of the message.
        hello_time (int | None): Interval between BPDUs.
        forward_delay (int | None): Time to wait before forwarding.
    """

    def __init__(self):
        """
        Initialize a new STPPacket instance.

        Sets up the basic attributes for an STP packet.
        """
        super().__init__()
        self.protocol_id: int | None = None
        self.version: int | None = None
        self.bpdutype: int | None = None  # 0x00(Configuracion) 0x80(TCN)
        self.flags: bytes | None = None  # Bit topology channel 0x01(TCN)
        self.root_bridge_id: str | None = None
        self.sender_bridge_id: str | None = None
        self.root_path_cost: int | None = None
        self.port_id: int | None = None  # ID del puerto emisor
        self.message_age: int | None = (
            None  # Tiempo de vida del mensaje desde que fue generado
        )
        self.max_age: int | None = None  # Tiempo de vida maximo del mensaje
        self.hello_time: int | None = None  # Intervalo entre BPDUs
        self.forward_delay: int | None = None  # Tiempo espera antes de forwarding

    def get_payload(self):
        """
        Get the payload data of the packet.

        Returns:
            str: The payload data of the packet.
        """
        return self.payload

    def get_layers(self):
        """
        Get the list of protocol layers in the packet.

        Returns:
            list: A list of protocol layers in the packet.
        """
        return self.layers

    def get_timestamp(self):
        """
        Get the timestamp when the packet was captured.

        Returns:
            str: The timestamp of the packet capture.
        """
        return self.timestamp

    def get_dst_ip(self):
        """
        Get the destination IP address of the packet.

        Returns:
            str: The destination IP address.
            Note: STP operates at Layer 2 and doesn't have IP addresses.
        """
        return self.dst_ip

    def get_src_ip(self):
        """
        Get the source IP address of the packet.

        Returns:
            str: The source IP address.
            Note: STP operates at Layer 2 and doesn't have IP addresses.
        """
        return self.src_ip

    def show(self):
        """
        Display the packet information in a human-readable format.

        This method prints out all relevant STP packet information,
        including protocol ID, version, BPDU type, flags, and bridge IDs.
        """
        print("STP Packet:")
        print(f"  Protocol ID: {self.protocol_id}")
        print(f"  Version: {self.version}")
        print(f"  BPDU Type: {self.bpdutype}")
        print(f"  Flags: {self.flags}")
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
        preamble (int | None): Synchronization pattern (typically 0xAA).
        sfd (int | None): Start Frame Delimiter, marks the beginning of the frame.
        dst_mac (str | None): Destination MAC address.
        src_mac (str | None): Source MAC address.
        type (int | None): EtherType field indicating the protocol of the payload (e.g., 0x0800 for IPv4).
        payload (str | None): The data being carried by the frame.
        crc (str | None): Cyclic Redundancy Check for error detection.
    """

    def __init__(self):
        """
        Initialize a new EthernetPacket instance.

        Sets up the basic attributes for an Ethernet frame.
        """
        super().__init__()
        self.preamble: int | None = None  # Patron de sincronizacion (0xAA)
        self.sfd: int | None = None  # Marca de inicio de la trama
        self.dst_mac: str | None = None
        self.src_mac: str | None = None
        self.type: int | None = None  # Ej: 0x0800 IPv4
        self.payload: str | None = None
        self.crc: str | None = None  # checksum de la trama

    def get_payload(self):
        """
        Get the payload data of the packet.

        Returns:
            str: The payload data of the packet.
        """
        return self.payload

    def get_layers(self):
        """
        Get the list of protocol layers in the packet.

        Returns:
            list: A list of protocol layers in the packet.
        """
        return self.layers

    def get_timestamp(self):
        """
        Get the timestamp when the packet was captured.

        Returns:
            str: The timestamp of the packet capture.
        """
        return self.timestamp

    def get_dst_ip(self):
        """
        Get the destination IP address of the packet.

        Returns:
            str: The destination IP address.
            Note: Ethernet frames themselves don't contain IP addresses,
            but this method returns the dst_ip attribute which might be
            populated from higher layer protocols.
        """
        return self.dst_ip

    def get_src_ip(self):
        """
        Get the source IP address of the packet.

        Returns:
            str: The source IP address.
            Note: Ethernet frames themselves don't contain IP addresses,
            but this method returns the src_ip attribute which might be
            populated from higher layer protocols.
        """
        return self.src_ip

    def show(self):
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

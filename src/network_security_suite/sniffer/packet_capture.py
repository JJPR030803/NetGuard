from scapy.all import *
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, STP, Ether
import polars as pl
import pandas as pd
import time
from src.network_security_suite.models.data_structures import (
    ARPPacketModel,
    EthernetPacketModel,
    ICMPPacketModel,
    IPPacketModel,
    NetworkPacketModel,
    Packet,
    PacketLayer,
    STPPacketModel,
    TCPPacketModel,
    UDPPacketModel, POLARS_AVAILABLE,
)
from src.network_security_suite.sniffer.packet import ARPPacket, NetworkPacket

# TODO crear clases para capturar paquetes


class PacketCapture:
    """
    Class for capturing and processing network packets from a specified interface.

    This class uses the scapy library to capture packets from a network interface
    and converts them into appropriate packet models based on their protocol type.

    Attributes:
        interface (str): The name of the network interface to capture packets from.
        packets (list[Packet]): A list of captured packet objects.
    """

    def __init__(self, interface: str):
        """
        Initialize a new PacketCapture instance.

        Args:
            interface (str): The name of the network interface to capture packets from.
        """
        self.interface = interface
        self.packets: list[Packet] = []

    def process_packet_layers(self, packet) -> Packet:
        """
        Process all layers of a packet and return a Packet instance with PacketLayers.

        This method extracts information from each layer of the scapy packet and
        converts it into a structured Packet object with PacketLayer instances.

        Args:
            packet: A scapy packet object containing multiple protocol layers.

        Returns:
            Packet: A structured representation of the packet with all its layers.
        """
        packet_layers = []

        # Get timestamp and raw size
        timestamp = float(packet.time)
        raw_size = len(packet)

        # Process Ethernet layer if present
        if packet.haslayer(Ether):
            ethernet_fields = {
                'dst_mac': packet[Ether].dst,
                'src_mac': packet[Ether].src,
                'type': packet[Ether].type,
            }
            packet_layers.append(PacketLayer(
                layer_name="Ethernet",
                fields=ethernet_fields
            ))

        # Process IP layer if present
        if packet.haslayer(IP):
            # Convert flags to integer value
            ip_flags = int(packet[IP].flags) if packet[IP].flags is not None else None

            ip_fields = {
                'version': packet[IP].version,
                'ihl': packet[IP].ihl,
                'tos': packet[IP].tos,
                'len': packet[IP].len,
                'id': packet[IP].id,
                'flags': ip_flags,
                'frag': packet[IP].frag,
                'ttl': packet[IP].ttl,
                'proto': packet[IP].proto,
                'chksum': packet[IP].chksum,
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                'options': packet[IP].options if hasattr(packet[IP], "options") else None,
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
            }
            packet_layers.append(PacketLayer(
                layer_name="IP",
                fields=ip_fields
            ))

        # Process TCP layer if present
        if packet.haslayer(TCP):
            tcp_fields = {
                'sport': packet[TCP].sport,
                'dport': packet[TCP].dport,
                'seq': packet[TCP].seq,
                'ack': packet[TCP].ack,
                'dataofs': packet[TCP].dataofs,
                'reserved': packet[TCP].reserved,
                'flags': str(packet[TCP].flags),
                'window': packet[TCP].window,
                'chksum': packet[TCP].chksum,
                'urgptr': packet[TCP].urgptr,
                'options': [(opt[0], opt[1]) for opt in packet[TCP].options] if packet[TCP].options else None,
                'src_ip': packet[IP].src if packet.haslayer(IP) else None,
                'dst_ip': packet[IP].dst if packet.haslayer(IP) else None,
            }
            packet_layers.append(PacketLayer(
                layer_name="TCP",
                fields=tcp_fields
            ))

        # Process UDP layer if present
        if packet.haslayer(UDP):
            udp_fields = {
                'sport': packet[UDP].sport,
                'dport': packet[UDP].dport,
                'len': packet[UDP].len,
                'chksum': packet[UDP].chksum,
                'src_ip': packet[IP].src if packet.haslayer(IP) else None,
                'dst_ip': packet[IP].dst if packet.haslayer(IP) else None,
            }
            packet_layers.append(PacketLayer(
                layer_name="UDP",
                fields=udp_fields
            ))

        # Process ICMP layer if present
        if packet.haslayer(ICMP):
            icmp_fields = {
                'type': packet[ICMP].type,
                'code': packet[ICMP].code,
                'chksum': packet[ICMP].chksum,
                'id': packet[ICMP].id if hasattr(packet[ICMP], "id") else None,
                'seq': packet[ICMP].seq if hasattr(packet[ICMP], "seq") else None,
                'src_ip': packet[IP].src if packet.haslayer(IP) else None,
                'dst_ip': packet[IP].dst if packet.haslayer(IP) else None,
            }
            packet_layers.append(PacketLayer(
                layer_name="ICMP",
                fields=icmp_fields
            ))

        # Process ARP layer if present
        if packet.haslayer(ARP):
            arp_fields = {
                'hw_type': packet[ARP].hwtype,
                'proto_type': packet[ARP].ptype,
                'hw_len': packet[ARP].hwlen,
                'proto_len': packet[ARP].plen,
                'opcode': packet[ARP].op,
                'sender_mac': packet[ARP].hwsrc,
                'sender_ip': packet[ARP].psrc,
                'target_mac': packet[ARP].hwdst,
                'target_ip': packet[ARP].pdst,
            }
            packet_layers.append(PacketLayer(
                layer_name="ARP",
                fields=arp_fields
            ))

        # Process STP layer if present
        if packet.haslayer(STP):
            stp_fields = {
                'protocol_id': packet[STP].proto,
                'version': packet[STP].version,
                'bpdutype': packet[STP].bpdutype,
                'flags': packet[STP].flags,
                'root_bridge_id': f"{packet[STP].rootid}",
                'sender_bridge_id': f"{packet[STP].bridgeid}",
                'root_path_cost': packet[STP].rootcost,
                'port_id': packet[STP].portid,
                'message_age': packet[STP].age,
                'max_age': packet[STP].maxage,
                'hello_time': packet[STP].hellotime,
                'forward_delay': packet[STP].fwddelay,
            }
            packet_layers.append(PacketLayer(
                layer_name="STP",
                fields=stp_fields
            ))

        # Create and return the Packet instance with all layers
        return Packet(
            timestamp=timestamp,
            layers=packet_layers,
            raw_size=raw_size
        )

    def capture(self, max_packets: int = 10000, verbose: bool = False):
        """
        Capture network packets from the specified interface.

        This method uses scapy's sniff function to capture packets from the network
        interface specified during initialization. Each captured packet is processed
        using the process_packet_layers method and added to the packets list.

        Args:
            max_packets (int, optional): Maximum number of packets to capture. Defaults to 10000.
            verbose (bool, optional): Whether to print information about captured packets. Defaults to False.

        Raises:
            Exception: If there's an error during packet capture or processing.
        """
        try:
            packets = sniff(iface=self.interface, count=max_packets)
            for packet in packets:
                # Process all layers of the packet
                processed_packet = self.process_packet_layers(packet)
                self.packets.append(processed_packet)
                if verbose:
                    print(f"Captured packet with {len(processed_packet.layers)} layers")
        except Exception as e:
            print(f"Error capturing packets: {e}")

    def show_packets(self):
        """
        Display information about all captured packets.

        This method prints information about each packet in the packets list,
        including timestamp, raw size, and all layers with their fields.
        """
        for i, packet in enumerate(self.packets):
            print(f"\nPacket {i+1}:")
            print(f"  Timestamp: {packet.timestamp}")
            print(f"  Raw Size: {packet.raw_size} bytes")
            print(f"  Layers: {len(packet.layers)}")

            for layer in packet.layers:
                print(f"\n  Layer: {layer.layer_name}")
                for field_name, field_value in layer.fields.items():
                    print(f"    {field_name}: {field_value}")
            print("-" * 50)

    def packets_to_json(self):
        """
        Convert captured packets to JSON format.

        Returns:
            list: List of packet data in JSON format.
        """
        return [packet.to_json() for packet in self.packets]

    def packets_to_polars(self):
        """
        Convert captured packets to Polars DataFrame format.

        Returns:
            list: List of packet data as Polars DataFrames.
        """
        if not POLARS_AVAILABLE:
            raise ImportError(
                "The polars package is not installed. "
                "Please install it with 'pip install polars' or 'poetry add polars'."
            )

        result = []
        for packet in self.packets:
            # Create a dictionary with basic packet info
            packet_data = {
                'timestamp': packet.timestamp,
                'raw_size': packet.raw_size
            }

            # Add layer information
            for layer in packet.layers:
                layer_data = {f"{layer.layer_name}_{k}": v for k, v in layer.fields.items()}
                packet_data.update(layer_data)

            # Convert to Polars DataFrame
            df = pl.DataFrame([packet_data])
            result.append(df)

        return result

    def packets_to_pandas(self):
        """
        Convert captured packets to Pandas DataFrame format.

        Returns:
            list: List of packet data as Pandas DataFrames.
        """
        result = []
        for packet in self.packets:
            # Create a dictionary with basic packet info
            packet_data = {
                'timestamp': packet.timestamp,
                'raw_size': packet.raw_size
            }

            # Add layer information
            for layer in packet.layers:
                layer_data = {f"{layer.layer_name}_{k}": v for k, v in layer.fields.items()}
                packet_data.update(layer_data)

            # Convert to Pandas DataFrame
            df = pd.DataFrame([packet_data])
            result.append(df)

        return result

    def to_json(self):
        """
        Convert all captured packets to a single JSON object.

        Returns:
            dict: A dictionary containing all captured packets data.
        """
        if not self.packets:
            return {}

        try:
            # Convert all packets to a single JSON object with an array of packets
            return {
                "packets": [packet.to_json() for packet in self.packets],
                "total_packets": len(self.packets)
            }
        except Exception as e:
            print(f"Error converting packets to JSON: {e}")
            return {}

    def to_pandas_df(self):
        """
        Convert all captured packets to a single pandas DataFrame.

        Returns:
            pd.DataFrame: A DataFrame containing all captured packets.
        """
        if not self.packets:
            return pd.DataFrame()

        try:
            # Create a list to store flattened packet data
            flattened_packets = []

            for packet in self.packets:
                # Start with basic packet info
                packet_data = {
                    'timestamp': packet.timestamp,
                    'raw_size': packet.raw_size
                }

                # Add layer information
                for layer in packet.layers:
                    layer_prefix = f"{layer.layer_name}_"
                    for field_name, field_value in layer.fields.items():
                        # Convert complex types to strings
                        if isinstance(field_value, (list, dict, tuple)):
                            field_value = str(field_value)
                        packet_data[f"{layer_prefix}{field_name}"] = field_value

                flattened_packets.append(packet_data)

            # Create DataFrame from flattened packet data
            return pd.DataFrame(flattened_packets)
        except Exception as e:
            print(f"Error converting packets to pandas DataFrame: {e}")
            return pd.DataFrame()

    def to_polars_df(self):
        """
        Convert all captured packets to a single Polars DataFrame.

        Returns:
            pl.DataFrame: A DataFrame containing all captured packets.

        Raises:
            ImportError: If the polars package is not installed.
        """
        if not POLARS_AVAILABLE:
            raise ImportError(
                "The polars package is not installed. "
                "Please install it with 'pip install polars' or 'poetry add polars'."
            )

        if not self.packets:
            return pl.DataFrame()

        def convert_to_string(value):
            """Helper function to convert any value to a string representation."""
            if value is None:
                return None
            elif isinstance(value, (str, int, float, bool)):
                return str(value)
            elif isinstance(value, bytes):
                return value.hex()
            elif isinstance(value, (list, tuple)):
                return str([convert_to_string(item) for item in value])
            elif isinstance(value, dict):
                return str({k: convert_to_string(v) for k, v in value.items()})
            else:
                return str(value)

        try:
            # Create a list to store flattened packet data
            flattened_packets = []

            # First pass: collect all possible columns
            columns = set(['timestamp', 'raw_size'])
            for packet in self.packets:
                for layer in packet.layers:
                    for field_name in layer.fields.keys():
                        columns.add(f"{layer.layer_name}_{field_name}")

            # Second pass: create flattened packet data
            for packet in self.packets:
                # Start with basic packet info
                packet_data = {
                    'timestamp': str(packet.timestamp),
                    'raw_size': str(packet.raw_size)
                }

                # Initialize all columns with None
                for col in columns:
                    if col not in packet_data:
                        packet_data[col] = None

                # Add layer information
                for layer in packet.layers:
                    layer_prefix = f"{layer.layer_name}_"
                    for field_name, field_value in layer.fields.items():
                        column_name = f"{layer_prefix}{field_name}"
                        packet_data[column_name] = convert_to_string(field_value)

                flattened_packets.append(packet_data)

            # Create schema with all columns as strings
            schema = {col: pl.Utf8 for col in columns}

            # Use pl.DataFrame constructor
            df = pl.DataFrame(
                flattened_packets,
                schema=schema
            )
            return df

        except Exception as e:
            print(f"Error converting packets to Polars DataFrame: {e}")
            return pl.DataFrame()


"""
Network packet capture and processing module.

This module provides functionality for capturing network packets from specified interfaces,
processing them into structured data models, and converting them to various formats
including JSON, pandas DataFrames, and Polars DataFrames.
"""

import gc
import platform
from datetime import datetime
from queue import Empty, Queue
from threading import Lock, Thread
from time import time
from typing import Any, Dict, List, Optional

import pandas as pd
import polars as pl
from scapy.all import Packet as ScapyPacket
from scapy.all import sniff
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, STP, Ether

from network_security_suite.models.packet_data_structures import (
    POLARS_AVAILABLE,
    Packet,
    PacketLayer,
)
from network_security_suite.sniffer.exceptions import DataConversionError
from network_security_suite.sniffer.loggers import (
    DebugLogger,
    ErrorLogger,
    InfoLogger,
    PacketLogger,
)
from network_security_suite.sniffer.sniffer_config import SnifferConfig
from network_security_suite.utils.performance_metrics import perf


class PacketCapture:
    """
    Class for capturing and processing network packets from a specified interface.

    This class uses the scapy library to capture packets from a network interface
    and converts them into appropriate packet models based on their protocol type.

    Attributes:
        interface (str): The name of the network interface to capture packets from.
        packets (list[Packet]): A list of captured packet objects.
    """

    def __init__(
        self, 
        config: Optional[SnifferConfig] = None,
        interface: Optional[str] = None,  # Keep for backward compatibility
        max_memory_packets: Optional[int] = None,  # Keep for backward compatibility
        log_dir: Optional[str] = None  # Keep for backward compatibility
    ):
        """Initialize PacketCapture with configuration."""
        # Import here to avoid circular imports
        from .sniffer_config import SnifferConfig
        
        # Use provided config or create default
        self.config = config if config is not None else SnifferConfig()
        
        # Legacy support - override config with direct parameters if provided
        if interface is not None:
            self.config.interface = interface
        if max_memory_packets is not None:
            self.config.max_memory_packets = max_memory_packets
        if log_dir is not None:
            self.config.log_dir = log_dir
        
        # Use config values directly
        self.interface = self.config.interface
        self.max_memory_packets = self.config.max_memory_packets
        self.log_dir = self.config.log_dir

        # Initialize loggers using config
        self.info_logger = InfoLogger(log_dir=self.config.log_dir)
        self.debug_logger = DebugLogger(log_dir=self.config.log_dir)
        self.error_logger = ErrorLogger(log_dir=self.config.log_dir)
        self.packet_logger = PacketLogger(log_dir=self.config.log_dir)

        # Validation using config values
        if self.config.max_memory_packets < 100:
            self.error_logger.log(f"Invalid max_memory_packets value: {self.config.max_memory_packets}")
            raise ValueError("max_memory_packets must be at least 100")
        
        if self.config.max_memory_packets % 10 != 0:
            self.error_logger.log(f"Invalid max_memory_packets value: {self.config.max_memory_packets}")
            raise ValueError("max_memory_packets must be multiple of 10")

        # Initialize other attributes
        self.packets: list[Packet] = []
        self.packet_queue: Queue[list[Packet]] = Queue()
        self.is_running: bool = False
        self.max_processing_batch = self.config.max_processing_batch_size
        self.stats_lock = Lock()
        self.stats = {
            "processed_packets": 0,
            "dropped_packets": 0,
            "processing_time": 0.0,
            "batch_count": 0,
        }

        self.info_logger.log(f"Initializing PacketCapture for interface: {self.config.interface}")

        if self.config.max_memory_packets < 100:
            self.error_logger.log(
                f"Invalid max_memory_packets value: {self.config.max_memory_packets}, must be at least 100"
            )
            raise ValueError("max_memory_packets must be at least 100")
        if self.config.max_memory_packets % 10 != 0:
            self.error_logger.log(
                f"Invalid max_memory_packets value: {self.config.max_memory_packets}, must be multiple of 10"
            )
            raise ValueError(
                "max_memory_packets must be multiple of 10 for faster processing"
            )

        self.packets: list[Packet] = []
        self.packet_queue: Queue[list[Packet]] = Queue()
        self.is_running: bool = False
        self.max_processing_batch = self.config.max_processing_batch_size
        self.stats_lock = Lock()
        self.stats = {
            "processed_packets": 0,
            "dropped_packets": 0,
            "processing_time": 0.0,
            "batch_count": 0,
        }
        self.debug_logger.log(
            f"PacketCapture initialized with max_memory_packets: {self.max_memory_packets}, "
            f"max_processing_batch: {self.max_processing_batch}"
        )

    def update_stats(self, processing_time: float, batch_size: int) -> None:
        """Update statistics."""
        with self.stats_lock:
            self.stats["processed_packets"] += batch_size
            self.stats["processing_time"] += processing_time
            self.stats["batch_count"] += 1

    @perf.monitor("process_queue")
    def process_queue(self) -> None:
        """Process packets in batches."""
        self.debug_logger.log("Starting packet queue processing")

        total_batches = 0
        total_packets = 0

        while self.is_running or not self.packet_queue.empty():
            try:
                batch = self.packet_queue.get(timeout=1)  # Get the batch
                batch_size = len(batch)
                total_batches += 1
                total_packets += batch_size

                self.debug_logger.log(f"Processing batch of {batch_size} packets")


                start_time = time()
                for packet in batch:  # Process each packet in the batch
                    try:
                        processed_packet = self.process_packet_layers(packet)
                        self.packets.append(processed_packet)
                        self.packet_logger.log(
                            f"Processed packet: {processed_packet.id}"
                        )
                    except Exception as e:
                        # Log the error but continue processing other packets
                        # We don't want to stop the entire queue processing for one packet
                        packet_id = getattr(packet, "time", "unknown")
                        self.error_logger.log(
                            f"Error processing packet {packet_id}: {str(e)}"
                        )
                        self.stats["dropped_packets"] += 1
                end_time = time()
                processing_time = end_time - start_time
                self.update_stats(processing_time, batch_size)
                self.debug_logger.log(
                    f"Batch processed in {processing_time:.4f} seconds"
                )


                self.packet_queue.task_done()
            except Empty:
                self.debug_logger.log("Queue empty, waiting for more packets")
                continue


        self.info_logger.log("Packet queue processing completed")


    @perf.monitor("process_packet_layers")
    def process_packet_layers(self, packet: ScapyPacket) -> Packet:
        """
        Optimized layer processing.

        This method processes a Scapy packet and extracts information from its layers.
        It handles various network protocol layers and creates a structured Packet object.

        Args:
            packet (ScapyPacket): The Scapy packet to process

        Returns:
            Packet: A structured packet object with extracted layer information

        Raises:
            Exception: If there's an error processing the packet that can't be handled
        """

        if packet is None:
            raise ValueError("Cannot process None packet")

        packet_layers = []
        timestamp = float(packet.time) if hasattr(packet, "time") else 0.0
        raw_size = len(packet)

        # Process all layers in one pass with a mapping
        layer_mapping = {
            Ether: (
                "Ethernet",
                lambda p: {"dst_mac": p.dst, "src_mac": p.src, "type": p.type},
            ),
            IP: (
                "IP",
                lambda p: {
                    "version": p.version,
                    "ihl": p.ihl,
                    "tos": p.tos,
                    "len": p.len,
                    "id": p.id,
                    "flags": p.flags,
                    "frag": p.frag,
                    "ttl": p.ttl,
                    "proto": p.proto,
                    "chksum": p.chksum,
                    "src": str(p.src),
                    "dst": str(p.dst),
                    "options": p.options if hasattr(p, "options") else None,
                },
            ),
            TCP: (
                "TCP",
                lambda p: {
                    "sport": p.sport,
                    "dport": p.dport,
                    "seq": p.seq,
                    "ack": p.ack,
                    "dataofs": p.dataofs,
                    "reserved": p.reserved,
                    "flags": str(p.flags),
                    "window": p.window,
                    "chksum": p.chksum,
                    "urgptr": p.urgptr,
                    "options": p.options if hasattr(p, "options") else None,
                },
            ),
            UDP: (
                "UDP",
                lambda p: {
                    "sport": p.sport,
                    "dport": p.dport,
                    "len": p.len,
                    "chksum": p.chksum,
                },
            ),
            ICMP: (
                "ICMP",
                lambda p: {
                    "type": p.type,
                    "code": p.code,
                    "chksum": p.chksum,
                    "id": p.id if hasattr(p, "id") else None,
                    "seq": p.seq if hasattr(p, "seq") else None,
                    "data": p.load if hasattr(p, "load") else None,
                },
            ),
            ARP: (
                "ARP",
                lambda p: {
                    "hw_type": p.hwtype,
                    "proto_type": p.ptype,
                    "hw_len": p.hwlen,
                    "proto_len": p.plen,
                    "opcode": p.op,
                    "sender_mac": p.hwsrc,
                    "sender_ip": p.psrc,
                    "target_mac": p.hwdst,
                    "target_ip": p.pdst,
                },
            ),
            STP: (
                "STP",
                lambda p: {
                    "protocol_id": p.proto,
                    "version": p.version,
                    "bpdutype": p.bpdutype,
                    "flags": p.flags,
                    "root_bridge_id": p.rootid,
                    "sender_bridge_id": p.bridgeid,
                    "root_path_cost": p.pathcost,
                    "port_id": p.portid,
                    "message_age": p.age,
                    "max_age": p.maxage,
                    "hello_time": p.hellotime,
                    "forward_delay": p.fwddelay,
                },
            ),
        }

        # Process known layers
        for layer_type, (name, processor) in layer_mapping.items():
            if packet.haslayer(layer_type):
                try:
                    fields = processor(packet[layer_type])
                    packet_layers.append(PacketLayer(layer_name=name, fields=fields))
                except Exception:
                    # Create but don't raise the exception - we want to continue processing other layers
                    # Just log the error in a production environment
                    pass

        # Process unknown layers
        try:
            for layer in packet.layers():
                layer_name = layer.__name__
                # Skip layers we've already processed
                if any(pl.layer_name == layer_name for pl in packet_layers):
                    continue

                # Try to extract basic fields for unknown layers
                try:
                    fields = {}
                    for field_name in layer.fields_desc:
                        field_value = getattr(packet[layer], field_name.name, None)
                        if field_value is not None:
                            # Convert complex objects to strings to avoid serialization issues
                            if not isinstance(
                                field_value, (int, float, str, bool, type(None))
                            ):
                                field_value = str(field_value)
                            fields[field_name.name] = field_value

                    if fields:  # Only add if we found some fields
                        packet_layers.append(
                            PacketLayer(layer_name=layer_name, fields=fields)
                        )
                except Exception:
                    # Create but don't raise the exception - we want to continue processing other layers
                    # Just log the error in a production environment
                    pass
        except Exception:
            # Continue with the layers we've processed so far
            # Just log the error in a production environment
            pass

        result = Packet(timestamp=timestamp, layers=packet_layers, raw_size=raw_size)


        return result

    def packet_callback(self, packet: ScapyPacket) -> None:
        """
            Process packets as they arrive in scapy sniff clalback
        :param packet:
        :return:
        """
        try:
            processed_packet = self.process_packet_layers(packet)
            self.packets.append(processed_packet)
        except Exception:
            # Create but don't raise the exception - this would be a good place for logging
            # in a production environment
            # packet_id = getattr(packet, "time", "unknown")
            # Just log the error in a production environment
            pass
            with self.stats_lock:
                self.stats["dropped_packets"] += 1

    def _get_session_info(self) -> Dict[str, str]:
        """
        Get information about the current sniffing session.

        Returns:
            Dict[str, str]: A dictionary containing information about the session,
            including OS, machine type, interface type, date, etc.
        """
        session_info = {
            "os": platform.system(),
            "os_version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "interface": self.interface,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        # Try to determine interface type
        if self.interface.lower().startswith(("wlan", "wifi", "wl")):
            session_info["interface_type"] = "wireless"
        elif self.interface.lower().startswith(("docker", "br-")):
            session_info["interface_type"] = "docker"
        elif self.interface.lower().startswith(("eth", "en", "eno")):
            session_info["interface_type"] = "ethernet"
        elif self.interface.lower().startswith(("veth")):
            session_info["interface_type"] = "virtual"
        elif self.interface.lower().startswith(("tun", "tap")):
            session_info["interface_type"] = "vpn"
        elif self.interface.lower() in ("lo", "loopback"):
            session_info["interface_type"] = "loopback"
        else:
            session_info["interface_type"] = "unknown"

        return session_info

    @perf.monitor("capture")
    def capture(
        self,
        max_packets: int = None,
        bpf_filter: str | None = None,
        num_threads: int = None,
        log: bool = False,
    ) -> None:
        """
        Capture network packets from the specified interface.

        This method uses scapy's sniff function to capture packets from the network
        interface specified during initialization. Each captured packet is processed
        using the process_packet_layers method and added to the packets list.

        Args:
            max_packets (int, optional): Maximum number of packets to capture. If None, uses config value.
            bpf_filter (str | None, optional): Berkeley Packet Filter string. If None, uses config value.
            num_threads (int, optional): Number of processing threads to use. If None, uses config value.
            log (bool, optional): Whether to log detailed session information. Defaults to False.

        Raises:
            Exception: If there's an error during packet capture or processing.
        """
        # Use configuration values if parameters are not provided
        if max_packets is None:
            max_packets = self.config.packet_count if self.config.packet_count > 0 else 10000

        if bpf_filter is None:
            bpf_filter = self.config.filter_expression

        if num_threads is None:
            num_threads = self.config.num_threads

        self.info_logger.log(f"Starting packet capture on interface {self.interface}")
        self.debug_logger.log(
            f"Capture parameters: max_packets={max_packets}, filter='{bpf_filter}', threads={num_threads}"
        )

        # Log detailed session information if requested
        if log:
            session_info = self._get_session_info()
            self.info_logger.log("=== SNIFFING SESSION STARTED ===")
            self.info_logger.log(f"Date/Time: {session_info['date']}")
            self.info_logger.log(
                f"Operating System: {session_info['os']} {session_info['os_version']}"
            )
            self.info_logger.log(
                f"Machine: {session_info['machine']} ({session_info['processor']})"
            )
            self.info_logger.log(
                f"Interface: {session_info['interface']} (Type: {session_info['interface_type']})"
            )
            self.info_logger.log(f"Max Packets: {max_packets}")
            self.info_logger.log("================================")

        self.is_running = True

        # Start multiple processing threads
        self.debug_logger.log(f"Starting {num_threads} processing threads")
        processors = []
        for i in range(num_threads):
            processor = Thread(target=self.process_queue)
            processor.start()
            processors.append(processor)
            self.debug_logger.log(f"Thread {i+1} started")

        packet_buffer: list[ScapyPacket] = []

        def packet_callback_wrapper(packet: ScapyPacket) -> None:
            if self.max_memory_packets and len(self.packets) >= self.max_memory_packets:
                self.debug_logger.log(
                    f"Memory limit reached ({self.max_memory_packets} packets), trimming packet list"
                )
                self.packets = self.packets[-self.max_memory_packets :]
                gc.collect()
            packet_buffer.append(packet)
            if len(packet_buffer) >= self.max_processing_batch:
                self.packet_logger.log(
                    f"Queuing batch of {len(packet_buffer)} packets for processing"
                )
                self.packet_queue.put(packet_buffer[:])  # Create a copy of the buffer
                packet_buffer.clear()

        try:
            self.info_logger.log("Beginning packet sniffing")
            sniff(
                iface=self.interface,
                count=max_packets,
                store=False,
                prn=packet_callback_wrapper,
                timeout=None,
                filter=bpf_filter,
            )
            self.info_logger.log(
                f"Packet sniffing completed, captured up to {max_packets} packets"
            )
        except Exception as e:
            self.error_logger.log(f"Error during packet capture: {str(e)}")
            raise
        finally:
            # Process remaining packets in buffer
            if packet_buffer:
                self.packet_logger.log(
                    f"Queuing final batch of {len(packet_buffer)} packets"
                )
                self.packet_queue.put(packet_buffer)

            self.debug_logger.log("Signaling processing threads to stop")
            self.is_running = False

            for i, processor in enumerate(processors):
                self.debug_logger.log(f"Waiting for thread {i+1} to finish")
                processor.join()
                self.debug_logger.log(f"Thread {i+1} finished")

            self.info_logger.log("Packet capture and processing completed")

            # Log session completion details if requested
            if log:
                with self.stats_lock:
                    processed_packets = self.stats["processed_packets"]
                    dropped_packets = self.stats["dropped_packets"]
                    processing_time = self.stats["processing_time"]

                self.info_logger.log("=== SNIFFING SESSION COMPLETED ===")
                self.info_logger.log(
                    f"Date/Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                )
                self.info_logger.log(f"Packets Processed: {processed_packets}")
                self.info_logger.log(f"Packets Dropped: {dropped_packets}")
                self.info_logger.log(
                    f"Total Processing Time: {processing_time:.2f} seconds"
                )

                # Calculate layer distribution
                layer_counts = {}
                for packet in self.packets:
                    for layer in packet.layers:
                        layer_name = layer.layer_name
                        if layer_name in layer_counts:
                            layer_counts[layer_name] += 1
                        else:
                            layer_counts[layer_name] = 1

                self.info_logger.log("Layer Distribution:")
                for layer_name, count in layer_counts.items():
                    self.info_logger.log(f"  {layer_name}: {count}")

                self.info_logger.log("=================================")


    def show_packets(self) -> None:
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

    def show_stats(self) -> None:
        """
        Display statistics about captured packets and capture performance.

        This method prints information about the packet capture process, including:
        - Total number of packets processed
        - Total number of packets dropped
        - Total processing time
        - Number of batches processed
        - Average processing time per packet
        - Average batch size
        - Current number of packets in memory
        - Layer distribution (counts of each layer type)

        This is useful for monitoring the performance of the packet capture process
        and understanding the composition of the captured traffic.
        """
        with self.stats_lock:
            stats = self.stats.copy()

        # Basic statistics
        print("\n" + "=" * 50)
        print("PACKET CAPTURE STATISTICS")
        print("=" * 50)
        print(f"Total packets processed: {stats['processed_packets']}")
        print(f"Total packets dropped: {stats['dropped_packets']}")
        print(f"Total processing time: {stats['processing_time']:.4f} seconds")
        print(f"Number of batches processed: {stats['batch_count']}")

        # Derived statistics
        if stats["processed_packets"] > 0:
            avg_time_per_packet = stats["processing_time"] / stats["processed_packets"]
            print(
                f"Average processing time per packet: {avg_time_per_packet:.6f} seconds"
            )

        if stats["batch_count"] > 0:
            avg_batch_size = stats["processed_packets"] / stats["batch_count"]
            print(f"Average batch size: {avg_batch_size:.2f} packets")

        # Memory usage
        print(f"Current packets in memory: {len(self.packets)}")

        # Layer distribution
        if self.packets:
            layer_counts = {}
            for packet in self.packets:
                for layer in packet.layers:
                    layer_name = layer.layer_name
                    if layer_name in layer_counts:
                        layer_counts[layer_name] += 1
                    else:
                        layer_counts[layer_name] = 1

            print("\nLayer Distribution:")
            for layer_name, count in sorted(layer_counts.items()):
                percentage = (count / len(self.packets)) * 100
                print(f"  {layer_name}: {count} ({percentage:.2f}%)")

        print("=" * 50)

    def packets_to_json(self) -> List[Dict[str, Any]]:
        """
        Convert captured packets to JSON format.

        Returns:
            List[Dict[str, Any]]: List of packet data in JSON format.
        """
        return [packet.to_json() for packet in self.packets]

    def packets_to_polars(self) -> List[pl.DataFrame]:
        """
        Convert captured packets to Polars DataFrame format.

        Returns:
            List[pl.DataFrame]: List of packet data as Polars DataFrames.
        """
        if not POLARS_AVAILABLE:
            raise ImportError(
                "The polars package is not installed. "
                "Please install it with 'pip install polars' or 'poetry add polars'."
            )

        result = []
        for packet in self.packets:
            # Create a dictionary with basic packet info
            packet_data = {"timestamp": packet.timestamp, "raw_size": packet.raw_size}

            # Add layer information
            for layer in packet.layers:
                layer_data = {
                    f"{layer.layer_name}_{k}": v for k, v in layer.fields.items()
                }
                packet_data.update(layer_data)

            # Convert to Polars DataFrame
            df = pl.DataFrame([packet_data])
            result.append(df)

        return result

    def packets_to_pandas(self) -> List[pd.DataFrame]:
        """
        Convert captured packets to Pandas DataFrame format.

        Returns:
            List[pd.DataFrame]: List of packet data as Pandas DataFrames.
        """
        result = []
        for packet in self.packets:
            # Create a dictionary with basic packet info
            packet_data = {"timestamp": packet.timestamp, "raw_size": packet.raw_size}

            # Add layer information
            for layer in packet.layers:
                layer_data = {
                    f"{layer.layer_name}_{k}": v for k, v in layer.fields.items()
                }
                packet_data.update(layer_data)

            # Convert to Pandas DataFrame
            df = pd.DataFrame([packet_data])
            result.append(df)

        return result

    def to_json(self) -> Dict[str, Any]:
        """
        Convert all captured packets to a single JSON object.

        Returns:
            Dict[str, Any]: A dictionary containing all captured packets data.
        """
        if not self.packets:
            return {}

        try:
            # Convert all packets to a single JSON object with an array of packets
            return {
                "packets": [packet.to_json() for packet in self.packets],
                "total_packets": len(self.packets),
            }
        except Exception as e:
            raise DataConversionError(
                source_format="packets", target_format="JSON", error_details=str(e)
            ) from e

    @perf.monitor("to_pandas_df")
    def to_pandas_df(self) -> pd.DataFrame:
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
                    "timestamp": packet.timestamp,
                    "raw_size": packet.raw_size,
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
            result = pd.DataFrame(flattened_packets)


            return result
        except Exception as e:

            raise DataConversionError(
                source_format="packets",
                target_format="pandas DataFrame",
                error_details=str(e),
            ) from e

    @perf.monitor("to_polars_df")
    def to_polars_df(self) -> pl.DataFrame:
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

        def convert_to_string(value: Any) -> Optional[str]:
            """Helper function to convert any value to a string representation."""
            if value is None:
                return None
            if isinstance(value, (str, int, float, bool)):
                return str(value)
            if isinstance(value, bytes):
                return value.hex()
            if isinstance(value, (list, tuple)):
                return str([convert_to_string(item) for item in value])
            if isinstance(value, dict):
                return str({k: convert_to_string(v) for k, v in value.items()})
            return str(value)

        try:
            # Create a list to store flattened packet data
            flattened_packets = []

            # First pass: collect all possible columns
            columns = {"timestamp", "raw_size"}
            for packet in self.packets:
                for layer in packet.layers:
                    for field_name in layer.fields:
                        columns.add(f"{layer.layer_name}_{field_name}")

            # Second pass: create flattened packet data
            for packet in self.packets:
                # Start with basic packet info
                packet_data = {
                    "timestamp": packet.timestamp,  # Keep as float for conversion to datetime
                    "raw_size": str(packet.raw_size),
                }

                # Initialize all columns with empty string
                for col in columns:
                    if col not in packet_data:
                        packet_data[col] = ""

                # Add layer information
                for layer in packet.layers:
                    layer_prefix = f"{layer.layer_name}_"
                    for field_name, field_value in layer.fields.items():
                        column_name = f"{layer_prefix}{field_name}"
                        converted_value = convert_to_string(field_value)
                        packet_data[column_name] = (
                            converted_value if converted_value is not None else ""
                        )

                flattened_packets.append(packet_data)

            # Create schema with appropriate types
            schema = {}
            for col in columns:
                if col == "timestamp":
                    schema[col] = pl.Float64  # Will be converted to datetime later
                else:
                    schema[col] = pl.Utf8

            # Use pl.DataFrame constructor
            df = pl.DataFrame(flattened_packets, schema=schema)

            # Convert timestamp to datetime
            df = df.with_columns(
                [
                    pl.col("timestamp")
                    .cast(pl.Float64)
                    .cast(pl.Datetime)
                    .alias("timestamp")
                ]
            )


            return df

        except Exception as e:

            raise DataConversionError(
                source_format="packets",
                target_format="Polars DataFrame",
                error_details=str(e),
            ) from e


def capture(self, max_packets: int = 100, log: bool = False) -> None:
    if log:
        self.packet_logger.log(f"Starting packet capture on interface {self.interface}")
        self.debug_
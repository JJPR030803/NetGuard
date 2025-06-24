# PacketCapture Module

## Overview

The `packet_capture.py` module provides functionality for capturing network packets from specified interfaces, processing them into structured data models, and converting them to various formats including JSON, pandas DataFrames, and Polars DataFrames.

This module is a core component of the network security suite, enabling network traffic analysis and monitoring.

## Classes

### PacketCapture

A class for capturing and processing network packets from a specified interface. This class uses the scapy library to capture packets from a network interface and converts them into appropriate packet models based on their protocol type.

#### Attributes

- `interface (str)`: The name of the network interface to capture packets from.
- `packets (list[Packet])`: A list of captured packet objects.
- `max_memory_packets (int)`: Maximum number of packets to keep in memory.
- `packet_queue (Queue[list[Packet]])`: Queue for packet processing.
- `is_running (bool)`: Flag indicating if capture is in progress.
- `stats (dict)`: Statistics about packet processing.

#### Methods

##### `__init__(self, interface: str, max_memory_packets: int = 10000, log_dir: Optional[str] = None)`

Initialize a new PacketCapture instance.

**Parameters:**
- `interface (str)`: The name of the network interface to capture packets from.
- `max_memory_packets (int, optional)`: Maximum number of packets to keep in memory. Defaults to 10000.
- `log_dir (Optional[str], optional)`: Directory to store log files. Defaults to None.

**Raises:**
- `ValueError`: If max_memory_packets is less than 100 or not a multiple of 10.

##### `update_stats(self, processing_time: float, batch_size: int) -> None`

Update statistics about packet processing.

**Parameters:**
- `processing_time (float)`: Time taken to process a batch of packets.
- `batch_size (int)`: Number of packets in the batch.

##### `process_queue(self) -> None`

Process packets in batches from the queue.

This method runs in a separate thread and continuously processes batches of packets from the queue until the capture is stopped and the queue is empty.

##### `process_packet_layers(self, packet: ScapyPacket) -> Packet`

Process a Scapy packet and extract information from its layers.

**Parameters:**
- `packet (ScapyPacket)`: The Scapy packet to process.

**Returns:**
- `Packet`: A structured packet object with extracted layer information.

**Raises:**
- `ValueError`: If the packet is None.
- `Exception`: If there's an error processing the packet that can't be handled.

##### `packet_callback(self, packet: ScapyPacket) -> None`

Process packets as they arrive in scapy sniff callback.

**Parameters:**
- `packet (ScapyPacket)`: The Scapy packet to process.

##### `_get_session_info(self) -> Dict[str, str]`

Get information about the current sniffing session.

**Returns:**
- `Dict[str, str]`: A dictionary containing information about the session, including OS, machine type, interface type, date, etc.

##### `capture(self, max_packets: int = 10000, bpf_filter: str | None = "", num_threads: int = 4, log: bool = False) -> None`

Capture network packets from the specified interface.

**Parameters:**
- `max_packets (int, optional)`: Maximum number of packets to capture. Defaults to 10000.
- `bpf_filter (str | None, optional)`: Berkeley Packet Filter string. Defaults to "".
- `num_threads (int, optional)`: Number of processing threads to use. Defaults to 4.
- `log (bool, optional)`: Whether to log detailed session information. Defaults to False.

**Raises:**
- `Exception`: If there's an error during packet capture or processing.

##### `show_packets(self) -> None`

Display information about all captured packets.

This method prints information about each packet in the packets list, including timestamp, raw size, and all layers with their fields.

##### `show_stats(self) -> None`

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

##### `packets_to_json(self) -> List[Dict[str, Any]]`

Convert captured packets to JSON format.

**Returns:**
- `List[Dict[str, Any]]`: List of packet data in JSON format.

##### `packets_to_polars(self) -> List[pl.DataFrame]`

Convert captured packets to Polars DataFrame format.

**Returns:**
- `List[pl.DataFrame]`: List of packet data as Polars DataFrames.

**Raises:**
- `ImportError`: If the polars package is not installed.

##### `packets_to_pandas(self) -> List[pd.DataFrame]`

Convert captured packets to Pandas DataFrame format.

**Returns:**
- `List[pd.DataFrame]`: List of packet data as Pandas DataFrames.

##### `to_json(self) -> Dict[str, Any]`

Convert all captured packets to a single JSON object.

**Returns:**
- `Dict[str, Any]`: A dictionary containing all captured packets data.

**Raises:**
- `DataConversionError`: If there's an error during conversion.

##### `to_pandas_df(self) -> pd.DataFrame`

Convert all captured packets to a single pandas DataFrame.

**Returns:**
- `pd.DataFrame`: A DataFrame containing all captured packets.

**Raises:**
- `DataConversionError`: If there's an error during conversion.

##### `to_polars_df(self) -> pl.DataFrame`

Convert all captured packets to a single Polars DataFrame.

**Returns:**
- `pl.DataFrame`: A DataFrame containing all captured packets.

**Raises:**
- `ImportError`: If the polars package is not installed.
- `DataConversionError`: If there's an error during conversion.

## Usage Example

```python
from network_security_suite.sniffer.packet_capture import PacketCapture

# Initialize packet capture on interface eth0
packet_capture = PacketCapture(interface="eth0", max_memory_packets=5000)

# Capture 1000 packets with a filter for TCP traffic only
packet_capture.capture(max_packets=1000, bpf_filter="tcp", log=True)

# Display statistics about the captured packets
packet_capture.show_stats()

# Convert packets to a pandas DataFrame for analysis
df = packet_capture.to_pandas_df()
print(df.head())

# Save packets as JSON
import json
with open("captured_packets.json", "w") as f:
    json.dump(packet_capture.to_json(), f, indent=2)
```

## Dependencies

- `scapy`: For packet capture and analysis
- `pandas`: For DataFrame conversion
- `polars` (optional): For high-performance DataFrame operations

## Notes

- The module is designed to handle high-volume packet capture with efficient multi-threaded processing.
- Memory management is implemented to prevent excessive memory usage during long capture sessions.
- Various data conversion methods allow for flexible analysis using different tools and libraries.

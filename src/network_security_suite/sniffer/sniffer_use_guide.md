# Network Security Suite - Sniffer Module User Guide

## Table of Contents
- [Introduction](#introduction)
- [Installation](#installation)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
  - [Using SnifferConfig](#using-snifferconfig)
  - [Loading and Saving Configurations](#loading-and-saving-configurations)
  - [Default Configuration](#default-configuration)
- [Network Interfaces](#network-interfaces)
  - [Listing Available Interfaces](#listing-available-interfaces)
  - [Selecting Interfaces](#selecting-interfaces)
  - [Interface Information](#interface-information)
- [Packet Capture](#packet-capture)
  - [Basic Capture](#basic-capture)
  - [Filtering Packets](#filtering-packets)
  - [Multi-threaded Capture](#multi-threaded-capture)
  - [Capture with Logging](#capture-with-logging)
- [Working with Captured Packets](#working-with-captured-packets)
  - [Displaying Packets](#displaying-packets)
  - [Packet Statistics](#packet-statistics)
  - [Data Conversion](#data-conversion)
    - [JSON Format](#json-format)
    - [Pandas DataFrames](#pandas-dataframes)
    - [Polars DataFrames](#polars-dataframes)
- [Logging](#logging)
  - [Available Loggers](#available-loggers)
  - [Configuring Loggers](#configuring-loggers)
- [Advanced Usage](#advanced-usage)
  - [Custom Packet Processing](#custom-packet-processing)
  - [Performance Considerations](#performance-considerations)
- [Examples](#examples)
  - [Basic Packet Capture](#basic-packet-capture)
  - [Filtered Capture](#filtered-capture)
  - [Data Analysis](#data-analysis)
- [Troubleshooting](#troubleshooting)
- [API Reference](#api-reference)

## Introduction

The Sniffer module is a component of the Network Security Suite designed for capturing, parsing, and analyzing network packets. It provides a high-level API for network packet capture while handling the complexities of different network protocols and operating systems.

Key features include:
- Cross-platform network interface detection
- Packet capture with BPF filtering
- Multi-threaded packet processing
- Conversion to various data formats (JSON, Pandas, Polars)
- Comprehensive logging system
- Performance metrics tracking

## Installation

The Sniffer module is part of the Network Security Suite package. To use it, you need to install the complete package:

```bash
# Using pip
pip install network-security-suite

# Using poetry
poetry add network-security-suite
```

## Getting Started

Here's a simple example to get started with packet capture:

```python
from network_security_suite.sniffer import PacketCapture

# Create a packet capture instance
sniffer = PacketCapture()

# Capture 100 packets
sniffer.capture(max_packets=100)

# Display captured packets
sniffer.show_packets()

# Show packet statistics
sniffer.show_stats()
```

## Configuration

### Using SnifferConfig

The `SnifferConfig` class provides a structured way to configure the sniffer:

```python
from network_security_suite.sniffer.sniffer_config import SnifferConfig
from network_security_suite.sniffer import PacketCapture

# Create a configuration
config = SnifferConfig(
    interface="eth0",
    max_memory_packets=1000,
    log_dir="/path/to/logs"
)

# Create a packet capture with the configuration
sniffer = PacketCapture(config=config)
```

### Loading and Saving Configurations

You can load and save configurations from/to YAML files:

```python
# Load configuration from a YAML file
config = SnifferConfig.from_yaml("sniffer_config.yaml")

# Save configuration to a YAML file
config.to_yaml("sniffer_config.yaml")
```

### Default Configuration

Generate a default configuration file:

```python
SnifferConfig.generate_default_config("default_config.yaml")
```

## Network Interfaces

### Listing Available Interfaces

To list all available network interfaces:

```python
from network_security_suite.sniffer.interfaces import Interface

# Create an interface handler
iface_handler = Interface()

# Show all available interfaces
iface_handler.show_available_interfaces()
```

### Selecting Interfaces

You can select interfaces manually or let the system recommend one:

```python
# Get a recommended interface
recommended_iface = iface_handler.get_recommended_interface()

# Get interfaces by type
wireless_ifaces = iface_handler.get_interface_by_type("wireless")
```

### Interface Information

Get detailed information about a specific interface:

```python
# Get information about a specific interface
info = iface_handler.get_interface_info("eth0")
print(info)
```

## Packet Capture

### Basic Capture

Capture a specific number of packets:

```python
sniffer = PacketCapture()
sniffer.capture(max_packets=100)
```

### Filtering Packets

Use Berkeley Packet Filter (BPF) syntax to filter packets:

```python
# Capture only TCP packets on port 80
sniffer.capture(max_packets=100, bpf_filter="tcp port 80")

# Capture only ICMP packets
sniffer.capture(max_packets=100, bpf_filter="icmp")
```

### Multi-threaded Capture

For better performance, use multiple threads for packet processing:

```python
# Capture with 4 processing threads
sniffer.capture(max_packets=1000, num_threads=4)
```

### Capture with Logging

Enable logging during capture:

```python
# Capture with logging enabled
sniffer.capture(max_packets=100, log=True)
```

## Working with Captured Packets

### Displaying Packets

Display captured packets in a readable format:

```python
# Show all captured packets
sniffer.show_packets()
```

### Packet Statistics

View statistics about captured packets:

```python
# Show packet statistics
sniffer.show_stats()
```

### Data Conversion

#### JSON Format

Convert packets to JSON format:

```python
# Convert to JSON
json_data = sniffer.to_json()

# Save to a file
with open("packets.json", "w") as f:
    f.write(json_data)
```

#### Pandas DataFrames

Convert packets to a Pandas DataFrame for analysis:

```python
# Convert to Pandas DataFrame
df = sniffer.to_pandas_df()

# Analyze the data
print(df.describe())

# Filter packets
http_packets = df[df["dst_port"] == 80]
```

#### Polars DataFrames

For high-performance data processing, convert to a Polars DataFrame:

```python
# Convert to Polars DataFrame (if available)
try:
    pl_df = sniffer.to_polars_df()
    
    # Analyze the data
    print(pl_df.describe())
    
    # Filter packets
    http_packets = pl_df.filter(pl.col("dst_port") == 80)
except ImportError:
    print("Polars is not available. Install with: pip install polars")
```

## Logging

### Available Loggers

The Sniffer module provides various specialized loggers:

- `ConsoleLogger`: Logs to the console
- `FileLogger`: Logs to a file
- `RotatingFileLogger`: Logs to a file with rotation
- `TimedRotatingFileLogger`: Logs to a file with time-based rotation
- `PacketLogger`: Specialized for packet logging
- `SecurityLogger`: For security-related events
- `ErrorLogger`, `DebugLogger`, `InfoLogger`, etc.: For different log levels

### Configuring Loggers

Example of configuring loggers:

```python
from network_security_suite.sniffer.loggers import FileLogger, ConsoleLogger

# Create a file logger
file_logger = FileLogger(log_file="/path/to/logs/sniffer.log")

# Create a console logger
console_logger = ConsoleLogger()

# Log messages
file_logger.info("Starting packet capture")
console_logger.debug("Debug information")
```

## Advanced Usage

### Custom Packet Processing

You can extend the `PacketCapture` class to implement custom packet processing:

```python
from network_security_suite.sniffer import PacketCapture
from scapy.all import Packet as ScapyPacket

class CustomPacketCapture(PacketCapture):
    def process_packet_layers(self, packet: ScapyPacket):
        # Call the parent method to get the basic processing
        processed_packet = super().process_packet_layers(packet)
        
        # Add custom processing
        # ...
        
        return processed_packet
```

### Performance Considerations

For high-volume packet capture:

1. Use multi-threaded capture with `num_threads` parameter
2. Set appropriate `max_memory_packets` to avoid memory issues
3. Consider using Polars instead of Pandas for faster data processing
4. Use BPF filters to reduce the number of captured packets

## Examples

### Basic Packet Capture

```python
from network_security_suite.sniffer import PacketCapture

# Create a packet capture instance
sniffer = PacketCapture()

# Capture 100 packets
sniffer.capture(max_packets=100)

# Display captured packets
sniffer.show_packets()

# Show packet statistics
sniffer.show_stats()
```

### Filtered Capture

```python
from network_security_suite.sniffer import PacketCapture

# Create a packet capture instance
sniffer = PacketCapture()

# Capture HTTP traffic
sniffer.capture(max_packets=100, bpf_filter="tcp port 80 or tcp port 443")

# Show packet statistics
sniffer.show_stats()
```

### Data Analysis

```python
from network_security_suite.sniffer import PacketCapture
import matplotlib.pyplot as plt

# Create a packet capture instance
sniffer = PacketCapture()

# Capture packets
sniffer.capture(max_packets=1000)

# Convert to Pandas DataFrame
df = sniffer.to_pandas_df()

# Analyze protocol distribution
protocol_counts = df["protocol"].value_counts()
protocol_counts.plot(kind="bar")
plt.title("Protocol Distribution")
plt.savefig("protocol_distribution.png")

# Analyze packet sizes
plt.figure()
df["packet_size"].hist(bins=50)
plt.title("Packet Size Distribution")
plt.xlabel("Packet Size (bytes)")
plt.ylabel("Frequency")
plt.savefig("packet_size_distribution.png")
```

## Troubleshooting

Common issues and solutions:

1. **Permission errors**: Packet capture typically requires elevated privileges. Run your script with sudo or as administrator.

2. **No packets captured**: Check that you're using the correct interface and that there is traffic on that interface.

3. **BPF filter syntax errors**: Verify your BPF filter syntax. Common examples are available in the Filtering Packets section.

4. **Memory issues**: If you're capturing a large number of packets, adjust the `max_memory_packets` parameter to limit memory usage.

5. **Performance problems**: Use multi-threaded capture and consider using Polars instead of Pandas for data processing.

## API Reference

For detailed API documentation, refer to the docstrings in the source code or the generated API documentation.

Key classes:
- `PacketCapture`: Main class for capturing and processing packets
- `SnifferConfig`: Configuration class for the sniffer
- `Interface`: Class for working with network interfaces
- Various logger classes for different logging purposes
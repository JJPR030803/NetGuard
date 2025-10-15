# Getting Started with Sniffer Module

This guide will help you get started with the Network Security Suite's packet capture capabilities.

## Prerequisites

- Python 3.11 or higher
- Root/Administrator privileges (required for packet capture)
- A network interface to capture from

## Installation

The sniffer module is included with the Network Security Suite. Make sure you have all dependencies installed:

```bash
# Using uv
uv sync

# Or using poetry
poetry install
```

## Basic Packet Capture

### Step 1: List Available Interfaces

First, identify which network interfaces are available:

```python
from network_security_suite.sniffer.interfaces import get_available_interfaces

# List all available interfaces
interfaces = get_available_interfaces()
for iface in interfaces:
    print(f"Interface: {iface['name']}, IP: {iface.get('ip', 'N/A')}")
```

### Step 2: Create a Simple Capture

Create a basic packet capture on a specific interface:

```python
from network_security_suite.sniffer import PacketCapture

# Create capture instance
capture = PacketCapture(
    interface="eth0",           # Your network interface
    packet_count=100,           # Capture 100 packets
    output_file="capture.parquet"  # Save to Parquet file
)

# Start capturing
print("Starting packet capture...")
capture.start()
print("Capture complete!")
```

### Step 3: Apply Packet Filters

Capture only specific traffic using BPF filters:

```python
# Capture only HTTP traffic
capture = PacketCapture(
    interface="eth0",
    filter_str="tcp port 80 or tcp port 443"
)

# Capture DNS queries
capture = PacketCapture(
    interface="eth0",
    filter_str="udp port 53"
)

# Capture traffic to/from specific IP
capture = PacketCapture(
    interface="eth0",
    filter_str="host 192.168.1.100"
)
```

## Working with Captured Data

### Reading Parquet Files

After capturing, you can read and analyze the Parquet files:

```python
import pandas as pd

# Read captured packets
df = pd.read_parquet("capture.parquet")

# Display basic statistics
print(f"Total packets: {len(df)}")
print(f"Protocols: {df['protocol'].value_counts()}")
print(f"Top sources: {df['src_ip'].value_counts().head()}")
```

### Using ParquetProcessing

The module provides utilities for working with captured data:

```python
from network_security_suite.sniffer.parquet_processing import ParquetProcessor

# Load and process captured data
processor = ParquetProcessor("capture.parquet")

# Get summary statistics
summary = processor.get_summary()
print(summary)

# Filter by protocol
tcp_packets = processor.filter_by_protocol("TCP")
```

## Logging

### Basic Logging Setup

```python
from network_security_suite.sniffer import (
    PacketCapture,
    ConsoleLogger,
    FileLogger
)

# Set up loggers
console_logger = ConsoleLogger(level="INFO")
file_logger = FileLogger(
    filename="packet_capture.log",
    level="DEBUG"
)

# Create capture with logging
capture = PacketCapture(
    interface="eth0",
    loggers=[console_logger, file_logger]
)
```

### Specialized Loggers

```python
from network_security_suite.sniffer import (
    SecurityLogger,
    PacketLogger,
    ErrorLogger
)

# Security events logger
security_logger = SecurityLogger(
    filename="security.log",
    level="WARNING"
)

# Packet details logger
packet_logger = PacketLogger(
    filename="packets.log",
    level="DEBUG"
)

# Error logger
error_logger = ErrorLogger(
    filename="errors.log",
    level="ERROR"
)

capture = PacketCapture(
    interface="eth0",
    loggers=[security_logger, packet_logger, error_logger]
)
```

## Configuration Files

### Creating a Configuration File

Create a YAML configuration file (`sniffer_config.yaml`):

```yaml
sniffer:
  interface: eth0
  packet_count: 1000
  timeout: 60
  promisc_mode: true

  filters:
    - "tcp port 80"
    - "tcp port 443"

  output:
    directory: "./captures"
    format: parquet
    rotation: daily

  logging:
    level: INFO
    console: true
    file:
      enabled: true
      path: "./logs/sniffer.log"
      rotation: daily
      max_size: 100MB
```

### Using Configuration

```python
from network_security_suite.sniffer.sniffer_config import SnifferConfig

# Load configuration
config = SnifferConfig.from_yaml("sniffer_config.yaml")

# Create capture from configuration
capture = PacketCapture.from_config(config)
capture.start()
```

## Common Patterns

### Continuous Capture

```python
import time
from network_security_suite.sniffer import PacketCapture

# Create capture that runs continuously
capture = PacketCapture(
    interface="eth0",
    packet_count=0,  # 0 = unlimited
    timeout=None     # No timeout
)

# Start in background
capture.start_async()

# Run for specific duration
time.sleep(3600)  # Capture for 1 hour

# Stop capture
capture.stop()
```

### Multiple Interface Capture

```python
from network_security_suite.sniffer import PacketCapture
import threading

def capture_interface(interface_name):
    capture = PacketCapture(
        interface=interface_name,
        output_file=f"capture_{interface_name}.parquet"
    )
    capture.start()

# Capture from multiple interfaces
interfaces = ["eth0", "eth1", "wlan0"]
threads = []

for iface in interfaces:
    thread = threading.Thread(target=capture_interface, args=(iface,))
    thread.start()
    threads.append(thread)

# Wait for all captures to complete
for thread in threads:
    thread.join()
```

## Troubleshooting

### Permission Denied

If you get permission errors:

```bash
# Run with sudo
sudo python your_capture_script.py

# Or set capabilities (Linux)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3.11
```

### Interface Not Found

```python
# Verify interface exists
from network_security_suite.sniffer.interfaces import get_available_interfaces

interfaces = get_available_interfaces()
print("Available interfaces:", [i['name'] for i in interfaces])
```

### No Packets Captured

- Check if interface is active and has traffic
- Verify filter string is correct
- Ensure sufficient permissions
- Check if promiscuous mode is enabled

## Next Steps

- Learn about [advanced filtering](packet-filtering.md)
- Explore [configuration options](configuration.md)
- See [API reference](api/packet-capture.md) for all available options
- Check out [examples](examples/basic-capture.md) for more use cases

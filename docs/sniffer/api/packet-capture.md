# PacketCapture API Reference

The `PacketCapture` class is the main interface for capturing network packets.

## Overview

PacketCapture provides a high-level API for capturing network traffic from network interfaces. It handles packet filtering, buffering, and storage.

## Class Reference

::: network_security_suite.sniffer.packet_capture.PacketCapture
    options:
      show_source: true
      show_root_heading: true
      heading_level: 2
      members:
        - __init__
        - start
        - stop
        - start_async
        - set_filter
        - get_stats
        - from_config

## Usage Examples

### Basic Capture

```python
from network_security_suite.sniffer import PacketCapture

# Create and start capture
capture = PacketCapture(
    interface="eth0",
    packet_count=1000,
    filter_str="tcp port 80"
)
capture.start()
```

### Async Capture

```python
# Start capture in background
capture = PacketCapture(interface="eth0")
capture.start_async()

# Do other work...

# Stop when done
capture.stop()
```

### Get Statistics

```python
capture = PacketCapture(interface="eth0")
capture.start()

stats = capture.get_stats()
print(f"Packets captured: {stats['captured']}")
print(f"Packets dropped: {stats['dropped']}")
```

### From Configuration

```python
from network_security_suite.sniffer.sniffer_config import SnifferConfig

config = SnifferConfig.from_yaml("config.yaml")
capture = PacketCapture.from_config(config)
capture.start()
```

## Parameters

### Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `interface` | str | None | Network interface name |
| `packet_count` | int | 0 | Number of packets to capture (0=unlimited) |
| `timeout` | int \| None | None | Capture timeout in seconds |
| `promisc` | bool | True | Enable promiscuous mode |
| `filter_str` | str | "" | BPF filter string |
| `output_file` | str \| None | None | Output Parquet file path |
| `buffer_size` | int | 65536 | Packet buffer size |
| `snaplen` | int | 65535 | Snapshot length |

## Methods

### start()

Start packet capture (blocking).

```python
capture.start()
```

**Returns:** None

**Raises:**
- `PermissionError`: If insufficient permissions
- `InterfaceError`: If interface not found

### start_async()

Start packet capture in background thread.

```python
capture.start_async()
```

**Returns:** None

### stop()

Stop packet capture.

```python
capture.stop()
```

**Returns:** None

### set_filter(filter_str: str)

Update the BPF filter.

```python
capture.set_filter("tcp port 443")
```

**Parameters:**
- `filter_str` (str): BPF filter string

**Returns:** None

**Raises:**
- `ValueError`: If filter string is invalid

### get_stats()

Get capture statistics.

```python
stats = capture.get_stats()
```

**Returns:** dict with keys:
- `captured`: Number of packets captured
- `dropped`: Number of packets dropped
- `interface_dropped`: Number dropped by interface

## Properties

### interface

Get the current interface name.

```python
iface = capture.interface
```

### is_running

Check if capture is currently running.

```python
if capture.is_running:
    print("Capture is active")
```

### packets_captured

Get number of packets captured so far.

```python
count = capture.packets_captured
```

## Events and Callbacks

### Packet Callback

Process packets as they are captured:

```python
def packet_handler(packet):
    print(f"Captured: {packet.summary()}")

capture = PacketCapture(
    interface="eth0",
    packet_callback=packet_handler
)
```

### Statistics Callback

Get periodic statistics:

```python
def stats_callback(stats):
    print(f"Captured: {stats['captured']}, Dropped: {stats['dropped']}")

capture = PacketCapture(
    interface="eth0",
    stats_callback=stats_callback,
    stats_interval=10  # Every 10 seconds
)
```

## Error Handling

```python
from network_security_suite.sniffer import PacketCapture
from network_security_suite.sniffer.exceptions import (
    InterfaceError,
    CaptureError,
    FilterError
)

try:
    capture = PacketCapture(interface="invalid")
    capture.start()
except InterfaceError as e:
    print(f"Interface error: {e}")
except FilterError as e:
    print(f"Filter error: {e}")
except CaptureError as e:
    print(f"Capture error: {e}")
except PermissionError as e:
    print(f"Permission denied: {e}")
```

## Performance Considerations

### Buffer Size

Adjust buffer size based on traffic volume:

```python
# High traffic
capture = PacketCapture(
    interface="eth0",
    buffer_size=524288  # 512KB
)

# Low traffic
capture = PacketCapture(
    interface="eth0",
    buffer_size=65536   # 64KB
)
```

### Snapshot Length

Reduce snaplen to capture only headers:

```python
# Capture only headers (faster)
capture = PacketCapture(
    interface="eth0",
    snaplen=128  # Just headers
)

# Capture full packets
capture = PacketCapture(
    interface="eth0",
    snaplen=65535  # Full packets
)
```

## Thread Safety

PacketCapture is thread-safe. You can safely call methods from multiple threads:

```python
import threading

capture = PacketCapture(interface="eth0")

# Start in one thread
start_thread = threading.Thread(target=capture.start_async)
start_thread.start()

# Stop from another thread
def stop_after_delay():
    time.sleep(60)
    capture.stop()

stop_thread = threading.Thread(target=stop_after_delay)
stop_thread.start()
```

## See Also

- [Getting Started Guide](../getting-started.md)
- [Configuration Guide](../configuration.md)
- [Packet Filtering Guide](../packet-filtering.md)
- [ParquetProcessing API](parquet-processing.md)
- [Interfaces API](interfaces.md)

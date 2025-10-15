# Basic Packet Capture Examples

This page provides practical examples for common packet capture scenarios.

## Simple Capture

Capture 100 packets from the default interface:

```python
from network_security_suite.sniffer import PacketCapture

capture = PacketCapture(
    interface="eth0",
    packet_count=100
)
capture.start()
print("Captured 100 packets!")
```

## Capture with Timeout

Capture for a specific duration:

```python
capture = PacketCapture(
    interface="eth0",
    timeout=60  # 60 seconds
)
capture.start()
```

## Capture to File

Save captured packets to a Parquet file:

```python
capture = PacketCapture(
    interface="eth0",
    packet_count=1000,
    output_file="capture.parquet"
)
capture.start()
```

## Continuous Capture

Capture continuously in the background:

```python
import time

# Start capture
capture = PacketCapture(interface="eth0", packet_count=0)
capture.start_async()

# Let it run
print("Capturing packets...")
time.sleep(300)  # Run for 5 minutes

# Stop capture
capture.stop()
print(f"Captured {capture.packets_captured} packets")
```

## Filtered Capture

Capture only HTTP traffic:

```python
capture = PacketCapture(
    interface="eth0",
    filter_str="tcp port 80",
    packet_count=100
)
capture.start()
```

## See Also

- [Advanced Filtering Examples](advanced-filtering.md)
- [Getting Started Guide](../getting-started.md)
- [Packet Filtering Guide](../packet-filtering.md)

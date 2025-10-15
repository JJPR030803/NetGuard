# Advanced Filtering Examples

This page provides examples of advanced packet filtering techniques.

## Multi-Protocol Filtering

Capture HTTP, HTTPS, and DNS traffic:

```python
from network_security_suite.sniffer import PacketCapture

capture = PacketCapture(
    interface="eth0",
    filter_str="(tcp port 80 or tcp port 443 or udp port 53)"
)
capture.start()
```

## Network-Based Filtering

Capture traffic to/from a specific subnet:

```python
capture = PacketCapture(
    interface="eth0",
    filter_str="src net 192.168.1.0/24 or dst net 192.168.1.0/24"
)
capture.start()
```

## Security Monitoring

Detect potential port scans:

```python
# Capture SYN packets (connection attempts)
capture = PacketCapture(
    interface="eth0",
    filter_str="tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0"
)
capture.start()
```

## Large Packet Detection

Capture only large packets (potential data exfiltration):

```python
capture = PacketCapture(
    interface="eth0",
    filter_str="greater 1400 and not broadcast"
)
capture.start()
```

## Exclude Local Traffic

Capture only external traffic:

```python
capture = PacketCapture(
    interface="eth0",
    filter_str="not (src net 192.168.0.0/16 and dst net 192.168.0.0/16)"
)
capture.start()
```

## See Also

- [Basic Capture Examples](basic-capture.md)
- [Packet Filtering Guide](../packet-filtering.md)
- [Configuration Guide](../configuration.md)

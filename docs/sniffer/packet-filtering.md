# Packet Filtering Guide

This guide covers advanced packet filtering techniques using Berkeley Packet Filter (BPF) syntax.

## BPF Filter Basics

BPF filters allow you to capture only the packets you're interested in, reducing processing overhead and storage requirements.

### Basic Syntax

```python
from network_security_suite.sniffer import PacketCapture

# Capture all TCP packets
capture = PacketCapture(interface="eth0", filter_str="tcp")

# Capture all UDP packets
capture = PacketCapture(interface="eth0", filter_str="udp")

# Capture all ICMP packets
capture = PacketCapture(interface="eth0", filter_str="icmp")
```

## Common Filter Patterns

### Filter by Protocol

```python
# TCP only
filter_str = "tcp"

# UDP only
filter_str = "udp"

# ICMP only
filter_str = "icmp"

# ARP only
filter_str = "arp"

# IP (any IP protocol)
filter_str = "ip"
```

### Filter by Port

```python
# Specific port
filter_str = "port 80"

# Source port
filter_str = "src port 443"

# Destination port
filter_str = "dst port 22"

# Port range
filter_str = "portrange 8000-9000"

# Multiple ports
filter_str = "port 80 or port 443 or port 8080"
```

### Filter by IP Address

```python
# Specific host
filter_str = "host 192.168.1.100"

# Source IP
filter_str = "src host 10.0.0.1"

# Destination IP
filter_str = "dst host 172.16.0.1"

# Network range (CIDR)
filter_str = "net 192.168.1.0/24"

# Source network
filter_str = "src net 10.0.0.0/8"

# Destination network
filter_str = "dst net 172.16.0.0/16"
```

## Advanced Filters

### Combining Filters

Use logical operators to combine filters:

```python
# AND operator
filter_str = "tcp and port 80"

# OR operator
filter_str = "tcp port 80 or tcp port 443"

# NOT operator
filter_str = "not broadcast"

# Complex combination
filter_str = "tcp and (port 80 or port 443) and src net 192.168.1.0/24"
```

### Protocol-Specific Filters

#### HTTP/HTTPS Traffic

```python
# HTTP traffic
filter_str = "tcp port 80"

# HTTPS traffic
filter_str = "tcp port 443"

# Both HTTP and HTTPS
filter_str = "tcp port 80 or tcp port 443"

# HTTP methods (requires deep packet inspection)
filter_str = "tcp port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420"  # GET
```

#### DNS Traffic

```python
# DNS queries and responses
filter_str = "udp port 53"

# DNS over TCP
filter_str = "tcp port 53"

# All DNS traffic
filter_str = "port 53"

# DNS from specific server
filter_str = "src host 8.8.8.8 and port 53"
```

#### SSH Traffic

```python
# SSH connections
filter_str = "tcp port 22"

# SSH to specific host
filter_str = "tcp port 22 and dst host 192.168.1.100"
```

#### Email Protocols

```python
# SMTP
filter_str = "tcp port 25"

# IMAP
filter_str = "tcp port 143"

# POP3
filter_str = "tcp port 110"

# All email protocols
filter_str = "port 25 or port 110 or port 143"
```

### TCP-Specific Filters

```python
# TCP SYN packets (connection attempts)
filter_str = "tcp[tcpflags] & tcp-syn != 0"

# TCP SYN-ACK packets
filter_str = "tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)"

# TCP RST packets
filter_str = "tcp[tcpflags] & tcp-rst != 0"

# TCP FIN packets
filter_str = "tcp[tcpflags] & tcp-fin != 0"

# Established connections
filter_str = "tcp[tcpflags] & tcp-ack != 0 and not tcp[tcpflags] & tcp-syn != 0"
```

### Size-Based Filters

```python
# Packets larger than 1000 bytes
filter_str = "greater 1000"

# Packets smaller than 100 bytes
filter_str = "less 100"

# Large packets only
filter_str = "greater 1400"  # Likely fragmented

# Small packets only
filter_str = "less 64"  # Might be suspicious
```

### Direction-Based Filters

```python
# Incoming traffic only
filter_str = "inbound"

# Outgoing traffic only
filter_str = "outbound"

# Incoming on specific network
filter_str = "src net 192.168.1.0/24 and dst net 10.0.0.0/8"
```

## Security-Focused Filters

### Suspicious Activity

```python
# Port scanning detection (SYN to multiple ports)
filter_str = "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0"

# NULL scans
filter_str = "tcp[tcpflags] == 0"

# XMAS scans
filter_str = "tcp[tcpflags] & (tcp-fin|tcp-urg|tcp-push) == (tcp-fin|tcp-urg|tcp-push)"

# Fragmented packets (potential evasion)
filter_str = "ip[6:2] & 0x1fff != 0"
```

### Broadcast and Multicast

```python
# Exclude broadcast
filter_str = "not broadcast"

# Exclude multicast
filter_str = "not multicast"

# Only broadcast
filter_str = "broadcast"

# Only multicast
filter_str = "multicast"
```

### Specific Threats

```python
# DNS tunneling detection (large DNS responses)
filter_str = "udp port 53 and greater 512"

# Potential DDoS (many connections from same source)
filter_str = "tcp[tcpflags] & tcp-syn != 0 and src host 192.168.1.100"

# ARP spoofing detection
filter_str = "arp"
```

## Performance Optimization

### Efficient Filters

```python
# Good: Specific and efficient
filter_str = "tcp port 443 and src net 192.168.1.0/24"

# Bad: Too broad, captures everything
filter_str = "ip"

# Good: Combines related filters
filter_str = "(port 80 or port 443) and tcp"

# Bad: Redundant
filter_str = "tcp and tcp port 80"  # "tcp" is redundant
```

### Filter Order Matters

```python
# More efficient (checks protocol first)
filter_str = "tcp and port 443 and host 192.168.1.100"

# Less efficient (checks host first, broader)
filter_str = "host 192.168.1.100 and port 443 and tcp"
```

## Complex Filter Examples

### Web Traffic Analysis

```python
# All web traffic (HTTP + HTTPS)
filter_str = "tcp and (port 80 or port 443 or port 8080)"

# Web traffic to/from specific subnet
filter_str = "(tcp port 80 or tcp port 443) and (src net 192.168.1.0/24 or dst net 192.168.1.0/24)"

# Non-standard web ports
filter_str = "tcp and (port 8080 or port 8443 or port 3000)"
```

### Database Traffic

```python
# MySQL
filter_str = "tcp port 3306"

# PostgreSQL
filter_str = "tcp port 5432"

# MongoDB
filter_str = "tcp port 27017"

# Redis
filter_str = "tcp port 6379"

# All common databases
filter_str = "tcp and (port 3306 or port 5432 or port 27017 or port 6379)"
```

### Network Diagnostics

```python
# ICMP Echo (ping)
filter_str = "icmp[icmptype] == icmp-echo or icmp[icmptype] == icmp-echoreply"

# Traceroute
filter_str = "icmp or (udp and portrange 33434-33534)"

# Network errors
filter_str = "icmp and (icmp[icmptype] == icmp-unreach or icmp[icmptype] == icmp-timxceed)"
```

### VPN and Tunneling

```python
# OpenVPN
filter_str = "udp port 1194"

# IPSec
filter_str = "esp or ah or udp port 500"

# WireGuard
filter_str = "udp port 51820"

# GRE tunnels
filter_str = "proto gre"
```

## Filter Testing

Test your filters before deployment:

```python
from network_security_suite.sniffer import PacketCapture

def test_filter(filter_str, count=10):
    """Test a BPF filter"""
    try:
        capture = PacketCapture(
            interface="eth0",
            filter_str=filter_str,
            packet_count=count
        )
        print(f"Filter valid: {filter_str}")
        capture.start()
        print(f"Captured {count} packets")
    except Exception as e:
        print(f"Filter error: {e}")

# Test various filters
test_filter("tcp port 80")
test_filter("invalid filter")  # Will show error
```

## Common Mistakes

### 1. Incorrect Syntax

```python
# Wrong
filter_str = "port = 80"  # No '=' operator

# Correct
filter_str = "port 80"
```

### 2. Missing Quotes

```python
# Wrong (in YAML)
filter: tcp port 80  # Might be parsed incorrectly

# Correct
filter: "tcp port 80"
```

### 3. Overly Complex Filters

```python
# Too complex, hard to maintain
filter_str = "((tcp port 80 or tcp port 443) and (src net 192.168.1.0/24 or dst net 192.168.1.0/24)) or ((udp port 53) and not (src host 8.8.8.8 or src host 8.8.4.4))"

# Better: Break into separate captures or simplify
filter_str = "tcp and (port 80 or port 443)"
```

## Best Practices

1. **Start broad, then narrow**: Begin with simple filters and add specificity
2. **Test filters**: Always test on low-traffic interfaces first
3. **Document filters**: Comment complex filters in configuration files
4. **Performance**: More specific filters = better performance
5. **Security**: Use filters to reduce attack surface

## Filter Reference

### Quick Reference Table

| Filter | Description |
|--------|-------------|
| `tcp` | TCP packets only |
| `udp` | UDP packets only |
| `icmp` | ICMP packets only |
| `port N` | Port N (src or dst) |
| `src port N` | Source port N |
| `dst port N` | Destination port N |
| `host IP` | IP address (src or dst) |
| `src host IP` | Source IP |
| `dst host IP` | Destination IP |
| `net CIDR` | Network range |
| `greater N` | Packets > N bytes |
| `less N` | Packets < N bytes |
| `and` | Logical AND |
| `or` | Logical OR |
| `not` | Logical NOT |

## Next Steps

- Practice with [examples](examples/advanced-filtering.md)
- Read [BPF manual](https://www.tcpdump.org/manpages/pcap-filter.7.html)
- Learn about [configuration](configuration.md)
- See [API reference](api/packet-capture.md)

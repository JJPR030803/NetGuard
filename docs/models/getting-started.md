# Getting Started with Models

This guide will help you understand and use the data models in the Network Security Suite.

## Overview

The models module provides Pydantic-based data structures for representing network packets and related data. These models ensure type safety, validation, and easy serialization.

## Basic Usage

### Creating a Packet Model

```python
from network_security_suite.models import ARPPacket

# Create an ARP packet
packet = ARPPacket(
    operation=1,  # ARP Request
    sender_mac="00:11:22:33:44:55",
    sender_ip="192.168.1.100",
    target_mac="00:00:00:00:00:00",
    target_ip="192.168.1.1"
)

print(f"ARP Request from {packet.sender_ip} to {packet.target_ip}")
```

### Accessing Fields

```python
# Access individual fields
print(packet.sender_mac)
print(packet.sender_ip)
print(packet.operation)

# Check operation type
if packet.operation == 1:
    print("This is an ARP request")
elif packet.operation == 2:
    print("This is an ARP reply")
```

### Serialization

```python
# Convert to dictionary
packet_dict = packet.model_dump()
print(packet_dict)

# Convert to JSON
packet_json = packet.model_dump_json(indent=2)
print(packet_json)
```

## Working with Different Protocols

### Ethernet Packets

```python
from network_security_suite.models import EthernetPacket

ethernet = EthernetPacket(
    src_mac="00:11:22:33:44:55",
    dst_mac="66:77:88:99:aa:bb",
    ethertype=0x0800,  # IPv4
    payload=b"\x00\x01\x02\x03"
)
```

### TCP Packets

```python
from network_security_suite.models import TCPPacket

tcp = TCPPacket(
    src_port=443,
    dst_port=54321,
    seq=1000,
    ack=2000,
    flags="SA",  # SYN-ACK
    window=65535,
    checksum=0x1234
)

# Check flags
if "S" in tcp.flags:
    print("SYN flag set")
if "A" in tcp.flags:
    print("ACK flag set")
```

### UDP Packets

```python
from network_security_suite.models import UDPPacket

udp = UDPPacket(
    src_port=53,
    dst_port=12345,
    length=100,
    checksum=0x5678,
    payload=b"DNS query data"
)
```

## Validation

### Automatic Validation

Pydantic automatically validates data:

```python
from network_security_suite.models import ARPPacket
from pydantic import ValidationError

try:
    # Invalid MAC address format
    packet = ARPPacket(
        operation=1,
        sender_mac="invalid",
        sender_ip="192.168.1.1",
        target_mac="00:00:00:00:00:00",
        target_ip="192.168.1.1"
    )
except ValidationError as e:
    print(f"Validation error: {e}")
```

### Custom Validation

```python
def validate_tcp_packet(packet: TCPPacket) -> bool:
    """Custom validation logic"""
    # Check port ranges
    if not (0 <= packet.src_port <= 65535):
        return False
    if not (0 <= packet.dst_port <= 65535):
        return False

    # Check sequence numbers
    if packet.seq < 0:
        return False

    return True
```

## Creating from Raw Data

### From Dictionary

```python
from network_security_suite.models import TCPPacket

raw_data = {
    "src_port": 80,
    "dst_port": 54321,
    "seq": 1000,
    "ack": 2000,
    "flags": "PA",
    "window": 65535
}

packet = TCPPacket(**raw_data)
```

### From JSON

```python
import json
from network_security_suite.models import ARPPacket

json_data = '{"operation": 1, "sender_mac": "00:11:22:33:44:55", "sender_ip": "192.168.1.1", "target_mac": "00:00:00:00:00:00", "target_ip": "192.168.1.254"}'

packet = ARPPacket(**json.loads(json_data))
```

### From Captured Packets

```python
from scapy.all import sniff
from network_security_suite.models import ARPPacket

def packet_handler(scapy_packet):
    if scapy_packet.haslayer("ARP"):
        arp = scapy_packet["ARP"]
        model = ARPPacket(
            operation=arp.op,
            sender_mac=arp.hwsrc,
            sender_ip=arp.psrc,
            target_mac=arp.hwdst,
            target_ip=arp.pdst
        )
        print(model)

# Capture ARP packets
sniff(filter="arp", prn=packet_handler, count=10)
```

## Database Integration

### Storing Models

```python
from network_security_suite.models import PacketRecord
from sqlalchemy.orm import Session

def save_packet(session: Session, packet: EthernetPacket):
    record = PacketRecord(**packet.model_dump())
    session.add(record)
    session.commit()
```

### Loading from Database

```python
def load_packet(session: Session, packet_id: int) -> EthernetPacket:
    record = session.query(PacketRecord).get(packet_id)
    return EthernetPacket(**record.to_dict())
```

## Common Patterns

### Packet Processing Pipeline

```python
from typing import List
from network_security_suite.models import TCPPacket

def process_tcp_packets(packets: List[dict]) -> List[TCPPacket]:
    """Process raw packet data into validated models"""
    validated = []
    errors = []

    for raw_packet in packets:
        try:
            packet = TCPPacket(**raw_packet)
            validated.append(packet)
        except ValidationError as e:
            errors.append((raw_packet, e))

    if errors:
        log_errors(errors)

    return validated
```

### Filtering Packets

```python
def filter_syn_packets(packets: List[TCPPacket]) -> List[TCPPacket]:
    """Filter for SYN packets"""
    return [p for p in packets if "S" in p.flags and "A" not in p.flags]

def filter_by_port(packets: List[TCPPacket], port: int) -> List[TCPPacket]:
    """Filter packets by port"""
    return [p for p in packets if p.src_port == port or p.dst_port == port]
```

### Aggregating Data

```python
from collections import Counter

def analyze_tcp_flags(packets: List[TCPPacket]) -> dict:
    """Analyze TCP flag distribution"""
    flag_counter = Counter()

    for packet in packets:
        for flag in packet.flags:
            flag_counter[flag] += 1

    return dict(flag_counter)
```

## Best Practices

### 1. Always Handle Validation Errors

```python
from pydantic import ValidationError

try:
    packet = ARPPacket(**raw_data)
except ValidationError as e:
    logger.error(f"Invalid packet data: {e}")
    # Handle error appropriately
```

### 2. Use Type Hints

```python
from network_security_suite.models import TCPPacket

def analyze_connection(packet: TCPPacket) -> dict:
    return {
        "is_syn": "S" in packet.flags,
        "is_established": "A" in packet.flags
    }
```

### 3. Validate Before Processing

```python
def safe_process(raw_data: dict):
    try:
        packet = TCPPacket(**raw_data)
        # Process validated packet
        return process_packet(packet)
    except ValidationError:
        return None
```

## Next Steps

- Learn about [data structures](data-structures.md)
- See [API reference](api/packet-data-structures.md)
- Explore [database schemas](api/database-schemas.md)

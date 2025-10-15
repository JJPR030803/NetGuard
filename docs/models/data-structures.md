# Data Structures Guide

Detailed guide to the data structures used in the Network Security Suite.

## Model Hierarchy

```
NetworkPacket (Base)
├── Layer2Packet
│   ├── EthernetPacket
│   ├── ARPPacket
│   └── STPPacket
├── Layer3Packet
│   ├── IPPacket
│   └── ICMPPacket
└── Layer4Packet
    ├── TCPPacket
    └── UDPPacket
```

## Layer 2 Models

### EthernetPacket

Represents an Ethernet frame (Layer 2).

**Fields:**
- `src_mac`: Source MAC address
- `dst_mac`: Destination MAC address
- `ethertype`: EtherType (e.g., 0x0800 for IPv4)
- `payload`: Frame payload
- `timestamp`: Capture timestamp

**Example:**
```python
from network_security_suite.models import EthernetPacket

ethernet = EthernetPacket(
    src_mac="00:11:22:33:44:55",
    dst_mac="66:77:88:99:aa:bb",
    ethertype=0x0800
)
```

### ARPPacket

Represents an ARP (Address Resolution Protocol) packet.

**Fields:**
- `operation`: 1 (request) or 2 (reply)
- `sender_mac`: Sender hardware address
- `sender_ip`: Sender protocol address
- `target_mac`: Target hardware address
- `target_ip`: Target protocol address

**Example:**
```python
from network_security_suite.models import ARPPacket

arp = ARPPacket(
    operation=1,
    sender_mac="00:11:22:33:44:55",
    sender_ip="192.168.1.100",
    target_mac="00:00:00:00:00:00",
    target_ip="192.168.1.1"
)
```

### STPPacket

Represents a Spanning Tree Protocol packet.

**Fields:**
- `protocol_id`: Protocol identifier
- `version`: STP version
- `message_type`: BPDU type
- `flags`: STP flags
- `root_id`: Root bridge ID
- `bridge_id`: Bridge ID
- `port_id`: Port identifier

## Layer 3 Models

### IPPacket

Represents an IP packet (Layer 3).

**Fields:**
- `version`: IP version (4 or 6)
- `src_ip`: Source IP address
- `dst_ip`: Destination IP address
- `protocol`: Protocol number (6=TCP, 17=UDP)
- `ttl`: Time to live
- `length`: Packet length

**Example:**
```python
from network_security_suite.models import IPPacket

ip = IPPacket(
    version=4,
    src_ip="192.168.1.100",
    dst_ip="10.0.0.1",
    protocol=6,  # TCP
    ttl=64
)
```

### ICMPPacket

Represents an ICMP packet.

**Fields:**
- `type`: ICMP type (e.g., 8=echo request, 0=echo reply)
- `code`: ICMP code
- `checksum`: Checksum
- `identifier`: Identifier (for echo)
- `sequence`: Sequence number

## Layer 4 Models

### TCPPacket

Represents a TCP packet (Layer 4).

**Fields:**
- `src_port`: Source port
- `dst_port`: Destination port
- `seq`: Sequence number
- `ack`: Acknowledgment number
- `flags`: TCP flags (S, A, F, R, P, U)
- `window`: Window size
- `checksum`: Checksum
- `urgent_ptr`: Urgent pointer

**Example:**
```python
from network_security_suite.models import TCPPacket

tcp = TCPPacket(
    src_port=443,
    dst_port=54321,
    seq=1000,
    ack=2000,
    flags="SA",  # SYN-ACK
    window=65535
)
```

**TCP Flags:**
- `S`: SYN (Synchronize)
- `A`: ACK (Acknowledgment)
- `F`: FIN (Finish)
- `R`: RST (Reset)
- `P`: PSH (Push)
- `U`: URG (Urgent)

### UDPPacket

Represents a UDP packet.

**Fields:**
- `src_port`: Source port
- `dst_port`: Destination port
- `length`: Length
- `checksum`: Checksum
- `payload`: Data payload

**Example:**
```python
from network_security_suite.models import UDPPacket

udp = UDPPacket(
    src_port=53,
    dst_port=12345,
    length=100,
    payload=b"DNS data"
)
```

## Application Layer Models

### DNSPacket

Represents a DNS packet.

**Fields:**
- `transaction_id`: Transaction ID
- `flags`: DNS flags
- `questions`: DNS questions
- `answers`: DNS answers
- `authority`: Authority records
- `additional`: Additional records

## Database Models

### PacketRecord

Database schema for storing packet records.

**Fields:**
- `id`: Primary key
- `timestamp`: Capture timestamp
- `src_mac`: Source MAC
- `dst_mac`: Destination MAC
- `src_ip`: Source IP
- `dst_ip`: Destination IP
- `protocol`: Protocol
- `length`: Packet length
- `raw_data`: Raw packet data

### FlowRecord

Database schema for network flows.

**Fields:**
- `id`: Primary key
- `start_time`: Flow start time
- `end_time`: Flow end time
- `src_ip`: Source IP
- `dst_ip`: Destination IP
- `src_port`: Source port
- `dst_port`: Destination port
- `protocol`: Protocol
- `packet_count`: Number of packets
- `byte_count`: Total bytes

## Model Features

### Serialization

All models support serialization to dict and JSON:

```python
# To dictionary
packet_dict = packet.model_dump()

# To JSON
packet_json = packet.model_dump_json()

# To JSON with formatting
packet_json = packet.model_dump_json(indent=2)
```

### Validation

All models include automatic validation:

```python
from pydantic import ValidationError

try:
    packet = TCPPacket(src_port=999999)  # Invalid port
except ValidationError as e:
    print(e)
```

### Immutability (Optional)

Models can be made immutable using Pydantic's frozen feature:

```python
from pydantic import BaseModel

class ImmutablePacket(BaseModel):
    model_config = {"frozen": True}

# packet.src_port = 80  # Raises error
```

## Best Practices

### Use Appropriate Models

Choose the right model for your data layer:

```python
# Layer 2 analysis
ethernet = EthernetPacket(...)

# Layer 3 analysis
ip = IPPacket(...)

# Layer 4 analysis
tcp = TCPPacket(...)
```

### Validate Early

Validate data as soon as possible:

```python
def process_raw_packet(raw_data: dict):
    try:
        packet = TCPPacket(**raw_data)
        return process_validated_packet(packet)
    except ValidationError:
        return handle_invalid_packet(raw_data)
```

### Use Type Hints

Always use type hints for better code quality:

```python
from network_security_suite.models import TCPPacket

def analyze(packet: TCPPacket) -> dict:
    return {"port": packet.src_port}
```

## See Also

- [Getting Started Guide](getting-started.md)
- [API Reference](api/packet-data-structures.md)
- [Database Schemas](api/database-schemas.md)

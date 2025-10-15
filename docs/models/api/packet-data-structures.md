# Packet Data Structures API Reference

Complete API reference for packet data structure models.

## Module Reference

::: network_security_suite.models.packet_data_structures
    options:
      show_source: true
      show_root_heading: true
      heading_level: 2

## Usage Examples

### EthernetPacket

```python
from network_security_suite.models import EthernetPacket

ethernet = EthernetPacket(
    src_mac="00:11:22:33:44:55",
    dst_mac="66:77:88:99:aa:bb",
    ethertype=0x0800,
    payload=b"\x00\x01\x02"
)

print(ethernet.model_dump_json(indent=2))
```

### ARPPacket

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

### TCPPacket

```python
from network_security_suite.models import TCPPacket

tcp = TCPPacket(
    src_port=443,
    dst_port=54321,
    seq=1000,
    ack=2000,
    flags="SA",
    window=65535
)
```

### UDPPacket

```python
from network_security_suite.models import UDPPacket

udp = UDPPacket(
    src_port=53,
    dst_port=12345,
    length=100,
    payload=b"data"
)
```

## See Also

- [Getting Started Guide](../getting-started.md)
- [Data Structures Guide](../data-structures.md)
- [Database Schemas](database-schemas.md)

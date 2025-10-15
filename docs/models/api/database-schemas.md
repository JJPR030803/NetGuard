# Database Schemas API Reference

Complete API reference for database schema definitions.

## Module Reference

::: network_security_suite.models.database_schemas
    options:
      show_source: true
      show_root_heading: true
      heading_level: 2

## Usage Examples

### PacketRecord

```python
from network_security_suite.models import PacketRecord
from sqlalchemy.orm import Session

# Create a packet record
record = PacketRecord(
    timestamp=datetime.now(),
    src_mac="00:11:22:33:44:55",
    dst_mac="66:77:88:99:aa:bb",
    protocol="TCP",
    length=100
)

# Save to database
session.add(record)
session.commit()
```

### FlowRecord

```python
from network_security_suite.models import FlowRecord

# Create a flow record
flow = FlowRecord(
    start_time=datetime.now(),
    src_ip="192.168.1.100",
    dst_ip="10.0.0.1",
    src_port=54321,
    dst_port=443,
    protocol="TCP",
    packet_count=100,
    byte_count=50000
)
```

## See Also

- [Packet Data Structures](packet-data-structures.md)
- [Getting Started Guide](../getting-started.md)

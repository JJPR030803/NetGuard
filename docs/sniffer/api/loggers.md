# Loggers API Reference

Specialized logger classes for different types of logging events.

## Module Reference

::: network_security_suite.sniffer.loggers
    options:
      show_source: true
      show_root_heading: true
      heading_level: 2

## Usage Examples

### Console Logger

```python
from network_security_suite.sniffer import ConsoleLogger

logger = ConsoleLogger(level="INFO")
logger.info("Application started")
```

### File Logger

```python
from network_security_suite.sniffer import FileLogger

logger = FileLogger(
    filename="app.log",
    level="DEBUG"
)
logger.debug("Debug message")
```

### Rotating File Logger

```python
from network_security_suite.sniffer import RotatingFileLogger

logger = RotatingFileLogger(
    filename="app.log",
    max_bytes=10485760,  # 10MB
    backup_count=5
)
```

### Security Logger

```python
from network_security_suite.sniffer import SecurityLogger

security_logger = SecurityLogger(
    filename="security.log",
    level="WARNING"
)
security_logger.warning("Suspicious activity detected")
```

### Packet Logger

```python
from network_security_suite.sniffer import PacketLogger

packet_logger = PacketLogger(filename="packets.log")
packet_logger.info(f"Captured packet: {packet.summary()}")
```

## See Also

- [PacketCapture API](packet-capture.md)
- [Configuration Guide](../configuration.md)

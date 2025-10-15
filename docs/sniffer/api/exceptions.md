# Exceptions API Reference

Custom exceptions for packet capture operations.

## Module Reference

::: network_security_suite.sniffer.exceptions
    options:
      show_source: true
      show_root_heading: true
      heading_level: 2

## Usage Examples

### Handling Exceptions

```python
from network_security_suite.sniffer import PacketCapture
from network_security_suite.sniffer.exceptions import (
    InterfaceError,
    CaptureError,
    FilterError,
    PermissionError
)

try:
    capture = PacketCapture(interface="eth0", filter_str="tcp")
    capture.start()
except InterfaceError as e:
    print(f"Interface not found: {e}")
except FilterError as e:
    print(f"Invalid filter: {e}")
except CaptureError as e:
    print(f"Capture failed: {e}")
except PermissionError as e:
    print(f"Permission denied: {e}")
```

## See Also

- [PacketCapture API](packet-capture.md)
- [Getting Started Guide](../getting-started.md)

# Exceptions API Reference

Custom exceptions for packet capture operations.

## Module Reference

::: netguard.core.exceptions
    options:
      show_source: true
      show_root_heading: true
      heading_level: 2

## Usage Examples

### Handling Exceptions

```python
from netguard.sniffer import PacketCapture
from netguard.core.exceptions import (
    InterfaceNotFoundError,
    PacketCaptureError,
    FilterError,
    InterfacePermissionError
)

try:
    capture = PacketCapture(interface="eth0", filter_str="tcp")
    capture.start()
except InterfaceNotFoundError as e:
    print(f"Interface not found: {e}")
except FilterError as e:
    print(f"Invalid filter: {e}")
except PacketCaptureError as e:
    print(f"Capture failed: {e}")
except InterfacePermissionError as e:
    print(f"Permission denied: {e}")
```

## See Also

- [PacketCapture API](packet-capture.md)
- [Getting Started Guide](../getting-started.md)

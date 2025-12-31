# Interfaces API Reference

Network interface discovery and management utilities.

## Module Reference

::: netguard.core.interfaces
    options:
      show_source: true
      show_root_heading: true
      heading_level: 2

## Usage Examples

### List Available Interfaces

```python
from netguard.core.interfaces import get_available_interfaces

# Get all interfaces
interfaces = get_available_interfaces()
for iface in interfaces:
    print(f"Interface: {iface['name']}")
    print(f"  IP: {iface.get('ip', 'N/A')}")
    print(f"  MAC: {iface.get('mac', 'N/A')}")
    print(f"  Status: {iface.get('status', 'unknown')}")
```

### Get Default Interface

```python
from netguard.core.interfaces import get_default_interface

# Get default interface
default_iface = get_default_interface()
print(f"Default interface: {default_iface}")
```

### Check Interface Status

```python
from netguard.core.interfaces import is_interface_up

# Check if interface is up
if is_interface_up("eth0"):
    print("Interface is up")
else:
    print("Interface is down")
```

## See Also

- [PacketCapture API](packet-capture.md)
- [Getting Started Guide](../getting-started.md)

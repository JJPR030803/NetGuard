# SnifferConfig API Reference

Configuration management for the sniffer module.

## Module Reference

::: network_security_suite.sniffer.sniffer_config
    options:
      show_source: true
      show_root_heading: true
      heading_level: 2

## Usage Examples

### Load Configuration from YAML

```python
from network_security_suite.sniffer.sniffer_config import SnifferConfig

# Load from YAML file
config = SnifferConfig.from_yaml("config.yaml")

# Use configuration
print(f"Interface: {config.interface}")
print(f"Packet count: {config.packet_count}")
print(f"Filter: {config.filter_str}")
```

### Create Configuration Programmatically

```python
from network_security_suite.sniffer.sniffer_config import SnifferConfig

# Create configuration
config = SnifferConfig(
    interface="eth0",
    packet_count=1000,
    timeout=60,
    filter_str="tcp port 80"
)

# Save to YAML
config.to_yaml("config.yaml")
```

### Validate Configuration

```python
config = SnifferConfig.from_yaml("config.yaml")

try:
    config.validate()
    print("Configuration is valid")
except ValueError as e:
    print(f"Invalid configuration: {e}")
```

## See Also

- [Configuration Guide](../configuration.md)
- [PacketCapture API](packet-capture.md)

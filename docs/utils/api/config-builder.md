# Config Builder API Reference

Complete API reference for the configuration management utilities.

## Module Reference

::: network_security_suite.utils.config_builder
    options:
      show_source: true
      show_root_heading: true
      heading_level: 2

## Usage Examples

### Load Configuration

```python
from network_security_suite.utils import ConfigBuilder

# From YAML file
config = ConfigBuilder.from_yaml("config.yaml")

# Access values
value = config.get("section.key")
value_with_default = config.get("section.key", default="default_value")
```

### Environment Variables

```python
# Load with environment variable support
config = ConfigBuilder.from_yaml(
    "config.yaml",
    env_prefix="NETGUARD_"
)

# NETGUARD_DATABASE_HOST environment variable
# overrides database.host in config.yaml
host = config.get("database.host")
```

### Update Configuration

```python
config = ConfigBuilder.from_yaml("config.yaml")

# Update value
config.set("sniffer.interface", "wlan0")

# Save to file
config.to_yaml("config_updated.yaml")
```

### Merge Configurations

```python
base = ConfigBuilder.from_yaml("base.yaml")
override = ConfigBuilder.from_yaml("override.yaml")

# Merge (override takes precedence)
config = base.merge(override)
```

## See Also

- [Configuration Guide](../configuration.md)
- [Logger API](logger.md)
- [Getting Started](../logging.md)

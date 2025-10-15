# Configuration Management Guide

Guide to configuration management in the Network Security Suite.

## Overview

The configuration system provides a flexible way to manage application settings using YAML files, environment variables, and programmatic configuration.

## Basic Usage

### Loading Configuration

```python
from network_security_suite.utils import ConfigBuilder

# Load from YAML file
config = ConfigBuilder.from_yaml("config.yaml")

# Access values
interface = config.get("sniffer.interface")
packet_count = config.get("sniffer.packet_count")
```

### With Default Values

```python
# Get value with default
interface = config.get("sniffer.interface", default="eth0")
timeout = config.get("sniffer.timeout", default=60)
```

### Environment Variables

```python
# Load with environment variable support
config = ConfigBuilder.from_yaml(
    "config.yaml",
    env_prefix="NETGUARD_"
)

# Environment variables override YAML values
# NETGUARD_SNIFFER_INTERFACE=wlan0 overrides config.yaml
```

## Configuration File Format

### Basic Structure

```yaml
# config.yaml
app:
  name: "Network Security Suite"
  version: "1.0.0"
  debug: false

sniffer:
  interface: "eth0"
  packet_count: 1000
  timeout: 60
  filter: "tcp port 80"

  output:
    directory: "./captures"
    format: "parquet"

  logging:
    level: "INFO"
    file: "./logs/sniffer.log"

ml:
  models_path: "./models"
  threshold: 0.8

database:
  host: "localhost"
  port: 5432
  name: "netguard"
  user: "admin"
```

### Environment-Specific Config

```yaml
# config.yaml
defaults: &defaults
  app:
    name: "Network Security Suite"

  database:
    port: 5432

development:
  <<: *defaults
  app:
    debug: true
  database:
    host: "localhost"
    name: "netguard_dev"

production:
  <<: *defaults
  app:
    debug: false
  database:
    host: "db.example.com"
    name: "netguard_prod"
```

Load environment-specific config:

```python
import os

env = os.getenv("ENV", "development")
config = ConfigBuilder.from_yaml(f"config.yaml", section=env)
```

## Advanced Features

### Nested Configuration

```python
# Access nested values
db_host = config.get("database.host")
log_file = config.get("sniffer.logging.file")

# Or use dict-style access
db_config = config.get("database")
host = db_config["host"]
port = db_config["port"]
```

### Validation

```python
from network_security_suite.utils import ConfigBuilder

class AppConfig(ConfigBuilder):
    def validate(self):
        # Validate required fields
        required = ["sniffer.interface", "database.host"]
        for field in required:
            if not self.get(field):
                raise ValueError(f"Missing required config: {field}")

        # Validate types
        packet_count = self.get("sniffer.packet_count")
        if not isinstance(packet_count, int):
            raise TypeError("packet_count must be integer")

        # Validate ranges
        if packet_count < 0:
            raise ValueError("packet_count must be positive")

config = AppConfig.from_yaml("config.yaml")
config.validate()
```

### Dynamic Updates

```python
# Update configuration at runtime
config.set("sniffer.interface", "wlan0")
config.set("sniffer.packet_count", 2000)

# Save updated configuration
config.to_yaml("config_updated.yaml")
```

### Configuration Merging

```python
# Merge multiple configurations
base_config = ConfigBuilder.from_yaml("config.base.yaml")
env_config = ConfigBuilder.from_yaml("config.prod.yaml")

# Merge (env_config overrides base_config)
config = base_config.merge(env_config)
```

## Environment Variables

### Variable Mapping

```yaml
# config.yaml
database:
  host: "localhost"
  port: 5432
```

Environment variables (with prefix `NETGUARD_`):
```bash
export NETGUARD_DATABASE_HOST=db.example.com
export NETGUARD_DATABASE_PORT=3306
```

Load configuration:
```python
config = ConfigBuilder.from_yaml(
    "config.yaml",
    env_prefix="NETGUARD_"
)

# Values from environment variables take precedence
print(config.get("database.host"))  # "db.example.com"
```

### Type Conversion

```python
# Automatic type conversion from environment variables
# NETGUARD_SNIFFER_PACKET_COUNT=1000 (string)
packet_count = config.get("sniffer.packet_count")  # 1000 (int)

# NETGUARD_APP_DEBUG=true (string)
debug = config.get("app.debug")  # True (bool)
```

## Best Practices

### 1. Separate Configs by Environment

```
config/
├── base.yaml           # Common configuration
├── development.yaml    # Development overrides
├── testing.yaml        # Testing configuration
└── production.yaml     # Production configuration
```

### 2. Don't Commit Secrets

```yaml
# config.yaml - Committed to git
database:
  host: "${DB_HOST}"
  port: 5432
  name: "netguard"

# secrets.yaml - NOT committed (in .gitignore)
database:
  user: "admin"
  password: "secret123"
```

### 3. Use Type Hints

```python
from typing import Dict, Any

def get_db_config(config: ConfigBuilder) -> Dict[str, Any]:
    return {
        "host": config.get("database.host"),
        "port": config.get("database.port", default=5432),
        "name": config.get("database.name"),
    }
```

### 4. Validate Early

```python
# At application startup
config = ConfigBuilder.from_yaml("config.yaml")

try:
    config.validate()
except ValueError as e:
    logger.error(f"Invalid configuration: {e}")
    sys.exit(1)
```

## Examples

### Application Configuration

```python
from network_security_suite.utils import ConfigBuilder

class ApplicationConfig:
    def __init__(self, config_file: str):
        self.config = ConfigBuilder.from_yaml(
            config_file,
            env_prefix="NETGUARD_"
        )
        self.validate()

    def validate(self):
        # Validate configuration
        required = ["sniffer.interface", "database.host"]
        for field in required:
            if not self.config.get(field):
                raise ValueError(f"Missing: {field}")

    @property
    def sniffer_config(self):
        return self.config.get("sniffer")

    @property
    def database_config(self):
        return self.config.get("database")

# Use in application
app_config = ApplicationConfig("config.yaml")
sniffer = PacketCapture(**app_config.sniffer_config)
```

### Feature Flags

```yaml
# config.yaml
features:
  ml_analysis: true
  real_time_alerts: false
  packet_logging: true
```

```python
config = ConfigBuilder.from_yaml("config.yaml")

if config.get("features.ml_analysis"):
    enable_ml_analysis()

if config.get("features.real_time_alerts"):
    enable_alerts()
```

## See Also

- [Logging Guide](logging.md)
- [Performance Metrics Guide](performance-metrics.md)
- [Config Builder API Reference](api/config-builder.md)

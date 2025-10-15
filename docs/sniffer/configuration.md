# Sniffer Configuration

This guide covers all configuration options for the packet capture module.

## Configuration Methods

### 1. Direct Configuration

Pass configuration directly to PacketCapture:

```python
from network_security_suite.sniffer import PacketCapture

capture = PacketCapture(
    interface="eth0",
    packet_count=1000,
    timeout=60,
    promisc=True,
    filter_str="tcp",
    output_file="capture.parquet"
)
```

### 2. YAML Configuration

Use a YAML configuration file:

```yaml
# config.yaml
sniffer:
  interface: eth0
  packet_count: 1000
  timeout: 60
  promisc_mode: true
  filter: "tcp port 80"

  output:
    directory: ./captures
    filename_pattern: "capture_{timestamp}.parquet"
    rotation: daily

  logging:
    level: INFO
    handlers:
      - type: console
        level: INFO
      - type: file
        level: DEBUG
        path: ./logs/sniffer.log
```

Load configuration:

```python
from network_security_suite.sniffer.sniffer_config import SnifferConfig

config = SnifferConfig.from_yaml("config.yaml")
capture = PacketCapture.from_config(config)
```

## Configuration Options

### Interface Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `interface` | str | None | Network interface to capture from |
| `promisc` | bool | True | Enable promiscuous mode |
| `monitor_mode` | bool | False | Enable monitor mode (wireless) |

```python
capture = PacketCapture(
    interface="wlan0",
    promisc=True,
    monitor_mode=True  # For wireless sniffing
)
```

### Capture Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `packet_count` | int | 0 | Number of packets to capture (0 = unlimited) |
| `timeout` | int | None | Capture timeout in seconds |
| `buffer_size` | int | 65536 | Packet buffer size in bytes |
| `snaplen` | int | 65535 | Maximum bytes to capture per packet |

```python
capture = PacketCapture(
    interface="eth0",
    packet_count=10000,
    timeout=300,  # 5 minutes
    buffer_size=131072,  # 128KB
    snaplen=1500  # Capture only headers
)
```

### Filter Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `filter_str` | str | "" | BPF filter string |
| `filter_optimize` | bool | True | Optimize BPF filter |

```python
capture = PacketCapture(
    interface="eth0",
    filter_str="tcp port 443 and host 192.168.1.100",
    filter_optimize=True
)
```

### Output Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `output_file` | str | None | Output Parquet file path |
| `output_dir` | str | "./captures" | Output directory |
| `compression` | str | "snappy" | Parquet compression (snappy, gzip, none) |
| `batch_size` | int | 1000 | Packets per batch write |

```python
capture = PacketCapture(
    interface="eth0",
    output_file="capture.parquet",
    compression="gzip",
    batch_size=5000
)
```

### Logging Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `log_level` | str | "INFO" | Logging level |
| `log_file` | str | None | Log file path |
| `log_rotation` | str | None | Log rotation (daily, weekly) |

```python
from network_security_suite.sniffer import PacketCapture, FileLogger

logger = FileLogger(
    filename="sniffer.log",
    level="DEBUG",
    rotation="daily"
)

capture = PacketCapture(
    interface="eth0",
    loggers=[logger]
)
```

## Complete YAML Configuration Example

```yaml
# sniffer_config.yaml
sniffer:
  # Interface configuration
  interface: eth0
  promisc_mode: true
  monitor_mode: false

  # Capture settings
  packet_count: 0  # Unlimited
  timeout: null
  buffer_size: 131072  # 128KB
  snaplen: 65535

  # Filter configuration
  filters:
    protocol: tcp
    ports: [80, 443, 8080]
    ips:
      - 192.168.1.0/24
      - 10.0.0.0/8
    exclude:
      - broadcast
      - multicast

  # Output configuration
  output:
    directory: ./captures
    filename_pattern: "capture_{date}_{time}.parquet"
    compression: snappy
    batch_size: 1000
    rotation:
      enabled: true
      interval: hourly
      max_size: 1GB
      max_files: 10

  # Logging configuration
  logging:
    level: INFO
    format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    handlers:
      console:
        enabled: true
        level: INFO
        colored: true

      file:
        enabled: true
        level: DEBUG
        path: ./logs/sniffer.log
        rotation: daily
        max_size: 100MB
        backup_count: 7

      security:
        enabled: true
        level: WARNING
        path: ./logs/security.log
        rotation: daily

      packet:
        enabled: true
        level: DEBUG
        path: ./logs/packets.log
        rotation: hourly
        max_size: 500MB

  # Performance settings
  performance:
    buffer_timeout: 100  # ms
    batch_processing: true
    parallel_processing: false
    worker_threads: 4

  # Security settings
  security:
    detect_anomalies: true
    alert_on_suspicious: true
    rate_limit: 10000  # packets/sec
    blacklist:
      - 192.168.1.666
    whitelist:
      - 192.168.1.1
```

## Environment-Specific Configurations

### Development

```yaml
# config.dev.yaml
sniffer:
  interface: lo  # Loopback for testing
  packet_count: 100
  timeout: 10

  logging:
    level: DEBUG
    handlers:
      console:
        enabled: true
        level: DEBUG
```

### Production

```yaml
# config.prod.yaml
sniffer:
  interface: eth0
  packet_count: 0
  promisc_mode: true

  output:
    directory: /var/log/netguard/captures
    rotation:
      enabled: true
      interval: hourly

  logging:
    level: WARNING
    handlers:
      file:
        enabled: true
        path: /var/log/netguard/sniffer.log
        rotation: daily
```

### Testing

```yaml
# config.test.yaml
sniffer:
  interface: any
  packet_count: 50
  timeout: 5

  output:
    directory: ./test_captures

  logging:
    level: ERROR
```

## Dynamic Configuration

Update configuration at runtime:

```python
from network_security_suite.sniffer import PacketCapture

# Start with initial config
capture = PacketCapture(interface="eth0")

# Update filter
capture.set_filter("tcp port 443")

# Update output
capture.set_output_file("new_capture.parquet")

# Update buffer size
capture.set_buffer_size(262144)
```

## Configuration Validation

```python
from network_security_suite.sniffer.sniffer_config import SnifferConfig

try:
    config = SnifferConfig.from_yaml("config.yaml")
    config.validate()
except ValueError as e:
    print(f"Configuration error: {e}")
```

## Best Practices

### 1. Use Configuration Files

For production environments, always use configuration files:
- Easier to maintain
- Version controlled
- Environment-specific configs
- No hardcoded values

### 2. Optimize Buffer Sizes

```python
# For high-traffic environments
capture = PacketCapture(
    interface="eth0",
    buffer_size=524288,  # 512KB
    batch_size=5000
)

# For low-traffic environments
capture = PacketCapture(
    interface="eth0",
    buffer_size=65536,   # 64KB
    batch_size=1000
)
```

### 3. Use Appropriate Filters

```python
# Good: Specific filter
filter_str = "tcp port 443 and src net 192.168.1.0/24"

# Bad: Too broad
filter_str = "ip"  # Captures everything
```

### 4. Configure Rotation

```yaml
output:
  rotation:
    enabled: true
    interval: hourly  # Rotate every hour
    max_size: 1GB     # Rotate at 1GB
    max_files: 24     # Keep last 24 files
```

### 5. Separate Log Levels

```yaml
logging:
  handlers:
    console:
      level: INFO  # Less verbose for console
    file:
      level: DEBUG  # More verbose for file
    security:
      level: WARNING  # Only important security events
```

## Troubleshooting

### Configuration Not Loading

```python
import logging
logging.basicConfig(level=logging.DEBUG)

config = SnifferConfig.from_yaml("config.yaml")  # Will show debug info
```

### Invalid Filter String

```python
from network_security_suite.sniffer import PacketCapture

try:
    capture = PacketCapture(
        interface="eth0",
        filter_str="invalid filter"
    )
except ValueError as e:
    print(f"Invalid filter: {e}")
```

### Permission Issues

```bash
# Check file permissions
ls -l config.yaml

# Fix if needed
chmod 644 config.yaml
```

## Next Steps

- Learn about [packet filtering](packet-filtering.md)
- See [API reference](api/sniffer-config.md) for all configuration options
- Check [examples](examples/advanced-filtering.md) for more configurations

# Logging Guide

Comprehensive guide to the logging system in the Network Security Suite.

## Overview

The logging system provides flexible, configurable logging with support for multiple handlers, formatters, and log levels.

## Basic Usage

### Getting a Logger

```python
from network_security_suite.utils import get_logger

# Get logger for current module
logger = get_logger(__name__)

# Log messages
logger.debug("Debug information")
logger.info("General information")
logger.warning("Warning message")
logger.error("Error occurred")
logger.critical("Critical issue")
```

### Log Levels

| Level | Numeric Value | When to Use |
|-------|---------------|-------------|
| DEBUG | 10 | Detailed diagnostic information |
| INFO | 20 | General informational messages |
| WARNING | 30 | Warning messages |
| ERROR | 40 | Error messages |
| CRITICAL | 50 | Critical errors |

## Configuration

### Setup Logging

```python
from network_security_suite.utils import setup_logging

# Basic setup
setup_logging(level="INFO")

# With file output
setup_logging(
    level="DEBUG",
    log_file="app.log"
)

# With colored console output
setup_logging(
    level="INFO",
    console=True,
    colored=True
)

# Complete configuration
setup_logging(
    level="DEBUG",
    log_file="app.log",
    console=True,
    colored=True,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
```

### YAML Configuration

```yaml
# logging.yaml
logging:
  version: 1
  disable_existing_loggers: false

  formatters:
    standard:
      format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    detailed:
      format: "%(asctime)s - %(name)s - %(levelname)s - %(pathname)s:%(lineno)d - %(message)s"

  handlers:
    console:
      class: logging.StreamHandler
      level: INFO
      formatter: standard
      stream: ext://sys.stdout

    file:
      class: logging.handlers.RotatingFileHandler
      level: DEBUG
      formatter: detailed
      filename: app.log
      maxBytes: 10485760  # 10MB
      backupCount: 5

  loggers:
    network_security_suite:
      level: DEBUG
      handlers: [console, file]
      propagate: false

  root:
    level: INFO
    handlers: [console]
```

Load configuration:

```python
import logging.config
import yaml

with open("logging.yaml") as f:
    config = yaml.safe_load(f)
    logging.config.dictConfig(config)
```

## Advanced Features

### Structured Logging

```python
logger = get_logger(__name__)

# Add extra context
logger.info("Packet captured", extra={
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.1",
    "protocol": "TCP",
    "size": 1500
})
```

### Custom Formatters

```python
import logging

class CustomFormatter(logging.Formatter):
    def format(self, record):
        # Add custom formatting
        record.custom_field = "value"
        return super().format(record)

# Use custom formatter
handler = logging.FileHandler("app.log")
handler.setFormatter(CustomFormatter())
logger.addHandler(handler)
```

### Rotating File Handler

```python
from logging.handlers import RotatingFileHandler

# Rotate by size
handler = RotatingFileHandler(
    "app.log",
    maxBytes=10485760,  # 10MB
    backupCount=5
)
logger.addHandler(handler)
```

### Timed Rotating Handler

```python
from logging.handlers import TimedRotatingFileHandler

# Rotate daily
handler = TimedRotatingFileHandler(
    "app.log",
    when="D",  # Daily
    interval=1,
    backupCount=7  # Keep 7 days
)
logger.addHandler(handler)
```

## Best Practices

### 1. Use Appropriate Log Levels

```python
# DEBUG: Detailed information for diagnosing problems
logger.debug(f"Processing packet {packet_id}")

# INFO: General informational messages
logger.info("Application started successfully")

# WARNING: Indicate something unexpected happened
logger.warning("High packet drop rate detected")

# ERROR: A serious problem occurred
logger.error("Failed to connect to database")

# CRITICAL: A very serious error
logger.critical("System out of memory")
```

### 2. Include Context

```python
# Good: Include relevant context
logger.error("Failed to process packet", extra={
    "packet_id": packet_id,
    "error": str(e),
    "timestamp": timestamp
})

# Less ideal: Generic message
logger.error("Error occurred")
```

### 3. Use Lazy Formatting

```python
# Good: Lazy evaluation
logger.debug("Packet: %s", packet)

# Less efficient: Eager evaluation
logger.debug(f"Packet: {packet}")
```

### 4. Don't Log Sensitive Data

```python
# Bad: Logging sensitive data
logger.info(f"User password: {password}")

# Good: Redact sensitive data
logger.info(f"User authenticated: {username}")
```

## Examples

### Module-Level Logger

```python
# my_module.py
from network_security_suite.utils import get_logger

logger = get_logger(__name__)

def process_data():
    logger.info("Starting data processing")
    try:
        # Process data
        result = do_work()
        logger.info("Data processed successfully")
        return result
    except Exception as e:
        logger.error(f"Processing failed: {e}")
        raise
```

### Performance Logging

```python
import time

logger = get_logger(__name__)

def time_operation(func):
    def wrapper(*args, **kwargs):
        start = time.time()
        logger.debug(f"Starting {func.__name__}")

        result = func(*args, **kwargs)

        duration = time.time() - start
        logger.info(f"{func.__name__} completed in {duration:.2f}s")

        return result
    return wrapper

@time_operation
def process_packets(packets):
    # Process packets
    pass
```

### Error Logging with Traceback

```python
import traceback

logger = get_logger(__name__)

try:
    risky_operation()
except Exception as e:
    logger.error(
        f"Operation failed: {e}",
        extra={"traceback": traceback.format_exc()}
    )
    # Or use logger.exception
    logger.exception("Operation failed")
```

## Troubleshooting

### Logs Not Appearing

Check log level configuration:

```python
import logging

# Set root logger level
logging.getLogger().setLevel(logging.DEBUG)

# Set specific logger level
logging.getLogger("network_security_suite").setLevel(logging.DEBUG)
```

### Multiple Log Entries

Disable propagation:

```python
logger.propagate = False
```

### Log File Not Created

Check file permissions and path:

```python
import os

log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)

logger = setup_logging(log_file=f"{log_dir}/app.log")
```

## See Also

- [Performance Metrics Guide](performance-metrics.md)
- [Configuration Guide](configuration.md)
- [Logger API Reference](api/logger.md)

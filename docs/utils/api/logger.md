# Logger API Reference

Complete API reference for the logging utilities.

## Module Reference

::: network_security_suite.utils.logger
    options:
      show_source: true
      show_root_heading: true
      heading_level: 2

## Usage Examples

### Basic Logger

```python
from network_security_suite.utils import get_logger

logger = get_logger(__name__)
logger.info("Application started")
logger.warning("High memory usage detected")
logger.error("Failed to connect to database")
```

### Setup Logging

```python
from network_security_suite.utils import setup_logging

# Configure logging for entire application
setup_logging(
    level="DEBUG",
    log_file="app.log",
    console=True,
    colored=True
)
```

### Custom Configuration

```python
from network_security_suite.utils.logger import Logger

logger = Logger(
    name="my_app",
    level="INFO",
    handlers=["console", "file"],
    log_file="my_app.log"
)

logger.info("Custom logger initialized")
```

## See Also

- [Logging Guide](../logging.md)
- [Configuration Guide](../configuration.md)
- [Performance Metrics API](performance-metrics.md)

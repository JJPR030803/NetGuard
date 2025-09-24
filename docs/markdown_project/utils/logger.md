# Logger System

The Network Security Suite includes a flexible and extensible logging system designed to handle various types of logs, from general application logs to specialized security and performance logs.

## Overview

The logging system is built around the abstract `Logger` class, which provides a common interface for all logger implementations. The system includes several specialized logger classes:

- **NetworkSecurityLogger**: For logging security-related events and messages
- **PerformanceLogger**: For logging performance metrics and measurements

Each logger can be configured with different handlers for different types of logs, and can output logs to both the console and files.

## Logger Classes

### Logger (Abstract Base Class)

The `Logger` class is the foundation of the logging system. It provides common functionality for all logger implementations, including:

- Setting up logging handlers
- Configuring log formats
- Managing log directories

This is an abstract class that should be extended by concrete logger implementations.

### NetworkSecurityLogger

The `NetworkSecurityLogger` class is specialized for network security applications. It provides:

- Console logging for general messages
- Error logging to a dedicated error log file
- Security event logging to a dedicated security log file
- Packet logging for detailed network packet information

#### Methods

- `log(message)`: Log an informational message
- `debug(message)`: Log a debug message
- `error(message)`: Log an error message

### PerformanceLogger

The `PerformanceLogger` class is designed to work with the `PerformanceMetrics` utility to log performance data. It:

- Logs all performance metrics at the DEBUG level
- Writes to a dedicated performance log file
- Can be configured to log to console only if needed

## Handler Configuration

The logging system uses a custom `HandlerConfig` class to configure logging handlers. This class:

- Supports both console and file-based logging
- Provides automatic log file rotation when files reach a specified size
- Allows custom formatters for different types of logs

## Usage Examples

### Basic Logging

```python
from src.network_security_suite.utils.logger import NetworkSecurityLogger

# Create a logger
logger = NetworkSecurityLogger()

# Log messages at different levels
logger.log("This is an informational message")
logger.debug("This is a debug message")
logger.error("This is an error message")
```

### Performance Logging

```python
from src.network_security_suite.utils.logger import PerformanceLogger

# Create a performance logger with a custom log directory
logger = PerformanceLogger(log_dir="logs/performance")

# Log performance metrics
logger.log("Memory usage: 125MB")
logger.log("Function execution time: 0.5s")
```

### Custom Logger Implementation

```python
from src.network_security_suite.utils.logger import Logger, HandlerConfig, HandlerTypes
import logging

class CustomLogger(Logger):
    def __init__(self):
        handlers: HandlerTypes = {
            "custom_handler": HandlerConfig(
                "custom",
                logging.INFO,
                logging.Formatter("%(asctime)s [CUSTOM] %(message)s"),
                filepath="logs/custom.log",
            )
        }
        super().__init__(handlers=handlers)
    
    def log(self, message: str) -> None:
        self.logger.info(message)
    
    def save_logs(self, path: str) -> None:
        # Custom implementation if needed
        pass
```

## Log File Locations

By default, log files are stored in the following locations:

- Error logs: `logs/error.log`
- Security logs: `logs/security.log`
- Packet logs: `logs/packets.log`
- Performance logs: `performance.log`

You can customize these locations by providing a `log_dir` parameter when initializing a logger.

## Implementation Status

The logging system is fully implemented and integrated with the rest of the application. It is used throughout the codebase for logging various types of events and messages.

## Potential Improvements

Future improvements to the logging system could include:

1. Adding support for remote logging (e.g., to a centralized logging server)
2. Implementing log filtering based on message content
3. Adding support for structured logging formats like JSON
4. Integrating with monitoring systems for real-time alerting
5. Adding more specialized logger types for different components of the application
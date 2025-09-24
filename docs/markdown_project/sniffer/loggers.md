# Loggers Module

## Overview

The `loggers.py` module provides specialized logger classes for different handler types used in the network security suite's sniffer module. These loggers are designed to capture and store various types of log messages, from debug information to critical errors, in appropriate formats and locations.

The module extends the base Logger class from the network_security_suite.utils.logger module, customizing it for specific logging needs within the sniffer component.

## Classes

### ConsoleLogger

Logger for console output. This logger is designed for displaying log messages in the console with a simple format focused on readability.

#### Methods

##### `__init__(self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None)`

Initialize a new ConsoleLogger instance.

**Parameters:**
- `log_format (Optional[Formatter], optional)`: Custom log formatter. Defaults to None.
- `log_dir (Optional[str], optional)`: Directory to store log files. Defaults to None.

##### `log(self, message: str) -> None`

Log a message at INFO level.

**Parameters:**
- `message (str)`: The message to log.

##### `save_logs(self)`

Save logs to a file. Console logs are not saved to a file.

### SecurityLogger

Logger for security-related events. This logger captures security-related events and warnings, storing them in a dedicated log file.

#### Methods

##### `__init__(self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None)`

Initialize a new SecurityLogger instance.

**Parameters:**
- `log_format (Optional[Formatter], optional)`: Custom log formatter. Defaults to None.
- `log_dir (Optional[str], optional)`: Directory to store log files. Defaults to None.

##### `log(self, message: str) -> None`

Log a message at WARNING level.

**Parameters:**
- `message (str)`: The message to log.

##### `save_logs(self)`

Save logs to a file. Logs are automatically saved by the handler.

### PacketLogger

Logger for packet-related information. This logger is specialized for logging packet capture and processing information, useful for debugging and analysis.

#### Methods

##### `__init__(self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None)`

Initialize a new PacketLogger instance.

**Parameters:**
- `log_format (Optional[Formatter], optional)`: Custom log formatter. Defaults to None.
- `log_dir (Optional[str], optional)`: Directory to store log files. Defaults to None.

##### `log(self, message: str) -> None`

Log a message at DEBUG level.

**Parameters:**
- `message (str)`: The message to log.

##### `save_logs(self)`

Save logs to a file. Logs are automatically saved by the handler.

### FileLogger

Logger for general file-based logging. This logger writes log messages to a specified file with a standard format.

#### Methods

##### `__init__(self, filepath: str = "logs/general.log", log_format: Optional[Formatter] = None, log_dir: Optional[str] = None)`

Initialize a new FileLogger instance.

**Parameters:**
- `filepath (str, optional)`: Path to the log file. Defaults to "logs/general.log".
- `log_format (Optional[Formatter], optional)`: Custom log formatter. Defaults to None.
- `log_dir (Optional[str], optional)`: Directory to store log files. Defaults to None.

##### `log(self, message: str) -> None`

Log a message at INFO level.

**Parameters:**
- `message (str)`: The message to log.

##### `save_logs(self)`

Save logs to a file. Logs are automatically saved by the handler.

### RotatingFileLogger

Logger with rotating file capability. This logger writes to files that rotate when they reach a certain size, useful for managing log file sizes in long-running applications.

#### Methods

##### `__init__(self, filepath: str = "logs/rotating.log", max_bytes: int = 10485760, backup_count: int = 5, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None)`

Initialize a new RotatingFileLogger instance.

**Parameters:**
- `filepath (str, optional)`: Path to the log file. Defaults to "logs/rotating.log".
- `max_bytes (int, optional)`: Maximum size of the log file in bytes before rotation. Defaults to 10485760 (10MB).
- `backup_count (int, optional)`: Number of backup files to keep. Defaults to 5.
- `log_format (Optional[Formatter], optional)`: Custom log formatter. Defaults to None.
- `log_dir (Optional[str], optional)`: Directory to store log files. Defaults to None.

##### `log(self, message: str) -> None`

Log a message at INFO level.

**Parameters:**
- `message (str)`: The message to log.

##### `save_logs(self)`

Save logs to a file. Logs are automatically saved by the handler.

### TimedRotatingFileLogger

Logger with time-based file rotation. This logger writes to files that rotate at specified time intervals, useful for organizing logs by time periods.

#### Methods

##### `__init__(self, filepath: str = "logs/timed_rotating.log", log_format: Optional[Formatter] = None, log_dir: Optional[str] = None)`

Initialize a new TimedRotatingFileLogger instance.

**Parameters:**
- `filepath (str, optional)`: Path to the log file. Defaults to "logs/timed_rotating.log".
- `log_format (Optional[Formatter], optional)`: Custom log formatter. Defaults to None.
- `log_dir (Optional[str], optional)`: Directory to store log files. Defaults to None.

##### `log(self, message: str) -> None`

Log a message at INFO level.

**Parameters:**
- `message (str)`: The message to log.

##### `save_logs(self)`

Save logs to a file. Logs are automatically saved by the handler.

### ErrorLogger

Logger for error messages. This logger is dedicated to capturing and storing error messages for debugging and troubleshooting.

#### Methods

##### `__init__(self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None)`

Initialize a new ErrorLogger instance.

**Parameters:**
- `log_format (Optional[Formatter], optional)`: Custom log formatter. Defaults to None.
- `log_dir (Optional[str], optional)`: Directory to store log files. Defaults to None.

##### `log(self, message: str) -> None`

Log a message at ERROR level.

**Parameters:**
- `message (str)`: The message to log.

##### `save_logs(self)`

Save logs to a file. Logs are automatically saved by the handler.

### DebugLogger

Logger for debug messages. This logger captures detailed debug information useful during development and troubleshooting.

#### Methods

##### `__init__(self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None)`

Initialize a new DebugLogger instance.

**Parameters:**
- `log_format (Optional[Formatter], optional)`: Custom log formatter. Defaults to None.
- `log_dir (Optional[str], optional)`: Directory to store log files. Defaults to None.

##### `log(self, message: str) -> None`

Log a message at DEBUG level.

**Parameters:**
- `message (str)`: The message to log.

##### `save_logs(self)`

Save logs to a file. Logs are automatically saved by the handler.

### CriticalLogger

Logger for critical messages. This logger captures critical issues that require immediate attention.

#### Methods

##### `__init__(self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None)`

Initialize a new CriticalLogger instance.

**Parameters:**
- `log_format (Optional[Formatter], optional)`: Custom log formatter. Defaults to None.
- `log_dir (Optional[str], optional)`: Directory to store log files. Defaults to None.

##### `log(self, message: str) -> None`

Log a message at CRITICAL level.

**Parameters:**
- `message (str)`: The message to log.

##### `save_logs(self)`

Save logs to a file. Logs are automatically saved by the handler.

### WarningLogger

Logger for warning messages. This logger captures warning messages that indicate potential issues.

#### Methods

##### `__init__(self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None)`

Initialize a new WarningLogger instance.

**Parameters:**
- `log_format (Optional[Formatter], optional)`: Custom log formatter. Defaults to None.
- `log_dir (Optional[str], optional)`: Directory to store log files. Defaults to None.

##### `log(self, message: str) -> None`

Log a message at WARNING level.

**Parameters:**
- `message (str)`: The message to log.

##### `save_logs(self)`

Save logs to a file. Logs are automatically saved by the handler.

### InfoLogger

Logger for informational messages. This logger captures general informational messages about system operation.

#### Methods

##### `__init__(self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None)`

Initialize a new InfoLogger instance.

**Parameters:**
- `log_format (Optional[Formatter], optional)`: Custom log formatter. Defaults to None.
- `log_dir (Optional[str], optional)`: Directory to store log files. Defaults to None.

##### `log(self, message: str) -> None`

Log a message at INFO level.

**Parameters:**
- `message (str)`: The message to log.

##### `save_logs(self)`

Save logs to a file. Logs are automatically saved by the handler.

## Usage Example

```python
from network_security_suite.sniffer.loggers import (
    InfoLogger, 
    ErrorLogger, 
    DebugLogger, 
    PacketLogger
)

# Initialize loggers
info_logger = InfoLogger(log_dir="/path/to/logs")
error_logger = ErrorLogger(log_dir="/path/to/logs")
debug_logger = DebugLogger(log_dir="/path/to/logs")
packet_logger = PacketLogger(log_dir="/path/to/logs")

# Log messages at different levels
info_logger.log("Application started successfully")
debug_logger.log("Initializing network interface eth0")
packet_logger.log("Captured packet with ID: 12345")

# Log an error
try:
    # Some operation that might fail
    result = perform_risky_operation()
except Exception as e:
    error_logger.log(f"Operation failed: {str(e)}")
```

## Dependencies

- `logging`: Python's built-in logging module
- `network_security_suite.utils.logger`: Base Logger class and handler configurations

## Notes

- Each logger class is specialized for a specific type of log message, with appropriate log levels and formatters.
- Log files are automatically created and managed by the handlers.
- The module supports various logging strategies including console output, file-based logging, and rotating logs.
- Custom log formatters can be provided to change the format of log messages.
- A custom log directory can be specified to change where log files are stored.
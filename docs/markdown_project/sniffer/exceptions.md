# Exceptions Module

## Overview

The `exceptions.py` module provides a comprehensive set of exception classes for the sniffer module. These exceptions help in identifying and handling specific error scenarios that may occur during network sniffing operations, packet processing, data conversion, and interface management.

The exception hierarchy is organized to provide specific error types for different components of the sniffer module, allowing for more precise error handling and debugging.

## Exception Hierarchy

### SnifferException

Base exception class for all sniffer-related errors. This is the parent class for all exceptions in the sniffer module and provides a common base for catching all sniffer-related exceptions.

#### Attributes

- `message (str)`: Explanation of the error
- `logger (ErrorLogger)`: Logger for error messages

#### Methods

##### `__init__(self, message="An error occurred in the sniffer module")`

Initialize a new SnifferException instance.

**Parameters:**
- `message (str, optional)`: Explanation of the error. Defaults to "An error occurred in the sniffer module".

### InterfaceException

Base exception for interface-related errors. This exception is raised when there's an issue with network interfaces.

#### Attributes

- `interface (str)`: Name of the interface that caused the error
- `message (str)`: Explanation of the error

#### Methods

##### `__init__(self, interface="", message="An interface-related error occurred")`

Initialize a new InterfaceException instance.

**Parameters:**
- `interface (str, optional)`: Name of the interface that caused the error. Defaults to "".
- `message (str, optional)`: Explanation of the error. Defaults to "An interface-related error occurred".

### InterfaceNotFoundError

Exception raised when a specified interface doesn't exist. This exception is raised when trying to use a network interface that doesn't exist on the system.

#### Attributes

- `interface (str)`: Name of the interface that wasn't found

#### Methods

##### `__init__(self, interface="")`

Initialize a new InterfaceNotFoundError instance.

**Parameters:**
- `interface (str, optional)`: Name of the interface that wasn't found. Defaults to "".

### InterfacePermissionError

Exception raised when permissions are insufficient for an interface. This exception is raised when the user doesn't have sufficient permissions to access or use a network interface.

#### Attributes

- `interface (str)`: Name of the interface with permission issues

#### Methods

##### `__init__(self, interface="")`

Initialize a new InterfacePermissionError instance.

**Parameters:**
- `interface (str, optional)`: Name of the interface with permission issues. Defaults to "".

### InterfaceConfigurationError

Exception raised when interface configuration is invalid. This exception is raised when there's an issue with the configuration of a network interface.

#### Attributes

- `interface (str)`: Name of the interface with configuration issues
- `config_issue (str)`: Description of the configuration issue

#### Methods

##### `__init__(self, interface="", config_issue="")`

Initialize a new InterfaceConfigurationError instance.

**Parameters:**
- `interface (str, optional)`: Name of the interface with configuration issues. Defaults to "".
- `config_issue (str, optional)`: Description of the configuration issue. Defaults to "".

### PacketCaptureException

Base exception for packet capture errors. This exception is raised when there's an issue with packet capturing.

#### Attributes

- `message (str)`: Explanation of the error

#### Methods

##### `__init__(self, message="An error occurred during packet capture")`

Initialize a new PacketCaptureException instance.

**Parameters:**
- `message (str, optional)`: Explanation of the error. Defaults to "An error occurred during packet capture".

### PacketProcessingError

Exception raised when processing a packet fails. This exception is raised when there's an error processing a captured packet.

#### Attributes

- `packet_id (str)`: Identifier for the packet that caused the error
- `error_details (str)`: Details about the processing error

#### Methods

##### `__init__(self, packet_id="", error_details="")`

Initialize a new PacketProcessingError instance.

**Parameters:**
- `packet_id (str, optional)`: Identifier for the packet that caused the error. Defaults to "".
- `error_details (str, optional)`: Details about the processing error. Defaults to "".

### CaptureLimitExceededError

Exception raised when capture limits are exceeded. This exception is raised when a capture operation exceeds defined limits such as maximum number of packets or memory usage.

#### Attributes

- `limit_type (str)`: Type of limit that was exceeded (e.g., "packets", "memory")
- `limit_value (int)`: Value of the limit that was exceeded
- `current_value (int)`: Current value that exceeded the limit

#### Methods

##### `__init__(self, limit_type="", limit_value=0, current_value=0)`

Initialize a new CaptureLimitExceededError instance.

**Parameters:**
- `limit_type (str, optional)`: Type of limit that was exceeded. Defaults to "".
- `limit_value (int, optional)`: Value of the limit that was exceeded. Defaults to 0.
- `current_value (int, optional)`: Current value that exceeded the limit. Defaults to 0.

### FilterError

Exception raised when a BPF filter is invalid. This exception is raised when there's an issue with a Berkeley Packet Filter (BPF) used for packet capturing.

#### Attributes

- `filter_expression (str)`: The filter expression that caused the error
- `error_details (str)`: Details about the filter error

#### Methods

##### `__init__(self, filter_expression="", error_details="")`

Initialize a new FilterError instance.

**Parameters:**
- `filter_expression (str, optional)`: The filter expression that caused the error. Defaults to "".
- `error_details (str, optional)`: Details about the filter error. Defaults to "".

### DataProcessingException

Base exception for data processing errors. This exception is raised when there's an issue with processing captured data.

#### Attributes

- `message (str)`: Explanation of the error

#### Methods

##### `__init__(self, message="An error occurred during data processing")`

Initialize a new DataProcessingException instance.

**Parameters:**
- `message (str, optional)`: Explanation of the error. Defaults to "An error occurred during data processing".

### DataConversionError

Exception raised when converting data between formats fails. This exception is raised when there's an error converting data between different formats (e.g., from raw packets to JSON, Pandas, or Polars).

#### Attributes

- `source_format (str)`: Format being converted from
- `target_format (str)`: Format being converted to
- `error_details (str)`: Details about the conversion error

#### Methods

##### `__init__(self, source_format="", target_format="", error_details="")`

Initialize a new DataConversionError instance.

**Parameters:**
- `source_format (str, optional)`: Format being converted from. Defaults to "".
- `target_format (str, optional)`: Format being converted to. Defaults to "".
- `error_details (str, optional)`: Details about the conversion error. Defaults to "".

### DataExportError

Exception raised when exporting data fails. This exception is raised when there's an error exporting data to a file or external system.

#### Attributes

- `export_format (str)`: Format being exported to
- `destination (str)`: Destination of the export
- `error_details (str)`: Details about the export error

#### Methods

##### `__init__(self, export_format="", destination="", error_details="")`

Initialize a new DataExportError instance.

**Parameters:**
- `export_format (str, optional)`: Format being exported to. Defaults to "".
- `destination (str, optional)`: Destination of the export. Defaults to "".
- `error_details (str, optional)`: Details about the export error. Defaults to "".

### DataImportError

Exception raised when importing data fails. This exception is raised when there's an error importing data from a file or external system.

#### Attributes

- `import_format (str)`: Format being imported from
- `source (str)`: Source of the import
- `error_details (str)`: Details about the import error

#### Methods

##### `__init__(self, import_format="", source="", error_details="")`

Initialize a new DataImportError instance.

**Parameters:**
- `import_format (str, optional)`: Format being imported from. Defaults to "".
- `source (str, optional)`: Source of the import. Defaults to "".
- `error_details (str, optional)`: Details about the import error. Defaults to "".

### ConfigurationException

Base exception for configuration errors. This exception is raised when there's an issue with sniffer configuration.

#### Attributes

- `config_name (str)`: Name of the configuration that caused the error
- `message (str)`: Explanation of the error

#### Methods

##### `__init__(self, config_name="", message="A configuration error occurred")`

Initialize a new ConfigurationException instance.

**Parameters:**
- `config_name (str, optional)`: Name of the configuration that caused the error. Defaults to "".
- `message (str, optional)`: Explanation of the error. Defaults to "A configuration error occurred".

### InvalidConfigurationError

Exception raised when configuration is invalid. This exception is raised when a configuration value or setting is invalid.

#### Attributes

- `config_name (str)`: Name of the configuration that is invalid
- `config_value (str)`: Value of the configuration that is invalid
- `reason (str)`: Reason why the configuration is invalid

#### Methods

##### `__init__(self, config_name="", config_value="", reason="")`

Initialize a new InvalidConfigurationError instance.

**Parameters:**
- `config_name (str, optional)`: Name of the configuration that is invalid. Defaults to "".
- `config_value (str, optional)`: Value of the configuration that is invalid. Defaults to "".
- `reason (str, optional)`: Reason why the configuration is invalid. Defaults to "".

### ConfigurationNotFoundError

Exception raised when configuration is not found. This exception is raised when a required configuration setting is missing.

#### Attributes

- `config_name (str)`: Name of the configuration that is missing

#### Methods

##### `__init__(self, config_name="")`

Initialize a new ConfigurationNotFoundError instance.

**Parameters:**
- `config_name (str, optional)`: Name of the configuration that is missing. Defaults to "".

## Usage Example

```python
from network_security_suite.sniffer.exceptions import InterfaceNotFoundError, FilterError, DataConversionError

# Handle interface not found
try:
    # Code that might raise InterfaceNotFoundError
    if not interface_exists("eth0"):
        raise InterfaceNotFoundError("eth0")
except InterfaceNotFoundError as e:
    print(f"Error: {e}")
    # Handle the error appropriately

# Handle invalid filter
try:
    # Code that might raise FilterError
    if not is_valid_filter("tcp and port 80"):
        raise FilterError("tcp and port 80", "Syntax error in filter expression")
except FilterError as e:
    print(f"Error: {e}")
    # Handle the error appropriately

# Handle data conversion error
try:
    # Code that might raise DataConversionError
    try:
        convert_data("raw_packets", "JSON")
    except Exception as inner_e:
        raise DataConversionError("raw_packets", "JSON", str(inner_e))
except DataConversionError as e:
    print(f"Error: {e}")
    # Handle the error appropriately
```

## Dependencies

- `network_security_suite.sniffer.loggers`: For logging error messages

## Notes

- All exceptions in this module inherit from the base `SnifferException` class, allowing for consistent error handling.
- Each exception includes detailed error messages that incorporate relevant context information.
- The exceptions automatically log error messages using the `ErrorLogger` class.
- The hierarchical structure allows for catching specific types of errors or broader categories as needed.
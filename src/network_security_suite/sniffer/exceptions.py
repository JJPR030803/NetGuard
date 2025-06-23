"""
Exception handler for different types of sniffing related exceptions.md.

This module provides a comprehensive set of exception classes for the sniffer module.
These exceptions.md help in identifying and handling specific error scenarios that may
occur during network sniffing operations, packet processing, data conversion, and
interface management.

The exception hierarchy is organized as follows:
- SnifferException: Base exception for all sniffer-related errors
  - InterfaceException: Base for interface-related errors
    - InterfaceNotFoundError: When a specified interface doesn't exist
    - InterfacePermissionError: When permissions are insufficient for an interface
    - InterfaceConfigurationError: When interface configuration is invalid
  - PacketCaptureException: Base for packet capture errors
    - PacketProcessingError: When processing a packet fails
    - CaptureLimitExceededError: When capture limits are exceeded
    - FilterError: When a BPF filter is invalid
  - DataProcessingException: Base for data processing errors
    - DataConversionError: When converting data between formats fails
    - DataExportError: When exporting data fails
    - DataImportError: When importing data fails
  - ConfigurationException: Base for configuration errors
    - InvalidConfigurationError: When configuration is invalid
    - ConfigurationNotFoundError: When configuration is not found
"""

from network_security_suite.sniffer.loggers import ErrorLogger


class SnifferException(Exception):
    """Base exception class for all sniffer-related errors.

    This is the parent class for all exceptions.md in the sniffer module.
    It provides a common base for catching all sniffer-related exceptions.md.

    Attributes:
        message (str): Explanation of the error
        logger (ErrorLogger): Logger for error messages
    """

    def __init__(self, message="An error occurred in the sniffer module"):
        self.message = message
        self.logger = ErrorLogger()
        self.logger.log(f"SnifferException: {self.message}")
        super().__init__(self.message)


# Interface-related exceptions.md
class InterfaceException(SnifferException):
    """Base exception for interface-related errors.

    This exception is raised when there's an issue with network interfaces.

    Attributes:
        interface (str): Name of the interface that caused the error
        message (str): Explanation of the error
    """

    def __init__(self, interface="", message="An interface-related error occurred"):
        self.interface = interface
        message_with_interface = (
            f"{message}" if not interface else f"{message} (Interface: {interface})"
        )
        super().__init__(message_with_interface)


class InterfaceNotFoundError(InterfaceException):
    """Exception raised when a specified interface doesn't exist.

    This exception is raised when trying to use a network interface that
    doesn't exist on the system.

    Attributes:
        interface (str): Name of the interface that wasn't found
    """

    def __init__(self, interface=""):
        super().__init__(interface, "Network interface not found")


class InterfacePermissionError(InterfaceException):
    """Exception raised when permissions are insufficient for an interface.

    This exception is raised when the user doesn't have sufficient permissions
    to access or use a network interface.

    Attributes:
        interface (str): Name of the interface with permission issues
    """

    def __init__(self, interface=""):
        super().__init__(interface, "Insufficient permissions for network interface")


class InterfaceConfigurationError(InterfaceException):
    """Exception raised when interface configuration is invalid.

    This exception is raised when there's an issue with the configuration
    of a network interface.

    Attributes:
        interface (str): Name of the interface with configuration issues
        config_issue (str): Description of the configuration issue
    """

    def __init__(self, interface="", config_issue=""):
        message = "Invalid interface configuration"
        if config_issue:
            message += f": {config_issue}"
        super().__init__(interface, message)


# Packet capture exceptions.md
class PacketCaptureException(SnifferException):
    """Base exception for packet capture errors.

    This exception is raised when there's an issue with packet capturing.

    Attributes:
        message (str): Explanation of the error
    """

    def __init__(self, message="An error occurred during packet capture"):
        super().__init__(message)


class PacketProcessingError(PacketCaptureException):
    """Exception raised when processing a packet fails.

    This exception is raised when there's an error processing a captured packet.

    Attributes:
        packet_id (str): Identifier for the packet that caused the error
        error_details (str): Details about the processing error
    """

    def __init__(self, packet_id="", error_details=""):
        message = "Error processing packet"
        if packet_id:
            message += f" (ID: {packet_id})"
        if error_details:
            message += f": {error_details}"
        super().__init__(message)


class CaptureLimitExceededError(PacketCaptureException):
    """Exception raised when capture limits are exceeded.

    This exception is raised when a capture operation exceeds defined limits
    such as maximum number of packets or memory usage.

    Attributes:
        limit_type (str): Type of limit that was exceeded (e.g., "packets", "memory")
        limit_value (int): Value of the limit that was exceeded
        current_value (int): Current value that exceeded the limit
    """

    def __init__(self, limit_type="", limit_value=0, current_value=0):
        message = "Capture limit exceeded"
        if limit_type:
            message += f" for {limit_type}"
            if limit_value > 0:
                message += f" (limit: {limit_value}"
                if current_value > 0:
                    message += f", current: {current_value}"
                message += ")"
        super().__init__(message)


class FilterError(PacketCaptureException):
    """Exception raised when a BPF filter is invalid.

    This exception is raised when there's an issue with a Berkeley Packet Filter (BPF)
    used for packet capturing.

    Attributes:
        filter_expression (str): The filter expression that caused the error
        error_details (str): Details about the filter error
    """

    def __init__(self, filter_expression="", error_details=""):
        message = "Invalid packet filter"
        if filter_expression:
            message += f" (expression: '{filter_expression}')"
        if error_details:
            message += f": {error_details}"
        super().__init__(message)


# Data processing exceptions.md
class DataProcessingException(SnifferException):
    """Base exception for data processing errors.

    This exception is raised when there's an issue with processing captured data.

    Attributes:
        message (str): Explanation of the error
    """

    def __init__(self, message="An error occurred during data processing"):
        super().__init__(message)


class DataConversionError(DataProcessingException):
    """Exception raised when converting data between formats fails.

    This exception is raised when there's an error converting data between
    different formats (e.g., from raw packets to JSON, Pandas, or Polars).

    Attributes:
        source_format (str): Format being converted from
        target_format (str): Format being converted to
        error_details (str): Details about the conversion error
    """

    def __init__(self, source_format="", target_format="", error_details=""):
        message = "Error converting data"
        if source_format and target_format:
            message += f" from {source_format} to {target_format}"
        if error_details:
            message += f": {error_details}"
        super().__init__(message)


class DataExportError(DataProcessingException):
    """Exception raised when exporting data fails.

    This exception is raised when there's an error exporting data to a file
    or external system.

    Attributes:
        export_format (str): Format being exported to
        destination (str): Destination of the export
        error_details (str): Details about the export error
    """

    def __init__(self, export_format="", destination="", error_details=""):
        message = "Error exporting data"
        if export_format:
            message += f" as {export_format}"
        if destination:
            message += f" to {destination}"
        if error_details:
            message += f": {error_details}"
        super().__init__(message)


class DataImportError(DataProcessingException):
    """Exception raised when importing data fails.

    This exception is raised when there's an error importing data from a file
    or external system.

    Attributes:
        import_format (str): Format being imported from
        source (str): Source of the import
        error_details (str): Details about the import error
    """

    def __init__(self, import_format="", source="", error_details=""):
        message = "Error importing data"
        if import_format:
            message += f" from {import_format}"
        if source:
            message += f" source {source}"
        if error_details:
            message += f": {error_details}"
        super().__init__(message)


# Configuration exceptions.md
class ConfigurationException(SnifferException):
    """Base exception for configuration errors.

    This exception is raised when there's an issue with sniffer configuration.

    Attributes:
        config_name (str): Name of the configuration that caused the error
        message (str): Explanation of the error
    """

    def __init__(self, config_name="", message="A configuration error occurred"):
        self.config_name = config_name
        message_with_config = (
            f"{message}"
            if not config_name
            else f"{message} (Configuration: {config_name})"
        )
        super().__init__(message_with_config)


class InvalidConfigurationError(ConfigurationException):
    """Exception raised when configuration is invalid.

    This exception is raised when a configuration value or setting is invalid.

    Attributes:
        config_name (str): Name of the configuration that is invalid
        config_value (str): Value of the configuration that is invalid
        reason (str): Reason why the configuration is invalid
    """

    def __init__(self, config_name="", config_value="", reason=""):
        message = "Invalid configuration"
        if config_value:
            message += f" value: {config_value}"
        if reason:
            message += f" - {reason}"
        super().__init__(config_name, message)


class ConfigurationNotFoundError(ConfigurationException):
    """Exception raised when configuration is not found.

    This exception is raised when a required configuration setting is missing.

    Attributes:
        config_name (str): Name of the configuration that is missing
    """

    def __init__(self, config_name=""):
        super().__init__(config_name, "Configuration not found")

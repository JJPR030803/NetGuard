"""
Tests for the sniffer exceptions.md module.

This module contains tests for the exception classes defined in the
network_security_suite.sniffer.exceptions.md module.
"""

import unittest

from netguard.core.exceptions import (
    CaptureLimitExceededError,
    ConfigurationError,
    ConfigurationNotFoundError,
    DataConversionError,
    DataExportError,
    DataImportError,
    DataProcessingError,
    FilterError,
    InterfaceConfigurationError,
    InterfaceError,
    InterfaceNotFoundError,
    InterfacePermissionError,
    InvalidConfigurationError,
    PacketCaptureError,
    PacketProcessingError,
    SnifferError,
)


class TestSnifferExceptions(unittest.TestCase):
    """Test cases for sniffer exceptions.md."""

    def test_base_exception(self):
        """Test the base SnifferException class."""
        # Test with default message
        exception = SnifferError()
        self.assertEqual(str(exception), "An error occurred in the sniffer module")

        # Test with custom message
        custom_msg = "Custom error message"
        exception = SnifferError(custom_msg)
        self.assertEqual(str(exception), custom_msg)

    def test_interface_exceptions(self):
        """Test interface-related exception classes."""
        # Test InterfaceException
        exception = InterfaceError()
        self.assertEqual(str(exception), "An interface-related error occurred")

        exception = InterfaceError("eth0")
        self.assertEqual(str(exception), "An interface-related error occurred (Interface: eth0)")

        # Test InterfaceNotFoundError
        exception = InterfaceNotFoundError("wlan0")
        self.assertEqual(str(exception), "Network interface not found (Interface: wlan0)")

        # Test InterfacePermissionError
        exception = InterfacePermissionError("eth1")
        self.assertEqual(
            str(exception),
            "Insufficient permissions for network interface (Interface: eth1)",
        )

        # Test InterfaceConfigurationError
        exception = InterfaceConfigurationError("eth2", "Invalid MTU")
        self.assertEqual(
            str(exception),
            "Invalid interface configuration: Invalid MTU (Interface: eth2)",
        )

    def test_packet_capture_exceptions(self):
        """Test packet capture-related exception classes."""
        # Test PacketCaptureException
        exception = PacketCaptureError()
        self.assertEqual(str(exception), "An error occurred during packet capture")

        # Test PacketProcessingError
        exception = PacketProcessingError("12345", "Invalid packet format")
        self.assertEqual(
            str(exception), "Error processing packet (ID: 12345): Invalid packet format"
        )

        # Test CaptureLimitExceededError
        exception = CaptureLimitExceededError("packets", 1000, 1001)
        self.assertEqual(
            str(exception),
            "Capture limit exceeded for packets (limit: 1000, current: 1001)",
        )

        # Test FilterError
        exception = FilterError("tcp port 80", "Syntax error")
        self.assertEqual(
            str(exception),
            "Invalid packet filter (expression: 'tcp port 80'): Syntax error",
        )

    def test_data_processing_exceptions(self):
        """Test data processing-related exception classes."""
        # Test DataProcessingException
        exception = DataProcessingError()
        self.assertEqual(str(exception), "An error occurred during data processing")

        # Test DataConversionError
        exception = DataConversionError("raw", "json", "Invalid data format")
        self.assertEqual(
            str(exception),
            "Error converting data from raw to json: Invalid data format",
        )

        # Test DataExportError
        exception = DataExportError("parquet", "/path/to/file.parquet", "Permission denied")
        self.assertEqual(
            str(exception),
            "Error exporting data as parquet to /path/to/file.parquet: Permission denied",
        )

        # Test DataImportError
        exception = DataImportError("csv", "/path/to/file.csv", "File not found")
        self.assertEqual(
            str(exception),
            "Error importing data from csv source /path/to/file.csv: File not found",
        )

    def test_configuration_exceptions(self):
        """Test configuration-related exception classes."""
        # Test ConfigurationException
        exception = ConfigurationError()
        self.assertEqual(str(exception), "A configuration error occurred")

        exception = ConfigurationError("capture_settings")
        self.assertEqual(
            str(exception),
            "A configuration error occurred (Configuration: capture_settings)",
        )

        # Test InvalidConfigurationError
        exception = InvalidConfigurationError("timeout", "abc", "Expected integer")
        self.assertEqual(
            str(exception),
            "Invalid configuration value: abc - Expected integer (Configuration: timeout)",
        )

        # Test ConfigurationNotFoundError
        exception = ConfigurationNotFoundError("interface")
        self.assertEqual(str(exception), "Configuration not found (Configuration: interface)")

    def test_exception_hierarchy(self):
        """Test the exception hierarchy to ensure proper inheritance."""
        # Create instances of each exception type
        sniffer_ex = SnifferError()
        interface_ex = InterfaceError()
        interface_not_found_ex = InterfaceNotFoundError()
        packet_capture_ex = PacketCaptureError()
        data_processing_ex = DataProcessingError()
        config_ex = ConfigurationError()

        # Test that all exceptions.md are instances of SnifferException
        self.assertIsInstance(sniffer_ex, SnifferError)
        self.assertIsInstance(interface_ex, SnifferError)
        self.assertIsInstance(interface_not_found_ex, SnifferError)
        self.assertIsInstance(packet_capture_ex, SnifferError)
        self.assertIsInstance(data_processing_ex, SnifferError)
        self.assertIsInstance(config_ex, SnifferError)

        # Test that specific exceptions.md are instances of their parent classes
        self.assertIsInstance(interface_not_found_ex, InterfaceError)
        self.assertIsInstance(interface_not_found_ex, SnifferError)


if __name__ == "__main__":
    unittest.main()

"""
Examples of using the Network Security Suite with different configuration approaches.

This script demonstrates the different ways to configure and use the Network Security Suite:
1. Using a YAML configuration file
2. Using direct parameters
3. Using modules independently
"""

import os
import time
from pathlib import Path

from src.network_security_suite.sniffer.interfaces import Interface
from src.network_security_suite.sniffer.packet_capture import PacketCapture
from src.network_security_suite.sniffer.parquet_processing import ParquetProcessing
from src.network_security_suite.sniffer.sniffer_config import SnifferConfig
from src.network_security_suite.utils.config_builder import ConfigBuilder


def example_with_yaml_config():
    """Example of using the Network Security Suite with a YAML configuration file."""
    print("\n=== Example: Using YAML Configuration ===")

    # Generate a default configuration file if it doesn't exist
    config_path = os.path.join("configs", "example_config.yaml")
    if not os.path.exists(config_path):
        print(f"Generating default configuration file at {config_path}")
        SnifferConfig.generate_default_config(config_path)

    # Load configuration from YAML file
    config = ConfigBuilder.from_yaml(config_path)
    print(f"Loaded configuration from {config_path}")

    # Use the configuration with different modules
    interface = Interface(config=config)
    print(f"Created Interface with configuration, using interface: {config.interface}")

    # Show available interfaces
    interface.show_available_interfaces()


def example_with_direct_params():
    """Example of using the Network Security Suite with direct parameters."""
    print("\n=== Example: Using Direct Parameters ===")

    # Create a configuration with direct parameters
    config = ConfigBuilder.minimal(
        interface="eth0", log_dir="logs/example", export_dir="logs/example/export"
    )
    print(f"Created minimal configuration with interface: {config.interface}")

    # Use the configuration with different modules
    interface = Interface(config=config)
    print(f"Created Interface with configuration")

    # Or use modules with direct parameters (no config)
    capture = PacketCapture(
        interface="eth0", max_memory_packets=1000, log_dir="logs/example"
    )
    print(f"Created PacketCapture with direct parameters")


def example_modules_independently():
    """Example of using the Network Security Suite modules independently."""
    print("\n=== Example: Using Modules Independently ===")

    # Create and use Interface directly
    interface = Interface(interface="eth0", interface_detection_method="manual")
    print(f"Created Interface directly with interface: eth0")

    # Create and use PacketCapture directly
    capture = PacketCapture(interface="eth0", max_memory_packets=1000)
    print(f"Created PacketCapture directly with interface: eth0")

    # Create and use ParquetProcessing directly
    processor = ParquetProcessing(interface="eth0", log_dir="logs/example")
    print(f"Created ParquetProcessing directly with interface: eth0")


def example_config_builder():
    """Example of using the ConfigBuilder utility class."""
    print("\n=== Example: Using ConfigBuilder ===")

    # Create a default configuration
    default_config = ConfigBuilder.default()
    print(f"Created default configuration with interface: {default_config.interface}")

    # Create a configuration from a dictionary
    config_dict = {
        "interface": "wlan0",
        "packet_count": 500,
        "filter_expression": "tcp",
        "log_dir": "logs/custom",
    }
    dict_config = ConfigBuilder.from_dict(config_dict)
    print(
        f"Created configuration from dictionary with interface: {dict_config.interface}"
    )

    # Create a minimal configuration
    minimal_config = ConfigBuilder.minimal(interface="eth1")
    print(f"Created minimal configuration with interface: {minimal_config.interface}")


if __name__ == "__main__":
    # Create necessary directories
    Path("logs/example").mkdir(parents=True, exist_ok=True)
    Path("logs/example/export").mkdir(parents=True, exist_ok=True)
    Path("configs").mkdir(parents=True, exist_ok=True)

    # Run examples
    example_with_yaml_config()
    example_with_direct_params()
    example_modules_independently()
    example_config_builder()

    print("\nAll examples completed successfully!")

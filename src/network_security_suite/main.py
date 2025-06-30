"""
Network Security Suite Main Module

This module serves as the entry point for the Network Security Suite application.
It supports both YAML-based configuration and direct parameter configuration.
"""

import logging
import os
import time
import argparse
from pathlib import Path
from typing import Optional, Dict, Any

from src.network_security_suite.sniffer.interfaces import Interface
from src.network_security_suite.sniffer.loggers import (
    DebugLogger,
    InfoLogger,
    PacketLogger,
)
from src.network_security_suite.sniffer.packet_capture import PacketCapture
from src.network_security_suite.sniffer.sniffer_config import SnifferConfig
from src.network_security_suite.utils.config_builder import ConfigBuilder

def generate_default_config():
    """Generate a default configuration file if it doesn't exist."""
    config_path = os.path.join("configs", "sniffer_config.yaml")
    if not os.path.exists(config_path):
        print(f"Generating default configuration file at {config_path}")
        SnifferConfig.generate_default_config(config_path)
    return config_path

def run_with_config(config_path: str):
    """Run the application with the specified YAML configuration."""
    # Load configuration from YAML file using ConfigBuilder
    config = ConfigBuilder.from_yaml(config_path)

    # Run with the loaded configuration
    run_with_config_object(config)

def run_with_params(interface: Optional[str] = None, 
                   max_packets: int = 100,
                   filter_expression: str = "",
                   log_dir: Optional[str] = None,
                   export_dir: Optional[str] = None,
                   export_format: str = "parquet",
                   num_threads: int = 4,
                   **kwargs):
    """
    Run the application with direct parameters.

    Args:
        interface (Optional[str], optional): Interface name. If None, auto-detection is used.
        max_packets (int, optional): Maximum number of packets to capture. Defaults to 100.
        filter_expression (str, optional): BPF filter expression. Defaults to "".
        log_dir (Optional[str], optional): Log directory. Defaults to None.
        export_dir (Optional[str], optional): Export directory. Defaults to None.
        export_format (str, optional): Export format (parquet or csv). Defaults to "parquet".
        num_threads (int, optional): Number of processing threads. Defaults to 4.
        **kwargs: Additional configuration parameters.
    """
    # Create configuration dictionary
    config_dict = {
        'packet_count': max_packets,
        'filter_expression': filter_expression,
        'export_format': export_format,
        'num_threads': num_threads,
    }

    # Add optional parameters if provided
    if interface:
        config_dict['interface'] = interface
        config_dict['interface_detection_method'] = 'manual'
    else:
        config_dict['interface_detection_method'] = 'auto'

    if log_dir:
        config_dict['log_dir'] = log_dir
        config_dict['log_to_file'] = True

    if export_dir:
        config_dict['export_dir'] = export_dir

    # Add any additional parameters
    config_dict.update(kwargs)

    # Create configuration object using ConfigBuilder
    config = ConfigBuilder.from_dict(config_dict)

    # Run with the created configuration
    run_with_config_object(config)

def run_with_config_object(config: SnifferConfig):
    """
    Run the application with the specified configuration object.

    Args:
        config (SnifferConfig): Configuration object.
    """
    # Configure root logger
    logging.basicConfig(level=getattr(logging, config.log_level))

    print(f"Using log directory: {config.log_dir}")
    print(f"Log directory exists: {os.path.exists(config.log_dir)}")
    print(
        f"Log directory is writable: {os.access(config.log_dir, os.W_OK) if os.path.exists(config.log_dir) else 'Dir not exist'}"
    )

    # Initialize loggers first
    info_logger = InfoLogger(log_dir=config.log_dir)
    packet_logger = PacketLogger(log_dir=config.log_dir)
    debug_logger = DebugLogger(log_dir=config.log_dir)

    # Test logging
    info_logger.log("Starting network security suite")
    debug_logger.log("Debug logging initialized")
    packet_logger.log("Packet logging system ready")

    # Create Interface instance with configuration
    interface = Interface(config=config)

    # Get interface based on configuration
    if config.interface_detection_method == "auto":
        selected_interface = interface.get_recommended_interface()
        if not selected_interface:
            info_logger.log("No suitable interface found based on preferences")
            raise RuntimeError("No suitable interface available")
    else:
        # Use the configured interface
        selected_interface = config.interface

    info_logger.log(f"Using interface: {selected_interface}")

    # Create PacketCapture instance with configuration
    capture = PacketCapture(config=config, interface=selected_interface)

    # Enable logging in the capture call
    info_logger.log("Starting packet capture")
    capture.capture(
        max_packets=config.packet_count if config.packet_count > 0 else 100,
        bpf_filter=config.filter_expression,
        num_threads=config.num_threads,
        log=True
    )

    # Process captured packets
    info_logger.log("Converting captured packets to DataFrame")
    packets_pl = capture.to_polars_df()

    info_logger.log("Showing capture statistics")
    capture.show_stats()

    # Export data if configured
    if packets_pl is not None and len(packets_pl) > 0:
        export_path = os.path.join(config.export_dir, f"packets_{selected_interface}_{int(time.time())}.{config.export_format}")
        info_logger.log(f"Exporting data to {export_path}")
        if config.export_format == "parquet":
            packets_pl.write_parquet(export_path)
        elif config.export_format == "csv":
            packets_pl.write_csv(export_path)
        else:
            info_logger.log(f"Unsupported export format: {config.export_format}")

def run_modules_individually():
    """
    Example of using modules independently without shared configuration.

    This demonstrates how to use each module directly with its own parameters.
    """
    print("Running modules individually without shared configuration")

    # Create Interface instance directly
    interface = Interface(interface="eth0", interface_detection_method="manual")
    interface.show_available_interfaces()

    # Create PacketCapture instance directly
    capture = PacketCapture(interface="wlo1", max_memory_packets=5000)
    capture.capture(max_packets=100, log=True)
    capture.show_stats()

    # Process captured packets
    packets_pl = capture.to_polars_df()

    # Export data
    if packets_pl is not None and len(packets_pl) > 0:
        export_path = f"packets_direct_{int(time.time())}.parquet"
        print(f"Exporting data to {export_path}")
        packets_pl.write_parquet(export_path)

if __name__ == "__main__":
    run_with_config("/home/batman/Documents/networkguard2/src/network_security_suite/sniffer/test_sniffer_config.yaml")

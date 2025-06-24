"""
Network Security Suite Main Module

This module serves as the entry point for the Network Security Suite application.
It demonstrates how to use the YAML-based configuration system.
"""

import logging
import os
import time
import argparse
from pathlib import Path

from src.network_security_suite.sniffer.interfaces import Interface
from src.network_security_suite.sniffer.loggers import (
    DebugLogger,
    InfoLogger,
    PacketLogger,
)
from src.network_security_suite.sniffer.packet_capture import PacketCapture
from src.network_security_suite.sniffer.sniffer_config import SnifferConfig

def generate_default_config():
    """Generate a default configuration file if it doesn't exist."""
    config_path = os.path.join("configs", "sniffer_config.yaml")
    if not os.path.exists(config_path):
        print(f"Generating default configuration file at {config_path}")
        SnifferConfig.generate_default_config(config_path)
    return config_path

def run_with_config(config_path: str):
    """Run the application with the specified configuration."""
    # Load configuration from YAML file
    config = SnifferConfig.from_yaml(config_path)

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
    info_logger.log("Starting network security suite with YAML configuration")
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
    capture = PacketCapture(
        interface=selected_interface, 
        max_memory_packets=config.max_memory_packets,
        log_dir=config.log_dir
    )

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

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Network Security Suite")
    parser.add_argument("--config", help="Path to configuration file", default=None)
    parser.add_argument("--generate-config", help="Generate default configuration file", action="store_true")
    args = parser.parse_args()

    # Generate default configuration if requested
    if args.generate_config:
        config_path = generate_default_config()
        print(f"Default configuration generated at {config_path}")
        exit(0)

    # Use specified config or generate default if not specified
    config_path = args.config if args.config else generate_default_config()

    # Run the application with the configuration
    run_with_config(config_path)

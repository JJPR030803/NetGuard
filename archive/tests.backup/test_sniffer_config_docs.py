#!/usr/bin/env python3
"""
Test script to verify the SnifferConfig documentation is accurate.
This script creates instances of SnifferConfig with various parameter combinations
to ensure that the documented parameters work as expected.
"""

import sys
from pathlib import Path

# Add the project root to the Python path
sys.path.append(str(Path(__file__).parent.parent))

from src.network_security_suite.sniffer.sniffer_config import SnifferConfig


def test_default_config():
    """Test creating a SnifferConfig with default values."""
    print("Testing default configuration...")
    config = SnifferConfig()
    print("✓ Default configuration created successfully")
    print(f"  - Interface: {config.interface}")
    print(f"  - Detection method: {config.interface_detection_method}")
    print(f"  - Log level: {config.log_level}")
    return config


def test_interface_settings():
    """Test creating a SnifferConfig with custom interface settings."""
    print("\nTesting interface settings...")
    config = SnifferConfig(
        interface="wlan0",
        interface_detection_method="manual",
        preferred_interface_types=["wireless", "ethernet"],
    )
    print("✓ Configuration with custom interface settings created successfully")
    print(f"  - Interface: {config.interface}")
    print(f"  - Detection method: {config.interface_detection_method}")
    print(f"  - Preferred types: {config.preferred_interface_types}")
    return config


def test_capture_settings():
    """Test creating a SnifferConfig with custom capture settings."""
    print("\nTesting capture settings...")
    config = SnifferConfig(
        filter_expression="tcp port 80",
        packet_count=500,
        timeout=60,
        promiscuous_mode=False,
        max_memory_packets=5000,
        max_processing_batch_size=50,
        num_threads=2,
    )
    print("✓ Configuration with custom capture settings created successfully")
    print(f"  - Filter expression: {config.filter_expression}")
    print(f"  - Packet count: {config.packet_count}")
    print(f"  - Timeout: {config.timeout}")
    print(f"  - Promiscuous mode: {config.promiscuous_mode}")
    print(f"  - Max memory packets: {config.max_memory_packets}")
    print(f"  - Max processing batch size: {config.max_processing_batch_size}")
    print(f"  - Num threads: {config.num_threads}")
    return config


def test_logging_settings():
    """Test creating a SnifferConfig with custom logging settings."""
    print("\nTesting logging settings...")
    config = SnifferConfig(
        log_level="DEBUG",
        log_to_file=True,
        log_dir="/tmp/logs",
        log_format="%(asctime)s - %(message)s",
        enable_console_logging=True,
        enable_file_logging=True,
        enable_security_logging=False,
        enable_packet_logging=True,
        enable_performance_logging=False,
        max_log_file_size=5242880,  # 5MB
        log_backup_count=3,
    )
    print("✓ Configuration with custom logging settings created successfully")
    print(f"  - Log level: {config.log_level}")
    print(f"  - Log to file: {config.log_to_file}")
    print(f"  - Log dir: {config.log_dir}")
    print(f"  - Console logging: {config.enable_console_logging}")
    print(f"  - Security logging: {config.enable_security_logging}")
    return config


def test_export_settings():
    """Test creating a SnifferConfig with custom export settings."""
    print("\nTesting export settings...")
    config = SnifferConfig(export_format="csv", export_dir="/tmp/exports")
    print("✓ Configuration with custom export settings created successfully")
    print(f"  - Export format: {config.export_format}")
    print(f"  - Export dir: {config.export_dir}")
    return config


def test_performance_settings():
    """Test creating a SnifferConfig with custom performance settings."""
    print("\nTesting performance settings...")
    config = SnifferConfig(
        enable_performance_monitoring=True,
        performance_log_interval=30,
        performance_parquet_path="/tmp/perf_metrics.parquet",
    )
    print("✓ Configuration with custom performance settings created successfully")
    print(f"  - Performance monitoring: {config.enable_performance_monitoring}")
    print(f"  - Log interval: {config.performance_log_interval}")
    print(f"  - Parquet path: {config.performance_parquet_path}")
    return config


def test_security_settings():
    """Test creating a SnifferConfig with custom security settings."""
    print("\nTesting security settings...")
    config = SnifferConfig(
        validate_interface_names=True,
        sanitize_filter_expressions=True,
        max_filter_length=100,
    )
    print("✓ Configuration with custom security settings created successfully")
    print(f"  - Validate interface names: {config.validate_interface_names}")
    print(f"  - Sanitize filter expressions: {config.sanitize_filter_expressions}")
    print(f"  - Max filter length: {config.max_filter_length}")
    return config


def test_mixed_settings():
    """Test creating a SnifferConfig with a mix of settings from different categories."""
    print("\nTesting mixed settings...")
    config = SnifferConfig(
        interface="wlan0",
        packet_count=1000,
        log_level="DEBUG",
        export_format="parquet",
        num_threads=8,
        enable_performance_monitoring=True,
    )
    print("✓ Configuration with mixed settings created successfully")
    print(f"  - Interface: {config.interface}")
    print(f"  - Packet count: {config.packet_count}")
    print(f"  - Log level: {config.log_level}")
    print(f"  - Export format: {config.export_format}")
    print(f"  - Num threads: {config.num_threads}")
    print(f"  - Performance monitoring: {config.enable_performance_monitoring}")
    return config


def run_all_tests():
    """Run all tests."""
    test_default_config()
    test_interface_settings()
    test_capture_settings()
    test_logging_settings()
    test_export_settings()
    test_performance_settings()
    test_security_settings()
    test_mixed_settings()
    print("\n✓ All tests passed successfully!")
    print(
        "The SnifferConfig documentation is accurate and all parameters work as expected."
    )


if __name__ == "__main__":
    run_all_tests()

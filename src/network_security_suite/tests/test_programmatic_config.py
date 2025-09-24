#!/usr/bin/env python3
"""
Simple test script for programmatic configuration.
"""

from network_security_suite.sniffer.interfaces import Interface
from network_security_suite.sniffer.packet_capture import PacketCapture
from network_security_suite.sniffer.sniffer_config import SnifferConfig


def test_programmatic_config():
    """Test programmatic configuration without YAML."""

    # Create configuration programmatically
    config = SnifferConfig(
        interface_detection_method="auto",
        preferred_interface_types=["ethernet", "wireless"],
        packet_count=50,
        filter_expression="",
        num_threads=2,
        max_memory_packets=1000,
        log_level="INFO",
    )

    print("Configuration created successfully")
    print(f"Detection method: {config.interface_detection_method}")
    print(f"Preferred types: {config.preferred_interface_types}")

    # Test interface detection
    interface_manager = Interface(config=config)
    interface_manager.show_available_interfaces()

    # Get recommended interface
    selected_interface = interface_manager.get_recommended_interface()
    if selected_interface:
        print(f"Selected interface: {selected_interface}")

        # Update config with selected interface
        config.interface = selected_interface

        # Test packet capture
        capture = PacketCapture(config=config)
        print("PacketCapture initialized successfully")

        # You can uncomment this to actually capture packets
        # capture.capture(max_packets=10, log=True)
        # capture.show_stats()

    else:
        print("No suitable interface found")


if __name__ == "__main__":
    test_programmatic_config()

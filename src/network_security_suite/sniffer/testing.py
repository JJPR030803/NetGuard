"""
Testing module for network interface detection and packet capture functionality.

This module provides a simple script to test the Interface and PacketCapture classes
by capturing packets from a wireless interface and converting them to a Polars DataFrame.
"""

import polars as pl

from network_security_suite.sniffer.interfaces import Interface
from network_security_suite.sniffer.packet_capture import PacketCapture

if __name__ == "__main__":
    try:
        # Initialize interface and capture packets
        interface_manager = Interface()
        wireless_interfaces = interface_manager.get_interface_by_type("wireless")
        capture = PacketCapture(interface=wireless_interfaces[0])
        capture.capture(max_packets=10, verbose=True)

        print("\n=== Testing Polars conversion ===")
        pl.Config.set_tbl_cols(-1)
        pl.Config.set_tbl_width_chars(None)
        df = capture.to_polars_df()
        print(df["raw_size"])

    except Exception as e:
        print(f"Error during testing: {e}")

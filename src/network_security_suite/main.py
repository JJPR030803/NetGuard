"""
Testing main
"""
import os
import logging
from pathlib import Path
from src.network_security_suite.sniffer.interfaces import Interface
from src.network_security_suite.sniffer.packet_capture import PacketCapture
from src.network_security_suite.sniffer.loggers import (
    InfoLogger,
    PacketLogger,
    DebugLogger
)

if __name__ == "__main__":
    # Configure root logger
    logging.basicConfig(level=logging.DEBUG)
    
    # Use the same path that the shell script creates
    log_dir = "/home/batman/Documents/networkguard2/logs"
    
    print(f"Using log directory: {log_dir}")
    print(f"Log directory exists: {os.path.exists(log_dir)}")
    print(f"Log directory is writable: {os.access(log_dir, os.W_OK) if os.path.exists(log_dir) else 'Directory does not exist'}")
    
    # Initialize loggers first
    info_logger = InfoLogger(log_dir=log_dir)
    packet_logger = PacketLogger(log_dir=log_dir)
    debug_logger = DebugLogger(log_dir=log_dir)
    
    # Test logging
    info_logger.log("Starting network security suite")
    debug_logger.log("Debug logging initialized")
    packet_logger.log("Packet logging system ready")
    
    # Create Interface instance with logging enabled
    interface = Interface(log_dir=log_dir)
    wireless_interface = interface.get_interface_by_type("wireless")
    
    if not wireless_interface:
        info_logger.log("No wireless interface found")
        raise RuntimeError("No wireless interface available")
    
    info_logger.log(f"Using wireless interface: {wireless_interface[0]}")
    
    # Create PacketCapture instance with logging enabled
    capture = PacketCapture(interface=wireless_interface[0], log_dir=log_dir)
    
    # Enable logging in the capture call
    info_logger.log("Starting packet capture")
    capture.capture(max_packets=100, log=True)
    
    # Process captured packets
    info_logger.log("Converting captured packets to DataFrame")
    packets_pl = capture.to_polars_df()
    
    info_logger.log("Showing capture statistics")
    capture.show_stats()
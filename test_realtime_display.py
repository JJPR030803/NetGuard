#!/usr/bin/env python3
"""
Test script for real-time display functionality.

This script tests the real-time display functionality in both
PacketCapture and ParquetProcessing classes.
"""

import os
import sys
from pathlib import Path

# Add the project root to the Python path
sys.path.append(str(Path(__file__).parent))

from src.network_security_suite.sniffer.sniffer_config import SnifferConfig
from src.network_security_suite.sniffer.packet_capture import PacketCapture
from src.network_security_suite.sniffer.parquet_processing import ParquetProcessing

def test_packet_capture_realtime():
    """Test real-time display in PacketCapture."""
    print("=== Testing PacketCapture Real-time Display ===")
    
    # Create config with real-time display enabled
    config = SnifferConfig(
        interface="wlo1",  # Change to a valid interface on your system
        packet_count=100,
        enable_realtime_display=True
    )
    
    # Create PacketCapture with real-time display enabled
    capture = PacketCapture(config=config)
    
    # Capture packets with real-time display
    print("Starting packet capture with real-time display...")
    capture.capture(max_packets=50)
    
    print("Packet capture completed.")

def test_parquet_processing_realtime():
    """Test real-time display in ParquetProcessing."""
    print("\n=== Testing ParquetProcessing Real-time Display ===")
    
    # Create config with real-time display enabled
    config = SnifferConfig(
        interface="wlo1",  # Change to a valid interface on your system
        packet_count=100,
        enable_realtime_display=True
    )
    
    # Create ParquetProcessing with real-time display enabled
    processor = ParquetProcessing(config=config)
    
    # Create a temporary file path
    filepath = "/tmp/test_realtime_display.parquet"
    
    # Save packets with real-time display
    print(f"Starting packet capture and save to {filepath}...")
    processor.save_packets(filepath=filepath)
    
    print("Packet capture and save completed.")
    
    # Load and analyze the saved packets
    print("\nLoading and analyzing saved packets...")
    df = processor.load_packets(filepath)
    processor.show_dataframe_stats(df)
    processor.analyze_packet_data(df)

if __name__ == "__main__":
    # Test PacketCapture real-time display
    test_packet_capture_realtime()
    
    # Test ParquetProcessing real-time display
    test_parquet_processing_realtime()
"""
Testing module for network interface detection and packet capture functionality.

This module provides a simple script to test the Interface and PacketCapture classes
by capturing packets from a wireless interface, displaying them, and showing
performance statistics about the capture process.

Example usage:
    python -m network_security_suite.sniffer.testing
"""

import polars as pl

from network_security_suite.sniffer.interfaces import Interface
from network_security_suite.sniffer.packet_capture import PacketCapture

# Check if pyarrow is available
PYARROW_AVAILABLE = False
try:
    import pyarrow
    PYARROW_AVAILABLE = True
except ImportError:
    pass

if __name__ == "__main__":
    try:
        # Initialize interface and capture packets
        interface_manager = Interface()
        wireless_interfaces = interface_manager.get_interface_by_type("wireless")

        if not wireless_interfaces:
            print("No wireless interfaces found. Using the first available interface.")
            all_interfaces = interface_manager.get_active_interfaces()
            if not all_interfaces:
                raise ValueError("No network interfaces found")
            interface_name = all_interfaces[0]
        else:
            interface_name = wireless_interfaces[0]

        print(f"Using interface: {interface_name}")

        # Create packet capture instance and capture packets
        capture = PacketCapture(interface=interface_name)
        print("Starting packet capture (10 packets)...")
        capture.capture(max_packets=100)

        # Display captured packets
        print("\nCaptured Packets:")
        capture.show_packets()

        # Display performance statistics
        print("\nPerformance Statistics:")
        capture.show_stats()


        # Convert to Polars DataFrame and add date/time columns
        print("\nConverting to Polars DataFrame...")
        df_pl = capture.to_polars_df()

        try:
            # Verify timestamp is a datetime type
            if df_pl.schema["timestamp"] != pl.Datetime:
                print(f"Warning: timestamp column is not datetime type, it's {df_pl.schema['timestamp']}")
                print("Converting timestamp to datetime...")
                df_pl = df_pl.with_columns([
                    pl.col("timestamp").cast(pl.Datetime).alias("timestamp")
                ])

            # Add date and hour columns
            df_pl = df_pl.with_columns([
                pl.col("timestamp").dt.date().alias("date"),
                pl.col("timestamp").dt.hour().alias("hour")
            ])

            print(f"DataFrame shape: {df_pl.shape}")
            print(f"DataFrame schema: {df_pl.schema}")

            # Create directory if it doesn't exist
            import os
            os.makedirs("/home/batman/Documents/networkguard2/src/network_security_suite/data/", exist_ok=True)

            # Write to parquet file
            output_file = "/home/batman/Documents/networkguard2/src/network_security_suite/data/packet_capture.parquet"

            if not PYARROW_AVAILABLE:
                print("Warning: pyarrow is not installed. Cannot write to Parquet format.")
                print("Please install pyarrow with: pip install pyarrow")

                # Save as CSV instead
                csv_output = output_file.replace(".parquet", ".csv")
                df_pl.write_csv(csv_output)
                print(f"Saved DataFrame as CSV instead: {csv_output}")
            else:
                df_pl.write_parquet(
                    file=output_file,
                    compression="zstd",  # Best for network data
                    row_group_size=50000,  # Good for time-series analysis
                    statistics=True,
                    use_pyarrow=True
                )
                print(f"Wrote DataFrame to {output_file}")
        except Exception as e:
            print(f"Error processing DataFrame: {e}")
            print(f"DataFrame schema: {df_pl.schema}")
            print(f"First few rows: {df_pl.head()}")

    except Exception as e:
        print(f"Error during testing: {e}")

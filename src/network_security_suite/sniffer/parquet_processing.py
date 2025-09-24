"""
Parquet Processing Module for Network Security Suite.

This module provides functionality for capturing network packets and storing them
in Parquet format, which is an efficient columnar storage format. It also provides
functionality for loading previously saved packet data from Parquet files.

The module uses the Polars library for DataFrame operations and the PyArrow library
for Parquet file handling. It integrates with the PacketCapture class to capture
network packets and the Interface class to manage network interfaces.

Key features:
- Comprehensive logging with InfoLogger, DebugLogger, and ErrorLogger
- Performance monitoring with metrics for timing and memory usage
- Efficient packet capture and storage in Parquet format
- Data analysis utilities for examining captured packet data

Example usage:
    # Basic usage
    config = SnifferConfig(interface="eth0")
    processor = ParquetProcessing(config=config)
    processor.save_packets(filepath="/path/to/output.parquet")
    df = processor.load_packets(filepath="/path/to/output.parquet")
    processor.show_dataframe_stats(df)

    # With real-time display enabled in config
    config = SnifferConfig(interface="eth0", enable_realtime_display=True)
    processor = ParquetProcessing(config=config)
    processor.save_packets(filepath="/path/to/output.parquet")

    # With real-time display enabled for a specific capture
    config = SnifferConfig(interface="eth0")
    processor = ParquetProcessing(config=config)
    processor.save_packets(filepath="/path/to/output.parquet", realtime=True)
"""

import os
import time
from collections import deque
from datetime import datetime
from threading import Thread
from time import sleep
from typing import Optional

import polars as pl

from network_security_suite.sniffer.exceptions import (
    DataConversionError,
    DataExportError,
    DataImportError,
    DataProcessingException,
    InterfaceNotFoundError,
)
from network_security_suite.sniffer.interfaces import Interface
from network_security_suite.sniffer.loggers import DebugLogger, ErrorLogger, InfoLogger
from network_security_suite.sniffer.packet_capture import PacketCapture
from network_security_suite.sniffer.sniffer_config import SnifferConfig
from network_security_suite.utils.performance_metrics import perf


class ParquetProcessing:
    """
    A class for capturing network packets and storing them in Parquet format.

    This class provides methods for capturing network packets from specified interfaces,
    processing them into structured data models, and saving them to Parquet files.
    It also provides methods for loading previously saved packet data from Parquet files.

    Parquet is an efficient columnar storage format that is well-suited for storing
    and querying large datasets, making it ideal for network packet capture data.

    The class includes comprehensive logging capabilities using InfoLogger, DebugLogger,
    and ErrorLogger to track operations, debug issues, and record errors. It also
    integrates performance monitoring through the performance_metrics utility to track
    execution time and resource usage of key operations.

    Attributes:
        interface (str): The name of the network interface to capture packets from.
        log_dir (str): Directory where log files are stored.
        config (SnifferConfig): Configuration object with settings for packet capture.
        info_logger (InfoLogger): Logger for informational messages.
        debug_logger (DebugLogger): Logger for debug messages.
        error_logger (ErrorLogger): Logger for error messages.
        perf_metrics (PerformanceMetricsProxy): Performance monitoring utility.
        realtime_display (bool): Whether real-time display of packets is enabled.
        realtime_packets (deque): Queue of packets for real-time display.
        display_thread (Thread): Thread for real-time display.
        display_running (bool): Whether the real-time display thread is running.
    """

    def __init__(self, config: Optional[SnifferConfig] = None):
        """
        Initialize a new ParquetProcessing instance.

        Args:
            config (Optional[SnifferConfig], optional): Configuration object. Defaults to None.
        """
        # Use configuration if provided
        self.config = config if config is not None else SnifferConfig()

        # Get values from config
        self.interface = self.config.interface
        self.log_dir = self.config.log_dir if self.config.log_to_file else None

        # Initialize loggers
        self.info_logger = InfoLogger(log_dir=self.log_dir)
        self.debug_logger = DebugLogger(log_dir=self.log_dir)
        self.error_logger = ErrorLogger(log_dir=self.log_dir)

        # Initialize performance metrics
        self.perf_metrics = perf

        # Initialize real-time display attributes
        self.realtime_display = self.config.enable_realtime_display
        self.realtime_packets = deque(maxlen=50)  # Store last 50 packets for display
        self.display_thread = None
        self.display_running = False

        self.info_logger.log(
            f"Initializing ParquetProcessing for interface: {self.interface}"
        )

    @perf.monitor("save_packets")
    def save_packets(
        self,
        filepath: str = "",
        interface_type: str = "",
        max_packets: int = None,
        realtime: bool = None,
        # compression_type: str = "zstd",
    ) -> None:
        """
        Capture network packets and save them to a Parquet file.

        This method captures network packets from the specified interface type,
        processes them into a structured format, and saves them to a Parquet file.
        It also displays information about the captured packets and performance statistics.


        The method performs the following steps:
        1. Initialize the interface and capture packets
        2. Display captured packets and performance statistics
        3. Convert the packets to a Polars DataFrame
        4. Add date and hour columns based on the timestamp
        5. Save the DataFrame to a Parquet file (or CSV if PyArrow is not available)

        Args:
            filepath (str, optional): The path where the Parquet file will be saved.
                If empty, uses the export_dir from config.
            interface_type (str, optional): The type of interface to capture packets from.
                If empty, uses the preferred_interface_types from config.
            max_packets (int, optional): Maximum number of packets to capture.
                If None, uses the packet_count from config.
            realtime (bool, optional): Enable real-time display of packets.
                If None, uses the value from config.enable_realtime_display.

        Raises:
            ValueError: If no network interfaces are found or if no filepath is provided.
            Exception: If there's an error processing the DataFrame or writing to the file.
        """
        # Start performance monitoring
        start_time = time.time()
        # Use configuration values if parameters are not provided
        if not filepath:
            timestamp = int(time.time())
            filepath = os.path.join(
                self.config.export_dir,
                f"packets_{self.interface}_{timestamp}.{self.config.export_format}",
            )

        if not interface_type and self.config.preferred_interface_types:
            interface_type = self.config.preferred_interface_types[0]
        elif not interface_type:
            interface_type = "wireless"  # Default fallback

        if max_packets is None:
            max_packets = (
                self.config.packet_count if self.config.packet_count > 0 else 10000
            )

        # Set realtime display flag
        # Use realtime parameter if provided, otherwise use config value
        if realtime is None:
            realtime = self.realtime_display
        self.realtime_display = realtime

        self.info_logger.log(f"Starting packet capture and save to {filepath}")
        self.debug_logger.log(
            f"Using interface type: {interface_type}, realtime={realtime}"
        )

        # Initialize interface and capture packets
        interface_manager = Interface(log_dir=self.log_dir)
        working_interface = interface_manager.get_interface_by_type(interface_type)

        if not working_interface:
            self.debug_logger.log(
                f"No interfaces of type {interface_type} found, using first active interface"
            )
            all_interfaces = interface_manager.get_active_interfaces()
            if not all_interfaces:
                self.error_logger.log("No network interfaces found")
                raise InterfaceNotFoundError("No network interfaces found")
            interface_name = all_interfaces[0]
        else:
            interface_name = working_interface[0]

        self.info_logger.log(f"Using interface: {interface_name}")
        print(f"Using interface: {interface_name}")

        # Create a new config with the selected interface
        capture_config = SnifferConfig(
            interface=interface_name,
            log_dir=self.log_dir,
            # Copy other relevant settings from the original config
            packet_count=self.config.packet_count,
            max_memory_packets=self.config.max_memory_packets,
            log_level=self.config.log_level,
            export_format=self.config.export_format,
            export_dir=self.config.export_dir,
            performance_parquet_path=self.config.performance_parquet_path,
            enable_realtime_display=self.realtime_display,
        )

        # Create PacketCapture with the new configuration
        capture = PacketCapture(config=capture_config)
        self.info_logger.log(f"Starting packet capture ({max_packets} packets)...")
        print(f"Starting packet capture ({max_packets} packets)...")

        # Start real-time display if requested
        if self.realtime_display:
            self.debug_logger.log("Starting real-time display thread")
            self.start_realtime_display()

        try:
            # Pass the realtime flag to the capture method
            capture.capture(max_packets=max_packets, realtime=self.realtime_display)
        finally:
            # Stop real-time display if it was started
            if self.realtime_display:
                self.debug_logger.log("Stopping real-time display thread")
                self.stop_realtime_display()

        # Display captured packets
        self.debug_logger.log("Displaying captured packets")
        print("\nCaptured Packets:")
        capture.show_packets()

        # Display performance statistics
        self.debug_logger.log("Displaying performance statistics")
        print("\nPerformance Statistics:")
        capture.show_stats()

        # Convert to Polars DataFrame and add date/time columns
        self.info_logger.log("Converting to Polars DataFrame")
        print("\nConverting to Polars DataFrame...")
        df_pl = capture.to_polars_df()

        try:
            # Verify timestamp is a datetime type
            self.debug_logger.log("Verifying timestamp data type")
            if df_pl.schema["timestamp"] != pl.Datetime:
                self.debug_logger.log("Converting timestamp to datetime type")
                df_pl = df_pl.with_columns(
                    [pl.col("timestamp").cast(pl.Datetime).alias("timestamp")]
                )

            # Add date and hour columns
            self.debug_logger.log("Adding date and hour columns")
            df_pl = df_pl.with_columns(
                [
                    pl.col("timestamp").dt.date().alias("date"),
                    pl.col("timestamp").dt.hour().alias("hour"),
                ]
            )

            self.debug_logger.log(f"DataFrame shape: {df_pl.shape}")
            print(f"DataFrame shape: {df_pl.shape}")
            print(f"DataFrame schema: {df_pl.schema}")

            # Check if filepath is provided
            if not filepath:
                self.error_logger.log("No filepath provided for saving the data file")
                raise ValueError("No filepath provided for saving the data file")

            # Determine export format from filepath or config
            export_format = self.config.export_format
            if "." in filepath:
                file_extension = filepath.split(".")[-1].lower()
                if file_extension in ["parquet", "csv"]:
                    export_format = file_extension

            self.info_logger.log(
                f"Writing DataFrame to {filepath} in {export_format} format"
            )

            if export_format.lower() == "parquet":
                df_pl.write_parquet(
                    file=filepath,
                    compression="zstd",  # Best for network data
                    row_group_size=50000,  # Good for time-series analysis
                    statistics=True,
                    use_pyarrow=True,
                )
            elif export_format.lower() == "csv":
                df_pl.write_csv(
                    file=filepath,
                    has_header=True,
                )
            else:
                self.error_logger.log(f"Unsupported export format: {export_format}")
                raise ValueError(f"Unsupported export format: {export_format}")
            self.info_logger.log(f"Successfully wrote DataFrame to {filepath}")
            print(f"Successfully wrote DataFrame to {filepath}")

        except ValueError as ve:
            # End performance monitoring - error case
            end_time = time.time()
            elapsed_time = end_time - start_time
            self.perf_metrics._log_metric(
                {
                    "timestamp": datetime.now(),
                    "type": "end_save_packets",
                    "label": "save_packets",
                    "value": round(elapsed_time, 4),
                    "filepath": filepath,
                    "error": str(ve),
                    "status": "error",
                }
            )

            error_msg = f"Error converting DataFrame to Parquet: {str(ve)}"
            self.error_logger.log(error_msg)
            raise DataConversionError(
                source_format="DataFrame",
                target_format="Parquet",
                error_details=str(ve),
            ) from ve
        except Exception as e:
            # End performance monitoring - error case
            end_time = time.time()
            elapsed_time = end_time - start_time
            self.perf_metrics._log_metric(
                {
                    "timestamp": datetime.now(),
                    "type": "end_save_packets",
                    "label": "save_packets",
                    "value": round(elapsed_time, 4),
                    "filepath": filepath,
                    "error": str(e),
                    "status": "error",
                }
            )

            error_msg = f"Error exporting data to {filepath}: {str(e)}"
            self.error_logger.log(error_msg)
            raise DataExportError(
                export_format="Parquet", destination=filepath, error_details=str(e)
            ) from e

    @perf.monitor("load_packets")
    def load_packets(self, filepath: str = "") -> pl.DataFrame:
        """
        Load packet data from a Parquet file.

        This method reads a Parquet file containing packet data and returns it as a
        Polars DataFrame. The DataFrame can then be used for analysis, visualization,
        or further processing.

        Performance metrics for this operation are automatically captured using the
        performance monitoring system.

        Args:
            filepath (str, optional): The path to the Parquet file to load.
                If empty, a ValueError will be raised.

        Returns:
            pl.DataFrame: A Polars DataFrame containing the packet data.

        Raises:
            ValueError: If no filepath is provided.
            FileNotFoundError: If the specified file does not exist.
            Exception: If there's an error reading the Parquet file.
        """
        self.info_logger.log(f"Loading packet data from {filepath}")

        if not filepath:
            self.error_logger.log("No filepath provided for loading the Parquet file")
            raise ValueError("No filepath provided for loading the Parquet file")

        try:
            self.debug_logger.log(f"Reading Parquet file: {filepath}")
            df_pl = pl.read_parquet(filepath)

            self.info_logger.log(
                f"Successfully loaded DataFrame with shape: {df_pl.shape}"
            )
            return df_pl
        except FileNotFoundError as e:
            self.error_logger.log(f"File not found: {filepath}, Error: {e}")
            raise
        except Exception as e:
            error_msg = f"Error importing data from {filepath}: {str(e)}"
            self.error_logger.log(error_msg)
            raise DataImportError(
                import_format="Parquet", source=filepath, error_details=str(e)
            ) from e

    @perf.monitor("show_dataframe_stats")
    def show_dataframe_stats(self, df: pl.DataFrame) -> None:
        """
        Display statistics about a DataFrame.

        This method prints various statistics about a DataFrame, including its shape,
        schema, and basic descriptive statistics for each column. It's useful for
        getting a quick overview of the data.

        Performance metrics for this operation are automatically captured using the
        performance monitoring system.

        Args:
            df (pl.DataFrame): The DataFrame to analyze.

        Raises:
            ValueError: If the DataFrame is empty.
        """
        self.info_logger.log("Generating DataFrame statistics")

        if df.is_empty():
            self.error_logger.log("Cannot show statistics for empty DataFrame")
            raise ValueError("DataFrame is empty")

        self.debug_logger.log(f"DataFrame shape: {df.shape}")
        print("\n" + "=" * 50)
        print("DATAFRAME STATISTICS")
        print("=" * 50)
        print(f"Shape: {df.shape}")
        print(f"Number of rows: {df.height}")
        print(f"Number of columns: {df.width}")

        self.debug_logger.log("Displaying DataFrame schema")
        print("\nSchema:")
        for name, dtype in df.schema.items():
            print(f"  {name}: {dtype}")

        print("\nColumn Statistics:")
        # Get basic statistics for each column
        try:
            self.debug_logger.log("Computing descriptive statistics")
            stats = df.describe()
            print(stats)
        except Exception as e:
            error_msg = f"Could not compute statistics: {e}"
            self.error_logger.log(error_msg)
            raise DataProcessingException(error_msg) from e

        # Show unique values for categorical columns (if not too many)
        self.debug_logger.log("Analyzing categorical columns for unique values")
        print("\nUnique Values for Selected Columns:")
        for col in df.columns:
            try:
                if df[col].dtype in [pl.Utf8, pl.Categorical]:
                    unique_values = df[col].unique()
                    if (
                        len(unique_values) <= 10
                    ):  # Only show if not too many unique values
                        self.debug_logger.log(
                            f"Found {len(unique_values)} unique values for column {col}"
                        )
                        print(f"  {col}: {unique_values.to_list()}")
            except Exception as e:
                self.debug_logger.log(f"Error processing column {col}: {str(e)}")
                # Skip to the next column if there's an error processing this one
                continue

        self.info_logger.log("Completed DataFrame statistics display")
        print("=" * 50)

    def start_realtime_display(self):
        """Start the real-time display thread."""
        if self.realtime_display and not self.display_running:
            self.display_running = True
            self.display_thread = Thread(target=self._realtime_display_loop)
            self.display_thread.daemon = True
            self.display_thread.start()
            self.info_logger.log("Started real-time display thread")

    def stop_realtime_display(self):
        """Stop the real-time display thread."""
        self.display_running = False
        if self.display_thread:
            self.display_thread.join(
                timeout=2
            )  # Wait up to 2 seconds for thread to finish
            self.info_logger.log("Stopped real-time display thread")

    def _realtime_display_loop(self):
        """Real-time display loop that runs in a separate thread."""
        while self.display_running:
            # Clear screen (Linux/Mac)
            os.system("clear" if os.name == "posix" else "cls")

            print("=" * 80)
            print(
                f"REAL-TIME PARQUET PROCESSING - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            print(f"Interface: {self.interface}")
            print(f"Total Packets: {len(self.realtime_packets)}")
            print("=" * 80)

            # Display last few packets
            if self.realtime_packets:
                print("\nLAST 10 PACKETS:")
                print("-" * 80)
                for i, packet in enumerate(list(self.realtime_packets)[-10:]):
                    print(
                        f"{i+1:2d}. {packet.timestamp} | "
                        f"Size: {packet.raw_size:4d} | "
                        f"Layers: {len(packet.layers):2d} | "
                        f"Proto: {packet.layers[0].layer_name if packet.layers else 'Unknown'}"
                    )

                    # Show some layer details
                    if packet.layers:
                        layer = packet.layers[0]
                        if hasattr(layer, "fields") and layer.fields:
                            # Show first few fields
                            fields = list(layer.fields.items())[:3]
                            field_str = ", ".join([f"{k}={v}" for k, v in fields])
                            print(f"    {field_str}")
                    print()

            sleep(1)  # Update every second

    @perf.monitor("analyze_packet_data")
    def analyze_packet_data(
        self, df: pl.DataFrame, group_by: str = "protocol"
    ) -> pl.DataFrame:
        """
        Analyze packet data by grouping and aggregating.

        This method provides more advanced analysis of packet data by grouping
        by a specified column and calculating various aggregations like count,
        mean packet size, and time ranges.

        Performance metrics for this operation are automatically captured using the
        performance monitoring system.

        Args:
            df (pl.DataFrame): The DataFrame containing packet data.
            group_by (str, optional): Column to group by. Defaults to "protocol".
                Common options include "protocol", "src_ip", "dst_ip", "src_port", "dst_port".

        Returns:
            pl.DataFrame: A DataFrame with the analysis results.

        Raises:
            ValueError: If the DataFrame is empty or doesn't contain the required columns.
            DataProcessingException: If there's an error during analysis.
        """
        self.info_logger.log(f"Analyzing packet data grouped by {group_by}")

        if df.is_empty():
            self.error_logger.log("Cannot analyze empty DataFrame")
            raise ValueError("DataFrame is empty")

        if group_by not in df.columns:
            self.error_logger.log(f"Column {group_by} not found in DataFrame")
            raise ValueError(f"Column {group_by} not found in DataFrame")

        try:
            # Create analysis DataFrame with aggregations
            self.debug_logger.log(
                f"Grouping by {group_by} and calculating aggregations"
            )

            # Check if packet_size column exists
            size_agg = []
            if "packet_size" in df.columns:
                size_agg = [
                    pl.col("packet_size").mean().alias(f"avg_{group_by}_packet_size"),
                    pl.col("packet_size").sum().alias(f"total_{group_by}_bytes"),
                    pl.col("packet_size").min().alias(f"min_{group_by}_packet_size"),
                    pl.col("packet_size").max().alias(f"max_{group_by}_packet_size"),
                ]

            # Check if timestamp column exists
            time_agg = []
            if "timestamp" in df.columns:
                time_agg = [
                    pl.col("timestamp").min().alias(f"first_{group_by}_packet_time"),
                    pl.col("timestamp").max().alias(f"last_{group_by}_packet_time"),
                ]

            # Create the analysis DataFrame
            analysis_df = df.group_by(group_by).agg(
                [pl.count().alias(f"{group_by}_packet_count"), *size_agg, *time_agg]
            )

            # Sort by packet count in descending order
            analysis_df = analysis_df.sort(f"{group_by}_packet_count", descending=True)

            # Display the results
            print("\n" + "=" * 50)
            print(f"PACKET ANALYSIS BY {group_by.upper()}")
            print("=" * 50)
            print(analysis_df)
            print("=" * 50)

            self.info_logger.log(f"Completed packet analysis by {group_by}")
            return analysis_df

        except Exception as e:
            error_msg = f"Error analyzing packet data: {e}"
            self.error_logger.log(error_msg)
            raise DataProcessingException(error_msg) from e

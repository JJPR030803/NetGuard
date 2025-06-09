"""
Parquet Processing Module for Network Security Suite.

This module provides functionality for capturing network packets and storing them
in Parquet format, which is an efficient columnar storage format. It also provides
functionality for loading previously saved packet data from Parquet files.

The module uses the Polars library for DataFrame operations and the PyArrow library
for Parquet file handling. It integrates with the PacketCapture class to capture
network packets and the Interface class to manage network interfaces.

Example usage:
    processor = ParquetProcessing(interface="eth0")
    processor.save_packets(filepath="/path/to/output.parquet")
    df = processor.load_packets(filepath="/path/to/output.parquet")
"""

import polars as pl

from network_security_suite.sniffer.interfaces import Interface
from network_security_suite.sniffer.packet_capture import PacketCapture


class ParquetProcessing:
    """
    A class for capturing network packets and storing them in Parquet format.

    This class provides methods for capturing network packets from specified interfaces,
    processing them into structured data models, and saving them to Parquet files.
    It also provides methods for loading previously saved packet data from Parquet files.

    Parquet is an efficient columnar storage format that is well-suited for storing
    and querying large datasets, making it ideal for network packet capture data.

    Attributes:
        interface (str): The name of the network interface to capture packets from.
    """

    def __init__(self, interface: str):
        self.interface = interface

    def save_packets(
        self,
        filepath: str = "",
        interface_type: str = "wireless",
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
                If empty, an error will occur when trying to write the file.
            interface_type (str, optional): The type of interface to capture packets from.
                Defaults to "wireless". If the specified interface type is not found,
                the first available interface will be used.

        Raises:
            ValueError: If no network interfaces are found or if no filepath is provided.
            Exception: If there's an error processing the DataFrame or writing to the file.
        """
        # Initialize interface and capture packets
        interface_manager = Interface()
        working_interface = interface_manager.get_interface_by_type(interface_type)

        if not working_interface:
            print(
                f"Interface type '{interface_type}' not found. Using the first available interface."
            )
            all_interfaces = interface_manager.get_active_interfaces()
            if not all_interfaces:
                raise ValueError("No network interfaces found")
            interface_name = all_interfaces[0]
        else:
            interface_name = working_interface[0]

        print(f"Using interface: {interface_name}")

        capture = PacketCapture(interface=interface_name)
        print("Starting packet capture (10 packets)...")
        capture.capture(max_packets=10000)

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
                print(
                    f"Warning: timestamp column is not datetime type, it's {df_pl.schema['timestamp']}"
                )
                print("Converting timestamp to datetime...")
                df_pl = df_pl.with_columns(
                    [pl.col("timestamp").cast(pl.Datetime).alias("timestamp")]
                )

            # Add date and hour columns
            df_pl = df_pl.with_columns(
                [
                    pl.col("timestamp").dt.date().alias("date"),
                    pl.col("timestamp").dt.hour().alias("hour"),
                ]
            )

            print(f"DataFrame shape: {df_pl.shape}")
            print(f"DataFrame schema: {df_pl.schema}")

            # Check if filepath is provided
            if not filepath:
                raise ValueError("No filepath provided for saving the Parquet file")

            df_pl.write_parquet(
                file=filepath,
                compression="zstd",  # Best for network data
                row_group_size=50000,  # Good for time-series analysis
                statistics=True,
                use_pyarrow=True,
            )
            print(f"Successfully wrote DataFrame to {filepath}")
        except ValueError as ve:
            print(f"Value Error: {ve}")
        except Exception as e:
            print(f"Error processing DataFrame: {e}")
            print(f"DataFrame schema: {df_pl.schema}")
            print(f"First few rows: {df_pl.head()}")

    def load_packets(self, filepath: str = "") -> pl.DataFrame:
        """
        Load packet data from a Parquet file.

        This method reads a Parquet file containing packet data and returns it as a
        Polars DataFrame. The DataFrame can then be used for analysis, visualization,
        or further processing.

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
        if not filepath:
            raise ValueError("No filepath provided for loading the Parquet file")

        try:
            df_pl = pl.read_parquet(filepath)
            print(f"Successfully loaded DataFrame from {filepath}")
            print(f"DataFrame shape: {df_pl.shape}")
            return df_pl
        except FileNotFoundError:
            print(f"File not found: {filepath}")
            raise
        except Exception as e:
            print(f"Error loading Parquet file: {e}")
            raise

    def show_dataframe_stats(self, df: pl.DataFrame) -> None:
        """
        Display statistics about a DataFrame.

        This method prints various statistics about a DataFrame, including its shape,
        schema, and basic descriptive statistics for each column. It's useful for
        getting a quick overview of the data.

        Args:
            df (pl.DataFrame): The DataFrame to analyze.

        Raises:
            ValueError: If the DataFrame is empty.
        """
        if df.is_empty():
            raise ValueError("DataFrame is empty")

        print("\n" + "=" * 50)
        print("DATAFRAME STATISTICS")
        print("=" * 50)
        print(f"Shape: {df.shape}")
        print(f"Number of rows: {df.height}")
        print(f"Number of columns: {df.width}")

        print("\nSchema:")
        for name, dtype in df.schema.items():
            print(f"  {name}: {dtype}")

        print("\nColumn Statistics:")
        # Get basic statistics for each column
        try:
            stats = df.describe()
            print(stats)
        except Exception as e:
            print(f"Could not compute statistics: {e}")

        # Show unique values for categorical columns (if not too many)
        print("\nUnique Values for Selected Columns:")
        for col in df.columns:
            try:
                if df[col].dtype in [pl.Utf8, pl.Categorical]:
                    unique_values = df[col].unique()
                    if (
                        len(unique_values) <= 10
                    ):  # Only show if not too many unique values
                        print(f"  {col}: {unique_values.to_list()}")
            except Exception:
                print("Avanzando a la siguiente columna")
                pass# Skip columns that can't be processed

        print("=" * 50)

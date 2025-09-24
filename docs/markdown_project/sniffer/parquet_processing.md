# Parquet Processing Module

## Overview

The `parquet_processing.py` module provides functionality for capturing network packets and storing them in Parquet format, which is an efficient columnar storage format. It also provides functionality for loading previously saved packet data from Parquet files.

The module uses the Polars library for DataFrame operations and the PyArrow library for Parquet file handling. It integrates with the PacketCapture class to capture network packets and the Interface class to manage network interfaces.

## Classes

### ParquetProcessing

A class for capturing network packets and storing them in Parquet format. This class provides methods for capturing network packets from specified interfaces, processing them into structured data models, and saving them to Parquet files. It also provides methods for loading previously saved packet data from Parquet files.

Parquet is an efficient columnar storage format that is well-suited for storing and querying large datasets, making it ideal for network packet capture data.

#### Attributes

- `interface (str)`: The name of the network interface to capture packets from.

#### Methods

##### `__init__(self, interface: str, log_dir: Optional[str] = None)`

Initialize a new ParquetProcessing instance.

**Parameters:**
- `interface (str)`: The name of the network interface to capture packets from.
- `log_dir (Optional[str], optional)`: Directory to store log files. Defaults to None.

##### `save_packets(self, filepath: str = "", interface_type: str = "wireless") -> None`

Capture network packets and save them to a Parquet file.

This method captures network packets from the specified interface type, processes them into a structured format, and saves them to a Parquet file. It also displays information about the captured packets and performance statistics.

The method performs the following steps:
1. Initialize the interface and capture packets
2. Display captured packets and performance statistics
3. Convert the packets to a Polars DataFrame
4. Add date and hour columns based on the timestamp
5. Save the DataFrame to a Parquet file (or CSV if PyArrow is not available)

**Parameters:**
- `filepath (str, optional)`: The path where the Parquet file will be saved. If empty, an error will occur when trying to write the file.
- `interface_type (str, optional)`: The type of interface to capture packets from. Defaults to "wireless". If the specified interface type is not found, the first available interface will be used.

**Raises:**
- `ValueError`: If no network interfaces are found or if no filepath is provided.
- `Exception`: If there's an error processing the DataFrame or writing to the file.

##### `load_packets(self, filepath: str = "") -> pl.DataFrame`

Load packet data from a Parquet file.

This method reads a Parquet file containing packet data and returns it as a Polars DataFrame. The DataFrame can then be used for analysis, visualization, or further processing.

**Parameters:**
- `filepath (str, optional)`: The path to the Parquet file to load. If empty, a ValueError will be raised.

**Returns:**
- `pl.DataFrame`: A Polars DataFrame containing the packet data.

**Raises:**
- `ValueError`: If no filepath is provided.
- `FileNotFoundError`: If the specified file does not exist.
- `Exception`: If there's an error reading the Parquet file.

##### `show_dataframe_stats(self, df: pl.DataFrame) -> None`

Display statistics about a DataFrame.

This method prints various statistics about a DataFrame, including its shape, schema, and basic descriptive statistics for each column. It's useful for getting a quick overview of the data.

**Parameters:**
- `df (pl.DataFrame)`: The DataFrame to analyze.

**Raises:**
- `ValueError`: If the DataFrame is empty.

## Usage Example

```python
from network_security_suite.sniffer.parquet_processing import ParquetProcessing
import polars as pl

# Initialize ParquetProcessing with a specific interface
processor = ParquetProcessing(interface="eth0")

# Capture packets and save to a Parquet file
processor.save_packets(
    filepath="/path/to/output.parquet",
    interface_type="ethernet"
)

# Load packets from a Parquet file
df = processor.load_packets(filepath="/path/to/output.parquet")

# Display statistics about the loaded data
processor.show_dataframe_stats(df)

# Perform analysis on the DataFrame
filtered_df = df.filter(pl.col("Ethernet_type") == 2048)  # Filter for IPv4 packets
print(f"Number of IPv4 packets: {filtered_df.height}")

# Group by source IP address and count packets
ip_counts = df.filter(pl.col("IP_src").is_not_null()) \
              .group_by("IP_src") \
              .agg(pl.count().alias("packet_count")) \
              .sort("packet_count", descending=True)
print("Top source IP addresses by packet count:")
print(ip_counts.head(10))
```

## Dependencies

- `polars`: For DataFrame operations and Parquet file handling
- `pyarrow`: For Parquet file format support (used by Polars)
- `network_security_suite.sniffer.exceptions`: For exception handling
- `network_security_suite.sniffer.interfaces`: For network interface management
- `network_security_suite.sniffer.packet_capture`: For packet capture functionality
- `network_security_suite.sniffer.loggers`: For logging information, debug messages, and errors

## Notes

- The module uses Parquet format with zstd compression, which provides excellent compression ratios for network data.
- The DataFrame includes timestamp, date, and hour columns for time-based analysis.
- Row groups are optimized for time-series analysis with a default size of 50,000 rows.
- Statistics are enabled in the Parquet files to improve query performance.
- The module gracefully handles errors during packet capture, data conversion, and file operations.
- The show_dataframe_stats method provides a quick overview of the captured data, including unique values for categorical columns.
# ParquetProcessing API Reference

The `ParquetProcessing` module handles conversion and processing of captured packets to/from Parquet format.

## Module Reference

::: network_security_suite.sniffer.parquet_processing
    options:
      show_source: true
      show_root_heading: true
      heading_level: 2

## Usage Examples

### Basic Usage

```python
from network_security_suite.sniffer.parquet_processing import ParquetProcessor

# Process captured packets
processor = ParquetProcessor("capture.parquet")

# Get summary
summary = processor.get_summary()
print(summary)

# Filter by protocol
tcp_packets = processor.filter_by_protocol("TCP")
```

### Writing Packets

```python
from network_security_suite.sniffer.parquet_processing import write_packets_to_parquet

# Write packets to Parquet
write_packets_to_parquet(
    packets=packet_list,
    output_file="output.parquet",
    compression="snappy"
)
```

### Reading Packets

```python
from network_security_suite.sniffer.parquet_processing import read_packets_from_parquet

# Read packets from Parquet
packets_df = read_packets_from_parquet("capture.parquet")
print(packets_df.head())
```

## See Also

- [PacketCapture API](packet-capture.md)
- [Getting Started Guide](../getting-started.md)

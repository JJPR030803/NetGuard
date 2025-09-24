# Performance Metrics

The `PerformanceMetrics` class provides utilities for measuring and logging performance metrics in the Network Security Suite application.

## Overview

This utility allows you to:
- Measure execution time of functions
- Track memory usage of functions
- Monitor system CPU and memory usage
- Log performance data to console, log files, and/or Parquet files

## Usage

### Initialization

```python
from src.network_security_suite.utils.performance_metrics import PerformanceMetrics

# Basic initialization with default settings
performance_metrics = PerformanceMetrics()

# Custom initialization
performance_metrics = PerformanceMetrics(
    is_log_to_file=True,  # Whether to log metrics to files
    parquet_path="data/performance_metrics.parquet",  # Path to save Parquet data
    log_dir="logs/custom_metrics"  # Directory for log files
)
```

### Measuring Execution Time

Use the `timeit` decorator to measure how long a function takes to execute:

```python
@performance_metrics.timeit("process_packets")
def process_packets(packets):
    # Process packets here
    pass
```

This will log the execution time in milliseconds each time the function is called.

### Measuring Memory Usage

Use the `memory_profile` decorator to track memory usage during function execution:

```python
@performance_metrics.memory_profile("analyze_data")
def analyze_data(data):
    # Analyze data here
    pass
```

This will log both current memory usage and peak memory usage in kilobytes.

### System Monitoring

Start continuous monitoring of system resources:

```python
# Monitor CPU and memory usage every 5 seconds (default)
performance_metrics.start_system_monitoring()

# Custom monitoring interval (10 seconds)
performance_metrics.start_system_monitoring(interval=10)
```

## Data Storage

Performance metrics are stored in three ways:

1. **Console Output**: All metrics are printed to the console with the `[PERF]` prefix.
2. **Log Files**: If `is_log_to_file` is True, metrics are saved to log files in the specified `log_dir`.
3. **Parquet Files**: If `parquet_path` is provided, metrics are saved to a Parquet file for later analysis.

## Implementation Status

This utility is currently not integrated with the rest of the application. It's available for use but requires explicit integration into the codebase.

## Potential Improvements

The current implementation has some limitations:

1. No method to stop system monitoring once started
2. Limited error handling for memory profiling
3. No way to enable/disable performance monitoring at runtime
4. Basic error handling for Parquet file operations

These could be addressed in future versions of the utility.
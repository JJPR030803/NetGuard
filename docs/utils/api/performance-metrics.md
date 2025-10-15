# Performance Metrics API Reference

Complete API reference for the performance metrics utilities.

## Module Reference

::: network_security_suite.utils.performance_metrics
    options:
      show_source: true
      show_root_heading: true
      heading_level: 2

## Usage Examples

### Basic Usage

```python
from network_security_suite.utils import PerformanceMetrics

metrics = PerformanceMetrics()

# Measure execution time
with metrics.measure("operation"):
    do_work()

# Get time
duration = metrics.get_time("operation")
print(f"Duration: {duration:.2f}s")
```

### Multiple Measurements

```python
metrics = PerformanceMetrics()

for i in range(100):
    with metrics.measure("operation"):
        process_data()

# Get statistics
stats = metrics.get_stats("operation")
print(f"Average: {stats['mean']:.2f}s")
print(f"Min: {stats['min']:.2f}s")
print(f"Max: {stats['max']:.2f}s")
```

### Custom Metrics

```python
metrics = PerformanceMetrics()

# Record custom values
metrics.record("packets_processed", 1000)
metrics.record("errors", 5)

# Increment counters
metrics.increment("request_count")

# Get report
report = metrics.get_report()
```

## See Also

- [Performance Metrics Guide](../performance-metrics.md)
- [Logger API](logger.md)
- [Configuration Guide](../configuration.md)

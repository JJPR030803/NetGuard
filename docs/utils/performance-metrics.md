# Performance Metrics Guide

Guide to performance monitoring and metrics collection in the Network Security Suite.

## Overview

The performance metrics system allows you to track execution times, resource usage, and custom metrics throughout your application.

## Basic Usage

### Tracking Execution Time

```python
from network_security_suite.utils import PerformanceMetrics

metrics = PerformanceMetrics()

# Using context manager
with metrics.measure("operation"):
    # Your code here
    process_data()

# Get the time
duration = metrics.get_time("operation")
print(f"Operation took {duration:.2f}s")
```

### Multiple Operations

```python
metrics = PerformanceMetrics()

# Track multiple operations
with metrics.measure("database_query"):
    db.query(...)

with metrics.measure("data_processing"):
    process(data)

with metrics.measure("file_write"):
    write_to_file(data)

# Get summary
report = metrics.get_report()
print(report)
```

## Advanced Features

### Custom Metrics

```python
from network_security_suite.utils import PerformanceMetrics

metrics = PerformanceMetrics()

# Record custom metrics
metrics.record("packets_processed", 1000)
metrics.record("bytes_transferred", 500000)
metrics.record("errors_encountered", 5)

# Increment counters
for packet in packets:
    metrics.increment("packet_count")
    if is_error(packet):
        metrics.increment("error_count")
```

### Nested Measurements

```python
metrics = PerformanceMetrics()

with metrics.measure("total_operation"):
    with metrics.measure("step1"):
        do_step1()

    with metrics.measure("step2"):
        do_step2()

    with metrics.measure("step3"):
        do_step3()

# Get detailed breakdown
print(metrics.get_report(detailed=True))
```

### Statistical Analysis

```python
metrics = PerformanceMetrics()

# Run operation multiple times
for i in range(100):
    with metrics.measure("operation"):
        process_data()

# Get statistics
stats = metrics.get_stats("operation")
print(f"Average: {stats['mean']:.2f}s")
print(f"Min: {stats['min']:.2f}s")
print(f"Max: {stats['max']:.2f}s")
print(f"Std Dev: {stats['std']:.2f}s")
```

## Use Cases

### API Endpoint Monitoring

```python
from fastapi import FastAPI
from network_security_suite.utils import PerformanceMetrics

app = FastAPI()
metrics = PerformanceMetrics()

@app.get("/api/data")
async def get_data():
    with metrics.measure("api_get_data"):
        data = fetch_data()
        return data

@app.get("/api/metrics")
async def get_metrics():
    return metrics.get_report()
```

### Packet Processing Pipeline

```python
metrics = PerformanceMetrics()

def process_packets(packets):
    with metrics.measure("total_processing"):
        # Capture phase
        with metrics.measure("capture"):
            captured = capture_packets()

        # Parse phase
        with metrics.measure("parse"):
            parsed = parse_packets(captured)

        # Analysis phase
        with metrics.measure("analysis"):
            results = analyze_packets(parsed)

        # Storage phase
        with metrics.measure("storage"):
            store_results(results)

    # Log performance
    logger.info("Performance:", extra=metrics.get_report())
```

### Resource Usage Monitoring

```python
import psutil
from network_security_suite.utils import PerformanceMetrics

metrics = PerformanceMetrics()

def monitor_resources():
    # CPU usage
    cpu_percent = psutil.cpu_percent(interval=1)
    metrics.record("cpu_usage", cpu_percent)

    # Memory usage
    memory = psutil.virtual_memory()
    metrics.record("memory_usage", memory.percent)
    metrics.record("memory_available", memory.available)

    # Disk usage
    disk = psutil.disk_usage('/')
    metrics.record("disk_usage", disk.percent)

    return metrics.get_report()
```

## Decorators

### Timing Decorator

```python
from network_security_suite.utils import measure_time

@measure_time
def expensive_operation():
    # Your code
    pass

# Call function - timing is automatic
result = expensive_operation()
```

### Custom Performance Decorator

```python
import functools
from network_security_suite.utils import PerformanceMetrics

def track_performance(metric_name):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            metrics = PerformanceMetrics()
            with metrics.measure(metric_name):
                result = func(*args, **kwargs)
            logger.info(f"{metric_name}: {metrics.get_time(metric_name):.2f}s")
            return result
        return wrapper
    return decorator

@track_performance("data_processing")
def process_data(data):
    # Process data
    return result
```

## Reporting

### Console Report

```python
metrics = PerformanceMetrics()

# Run operations
with metrics.measure("op1"):
    do_op1()

with metrics.measure("op2"):
    do_op2()

# Print report
print(metrics.get_report())
```

Output:
```
Performance Report:
------------------
op1: 1.23s
op2: 0.45s
Total: 1.68s
```

### JSON Report

```python
import json

report = metrics.get_report(format="json")
print(json.dumps(report, indent=2))
```

### Detailed Report

```python
detailed = metrics.get_report(detailed=True)
```

Output includes:
- Execution times
- Call counts
- Min/max/average
- Standard deviation
- Percentiles

## Best Practices

### 1. Use Context Managers

```python
# Good
with metrics.measure("operation"):
    do_work()

# Avoid manual timing
start = time.time()
do_work()
metrics.record("operation", time.time() - start)
```

### 2. Name Metrics Consistently

```python
# Good: Consistent naming
with metrics.measure("db.query.users"):
    ...

with metrics.measure("db.query.packets"):
    ...

# Avoid: Inconsistent naming
with metrics.measure("queryUsers"):
    ...

with metrics.measure("packet-query"):
    ...
```

### 3. Don't Over-Instrument

```python
# Good: Track important operations
with metrics.measure("packet_processing"):
    for packet in packets:
        process(packet)

# Avoid: Tracking every tiny operation
for packet in packets:
    with metrics.measure("single_packet"):  # Too granular
        process(packet)
```

### 4. Clean Up Old Metrics

```python
# Clear metrics periodically
if metrics.count() > 1000:
    metrics.clear()

# Or use time-based cleanup
if time.time() - metrics.start_time > 3600:  # 1 hour
    metrics.save_report()
    metrics.clear()
```

## Integration with Monitoring Systems

### Prometheus

```python
from prometheus_client import Summary

REQUEST_TIME = Summary('request_processing_seconds', 'Time spent processing request')

@REQUEST_TIME.time()
def process_request():
    with metrics.measure("request"):
        # Process request
        pass
```

### Grafana

Export metrics for Grafana:

```python
def export_metrics():
    report = metrics.get_report(format="json")
    # Send to Grafana endpoint
    requests.post(grafana_url, json=report)
```

## See Also

- [Logging Guide](logging.md)
- [Configuration Guide](configuration.md)
- [Performance Metrics API Reference](api/performance-metrics.md)

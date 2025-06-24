

import time
import tracemalloc
import polars as pl
from datetime import datetime
import os
import psutil
import threading
from functools import wraps
from typing import Callable, Any, Optional, Dict
from src.network_security_suite.utils.logger import PerformanceLogger

class PerformanceMetrics:
    """
    Performance monitoring system with FastAPI-style decorators.
    
    Usage:
        perf = PerformanceMetrics()
        
        @perf.timeit()
        def my_function():
            pass
            
        @perf.memory()  
        def memory_intensive():
            pass
            
        @perf.monitor("custom_label")
        def complete_monitoring():
            pass
    """
    
    def __init__(
        self,
        enabled: bool = True,
        log_to_file: bool = True,
        log_dir: str = "logs/performance_metrics",
        parquet_path: Optional[str] = None
    ):
        """
        Initialize the PerformanceMetrics instance.
        
        Args:
            enabled: Whether performance monitoring is enabled
            log_to_file: Whether to save logs to files
            log_dir: Directory for log files
            parquet_path: Path for parquet metrics file
        """
        self.enabled = enabled
        self.log_to_file = log_to_file
        self.log_dir = log_dir
        self.parquet_path = parquet_path or f"{log_dir}/perf_metrics.parquet"
        self.logger = (
            PerformanceLogger(save_logs=log_to_file, log_dir=log_dir)
            if log_to_file
            else None
        )
        self._system_monitoring_active = False

    def timeit(self, label: Optional[str] = None):
        """
        Decorator to measure execution time.
        
        Args:
            label: Optional custom label for the metric
            
        Usage:
            @perf.timeit()
            def my_function():
                pass
                
            @perf.timeit("database_query")
            def query_db():
                pass
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                if not self.enabled:
                    return func(*args, **kwargs)
                
                start_time = time.perf_counter()
                result = func(*args, **kwargs)
                elapsed_time = (time.perf_counter() - start_time) * 1000
                
                metric_data = {
                    "timestamp": datetime.now(),
                    "type": "timing",
                    "label": label or func.__name__,
                    "value_ms": round(elapsed_time, 4),
                }
                self._log_metric(metric_data)
                return result
            return wrapper
        return decorator

    def memory(self, label: Optional[str] = None):
        """
        Decorator to measure memory usage.
        
        Args:
            label: Optional custom label for the metric
            
        Usage:
            @perf.memory()
            def memory_intensive():
                pass
                
            @perf.memory("large_processing")
            def process_data():
                pass
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                if not self.enabled:
                    return func(*args, **kwargs)
                
                tracemalloc.start()
                result = func(*args, **kwargs)
                current, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                
                metric_data = {
                    "timestamp": datetime.now(),
                    "type": "memory",
                    "label": label or func.__name__,
                    "mem_current_kb": current // 1024,
                    "mem_peak_kb": peak // 1024,
                }
                self._log_metric(metric_data)
                return result
            return wrapper
        return decorator

    def monitor(self, label: Optional[str] = None):
        """
        Decorator to measure both timing and memory usage.
        
        Args:
            label: Optional custom label for the metric
            
        Usage:
            @perf.monitor()
            def complex_function():
                pass
                
            @perf.monitor("packet_processing")
            def process_packet():
                pass
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                if not self.enabled:
                    return func(*args, **kwargs)
                
                tracemalloc.start()
                start_time = time.perf_counter()
                
                result = func(*args, **kwargs)
                
                elapsed_time = (time.perf_counter() - start_time) * 1000
                current, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                
                metric_data = {
                    "timestamp": datetime.now(),
                    "type": "complete",
                    "label": label or func.__name__,
                    "timing_ms": round(elapsed_time, 4),
                    "mem_current_kb": current // 1024,
                    "mem_peak_kb": peak // 1024,
                }
                self._log_metric(metric_data)
                return result
            return wrapper
        return decorator

    def system_monitor(self, interval: int = 5):
        """
        Start continuous system monitoring.
        
        Args:
            interval: Time in seconds between measurements
            
        Usage:
            perf.system_monitor(interval=10)
        """
        if self._system_monitoring_active:
            return
            
        def monitor():
            self._system_monitoring_active = True
            while self.enabled and self._system_monitoring_active:
                metric_data = {
                    "timestamp": datetime.now(),
                    "type": "system",
                    "label": "system_monitor",
                    "cpu_percent": psutil.cpu_percent(),
                    "mem_percent": psutil.virtual_memory().percent,
                }
                self._log_metric(metric_data)
                time.sleep(interval)
        
        if self.enabled:
            thread = threading.Thread(target=monitor, daemon=True)
            thread.start()

    def stop_system_monitor(self):
        """Stop system monitoring."""
        self._system_monitoring_active = False

    def enable(self):
        """Enable performance monitoring."""
        self.enabled = True

    def disable(self):
        """Disable performance monitoring."""
        self.enabled = False

    def _log_metric(self, metric_data: Dict[str, Any]):
        """Log performance metric to console, file, and/or parquet."""
        # Always print to console
        print(f"[PERF] {metric_data['label']}: {metric_data}")
        
        # Log to file if enabled
        if self.log_to_file and self.logger:
            self.logger.log(str(metric_data))
        
        # Save to parquet if enabled
        if self.log_to_file and self.parquet_path:
            self._save_to_parquet(metric_data)

    def _save_to_parquet(self, metric_data: Dict[str, Any]):
        """Save metric data to parquet file."""
        try:
            df = pl.DataFrame([metric_data])
            
            if not os.path.exists(self.parquet_path):
                os.makedirs(os.path.dirname(self.parquet_path), exist_ok=True)
                df.write_parquet(self.parquet_path)
            else:
                existing_df = pl.read_parquet(self.parquet_path)
                combined_df = pl.concat([existing_df, df])
                combined_df.write_parquet(self.parquet_path)
        except Exception as e:
            print(f"[PERF] Error saving to parquet: {e}")


# Global instance for easy usage (optional)
perf = PerformanceMetrics()
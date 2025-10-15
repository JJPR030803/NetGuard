"""Logging configuration for preprocessing module."""

import logging
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime


# Default log format
DEFAULT_FORMAT = (
    "%(asctime)s | %(name)s | %(levelname)8s | %(message)s"
)

# Detailed format with more context
DETAILED_FORMAT = (
    "%(asctime)s | %(name)s | %(levelname)8s | "
    "%(filename)s:%(lineno)d | %(funcName)s | %(message)s"
)


class PreprocessingLogger:
    """Logger for ML preprocessing operations."""

    def __init__(
        self,
        name: str = "preprocessing",
        level: int = logging.INFO,
        log_file: Optional[Path] = None,
        detailed: bool = False
    ):
        """
        Initialize preprocessing logger.

        Args:
            name: Logger name
            level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Optional file path for logging
            detailed: Whether to use detailed format
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.logger.propagate = False  # Don't propagate to root logger

        # Clear existing handlers
        self.logger.handlers = []

        # Choose format
        fmt = DETAILED_FORMAT if detailed else DEFAULT_FORMAT
        formatter = logging.Formatter(fmt, datefmt="%Y-%m-%d %H:%M:%S")

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        # File handler (optional)
        if log_file:
            log_file = Path(log_file)
            log_file.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def debug(self, message: str, **kwargs):
        """Log debug message."""
        self.logger.debug(message, **kwargs)

    def info(self, message: str, **kwargs):
        """Log info message."""
        self.logger.info(message, **kwargs)

    def warning(self, message: str, **kwargs):
        """Log warning message."""
        self.logger.warning(message, **kwargs)

    def error(self, message: str, **kwargs):
        """Log error message."""
        self.logger.error(message, **kwargs)

    def critical(self, message: str, **kwargs):
        """Log critical message."""
        self.logger.critical(message, **kwargs)

    def log_operation(self, operation: str, duration: float, **details):
        """
        Log an operation with performance metrics.

        Args:
            operation: Operation name
            duration: Duration in seconds
            **details: Additional details to log
        """
        details_str = ", ".join(f"{k}={v}" for k, v in details.items())
        self.info(
            f"Operation '{operation}' completed in {duration:.3f}s"
            + (f" | {details_str}" if details_str else "")
        )

    def log_dataframe_info(self, df_name: str, shape: tuple, memory_mb: float = None):
        """
        Log DataFrame information.

        Args:
            df_name: Name of the DataFrame
            shape: DataFrame shape (rows, cols)
            memory_mb: Memory usage in MB (optional)
        """
        mem_str = f", {memory_mb:.2f} MB" if memory_mb else ""
        self.info(f"DataFrame '{df_name}': {shape[0]} rows × {shape[1]} cols{mem_str}")

    def log_analysis_start(self, analysis_type: str, **params):
        """
        Log the start of an analysis operation.

        Args:
            analysis_type: Type of analysis
            **params: Analysis parameters
        """
        params_str = ", ".join(f"{k}={v}" for k, v in params.items())
        self.info(f"Starting {analysis_type} analysis" + (f" with {params_str}" if params_str else ""))

    def log_analysis_complete(self, analysis_type: str, result_count: int = None):
        """
        Log completion of an analysis operation.

        Args:
            analysis_type: Type of analysis
            result_count: Number of results (optional)
        """
        count_str = f" ({result_count} results)" if result_count is not None else ""
        self.info(f"Completed {analysis_type} analysis{count_str}")


# Global logger instance
_global_logger: Optional[PreprocessingLogger] = None


def get_logger(
    name: str = "preprocessing",
    level: int = logging.INFO,
    log_file: Optional[Path] = None,
    detailed: bool = False
) -> PreprocessingLogger:
    """
    Get or create a preprocessing logger.

    Args:
        name: Logger name
        level: Logging level
        log_file: Optional log file path
        detailed: Use detailed format

    Returns:
        PreprocessingLogger: Logger instance
    """
    global _global_logger

    if _global_logger is None:
        _global_logger = PreprocessingLogger(
            name=name,
            level=level,
            log_file=log_file,
            detailed=detailed
        )

    return _global_logger


def set_log_level(level: int):
    """
    Set logging level for all handlers.

    Args:
        level: Logging level (logging.DEBUG, logging.INFO, etc.)
    """
    logger = get_logger()
    logger.logger.setLevel(level)
    for handler in logger.logger.handlers:
        handler.setLevel(level)


def enable_debug_logging():
    """Enable debug logging."""
    set_log_level(logging.DEBUG)


def disable_logging():
    """Disable all logging."""
    set_log_level(logging.CRITICAL + 1)


# Convenience functions
def debug(message: str, **kwargs):
    """Log debug message using global logger."""
    get_logger().debug(message, **kwargs)


def info(message: str, **kwargs):
    """Log info message using global logger."""
    get_logger().info(message, **kwargs)


def warning(message: str, **kwargs):
    """Log warning message using global logger."""
    get_logger().warning(message, **kwargs)


def error(message: str, **kwargs):
    """Log error message using global logger."""
    get_logger().error(message, **kwargs)


def critical(message: str, **kwargs):
    """Log critical message using global logger."""
    get_logger().critical(message, **kwargs)

"""
Consolidated logging module for NetGuard.

This module provides specialized logger classes for different handler types
used throughout the network security suite.
"""

import logging
import sys
from logging import Formatter
from pathlib import Path
from typing import Optional

from ..utils.logger import HandlerConfig, HandlerTypes, Logger

# Default log format
DEFAULT_FORMAT = "%(asctime)s | %(name)s | %(levelname)8s | %(message)s"

# Detailed format with more context
DETAILED_FORMAT = "%(asctime)s | %(name)s | %(levelname)8s | %(filename)s:%(lineno)d | %(funcName)s | %(message)s"


class ConsoleLogger(Logger):
    """
    Logger for console output.

    This logger is designed for displaying log messages in the console
    with a simple format focused on readability.
    """

    def __init__(self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None):
        handlers: HandlerTypes = {"console_handler": HandlerConfig("console", logging.INFO, Formatter("%(message)s"))}
        super().__init__(log_format=log_format, handlers=handlers, log_dir=log_dir)

    def log(self, message: str) -> None:
        self.logger.info(message)

    def save_logs(self):
        # Console logs are not saved to a file
        pass


class SecurityLogger(Logger):
    """
    Logger for security-related events.

    This logger captures security-related events and warnings,
    storing them in a dedicated log file.
    """

    def __init__(self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None):
        handlers: HandlerTypes = {
            "security_handler": HandlerConfig(
                "security",
                logging.WARNING,
                Formatter("%(asctime)s [SECURITY] %(message)s"),
                filepath="security.log",
                log_dir=log_dir,
            )
        }
        super().__init__(log_format=log_format, handlers=handlers, log_dir=log_dir)

    def log(self, message: str) -> None:
        self.logger.warning(message)

    def save_logs(self):
        # Logs are automatically saved by the handler
        pass


class PacketLogger(Logger):
    """
    Logger for packet-related information.

    This logger is specialized for logging packet capture and processing
    information, useful for debugging and analysis.
    """

    def __init__(self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None):
        handlers: HandlerTypes = {
            "packet_handler": HandlerConfig(
                "packet",
                logging.DEBUG,
                Formatter("%(asctime)s [PACKET] %(message)s"),
                filepath="packets.log",
                log_dir=log_dir,
            )
        }
        super().__init__(log_format=log_format, handlers=handlers, log_dir=log_dir)

    def log(self, message: str) -> None:
        self.logger.debug(message)

    def save_logs(self):
        # Logs are automatically saved by the handler
        pass


class FileLogger(Logger):
    """
    Logger for general file-based logging.

    This logger writes log messages to a specified file with
    a standard format.
    """

    def __init__(
        self,
        filepath: str = "general.log",
        log_format: Optional[Formatter] = None,
        log_dir: Optional[str] = None,
    ):
        handlers: HandlerTypes = {
            "file_handler": HandlerConfig(
                "file",
                logging.INFO,
                Formatter("%(asctime)s [%(levelname)s] %(message)s"),
                filepath=filepath,
                log_dir=log_dir,
            )
        }
        super().__init__(log_format=log_format, handlers=handlers, log_dir=log_dir)

    def log(self, message: str) -> None:
        self.logger.info(message)

    def save_logs(self):
        # Logs are automatically saved by the handler
        pass


class RotatingFileLogger(Logger):
    """
    Logger with rotating file capability.

    This logger writes to files that rotate when they reach a certain size,
    useful for managing log file sizes in long-running applications.
    """

    def __init__(
        self,
        filepath: str = "rotating.log",
        max_bytes: int = 10485760,  # 10MB
        backup_count: int = 5,
        log_format: Optional[Formatter] = None,
        log_dir: Optional[str] = None,
    ):
        handlers: HandlerTypes = {
            "rotating_file_handler": HandlerConfig(
                "rotating_file",
                logging.INFO,
                Formatter("%(asctime)s [%(levelname)s] %(message)s"),
                filepath=filepath,
                max_bytes=max_bytes,
                backup_count=backup_count,
                log_dir=log_dir,
            )
        }
        super().__init__(log_format=log_format, handlers=handlers, log_dir=log_dir)

    def log(self, message: str) -> None:
        self.logger.info(message)

    def save_logs(self):
        # Logs are automatically saved by the handler
        pass


class TimedRotatingFileLogger(Logger):
    """
    Logger with time-based file rotation.

    This logger writes to files that rotate at specified time intervals,
    useful for organizing logs by time periods.
    """

    def __init__(
        self,
        filepath: str = "timed_rotating.log",
        log_format: Optional[Formatter] = None,
        log_dir: Optional[str] = None,
    ):
        # Note: TimedRotatingFileHandler would need to be implemented in HandlerConfig
        # For now, using regular rotating file handler
        handlers: HandlerTypes = {
            "timed_rotating_file_handler": HandlerConfig(
                "timed_rotating_file",
                logging.INFO,
                Formatter("%(asctime)s [%(levelname)s] %(message)s"),
                filepath=filepath,
                log_dir=log_dir,
            )
        }
        super().__init__(log_format=log_format, handlers=handlers, log_dir=log_dir)

    def log(self, message: str) -> None:
        self.logger.info(message)

    def save_logs(self):
        # Logs are automatically saved by the handler
        pass


class ErrorLogger(Logger):
    """
    Logger for error messages.

    This logger is dedicated to capturing and storing error messages
    for debugging and troubleshooting.
    """

    def __init__(self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None):
        handlers: HandlerTypes = {
            "error_handler": HandlerConfig(
                "error",
                logging.ERROR,
                Formatter("%(asctime)s [ERROR] %(message)s"),
                filepath="error.log",
                log_dir=log_dir,
            )
        }
        super().__init__(log_format=log_format, handlers=handlers, log_dir=log_dir)

    def log(self, message: str) -> None:
        self.logger.error(message)

    def save_logs(self):
        # Logs are automatically saved by the handler
        pass


class DebugLogger(Logger):
    """
    Logger for debug messages.

    This logger captures detailed debug information useful during
    development and troubleshooting.
    """

    def __init__(self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None):
        handlers: HandlerTypes = {
            "debug_handler": HandlerConfig(
                "debug",
                logging.DEBUG,
                Formatter("%(asctime)s [DEBUG] %(message)s"),
                filepath="debug.log",
                log_dir=log_dir,
            )
        }
        super().__init__(log_format=log_format, handlers=handlers, log_dir=log_dir)

    def log(self, message: str) -> None:
        self.logger.debug(message)

    def save_logs(self):
        # Logs are automatically saved by the handler
        pass


class CriticalLogger(Logger):
    """
    Logger for critical messages.

    This logger captures critical issues that require immediate attention.
    """

    def __init__(self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None):
        handlers: HandlerTypes = {
            "critical_handler": HandlerConfig(
                "critical",
                logging.CRITICAL,
                Formatter("%(asctime)s [CRITICAL] %(message)s"),
                filepath="critical.log",
                log_dir=log_dir,
            )
        }
        super().__init__(log_format=log_format, handlers=handlers, log_dir=log_dir)

    def log(self, message: str) -> None:
        self.logger.critical(message)

    def save_logs(self):
        # Logs are automatically saved by the handler
        pass


class WarningLogger(Logger):
    """
    Logger for warning messages.

    This logger captures warning messages that indicate potential issues.
    """

    def __init__(self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None):
        handlers: HandlerTypes = {
            "warning_handler": HandlerConfig(
                "warning",
                logging.WARNING,
                Formatter("%(asctime)s [WARNING] %(message)s"),
                filepath="warning.log",
                log_dir=log_dir,
            )
        }
        super().__init__(log_format=log_format, handlers=handlers, log_dir=log_dir)

    def log(self, message: str) -> None:
        self.logger.warning(message)

    def save_logs(self):
        # Logs are automatically saved by the handler
        pass


class InfoLogger(Logger):
    """
    Logger for informational messages.

    This logger captures general informational messages about system operation.
    """

    def __init__(self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None):
        handlers: HandlerTypes = {
            "info_handler": HandlerConfig(
                "info",
                logging.INFO,
                Formatter("%(asctime)s [INFO] %(message)s"),
                filepath="info.log",
                log_dir=log_dir,
            )
        }
        super().__init__(log_format=log_format, handlers=handlers, log_dir=log_dir)

    def log(self, message: str) -> None:
        self.logger.info(message)

    def save_logs(self):
        # Logs are automatically saved by the handler
        pass


# ==================== Preprocessing Logger ====================


class PreprocessingLogger:
    """Logger for ML preprocessing operations."""

    def __init__(
        self,
        name: str = "preprocessing",
        level: int = logging.INFO,
        log_file: Optional[Path] = None,
        detailed: bool = False,
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
        self.info(f"Operation '{operation}' completed in {duration:.3f}s" + (f" | {details_str}" if details_str else ""))

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
    detailed: bool = False,
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
        _global_logger = PreprocessingLogger(name=name, level=level, log_file=log_file, detailed=detailed)

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

"""
Logging module for the Network Security Suite.

This module provides a flexible and extensible logging system for the Network Security Suite.
It includes several logger classes for different purposes, such as general logging,
network security logging, and performance logging.

The module is designed to be easily extended with new logger types while maintaining
a consistent interface through the abstract Logger base class.
"""

import contextlib
import logging
import logging.handlers
import os
from abc import ABC, abstractmethod
from logging import Formatter, Handler
from typing import Optional, TypedDict

from typing_extensions import override
from ..sniffer.sniffer_config import SnifferConfig

class HandlerConfig(Handler):
    """
    A custom logging handler that extends the standard Handler class.

    This handler supports both console and file-based logging with rotation capabilities.
    It can be configured with a specific formatter, log level, and file path.
    When a file path is provided, it creates a RotatingFileHandler that automatically
    rotates log files when they reach a specified size.

    :ivar name: Name of the handler.
    :type name: str
    :ivar filepath: Path to the log file (if file-based logging is used).
    :type filepath: str or None
    :ivar max_bytes: Maximum size of log files before rotation (default: 10MB).
    :type max_bytes: int
    :ivar backup_count: Number of backup files to keep (default: 5).
    :type backup_count: int
    :ivar file_handler: The underlying RotatingFileHandler (if file-based logging is used).
    :type file_handler: logging.handlers.RotatingFileHandler or None
    :ivar formatter: Formatter for log messages.
    :type formatter: logging.Formatter or None
    """

    def __init__(
        self,
        name: str,
        level: int = logging.INFO,
        formatter: Optional[Formatter] = None,
        filepath: Optional[str] = None,
        max_bytes: int = 10485760,  # 10MB
        backup_count: int = 5,
        log_dir: Optional[str] = None,
    ):
        super().__init__(level=level)
        self.name = name
        self.filepath = filepath
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.file_handler = None
        self.formatter = formatter

        if formatter:
            self.setFormatter(formatter)

        if filepath:
            # Create full path
            full_path = os.path.join(log_dir, filepath) if log_dir else filepath

            # Ensure directory exists
            os.makedirs(os.path.dirname(full_path), exist_ok=True)

            # Create the file handler
            self.file_handler = logging.handlers.RotatingFileHandler(
                full_path,
                maxBytes=max_bytes,
                backupCount=backup_count,
                mode="a",  # Append mode
            )

            if formatter:
                self.file_handler.setFormatter(formatter)

            # Set permissions on the log file
            try:
                os.chmod(full_path, 0o666)
            except Exception:
                contextlib.suppress(Exception)  # Ignore permission errors

    def has_format(self) -> bool:
        """Check if the handler has a formatter set."""
        return self.formatter is not None or (
            self.file_handler is not None and self.file_handler.formatter is not None
        )


class HandlerTypes(TypedDict, total=False):
    """
    A TypedDict for handler configurations used in loggers.

    This class defines the structure for a dictionary of handler configurations,
    where each key represents a handler type and each value is a HandlerConfig instance.
    The 'total=False' parameter indicates that all keys are optional.

    This type is used to provide type hints for the handlers parameter in the Logger class,
    making it easier to understand and validate the expected structure of handler configurations.
    """

    console_handler: HandlerConfig
    security_handler: HandlerConfig
    packet_handler: HandlerConfig
    file_handler: HandlerConfig
    rotating_file_handler: HandlerConfig
    timed_rotating_file_handler: HandlerConfig
    smtp_handler: HandlerConfig
    http_handler: HandlerConfig
    queue_handler: HandlerConfig
    error_handler: HandlerConfig
    debug_handler: HandlerConfig
    critical_handler: HandlerConfig
    warning_handler: HandlerConfig
    info_handler: HandlerConfig


"""
Abstract class for logging functionality
Used on different sections of project.
"""


class Logger(ABC):
    def __init__(
        self,
        config: Optional[SnifferConfig] = None,
        log_format: Optional[Formatter] = None,
        handlers: Optional[HandlerTypes] = None,
        log_dir: Optional[str] = None  # Keep for backward compatibility
    ):
        self.config = config if config is not None else SnifferConfig()

        # Use config values, with fallback to direct parameters for backward compatibility
        self.log_dir = self.config.log_dir if config else (log_dir or self.config.log_dir)

        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(getattr(logging, self.config.log_level.upper()))

        # Setup format from config
        format_string = self.config.log_format if config else "%(asctime)s [%(levelname)s] %(message)s"
        self.format = log_format or logging.Formatter(format_string)

        # Setup handlers from config or provided handlers
        self.handlers = handlers or self._create_handlers_from_config()

        self.set_handlers()

    def _create_handlers_from_config(self) -> HandlerTypes:
        """Create handlers based on configuration."""
        handlers: HandlerTypes = {}

        if self.config.enable_console_logging:
            handlers["console_handler"] = HandlerConfig(
                "console", 
                getattr(logging, self.config.log_level.upper()),
                Formatter("%(message)s")
            )

        if self.config.enable_file_logging and self.config.log_to_file:
            handlers["file_handler"] = HandlerConfig(
                "file",
                getattr(logging, self.config.log_level.upper()),
                self.format,
                filepath=f"{self.__class__.__name__.lower()}.log",
                max_bytes=self.config.max_log_file_size,
                backup_count=self.config.log_backup_count
            )

        return handlers

    @abstractmethod
    def log(self, message: str):
        pass

    @abstractmethod
    def save_logs(self, path: str):
        if self.save_logs:
            pass

    def set_handlers(self):
        """Set up logging handlers for the logger."""
        for handler in self.handlers.values():
            if handler:
                # Set the log_dir for the handler if it's a HandlerConfig instance
                if isinstance(handler, HandlerConfig) and self.log_dir:
                    # Store original values
                    original_filepath = handler.filepath
                    original_formatter = handler.formatter
                    original_name = handler.name
                    original_level = handler.level
                    original_max_bytes = handler.max_bytes
                    original_backup_count = handler.backup_count

                    # Close existing file handler if it exists
                    if handler.file_handler:
                        handler.file_handler.close()
                        handler.file_handler = None

                    # Recreate the handler with the log_dir
                    if original_filepath:
                        handler.__init__(
                            original_name,
                            original_level,
                            original_formatter,
                            original_filepath,
                            original_max_bytes,
                            original_backup_count,
                            self.log_dir,
                        )

                # Set formatter if not already set
                if not handler.has_format():
                    handler.setFormatter(self.format)
                    if handler.file_handler:
                        handler.file_handler.setFormatter(self.format)

                # Add the file_handler to the logger if it exists
                if hasattr(handler, "file_handler") and handler.file_handler:
                    self.logger.addHandler(handler.file_handler)


"""
NetworkSecurityLogger: custom logger for network security
"""


class NetworkSecurityLogger(Logger):
    def __init__(self, config: Optional[SnifferConfig] = None):
        self.config = config if config is not None else SnifferConfig()

        handlers: HandlerTypes = {}

        if self.config.enable_console_logging:
            handlers["console_handler"] = HandlerConfig(
                "console", logging.INFO, Formatter("%(message)s")
            )

        if self.config.enable_file_logging and self.config.log_to_file:
            handlers["error_handler"] = HandlerConfig(
                "error", logging.ERROR,
                Formatter(self.config.log_format),
                filepath="error.log",
                max_bytes=self.config.max_log_file_size,
                backup_count=self.config.log_backup_count
            )

        if self.config.enable_security_logging and self.config.log_to_file:
            handlers["security_handler"] = HandlerConfig(
                "security", logging.WARNING,
                Formatter("%(asctime)s [SECURITY] %(message)s"),
                filepath="security.log",
                max_bytes=self.config.max_log_file_size,
                backup_count=self.config.log_backup_count
            )

        if self.config.enable_packet_logging and self.config.log_to_file:
            handlers["packet_handler"] = HandlerConfig(
                "packet", logging.DEBUG,
                Formatter("%(asctime)s [PACKET] %(message)s"),
                filepath="packets.log",
                max_bytes=self.config.max_log_file_size,
                backup_count=self.config.log_backup_count
            )

        super().__init__(config=config, handlers=handlers)

    def log(self, message: str) -> None:
        """
        Log an informational message.

        This method logs a message at the INFO level using the configured handlers.

        :param message: The message to log.
        :type message: str
        """
        self.logger.info(message)

    def debug(self, message: str) -> None:
        """
        Log a debug message.

        This method logs a message at the DEBUG level using the configured handlers.

        :param message: The message to log.
        :type message: str
        """
        self.logger.debug(message)

    def error(self, message: str) -> None:
        """
        Log an error message.

        This method logs a message at the ERROR level using the configured handlers.

        :param message: The message to log.
        :type message: str
        """
        self.logger.error(message)

    def save_logs(self):
        """
        Save logs manually if needed.

        This method is a placeholder for implementing manual log saving functionality
        if additional persistence is required beyond the automatic file logging.
        Currently, it does nothing as logs are automatically saved by the handlers.
        """
        # Optional: save to file manually if you need separate persistence
        pass


class PerformanceLogger(Logger):
    def __init__(self, config: Optional[SnifferConfig] = None, save_logs: bool = None, log_dir: Optional[str] = None, **kwargs):
        self.config = config if config is not None else SnifferConfig()

        # Use save_logs parameter if provided, otherwise use config
        should_save_logs = save_logs if save_logs is not None else self.config.log_to_file

        # Use log_dir parameter if provided, otherwise use config
        log_directory = log_dir if log_dir is not None else self.config.log_dir

        handlers: HandlerTypes = {}

        if self.config.enable_performance_logging and should_save_logs:
            handlers["performance_handler"] = HandlerConfig(
                "performance", logging.DEBUG,
                Formatter("%(asctime)s [PERFORMANCE] %(message)s"),
                filepath="performance.log",
                max_bytes=self.config.max_log_file_size,
                backup_count=self.config.log_backup_count,
                log_dir=log_directory
            )

        super().__init__(config=config, handlers=handlers)

    def log(self, message: str) -> None:
        """
        Log a performance message.

        This method logs a message at the DEBUG level to ensure all performance
        metrics are captured, regardless of the logger's overall level setting.

        :param message: The performance metric message to log.
        :type message: str
        """
        self.logger.debug(message)

    def save_logs(self, path: str) -> None:
        """
        Save logs to a specific path.

        This method is a placeholder for implementing custom log saving functionality.
        Currently, it does nothing as logs are automatically saved by the handlers
        if save_logs was set to True during initialization.

        :param path: The path where logs should be saved.
        :type path: str
        """
        # This is a placeholder for custom log saving functionality
        pass

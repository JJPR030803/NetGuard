"""
Logger utilities for the Network Security Suite.

This module centralizes logging concerns across the project. It provides:
- A HandlerConfig helper to consistently create file/rotating/timed handlers.
- An abstract Logger base with sensible defaults and handler wiring.
- Concrete loggers for distinct domains (NetworkSecurityLogger, PerformanceLogger).

Quick start:
    from network_security_suite.utils.logger import NetworkSecurityLogger
    sec_log = NetworkSecurityLogger(log_dir="./logs")
    sec_log.log("Suspicious traffic detected from 10.0.0.5")
    sec_log.debug("Rule X matched packet 12345")
    sec_log.error("Failed to parse payload")

Notes:
- By default, file-based handlers write under log_dir (defaults to /tmp/network_security_suite).
- Formatters are lightweight by default to avoid duplicated timestamps where
  upstream logging already adds them.
- All methods are designed to be safe no-ops if misconfigured; override as
  needed in your application.
"""

import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from logging import Formatter, Handler
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from typing import Optional, TypedDict


@dataclass
class HandlerConfig:
    """
    HandlerConfig is a data class meant to configure and manage logging handlers.

    This class is used to set up various logging handle configurations, including
    rotating file handlers and timed rotating file handlers. It provides an
    initializer for setting file paths, ensuring directory existence, and
    dynamically creating handlers based on the provided name. This class is
    designed for flexible logging configurations in applications and supports
    optional log directory and max byte configuration for log files.

    It ensures the creation and readiness of log handlers that can be directly
    utilized in logging setups.

    :ivar name: Name indicating the type of log handler to use, such as
        rotating_file or timed_rotating_file.
    :type name: str
    :ivar level: Logging level to be used for this handler (e.g., DEBUG, INFO).
    :type level: int
    :ivar formatter: Formatter to use for the log messages.
    :type formatter: Formatter
    :ivar filepath: Path to the log file, optionally including the filename. If not
        provided, no file handler is created.
    :type filepath: Optional[str]
    :ivar max_bytes: Maximum size of the file in bytes for rotating file handlers.
        Defaults to 10MB.
    :type max_bytes: int
    :ivar backup_count: Number of backup log files to keep when using a rotating
        file handler. Defaults to 5.
    :type backup_count: int
    :ivar log_dir: Directory where logs are stored. If not provided, defaults to
        the current directory.
    :type log_dir: Optional[str]
    :ivar file_handler: The created logging handler instance (if applicable). None
        if no file handler is created.
    :type file_handler: Optional[Handler]
    """

    name: str
    level: int
    formatter: Formatter
    filepath: Optional[str] = None
    max_bytes: int = 10485760  # 10MB
    backup_count: int = 5
    log_dir: Optional[str] = None
    file_handler: Optional[Handler] = None

    def __init__(
        self,
        name: str,
        level: int,
        formatter: Formatter,
        filepath: Optional[str] = None,
        max_bytes: int = 10485760,
        backup_count: int = 5,
        log_dir: Optional[str] = None,
    ):
        self.name = name
        self.level = level
        self.formatter = formatter
        self.filepath = filepath
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.log_dir = log_dir
        self.file_handler = None

        # Create file handler if filepath is provided
        if filepath:
            # Use log_dir if provided, otherwise use current directory
            if log_dir:
                # Ensure log directory exists
                os.makedirs(log_dir, exist_ok=True)
                full_path = os.path.join(log_dir, filepath)
            else:
                full_path = filepath
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(full_path), exist_ok=True)

            # Create appropriate handler based on name
            if name == "rotating_file":
                self.file_handler = RotatingFileHandler(
                    full_path, maxBytes=max_bytes, backupCount=backup_count
                )
            elif name == "timed_rotating_file":
                self.file_handler = TimedRotatingFileHandler(
                    full_path, when="midnight", interval=1, backupCount=backup_count
                )
            else:
                self.file_handler = logging.FileHandler(full_path)

            self.file_handler.setLevel(level)
            self.file_handler.setFormatter(formatter)

    def has_format(self) -> bool:
        """
        Return True if this handler configuration has a formatter assigned.

        This is useful when normalizing handler setup inside Logger.set_handlers,
        where a default formatter may be applied if none is configured.

        Returns:
            bool: True if a formatter is set, otherwise False.
        """
        return self.formatter is not None


class HandlerTypes(TypedDict, total=False):
    """
    Typed dictionary for defining optional handler configurations.

    This class is used for specifying various handler configurations that may
    be part of a logging or event system. Each handler type is optional
    and can be specified as needed. Typical usage includes providing
    specific configurations for logging handlers such as file handlers,
    console handlers, or handlers for specific log levels like error,
    debug, and warning.

    :ivar console_handler: Optional configuration for a console handler.
    :type console_handler: Optional[HandlerConfig]
    :ivar security_handler: Optional configuration for a security handler.
    :type security_handler: Optional[HandlerConfig]
    :ivar packet_handler: Optional configuration for a packet handler.
    :type packet_handler: Optional[HandlerConfig]
    :ivar file_handler: Optional configuration for a file handler.
    :type file_handler: Optional[HandlerConfig]
    :ivar rotating_file_handler: Optional configuration for a rotating file handler.
    :type rotating_file_handler: Optional[HandlerConfig]
    :ivar timed_rotating_file_handler: Optional configuration for a timed rotating file handler.
    :type timed_rotating_file_handler: Optional[HandlerConfig]
    :ivar smtp_handler: Optional configuration for an SMTP handler.
    :type smtp_handler: Optional[HandlerConfig]
    :ivar http_handler: Optional configuration for an HTTP handler.
    :type http_handler: Optional[HandlerConfig]
    :ivar queue_handler: Optional configuration for a queue handler.
    :type queue_handler: Optional[HandlerConfig]
    :ivar error_handler: Optional configuration for an error handler.
    :type error_handler: Optional[HandlerConfig]
    :ivar debug_handler: Optional configuration for a debug handler.
    :type debug_handler: Optional[HandlerConfig]
    :ivar critical_handler: Optional configuration for a critical handler.
    :type critical_handler: Optional[HandlerConfig]
    :ivar warning_handler: Optional configuration for a warning handler.
    :type warning_handler: Optional[HandlerConfig]
    :ivar info_handler: Optional configuration for an info handler.
    :type info_handler: Optional[HandlerConfig]
    """

    console_handler: Optional[HandlerConfig]
    security_handler: Optional[HandlerConfig]
    packet_handler: Optional[HandlerConfig]
    file_handler: Optional[HandlerConfig]
    rotating_file_handler: Optional[HandlerConfig]
    timed_rotating_file_handler: Optional[HandlerConfig]
    smtp_handler: Optional[HandlerConfig]
    http_handler: Optional[HandlerConfig]
    queue_handler: Optional[HandlerConfig]
    error_handler: Optional[HandlerConfig]
    debug_handler: Optional[HandlerConfig]
    critical_handler: Optional[HandlerConfig]
    warning_handler: Optional[HandlerConfig]
    info_handler: Optional[HandlerConfig]


class Logger(ABC):
    """
    Logger class providing a base structure for log management and customization.

    This class is designed as an abstract base class (ABC) for creating custom
    loggers with specific behavior. It initializes default logging configurations,
    allows for the addition of custom handlers, and enables saving logs to files.
    Derived classes are expected to implement the abstract methods for logging and
    saving logs.

    :ivar logger: The logging instance for managing log messages.
    :type logger: logging.Logger
    :ivar format: Logging format used for formatting log messages.
    :type format: logging.Formatter
    :ivar handlers: Collection of handler configurations for log management.
    :type handlers: Optional[HandlerTypes]
    :ivar log_dir: Path to the directory where logs can be saved.
    :type log_dir: Optional[str]
    """

    def __init__(
        self,
        log_format: Optional[Formatter] = None,
        handlers: Optional[HandlerTypes] = None,
        log_dir: Optional[str] = None,
    ):
        """
        Initialize the base logger with format, handlers, and log directory.

        Args:
            log_format (Optional[logging.Formatter]): Custom formatter to use for
                messages. If None, defaults to "%(asctime)s [%(levelname)s] %(message)s".
            handlers (Optional[HandlerTypes]): Mapping of handler names to
                HandlerConfig instances. If None, a minimal console handler is created.
            log_dir (Optional[str]): Base directory where file handlers should
                write logs. Defaults to "/tmp/network_security_suite" if not provided.
        """
        self.log_dir = log_dir or "/tmp/network_security_suite"

        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.INFO)

        # Setup default format
        format_string = "%(asctime)s [%(levelname)s] %(message)s"
        self.format = log_format or logging.Formatter(format_string)

        # Setup handlers
        self.handlers = handlers or self._create_default_handlers()
        self.set_handlers()

    def _create_default_handlers(self) -> HandlerTypes:
        """
        Create a minimal default handler configuration.

        By default, a simple console handler is used with level INFO and a
        bare "%(message)s" format to avoid duplicating timestamps/levels that
        higher-level classes may include. Projects can override this by passing
        a custom handlers dict to the constructor.

        Returns:
            HandlerTypes: Dictionary with a single console handler definition.
        """
        handlers: HandlerTypes = {
            "console_handler": HandlerConfig(
                "console", logging.INFO, Formatter("%(message)s")
            )
        }
        return handlers

    @abstractmethod
    def log(self, message: str):
        """
        Emit a log message.

        Subclasses decide the log level and any additional formatting. For
        example, NetworkSecurityLogger.log() uses WARNING while
        PerformanceLogger.log() uses INFO.

        Args:
            message (str): The message to be logged.
        """
        pass

    @abstractmethod
    def save_logs(self, path: str):
        """
        Persist current logs to a target destination.

        Subclasses can implement exporting, archiving, or uploading of log
        records. Many use-cases are already covered by file handlers, so this
        method is optional to implement unless custom behavior is needed.

        Args:
            path (str): Destination path (file or directory) for the persisted logs.
        """
        pass

    def set_handlers(self):
        """
        Build and attach logging handlers defined in self.handlers.

        This method iterates through HandlerConfig entries and ensures each
        handler is correctly bound to this logger instance, honoring the
        configured log_dir. It will recreate file-based handlers with the
        resolved log_dir to guarantee log files end up under the intended
        directory.

        Behavior:
        - If a HandlerConfig already created a file handler and a log_dir is set,
          the file handler is safely closed and recreated with the updated path.
        - If a handler has no formatter, the logger's default formatter is
          applied.
        - Any available file_handler on the config is added to the logger.

        Note:
        The HandlerConfig object is used as a convenience container. The actual
        logging.Handler attached to the logger is handler.file_handler.
        """
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


class NetworkSecurityLogger(Logger):
    """
    Provides specialized logging for network security-related messages.

    This class extends a base Logger to handle and format logging specifically
    for security-related data. It supports logging at different levels such as
    warning, debug, and error, while also allowing the saving of logs to file.
    The log messages can be output to the console and/or a specific security log
    file, based on the handler configuration.

    :ivar logger: The logger instance used to write logs.
    :type logger: logging.Logger
    """

    def __init__(self, log_dir: Optional[str] = None):
        handlers: HandlerTypes = {
            "console_handler": HandlerConfig(
                "console", logging.INFO, Formatter("%(asctime)s [SECURITY] %(message)s")
            ),
            "security_handler": HandlerConfig(
                "security",
                logging.WARNING,
                Formatter("%(asctime)s [SECURITY] %(message)s"),
                filepath="security.log",
                log_dir=log_dir,
            ),
        }
        super().__init__(handlers=handlers, log_dir=log_dir)

    def log(self, message: str) -> None:
        """
        Log a security-related message at WARNING level.

        Args:
            message (str): The text to log. Should be concise and redact any
                sensitive data before calling.
        """
        self.logger.warning(message)

    def debug(self, message: str) -> None:
        """
        Log a security debug message.

        Only emitted if the logger level allows DEBUG.

        Args:
            message (str): Debug details useful for troubleshooting.
        """
        self.logger.debug(message)

    def error(self, message: str) -> None:
        """
        Log a security error message at ERROR level.

        Args:
            message (str): Description of the error condition.
        """
        self.logger.error(message)

    def save_logs(self, path: str):
        """
        Persist accumulated security logs to the specified path.

        Note: In most deployments handlers already write to files (e.g.,
        security.log). Override this in integrators if you need to export,
        rotate, or upload logs elsewhere.

        Args:
            path (str): Destination file or directory for saving/exporting logs.
        """
        # Implementation intentionally left as a no-op for now
        pass


class PerformanceLogger(Logger):
    """
    A logger for performance monitoring tasks.

    The PerformanceLogger class is designed to handle and manage performance-related
    logging efficiently. It extends the base Logger functionality, introducing specific
    handlers and configurations tailored for performance monitoring. It allows logging
    both to the console and to a dedicated performance log file in an easy and
    structured way.

    :ivar handlers: A dictionary containing configurations for the console and performance
        handlers. These handlers define where and how the performance logs are outputted.
    :type handlers: HandlerTypes
    """

    def __init__(self, log_dir: Optional[str] = None):
        handlers: HandlerTypes = {
            "console_handler": HandlerConfig(
                "console", logging.INFO, Formatter("%(asctime)s [PERF] %(message)s")
            ),
            "performance_handler": HandlerConfig(
                "performance",
                logging.INFO,
                Formatter("%(asctime)s [PERF] %(message)s"),
                filepath="performance.log",
                log_dir=log_dir,
            ),
        }
        super().__init__(handlers=handlers, log_dir=log_dir)

    def log(self, message: str) -> None:
        """
        Log a performance-related message at INFO level.

        Typical messages include timing, throughput, resource usage, or other
        metrics summaries.

        Args:
            message (str): Human-readable performance information.
        """
        self.logger.info(message)

    def save_logs(self, path: str):
        """
        Persist performance logs to the specified path.

        In many setups, handlers already stream to performance.log. Override to
        export or transform metrics (e.g., upload to time-series DB).

        Args:
            path (str): Destination file or directory for saving/exporting logs.
        """
        # Implementation intentionally left as a no-op for now
        pass

"""
Logging module
"""

import logging
import logging.handlers
import os
from abc import ABC, abstractmethod
from logging import Formatter, Handler
from pathlib import Path
from typing import Optional, TypedDict


class HandlerConfig(Handler):
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
            if log_dir:
                full_path = os.path.join(log_dir, filepath)
            else:
                full_path = filepath

            # Ensure directory exists
            os.makedirs(os.path.dirname(full_path), exist_ok=True)

            # Create the file handler
            self.file_handler = logging.handlers.RotatingFileHandler(
                full_path,
                maxBytes=max_bytes,
                backupCount=backup_count,
                mode='a'  # Append mode
            )
            
            if formatter:
                self.file_handler.setFormatter(formatter)
            
            # Set permissions on the log file
            try:
                os.chmod(full_path, 0o666)
            except Exception:
                pass  # Ignore permission errors

    def has_format(self) -> bool:
        """Check if the handler has a formatter set."""
        return self.formatter is not None or (
            self.file_handler is not None and self.file_handler.formatter is not None
        )


"""
HandlerTypes: typing dictionary for handler configuration
"""


class HandlerTypes(TypedDict, total=False):
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
    """
    Abstract base class for logging functionality.

    This class provides a basic structure to implement logging mechanisms through
    custom loggers. It allows setting a particular log format and logging handlers,
    enabling developers to manage logging processes with flexibility and separation
    of concerns. Extend this class to create specific types of loggers, implementing
    the required abstract methods while making use of its predefined setup logic.

    :ivar logger: Logger instance for handling log messages.
    :type logger: logging.Logger
    :ivar format: Format used for log messages.
    :type format: logging.Formatter
    :ivar handlers: Dictionary containing logging handlers for different logging
        destinations.
    :type handlers: dict
    :ivar log_dir: Base directory for log files. If provided, all file paths in handlers
        will be relative to this directory unless they are absolute paths.
    :type log_dir: str | None
    """

    def __init__(
        self,
        log_format: Optional[Formatter] = None,
        handlers: Optional[HandlerTypes] = None,
        log_dir: Optional[str] = None,
    ):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)

        self.format = log_format or logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s"
        )
        self.handlers = handlers or {}
        self.log_dir = log_dir

        self.set_handlers()

    @abstractmethod
    def log(self, message: str):
        pass

    @abstractmethod
    def save_logs(self):
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
                            self.log_dir
                        )

                # Set formatter if not already set
                if not handler.has_format():
                    handler.setFormatter(self.format)
                    if handler.file_handler:
                        handler.file_handler.setFormatter(self.format)

                # Add the file_handler to the logger if it exists
                if hasattr(handler, 'file_handler') and handler.file_handler:
                    self.logger.addHandler(handler.file_handler)


"""
NetworkSecurityLogger: custom logger for network security
"""


class NetworkSecurityLogger(Logger):
    """
    Handles logging for a network security application.

    The `NetworkSecurityLogger` class provides a specialized logging mechanism
    for a network security environment. It manages log handlers for various
    levels of logging such as informational messages, errors, security warnings,
    and packet-related debugging information. Each type of log is directed
    to an appropriate file or console output using specific formatting rules.

    :ivar handlers: A dictionary of handlers that includes different levels
        of logging options (console_handler, error_handler, security_handler,
        packet_handler) and their respective format configurations.
    :type handlers: HandlerTypes
    """

    def __init__(self):
        handlers: HandlerTypes = {
            "console_handler": HandlerConfig(
                "console", logging.INFO, Formatter("%(message)s")
            ),
            "error_handler": HandlerConfig(
                "error",
                logging.ERROR,
                Formatter("%(asctime)s [%(levelname)s] %(message)s"),
                filepath="logs/error.log",
            ),
            "security_handler": HandlerConfig(
                "security",
                logging.WARNING,
                Formatter("%(asctime)s [SECURITY] %(message)s"),
                filepath="logs/security.log",
            ),
            "packet_handler": HandlerConfig(
                "packet",
                logging.DEBUG,
                Formatter("%(asctime)s [PACKET] %(message)s"),
                filepath="logs/packets.log",
            ),
        }
        super().__init__(handlers=handlers)

    def log(self, message: str) -> None:
        self.logger.info(message)

    def debug(self, message: str) -> None:
        self.logger.debug(message)

    def error(self, message: str) -> None:
        self.logger.error(message)

    def save_logs(self):
        # Opcional: guardar en archivo manualmente si necesitas persistencia aparte
        pass
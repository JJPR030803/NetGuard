"""
Logging module for the sniffer component.

This module provides specialized logger classes for different handler types
used in the network security suite's sniffer module.
"""

import logging
from logging import Formatter
from typing import Optional

from ..utils.logger import HandlerConfig, HandlerTypes, Logger


class ConsoleLogger(Logger):
    """
    Logger for console output.

    This logger is designed for displaying log messages in the console
    with a simple format focused on readability.
    """

    def __init__(
        self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None
    ):
        handlers: HandlerTypes = {
            "console_handler": HandlerConfig(
                "console", logging.INFO, Formatter("%(message)s")
            )
        }
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

    def __init__(
        self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None
    ):
        handlers: HandlerTypes = {
            "security_handler": HandlerConfig(
                "security",
                logging.WARNING,
                Formatter("%(asctime)s [SECURITY] %(message)s"),
                filepath="logs/security.log",
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

    def __init__(
        self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None
    ):
        handlers: HandlerTypes = {
            "packet_handler": HandlerConfig(
                "packet",
                logging.DEBUG,
                Formatter("%(asctime)s [PACKET] %(message)s"),
                filepath="logs/packets.log",
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
        filepath: str = "logs/general.log",
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
        filepath: str = "logs/rotating.log",
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
        filepath: str = "logs/timed_rotating.log",
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

    def __init__(
        self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None
    ):
        handlers: HandlerTypes = {
            "error_handler": HandlerConfig(
                "error",
                logging.ERROR,
                Formatter("%(asctime)s [ERROR] %(message)s"),
                filepath="logs/error.log",
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

    def __init__(
        self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None
    ):
        handlers: HandlerTypes = {
            "debug_handler": HandlerConfig(
                "debug",
                logging.DEBUG,
                Formatter("%(asctime)s [DEBUG] %(message)s"),
                filepath="logs/debug.log",
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

    def __init__(
        self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None
    ):
        handlers: HandlerTypes = {
            "critical_handler": HandlerConfig(
                "critical",
                logging.CRITICAL,
                Formatter("%(asctime)s [CRITICAL] %(message)s"),
                filepath="logs/critical.log",
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

    def __init__(
        self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None
    ):
        handlers: HandlerTypes = {
            "warning_handler": HandlerConfig(
                "warning",
                logging.WARNING,
                Formatter("%(asctime)s [WARNING] %(message)s"),
                filepath="logs/warning.log",
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

    def __init__(
        self, log_format: Optional[Formatter] = None, log_dir: Optional[str] = None
    ):
        handlers: HandlerTypes = {
            "info_handler": HandlerConfig(
                "info",
                logging.INFO,
                Formatter("%(asctime)s [INFO] %(message)s"),
                filepath="logs/info.log",
                log_dir=log_dir,
            )
        }
        super().__init__(log_format=log_format, handlers=handlers, log_dir=log_dir)

    def log(self, message: str) -> None:
        self.logger.info(message)

    def save_logs(self):
        # Logs are automatically saved by the handler
        pass

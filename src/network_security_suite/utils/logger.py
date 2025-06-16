import logging
from abc import ABC, abstractmethod
from logging import Handler, Formatter
from typing import Optional, TypedDict, Literal
import logging.handlers

class HandlerEnum(Handler):
    def __init__(
        self,
        name: str,
        level: int = logging.INFO,
        formatter: Formatter | None = None,
        filepath: Optional[str] = None,
        max_bytes: int = 10485760,  # 10MB
        backup_count: int = 5
    ):
        super().__init__(level=level)
        self.name = name
        if formatter:
            self.setFormatter(formatter)
        
        if filepath:
            # Use RotatingFileHandler instead of FileHandler
            file_handler = logging.handlers.RotatingFileHandler(
                filepath,
                maxBytes=max_bytes,
                backupCount=backup_count
            )
            if formatter:
                file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)


class HandlerTypes(TypedDict, total=False):
    console_handler: HandlerEnum
    security_handler: HandlerEnum
    packet_handler: HandlerEnum
    file_handler: HandlerEnum
    rotating_file_handler: HandlerEnum
    timed_rotating_file_handler: HandlerEnum
    smtp_handler: HandlerEnum
    http_handler: HandlerEnum
    queue_handler: HandlerEnum
    error_handler: HandlerEnum
    debug_handler: HandlerEnum
    critical_handler: HandlerEnum
    warning_handler: HandlerEnum
    info_handler: HandlerEnum


class Logger(ABC):
    def __init__(
        self,
        log_format: Optional[Formatter] = None,
        handlers: Optional[HandlerTypes] = None,
    ):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)

        self.format = log_format or logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        self.handlers = handlers or {}

        self.set_handlers()

    @abstractmethod
    def log(self, message: str):
        pass

    @abstractmethod
    def save_logs(self):
        pass

    def set_handlers(self):
        for handler in self.handlers.values():
            if handler:
                if not handler.has_format():
                    handler.setFormatter(self.format)
            self.logger.addHandler(handler)


class NetworkSecurityLogger(Logger):
    def __init__(self):
        handlers: HandlerTypes = {
            "console_handler": HandlerEnum(
                "console",
                logging.INFO,
                Formatter("%(message)s")
            ),
            "error_handler": HandlerEnum(
                "error",
                logging.ERROR,
                Formatter("%(asctime)s [%(levelname)s] %(message)s"),
                filepath="logs/error.log"
            ),
            "security_handler": HandlerEnum(
                "security",
                logging.WARNING,
                Formatter("%(asctime)s [SECURITY] %(message)s"),
                filepath="logs/security.log"
            ),
            "packet_handler": HandlerEnum(
                "packet",
                logging.DEBUG,
                Formatter("%(asctime)s [PACKET] %(message)s"),
                filepath="logs/packets.log"
            )
        }
        super().__init__(handlers=handlers)

    def log(self, message: str)->None:
        self.logger.info(message)

    def debug(self, message: str)->None:
        self.logger.debug(message)

    def error(self,message:str)->None:
        self.logger.error(message)

    def save_logs(self):
        # Opcional: guardar en archivo manualmente si necesitas persistencia aparte
        pass
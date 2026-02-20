"""
Sniffer Configuration Module

This module provides the SnifferConfig class for managing all configuration aspects
of the network sniffer components. It handles loading configurations from YAML files,
saving configurations to YAML files, and provides default values for all settings.

The configuration is organized into several categories:
- Interface settings: Network interface selection and detection
- Capture settings: Packet capture parameters and filtering
- Logging configuration: Log levels, formats, and destinations
- Export settings: Data export formats and locations
- Performance settings: Performance monitoring and optimization
- Security settings: Security validations and sanitization

Example:
    # Create a default configuration
    config = SnifferConfig()

    # Load configuration from a YAML file
    config = SnifferConfig.from_yaml('path/to/config.yaml')

    # Access configuration values (read-only)
    print(config.interface)
    print(config.enable_security_logging)

    # This will raise an AttributeError (read-only):
    # config.interface = "wlan0"  ❌

    # To change config, create a new instance:
    new_config = SnifferConfig(interface="wlan0")  ✅

    # Save configuration to a YAML file
    config.to_yaml('path/to/new_config.yaml')

    # Generate a default configuration file
    SnifferConfig.generate_default_config('path/to/default_config.yaml')
"""

from pathlib import Path
from typing import Optional

import yaml

from netguard.core.paths import (
    get_log_dir,
    get_parquet_dir,
    get_performance_parquet_path,
)

__all__ = ["SnifferConfig"]


class SnifferConfig:
    """
    Configuration class for all network sniffer components.

    This class centralizes all configuration parameters for the network sniffer,
    providing a single point of configuration for interface selection, packet capture,
    logging, data export, performance monitoring, and security settings.

    All configuration values are READ-ONLY after initialization. To change configuration,
    create a new SnifferConfig instance with the desired values.

    When instantiated, the class ensures that all required directories exist,
    creating them if necessary.

    Attributes are organized into logical groups for easier management:
    - Interface settings
    - Capture settings
    - Logging configuration
    - Export settings
    - Performance settings
    - Security settings

    Constructor Parameters:
        All parameters are optional and have sensible defaults.

        Interface Settings:
        ------------------
        interface (str): Name of the network interface to use (e.g., "eth0", "wlan0").
            Default: "eth0"

        interface_detection_method (str): Method for detecting interfaces
            ("auto", "manual", "preferred_type"). Default: "auto"

        preferred_interface_types (List[str]): List of interface types in order
            of preference. Default: ["ethernet", "wireless"]


        Capture Settings:
        ----------------
        filter_expression (str): BPF filter expression for filtering packets.
                                Default: "" (no filtering)
        packet_count (int): Maximum number of packets to capture (0 = unlimited).
                           Default: 0


        timeout (int): Maximum time in seconds to capture packets (0 = no timeout).
                      Default: 0
        promiscuous_mode (bool): Whether to put the interface in promiscuous mode.
                                Default: True
        max_memory_packets (int): Maximum number of packets to store in memory.
                                 Must be at least 100 and a multiple of 10.
                                 Default: 10000
        max_processing_batch_size (int): Maximum number of packets to process in a single batch.
                                        Default: 100
        num_threads (int): Number of threads to use for packet processing.
                          Default: 4
        enable_realtime_display (bool): Whether to enable real-time display of captured packets.
                                      Default: False

        Logging Configuration:
        ---------------------
        log_level (str): Logging level ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL").
                        Default: "INFO"
        log_to_file (bool): Whether to write log messages to files.
                           Default: True
        log_dir (str): Directory where log files will be stored.
                      Default: from get_log_dir()
        log_format (str): Format string for log messages.
                         Default: "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        enable_console_logging (bool): Whether to enable logging to the console.
                                      Default: True
        enable_file_logging (bool): Whether to enable logging to files.
                                   Default: True
        enable_security_logging (bool): Whether to enable security-related logging.
                                       Default: True
        enable_packet_logging (bool): Whether to enable packet-level logging.
                                     Default: True
        enable_performance_logging (bool): Whether to enable performance metric logging.
                                          Default: True
        max_log_file_size (int): Maximum size of a log file in bytes before rotation.
                                Default: 10485760 (10MB)
        log_backup_count (int): Number of rotated log files to keep.
                               Default: 5

        Export Settings:
        --------------
        export_format (str): Format for exporting captured packet data ("parquet", "csv").
                            Default: "parquet"
        export_dir (str): Directory where exported packet data files will be stored.
                         Default: from get_parquet_dir()
        export_filename (str): Filename for the exported packet data file.
                              Default: "captured_packets.parquet"
                              Note: Extension will be automatically added if not present

        Performance Settings:
        -------------------
        enable_performance_monitoring (bool): Whether to enable performance monitoring.
                                             Default: True
        performance_log_interval (int): Interval in seconds between performance metric logging.
                                       Default: 60
        performance_parquet_path (str): Path to the Parquet file for performance metrics.
                                       Default: from get_performance_parquet_path()

        Security Settings:
        ----------------
        validate_interface_names (bool): Whether to validate network interface names.
                                        Default: True
        sanitize_filter_expressions (bool): Whether to sanitize BPF filter expressions.
                                           Default: True
        max_filter_length (int): Maximum allowed length for BPF filter expressions.
                                Default: 200

    Example:
        # Create a configuration with default values
        config = SnifferConfig()

        # Create a configuration with custom values
        config = SnifferConfig(
            interface="wlan0",
            packet_count=1000,
            log_level="DEBUG"
        )

        # Access values (read-only)
        print(config.interface)  # "wlan0"
        print(config.packet_count)  # 1000

        # Cannot modify after creation (read-only)
        # config.interface = "eth0"  # ❌ AttributeError

        # Use the configuration with a packet capture
        capture = PacketCapture(config=config)
    """

    def __init__(
        self,
        # Interface settings
        interface: str = "eth0",
        interface_detection_method: str = "auto",
        preferred_interface_types: Optional[list[str]] = None,
        # Capture settings
        filter_expression: str = "",
        packet_count: int = 0,
        timeout: int = 0,
        promiscuous_mode: bool = True,
        max_memory_packets: int = 10000,
        max_processing_batch_size: int = 100,
        num_threads: int = 4,
        enable_realtime_display: bool = False,
        # Logging settings
        log_level: str = "INFO",
        log_to_file: bool = True,
        log_dir: Optional[str] = None,
        log_format: str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        enable_console_logging: bool = True,
        enable_file_logging: bool = True,
        enable_security_logging: bool = True,
        enable_packet_logging: bool = True,
        enable_performance_logging: bool = True,
        max_log_file_size: int = 10485760,
        log_backup_count: int = 5,
        # Export settings
        export_format: str = "parquet",
        export_dir: Optional[str] = None,
        export_filename: str = "captured_packets.parquet",
        # Performance settings
        enable_performance_monitoring: bool = True,
        performance_log_interval: int = 60,
        performance_parquet_path: Optional[str] = None,
        # Security settings
        validate_interface_names: bool = True,
        sanitize_filter_expressions: bool = True,
        max_filter_length: int = 200,
    ):
        """
        Initialize SnifferConfig with the specified parameters.

        All parameters are stored in private attributes and exposed through
        read-only properties to prevent modification after initialization.
        """
        # Interface settings
        self._interface = interface
        self._interface_detection_method = interface_detection_method
        self._preferred_interface_types = (
            preferred_interface_types
            if preferred_interface_types is not None
            else ["ethernet", "wireless"]
        )

        # Capture settings
        self._filter_expression = filter_expression
        self._packet_count = packet_count
        self._timeout = timeout
        self._promiscuous_mode = promiscuous_mode
        self._max_memory_packets = max_memory_packets
        self._max_processing_batch_size = max_processing_batch_size
        self._num_threads = num_threads
        self._enable_realtime_display = enable_realtime_display

        # Logging settings
        self._log_level = log_level
        self._log_to_file = log_to_file
        self._log_dir = log_dir if log_dir is not None else str(get_log_dir())
        self._log_format = log_format
        self._enable_console_logging = enable_console_logging
        self._enable_file_logging = enable_file_logging
        self._enable_security_logging = enable_security_logging
        self._enable_packet_logging = enable_packet_logging
        self._enable_performance_logging = enable_performance_logging
        self._max_log_file_size = max_log_file_size
        self._log_backup_count = log_backup_count

        # Export settings
        self._export_format = export_format
        self._export_dir = export_dir if export_dir is not None else str(get_parquet_dir())
        self._export_filename = export_filename

        # Performance settings
        self._enable_performance_monitoring = enable_performance_monitoring
        self._performance_log_interval = performance_log_interval
        self._performance_parquet_path = (
            performance_parquet_path
            if performance_parquet_path is not None
            else str(get_performance_parquet_path())
        )

        # Security settings
        self._validate_interface_names = validate_interface_names
        self._sanitize_filter_expressions = sanitize_filter_expressions
        self._max_filter_length = max_filter_length

        # Ensure export filename has correct extension
        self._export_filename = self._ensure_extension(export_filename, export_format)

        # Validate all parameters
        self._validate_parameters()

        # Ensure directories exist
        self._ensure_directories()

    # ========================================================================
    # Validation Methods
    # ========================================================================

    def _validate_parameters(self) -> None:
        """
        Validate all configuration parameters.

        Raises:
            ValueError: If any parameter has an invalid value
        """
        # Validate packet_count
        if self._packet_count < 0:
            raise ValueError(f"packet_count must be non-negative, got {self._packet_count}")

        # Validate timeout
        if self._timeout < 0:
            raise ValueError(f"timeout must be non-negative, got {self._timeout}")

        # Validate num_threads
        if self._num_threads < 1:
            raise ValueError(f"num_threads must be at least 1, got {self._num_threads}")

        # Validate max_memory_packets
        if self._max_memory_packets < 100:
            raise ValueError(
                f"max_memory_packets must be at least 100, got {self._max_memory_packets}"
            )
        if self._max_memory_packets % 10 != 0:
            raise ValueError(
                f"max_memory_packets must be a multiple of 10, got {self._max_memory_packets}"
            )

        # Validate max_processing_batch_size
        if self._max_processing_batch_size < 1:
            raise ValueError(
                f"max_processing_batch_size must be at least 1, "
                f"got {self._max_processing_batch_size}"
            )

        # Validate log_level
        valid_log_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self._log_level.upper() not in valid_log_levels:
            raise ValueError(
                f"log_level must be one of {valid_log_levels}, got {self._log_level!r}"
            )
        self._log_level = self._log_level.upper()  # Normalize to uppercase

        # Validate export_format
        valid_formats = {"parquet", "csv"}
        if self._export_format.lower() not in valid_formats:
            raise ValueError(
                f"export_format must be one of {valid_formats}, got {self._export_format!r}"
            )
        self._export_format = self._export_format.lower()  # Normalize to lowercase

        # Validate interface_detection_method
        valid_methods = {"auto", "manual", "preferred_type"}
        if self._interface_detection_method not in valid_methods:
            raise ValueError(
                f"interface_detection_method must be one of {valid_methods}, "
                f"got {self._interface_detection_method!r}"
            )

        # Validate max_log_file_size
        if self._max_log_file_size < 1024:  # At least 1KB
            raise ValueError(
                f"max_log_file_size must be at least 1024 bytes, got {self._max_log_file_size}"
            )

        # Validate log_backup_count
        if self._log_backup_count < 0:
            raise ValueError(f"log_backup_count must be non-negative, got {self._log_backup_count}")

        # Validate performance_log_interval
        if self._performance_log_interval < 1:
            raise ValueError(
                f"performance_log_interval must be at least 1 second, "
                f"got {self._performance_log_interval}"
            )

        # Validate max_filter_length
        if self._max_filter_length < 1:
            raise ValueError(f"max_filter_length must be at least 1, got {self._max_filter_length}")

        # Validate interface name (if validation enabled)
        if self._validate_interface_names and (not self._interface or not self._interface.strip()):
            raise ValueError("interface name cannot be empty")

    def _ensure_extension(self, filename: str, format: str) -> str:
        """
        Ensure filename has the correct extension for the format.

        Args:
            filename: The filename to check
            format: The export format (parquet, csv)

        Returns:
            Filename with correct extension
        """
        expected_ext = f".{format}"
        if not filename.endswith(expected_ext):
            return f"{filename}{expected_ext}"
        return filename

    def _ensure_directories(self) -> None:
        """
        Ensure that all required directories exist.

        This method creates any missing directories that are specified in the
        configuration. It is called automatically during initialization.
        """
        # Create log directory if it doesn't exist
        Path(self._log_dir).mkdir(parents=True, exist_ok=True)

        # Create export directory if it doesn't exist
        Path(self._export_dir).mkdir(parents=True, exist_ok=True)

        # Create performance metrics directory if it doesn't exist
        performance_dir = Path(self._performance_parquet_path).parent
        if performance_dir != Path():
            performance_dir.mkdir(parents=True, exist_ok=True)

    # ========================================================================
    # Interface Settings Properties (Read-Only)
    # ========================================================================

    @property
    def interface(self) -> str:
        """Name of the network interface to use for packet capture."""
        return self._interface

    @property
    def interface_detection_method(self) -> str:
        """Method to use for detecting the network interface."""
        return self._interface_detection_method

    @property
    def preferred_interface_types(self) -> list[str]:
        """List of preferred interface types in order of preference."""
        return self._preferred_interface_types.copy()  # Return copy to prevent modification

    # ========================================================================
    # Capture Settings Properties (Read-Only)
    # ========================================================================

    @property
    def filter_expression(self) -> str:
        """BPF filter expression for filtering packets."""
        return self._filter_expression

    @property
    def packet_count(self) -> int:
        """Maximum number of packets to capture (0 = unlimited)."""
        return self._packet_count

    @property
    def timeout(self) -> int:
        """Maximum time in seconds to capture packets (0 = no timeout)."""
        return self._timeout

    @property
    def promiscuous_mode(self) -> bool:
        """Whether to put the interface in promiscuous mode."""
        return self._promiscuous_mode

    @property
    def max_memory_packets(self) -> int:
        """Maximum number of packets to store in memory."""
        return self._max_memory_packets

    @property
    def max_processing_batch_size(self) -> int:
        """Maximum number of packets to process in a single batch."""
        return self._max_processing_batch_size

    @property
    def num_threads(self) -> int:
        """Number of threads to use for packet processing."""
        return self._num_threads

    @property
    def enable_realtime_display(self) -> bool:
        """Whether to enable real-time display of captured packets."""
        return self._enable_realtime_display

    # ========================================================================
    # Logging Settings Properties (Read-Only)
    # ========================================================================

    @property
    def log_level(self) -> str:
        """Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)."""
        return self._log_level

    @property
    def log_to_file(self) -> bool:
        """Whether to write log messages to files."""
        return self._log_to_file

    @property
    def log_dir(self) -> str:
        """Directory where log files will be stored."""
        return self._log_dir

    @property
    def log_format(self) -> str:
        """Format string for log messages."""
        return self._log_format

    @property
    def enable_console_logging(self) -> bool:
        """Whether to enable logging to the console."""
        return self._enable_console_logging

    @property
    def enable_file_logging(self) -> bool:
        """Whether to enable logging to files."""
        return self._enable_file_logging

    @property
    def enable_security_logging(self) -> bool:
        """Whether to enable security-related logging."""
        return self._enable_security_logging

    @property
    def enable_packet_logging(self) -> bool:
        """Whether to enable packet-level logging."""
        return self._enable_packet_logging

    @property
    def enable_performance_logging(self) -> bool:
        """Whether to enable performance metric logging."""
        return self._enable_performance_logging

    @property
    def max_log_file_size(self) -> int:
        """Maximum size of a log file in bytes before rotation."""
        return self._max_log_file_size

    @property
    def log_backup_count(self) -> int:
        """Number of rotated log files to keep."""
        return self._log_backup_count

    # ========================================================================
    # Export Settings Properties (Read-Only)
    # ========================================================================

    @property
    def export_format(self) -> str:
        """Format for exporting captured packet data (parquet, csv)."""
        return self._export_format

    @property
    def export_dir(self) -> str:
        """Directory where exported packet data files will be stored."""
        return self._export_dir

    @property
    def export_filename(self) -> str:
        """Filename for the exported packet data file."""
        return self._export_filename

    @property
    def export_path(self) -> str:
        """
        Full path to the export file (directory + filename).

        This is a convenience property that combines export_dir and export_filename.
        """
        return str(Path(self._export_dir) / self._export_filename)

    # ========================================================================
    # Performance Settings Properties (Read-Only)
    # ========================================================================

    @property
    def enable_performance_monitoring(self) -> bool:
        """Whether to enable performance monitoring."""
        return self._enable_performance_monitoring

    @property
    def performance_log_interval(self) -> int:
        """Interval in seconds between performance metric logging."""
        return self._performance_log_interval

    @property
    def performance_parquet_path(self) -> str:
        """Path to the Parquet file for performance metrics."""
        return self._performance_parquet_path

    # ========================================================================
    # Security Settings Properties (Read-Only)
    # ========================================================================

    @property
    def validate_interface_names(self) -> bool:
        """Whether to validate network interface names."""
        return self._validate_interface_names

    @property
    def sanitize_filter_expressions(self) -> bool:
        """Whether to sanitize BPF filter expressions."""
        return self._sanitize_filter_expressions

    @property
    def max_filter_length(self) -> int:
        """Maximum allowed length for BPF filter expressions."""
        return self._max_filter_length

    # ========================================================================
    # Class Methods
    # ========================================================================

    @classmethod
    def from_yaml(cls, yaml_file: str) -> "SnifferConfig":
        """
        Load configuration from a YAML file.

        This method reads a YAML configuration file and creates a new SnifferConfig
        instance with the values from the file. Any values not specified in the
        YAML file will use their default values.

        The YAML file should have the following structure:

        ```yaml
        interface:
          name: "eth0"
          detection_method: "auto"
          preferred_types:
            - "ethernet"
            - "wireless"

        capture:
          filter_expression: ""
          packet_count: 0
          timeout: 0
          promiscuous_mode: true
          max_memory_packets: 10000
          max_processing_batch_size: 100
          num_threads: 4
          enable_realtime_display: false

        logging:
          level: "INFO"
          log_to_file: true
          log_dir: "/path/to/logs"
          log_format: "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
          enable_console_logging: true
          enable_file_logging: true
          enable_security_logging: true
          enable_packet_logging: true
          enable_performance_logging: true
          max_log_file_size: 10485760
          log_backup_count: 5

        export:
          format: "parquet"
          dir: "/path/to/exports"

        performance:
          enable_monitoring: true
          log_interval: 60
          parquet_path: "/path/to/performance_metrics.parquet"

        security:
          validate_interface_names: true
          sanitize_filter_expressions: true
          max_filter_length: 200
        ```

        Args:
            yaml_file: Path to the YAML configuration file to load

        Returns:
            A new SnifferConfig instance with values from the YAML file

        Raises:
            FileNotFoundError: If the specified YAML file does not exist
            yaml.YAMLError: If the YAML file is malformed

        Example:
            ```python
            # Load configuration from a file
            config = SnifferConfig.from_yaml('configs/my_config.yaml')

            # Use the loaded configuration
            print(config.interface)
            print(config.packet_count)
            ```
        """
        with Path(yaml_file).open() as f:
            config_data = yaml.safe_load(f)

        # Initialize with defaults
        config_dict = {}

        # Parse interface settings
        if "interface" in config_data:
            interface_config = config_data["interface"]
            if "name" in interface_config:
                config_dict["interface"] = interface_config["name"]
            if "detection_method" in interface_config:
                config_dict["interface_detection_method"] = interface_config["detection_method"]
            if "preferred_types" in interface_config:
                config_dict["preferred_interface_types"] = interface_config["preferred_types"]

        # Parse capture settings
        if "capture" in config_data:
            capture_config = config_data["capture"]
            if "filter_expression" in capture_config:
                config_dict["filter_expression"] = capture_config["filter_expression"]
            if "packet_count" in capture_config:
                config_dict["packet_count"] = capture_config["packet_count"]
            if "timeout" in capture_config:
                config_dict["timeout"] = capture_config["timeout"]
            if "promiscuous_mode" in capture_config:
                config_dict["promiscuous_mode"] = capture_config["promiscuous_mode"]
            if "max_memory_packets" in capture_config:
                config_dict["max_memory_packets"] = capture_config["max_memory_packets"]
            if "max_processing_batch_size" in capture_config:
                config_dict["max_processing_batch_size"] = capture_config[
                    "max_processing_batch_size"
                ]
            if "num_threads" in capture_config:
                config_dict["num_threads"] = capture_config["num_threads"]
            if "enable_realtime_display" in capture_config:
                config_dict["enable_realtime_display"] = capture_config["enable_realtime_display"]

        # Parse logging settings
        if "logging" in config_data:
            logging_config = config_data["logging"]
            if "level" in logging_config:
                config_dict["log_level"] = logging_config["level"]
            if "log_to_file" in logging_config:
                config_dict["log_to_file"] = logging_config["log_to_file"]
            if "log_dir" in logging_config:
                config_dict["log_dir"] = logging_config["log_dir"]
            if "log_format" in logging_config:
                config_dict["log_format"] = logging_config["log_format"]
            if "enable_console_logging" in logging_config:
                config_dict["enable_console_logging"] = logging_config["enable_console_logging"]
            if "enable_file_logging" in logging_config:
                config_dict["enable_file_logging"] = logging_config["enable_file_logging"]
            if "enable_security_logging" in logging_config:
                config_dict["enable_security_logging"] = logging_config["enable_security_logging"]
            if "enable_packet_logging" in logging_config:
                config_dict["enable_packet_logging"] = logging_config["enable_packet_logging"]
            if "enable_performance_logging" in logging_config:
                config_dict["enable_performance_logging"] = logging_config[
                    "enable_performance_logging"
                ]
            if "max_log_file_size" in logging_config:
                config_dict["max_log_file_size"] = logging_config["max_log_file_size"]
            if "log_backup_count" in logging_config:
                config_dict["log_backup_count"] = logging_config["log_backup_count"]

        # Parse export settings
        if "export" in config_data:
            export_config = config_data["export"]
            if "format" in export_config:
                config_dict["export_format"] = export_config["format"]
            if "dir" in export_config:
                config_dict["export_dir"] = export_config["dir"]
            if "filename" in export_config:
                config_dict["export_filename"] = export_config["filename"]

        # Parse performance settings
        if "performance" in config_data:
            performance_config = config_data["performance"]
            if "enable_monitoring" in performance_config:
                config_dict["enable_performance_monitoring"] = performance_config[
                    "enable_monitoring"
                ]
            if "log_interval" in performance_config:
                config_dict["performance_log_interval"] = performance_config["log_interval"]
            if "parquet_path" in performance_config:
                config_dict["performance_parquet_path"] = performance_config["parquet_path"]

        # Parse security settings
        if "security" in config_data:
            security_config = config_data["security"]
            if "validate_interface_names" in security_config:
                config_dict["validate_interface_names"] = security_config[
                    "validate_interface_names"
                ]
            if "sanitize_filter_expressions" in security_config:
                config_dict["sanitize_filter_expressions"] = security_config[
                    "sanitize_filter_expressions"
                ]
            if "max_filter_length" in security_config:
                config_dict["max_filter_length"] = security_config["max_filter_length"]

        # Create a new instance with the loaded values
        return cls(**config_dict)

    def to_yaml(self, yaml_file: str) -> None:
        """
        Save configuration to a YAML file.

        This method saves the current configuration to a YAML file with a nested structure
        that matches the logical organization of the configuration attributes. The resulting
        YAML file can be loaded later using the from_yaml method.

        The method ensures that the directory containing the YAML file exists, creating it
        if necessary.

        Args:
            yaml_file: Path to the YAML configuration file to be created or overwritten

        Example:
            ```python
            # Create a configuration
            config = SnifferConfig(interface="wlan0", packet_count=1000)

            # Save it to a file
            config.to_yaml('configs/my_config.yaml')
            ```
        """
        # Convert to nested dictionary structure
        config_dict = {
            "interface": {
                "name": self.interface,
                "detection_method": self.interface_detection_method,
                "preferred_types": self.preferred_interface_types,
            },
            "capture": {
                "filter_expression": self.filter_expression,
                "packet_count": self.packet_count,
                "timeout": self.timeout,
                "promiscuous_mode": self.promiscuous_mode,
                "max_memory_packets": self.max_memory_packets,
                "max_processing_batch_size": self.max_processing_batch_size,
                "num_threads": self.num_threads,
                "enable_realtime_display": self.enable_realtime_display,
            },
            "logging": {
                "level": self.log_level,
                "log_to_file": self.log_to_file,
                "log_dir": self.log_dir,
                "log_format": self.log_format,
                "enable_console_logging": self.enable_console_logging,
                "enable_file_logging": self.enable_file_logging,
                "enable_security_logging": self.enable_security_logging,
                "enable_packet_logging": self.enable_packet_logging,
                "enable_performance_logging": self.enable_performance_logging,
                "max_log_file_size": self.max_log_file_size,
                "log_backup_count": self.log_backup_count,
            },
            "export": {
                "format": self.export_format,
                "dir": self.export_dir,
                "filename": self.export_filename,
            },
            "performance": {
                "enable_monitoring": self.enable_performance_monitoring,
                "log_interval": self.performance_log_interval,
                "parquet_path": self.performance_parquet_path,
            },
            "security": {
                "validate_interface_names": self.validate_interface_names,
                "sanitize_filter_expressions": self.sanitize_filter_expressions,
                "max_filter_length": self.max_filter_length,
            },
        }

        # Ensure directory exists
        yaml_path = Path(yaml_file)
        if yaml_path.parent != Path():
            yaml_path.parent.mkdir(parents=True, exist_ok=True)

        # Write to file
        with yaml_path.open("w") as f:
            yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False)

    @classmethod
    def generate_default_config(cls, yaml_file: str) -> None:
        """
        Generate a default configuration file.

        This method creates a new SnifferConfig instance with default values and
        saves it to the specified YAML file. It's useful for creating initial
        configuration files that users can then modify according to their needs.

        Args:
            yaml_file: Path to the YAML configuration file to be created

        Example:
            ```python
            # Generate a default configuration file
            SnifferConfig.generate_default_config('configs/default_config.yaml')

            # Later, load and modify it
            config = SnifferConfig.from_yaml('configs/default_config.yaml')
            ```

        Note:
            This method will overwrite the file if it already exists.
            Should be used only once to generate the default configuration.
        """
        config = cls()
        config.to_yaml(yaml_file)
        print("Default configuration file generated successfully.\nAt:", yaml_file, "\n")

    def __str__(self) -> str:
        """Return a human-readable string representation of the configuration."""
        return f"""SnifferConfig:
          Interface Settings:
            - Interface: {self.interface}
            - Detection Method: {self.interface_detection_method}
            - Preferred Types: {", ".join(self.preferred_interface_types)}

          Capture Settings:
            - Filter Expression: {self.filter_expression if self.filter_expression else "None"}
            - Packet Count: {self.packet_count if self.packet_count > 0 else "Unlimited"}
            - Timeout: {self.timeout if self.timeout > 0 else "None"}
            - Promiscuous Mode: {self.promiscuous_mode}
            - Max Memory Packets: {self.max_memory_packets}
            - Batch Size: {self.max_processing_batch_size}
            - Threads: {self.num_threads}
            - Real-time Display: {self.enable_realtime_display}

          Logging Settings:
            - Log Level: {self.log_level}
            - Log Directory: {self.log_dir}
            - Log to File: {self.log_to_file}
            - Console Logging: {self.enable_console_logging}
            - File Logging: {self.enable_file_logging}
            - Security Logging: {self.enable_security_logging}
            - Packet Logging: {self.enable_packet_logging}
            - Performance Logging: {self.enable_performance_logging}
            - Max File Size: {self.max_log_file_size} bytes
            - Backup Count: {self.log_backup_count}

          Export Settings:
            - Format: {self.export_format}
            - Directory: {self.export_dir}
            - Filename: {self.export_filename}
            - Full Path: {self.export_path}

          Performance Settings:
            - Monitoring Enabled: {self.enable_performance_monitoring}
            - Log Interval: {self.performance_log_interval} seconds
            - Metrics Path: {self.performance_parquet_path}

          Security Settings:
            - Validate Interface Names: {self.validate_interface_names}
            - Sanitize Filter Expressions: {self.sanitize_filter_expressions}
            - Max Filter Length: {self.max_filter_length}"""

    def __repr__(self) -> str:
        """Return a detailed representation of the configuration."""
        return (
            f"SnifferConfig("
            f"interface={self.interface!r}, "
            f"packet_count={self.packet_count}, "
            f"log_level={self.log_level!r})"
        )

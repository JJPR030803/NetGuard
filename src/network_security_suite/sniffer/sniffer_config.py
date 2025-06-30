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

    # Save configuration to a YAML file
    config.to_yaml('path/to/new_config.yaml')

    # Generate a default configuration file
    SnifferConfig.generate_default_config('path/to/default_config.yaml')
"""
import os
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict

@dataclass
class SnifferConfig:
    """
    Configuration class for all network sniffer components.

    This class centralizes all configuration parameters for the network sniffer,
    providing a single point of configuration for interface selection, packet capture,
    logging, data export, performance monitoring, and security settings.

    The class is implemented as a dataclass with default values for all parameters,
    making it easy to create a working configuration with minimal setup. It also
    provides methods for loading configurations from YAML files and saving
    configurations to YAML files.

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
        interface_detection_method (str): Method for detecting interfaces ("auto", "manual", "preferred_type").
                                         Default: "auto"
        preferred_interface_types (List[str]): List of interface types in order of preference.
                                              Default: ["ethernet", "wireless"]

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

        Logging Configuration:
        ---------------------
        log_level (str): Logging level ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL").
                        Default: "INFO"
        log_to_file (bool): Whether to write log messages to files.
                           Default: True
        log_dir (str): Directory where log files will be stored.
                      Default: "/home/batman/Documents/networkguard2/logs/logs"
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
                         Default: "/home/batman/Documents/networkguard2/logs/parquet"

        Performance Settings:
        -------------------
        enable_performance_monitoring (bool): Whether to enable performance monitoring.
                                             Default: True
        performance_log_interval (int): Interval in seconds between performance metric logging.
                                       Default: 60
        performance_parquet_path (str): Path to the Parquet file for performance metrics.
                                       Default: "/home/batman/Documents/networkguard2/logs/performance_metrics/perf_metrics.parquet"

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

        # Use the configuration with a packet capture
        capture = PacketCapture(config=config)
    """

    # Interface settings
    interface: str = "eth0"
    """
    Name of the network interface to use for packet capture.

    This is the name of the network interface as recognized by the operating system
    (e.g., 'eth0', 'wlan0', 'en0'). If interface_detection_method is set to 'manual',
    this value will be used directly. Otherwise, it may be overridden by the
    automatic interface detection.

    Default: "eth0"
    """

    interface_detection_method: str = "auto"
    """
    Method to use for detecting the network interface.

    Valid values:
    - 'auto': Automatically select the best available interface
    - 'manual': Use the interface specified in the 'interface' attribute
    - 'preferred_type': Select an interface based on the types in 'preferred_interface_types'

    Default: "auto"
    """

    preferred_interface_types: List[str] = field(default_factory=lambda: ["ethernet", "wireless"])
    """
    List of preferred interface types in order of preference.

    Used when interface_detection_method is 'preferred_type' to select an interface
    based on its type. The first matching interface type in the list will be selected.

    Common types include:
    - 'ethernet': Wired Ethernet interfaces
    - 'wireless': Wi-Fi interfaces
    - 'loopback': Loopback interfaces (for testing)
    - 'virtual': Virtual interfaces

    Default: ["ethernet", "wireless"]
    """

    # Capture settings
    filter_expression: str = ""
    """
    Berkeley Packet Filter (BPF) expression for filtering captured packets.

    This expression follows the BPF syntax and allows filtering packets based on
    various criteria such as protocol, port, host, etc. For example:
    - "tcp port 80": Capture only TCP traffic on port 80
    - "host 192.168.1.1": Capture only traffic to/from the specified host
    - "icmp": Capture only ICMP packets

    An empty string means no filtering (capture all packets).

    Default: "" (no filtering)
    """

    packet_count: int = 0
    """
    Maximum number of packets to capture before stopping.

    If set to 0, packet capture will continue indefinitely until stopped manually
    or by timeout.

    Default: 0 (unlimited)
    """

    timeout: int = 0
    """
    Maximum time in seconds to capture packets before stopping.

    If set to 0, packet capture will continue indefinitely until stopped manually
    or by reaching packet_count.

    Default: 0 (no timeout)
    """

    promiscuous_mode: bool = True
    """
    Whether to put the network interface in promiscuous mode.

    In promiscuous mode, the interface captures all packets on the network segment,
    not just those addressed to it. This is typically required for network analysis
    but may require elevated privileges.

    Default: True
    """

    max_memory_packets: int = 10000
    """
    Maximum number of packets to store in memory.

    This limits the memory usage of the packet capture. Once this limit is reached,
    older packets may be discarded to make room for new ones, depending on the
    implementation.

    Must be at least 100 and a multiple of 10 for efficient processing.

    Default: 10000
    """

    max_processing_batch_size: int = 100
    """
    Maximum number of packets to process in a single batch.

    This affects the performance and responsiveness of the packet processing.
    Larger batches may be more efficient but can cause longer processing delays.

    Default: 100
    """

    num_threads: int = 4
    """
    Number of threads to use for packet processing.

    More threads can improve performance on multi-core systems but may increase
    overhead and complexity. The optimal value depends on the system's hardware
    and the specific workload.

    Default: 4
    """

    # Logging configuration
    log_level: str = "INFO"
    """
    Logging level for the application.

    Controls the verbosity of log messages. Valid values (in increasing order of verbosity):
    - "CRITICAL": Only critical errors that prevent the application from running
    - "ERROR": Errors that allow the application to continue but with reduced functionality
    - "WARNING": Warnings about potential issues or unexpected behavior
    - "INFO": General information about the application's operation
    - "DEBUG": Detailed information for debugging purposes

    Default: "INFO"
    """

    log_to_file: bool = True
    """
    Whether to write log messages to files.

    If True, log messages will be written to files in the directory specified by log_dir.
    If False, log messages will only be written to the console (if enabled).

    Default: True
    """

    log_dir: str = "/home/batman/Documents/networkguard2/logs/logs"
    """
    Directory where log files will be stored.

    This directory will be created if it doesn't exist when the configuration is initialized.

    Default: "/home/batman/Documents/networkguard2/logs/logs"
    """

    log_format: str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    """
    Format string for log messages.

    This follows the Python logging module's format string syntax. Common format specifiers:
    - %(asctime)s: Timestamp
    - %(levelname)s: Log level (INFO, DEBUG, etc.)
    - %(name)s: Logger name
    - %(message)s: Log message

    Default: "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    """

    # Logger-specific settings
    enable_console_logging: bool = True
    """
    Whether to enable logging to the console.

    If True, log messages will be printed to the console (stdout/stderr).

    Default: True
    """

    enable_file_logging: bool = True
    """
    Whether to enable logging to files.

    This is separate from log_to_file and provides finer control over which
    logging systems are active.

    Default: True
    """

    enable_security_logging: bool = True
    """
    Whether to enable security-related logging.

    If True, security events such as authentication attempts, permission changes,
    and potential security violations will be logged.

    Default: True
    """

    enable_packet_logging: bool = True
    """
    Whether to enable packet-level logging.

    If True, details about captured packets will be logged. This can generate
    a large volume of log data with high packet rates.

    Default: True
    """

    enable_performance_logging: bool = True
    """
    Whether to enable performance metric logging.

    If True, performance metrics such as processing time, memory usage,
    and throughput will be logged.

    Default: True
    """

    # File rotation settings
    max_log_file_size: int = 10485760  # 10MB
    """
    Maximum size of a log file in bytes before it is rotated.

    When a log file reaches this size, it will be renamed with a timestamp
    and a new log file will be created. This prevents log files from growing
    indefinitely.

    Default: 10485760 (10MB)
    """

    log_backup_count: int = 5
    """
    Number of rotated log files to keep.

    When log files are rotated, this controls how many old log files are kept
    before the oldest ones are deleted.

    Default: 5
    """

    # Export settings
    export_format: str = "parquet"
    """
    Format for exporting captured packet data.

    Valid values:
    - "parquet": Apache Parquet format (columnar storage, efficient for analytics)
    - "csv": Comma-separated values (more compatible but less efficient)

    Default: "parquet"
    """

    export_dir: str = "/home/batman/Documents/networkguard2/logs/parquet"
    """
    Directory where exported packet data files will be stored.

    This directory will be created if it doesn't exist when the configuration is initialized.

    Default: "/home/batman/Documents/networkguard2/logs/parquet"
    """

    # Performance settings
    enable_performance_monitoring: bool = True
    """
    Whether to enable performance monitoring.

    If True, the application will collect and log performance metrics such as
    CPU usage, memory usage, packet processing rates, etc.

    Default: True
    """

    performance_log_interval: int = 60  # seconds
    """
    Interval in seconds between performance metric logging.

    Controls how frequently performance metrics are collected and logged.
    Lower values provide more detailed monitoring but increase overhead.

    Default: 60 (seconds)
    """

    performance_parquet_path: str = "/home/batman/Documents/networkguard2/logs/performance_metrics/perf_metrics.parquet"
    """
    Path to the Parquet file where performance metrics will be stored.

    Performance metrics are stored in Parquet format for efficient storage and analysis.
    The directory containing this file will be created if it doesn't exist.

    Default: "/home/batman/Documents/networkguard2/logs/performance_metrics/perf_metrics.parquet"
    """

    # Security settings
    validate_interface_names: bool = True
    """
    Whether to validate network interface names.

    If True, interface names will be validated to ensure they match the pattern
    of valid interface names for the current operating system. This helps prevent
    command injection attacks.

    Default: True
    """

    sanitize_filter_expressions: bool = True
    """
    Whether to sanitize BPF filter expressions.

    If True, filter expressions will be sanitized to remove potentially dangerous
    characters or patterns. This helps prevent injection attacks.

    Default: True
    """

    max_filter_length: int = 200
    """
    Maximum allowed length for BPF filter expressions.

    This limits the complexity of filter expressions to prevent performance issues
    and potential denial-of-service attacks with extremely complex filters.

    Default: 200
    """

    def __post_init__(self):
        """
        Initialize the configuration after all attributes are set.

        This method is automatically called by the dataclass after the object is created.
        It ensures that all required directories exist, creating them if necessary.

        The following directories are created:
        - log_dir (if log_to_file is True)
        - export_dir
        - The directory containing performance_parquet_path

        This ensures that the application can write to these directories without errors.
        """
        if self.log_to_file:
            Path(self.log_dir).mkdir(parents=True, exist_ok=True)
        Path(self.export_dir).mkdir(parents=True, exist_ok=True)
        Path(os.path.dirname(self.performance_parquet_path)).mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_yaml(cls, yaml_file: str) -> 'SnifferConfig':
        """
        Load configuration from a YAML file.

        This method reads a YAML configuration file and creates a SnifferConfig object
        with the values from the file. If the file doesn't exist or is empty, a default
        configuration is returned.

        The YAML file should have a nested structure with sections corresponding to the
        configuration categories:

        ```yaml
        # Example YAML structure
        interface:
          name: "eth0"
          detection_method: "auto"
          preferred_types:
            - "ethernet"
            - "wireless"

        capture:
          filter_expression: "tcp port 80"
          packet_count: 1000
          # ...

        logging:
          level: "DEBUG"
          # ...

        # ... other sections
        ```

        Args:
            yaml_file: Path to the YAML configuration file

        Returns:
            SnifferConfig: Configuration object with values from the YAML file.
                           If the file doesn't exist or is empty, returns a default configuration.

        Example:
            ```python
            # Load configuration from a file
            config = SnifferConfig.from_yaml('configs/sniffer_config.yaml')

            # Use the configuration
            capture = PacketCapture(config=config)
            ```
        """
        if not os.path.exists(yaml_file):
            print(f"Warning: Configuration file {yaml_file} not found. Using default configuration.")
            return cls()

        with open(yaml_file, 'r') as f:
            config_data = yaml.safe_load(f)

        if not config_data:
            return cls()

        # Extract values from nested YAML structure
        config_dict = {}

        # Interface settings
        if 'interface' in config_data:
            interface_config = config_data['interface']
            if 'name' in interface_config:
                config_dict['interface'] = interface_config['name']
            if 'detection_method' in interface_config:
                config_dict['interface_detection_method'] = interface_config['detection_method']
            if 'preferred_types' in interface_config:
                config_dict['preferred_interface_types'] = interface_config['preferred_types']

        # Capture settings
        if 'capture' in config_data:
            capture_config = config_data['capture']
            if 'filter_expression' in capture_config:
                config_dict['filter_expression'] = capture_config['filter_expression']
            if 'packet_count' in capture_config:
                config_dict['packet_count'] = capture_config['packet_count']
            if 'timeout' in capture_config:
                config_dict['timeout'] = capture_config['timeout']
            if 'promiscuous_mode' in capture_config:
                config_dict['promiscuous_mode'] = capture_config['promiscuous_mode']
            if 'max_memory_packets' in capture_config:
                config_dict['max_memory_packets'] = capture_config['max_memory_packets']
            if 'max_processing_batch_size' in capture_config:
                config_dict['max_processing_batch_size'] = capture_config['max_processing_batch_size']
            if 'num_threads' in capture_config:
                config_dict['num_threads'] = capture_config['num_threads']

        # Logging configuration
        if 'logging' in config_data:
            logging_config = config_data['logging']
            if 'level' in logging_config:
                config_dict['log_level'] = logging_config['level']
            if 'log_to_file' in logging_config:
                config_dict['log_to_file'] = logging_config['log_to_file']
            if 'log_dir' in logging_config:
                config_dict['log_dir'] = logging_config['log_dir']
            if 'log_format' in logging_config:
                config_dict['log_format'] = logging_config['log_format']
            if 'enable_console_logging' in logging_config:
                config_dict['enable_console_logging'] = logging_config['enable_console_logging']
            if 'enable_file_logging' in logging_config:
                config_dict['enable_file_logging'] = logging_config['enable_file_logging']
            if 'enable_security_logging' in logging_config:
                config_dict['enable_security_logging'] = logging_config['enable_security_logging']
            if 'enable_packet_logging' in logging_config:
                config_dict['enable_packet_logging'] = logging_config['enable_packet_logging']
            if 'enable_performance_logging' in logging_config:
                config_dict['enable_performance_logging'] = logging_config['enable_performance_logging']
            if 'max_log_file_size' in logging_config:
                config_dict['max_log_file_size'] = logging_config['max_log_file_size']
            if 'log_backup_count' in logging_config:
                config_dict['log_backup_count'] = logging_config['log_backup_count']

        # Export settings
        if 'export' in config_data:
            export_config = config_data['export']
            if 'format' in export_config:
                config_dict['export_format'] = export_config['format']
            if 'dir' in export_config:
                config_dict['export_dir'] = export_config['dir']

        # Performance settings
        if 'performance' in config_data:
            performance_config = config_data['performance']
            if 'enable_monitoring' in performance_config:
                config_dict['enable_performance_monitoring'] = performance_config['enable_monitoring']
            if 'log_interval' in performance_config:
                config_dict['performance_log_interval'] = performance_config['log_interval']
            if 'parquet_path' in performance_config:
                config_dict['performance_parquet_path'] = performance_config['parquet_path']

        # Security settings
        if 'security' in config_data:
            security_config = config_data['security']
            if 'validate_interface_names' in security_config:
                config_dict['validate_interface_names'] = security_config['validate_interface_names']
            if 'sanitize_filter_expressions' in security_config:
                config_dict['sanitize_filter_expressions'] = security_config['sanitize_filter_expressions']
            if 'max_filter_length' in security_config:
                config_dict['max_filter_length'] = security_config['max_filter_length']

        # Create a new instance with the loaded values
        config = cls(**config_dict)
        return config

    def to_yaml(self, yaml_file: str) -> None:
        """
        Save configuration to a YAML file.

        This method saves the current configuration to a YAML file with a nested structure
        that matches the logical organization of the configuration attributes. The resulting
        YAML file can be loaded later using the from_yaml method.

        The method ensures that the directory containing the YAML file exists, creating it
        if necessary.

        The YAML file will have the following structure:

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
          # ... other capture settings

        logging:
          level: "INFO"
          # ... other logging settings

        # ... other configuration sections
        ```

        Args:
            yaml_file: Path to the YAML configuration file to be created or overwritten

        Returns:
            None

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
            'interface': {
                'name': self.interface,
                'detection_method': self.interface_detection_method,
                'preferred_types': self.preferred_interface_types
            },
            'capture': {
                'filter_expression': self.filter_expression,
                'packet_count': self.packet_count,
                'timeout': self.timeout,
                'promiscuous_mode': self.promiscuous_mode,
                'max_memory_packets': self.max_memory_packets,
                'max_processing_batch_size': self.max_processing_batch_size,
                'num_threads': self.num_threads
            },
            'logging': {
                'level': self.log_level,
                'log_to_file': self.log_to_file,
                'log_dir': self.log_dir,
                'log_format': self.log_format,
                'enable_console_logging': self.enable_console_logging,
                'enable_file_logging': self.enable_file_logging,
                'enable_security_logging': self.enable_security_logging,
                'enable_packet_logging': self.enable_packet_logging,
                'enable_performance_logging': self.enable_performance_logging,
                'max_log_file_size': self.max_log_file_size,
                'log_backup_count': self.log_backup_count
            },
            'export': {
                'format': self.export_format,
                'dir': self.export_dir
            },
            'performance': {
                'enable_monitoring': self.enable_performance_monitoring,
                'log_interval': self.performance_log_interval,
                'parquet_path': self.performance_parquet_path
            },
            'security': {
                'validate_interface_names': self.validate_interface_names,
                'sanitize_filter_expressions': self.sanitize_filter_expressions,
                'max_filter_length': self.max_filter_length
            }
        }

        # Ensure directory exists
        os.makedirs(os.path.dirname(yaml_file), exist_ok=True)

        # Write to file
        with open(yaml_file, 'w') as f:
            yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False)

    @classmethod
    def generate_default_config(cls, yaml_file: str) -> None:
        """
        Generate a default configuration file.

        This method creates a new SnifferConfig instance with default values and
        saves it to the specified YAML file. It's useful for creating initial
        configuration files that users can then modify according to their needs.

        The method ensures that the directory containing the YAML file exists,
        creating it if necessary.

        Args:
            yaml_file: Path to the YAML configuration file to be created

        Returns:
            None

        Example:
            ```python
            # Generate a default configuration file
            SnifferConfig.generate_default_config('configs/default_config.yaml')

            # Later, load and modify it
            config = SnifferConfig.from_yaml('configs/default_config.yaml')
            config.interface = "wlan0"
            config.to_yaml('configs/modified_config.yaml')
            ```

        Note:
            This method will overwrite the file if it already exists. Use with caution
            to avoid losing existing configurations.
        """
        config = cls()
        config.to_yaml(yaml_file)

    def __str__(self):
        """Return a human-readable string representation of the configuration."""
        return f"""SnifferConfig:
          Interface Settings:
            - Interface: {self.interface}
            - Detection Method: {self.interface_detection_method}
            - Preferred Types: {', '.join(self.preferred_interface_types)}

          Capture Settings:
            - Filter Expression: {self.filter_expression if self.filter_expression else 'None'}
            - Packet Count: {self.packet_count if self.packet_count > 0 else 'Unlimited'}
            - Timeout: {self.timeout if self.timeout > 0 else 'None'}
            - Promiscuous Mode: {self.promiscuous_mode}
            - Max Memory Packets: {self.max_memory_packets}
            - Batch Size: {self.max_processing_batch_size}
            - Threads: {self.num_threads}

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

          Performance Settings:
            - Monitoring Enabled: {self.enable_performance_monitoring}
            - Log Interval: {self.performance_log_interval} seconds
            - Metrics Path: {self.performance_parquet_path}

          Security Settings:
            - Validate Interface Names: {self.validate_interface_names}
            - Sanitize Filter Expressions: {self.sanitize_filter_expressions}
            - Max Filter Length: {self.max_filter_length}"""

"""
Class for handling different sniffer configurations.
"""
import os
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict

@dataclass
class SnifferConfig:
    """Enhanced configuration class for all sniffer components."""

    # Interface settings
    interface: str = "eth0"
    interface_detection_method: str = "auto"  # auto, manual, preferred_type
    preferred_interface_types: List[str] = field(default_factory=lambda: ["ethernet", "wireless"])

    # Capture settings
    filter_expression: str = ""
    packet_count: int = 0
    timeout: int = 0
    promiscuous_mode: bool = True
    max_memory_packets: int = 10000
    max_processing_batch_size: int = 100
    num_threads: int = 4

    # Logging configuration
    log_level: str = "INFO"
    log_to_file: bool = True
    log_dir: str = "/home/batman/Documents/networkguard2/logs/logs"
    log_format: str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    # Logger-specific settings
    enable_console_logging: bool = True
    enable_file_logging: bool = True
    enable_security_logging: bool = True
    enable_packet_logging: bool = True
    enable_performance_logging: bool = True

    # File rotation settings
    max_log_file_size: int = 10485760  # 10MB
    log_backup_count: int = 5

    # Export settings
    export_format: str = "parquet"
    export_dir: str = "/home/batman/Documents/networkguard2/logs/parquet"

    # Performance settings
    enable_performance_monitoring: bool = True
    performance_log_interval: int = 60  # seconds
    performance_parquet_path: str = "/home/batman/Documents/networkguard2/logs/performance_metrics/perf_metrics.parquet"

    # Security settings
    validate_interface_names: bool = True
    sanitize_filter_expressions: bool = True
    max_filter_length: int = 200

    def __post_init__(self):
        """Ensure directories exist."""
        if self.log_to_file:
            Path(self.log_dir).mkdir(parents=True, exist_ok=True)
        Path(self.export_dir).mkdir(parents=True, exist_ok=True)
        Path(os.path.dirname(self.performance_parquet_path)).mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_yaml(cls, yaml_file: str) -> 'SnifferConfig':
        """
        Load configuration from a YAML file.

        Args:
            yaml_file: Path to the YAML configuration file

        Returns:
            SnifferConfig: Configuration object with values from the YAML file
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

        Args:
            yaml_file: Path to the YAML configuration file
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

        Args:
            yaml_file: Path to the YAML configuration file
        """
        config = cls()
        config.to_yaml(yaml_file)

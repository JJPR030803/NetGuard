"""
Configuration Builder Module for Network Security Suite.

This module provides a utility class for creating SnifferConfig instances
in different ways (from YAML, from dict, default).
"""

from typing import Dict, Optional

from network_security_suite.sniffer.sniffer_config import SnifferConfig


class ConfigBuilder:
    """
    A utility class for creating SnifferConfig instances in different ways.

    This class provides static methods for creating SnifferConfig instances
    from YAML files, dictionaries, or with default values.
    """

    @staticmethod
    def from_yaml(yaml_path: str) -> SnifferConfig:
        """
        Create a SnifferConfig instance from a YAML file.

        Args:
            yaml_path (str): Path to the YAML configuration file

        Returns:
            SnifferConfig: Configuration object with values from the YAML file
        """
        return SnifferConfig.from_yaml(yaml_path)

    @staticmethod
    def from_dict(config_dict: Dict) -> SnifferConfig:
        """
        Create a SnifferConfig instance from a dictionary.

        Args:
            config_dict (Dict): Dictionary containing configuration values

        Returns:
            SnifferConfig: Configuration object with values from the dictionary
        """
        return SnifferConfig(**config_dict)

    @staticmethod
    def default() -> SnifferConfig:
        """
        Create a SnifferConfig instance with default values.

        Returns:
            SnifferConfig: Configuration object with default values
        """
        return SnifferConfig()

    @staticmethod
    def minimal(
        interface: Optional[str] = None,
        log_dir: Optional[str] = None,
        export_dir: Optional[str] = None,
    ) -> SnifferConfig:
        """
        Create a minimal SnifferConfig instance with only essential parameters.

        Args:
            interface (Optional[str], optional): Interface name. Defaults to None.
            log_dir (Optional[str], optional): Log directory. Defaults to None.
            export_dir (Optional[str], optional): Export directory. Defaults to None.

        Returns:
            SnifferConfig: Minimal configuration object
        """
        config_dict = {}
        if interface is not None:
            config_dict["interface"] = interface
        if log_dir is not None:
            config_dict["log_dir"] = log_dir
            config_dict["log_to_file"] = True
        if export_dir is not None:
            config_dict["export_dir"] = export_dir

        return SnifferConfig(**config_dict)

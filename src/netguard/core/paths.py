"""
Path Management Module

This module provides centralized path management for the NetGuard application.
All paths are computed dynamically based on the project root, ensuring the
application works correctly regardless of installation location.

The path structure is organized as:
- Project Root: The root directory of the NetGuard project
- Source Root: src/netguard/
- Data Root: src/netguard/data/
  - Logs: src/netguard/data/logs/
  - Parquet: src/netguard/data/parquet/
  - Performance Metrics: src/netguard/data/performance_metrics/
  - Configs: src/netguard/data/configs/

This module should be imported and used anywhere paths are needed in the application
to ensure consistency and avoid hardcoded paths.

Example:
    from netguard.core.paths import NetGuardPaths

    paths = NetGuardPaths()
    config_path = paths.get_config_dir() / "sniffer_config.yaml"
    log_path = paths.get_log_dir() / "application.log"
"""

from pathlib import Path
from typing import Optional


class NetGuardPaths:
    """
    Centralized path management for NetGuard application.

    This class computes and manages all directory paths used by the NetGuard
    application. Paths are determined dynamically based on the project structure,
    allowing the application to run from any location.

    The class provides methods to access various directories and ensures that
    all directories exist when requested.

    Attributes:
        _project_root (Path): The root directory of the project
        _source_root (Path): The src/netguard/ directory
        _data_root (Path): The src/netguard/data/ directory
    """

    def __init__(self, project_root: Optional[Path] = None):
        """
        Initialize the path manager.

        Args:
            project_root: Optional custom project root path. If not provided,
                         it will be automatically detected by walking up from
                         this file's location to find the project root.
        """
        if project_root:
            self._project_root = Path(project_root).resolve()
        else:
            # Auto-detect project root by walking up from this file
            # This file is at: src/netguard/core/paths.py
            # Project root is 3 levels up
            self._project_root = Path(__file__).resolve().parent.parent.parent.parent

        self._source_root = self._project_root / "src" / "netguard"
        self._data_root = self._source_root / "data"

    def get_project_root(self) -> Path:
        """
        Get the project root directory.

        Returns:
            Path: The absolute path to the project root directory
        """
        return self._project_root

    def get_source_root(self) -> Path:
        """
        Get the source root directory (src/netguard/).

        Returns:
            Path: The absolute path to the source root directory
        """
        return self._source_root

    def get_data_root(self) -> Path:
        """
        Get the data root directory (src/netguard/data/).

        Creates the directory if it doesn't exist.

        Returns:
            Path: The absolute path to the data root directory
        """
        self._data_root.mkdir(parents=True, exist_ok=True)
        return self._data_root

    def get_log_dir(self) -> Path:
        """
        Get the logs directory (src/netguard/data/logs/).

        Creates the directory if it doesn't exist.

        Returns:
            Path: The absolute path to the logs directory
        """
        log_dir = self._data_root / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        return log_dir

    def get_parquet_dir(self) -> Path:
        """
        Get the parquet data directory (src/netguard/data/parquet/).

        Creates the directory if it doesn't exist.

        Returns:
            Path: The absolute path to the parquet directory
        """
        parquet_dir = self._data_root / "parquet"
        parquet_dir.mkdir(parents=True, exist_ok=True)
        return parquet_dir

    def get_performance_metrics_dir(self) -> Path:
        """
        Get the performance metrics directory (src/netguard/data/performance_metrics/).

        Creates the directory if it doesn't exist.

        Returns:
            Path: The absolute path to the performance metrics directory
        """
        perf_dir = self._data_root / "performance_metrics"
        perf_dir.mkdir(parents=True, exist_ok=True)
        return perf_dir

    def get_config_dir(self) -> Path:
        """
        Get the config directory (src/netguard/data/configs/).

        Creates the directory if it doesn't exist.

        Returns:
            Path: The absolute path to the config directory
        """
        config_dir = self._data_root / "configs"
        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir

    def get_performance_parquet_path(self) -> Path:
        """
        Get the default performance metrics parquet file path.

        Creates the parent directory if it doesn't exist.

        Returns:
            Path: The absolute path to the performance metrics parquet file
        """
        return self.get_performance_metrics_dir() / "perf_metrics.parquet"

    def ensure_all_directories_exist(self) -> None:
        """
        Ensure all data directories exist.

        This method creates all standard data directories if they don't exist.
        It's useful to call during application initialization to ensure the
        file structure is ready.
        """
        self.get_data_root()
        self.get_log_dir()
        self.get_parquet_dir()
        self.get_performance_metrics_dir()
        self.get_config_dir()

    def __str__(self) -> str:
        """Return a human-readable string representation of the paths."""
        return f"""NetGuard Paths:
  Project Root: {self._project_root}
  Source Root: {self._source_root}
  Data Root: {self._data_root}

  Data Directories:
    - Logs: {self.get_log_dir()}
    - Parquet: {self.get_parquet_dir()}
    - Performance Metrics: {self.get_performance_metrics_dir()}
    - Configs: {self.get_config_dir()}

  Default Files:
    - Performance Parquet: {self.get_performance_parquet_path()}
"""

    def __repr__(self) -> str:
        """Return a technical representation of the paths."""
        return f"NetGuardPaths(project_root={self._project_root})"


# Create a global singleton instance for convenience
_default_paths = NetGuardPaths()


# Convenience functions that use the default instance
def get_project_root() -> Path:
    """Get the project root directory using the default path manager."""
    return _default_paths.get_project_root()


def get_source_root() -> Path:
    """Get the source root directory using the default path manager."""
    return _default_paths.get_source_root()


def get_data_root() -> Path:
    """Get the data root directory using the default path manager."""
    return _default_paths.get_data_root()


def get_log_dir() -> Path:
    """Get the logs directory using the default path manager."""
    return _default_paths.get_log_dir()


def get_parquet_dir() -> Path:
    """Get the parquet directory using the default path manager."""
    return _default_paths.get_parquet_dir()


def get_performance_metrics_dir() -> Path:
    """Get the performance metrics directory using the default path manager."""
    return _default_paths.get_performance_metrics_dir()


def get_config_dir() -> Path:
    """Get the config directory using the default path manager."""
    return _default_paths.get_config_dir()


def get_performance_parquet_path() -> Path:
    """Get the performance metrics parquet file path using the default path manager."""
    return _default_paths.get_performance_parquet_path()

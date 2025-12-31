"""
Unit tests for the NetGuardPaths module.

This module tests all functionality of the path management system,
including path computation, directory creation, and convenience functions.
"""

import pytest
from pathlib import Path
from unittest.mock import patch
import tempfile
import shutil

from netguard.core.paths import (
    NetGuardPaths,
    get_project_root,
    get_source_root,
    get_data_root,
    get_log_dir,
    get_parquet_dir,
    get_performance_metrics_dir,
    get_config_dir,
    get_performance_parquet_path,
)


@pytest.fixture
def temp_project_root():
    """Create a temporary project root structure for testing."""
    temp_dir = tempfile.mkdtemp()
    project_root = Path(temp_dir)

    # Create the expected structure: src/netguard/
    source_root = project_root / "src" / "netguard"
    source_root.mkdir(parents=True, exist_ok=True)

    yield project_root

    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


class TestNetGuardPathsInit:
    """Test NetGuardPaths initialization."""

    def test_init_with_custom_root(self, temp_project_root):
        """Test initialization with a custom project root."""
        paths = NetGuardPaths(project_root=temp_project_root)

        assert paths.get_project_root() == temp_project_root
        assert paths.get_source_root() == temp_project_root / "src" / "netguard"
        assert paths.get_data_root() == temp_project_root / "src" / "netguard" / "data"

    def test_init_without_custom_root(self):
        """Test initialization with auto-detected project root."""
        paths = NetGuardPaths()

        # The auto-detected root should be 3 levels up from paths.py
        # paths.py is at: src/netguard/core/paths.py
        # So project root should end with "netguard"
        project_root = paths.get_project_root()
        assert project_root.exists()
        assert project_root.is_dir()

        # Verify the structure
        source_root = paths.get_source_root()
        assert source_root == project_root / "src" / "netguard"

    def test_init_with_string_path(self, temp_project_root):
        """Test initialization with a string path instead of Path object."""
        paths = NetGuardPaths(project_root=str(temp_project_root))

        assert paths.get_project_root() == temp_project_root
        assert isinstance(paths.get_project_root(), Path)

# Tests passed upto: 27/12/2025
class TestNetGuardPathsGetters:
    """Test NetGuardPaths getter methods."""

    def test_get_project_root(self, temp_project_root):
        """Test getting project root directory."""
        paths = NetGuardPaths(project_root=temp_project_root)

        assert paths.get_project_root() == temp_project_root
        assert paths.get_project_root().is_absolute()

    def test_get_source_root(self, temp_project_root):
        """Test getting source root directory."""
        paths = NetGuardPaths(project_root=temp_project_root)

        expected = temp_project_root / "src" / "netguard"
        assert paths.get_source_root() == expected
        assert paths.get_source_root().is_absolute()

    def test_get_data_root_creates_directory(self, temp_project_root):
        """Test that get_data_root creates the directory if it doesn't exist."""
        paths = NetGuardPaths(project_root=temp_project_root)

        data_root = paths.get_data_root()
        expected = temp_project_root / "src" / "netguard" / "data"

        assert data_root == expected
        assert data_root.exists()
        assert data_root.is_dir()

    def test_get_log_dir_creates_directory(self, temp_project_root):
        """Test that get_log_dir creates the directory if it doesn't exist."""
        paths = NetGuardPaths(project_root=temp_project_root)

        log_dir = paths.get_log_dir()
        expected = temp_project_root / "src" / "netguard" / "data" / "logs"

        assert log_dir == expected
        assert log_dir.exists()
        assert log_dir.is_dir()

    def test_get_parquet_dir_creates_directory(self, temp_project_root):
        """Test that get_parquet_dir creates the directory if it doesn't exist."""
        paths = NetGuardPaths(project_root=temp_project_root)

        parquet_dir = paths.get_parquet_dir()
        expected = temp_project_root / "src" / "netguard" / "data" / "parquet"

        assert parquet_dir == expected
        assert parquet_dir.exists()
        assert parquet_dir.is_dir()

    def test_get_performance_metrics_dir_creates_directory(self, temp_project_root):
        """Test that get_performance_metrics_dir creates the directory."""
        paths = NetGuardPaths(project_root=temp_project_root)

        perf_dir = paths.get_performance_metrics_dir()
        expected = temp_project_root / "src" / "netguard" / "data" / "performance_metrics"

        assert perf_dir == expected
        assert perf_dir.exists()
        assert perf_dir.is_dir()

    def test_get_config_dir_creates_directory(self, temp_project_root):
        """Test that get_config_dir creates the directory if it doesn't exist."""
        paths = NetGuardPaths(project_root=temp_project_root)

        config_dir = paths.get_config_dir()
        expected = temp_project_root / "src" / "netguard" / "data" / "configs"

        assert config_dir == expected
        assert config_dir.exists()
        assert config_dir.is_dir()

    def test_get_performance_parquet_path(self, temp_project_root):
        """Test getting the performance parquet file path."""
        paths = NetGuardPaths(project_root=temp_project_root)

        parquet_path = paths.get_performance_parquet_path()
        expected = (
            temp_project_root / "src" / "netguard" / "data" /
            "performance_metrics" / "perf_metrics.parquet"
        )

        assert parquet_path == expected
        # The parent directory should exist
        assert parquet_path.parent.exists()

# Tests passed upto: 27/12/2025
class TestNetGuardPathsDirectoryCreation:
    """Test directory creation behavior."""

    def test_multiple_calls_dont_fail(self, temp_project_root):
        """Test that calling get methods multiple times doesn't cause errors."""
        paths = NetGuardPaths(project_root=temp_project_root)

        # Call each method multiple times
        for _ in range(3):
            paths.get_data_root()
            paths.get_log_dir()
            paths.get_parquet_dir()
            paths.get_performance_metrics_dir()
            paths.get_config_dir()

        # All directories should exist
        assert paths.get_data_root().exists()
        assert paths.get_log_dir().exists()
        assert paths.get_parquet_dir().exists()
        assert paths.get_performance_metrics_dir().exists()
        assert paths.get_config_dir().exists()

    def test_ensure_all_directories_exist(self, temp_project_root):
        """Test that ensure_all_directories_exist creates all directories."""
        paths = NetGuardPaths(project_root=temp_project_root)

        paths.ensure_all_directories_exist()

        # Verify all directories exist
        assert (temp_project_root / "src" / "netguard" / "data").exists()
        assert (temp_project_root / "src" / "netguard" / "data" / "logs").exists()
        assert (temp_project_root / "src" / "netguard" / "data" / "parquet").exists()
        assert (temp_project_root / "src" / "netguard" / "data" / "performance_metrics").exists()
        assert (temp_project_root / "src" / "netguard" / "data" / "configs").exists()

# Tests passed upt: 27/12/2025
class TestNetGuardPathsStringRepresentation:
    """Test string representation methods."""

    def test_str_representation(self, temp_project_root):
        """Test __str__ method output."""
        paths = NetGuardPaths(project_root=temp_project_root)

        str_repr = str(paths)

        # Check that all important paths are in the string
        assert "NetGuard Paths:" in str_repr
        assert str(temp_project_root) in str_repr
        assert "Project Root:" in str_repr
        assert "Source Root:" in str_repr
        assert "Data Root:" in str_repr
        assert "Logs:" in str_repr
        assert "Parquet:" in str_repr
        assert "Performance Metrics:" in str_repr
        assert "Configs:" in str_repr
        assert "Performance Parquet:" in str_repr

    def test_repr_representation(self, temp_project_root):
        """Test __repr__ method output."""
        paths = NetGuardPaths(project_root=temp_project_root)

        repr_str = repr(paths)

        assert "NetGuardPaths" in repr_str
        assert "project_root=" in repr_str
        assert str(temp_project_root) in repr_str

#Tests passed upt: 27/12/2025
class TestConvenienceFunctions:
    """Test module-level convenience functions."""

    def test_get_project_root_function(self):
        """Test the get_project_root convenience function."""
        project_root = get_project_root()

        assert isinstance(project_root, Path)
        assert project_root.exists()
        assert project_root.is_dir()

    def test_get_source_root_function(self):
        """Test the get_source_root convenience function."""
        source_root = get_source_root()

        assert isinstance(source_root, Path)
        assert source_root.exists()
        assert source_root.name == "netguard"

    def test_get_data_root_function(self):
        """Test the get_data_root convenience function."""
        data_root = get_data_root()

        assert isinstance(data_root, Path)
        assert data_root.exists()
        assert data_root.name == "data"

    def test_get_log_dir_function(self):
        """Test the get_log_dir convenience function."""
        log_dir = get_log_dir()

        assert isinstance(log_dir, Path)
        assert log_dir.exists()
        assert log_dir.name == "logs"

    def test_get_parquet_dir_function(self):
        """Test the get_parquet_dir convenience function."""
        parquet_dir = get_parquet_dir()

        assert isinstance(parquet_dir, Path)
        assert parquet_dir.exists()
        assert parquet_dir.name == "parquet"

    def test_get_performance_metrics_dir_function(self):
        """Test the get_performance_metrics_dir convenience function."""
        perf_dir = get_performance_metrics_dir()

        assert isinstance(perf_dir, Path)
        assert perf_dir.exists()
        assert perf_dir.name == "performance_metrics"

    def test_get_config_dir_function(self):
        """Test the get_config_dir convenience function."""
        config_dir = get_config_dir()

        assert isinstance(config_dir, Path)
        assert config_dir.exists()
        assert config_dir.name == "configs"

    def test_get_performance_parquet_path_function(self):
        """Test the get_performance_parquet_path convenience function."""
        parquet_path = get_performance_parquet_path()

        assert isinstance(parquet_path, Path)
        assert parquet_path.name == "perf_metrics.parquet"
        assert parquet_path.parent.exists()

    def test_convenience_functions_use_same_instance(self):
        """Test that convenience functions use the same default instance."""
        # All convenience functions should return consistent paths
        project_root = get_project_root()
        source_root = get_source_root()
        data_root = get_data_root()

        assert source_root == project_root / "src" / "netguard"
        assert data_root == source_root / "data"

# Tests passed upto: 27/12/2025
class TestPathResolution:
    """Test path resolution behavior."""

    def test_paths_are_absolute(self, temp_project_root):
        """Test that all returned paths are absolute."""
        paths = NetGuardPaths(project_root=temp_project_root)

        assert paths.get_project_root().is_absolute()
        assert paths.get_source_root().is_absolute()
        assert paths.get_data_root().is_absolute()
        assert paths.get_log_dir().is_absolute()
        assert paths.get_parquet_dir().is_absolute()
        assert paths.get_performance_metrics_dir().is_absolute()
        assert paths.get_config_dir().is_absolute()
        assert paths.get_performance_parquet_path().is_absolute()

    def test_relative_path_converted_to_absolute(self, temp_project_root):
        """Test that relative paths are converted to absolute."""
        # Create a relative path
        import os
        original_cwd = os.getcwd()
        try:
            os.chdir(temp_project_root.parent)
            relative_path = temp_project_root.name

            paths = NetGuardPaths(project_root=relative_path)

            assert paths.get_project_root().is_absolute()
            assert paths.get_project_root() == temp_project_root
        finally:
            os.chdir(original_cwd)

# Tests passed upto: 27/12/2025
class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_nested_directory_creation(self, temp_project_root):
        """Test that nested directories are created properly."""
        # Remove the src/netguard directory to test full creation
        src_dir = temp_project_root / "src"
        if src_dir.exists():
            shutil.rmtree(src_dir)

        paths = NetGuardPaths(project_root=temp_project_root)

        # This should create the full nested structure
        perf_dir = paths.get_performance_metrics_dir()

        assert perf_dir.exists()
        assert (temp_project_root / "src").exists()
        assert (temp_project_root / "src" / "netguard").exists()
        assert (temp_project_root / "src" / "netguard" / "data").exists()

    def test_paths_with_spaces(self):
        """Test that paths with spaces are handled correctly."""
        temp_dir = tempfile.mkdtemp(suffix=" test dir")
        try:
            project_root = Path(temp_dir)
            (project_root / "src" / "netguard").mkdir(parents=True)

            paths = NetGuardPaths(project_root=project_root)

            # Should work fine with spaces
            log_dir = paths.get_log_dir()
            assert log_dir.exists()
            assert " test dir" in str(log_dir)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_unicode_in_path(self):
        """Test that paths with unicode characters are handled correctly."""
        temp_dir = tempfile.mkdtemp(suffix="_测试")
        try:
            project_root = Path(temp_dir)
            (project_root / "src" / "netguard").mkdir(parents=True)

            paths = NetGuardPaths(project_root=project_root)

            # Should work fine with unicode
            log_dir = paths.get_log_dir()
            assert log_dir.exists()
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

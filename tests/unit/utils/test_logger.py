"""
Tests for logger utilities.
"""

import logging
import shutil
import tempfile
import unittest
from pathlib import Path

from netguard.utils.logger import (
    HandlerConfig,
    NetworkSecurityLogger,
    PerformanceLogger,
)


class TestHandlerConfig(unittest.TestCase):
    """Test HandlerConfig class."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_initialization(self):
        """Test initialization."""
        formatter = logging.Formatter("%(message)s")
        config = HandlerConfig(
            name="test",
            level=logging.INFO,
            formatter=formatter,
            filepath="test.log",
            log_dir=self.temp_dir,
        )
        self.assertEqual(config.name, "test")
        self.assertEqual(config.level, logging.INFO)
        self.assertIsNotNone(config.file_handler)

    def test_has_format(self):
        """Test has_format method."""
        formatter = logging.Formatter("%(message)s")
        config = HandlerConfig(name="test", level=logging.INFO, formatter=formatter)
        self.assertTrue(config.has_format())


class TestNetworkSecurityLogger(unittest.TestCase):
    """Test NetworkSecurityLogger class."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_initialization(self):
        """Test initialization."""
        logger = NetworkSecurityLogger(log_dir=self.temp_dir)
        self.assertIsInstance(logger, NetworkSecurityLogger)

    def test_logging_methods(self):
        """Test logging methods."""
        logger = NetworkSecurityLogger(log_dir=self.temp_dir)
        # Should not raise errors
        logger.log("warning message")
        logger.debug("debug message")
        logger.error("error message")

    def test_save_logs(self):
        """Test save_logs method."""
        logger = NetworkSecurityLogger(log_dir=self.temp_dir)
        # Should not raise error
        logger.save_logs("test_path")


class TestPerformanceLogger(unittest.TestCase):
    """Test PerformanceLogger class."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_initialization(self):
        """Test initialization."""
        logger = PerformanceLogger(log_dir=self.temp_dir)
        self.assertIsInstance(logger, PerformanceLogger)

    def test_log(self):
        """Test log method."""
        logger = PerformanceLogger(log_dir=self.temp_dir)
        # Should not raise error
        logger.log("performance message")

    def test_save_logs(self):
        """Test save_logs method."""
        logger = PerformanceLogger(log_dir=self.temp_dir)
        # Should not raise error
        logger.save_logs("test_path")


if __name__ == "__main__":
    unittest.main()

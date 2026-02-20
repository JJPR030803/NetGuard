"""
Tests for MLLogger class.
"""

import unittest
from unittest.mock import patch

from netguard.ml.ml_logger import MLLogger


class TestMLLogger(unittest.TestCase):
    """Test MLLogger class."""

    def test_initialization(self):
        """Test initialization."""
        logger = MLLogger()
        self.assertIsInstance(logger, MLLogger)

    def test_log(self):
        """Test log method."""
        logger = MLLogger()
        # Should not raise error
        logger.log("test message")

    def test_save_logs(self):
        """Test save_logs method."""
        logger = MLLogger()
        # Should not raise error
        logger.save_logs("test_path.log")


if __name__ == "__main__":
    unittest.main()

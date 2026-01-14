"""Tests for preprocessing configuration."""

import unittest

from netguard.workflows.preprocessing_config import AnalysisConfig


class TestAnalysisConfig:
    """Test AnalysisConfig dataclass."""

    def test_default_config_creation(self):
        """Test AnalysisConfig with default values."""
        config = AnalysisConfig()
        assert config.time_window == "1m"
        assert config.min_packets_threshold == 100
        assert config.protocols == {"TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"}

    def test_custom_time_window(self):
        """Test AnalysisConfig with custom time_window."""
        config = AnalysisConfig(time_window="5m")
        assert config.time_window == "5m"
        assert config.min_packets_threshold == 100  # Default still applies

    def test_custom_threshold(self):
        """Test AnalysisConfig with custom threshold."""
        config = AnalysisConfig(min_packets_threshold=500)
        assert config.min_packets_threshold == 500
        assert config.time_window == "1m"  # Default still applies

    def test_custom_protocols(self):
        """Test AnalysisConfig with custom protocols."""
        custom_protocols = {"TCP", "UDP"}
        config = AnalysisConfig(protocols=custom_protocols)
        assert config.protocols == custom_protocols
        assert len(config.protocols) == 2

    def test_all_custom_values(self):
        """Test AnalysisConfig with all custom values."""
        custom_protocols = {"TCP", "SSH"}
        config = AnalysisConfig(
            time_window="10m", min_packets_threshold=1000, protocols=custom_protocols
        )
        assert config.time_window == "10m"
        assert config.min_packets_threshold == 1000
        assert config.protocols == custom_protocols

    def test_protocols_is_set(self):
        """Test that protocols field is a set type."""
        config = AnalysisConfig()
        assert isinstance(config.protocols, set)

    def test_protocols_default_factory(self):
        """Test that each config instance gets its own protocols set."""
        config1 = AnalysisConfig()
        config2 = AnalysisConfig()

        # Modify one instance
        config1.protocols.add("SSH")

        # Ensure the other instance is not affected
        assert "SSH" in config1.protocols
        assert "SSH" not in config2.protocols

    def test_config_equality(self):
        """Test that two configs with same values are equal."""
        config1 = AnalysisConfig(time_window="5m", min_packets_threshold=200)
        config2 = AnalysisConfig(time_window="5m", min_packets_threshold=200)
        assert config1 == config2

    def test_config_inequality(self):
        """Test that configs with different values are not equal."""
        config1 = AnalysisConfig(time_window="5m")
        config2 = AnalysisConfig(time_window="10m")
        assert config1 != config2

    def test_config_representation(self):
        """Test string representation of config."""
        config = AnalysisConfig()
        repr_str = repr(config)
        assert "AnalysisConfig" in repr_str
        assert "time_window" in repr_str
        assert "min_packets_threshold" in repr_str
        assert "protocols" in repr_str


if __name__ == "__main__":
    unittest.main()

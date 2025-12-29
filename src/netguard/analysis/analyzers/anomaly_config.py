"""Configuration profiles for port scan detection"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ScanProfile(Enum):
    """Predefined port scan profiles"""

    AGGRESSIVE = "aggressive"  # Detects fast aggresive scanning
    BALANCED = "balanced"  # Balance between slow and fast scanning
    STEALTH = "stealth"  # Detects slow and stealthy scanning
    HONEYPOT = "honeypot"  # Most sensibility
    CUSTOM = "custom"  # User defined scanning


@dataclass
class PortScanConfig:
    """
    Configuration for port scan detection.

    Attributes:
        threshold: Minimum number of unique ports to flag as scan
        time_window: Time window for analysis (e.g., "1m", "5m", "30m")
        description: Human-readable description of the profile
        sensitivity: Sensitivity level (high/medium/low)
    """

    threshold: int
    time_window: str
    description: str
    sensitivity: str

    def __str__(self) -> str:
        return f"PortScanConfig(threshold:={self.threshold}),window={self.time_window}, sensitivity={self.sensitivity})"

    # Perfiles predefinidos


SCAN_PROFILES: dict[ScanProfile, PortScanConfig] = {
    ScanProfile.AGGRESSIVE: PortScanConfig(
        threshold=15,
        time_window="1m",
        description="Detects fast, aggressive port scans (e.g., nmap -T4/-T5)",
        sensitivity="high",
    ),
    ScanProfile.BALANCED: PortScanConfig(
        threshold=20,
        time_window="5m",
        description="Balanced detection for typical enterprise networks",
        sensitivity="medium",
    ),
    ScanProfile.STEALTH: PortScanConfig(
        threshold=25,
        time_window="30m",
        description="Detects slow, stealthy scans designed to evade detection",
        sensitivity="low",
    ),
    ScanProfile.HONEYPOT: PortScanConfig(
        threshold=5,
        time_window="1m",
        description="Maximum sensitivity for honeypot environments",
        sensitivity="very_high",
    ),
}


def get_scan_config(profile: ScanProfile) -> PortScanConfig:
    """
    Get port scan configuration for a given profile.

    Args:
        profile: ScanProfile enum value

    Returns:
        PortScanConfig with predefined parameters

    Example:
        >>> config = get_scan_config(ScanProfile.BALANCED)
        >>> print(config.threshold, config.time_window)
        20 5m
    """
    return SCAN_PROFILES[profile]


def create_custom_config(threshold: int, time_window: str, description: str = "Custom configuration") -> PortScanConfig:
    """
    Create a custom port scan configuration.

    Args:
        threshold: Number of unique ports threshold
        time_window: Time window string (e.g., "10m")
        description: Optional description

    Returns:
        Custom PortScanConfig

    Example:
        >>> config = create_custom_config(threshold=30, time_window="15m")
    """
    # Determinar sensibilidad basada en threshold
    if threshold < 10:
        sensitivity = "very_high"
    elif threshold < 20:
        sensitivity = "high"
    elif threshold < 30:
        sensitivity = "medium"
    else:
        sensitivity = "low"
    return PortScanConfig(
        threshold=threshold,
        time_window=time_window,
        description=description,
        sensitivity=sensitivity,
    )

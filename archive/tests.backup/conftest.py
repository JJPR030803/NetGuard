"""
Shared pytest fixtures(configurations) for all tests
"""

from typing import Generator

import pytest

from src.network_security_suite.sniffer.packet_capture import PacketCapture


@pytest.fixture
def mock_interface() -> str:
    """Provides a mock interface for testing"""
    return "test0"


@pytest.fixture
def packet_capture(mock_interface: str) -> Generator[PacketCapture, None, None]:
    """Provides a packet capture object for testing"""
    capture = PacketCapture(interface=mock_interface)
    yield capture

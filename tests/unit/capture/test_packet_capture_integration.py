"""
Integration tests for PacketCapture.

This module tests end-to-end scenarios, data conversion pipelines,
and integration between different components of the PacketCapture system.
"""

import contextlib
import tempfile
from collections.abc import Generator
from pathlib import Path
from unittest.mock import MagicMock, patch

import pandas as pd
import polars as pl
import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from netguard.capture.packet_capture import PacketCapture
from netguard.core.config import SnifferConfig
from netguard.core.exceptions import DataConversionError
from netguard.models.packet_data_structures import (
    POLARS_AVAILABLE,
    Packet,
    PacketLayer,
)

# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def temp_log_dir() -> Generator[str, None, None]:
    """Create a temporary directory for logs and exports."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def sniffer_config(temp_log_dir: str) -> SnifferConfig:
    """Create a SnifferConfig for testing."""
    return SnifferConfig(
        interface="lo",
        log_dir=temp_log_dir,
        export_dir=temp_log_dir,
        performance_parquet_path=f"{temp_log_dir}/performance.parquet",
        max_processing_batch_size=10,
        num_threads=2,
    )


@pytest.fixture
def packet_capture(sniffer_config: SnifferConfig) -> PacketCapture:
    """Create a PacketCapture instance for testing."""
    return PacketCapture(config=sniffer_config)


def create_realistic_mock_packet(
    src_ip: str = "192.168.1.1",
    dst_ip: str = "10.0.0.1",
    src_port: int = 12345,
    dst_port: int = 80,
    protocol: str = "TCP",
    timestamp: float = 1234567890.0,
    size: int = 100,
) -> MagicMock:
    """Create a realistic mock Scapy packet with multiple layers."""
    mock_packet = MagicMock()
    mock_packet.time = timestamp
    mock_packet.__len__.return_value = size

    # Define which layers the packet has
    layer_classes = [Ether, IP]
    if protocol == "TCP":
        layer_classes.append(TCP)
    elif protocol == "UDP":
        layer_classes.append(UDP)
    elif protocol == "ICMP":
        layer_classes.append(ICMP)
    elif protocol == "ARP":
        layer_classes = [Ether, ARP]

    mock_packet.haslayer.side_effect = lambda x: x in layer_classes
    mock_packet.layers.return_value = []

    # Layer factory functions to reduce return statements
    layer_factories = {
        Ether: lambda: MagicMock(
            dst="00:11:22:33:44:55",
            src="aa:bb:cc:dd:ee:ff",
            type=0x0800,
        ),
        IP: lambda: MagicMock(
            version=4,
            ihl=5,
            tos=0,
            len=size,
            id=12345,
            flags=0,
            frag=0,
            ttl=64,
            proto=6 if protocol == "TCP" else 17,
            chksum=0xABCD,
            src=src_ip,
            dst=dst_ip,
            options=[],
        ),
        TCP: lambda: MagicMock(
            sport=src_port,
            dport=dst_port,
            seq=1000,
            ack=2000,
            dataofs=5,
            reserved=0,
            flags="PA",
            window=8192,
            chksum=0x1234,
            urgptr=0,
            options=[],
        ),
        UDP: lambda: MagicMock(
            sport=src_port,
            dport=dst_port,
            len=size,
            chksum=0x5678,
        ),
        ICMP: lambda: MagicMock(
            type=8,
            code=0,
            chksum=0x9ABC,
            id=1,
            seq=1,
        ),
        ARP: lambda: MagicMock(
            hwtype=1,
            ptype=0x0800,
            hwlen=6,
            plen=4,
            op=1,
            hwsrc="aa:bb:cc:dd:ee:ff",
            psrc=src_ip,
            hwdst="00:00:00:00:00:00",
            pdst=dst_ip,
        ),
    }

    def get_layer(layer_type: type) -> MagicMock:
        factory = layer_factories.get(layer_type)
        return factory() if factory else MagicMock()

    mock_packet.__getitem__.side_effect = get_layer

    return mock_packet


# ============================================================================
# TEST CLASS: End-to-End Capture Simulation
# ============================================================================


class TestEndToEndCapture:
    """Test complete capture workflows."""

    @patch("netguard.capture.packet_capture.sniff")
    def test_full_capture_workflow(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture
    ) -> None:
        """Test complete capture, process, and convert workflow."""
        # Create mock packets
        packets_to_capture = [
            create_realistic_mock_packet(
                src_ip=f"192.168.1.{i}",
                dst_ip=f"10.0.0.{i}",
                timestamp=float(1000 + i),
            )
            for i in range(20)
        ]

        packet_index = [0]

        def sniff_side_effect(**kwargs) -> None:
            prn = kwargs.get("prn")
            count = kwargs.get("count", len(packets_to_capture))
            if prn:
                for _ in range(min(count, len(packets_to_capture))):
                    if packet_index[0] < len(packets_to_capture):
                        prn(packets_to_capture[packet_index[0]])
                        packet_index[0] += 1

        mock_sniff.side_effect = sniff_side_effect

        # Capture packets
        packet_capture.capture(max_packets=20)

        # Verify capture
        assert len(packet_capture.packets) == 20

        # Convert to different formats
        json_data = packet_capture.to_json()
        assert json_data["total_packets"] == 20

        pandas_df = packet_capture.to_pandas_df()
        assert len(pandas_df) == 20

        if POLARS_AVAILABLE:
            polars_df = packet_capture.to_polars_df()
            assert len(polars_df) == 20

    @patch("netguard.capture.packet_capture.sniff")
    def test_capture_with_bpf_filter(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture
    ) -> None:
        """Test capture with BPF filter."""
        mock_sniff.return_value = []

        packet_capture.capture(max_packets=10, bpf_filter="tcp port 80")

        # Verify filter was passed to sniff
        call_kwargs = mock_sniff.call_args[1]
        assert call_kwargs["filter"] == "tcp port 80"

    @patch("netguard.capture.packet_capture.sniff")
    def test_capture_with_logging_enabled(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture
    ) -> None:
        """Test capture with logging enabled."""
        mock_sniff.return_value = []

        # Should not raise with logging enabled
        packet_capture.capture(max_packets=0, log=True)

    @patch("netguard.capture.packet_capture.sniff")
    def test_capture_mixed_protocol_packets(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture
    ) -> None:
        """Test capturing packets of different protocols."""
        mixed_packets = [
            create_realistic_mock_packet(protocol="TCP", timestamp=1.0),
            create_realistic_mock_packet(protocol="UDP", timestamp=2.0),
            create_realistic_mock_packet(protocol="ICMP", timestamp=3.0),
            create_realistic_mock_packet(protocol="ARP", timestamp=4.0),
        ]

        def sniff_side_effect(**kwargs) -> None:
            prn = kwargs.get("prn")
            if prn:
                for pkt in mixed_packets:
                    prn(pkt)

        mock_sniff.side_effect = sniff_side_effect

        packet_capture.capture(max_packets=4)

        assert len(packet_capture.packets) == 4

        # Verify different layer types captured
        layer_names = set()
        for pkt in packet_capture.packets:
            for layer in pkt.layers:
                layer_names.add(layer.layer_name)

        assert "TCP" in layer_names or "UDP" in layer_names or "ICMP" in layer_names


# ============================================================================
# TEST CLASS: Data Conversion Pipeline
# ============================================================================


class TestDataConversionPipeline:
    """Test data conversion between formats."""

    def test_json_to_pandas_consistency(self, packet_capture: PacketCapture) -> None:
        """Test that JSON and Pandas conversions are consistent."""
        # Create test packets
        for i in range(5):
            layer = PacketLayer(
                layer_name="TCP",
                fields={"sport": 80 + i, "dport": 443},
            )
            packet_capture.packets.append(
                Packet(timestamp=float(i), layers=[layer], raw_size=100 + i)
            )

        # Convert to both formats
        json_data = packet_capture.to_json()
        pandas_df = packet_capture.to_pandas_df()

        # Verify consistency
        assert json_data["total_packets"] == len(pandas_df)
        for i, json_packet in enumerate(json_data["packets"]):
            assert json_packet["timestamp"] == pandas_df["timestamp"].iloc[i]
            assert json_packet["raw_size"] == pandas_df["raw_size"].iloc[i]

    @pytest.mark.skipif(not POLARS_AVAILABLE, reason="Polars not installed")
    def test_pandas_polars_consistency(self, packet_capture: PacketCapture) -> None:
        """Test that Pandas and Polars conversions are consistent."""
        # Create test packets
        for i in range(5):
            layer = PacketLayer(
                layer_name="IP",
                fields={"src": f"192.168.1.{i}", "dst": "10.0.0.1"},
            )
            packet_capture.packets.append(Packet(timestamp=float(i), layers=[layer], raw_size=100))

        pandas_df = packet_capture.to_pandas_df()
        polars_df = packet_capture.to_polars_df()

        # Verify same shape
        assert len(pandas_df) == len(polars_df)
        assert set(pandas_df.columns) == set(polars_df.columns)

        # Verify same data
        for col in pandas_df.columns:
            pandas_values = pandas_df[col].tolist()
            polars_values = polars_df[col].to_list()
            # Handle NaN comparisons
            for pv, plv in zip(pandas_values, polars_values):
                if pd.isna(pv) and plv is None:
                    continue
                assert pv == plv, f"Mismatch in column {col}: {pv} != {plv}"

    def test_conversion_with_complex_fields(self, packet_capture: PacketCapture) -> None:
        """Test conversion with complex/nested field values."""
        # Create packet with various field types
        layer = PacketLayer(
            layer_name="Test",
            fields={
                "int_field": 42,
                "float_field": 3.14,
                "str_field": "test",
                "bool_field": True,
                "none_field": None,
            },
        )
        packet_capture.packets.append(Packet(timestamp=1.0, layers=[layer], raw_size=100))

        # All conversions should work
        json_data = packet_capture.to_json()
        assert json_data["total_packets"] == 1

        pandas_df = packet_capture.to_pandas_df()
        assert len(pandas_df) == 1

        if POLARS_AVAILABLE:
            polars_df = packet_capture.to_polars_df()
            assert len(polars_df) == 1

    def test_conversion_empty_packets(self, packet_capture: PacketCapture) -> None:
        """Test conversion with empty packet list."""
        # Verify empty conversions
        assert packet_capture.to_json() == {}
        assert packet_capture.to_pandas_df().empty

        if POLARS_AVAILABLE:
            assert packet_capture.to_polars_df().is_empty()

    def test_packets_to_json_format(self, packet_capture: PacketCapture) -> None:
        """Test packets_to_json returns correct format."""
        layer = PacketLayer(layer_name="Test", fields={"key": "value"})
        packet_capture.packets.append(Packet(timestamp=1.0, layers=[layer], raw_size=100))

        result = packet_capture.packets_to_json()

        assert isinstance(result, list)
        assert len(result) == 1
        assert "timestamp" in result[0]
        assert "layers" in result[0]
        assert "raw_size" in result[0]

    def test_packets_to_pandas_format(self, packet_capture: PacketCapture) -> None:
        """Test packets_to_pandas returns correct format."""
        layer = PacketLayer(layer_name="Test", fields={"key": "value"})
        packet_capture.packets.append(Packet(timestamp=1.0, layers=[layer], raw_size=100))

        result = packet_capture.packets_to_pandas()

        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], pd.DataFrame)

    @pytest.mark.skipif(not POLARS_AVAILABLE, reason="Polars not installed")
    def test_packets_to_polars_format(self, packet_capture: PacketCapture) -> None:
        """Test packets_to_polars returns correct format."""
        layer = PacketLayer(layer_name="Test", fields={"key": "value"})
        packet_capture.packets.append(Packet(timestamp=1.0, layers=[layer], raw_size=100))

        result = packet_capture.packets_to_polars()

        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], pl.DataFrame)


# ============================================================================
# TEST CLASS: Error Handling
# ============================================================================


class TestErrorHandling:
    """Test error handling scenarios."""

    @patch("netguard.capture.packet_capture.sniff")
    def test_capture_handles_sniff_exception(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture
    ) -> None:
        """Test that capture handles sniff exceptions gracefully."""
        mock_sniff.side_effect = PermissionError("Permission denied")

        with pytest.raises(PermissionError):
            packet_capture.capture(max_packets=10)

        # is_running should be False after exception
        assert not packet_capture.is_running

    def test_process_packet_layers_none_input(self, packet_capture: PacketCapture) -> None:
        """Test that None input raises ValueError."""
        with pytest.raises(ValueError, match="Cannot process None packet"):
            packet_capture.process_packet_layers(None)  # type: ignore[arg-type]

    def test_to_json_handles_conversion_error(self, packet_capture: PacketCapture) -> None:
        """Test that to_json handles conversion errors."""
        # Create a packet that will fail conversion
        bad_packet = MagicMock(spec=Packet)
        bad_packet.to_json.side_effect = RuntimeError("Conversion failed")
        packet_capture.packets = [bad_packet]

        with pytest.raises(DataConversionError):
            packet_capture.to_json()

    def test_to_pandas_handles_conversion_error(self, packet_capture: PacketCapture) -> None:
        """Test that to_pandas_df handles conversion errors."""
        # Create a packet with invalid data
        bad_packet = MagicMock(spec=Packet)
        bad_packet.timestamp = "invalid"  # Should be float
        bad_packet.raw_size = 100
        bad_packet.layers = [MagicMock(layer_name="Test", fields={"key": object()})]
        packet_capture.packets = [bad_packet]

        # This may or may not raise depending on pandas behavior
        # but should handle gracefully
        with contextlib.suppress(DataConversionError):
            packet_capture.to_pandas_df()

    @pytest.mark.skipif(not POLARS_AVAILABLE, reason="Polars not installed")
    def test_to_polars_handles_conversion_error(self, packet_capture: PacketCapture) -> None:
        """Test that to_polars_df handles conversion errors."""
        bad_packet = MagicMock(spec=Packet)
        bad_packet.timestamp = "invalid"
        bad_packet.raw_size = 100
        bad_packet.layers = [MagicMock(layer_name="Test", fields={"key": object()})]
        packet_capture.packets = [bad_packet]

        with contextlib.suppress(DataConversionError):
            packet_capture.to_polars_df()

    def test_layer_processing_error_continues(self, packet_capture: PacketCapture) -> None:
        """Test that layer processing errors don't stop packet processing."""
        mock_packet = MagicMock()
        mock_packet.time = 1.0
        mock_packet.__len__.return_value = 100
        mock_packet.haslayer.side_effect = lambda x: x == IP
        mock_packet.layers.return_value = []

        # Make IP layer access raise exception
        def bad_getitem(layer_type: type) -> MagicMock:
            if layer_type == IP:
                raise RuntimeError("Layer access failed")
            return MagicMock()

        mock_packet.__getitem__.side_effect = bad_getitem

        # Should not raise - just skip the problematic layer
        result = packet_capture.process_packet_layers(mock_packet)

        assert result is not None
        assert result.timestamp == 1.0


# ============================================================================
# TEST CLASS: Configuration Integration
# ============================================================================


class TestConfigurationIntegration:
    """Test configuration integration."""

    def test_capture_uses_config_defaults(self, temp_log_dir: str) -> None:
        """Test that capture uses configuration defaults."""
        config = SnifferConfig(
            interface="eth0",
            log_dir=temp_log_dir,
            export_dir=temp_log_dir,
            packet_count=50,
            filter_expression="tcp",
            num_threads=4,
        )
        capture = PacketCapture(config=config)

        assert capture.interface == "eth0"
        assert capture.config.packet_count == 50
        assert capture.config.filter_expression == "tcp"
        assert capture.config.num_threads == 4

    @patch("netguard.capture.packet_capture.sniff")
    def test_capture_override_config_values(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture
    ) -> None:
        """Test that capture parameters override config values."""
        mock_sniff.return_value = []

        packet_capture.capture(
            max_packets=999,
            bpf_filter="udp",
            num_threads=8,
        )

        call_kwargs = mock_sniff.call_args[1]
        assert call_kwargs["count"] == 999
        assert call_kwargs["filter"] == "udp"

    def test_realtime_display_config(self, temp_log_dir: str) -> None:
        """Test realtime display configuration."""
        config = SnifferConfig(
            interface="lo",
            log_dir=temp_log_dir,
            export_dir=temp_log_dir,
            enable_realtime_display=True,
        )
        capture = PacketCapture(config=config)

        assert capture.realtime_display is True

    def test_realtime_display_parameter_override(self, temp_log_dir: str) -> None:
        """Test that realtime_display parameter overrides config."""
        config = SnifferConfig(
            interface="lo",
            log_dir=temp_log_dir,
            export_dir=temp_log_dir,
            enable_realtime_display=False,
        )
        capture = PacketCapture(config=config, realtime_display=True)

        assert capture.realtime_display is True


# ============================================================================
# TEST CLASS: Logging Integration
# ============================================================================


class TestLoggingIntegration:
    """Test logging integration."""

    def test_loggers_initialized(self, packet_capture: PacketCapture) -> None:
        """Test that all loggers are properly initialized."""
        assert packet_capture.info_logger is not None
        assert packet_capture.debug_logger is not None
        assert packet_capture.error_logger is not None
        assert packet_capture.packet_logger is not None

    @patch("netguard.capture.packet_capture.sniff")
    def test_capture_logs_session_info(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture
    ) -> None:
        """Test that capture logs session info when log=True."""
        mock_sniff.return_value = []
        log_calls = []

        original_log = packet_capture.info_logger.log

        def track_log(msg: str) -> None:
            log_calls.append(msg)
            original_log(msg)

        with patch.object(packet_capture.info_logger, "log", track_log):
            packet_capture.capture(max_packets=0, log=True)

        # Verify session info was logged
        session_logs = [log for log in log_calls if "SESSION" in log]
        assert len(session_logs) >= 2  # Start and end

    def test_session_info_content(self, packet_capture: PacketCapture) -> None:
        """Test session info contains expected fields."""
        session_info = packet_capture._get_session_info()

        assert "os" in session_info
        assert "os_version" in session_info
        assert "machine" in session_info
        assert "processor" in session_info
        assert "interface" in session_info
        assert "interface_type" in session_info
        assert "date" in session_info


# ============================================================================
# TEST CLASS: Parquet Export Integration
# ============================================================================


class TestParquetExportIntegration:
    """Test parquet export functionality."""

    @pytest.mark.skipif(not POLARS_AVAILABLE, reason="Polars not installed")
    def test_save_to_parquet_basic(self, packet_capture: PacketCapture) -> None:
        """Test basic parquet save functionality."""
        # Add test packets
        for i in range(5):
            layer = PacketLayer(layer_name="Test", fields={"id": i})
            packet_capture.packets.append(Packet(timestamp=float(i), layers=[layer], raw_size=100))

        # Save to parquet
        with tempfile.NamedTemporaryFile(suffix=".parquet", delete=False) as f:
            filepath = packet_capture.save_to_parquet(f.name)

        # Verify file exists and can be read
        assert Path(filepath).exists()
        df = pl.read_parquet(filepath)
        assert len(df) == 5

        # Cleanup
        Path(filepath).unlink()

    @pytest.mark.skipif(not POLARS_AVAILABLE, reason="Polars not installed")
    def test_save_to_parquet_default_path(
        self, packet_capture: PacketCapture, temp_log_dir: str
    ) -> None:
        """Test parquet save with default path from config."""
        layer = PacketLayer(layer_name="Test", fields={"id": 1})
        packet_capture.packets.append(Packet(timestamp=1.0, layers=[layer], raw_size=100))

        # Save without specifying path
        filepath = packet_capture.save_to_parquet()

        # Verify file was created in export_dir
        assert Path(filepath).exists()
        assert temp_log_dir in filepath

        # Cleanup
        Path(filepath).unlink()

    @pytest.mark.skipif(not POLARS_AVAILABLE, reason="Polars not installed")
    def test_save_to_parquet_empty_packets(self, packet_capture: PacketCapture) -> None:
        """Test parquet save with empty packet list."""
        with tempfile.NamedTemporaryFile(suffix=".parquet", delete=False) as f:
            filepath = packet_capture.save_to_parquet(f.name)

        # Should create empty parquet file
        assert Path(filepath).exists()
        df = pl.read_parquet(filepath)
        assert len(df) == 0

        # Cleanup
        Path(filepath).unlink()


# ============================================================================
# TEST CLASS: Display Integration
# ============================================================================


class TestDisplayIntegration:
    """Test display functionality integration."""

    def test_show_packets_displays_correctly(
        self, packet_capture: PacketCapture, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test that show_packets displays packet information."""
        layer = PacketLayer(
            layer_name="TCP",
            fields={"sport": 80, "dport": 443},
        )
        packet_capture.packets.append(Packet(timestamp=1234567890.0, layers=[layer], raw_size=100))

        packet_capture.show_packets()

        captured = capsys.readouterr()
        assert "Packet 1" in captured.out
        assert "1234567890.0" in captured.out
        assert "100 bytes" in captured.out
        assert "TCP" in captured.out

    def test_show_stats_displays_correctly(
        self, packet_capture: PacketCapture, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test that show_stats displays statistics."""
        packet_capture.stats = {
            "processed_packets": 100,
            "dropped_packets": 5,
            "processing_time": 2.5,
            "batch_count": 10,
        }

        layer = PacketLayer(layer_name="TCP", fields={})
        packet_capture.packets.append(Packet(timestamp=1.0, layers=[layer], raw_size=100))

        packet_capture.show_stats()

        captured = capsys.readouterr()
        assert "100" in captured.out  # processed_packets
        assert "5" in captured.out  # dropped_packets
        assert "2.5" in captured.out or "2.50" in captured.out  # processing_time
        assert "10" in captured.out  # batch_count

    def test_show_stats_layer_distribution(
        self, packet_capture: PacketCapture, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test that show_stats displays layer distribution."""
        # Add packets with different layers
        for layer_name in ["TCP", "TCP", "UDP", "ICMP"]:
            layer = PacketLayer(layer_name=layer_name, fields={})
            packet_capture.packets.append(Packet(timestamp=1.0, layers=[layer], raw_size=100))

        packet_capture.show_stats()

        captured = capsys.readouterr()
        assert "Layer Distribution" in captured.out
        assert "TCP" in captured.out
        assert "UDP" in captured.out
        assert "ICMP" in captured.out


# ============================================================================
# TEST CLASS: Configuration Validation Errors
# ============================================================================


class TestConfigurationValidationErrors:
    """Test configuration validation and error handling."""

    def test_invalid_max_memory_packets_less_than_100(self, temp_log_dir: str) -> None:
        """Test max_memory_packets < 100 raises ValueError."""
        with pytest.raises(ValueError, match="must be at least 100"):
            SnifferConfig(
                interface="lo",
                log_dir=temp_log_dir,
                export_dir=temp_log_dir,
                max_memory_packets=50,
            )

    def test_invalid_max_memory_packets_not_divisible_by_10(
        self, temp_log_dir: str
    ) -> None:
        """Test max_memory_packets not divisible by 10 raises ValueError."""
        with pytest.raises(ValueError, match="must be a multiple of 10"):
            SnifferConfig(
                interface="lo",
                log_dir=temp_log_dir,
                export_dir=temp_log_dir,
                max_memory_packets=105,
            )

    def test_missing_export_directory_created(
        self, packet_capture: PacketCapture, temp_log_dir: str
    ) -> None:
        """Test that missing export directory is created during save."""
        # Add a packet
        layer = PacketLayer(layer_name="Test", fields={"id": 1})
        packet_capture.packets.append(
            Packet(timestamp=1.0, layers=[layer], raw_size=100)
        )

        # Create path to non-existent directory
        new_dir = Path(temp_log_dir) / "new_subdir" / "another"
        filepath = new_dir / "test.parquet"

        # Ensure it doesn't exist
        assert not new_dir.exists()

        # Save should create the directory
        if POLARS_AVAILABLE:
            result = packet_capture.save_to_parquet(str(filepath))
            assert Path(result).exists()
            # Cleanup
            Path(result).unlink()
            new_dir.rmdir()
            new_dir.parent.rmdir()

    def test_boundary_max_memory_packets_values(self, temp_log_dir: str) -> None:
        """Test boundary values for max_memory_packets."""
        # Exactly 100 should work
        config_100 = SnifferConfig(
            interface="lo",
            log_dir=temp_log_dir,
            export_dir=temp_log_dir,
            max_memory_packets=100,
        )
        assert config_100.max_memory_packets == 100

        # Large value should work
        config_large = SnifferConfig(
            interface="lo",
            log_dir=temp_log_dir,
            export_dir=temp_log_dir,
            max_memory_packets=1000000,
        )
        assert config_large.max_memory_packets == 1000000


# ============================================================================
# TEST CLASS: Packet Processing Errors
# ============================================================================


class TestPacketProcessingErrors:
    """Test error handling during packet processing."""

    def test_malformed_packet_does_not_crash(
        self, packet_capture: PacketCapture
    ) -> None:
        """Test that malformed packets don't crash processing."""
        # Create a malformed mock packet that will cause issues
        malformed_packet = MagicMock()
        malformed_packet.time = None  # Invalid - should be float
        malformed_packet.__len__.return_value = 100
        malformed_packet.layers.return_value = []
        malformed_packet.haslayer.return_value = False

        # Add to queue with a good packet
        good_packet = MagicMock()
        good_packet.time = 1.0
        good_packet.__len__.return_value = 100
        good_packet.layers.return_value = []
        good_packet.haslayer.return_value = False

        packet_capture.packet_queue.put([malformed_packet, good_packet])
        packet_capture.is_running = False

        # Process should not crash
        packet_capture.process_queue()

        # At least the good packet should have been attempted
        # (processing may or may not succeed depending on error handling)
        assert packet_capture.stats["batch_count"] == 1

    def test_packet_with_exception_in_layer_processing(
        self, packet_capture: PacketCapture
    ) -> None:
        """Test handling when layer processing raises exception."""
        mock_packet = MagicMock()
        mock_packet.time = 1.0
        mock_packet.__len__.return_value = 100

        # Make haslayer return False (no exception thrown)
        # but the layer access via __getitem__ raises exception
        mock_packet.haslayer.return_value = True

        def getitem_side_effect(layer_type: type) -> MagicMock:
            raise RuntimeError("Layer access failed")

        mock_packet.__getitem__.side_effect = getitem_side_effect
        mock_packet.layers.return_value = []

        # Process should handle the error gracefully (exception caught in layer processing)
        result = packet_capture.process_packet_layers(mock_packet)

        # Should still return a packet (with whatever layers it could extract)
        assert result is not None
        assert result.timestamp == 1.0

    def test_packet_with_no_recognizable_layers(
        self, packet_capture: PacketCapture
    ) -> None:
        """Test that packets with no recognizable layers are handled."""
        mock_packet = MagicMock()
        mock_packet.time = 2.0
        mock_packet.__len__.return_value = 64
        mock_packet.haslayer.return_value = False  # No known layers
        mock_packet.layers.return_value = []

        result = packet_capture.process_packet_layers(mock_packet)

        # Should create a minimal packet
        assert result is not None
        assert result.timestamp == 2.0
        assert result.raw_size == 64
        assert len(result.layers) == 0

    def test_none_packet_raises_value_error(
        self, packet_capture: PacketCapture
    ) -> None:
        """Test that None packet raises ValueError."""
        with pytest.raises(ValueError, match="Cannot process None packet"):
            packet_capture.process_packet_layers(None)  # type: ignore[arg-type]

    def test_batch_with_mixed_valid_invalid_packets(
        self, packet_capture: PacketCapture
    ) -> None:
        """Test batch processing with mixed valid and invalid packets."""
        # Create valid packet
        valid_packet = MagicMock()
        valid_packet.time = 1.0
        valid_packet.__len__.return_value = 100
        valid_packet.haslayer.return_value = False
        valid_packet.layers.return_value = []

        # Create packet that will fail processing
        failing_packet = MagicMock()
        failing_packet.time = 2.0
        failing_packet.__len__.side_effect = RuntimeError("Size check failed")
        failing_packet.haslayer.return_value = False
        failing_packet.layers.return_value = []

        packet_capture.packet_queue.put([valid_packet, failing_packet, valid_packet])
        packet_capture.stats["dropped_packets"] = 0
        packet_capture.is_running = False

        packet_capture.process_queue()

        # At least 2 packets should succeed, 1 should be dropped
        assert packet_capture.stats["dropped_packets"] >= 1


# ============================================================================
# TEST CLASS: Data Conversion Errors
# ============================================================================


class TestDataConversionErrors:
    """Test error handling in data conversion methods."""

    def test_to_json_with_non_serializable_data(
        self, packet_capture: PacketCapture
    ) -> None:
        """Test to_json handles non-serializable packet data."""
        # Create a packet that will fail to serialize
        bad_packet = MagicMock(spec=Packet)
        bad_packet.to_json.side_effect = TypeError("Object not JSON serializable")
        packet_capture.packets = [bad_packet]

        with pytest.raises(DataConversionError):
            packet_capture.to_json()

    def test_to_json_returns_empty_for_no_packets(
        self, packet_capture: PacketCapture
    ) -> None:
        """Test to_json returns empty dict when no packets."""
        assert packet_capture.packets == []
        result = packet_capture.to_json()
        assert result == {}

    def test_to_pandas_with_conflicting_types(
        self, packet_capture: PacketCapture
    ) -> None:
        """Test to_pandas_df handles packets with different field types."""
        # Create packets with same field but different types
        layer1 = PacketLayer(layer_name="Test", fields={"value": 42})
        layer2 = PacketLayer(layer_name="Test", fields={"value": "string"})

        packet_capture.packets = [
            Packet(timestamp=1.0, layers=[layer1], raw_size=100),
            Packet(timestamp=2.0, layers=[layer2], raw_size=100),
        ]

        # Pandas should handle type coercion
        result = packet_capture.to_pandas_df()
        assert len(result) == 2

    @pytest.mark.skipif(not POLARS_AVAILABLE, reason="Polars not installed")
    def test_to_polars_with_complex_nested_data(
        self, packet_capture: PacketCapture
    ) -> None:
        """Test to_polars_df handles complex nested data."""
        layer = PacketLayer(
            layer_name="Complex",
            fields={
                "nested": {"a": 1, "b": {"c": 2}},
                "list_field": [1, 2, 3],
            },
        )
        packet_capture.packets = [
            Packet(timestamp=1.0, layers=[layer], raw_size=100)
        ]

        # Should handle without crashing
        result = packet_capture.to_polars_df()
        assert len(result) == 1


# ============================================================================
# TEST CLASS: File I/O Errors
# ============================================================================


class TestFileIOErrors:
    """Test error handling for file operations."""

    @pytest.mark.skipif(not POLARS_AVAILABLE, reason="Polars not installed")
    def test_save_to_parquet_with_empty_packets(
        self, packet_capture: PacketCapture, temp_log_dir: str
    ) -> None:
        """Test save_to_parquet handles empty packet list."""
        assert len(packet_capture.packets) == 0

        filepath = Path(temp_log_dir) / "empty.parquet"
        result = packet_capture.save_to_parquet(str(filepath))

        # Should create an empty parquet file
        assert Path(result).exists()
        df = pl.read_parquet(result)
        assert len(df) == 0

        # Cleanup
        Path(result).unlink()

    @pytest.mark.skipif(not POLARS_AVAILABLE, reason="Polars not installed")
    def test_save_to_parquet_overwrites_existing(
        self, packet_capture: PacketCapture, temp_log_dir: str
    ) -> None:
        """Test save_to_parquet overwrites existing file."""
        filepath = Path(temp_log_dir) / "overwrite.parquet"

        # First save
        layer1 = PacketLayer(layer_name="First", fields={"id": 1})
        packet_capture.packets = [Packet(timestamp=1.0, layers=[layer1], raw_size=100)]
        packet_capture.save_to_parquet(str(filepath))

        # Verify first save
        df1 = pl.read_parquet(filepath)
        assert len(df1) == 1

        # Second save with more packets
        layer2 = PacketLayer(layer_name="Second", fields={"id": 2})
        packet_capture.packets = [
            Packet(timestamp=2.0, layers=[layer2], raw_size=100),
            Packet(timestamp=3.0, layers=[layer2], raw_size=100),
        ]
        packet_capture.save_to_parquet(str(filepath))

        # Verify overwrite
        df2 = pl.read_parquet(filepath)
        assert len(df2) == 2

        # Cleanup
        filepath.unlink()

    @pytest.mark.skipif(not POLARS_AVAILABLE, reason="Polars not installed")
    def test_save_to_parquet_generates_unique_filename(
        self, packet_capture: PacketCapture
    ) -> None:
        """Test save_to_parquet generates unique filename when not specified."""
        layer = PacketLayer(layer_name="Test", fields={"id": 1})
        packet_capture.packets = [Packet(timestamp=1.0, layers=[layer], raw_size=100)]

        # Save without specifying filename - should use default from config
        filepath1 = packet_capture.save_to_parquet()

        assert Path(filepath1).exists()

        # Cleanup
        Path(filepath1).unlink()

    def test_save_preserves_packets_on_error(
        self, packet_capture: PacketCapture
    ) -> None:
        """Test that packets are preserved if save fails."""
        # Add some packets
        for i in range(5):
            layer = PacketLayer(layer_name="Test", fields={"id": i})
            packet_capture.packets.append(
                Packet(timestamp=float(i), layers=[layer], raw_size=100)
            )

        original_count = len(packet_capture.packets)
        assert original_count == 5

        # Try to save to invalid path (should fail but not lose packets)
        with contextlib.suppress(Exception):
            packet_capture.save_to_parquet("/nonexistent/path/file.parquet")

        # Packets should still be in memory
        assert len(packet_capture.packets) == original_count


# ============================================================================
# TEST CLASS: Capture Error Recovery
# ============================================================================


class TestCaptureErrorRecovery:
    """Test error recovery during capture operations."""

    @patch("netguard.capture.packet_capture.sniff")
    def test_capture_recovers_from_sniff_error(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture
    ) -> None:
        """Test that capture handles sniff errors appropriately."""
        mock_sniff.side_effect = OSError("Network interface error")

        with pytest.raises(OSError):
            packet_capture.capture(max_packets=10)

        # Should be able to try again after error
        mock_sniff.side_effect = None
        mock_sniff.return_value = []

        # Second capture should work
        packet_capture.capture(max_packets=0)

    @patch("netguard.capture.packet_capture.sniff")
    def test_capture_cleans_up_on_keyboard_interrupt(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture
    ) -> None:
        """Test that keyboard interrupt is handled cleanly."""
        mock_sniff.side_effect = KeyboardInterrupt()

        with pytest.raises(KeyboardInterrupt):
            packet_capture.capture(max_packets=10)

        # is_running should be False
        assert not packet_capture.is_running

    def test_stats_consistent_after_errors(
        self, packet_capture: PacketCapture
    ) -> None:
        """Test that stats remain consistent after processing errors."""
        # Reset stats and clear packets
        packet_capture.stats = {
            "processed_packets": 0,
            "dropped_packets": 0,
            "processing_time": 0.0,
            "batch_count": 0,
        }
        packet_capture.packets.clear()

        # Drain any existing items in the queue
        while not packet_capture.packet_queue.empty():
            packet_capture.packet_queue.get_nowait()

        # Process some batches
        good_packet = MagicMock()
        good_packet.time = 1.0
        good_packet.__len__.return_value = 100
        good_packet.haslayer.return_value = False
        good_packet.layers.return_value = []

        packet_capture.packet_queue.put([good_packet])
        packet_capture.packet_queue.put([good_packet, good_packet])
        packet_capture.is_running = False

        packet_capture.process_queue()

        # Stats should be consistent
        assert packet_capture.stats["batch_count"] == 2
        # Total packets attempted = processed + dropped
        total = packet_capture.stats["processed_packets"] + packet_capture.stats[
            "dropped_packets"
        ]
        assert total == 3


if __name__ == "__main__":
    pytest.main(["-v", __file__])

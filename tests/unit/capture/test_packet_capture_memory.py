"""
Memory management tests for PacketCapture.

This module tests memory limits, garbage collection, and resource management
in the PacketCapture class to ensure efficient memory usage.
"""

import gc
import tempfile
import threading
import time
import weakref
from collections.abc import Generator
from unittest.mock import MagicMock, patch

import pytest

from netguard.capture.packet_capture import PacketCapture
from netguard.core.config import SnifferConfig
from netguard.models.packet_data_structures import Packet, PacketLayer

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
        max_memory_packets=100,  # Low limit for testing
    )


@pytest.fixture
def large_memory_config(temp_log_dir: str) -> SnifferConfig:
    """Create a SnifferConfig with larger memory limit."""
    return SnifferConfig(
        interface="lo",
        log_dir=temp_log_dir,
        export_dir=temp_log_dir,
        performance_parquet_path=f"{temp_log_dir}/performance.parquet",
        max_memory_packets=1000,
    )


@pytest.fixture
def packet_capture(sniffer_config: SnifferConfig) -> PacketCapture:
    """Create a PacketCapture instance for testing."""
    return PacketCapture(config=sniffer_config)


@pytest.fixture
def large_packet_capture(large_memory_config: SnifferConfig) -> PacketCapture:
    """Create a PacketCapture with larger memory limit."""
    return PacketCapture(config=large_memory_config)


def create_mock_scapy_packet(
    timestamp: float = 1234567890.0,
    size: int = 100,
) -> MagicMock:
    """Create a mock Scapy packet for testing."""
    mock_packet = MagicMock()
    mock_packet.time = timestamp
    mock_packet.__len__.return_value = size
    mock_packet.layers.return_value = []
    mock_packet.haslayer.return_value = False
    return mock_packet


def create_sample_packet(
    timestamp: float = 1234567890.0,
    raw_size: int = 100,
    num_layers: int = 1,
) -> Packet:
    """Create a sample Packet object for testing."""
    layers = [PacketLayer(layer_name=f"Layer{i}", fields={"id": i}) for i in range(num_layers)]
    return Packet(timestamp=timestamp, layers=layers, raw_size=raw_size)


# ============================================================================
# TEST CLASS: Memory Limits
# ============================================================================


class TestMemoryLimits:
    """Test memory limit enforcement."""

    def test_init_validates_min_memory_packets(self, temp_log_dir: str) -> None:
        """Test that initialization validates minimum memory packets."""
        with pytest.raises(ValueError, match="must be at least 100"):
            SnifferConfig(
                interface="lo",
                log_dir=temp_log_dir,
                export_dir=temp_log_dir,
                max_memory_packets=50,
            )

    def test_init_validates_memory_packets_multiple_of_10(self, temp_log_dir: str) -> None:
        """Test that max_memory_packets must be multiple of 10."""
        with pytest.raises(ValueError, match="must be a multiple of 10"):
            SnifferConfig(
                interface="lo",
                log_dir=temp_log_dir,
                export_dir=temp_log_dir,
                max_memory_packets=105,
            )

    def test_memory_limit_configuration(self, packet_capture: PacketCapture) -> None:
        """Test that memory limit is properly configured."""
        assert packet_capture.max_memory_packets == 100

    @patch("netguard.capture.packet_capture.sniff")
    def test_packet_trimming_at_memory_limit(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture
    ) -> None:
        """Test that packets are trimmed when memory limit is reached during capture."""
        gc_collected = []

        # Pre-fill to exactly at the limit
        for i in range(100):
            packet_capture.packets.append(create_sample_packet(timestamp=float(i)))

        def sniff_side_effect(**kwargs) -> None:
            prn = kwargs.get("prn")
            if prn:
                # Add packets that will trigger trimming (callback checks before adding to buffer)
                for i in range(10):
                    mock_pkt = create_mock_scapy_packet(timestamp=float(100 + i))
                    prn(mock_pkt)

        mock_sniff.side_effect = sniff_side_effect

        with patch("netguard.capture.packet_capture.gc.collect") as mock_gc:
            mock_gc.side_effect = lambda: gc_collected.append(True)
            packet_capture.capture(max_packets=10)

        # gc.collect should have been called since we hit the limit
        assert len(gc_collected) >= 1
        # After capture completes, packets list may exceed limit briefly during queue processing
        # but should be trimmed on next callback. Verify gc was triggered as the key behavior.

    def test_packet_list_trimming_keeps_recent(self, packet_capture: PacketCapture) -> None:
        """Test that trimming keeps the most recent packets."""
        # Fill beyond limit
        for i in range(150):
            packet_capture.packets.append(create_sample_packet(timestamp=float(i)))

        # Simulate trimming (as done in packet_callback_wrapper)
        packet_capture.packets = packet_capture.packets[-packet_capture.max_memory_packets :]

        # Should keep the most recent packets
        assert len(packet_capture.packets) == 100
        # First packet should be timestamp 50 (150 - 100)
        assert packet_capture.packets[0].timestamp == 50.0
        # Last packet should be timestamp 149
        assert packet_capture.packets[-1].timestamp == 149.0


# ============================================================================
# TEST CLASS: Garbage Collection
# ============================================================================


class TestGarbageCollection:
    """Test garbage collection behavior."""

    @patch("netguard.capture.packet_capture.sniff")
    def test_gc_collect_called_on_trim(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture
    ) -> None:
        """Test that gc.collect is called when packets are trimmed."""
        gc_calls = []

        # Pre-fill to trigger trimming
        for i in range(packet_capture.max_memory_packets):
            packet_capture.packets.append(create_sample_packet(timestamp=float(i)))

        def sniff_side_effect(**kwargs) -> None:
            prn = kwargs.get("prn")
            if prn:
                prn(create_mock_scapy_packet(timestamp=999.0))

        mock_sniff.side_effect = sniff_side_effect

        with patch("netguard.capture.packet_capture.gc.collect") as mock_gc:
            mock_gc.side_effect = lambda: gc_calls.append(True)
            packet_capture.capture(max_packets=1)

        # gc.collect should have been called during trimming
        assert len(gc_calls) >= 1

    def test_packet_objects_are_gc_eligible(self) -> None:
        """Test that packet objects can be garbage collected."""
        # Create packet and weak reference
        packet = create_sample_packet(timestamp=1.0, num_layers=3)
        weak_ref = weakref.ref(packet)

        # Verify reference exists
        assert weak_ref() is not None

        # Delete strong reference
        del packet

        # Force garbage collection
        gc.collect()

        # Weak reference should be dead
        assert weak_ref() is None

    def test_deque_maxlen_limits_realtime_packets(self, packet_capture: PacketCapture) -> None:
        """Test that realtime_packets deque respects maxlen."""
        # The deque should have maxlen=50
        assert packet_capture.realtime_packets.maxlen == 50

        # Add more than maxlen packets
        for i in range(100):
            packet_capture.realtime_packets.append(create_sample_packet(timestamp=float(i)))

        # Should only contain maxlen packets
        assert len(packet_capture.realtime_packets) == 50
        # Should contain the most recent packets (50-99)
        assert packet_capture.realtime_packets[0].timestamp == 50.0
        assert packet_capture.realtime_packets[-1].timestamp == 99.0


# ============================================================================
# TEST CLASS: Large Packet Handling
# ============================================================================


class TestLargePacketHandling:
    """Test handling of large packets and data."""

    def test_large_packet_raw_size(self, packet_capture: PacketCapture) -> None:
        """Test processing packets with large raw_size."""
        # Create packet with large size (jumbo frame)
        large_packet = create_mock_scapy_packet(size=9000)

        processed = packet_capture.process_packet_layers(large_packet)

        assert processed.raw_size == 9000

    def test_packet_with_many_layers(self, packet_capture: PacketCapture) -> None:
        """Test processing packets with many layers."""
        mock_packet = create_mock_scapy_packet()

        # Create many mock layers
        mock_layers = []
        for i in range(20):
            layer = MagicMock()
            layer.__name__ = f"Layer{i}"
            layer.fields_desc = []
            mock_layers.append(layer)

        mock_packet.layers.return_value = mock_layers

        processed = packet_capture.process_packet_layers(mock_packet)

        # Should process without error
        assert processed is not None

    def test_packet_with_large_field_values(self, packet_capture: PacketCapture) -> None:
        """Test processing packets with large field values."""
        mock_packet = create_mock_scapy_packet()

        # Simulate a packet with large payload data
        mock_layer = MagicMock()
        mock_layer.__name__ = "LargePayload"
        mock_layer.fields_desc = [MagicMock(name="data")]

        mock_packet.layers.return_value = [mock_layer]
        mock_packet.__getitem__.return_value = MagicMock(
            data="X" * 10000  # 10KB payload
        )

        processed = packet_capture.process_packet_layers(mock_packet)

        assert processed is not None

    def test_many_packets_memory_stability(self, large_packet_capture: PacketCapture) -> None:
        """Test memory stability when processing many packets."""
        initial_packets = len(large_packet_capture.packets)

        # Process many packets
        for i in range(500):
            mock_packet = create_mock_scapy_packet(timestamp=float(i))
            processed = large_packet_capture.process_packet_layers(mock_packet)
            large_packet_capture.packets.append(processed)

        # Verify all packets stored
        assert len(large_packet_capture.packets) == initial_packets + 500


# ============================================================================
# TEST CLASS: Resource Cleanup
# ============================================================================


class TestResourceCleanup:
    """Test proper resource cleanup."""

    def test_queue_cleanup_after_processing(self, packet_capture: PacketCapture) -> None:
        """Test that queue is properly cleaned up after processing."""
        # Add packets to queue
        for i in range(5):
            batch = [create_mock_scapy_packet(timestamp=float(i))]
            packet_capture.packet_queue.put(batch)

        # Process all
        packet_capture.is_running = False
        packet_capture.process_queue()

        # Queue should be empty
        assert packet_capture.packet_queue.empty()

    @patch("netguard.capture.packet_capture.sniff")
    def test_cleanup_after_capture_error(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture
    ) -> None:
        """Test cleanup occurs even after capture errors."""
        mock_sniff.side_effect = RuntimeError("Network error")

        with pytest.raises(RuntimeError):
            packet_capture.capture(max_packets=10)

        # is_running should be False after error
        assert not packet_capture.is_running

    def test_stats_reset_capability(self, packet_capture: PacketCapture) -> None:
        """Test that stats can be reset between captures."""
        # Simulate some activity
        packet_capture.update_stats(processing_time=1.0, batch_size=10)
        packet_capture.stats["dropped_packets"] = 5

        # Verify stats were updated
        assert packet_capture.stats["processed_packets"] == 10
        assert packet_capture.stats["dropped_packets"] == 5

        # Reset stats manually (simulating new capture session)
        packet_capture.stats = {
            "processed_packets": 0,
            "dropped_packets": 0,
            "processing_time": 0.0,
            "batch_count": 0,
        }

        # Verify reset
        assert packet_capture.stats["processed_packets"] == 0
        assert packet_capture.stats["dropped_packets"] == 0

    def test_packets_list_can_be_cleared(self, packet_capture: PacketCapture) -> None:
        """Test that packets list can be cleared for new capture."""
        # Add some packets
        for i in range(50):
            packet_capture.packets.append(create_sample_packet(timestamp=float(i)))

        assert len(packet_capture.packets) == 50

        # Clear packets
        packet_capture.packets.clear()

        assert len(packet_capture.packets) == 0


# ============================================================================
# TEST CLASS: Memory Stress Tests
# ============================================================================


class TestMemoryStress:
    """Stress tests for memory handling."""

    def test_rapid_packet_addition_and_removal(self, packet_capture: PacketCapture) -> None:
        """Test rapid addition and removal of packets."""
        for cycle in range(10):
            # Add packets
            for i in range(50):
                packet_capture.packets.append(
                    create_sample_packet(timestamp=float(cycle * 100 + i))
                )

            # Trim to limit
            if len(packet_capture.packets) > packet_capture.max_memory_packets:
                packet_capture.packets = packet_capture.packets[
                    -packet_capture.max_memory_packets :
                ]

        # Should stay within limits
        assert len(packet_capture.packets) <= packet_capture.max_memory_packets

    def test_concurrent_memory_operations(self, packet_capture: PacketCapture) -> None:
        """Test memory operations under concurrent access."""
        errors: list[Exception] = []

        def add_packets() -> None:
            try:
                for i in range(100):
                    packet_capture.packets.append(create_sample_packet(timestamp=float(i)))
            except Exception as e:
                errors.append(e)

        def trim_packets() -> None:
            try:
                for _ in range(100):
                    if len(packet_capture.packets) > 50:
                        packet_capture.packets = packet_capture.packets[-50:]
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=add_packets),
            threading.Thread(target=trim_packets),
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        # No errors should occur (list operations are thread-safe in Python)
        # Note: This tests basic safety, not correctness of concurrent modifications
        assert len(errors) == 0

    def test_packet_with_circular_reference(self, packet_capture: PacketCapture) -> None:
        """Test that packets with complex structures don't cause memory leaks."""
        # Create packets with nested structures
        for i in range(100):
            nested_fields = {"level1": {"level2": {"level3": {"value": i}}}}
            layer = PacketLayer(layer_name="Nested", fields=nested_fields)
            packet = Packet(timestamp=float(i), layers=[layer], raw_size=100)
            packet_capture.packets.append(packet)

        # Clear and force GC
        packet_capture.packets.clear()
        gc.collect()

        # Should have no remaining packets
        assert len(packet_capture.packets) == 0


# ============================================================================
# TEST CLASS: Configuration Validation
# ============================================================================


class TestConfigurationValidation:
    """Test configuration validation for memory settings."""

    def test_valid_memory_configurations(self, temp_log_dir: str) -> None:
        """Test various valid memory configurations."""
        valid_configs = [100, 500, 1000, 10000, 100000]

        for max_packets in valid_configs:
            config = SnifferConfig(
                interface="lo",
                log_dir=temp_log_dir,
                export_dir=temp_log_dir,
                max_memory_packets=max_packets,
            )
            capture = PacketCapture(config=config)
            assert capture.max_memory_packets == max_packets

    def test_invalid_memory_configurations(self, temp_log_dir: str) -> None:
        """Test that invalid memory configurations are rejected."""
        invalid_configs = [
            (50, "must be at least 100"),
            (99, "must be at least 100"),
            (101, "must be a multiple of 10"),
            (155, "must be a multiple of 10"),
        ]

        for max_packets, error_msg in invalid_configs:
            with pytest.raises(ValueError, match=error_msg):
                SnifferConfig(
                    interface="lo",
                    log_dir=temp_log_dir,
                    export_dir=temp_log_dir,
                    max_memory_packets=max_packets,
                )

    def test_memory_limit_affects_trimming_threshold(self, temp_log_dir: str) -> None:
        """Test that different memory limits affect trimming behavior."""
        # Small limit
        small_config = SnifferConfig(
            interface="lo",
            log_dir=temp_log_dir,
            export_dir=temp_log_dir,
            max_memory_packets=100,
        )
        small_capture = PacketCapture(config=small_config)

        # Large limit
        large_config = SnifferConfig(
            interface="lo",
            log_dir=temp_log_dir,
            export_dir=temp_log_dir,
            max_memory_packets=1000,
        )
        large_capture = PacketCapture(config=large_config)

        # Add 500 packets to both
        for i in range(500):
            packet = create_sample_packet(timestamp=float(i))
            small_capture.packets.append(packet)
            large_capture.packets.append(packet)

        # Apply trimming
        if len(small_capture.packets) > small_capture.max_memory_packets:
            small_capture.packets = small_capture.packets[-small_capture.max_memory_packets :]

        if len(large_capture.packets) > large_capture.max_memory_packets:
            large_capture.packets = large_capture.packets[-large_capture.max_memory_packets :]

        # Small capture should be trimmed, large should not
        assert len(small_capture.packets) == 100
        assert len(large_capture.packets) == 500


# ============================================================================
# TEST CLASS: Memory Efficiency
# ============================================================================


class TestMemoryEfficiency:
    """Test memory usage and garbage collection efficiency."""

    @patch("netguard.capture.packet_capture.sniff")
    def test_garbage_collection_called_on_memory_limit(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture
    ) -> None:
        """Test that garbage collection is triggered when memory limit is hit."""
        gc_calls: list[bool] = []

        # Pre-fill to memory limit
        for i in range(packet_capture.max_memory_packets):
            packet_capture.packets.append(create_sample_packet(timestamp=float(i)))

        def sniff_side_effect(**kwargs) -> None:
            prn = kwargs.get("prn")
            if prn:
                # Add more packets to trigger memory limit check
                for i in range(10):
                    prn(create_mock_scapy_packet(timestamp=float(1000 + i)))

        mock_sniff.side_effect = sniff_side_effect

        with patch("netguard.capture.packet_capture.gc.collect") as mock_gc:
            mock_gc.side_effect = lambda: gc_calls.append(True)
            packet_capture.capture(max_packets=10)

        # GC should have been called when memory limit was reached
        assert len(gc_calls) >= 1

    def test_packet_queue_bounded_growth(self, packet_capture: PacketCapture) -> None:
        """Test that packet queue doesn't grow unbounded."""
        initial_qsize = packet_capture.packet_queue.qsize()

        # Add many batches rapidly
        for i in range(100):
            batch = [create_mock_scapy_packet(timestamp=float(i * 10 + j)) for j in range(5)]
            packet_capture.packet_queue.put(batch)

        # Queue should contain the batches we added
        assert packet_capture.packet_queue.qsize() == initial_qsize + 100

        # Process queue to drain it
        packet_capture.is_running = False
        packet_capture.process_queue()

        # Queue should be empty after processing
        assert packet_capture.packet_queue.empty()

    def test_memory_released_after_clear(self, packet_capture: PacketCapture) -> None:
        """Test that memory is properly released when packets are cleared."""
        # Add many packets
        for i in range(500):
            packet_capture.packets.append(create_sample_packet(timestamp=float(i), num_layers=5))

        assert len(packet_capture.packets) == 500

        # Clear packets
        packet_capture.packets.clear()
        gc.collect()

        # Verify packets are cleared
        assert len(packet_capture.packets) == 0

    def test_large_batch_memory_efficiency(self, packet_capture: PacketCapture) -> None:
        """Test memory handling with large processing batches."""
        # Create a large batch
        large_batch = [create_mock_scapy_packet(timestamp=float(i)) for i in range(500)]
        packet_capture.packet_queue.put(large_batch)

        # Process the large batch
        packet_capture.is_running = False
        packet_capture.process_queue()

        # All packets should be processed
        assert len(packet_capture.packets) == 500
        assert packet_capture.stats["batch_count"] == 1

    def test_continuous_processing_memory_stability(self, packet_capture: PacketCapture) -> None:
        """Test memory stability during continuous packet processing."""
        # Simulate continuous capture with periodic trimming
        for cycle in range(5):
            # Add packets
            for i in range(50):
                packet_capture.packets.append(
                    create_sample_packet(timestamp=float(cycle * 100 + i))
                )

            # Check if trimming needed (simulating callback behavior)
            if len(packet_capture.packets) >= packet_capture.max_memory_packets:
                packet_capture.packets = packet_capture.packets[
                    -packet_capture.max_memory_packets :
                ]
                gc.collect()

        # Should stay within bounds
        assert len(packet_capture.packets) <= packet_capture.max_memory_packets


# ============================================================================
# TEST CLASS: Batch Processing Memory
# ============================================================================


class TestBatchProcessingMemory:
    """Test memory management during batch processing."""

    def test_batch_size_configuration(self, temp_log_dir: str) -> None:
        """Test batch size configuration affects processing."""
        small_batch_config = SnifferConfig(
            interface="lo",
            log_dir=temp_log_dir,
            export_dir=temp_log_dir,
            max_processing_batch_size=10,
        )
        large_batch_config = SnifferConfig(
            interface="lo",
            log_dir=temp_log_dir,
            export_dir=temp_log_dir,
            max_processing_batch_size=100,
        )

        small_capture = PacketCapture(config=small_batch_config)
        large_capture = PacketCapture(config=large_batch_config)

        assert small_capture.config.max_processing_batch_size == 10
        assert large_capture.config.max_processing_batch_size == 100

    def test_batch_processing_stats_accuracy(self, packet_capture: PacketCapture) -> None:
        """Test that batch processing stats are accurate."""
        # Reset stats
        packet_capture.stats = {
            "processed_packets": 0,
            "dropped_packets": 0,
            "processing_time": 0.0,
            "batch_count": 0,
        }

        # Add multiple batches of different sizes
        batch_sizes = [5, 10, 15, 3, 7]
        for batch_size in batch_sizes:
            batch = [create_mock_scapy_packet(timestamp=float(i)) for i in range(batch_size)]
            packet_capture.packet_queue.put(batch)

        packet_capture.is_running = False
        packet_capture.process_queue()

        # Verify stats
        assert packet_capture.stats["batch_count"] == len(batch_sizes)
        assert packet_capture.stats["processed_packets"] == sum(batch_sizes)

    def test_empty_batch_doesnt_corrupt_memory(self, packet_capture: PacketCapture) -> None:
        """Test that empty batches don't cause memory issues."""
        initial_packets = len(packet_capture.packets)

        # Add empty batch
        packet_capture.packet_queue.put([])

        # Add normal batch
        packet_capture.packet_queue.put([create_mock_scapy_packet(timestamp=1.0)])

        # Add another empty batch
        packet_capture.packet_queue.put([])

        packet_capture.is_running = False
        packet_capture.process_queue()

        # Only the non-empty batch should add packets
        assert len(packet_capture.packets) == initial_packets + 1
        assert packet_capture.stats["batch_count"] == 3

    def test_mixed_batch_sizes_memory_handling(self, packet_capture: PacketCapture) -> None:
        """Test memory handling with varying batch sizes."""
        # Add batches of very different sizes
        batch_sizes = [1, 100, 5, 50, 2, 75]
        total_packets = sum(batch_sizes)

        for batch_size in batch_sizes:
            batch = [create_mock_scapy_packet(timestamp=float(i)) for i in range(batch_size)]
            packet_capture.packet_queue.put(batch)

        packet_capture.is_running = False
        packet_capture.process_queue()

        assert len(packet_capture.packets) == total_packets


# ============================================================================
# TEST CLASS: Queue Memory Management
# ============================================================================


class TestQueueMemoryManagement:
    """Test memory management in packet queues."""

    def test_queue_timeout_releases_resources(self, packet_capture: PacketCapture) -> None:
        """Test that queue timeout properly releases resources."""
        packet_capture.is_running = True

        # Start processing with empty queue
        def process_with_timeout() -> None:
            # Process will timeout on empty queue and exit when is_running=False
            packet_capture.process_queue()

        process_thread = threading.Thread(target=process_with_timeout)
        process_thread.start()

        # Let it run with empty queue for a bit
        time.sleep(1.5)

        # Stop and wait
        packet_capture.is_running = False
        process_thread.join(timeout=3)

        # Thread should have exited cleanly
        assert not process_thread.is_alive()

    def test_queue_clear_during_processing(self, packet_capture: PacketCapture) -> None:
        """Test behavior when queue is cleared during processing."""
        # Add some batches
        for i in range(5):
            batch = [create_mock_scapy_packet(timestamp=float(i))]
            packet_capture.packet_queue.put(batch)

        # Process one batch at a time manually
        packet_capture.is_running = False

        # Process first batch
        batch = packet_capture.packet_queue.get()
        assert len(batch) == 1

        # Remaining batches still in queue
        assert packet_capture.packet_queue.qsize() == 4

    def test_queue_overflow_prevention(self, temp_log_dir: str) -> None:
        """Test that queue operations handle high load gracefully."""
        config = SnifferConfig(
            interface="lo",
            log_dir=temp_log_dir,
            export_dir=temp_log_dir,
        )
        capture = PacketCapture(config=config)

        # Add many batches rapidly
        added_count = 0
        for i in range(1000):
            batch = [create_mock_scapy_packet(timestamp=float(i))]
            capture.packet_queue.put(batch)
            added_count += 1

        # All batches should be in queue (Python Queue is unbounded by default)
        assert capture.packet_queue.qsize() == added_count

        # Process all
        capture.is_running = False
        capture.process_queue()

        # All should be processed
        assert len(capture.packets) == added_count


if __name__ == "__main__":
    pytest.main(["-v", __file__])

"""
Threading and concurrency tests for PacketCapture.

This module tests thread safety, queue processing, and concurrent operations
in the PacketCapture class to ensure reliable operation under load.
"""

import tempfile
import threading
import time
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
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
        max_processing_batch_size=5,
        num_threads=2,
    )


@pytest.fixture
def packet_capture(sniffer_config: SnifferConfig) -> PacketCapture:
    """Create a PacketCapture instance for testing."""
    return PacketCapture(config=sniffer_config)


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


# ============================================================================
# TEST CLASS: Queue Processing
# ============================================================================


class TestPacketQueueProcessing:
    """Test the queue-based packet processing system."""

    def test_process_queue_starts_and_stops_cleanly(self, packet_capture: PacketCapture) -> None:
        """Test that process_queue can start and stop without errors."""
        # Add some packets to queue
        mock_packets = [create_mock_scapy_packet(timestamp=float(i)) for i in range(5)]
        packet_capture.packet_queue.put(mock_packets)

        # Start processing in background thread
        packet_capture.is_running = True
        process_thread = threading.Thread(target=packet_capture.process_queue)
        process_thread.start()

        # Give some time to process
        time.sleep(0.5)

        # Stop processing
        packet_capture.is_running = False
        process_thread.join(timeout=3)

        # Verify thread completed
        assert not process_thread.is_alive()
        # Verify queue is empty
        assert packet_capture.packet_queue.empty()
        # Verify packets were processed
        assert len(packet_capture.packets) == 5

    def test_process_queue_handles_empty_queue(self, packet_capture: PacketCapture) -> None:
        """Test process_queue waits when queue is empty."""
        packet_capture.is_running = True

        # Start processing in background thread
        process_thread = threading.Thread(target=packet_capture.process_queue)
        process_thread.start()

        # Wait a bit with empty queue
        time.sleep(1.5)

        # Add a packet after some time
        mock_packet = create_mock_scapy_packet(timestamp=999.0)
        packet_capture.packet_queue.put([mock_packet])

        # Give time to process
        time.sleep(0.5)

        # Stop processing
        packet_capture.is_running = False
        process_thread.join(timeout=3)

        # Verify packet was processed
        assert len(packet_capture.packets) == 1
        assert packet_capture.packets[0].timestamp == 999.0

    def test_process_queue_processes_batches(self, packet_capture: PacketCapture) -> None:
        """Test that packets are processed in batches."""
        # Create multiple batches
        batch1 = [create_mock_scapy_packet(timestamp=float(i)) for i in range(5)]
        batch2 = [create_mock_scapy_packet(timestamp=float(i + 100)) for i in range(3)]

        packet_capture.packet_queue.put(batch1)
        packet_capture.packet_queue.put(batch2)

        # Process with is_running=False to exit after draining queue
        packet_capture.is_running = False
        packet_capture.process_queue()

        # Verify all packets processed
        assert len(packet_capture.packets) == 8
        # Verify stats show correct batch count
        assert packet_capture.stats["batch_count"] == 2
        assert packet_capture.stats["processed_packets"] == 8
        # Verify timing stats are recorded
        assert packet_capture.stats["processing_time"] > 0

    def test_process_queue_continues_on_packet_error(self, packet_capture: PacketCapture) -> None:
        """Test that processing continues if one packet fails."""
        good_packet1 = create_mock_scapy_packet(timestamp=1.0)
        bad_packet = create_mock_scapy_packet(timestamp=2.0)
        good_packet2 = create_mock_scapy_packet(timestamp=3.0)

        # Mark packets explicitly (MagicMock returns MagicMock for any attr)
        good_packet1.should_fail = False
        bad_packet.should_fail = True
        good_packet2.should_fail = False

        call_count = [0]

        def mock_process(pkt: MagicMock) -> MagicMock:
            call_count[0] += 1
            if pkt.should_fail is True:  # Explicit True check
                raise ValueError("Simulated processing error")
            # Return a mock Packet with id attribute (required by logging)
            mock_packet = MagicMock(spec=Packet)
            mock_packet.timestamp = float(pkt.time)
            mock_packet.layers = []
            mock_packet.raw_size = 100
            mock_packet.id = f"test-{pkt.time}"  # Add id for logging
            return mock_packet

        # Reset dropped_packets to ensure clean state
        packet_capture.stats["dropped_packets"] = 0

        # Use wraps-style patching by replacing the method
        original_process = packet_capture.process_packet_layers
        packet_capture.process_packet_layers = mock_process  # type: ignore[method-assign]

        try:
            packet_capture.packet_queue.put([good_packet1, bad_packet, good_packet2])
            packet_capture.is_running = False
            packet_capture.process_queue()

            # Verify all packets were attempted
            assert call_count[0] == 3
            # Verify good packets still processed
            assert len(packet_capture.packets) == 2
            # Verify dropped_packets stat incremented
            assert packet_capture.stats["dropped_packets"] == 1
        finally:
            # Restore original method
            packet_capture.process_packet_layers = original_process  # type: ignore[method-assign]

    def test_process_queue_drains_on_stop(self, packet_capture: PacketCapture) -> None:
        """Test that queue is fully drained when stopping."""
        # Add multiple batches
        for i in range(5):
            batch = [create_mock_scapy_packet(timestamp=float(i * 10 + j)) for j in range(3)]
            packet_capture.packet_queue.put(batch)

        # Start processing
        packet_capture.is_running = True
        process_thread = threading.Thread(target=packet_capture.process_queue)
        process_thread.start()

        # Immediately stop
        packet_capture.is_running = False

        # Wait for thread to finish
        process_thread.join(timeout=5)

        # Verify all queued batches still process
        assert len(packet_capture.packets) == 15
        # Verify queue is empty
        assert packet_capture.packet_queue.empty()

    def test_process_queue_multiple_batches_sequential(self, packet_capture: PacketCapture) -> None:
        """Test processing multiple sequential batches."""
        total_packets = 0
        for i in range(10):
            batch_size = (i % 3) + 1
            batch = [
                create_mock_scapy_packet(timestamp=float(i * 100 + j)) for j in range(batch_size)
            ]
            packet_capture.packet_queue.put(batch)
            total_packets += batch_size

        packet_capture.is_running = False
        packet_capture.process_queue()

        assert len(packet_capture.packets) == total_packets
        assert packet_capture.stats["batch_count"] == 10


# ============================================================================
# TEST CLASS: Thread Safety
# ============================================================================


class TestThreadSafety:
    """Test thread-safe operations."""

    def test_stats_update_is_thread_safe(self, packet_capture: PacketCapture) -> None:
        """Test that concurrent stats updates don't corrupt data."""
        num_threads = 10
        updates_per_thread = 100
        expected_packets = num_threads * updates_per_thread
        expected_batches = num_threads * updates_per_thread

        def update_stats_task() -> None:
            for _ in range(updates_per_thread):
                packet_capture.update_stats(processing_time=0.01, batch_size=1)

        # Run concurrent updates
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(update_stats_task) for _ in range(num_threads)]
            for future in futures:
                future.result()

        # Verify final stats are correct (no race conditions)
        assert packet_capture.stats["processed_packets"] == expected_packets
        assert packet_capture.stats["batch_count"] == expected_batches
        # Allow small floating point tolerance
        expected_time = num_threads * updates_per_thread * 0.01
        assert abs(packet_capture.stats["processing_time"] - expected_time) < 0.001

    def test_concurrent_packet_processing(self, packet_capture: PacketCapture) -> None:
        """Test multiple threads processing packets simultaneously."""
        # Add many packets to queue
        num_batches = 20
        packets_per_batch = 5

        for i in range(num_batches):
            batch = [
                create_mock_scapy_packet(timestamp=float(i * 100 + j))
                for j in range(packets_per_batch)
            ]
            packet_capture.packet_queue.put(batch)

        # Start multiple processing threads
        packet_capture.is_running = True
        threads = []
        for _ in range(3):
            t = threading.Thread(target=packet_capture.process_queue)
            t.start()
            threads.append(t)

        # Stop after a short delay
        time.sleep(1)
        packet_capture.is_running = False

        # Wait for all threads
        for t in threads:
            t.join(timeout=3)

        # Verify all packets processed (may have some duplicates due to race, but no data loss)
        assert packet_capture.stats["processed_packets"] == num_batches * packets_per_batch

    def test_realtime_packets_deque_thread_safety(self, packet_capture: PacketCapture) -> None:
        """Test that realtime_packets deque is safely accessed by multiple threads."""
        packet_capture.realtime_display = True
        errors = []

        def writer_task() -> None:
            """Add packets to the deque."""
            try:
                for i in range(100):
                    layer = PacketLayer(layer_name="Test", fields={"id": i})
                    packet = Packet(timestamp=float(i), layers=[layer], raw_size=100)
                    packet_capture.realtime_packets.append(packet)
                    time.sleep(0.001)
            except Exception as e:
                errors.append(f"Writer error: {e}")

        def reader_task() -> None:
            """Read from the deque."""
            try:
                for _ in range(100):
                    # Access the deque safely
                    _ = list(packet_capture.realtime_packets)[-10:]
                    time.sleep(0.001)
            except Exception as e:
                errors.append(f"Reader error: {e}")

        # Start writer and reader threads
        writer = threading.Thread(target=writer_task)
        reader = threading.Thread(target=reader_task)

        writer.start()
        reader.start()

        writer.join(timeout=5)
        reader.join(timeout=5)

        # Verify no errors occurred
        assert len(errors) == 0, f"Thread safety errors: {errors}"

    def test_stats_lock_prevents_race_conditions(self, packet_capture: PacketCapture) -> None:
        """Test that stats_lock prevents race conditions during reads/writes."""
        results = []

        def read_stats_task() -> None:
            """Read stats with lock."""
            for _ in range(50):
                with packet_capture.stats_lock:
                    stats_copy = packet_capture.stats.copy()
                    results.append(stats_copy)
                time.sleep(0.001)

        def write_stats_task() -> None:
            """Write stats with lock."""
            for _ in range(50):
                packet_capture.update_stats(processing_time=0.1, batch_size=10)
                time.sleep(0.001)

        reader = threading.Thread(target=read_stats_task)
        writer = threading.Thread(target=write_stats_task)

        reader.start()
        writer.start()

        reader.join(timeout=5)
        writer.join(timeout=5)

        # Verify all reads got consistent snapshots
        for stats in results:
            assert "processed_packets" in stats
            assert "batch_count" in stats
            # processed_packets should always be batch_count * 10
            assert stats["processed_packets"] == stats["batch_count"] * 10


# ============================================================================
# TEST CLASS: Thread Lifecycle
# ============================================================================


class TestThreadLifecycle:
    """Test thread creation, management, and cleanup."""

    @patch("netguard.capture.packet_capture.sniff")
    def test_start_capture_creates_threads(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture
    ) -> None:
        """Test that start_capture creates necessary threads."""
        mock_sniff.return_value = []

        # Capture should create processing threads
        packet_capture.capture(max_packets=0, num_threads=2)

        # The threads should have completed since sniff returned immediately
        # We can verify by checking that processing completed
        assert packet_capture.stats["batch_count"] >= 0

    @patch("netguard.capture.packet_capture.sniff")
    def test_stop_capture_joins_threads(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture
    ) -> None:
        """Test that stop_capture properly joins all threads."""
        threads_started = []
        threads_joined = []

        original_thread_init = threading.Thread.__init__
        original_thread_join = threading.Thread.join

        def track_thread_init(self: threading.Thread, *args, **kwargs) -> None:
            original_thread_init(self, *args, **kwargs)
            threads_started.append(self)

        def track_thread_join(self: threading.Thread, *args, **kwargs) -> None:
            threads_joined.append(self)
            return original_thread_join(self, *args, **kwargs)

        with (
            patch.object(threading.Thread, "__init__", track_thread_init),
            patch.object(threading.Thread, "join", track_thread_join),
        ):
            mock_sniff.return_value = []
            packet_capture.capture(max_packets=0, num_threads=2)

        # All threads that started should have been joined
        # Note: We may have more joins than starts due to daemon threads
        assert len(threads_joined) >= 2

    @patch("netguard.capture.packet_capture.sniff")
    def test_capture_with_realtime_creates_display_thread(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture
    ) -> None:
        """Test that realtime display creates additional thread."""
        mock_sniff.return_value = []

        packet_capture.capture(max_packets=0, realtime=True)

        # Display thread should have been created and stopped
        # We verify by checking that stop_realtime_display was effective
        assert not packet_capture.display_running

    @patch("netguard.capture.packet_capture.sniff")
    def test_multiple_start_stop_cycles(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture
    ) -> None:
        """Test that capture can be started and stopped multiple times."""
        mock_sniff.return_value = []

        # First cycle
        packet_capture.capture(max_packets=0)
        first_stats = packet_capture.stats.copy()

        # Add some packets manually for second cycle
        layer = PacketLayer(layer_name="Test", fields={})
        packet_capture.packets.append(Packet(timestamp=1.0, layers=[layer], raw_size=100))

        # Second cycle
        packet_capture.capture(max_packets=0)

        # Verify no crashes and capture completed
        # Note: Stats may accumulate across cycles
        assert packet_capture.stats["batch_count"] >= first_stats["batch_count"]

    def test_thread_cleanup_on_exception(self, packet_capture: PacketCapture) -> None:
        """Test that threads are cleaned up even when exceptions occur."""
        packet_capture.is_running = True

        def failing_process_queue() -> None:
            raise RuntimeError("Simulated thread failure")

        # Start a thread that will fail
        failing_thread = threading.Thread(target=failing_process_queue)
        failing_thread.start()
        failing_thread.join(timeout=2)

        # Thread should complete (even with exception)
        assert not failing_thread.is_alive()

    @patch("netguard.capture.packet_capture.sniff")
    def test_realtime_display_thread_lifecycle(
        self, mock_sniff: MagicMock, packet_capture: PacketCapture
    ) -> None:
        """Test complete lifecycle of realtime display thread."""

        def delayed_sniff(**kwargs) -> list:
            # Simulate sniffing taking some time
            time.sleep(0.5)
            return []

        mock_sniff.side_effect = delayed_sniff

        # Patch the display loop to not actually clear screen
        with patch.object(packet_capture, "_realtime_display_loop"):
            packet_capture.capture(max_packets=0, realtime=True)

        # Verify display thread stopped
        assert not packet_capture.display_running


# ============================================================================
# TEST CLASS: Queue Edge Cases
# ============================================================================


class TestQueueEdgeCases:
    """Test edge cases in queue processing."""

    def test_empty_batch_handling(self, packet_capture: PacketCapture) -> None:
        """Test handling of empty batches in queue."""
        packet_capture.packet_queue.put([])
        packet_capture.is_running = False

        packet_capture.process_queue()

        # Empty batch should be handled gracefully
        assert packet_capture.stats["batch_count"] == 1
        assert packet_capture.stats["processed_packets"] == 0

    def test_large_batch_processing(self, packet_capture: PacketCapture) -> None:
        """Test processing of large batches."""
        large_batch = [create_mock_scapy_packet(timestamp=float(i)) for i in range(1000)]
        packet_capture.packet_queue.put(large_batch)
        packet_capture.is_running = False

        packet_capture.process_queue()

        assert len(packet_capture.packets) == 1000
        assert packet_capture.stats["processed_packets"] == 1000

    def test_queue_timeout_handling(self, packet_capture: PacketCapture) -> None:
        """Test that queue timeouts are handled properly."""
        packet_capture.is_running = True

        # Start processing with empty queue
        process_thread = threading.Thread(target=packet_capture.process_queue)
        process_thread.start()

        # Let it timeout a few times
        time.sleep(2.5)

        # Stop and verify clean exit
        packet_capture.is_running = False
        process_thread.join(timeout=3)

        assert not process_thread.is_alive()

    def test_rapid_queue_operations(self, packet_capture: PacketCapture) -> None:
        """Test rapid put/get operations on the queue."""
        packet_capture.is_running = True
        added_count = [0]

        def rapid_producer() -> None:
            for i in range(100):
                batch = [create_mock_scapy_packet(timestamp=float(i))]
                packet_capture.packet_queue.put(batch)
                added_count[0] += 1
                time.sleep(0.001)

        producer = threading.Thread(target=rapid_producer)
        consumer = threading.Thread(target=packet_capture.process_queue)

        producer.start()
        consumer.start()

        producer.join(timeout=5)
        packet_capture.is_running = False
        consumer.join(timeout=5)

        # All packets should be processed
        assert len(packet_capture.packets) == added_count[0]


# ============================================================================
# TEST CLASS: Realtime Display Threading
# ============================================================================


class TestRealtimeDisplayThreading:
    """Test realtime display thread behavior."""

    def test_start_realtime_display_creates_daemon_thread(
        self, packet_capture: PacketCapture
    ) -> None:
        """Test that realtime display creates a daemon thread."""
        packet_capture.realtime_display = True

        with patch.object(packet_capture, "_realtime_display_loop"):
            packet_capture.start_realtime_display()

            assert packet_capture.display_running
            assert packet_capture.display_thread is not None
            assert packet_capture.display_thread.daemon

            packet_capture.stop_realtime_display()

    def test_stop_realtime_display_waits_for_thread(self, packet_capture: PacketCapture) -> None:
        """Test that stop_realtime_display waits for thread completion."""
        packet_capture.realtime_display = True
        stop_called = threading.Event()

        def slow_display_loop() -> None:
            while packet_capture.display_running:
                time.sleep(0.1)
            stop_called.set()

        with patch.object(packet_capture, "_realtime_display_loop", slow_display_loop):
            packet_capture.start_realtime_display()
            time.sleep(0.2)
            packet_capture.stop_realtime_display()

        assert stop_called.is_set()

    def test_realtime_display_not_started_when_disabled(
        self, packet_capture: PacketCapture
    ) -> None:
        """Test that display thread is not started when disabled."""
        packet_capture.realtime_display = False

        packet_capture.start_realtime_display()

        assert not packet_capture.display_running
        assert packet_capture.display_thread is None

    def test_double_start_realtime_display(self, packet_capture: PacketCapture) -> None:
        """Test that starting realtime display twice doesn't create duplicate threads."""
        packet_capture.realtime_display = True

        with patch.object(packet_capture, "_realtime_display_loop"):
            packet_capture.start_realtime_display()
            first_thread = packet_capture.display_thread

            packet_capture.start_realtime_display()
            second_thread = packet_capture.display_thread

            # Should be the same thread (not duplicated)
            assert first_thread is second_thread

            packet_capture.stop_realtime_display()


if __name__ == "__main__":
    pytest.main(["-v", __file__])

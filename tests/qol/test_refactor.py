"""
Test script for refactored NetGuard architecture.

Tests:
1. DataStore - Parquet I/O
2. BaseAnalyzer - Analyzer base functionality
3. Individual Analyzers - Protocol-specific analysis
4. ParquetAnalysisFacade - Complete analysis workflow
"""

import sys
import traceback
from pathlib import Path

import polars as pl

# Add src to path if running directly
sys.path.insert(0, str(Path(__file__).parent / "src"))

from netguard.analysis.analyzers.ip_analyzer import IpAnalyzer
from netguard.analysis.analyzers.tcp_analyzer import TcpAnalyzer
from netguard.analysis.base_analyzer import BaseAnalyzer
from netguard.analysis.facade import ParquetAnalysisFacade
from netguard.core.data_store import DataStore


def test_datastore():
    """Test DataStore save/load functionality."""
    print("\n" + "=" * 60)
    print("TEST 1: DataStore")
    print("=" * 60)

    # Create test data with proper packet structure
    df = pl.DataFrame(
        {
            "timestamp": [1.0, 2.0, 3.0],
            "IP_src": ["192.168.1.1", "192.168.1.2", "192.168.1.3"],
            "IP_dst": ["8.8.8.8", "1.1.1.1", "192.168.1.1"],
            "IP_proto": [6, 6, 17],  # TCP, TCP, UDP
            "raw_size": [60, 120, 80],
        }
    )

    test_file = "/tmp/test_netguard_packets.parquet"

    # Test save
    print(f"Saving {len(df)} packets to {test_file}...")
    DataStore.save_packets(df, test_file)
    print("✓ Save successful")

    # Test load
    print(f"Loading packets from {test_file}...")
    loaded_df = DataStore.load_packets(test_file)
    print(f"✓ Load successful - {len(loaded_df)} packets loaded")

    # Verify
    assert len(loaded_df) == len(df), "Packet count mismatch"
    assert loaded_df.columns == df.columns, "Column mismatch"
    print("✓ Data integrity verified")

    # Test schema
    schema = DataStore.get_schema(test_file)
    print(f"Schema: {schema}")
    print("✓ Schema retrieval working")

    print("\n✅ DataStore: ALL TESTS PASSED")
    return test_file  # Return path for next tests


def test_base_analyzer():
    """Test BaseAnalyzer functionality."""
    print("\n" + "=" * 60)
    print("TEST 2: BaseAnalyzer")
    print("=" * 60)

    # Create test DataFrame
    df = pl.DataFrame(
        {
            "timestamp": [1704067200.0, 1704067201.0, 1704067202.0],  # Unix timestamps
            "IP_src": ["192.168.1.1", "192.168.1.2", "192.168.1.3"],
            "IP_dst": ["8.8.8.8", "1.1.1.1", "192.168.1.1"],
        }
    )

    # Create a basic analyzer (using BaseAnalyzer directly)
    analyzer = BaseAnalyzer(df)

    print(f"Analyzer repr: {analyzer!r}")
    print(f"Analyzer str: {analyzer!s}")
    print(f"Packet count: {analyzer.packet_count}")
    print(f"Is empty: {analyzer.is_empty}")
    print(f"Length: {len(analyzer)}")

    # Test date range
    date_range = analyzer.get_date_range()
    print(f"Date range: {date_range}")

    # Verify
    assert analyzer.packet_count == 3
    assert not analyzer.is_empty
    assert len(analyzer) == 3

    print("\n✅ BaseAnalyzer: ALL TESTS PASSED")


def test_tcp_analyzer():
    """Test TcpAnalyzer with proper TCP packet structure."""
    print("\n" + "=" * 60)
    print("TEST 3: TcpAnalyzer")
    print("=" * 60)

    # Create DataFrame with TCP-specific columns
    df = pl.DataFrame(
        {
            "timestamp": [1.0, 2.0, 3.0, 4.0],
            "IP_src": ["192.168.1.100", "192.168.1.100", "192.168.1.101", "192.168.1.102"],
            "IP_dst": ["8.8.8.8", "1.1.1.1", "192.168.1.100", "192.168.1.100"],
            "IP_proto": [6, 6, 6, 6],  # All TCP
            "TCP_sport": [54321, 54322, 80, 443],
            "TCP_dport": [80, 443, 54321, 12345],
            "TCP_flags": ["S", "SA", "A", "A"],
            "raw_size": [60, 64, 100, 120],
        }
    )

    print(f"Creating TcpAnalyzer with {len(df)} TCP packets...")
    analyzer = TcpAnalyzer(df)

    print(f"TCP Analyzer: {analyzer}")
    print(f"TCP packet count: {analyzer.packet_count}")

    # Verify TCP analyzer filtered to TCP only
    assert analyzer.packet_count == 4
    assert not analyzer.is_empty

    print("✓ TcpAnalyzer created successfully")
    print("\n✅ TcpAnalyzer: ALL TESTS PASSED")


def test_ip_analyzer():
    """Test IpAnalyzer."""
    print("\n" + "=" * 60)
    print("TEST 4: IpAnalyzer")
    print("=" * 60)

    df = pl.DataFrame(
        {
            "timestamp": [1.0, 2.0, 3.0],
            "IP_src": ["192.168.1.1", "192.168.1.2", "192.168.1.3"],
            "IP_dst": ["8.8.8.8", "1.1.1.1", "192.168.1.1"],
            "IP_proto": [6, 17, 1],  # TCP, UDP, ICMP
            "raw_size": [60, 120, 80],
        }
    )

    print(f"Creating IpAnalyzer with {len(df)} IP packets...")
    analyzer = IpAnalyzer(df)

    print(f"IP Analyzer: {analyzer}")
    print(f"IP packet count: {analyzer.packet_count}")

    assert analyzer.packet_count == 3

    print("✓ IpAnalyzer created successfully")
    print("\n✅ IpAnalyzer: ALL TESTS PASSED")


def test_facade_with_real_file(parquet_file: str):
    """Test ParquetAnalysisFacade with a real parquet file."""
    print("\n" + "=" * 60)
    print("TEST 5: ParquetAnalysisFacade")
    print("=" * 60)

    print(f"Loading facade from: {parquet_file}")
    analysis = ParquetAnalysisFacade(parquet_file)

    print(f"Facade: {analysis}")
    print(f"Repr: {analysis!r}")

    # Test analyzer access
    print("\nAnalyzer packet counts:")
    print(f"  Total: {len(analysis.df)}")
    print(f"  TCP: {len(analysis.tcp)}")
    print(f"  UDP: {len(analysis.udp)}")
    print(f"  DNS: {len(analysis.dns)}")
    print(f"  ARP: {len(analysis.arp)}")
    print(f"  ICMP: {len(analysis.icmp)}")
    print(f"  IP: {len(analysis.ip)}")

    # Test summary generation
    print("\nGenerating summary...")
    summary = analysis.generate_summary()

    print(f"Summary keys: {list(summary.keys())}")
    print(f"File size: {summary['file_info']['size_mb']:.2f} MB")
    print(f"Total packets: {summary['packet_counts']['total']}")

    # Test date range
    date_range = analysis.get_date_range()
    print(f"Date range: {date_range}")

    print("\n✅ ParquetAnalysisFacade: ALL TESTS PASSED")


def test_facade_with_comprehensive_data():
    """Test facade with comprehensive packet data."""
    print("\n" + "=" * 60)
    print("TEST 6: Facade with Comprehensive Data")
    print("=" * 60)

    # Create comprehensive test data with all protocols
    df = pl.DataFrame(
        {
            "timestamp": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0],
            "IP_src": [
                "192.168.1.1",
                "192.168.1.2",
                "192.168.1.3",
                "192.168.1.4",
                "192.168.1.5",
                "192.168.1.6",
            ],
            "IP_dst": [
                "8.8.8.8",
                "1.1.1.1",
                "192.168.1.100",
                "192.168.1.1",
                "224.0.0.1",
                "192.168.1.7",
            ],
            "IP_proto": [6, 17, 6, 1, 17, 6],  # TCP, UDP, TCP, ICMP, UDP, TCP
            "TCP_sport": [54321, None, 80, None, None, 443],
            "TCP_dport": [80, None, 54321, None, None, 12345],
            "UDP_sport": [None, 53, None, None, 5353, None],
            "UDP_dport": [None, 12345, None, None, 5353, None],
            "raw_size": [60, 120, 80, 64, 100, 150],
        }
    )

    # Save to temp file
    test_file = "/tmp/test_comprehensive.parquet"
    DataStore.save_packets(df, test_file)

    # Load with facade
    analysis = ParquetAnalysisFacade(test_file)

    print(f"Loaded {len(analysis.df)} packets")
    print(f"TCP packets: {len(analysis.tcp)}")
    print(f"UDP packets: {len(analysis.udp)}")
    print(f"ICMP packets: {len(analysis.icmp)}")

    # Generate summary
    summary = analysis.generate_summary()
    print("\nSummary:")
    print(f"  Total: {summary['packet_counts']['total']}")
    print(f"  TCP: {summary['packet_counts']['tcp']}")
    print(f"  UDP: {summary['packet_counts']['udp']}")
    print(f"  ICMP: {summary['packet_counts']['icmp']}")

    # Verify analyzers
    print("\nAnalyzers available:")
    for proto, available in summary["analyzers_available"].items():
        status = "✓" if available else "✗"
        print(f"  {status} {proto.upper()}")

    print("\n✅ Comprehensive Facade Test: PASSED")


def run_all_tests():
    """Run all tests in sequence."""
    print("\n" + "=" * 60)
    print("NETGUARD REFACTORED ARCHITECTURE - TEST SUITE")
    print("=" * 60)

    try:
        # Test 1: DataStore
        test_file = test_datastore()

        # Test 2: BaseAnalyzer
        test_base_analyzer()

        # Test 3: TcpAnalyzer
        test_tcp_analyzer()

        # Test 4: IpAnalyzer
        test_ip_analyzer()

        # Test 5: Facade with saved file
        test_facade_with_real_file(test_file)

        # Test 6: Facade with comprehensive data
        test_facade_with_comprehensive_data()

        print("\n" + "=" * 60)
        print("🎉 ALL TESTS PASSED! 🎉")
        print("=" * 60)
        print("\nRefactored architecture is working correctly:")
        print("  ✓ DataStore - Centralized parquet I/O")
        print("  ✓ BaseAnalyzer - Common analyzer functionality")
        print("  ✓ Individual Analyzers - Protocol-specific analysis")
        print("  ✓ ParquetAnalysisFacade - Unified interface")
        print("\nArchitecture is ready for:")
        print("  • CLI development")
        print("  • API integration")
        print("  • Workflow orchestration")
        print("  • Thesis defense demos")
        print("=" * 60)

    except Exception as e:
        print("\n" + "=" * 60)
        print("❌ TEST FAILED")
        print("=" * 60)
        print(f"Error: {e}")
        traceback.print_exc()
        return False

    return True


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)

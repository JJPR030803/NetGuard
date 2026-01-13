# test_datastore.py
import polars as pl

from netguard.core.data_store import DataStore


def test_datastore() -> None:
    # Create test data
    df = pl.DataFrame(
        {"timestamp": [1.0, 2.0, 3.0], "IP_src": ["192.168.1.1", "192.168.1.2", "192.168.1.3"]}
    )

    # Save
    DataStore.save_packets(df, "/tmp/test_packets.parquet")

    # Load
    loaded_df = DataStore.load_packets("/tmp/test_packets.parquet")

    assert len(loaded_df) == 3
    print("✓ DataStore working")


def test_base_analyzer() -> None:
    # test_base_analyzer.py
    import polars as pl

    from netguard.analysis.analyzers.tcp_analyzer import TcpAnalyzer

    df = pl.DataFrame(
        {
            "timestamp": [1.0, 2.0],
            "TCP_sport": [80, 443],
            "TCP_dport": [12345, 54321],
            "IP_proto": ["IPV4"],
        }
    )

    analyzer = TcpAnalyzer(df)
    print(f"Analyzer: {analyzer}")
    print(f"Packet count: {analyzer.packet_count}")
    print(f"Is empty: {analyzer.is_empty}")
    print("✓ BaseAnalyzer working")


if __name__ == "__main__":
    test_base_analyzer()

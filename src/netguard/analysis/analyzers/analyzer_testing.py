import polars as pl
from tcp_analyzer import TcpAnalyzer
from tcp_config import ScanProfile, get_scan_config

if __name__ == "__main__":
    PATH = "/mnt/shared/tesis/netguard/src/netguard/data/packet_capture.parquet"
    config = get_scan_config(ScanProfile.STEALTH)
    df = pl.read_parquet(PATH)
    an = TcpAnalyzer(df)
    an.detect_port_scanning(config=config)

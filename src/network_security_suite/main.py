from sniffer.parquet_processing import ParquetProcessing
from sniffer.sniffer_config import SnifferConfig
from sniffer.packet_capture import PacketCapture
from src.network_security_suite.sniffer.interfaces import Interface

if __name__ == "__main__":
   interface = Interface().get_active_interfaces()
   print(interface)
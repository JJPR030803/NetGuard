from netguard.capture.packet_capture import PacketCapture
from netguard.capture.parquet_processing import ParquetProcessing
from netguard.core.config import SnifferConfig
from netguard.core.interfaces import Interface

if __name__ == "__main__":
    interface = Interface().get_active_interfaces()
    print(interface)

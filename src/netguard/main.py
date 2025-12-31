from netguard.capture.packet_capture import PacketCapture
from netguard.core.config import SnifferConfig
from netguard.core.interfaces import Interface
from netguard.core.paths import NetGuardPaths

if __name__ == "__main__":
    config = SnifferConfig(
        interface="wlo1",
        export_filename="probando1.parquet",
        export_format="parquet",
        packet_count=1000,
        enable_realtime_display=True,
    )
    interface = Interface()
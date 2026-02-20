import time

from netguard.capture.packet_capture import PacketCapture, SnifferConfig
from netguard.core.interfaces import Interface
from netguard.analysis.base_analyzer import BaseAnalyzer

CFG_PATH: str = "/mnt/shared/tesis/netguard/src/netguard/sniffer_config.yaml"

if __name__ == "__main__":
    cfg = SnifferConfig.from_yaml(CFG_PATH)
    pc = PacketCapture(config=cfg)
    pc.capture()
    
    print("Packet Captured Successfully")
    time.sleep(10)
    print("Testing other")
    df = pc.to_polars_df()
    print(df)
    
    

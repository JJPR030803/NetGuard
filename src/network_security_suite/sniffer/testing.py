from src.network_security_suite.sniffer.interfaces import Interface
from src.network_security_suite.sniffer.packet_capture import PacketCapture
from src.network_security_suite.models.data_structures import POLARS_AVAILABLE
import polars as pl

if __name__ == "__main__":
    try:
        # Initialize interface and capture packets
        interface_manager = Interface()
        wireless_interfaces = interface_manager.get_interface_by_type("wireless")
        capture = PacketCapture(interface=wireless_interfaces[0])
        capture.capture(max_packets=10, verbose=True)



        print("\n=== Testing Polars conversion ===")
        pl.Config.set_tbl_cols(-1)
        pl.Config.set_tbl_width_chars(None)
        df = capture.to_polars_df()
        print(df["raw_size"])



    except Exception as e:
        print(f"Error during testing: {e}")

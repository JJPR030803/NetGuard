from src.network_security_suite.sniffer.interfaces import Interface
from src.network_security_suite.sniffer.packet_capture import PacketCapture

if __name__ == "__main__":
    interface = Interface()
    wireless_interface = interface.get_interface_by_type("wireless")
    capture = PacketCapture(interface=wireless_interface[0])
    capture.capture(max_packets=100)
    capture.show_stats()

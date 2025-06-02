from src.network_security_suite.sniffer.packet_capture import PacketCapture

if __name__ == "__main__":
    try:
        capture = PacketCapture(interface="eth0")
        capture.capture(max_packets=1000)
        capture.show_packets()
    except Exception as e:
        print(e)

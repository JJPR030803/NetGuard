from scapy.all import *
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, STP, Ether

from src.network_security_suite.models.data_structures import (
    ARPPacketModel,
    EthernetPacketModel,
    ICMPPacketModel,
    IPPacketModel,
    Packet,
    STPPacketModel,
    TCPPacketModel,
    UDPPacketModel,
)
from src.network_security_suite.sniffer.packet import ARPPacket, NetworkPacket

# TODO crear clases para capturar paquetes


class PacketCapture:
    def __init__(self, interface: str):
        self.interface = interface
        self.packets: list[NetworkPacket] = []

    def capture(self, max_packets: int = 10000):
        packets = sniff(iface=self.interface, count=max_packets)
        for packet in packets:
            if packet.haslayer(IP):
                # Check for specific IP-based protocols first
                if packet.haslayer(ICMP):
                    packet_model = ICMPPacketModel.new(
                        type=packet[ICMP].type,
                        code=packet[ICMP].code,
                        chksum=packet[ICMP].chksum,
                        id=packet[ICMP].id if hasattr(packet[ICMP], "id") else None,
                        seq=packet[ICMP].seq if hasattr(packet[ICMP], "seq") else None,
                        data=bytes(packet[ICMP].payload)
                        if packet[ICMP].payload
                        else None,
                        src_ip=packet[IP].src,
                        dst_ip=packet[IP].dst,
                    )
                    self.packets.append(packet_model)
                elif packet.haslayer(TCP):
                    packet_model = TCPPacketModel.new(
                        sport=packet[TCP].sport,
                        dport=packet[TCP].dport,
                        seq=packet[TCP].seq,
                        ack=packet[TCP].ack,
                        dataofs=packet[TCP].dataofs,
                        reserved=packet[TCP].reserved,
                        flags=str(packet[TCP].flags),
                        window=packet[TCP].window,
                        chksum=packet[TCP].chksum,
                        urgptr=packet[TCP].urgptr,
                        options=[(opt[0], opt[1]) for opt in packet[TCP].options]
                        if packet[TCP].options
                        else None,
                        src_ip=packet[IP].src,
                        dst_ip=packet[IP].dst,
                    )
                    self.packets.append(packet_model)
                elif packet.haslayer(UDP):
                    packet_model = UDPPacketModel.new(
                        sport=packet[UDP].sport,
                        dport=packet[UDP].dport,
                        len=packet[UDP].len,
                        chksum=packet[UDP].chksum,
                        src_ip=packet[IP].src,
                        dst_ip=packet[IP].dst,
                    )
                    self.packets.append(packet_model)
                else:
                    # Generic IP packet
                    packet_model = IPPacketModel.new(
                        version=packet[IP].version,
                        ihl=packet[IP].ihl,
                        tos=packet[IP].tos,
                        len=packet[IP].len,
                        id=packet[IP].id,
                        flags=packet[IP].flags,
                        frag=packet[IP].frag,
                        ttl=packet[IP].ttl,
                        proto=packet[IP].proto,
                        chksum=packet[IP].chksum,
                        src=packet[IP].src,
                        dst=packet[IP].dst,
                        options=packet[IP].options
                        if hasattr(packet[IP], "options")
                        else None,
                        src_ip=packet[IP].src,
                        dst_ip=packet[IP].dst,
                    )
                    self.packets.append(packet_model)
            elif packet.haslayer(ARP):
                packet_model = ARPPacketModel.new(
                    hw_type=packet.hwtype,
                    proto_type=packet.ptype,
                    hw_len=packet.hwlen,
                    proto_len=packet.plen,
                    opcode=packet.op,
                    sender_mac=packet.hwsrc,
                    sender_ip=packet.psrc,
                    target_mac=packet.hwdst,
                    target_ip=packet.pdst,
                )
                self.packets.append(packet_model)
            elif packet.haslayer(Ether):
                packet_model = EthernetPacketModel.new(
                    dst_mac=packet.dst,
                    src_mac=packet.src,
                    type=packet.type,
                    # Note: preamble and sfd are not directly accessible in scapy
                    # They are typically handled at the hardware level
                    # CRC is calculated automatically by scapy
                )
                self.packets.append(packet_model)
            elif packet.haslayer(STP):
                packet_model = STPPacketModel.new(
                    protocol_id=packet.protoid,
                    version=packet.version,
                    bpdutype=packet.bpdutype,
                    flags=packet.flags,
                    root_bridge_id=f"{packet.rootid:016x}",
                    sender_bridge_id=f"{packet.bridgeid:016x}",
                    root_path_cost=packet.pathcost,
                    port_id=packet.portid,
                    message_age=packet.age,
                    max_age=packet.maxage,
                    hello_time=packet.hellotime,
                    forward_delay=packet.fwddelay,
                )
                self.packets.append(packet_model)

    def show_packets(self):
        for packet in self.packets:
            packet.show()

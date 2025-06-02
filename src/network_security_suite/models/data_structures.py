from typing import List, Optional

import pydantic as pyd
from pydantic import IPvAnyAddress
from pydantic_extra_types.mac_address import MacAddress


# Modelos solo para procesamiento de datos
# O conversion a otros tipos de datos (Json,pandas,etc)
class Packet(pyd.BaseModel):
    src_ip: IPvAnyAddress | None
    dst_ip: IPvAnyAddress | None
    src_port: int | None
    dst_port: int | None
    protocol: str
    payload: bytes


class NetworkPacketModel(pyd.BaseModel):
    payload: Optional[str] = None
    layers: List[str] = []
    timestamp: Optional[str] = None
    dst_ip: Optional[IPvAnyAddress] = None
    src_ip: Optional[IPvAnyAddress] = None


class ARPPacketModel(NetworkPacketModel):
    hw_type: Optional[int] = None  # 1 para ethernet
    proto_type: Optional[int] = None  # 0x0800 para IPv4
    hw_len: Optional[int] = None  # Tamaño de direccion MAC(6)
    proto_len: Optional[int] = None  # Tamaño de direccion IP(4)
    opcode: Optional[int] = None  # 1 para request 2 para reply
    sender_mac: Optional[MacAddress] = None
    sender_ip: Optional[IPvAnyAddress] = None
    target_mac: Optional[MacAddress] = None
    target_ip: Optional[IPvAnyAddress] = None

    @classmethod
    def new(cls, **data):
        return cls(**data)


class STPPacketModel(NetworkPacketModel):
    protocol_id: Optional[int] = None
    version: Optional[int] = None
    bpdutype: Optional[int] = None  # 0x00(Configuracion) 0x80(TCN)
    flags: Optional[bytes] = None  # Bit topology channel 0x01(TCN)
    root_bridge_id: Optional[str] = None
    sender_bridge_id: Optional[str] = None
    root_path_cost: Optional[int] = None
    port_id: Optional[int] = None  # ID del puerto emisor
    message_age: Optional[
        int
    ] = None  # Tiempo de vida del mensaje desde que fue generado
    max_age: Optional[int] = None  # Tiempo de vida maximo del mensaje
    hello_time: Optional[int] = None  # Intervalo entre BPDUs
    forward_delay: Optional[int] = None #Tiempo de espera antes del forwarding

    @classmethod
    def new(cls, **data):
        return cls(**data)


class EthernetPacketModel(NetworkPacketModel):
    preamble: Optional[int] = None  # Patron de sincronizacion (0xAA)
    sfd: Optional[int] = None  # Marca de inicio de la trama
    dst_mac: Optional[MacAddress] = None
    src_mac: Optional[MacAddress] = None
    type: Optional[int] = None  # Ej: 0x0800 IPv4
    crc: Optional[str] = None  # checksum de la trama

    @classmethod
    def new(cls, **data):
        return cls(**data)


class IPPacketModel(NetworkPacketModel):
    version: Optional[int] = None  # 4 para IPv4, 6 para IPv6
    ihl: Optional[int] = None  # Internet Header Length
    tos: Optional[int] = None  # Type of Service
    len: Optional[int] = None  # Total Length
    id: Optional[int] = None  # Identification
    flags: Optional[int] = None  # Flags
    frag: Optional[int] = None  # Fragment Offset
    ttl: Optional[int] = None  # Time to Live
    proto: Optional[int] = None  # Protocol
    chksum: Optional[int] = None  # Header Checksum
    src: Optional[IPvAnyAddress] = None  # Source Address
    dst: Optional[IPvAnyAddress] = None  # Destination Address
    options: Optional[List[dict]] = None  # Options

    @classmethod
    def new(cls, **data):
        return cls(**data)


class ICMPPacketModel(NetworkPacketModel):
    type: Optional[int] = None  # Type of message
    code: Optional[int] = None  # Code
    chksum: Optional[int] = None  # Checksum
    id: Optional[int] = None  # Identifier
    seq: Optional[int] = None  # Sequence Number
    data: Optional[bytes] = None  # Data

    @classmethod
    def new(cls, **data):
        return cls(**data)


class TCPPacketModel(NetworkPacketModel):
    sport: Optional[int] = None  # Source Port
    dport: Optional[int] = None  # Destination Port
    seq: Optional[int] = None  # Sequence Number
    ack: Optional[int] = None  # Acknowledgment Number
    dataofs: Optional[int] = None  # Data Offset
    reserved: Optional[int] = None  # Reserved
    flags: Optional[str] = None  # Flags
    window: Optional[int] = None  # Window Size
    chksum: Optional[int] = None  # Checksum
    urgptr: Optional[int] = None  # Urgent Pointer
    options: Optional[List[tuple]] = None  # Options

    @classmethod
    def new(cls, **data):
        return cls(**data)


class UDPPacketModel(NetworkPacketModel):
    sport: Optional[int] = None  # Source Port
    dport: Optional[int] = None  # Destination Port
    len: Optional[int] = None  # Length
    chksum: Optional[int] = None  # Checksum

    @classmethod
    def new(cls, **data):
        return cls(**data)

from abc import ABC, abstractmethod


# TODO crear packet class para manejar los paquetes
# TODO pensar en estructura de datos


class NetworkPacket(ABC):
    def __init__(self):
        self.payload: str | None = None
        self.layers: list = []
        self.timestamp: str | None = None
        self.dst_ip: str | None = None
        self.src_ip: str | None = None

    @abstractmethod
    def get_payload(self):
        pass

    @abstractmethod
    def get_layers(self):
        pass

    @abstractmethod
    def get_timestamp(self):
        pass

    @abstractmethod
    def get_dst_ip(self):
        pass

    @abstractmethod
    def get_src_ip(self):
        pass

    @abstractmethod
    def show(self):
        pass


# Capa 2  del modelo OSI


class ARPPacket(NetworkPacket):
    def __init__(self):
        super().__init__()
        self.hw_type: int | None = None  # 1 para ethernet
        self.proto_type: int | None = None  # 0x0800 para IPv4
        self.hw_len: int | None = None  # Tamaño de direccion MAC(6)
        self.proto_len: int | None = None  # Tamaño de direccion IP(4)
        self.opcode: int | None = None  # 1 para request 2 para reply
        self.sender_mac: str | None = None
        self.sender_ip: str | None = None
        self.target_mac: str | None = None
        self.target_ip: str | None = None

    # TODO implementar metodos importantes para ARP


class STPPacket(NetworkPacket):
    def __init__(self):
        super().__init__()
        self.protocol_id: int | None = None
        self.version: int | None = None
        self.bpdutype: int | None = None  # 0x00(Configuracion) 0x80(TCN)
        self.flags: bytes | None = None  # Bit topology channel 0x01(TCN)
        self.root_bridge_id: str | None = None
        self.sender_bridge_id: str | None = None
        self.root_path_cost: int | None = None
        self.port_id: int | None = None  # ID del puerto emisor
        self.message_age: int | None = (
            None  # Tiempo de vida del mensaje desde que fue generado
        )
        self.max_age: int | None = None  # Tiempo de vida maximo del mensaje
        self.hello_time: int | None = None  # Intervalo entre BPDUs
        self.forward_delay: int | None = None #Tiempo espera antes de forwarding

    # TODO implementar metodos importantes para STP


class EthernetPacket(NetworkPacket):
    def __init__(self):
        super().__init__()
        self.preamble: int | None = None  # Patron de sincronizacion (0xAA)
        self.sfd: int | None = None  # Marca de inicio de la trama
        self.dst_mac: str | None = None
        self.src_mac: str | None = None
        self.type: int | None = None  # Ej: 0x0800 IPv4
        self.payload: str | None = None
        self.crc: str | None = None  # checksum de la trama


# TODO implementar metodos importantes para Ethernet


# ##################TODO implementar siguientes capas ######################

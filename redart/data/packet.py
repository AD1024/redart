import hashlib
from decimal import Decimal
from enum import IntEnum, auto
from functools import lru_cache


class PacketType(IntEnum):
    ACK = auto()
    SYN = auto()
    SEQ = auto()

    def is_ack(self):
        return self == PacketType.ACK

    def is_seq(self):
        return self == PacketType.SEQ

    def is_syn(self):
        return self == PacketType.SYN


class Packet:
    """A class that represents a packet.

    Attributes (note: all these should be read-only):
        src (str): The source IP address.
        srcport (int): The source port.
        dst (str): The destination IP address.
        dstport (int): The destination port.
        ack (int): The ACK number.
        seq (int): The SEQ number.
        payload (str): The payload of the packet.
    """

    def __init__(self, src: str, srcport: int, dst: str, dstport: int, ack: int, seq: int, timestamp: Decimal, packet_size: int, packet_type: PacketType, *, payload=None):
        self.src = src
        self.srcport = srcport
        self.dst = dst
        self.dstport = dstport
        self.ack = ack
        self.seq = seq
        self.payload = payload
        self.timestamp = timestamp
        self.packet_size = packet_size
        self.packet_type = packet_type

    def __str__(self):
        return f"Packet(src={self.src}, srcport={self.srcport}, dst={self.dst}, dstport={self.dstport}, ack={self.ack}, seq={self.seq}, payload={self.payload}, ts={self.timestamp})"

    def __repr__(self):
        return self.__str__()

    def is_ack(self):
        return self.packet_type.is_ack()

    def is_seq(self):
        return self.packet_type.is_seq()

    @lru_cache
    def to_src_dst_key(self):
        """
        Hash src and dst to a key
        """
        src_hash = int(hashlib.sha256(self.src.encode()).hexdigest(), 16)
        dst_hash = int(hashlib.sha256(self.dst.encode()).hexdigest(), 16)
        return src_hash ^ dst_hash ^ self.srcport ^ self.dstport

    @lru_cache
    def to_dict(self):
        return {
            "src": self.src,
            "srcport": self.srcport,
            "dst": self.dst,
            "dstport": self.dstport,
            "ack": self.ack,
            "seq": self.seq,
            "payload": self.payload,
            "timestamp": self.timestamp
        }

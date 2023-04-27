import datetime
import hashlib
from enum import IntEnum
from functools import lru_cache

from redart.config import TimestampScale, get_config


class PacketType(IntEnum):
    ACK = 1
    SEQ = 1 << 2
    SYN = 1 << 3
    FIN = 1 << 4


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

    def __init__(self, src: str, srcport: int, dst: str, dstport: int, ack: int, seq: int, timestamp: datetime.datetime, packet_size: int, packet_type: PacketType, *, payload=None, index=None):
        self.src = src
        self.srcport = srcport
        self.dst = dst
        self.dstport = dstport
        self.ack = ack
        self.seq = seq
        self.payload = payload
        self._timestamp = timestamp
        self.packet_size = packet_size
        self.packet_type = packet_type
        self.index = index

    def __str__(self):
        return f"Packet(src={self.src}, srcport={self.srcport}, dst={self.dst}, dstport={self.dstport}, ack={self.ack}, seq={self.seq}, size={self.size}, ts={self.timestamp})"

    def __repr__(self):
        return self.__str__()

    def is_ack(self):
        return (self.packet_type & PacketType.ACK) != 0

    def is_seq(self):
        return (self.packet_type & PacketType.SEQ) != 0

    def is_fin(self):
        return (self.packet_type & PacketType.FIN) != 0

    def is_syn(self):
        return (self.packet_type & PacketType.SYN) != 0

    @property
    def size(self):
        return self.packet_size

    @property
    def type(self):
        return self.packet_type

    @property
    def timestamp(self) -> datetime.datetime:
        return self._timestamp

    @lru_cache
    def _current_time_scale(self):
        return get_config().timescale

    def time_since(self, other) -> float:
        assert isinstance(other, Packet)
        diff = self.timestamp - other.timestamp
        time_scale = self._current_time_scale()
        if time_scale == TimestampScale.SECOND:
            return diff.total_seconds()
        if time_scale == TimestampScale.MILLISECOND:
            return diff / datetime.timedelta(milliseconds=1)
        if time_scale == TimestampScale.MICROSECOND:
            return diff / datetime.timedelta(microseconds=1)
        raise ValueError(f"Unknown timescale {time_scale}")

    @lru_cache
    def to_src_dst_key(self):
        """
        Hash src and dst to a key
        """
        src_hash = int(hashlib.sha256(self.src.encode()).hexdigest(), 16)
        dst_hash = int(hashlib.sha256(self.dst.encode()).hexdigest(), 16)
        return (src_hash ^ dst_hash ^ self.srcport ^ self.dstport) % 556580197052749600253904711163

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

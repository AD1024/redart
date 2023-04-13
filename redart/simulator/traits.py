from typing import TypeVar

from redart.data import Packet
from redart.logger import get_logger

K = TypeVar('K')
V = TypeVar('V')


class TrackerTrait(dict[K, V]):
    """
    A dict-like tracker trait.
    It is supposed to be used as a base class for RangeTracker and PacketTracker.
    """

    def __init__(self, *, name=None):
        self.logger = get_logger(name or self.__class__.__name__)
        super().__init__()

    def update(self, packet: K, packet_value: V):
        super().update({packet: packet_value})

    def get(self, packet: K):
        super().get(packet)

    def evict(self, packet: K):
        """
        Evict a record given a new `packet` to be stored
        """
        raise NotImplementedError

    def __contains__(self, __key: object) -> bool:
        super().__contains__(__key)


class SimulatorTrait:
    """
    Simulator base class.
    """

    def __init__(self, range_tracker: TrackerTrait,
                 packet_tracker: TrackerTrait, *, name=None):
        self.range_tracker = range_tracker
        self.packet_tracker = packet_tracker
        self.logger = get_logger(name or self.__class__.__name__)

    def run_trace(self, trace: list[Packet]):
        for packet in trace:
            self.process_packet(packet)

    def run_trace_file(self, trace_file: str):
        import pickle
        with open(trace_file, 'rb') as f:
            trace = pickle.load(f)
        self.run_trace(trace)

    def process_packet(self, packet: Packet):
        raise NotImplementedError

    def evict(self, new_packet: Packet):
        raise NotImplementedError

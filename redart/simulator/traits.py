from typing import Callable, Generic, NewType, TypeVar, Union

from redart.data import Packet
from redart.logger import get_logger

K = TypeVar('K')
V = TypeVar('V')


class EvictionTraitDecl(Generic[V]):
    def evict(self, value: V, *args):
        raise NotImplementedError


class TrackerTrait(dict[K, V]):
    """
    A dict-like tracker trait.
    It is supposed to be used as a base class for RangeTracker and PacketTracker.
    """

    def __init__(self, eviction_policy: Union[Callable[[object], None], EvictionTraitDecl], *, name=None):
        self.logger = get_logger(name or self.__class__.__name__)
        if eviction_policy is not None:
            self.eviction_policy = eviction_policy(self)
        super().__init__()

    def update(self, packet: K, packet_value: V):
        super().update({packet: packet_value})

    def get(self, packet: K) -> V:
        return super().get(packet)

    def evict(self, packet: K):
        """
        Evict a record given a new `packet` to be stored
        """
        raise NotImplementedError

    def __setitem__(self, __key: K, __value: V) -> None:
        super().__setitem__(__key, __value)

    def __contains__(self, __key: object) -> bool:
        return super().__contains__(__key)


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


class EvictionTrait(EvictionTraitDecl[V]):
    """
    Eviction base class.
    """

    def __init__(self, tracker: TrackerTrait, *, name=None):
        self.logger = get_logger(name or self.__class__.__name__)
        self.tracker = tracker

    def evict(self, value: V, *args):
        raise NotImplementedError

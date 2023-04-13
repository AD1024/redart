from redart.simulator import TrackerTrait
from redart.logger import get_logger
from redart.data import Packet
from typing import TypeVar, Generic

V = TypeVar('V')

class EvictionTrait(Generic[V]):
    """
    Eviction base class.
    """

    def __init__(self, tracker: TrackerTrait, *, name=None):
        self.logger = get_logger(name or self.__class__.__name__)
        self.tracker = tracker

    def evict(self, new_packet: V, *args):
        raise NotImplementedError
from redart.data import Packet
from redart.logger import get_logger


class TrackerTrait(dict):
    def __init__(self, *, name=None):
        self.logger = get_logger(name or self.__class__.__name__)

    def update(self, packet: Packet):
        raise NotImplementedError

    def get(self, packet: Packet):
        raise NotImplementedError

    def evict(self, packet: Packet):
        raise NotImplementedError

    def __contains__(self, __key: object) -> bool:
        raise NotImplementedError


class SimulatorTrait:
    def __init__(self, range_tracker: TrackerTrait,
                 packet_tracker: TrackerTrait, *, name=None):
        self.range_tracker = range_tracker
        self.packet_tracker = packet_tracker
        self.logger = get_logger(name or self.__class__.__name__)

    def run_trace(self, trace: list[Packet]):
        raise NotImplementedError

    def run_trace_file(self, trace_file: str):
        import pickle
        with open(trace_file, 'rb') as f:
            trace = pickle.load(f)
        self.run_trace(trace)

    def process_packet(self, packet: Packet):
        raise NotImplementedError

    def evict(self, new_packet: Packet):
        raise NotImplementedError

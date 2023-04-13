from redart.simulator import SimulatorTrait, TrackerTrait
from redart.data import Packet, PacketType
import typing
from typing import Tuple
from decimal import Decimal

# Value of range tracker:
# (flow_key, (Seq, Expected Ack), timestamp)
RangeValue = Tuple[int, Tuple[int, int], Decimal]
RangeKey = int

PacketValue = RangeValue
PacketKey = int

PacketTrackerT = typing.NewType("PacketTracker", TrackerTrait[PacketKey, PacketValue])


class RangeTracker(TrackerTrait[RangeKey, RangeValue]):
    def __init__(self, packet_tracker: PacketTrackerT, capacity: int, *, name="DartRangeTracker"):
        self.capacity = capacity
        self.packet_tracker_ref = packet_tracker
        super().__init__(name=name)

    def update(self, packet: PacketKey, packet_value: PacketValue):
        if packet in self:
            super().update(packet, packet_value)
        else:
            assert len(self) <= self.capacity, "Range tracker is full"
            super().update(packet, packet_value)

    def get(self, packet: PacketKey) -> RangeValue:
        return super().get(packet)
    
    def __contains__(self, packet: Packet) -> bool:
        key = packet.to_src_dst_key()
        return super().__contains__(key)

class PacketTracker(TrackerTrait[PacketKey, PacketValue]):
    def __init__(self, capacity: int, *, name="DartPacketTracker"):
        self.capacity = capacity
        self.range_tracker_ref = RangeTracker(self, capacity)
        super().__init__(name=name)

class DartSimulator(SimulatorTrait):
    def __init__(self, packet_tracker: PacketTracker, *, name="DartSim"):
        super().__init__(packet_tracker.range_tracker_ref, packet_tracker, name=name)

    def _process_seq_packet(self, packet: Packet):
        pass

    def _process_ack_packet(self, packet: Packet):
        pass

    def process_packet(self, packet: Packet):
        if packet.packet_type == PacketType.SEQ:
            self._process_seq_packet(packet)
        elif packet.packet_type == PacketType.ACK:
            self._process_ack_packet(packet)
        else:
            self.logger.warning("SYN packets are not supported for now")
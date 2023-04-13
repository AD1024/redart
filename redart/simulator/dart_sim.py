"""DART simulator re-implementation with better interfaces"""
import enum
import typing
from dataclasses import dataclass
from decimal import Decimal
from typing import Tuple, Union

from redart.data import Packet, PacketType
from redart.simulator import EvictionTrait, SimulatorTrait, TrackerTrait
from redart.simulator.exceptions import EntryNotFountException

# Value of range tracker:
# (flow_key, (Seq, Expected Ack), timestamp)
PacketKeyT = Tuple[int, int]
SeqT = int
AckT = int
TimestampT = Decimal
# number of recirculation loops allowed
# if set to 0, it corresponds to directly
# evicting the old entry with out any recirculation
RecircQuotaT = int


@dataclass
class PacketInfo:
    src: str
    dst: str
    sport: int
    dport: int
    packet_type: PacketType


@dataclass
class MeasureRange:
    left: int
    right: int


@dataclass
class RangeValueT:
    flow_key: PacketKeyT
    flow_info: PacketInfo
    tracking_range: MeasureRange
    seq: SeqT
    ack: AckT
    timestamp: TimestampT
    rtt: Union[TimestampT, None]
    recirc_quota: RecircQuotaT
    packet_ref: Packet


RangeKeyT = int

PacketValueT = RangeValueT

PacketTrackerT = typing.NewType(
    "PacketTracker", TrackerTrait[PacketKeyT, PacketValueT])


def hash_packet_key(packet_key: PacketKeyT) -> int:
    a, b = packet_key
    return a * a + a + b if a >= b else a + b * b


class RangeTrackerValidateAction(enum.IntEnum):
    VALID = enum.auto()
    IGNORE = enum.auto()
    RESET = enum.auto()


class PacketTrackerEviction(EvictionTrait[Tuple[Packet, PacketValueT]]):
    def evict(self, values: Tuple[Packet, PacketValueT], *args):
        (old_packet, new_value) = values
        assert old_packet in self.tracker
        self.tracker[old_packet] = new_value


class RangeTracker(TrackerTrait[RangeKeyT, RangeValueT]):
    def __init__(self, packet_tracker_capacity: int, packet_tracker_eviction: object, capacity: int, eviction_policy: object, *, name="DartRangeTracker", recirc=3):
        self.capacity = capacity
        self.packet_tracker_ref = PacketTracker(
            self, packet_tracker_capacity, packet_tracker_eviction, name="DartPacketTracker")
        self.recirc = recirc
        super().__init__(eviction_policy, name=name)

    def validate(self, packet_key: RangeKeyT, packet: Packet) -> RangeTrackerValidateAction:
        if packet_key in self:
            entry = self[packet_key]
            if packet.is_ack():
                if entry.ack < packet.ack <= entry.seq:
                    return RangeTrackerValidateAction.VALID
                if entry.ack == packet.ack:
                    # Reset Case: ACK coming for the left edge
                    return RangeTrackerValidateAction.RESET
                if packet.ack <= entry.ack or packet.ack > entry.seq:
                    return RangeTrackerValidateAction.IGNORE
            if packet.is_seq():
                if entry.seq < packet.seq + packet.packet_size:
                    return RangeTrackerValidateAction.VALID
                if entry.seq > packet.seq + packet.packet_size:
                    # Reset Case: SEQ less than right edge, signifying a retransmission
                    return RangeTrackerValidateAction.RESET
                return RangeTrackerValidateAction.IGNORE
            self.logger.warning("SYN not supported for now")
            return RangeTrackerValidateAction.IGNORE
        if packet.is_seq():
            return RangeTrackerValidateAction.VALID
        self.logger.warning("Seeing an ACK before SEQ: %s -> %s @ %s",
                            packet.src, packet.dst, packet.timestamp)
        return RangeTrackerValidateAction.IGNORE

    def update(self, packet: Packet, recirc=None):
        """
        Upon reciving a new flow:
            1. Validate the flow by checking ACK | SEQ with (left, right) range
               This will automatically shift the range towards the highest-byte SEQ
            2. If valid
                for SEQ packets, update right edge
                for ACK packets, update left edge
               If reset cases are met, reset (left, right) to (right, right)
        """
        packet_key = packet.to_src_dst_key() % self.capacity
        action = self.validate(packet_key, packet)
        if action == RangeTrackerValidateAction.IGNORE:
            self.logger.warning("Ignoring packet: %s -> %s @ %s",
                                packet.src, packet.dst, packet.timestamp)
            return
        if action == RangeTrackerValidateAction.RESET:
            if packet not in self:
                raise EntryNotFountException("Entry not found")
            range_item = self.get(packet_key)
            range_item.tracking_range = MeasureRange(
                range_item.tracking_range.right, range_item.tracking_range.right)
            self[packet_key] = range_item

        if action == RangeTrackerValidateAction.VALID:
            if packet in self:
                # if the flow has been recorded before,
                # update the range
                range_item = self.get(packet_key)
                if packet.is_seq():
                    eack = packet.seq + packet.packet_size
                    if packet.seq >= range_item.tracking_range.right:
                        if eack == range_item.tracking_range.right:
                            range_item.tracking_range = MeasureRange(
                                range_item.tracking_range.left, eack)
                        else:
                            # exceeding current measurement range
                            range_item.tracking_range = MeasureRange(
                                packet.seq, eack
                            )
                    else:
                        self.pop(packet_key)
                        self.packet_tracker_ref.pop(packet_key)
                if packet.is_ack():
                    # TODO: handle ACK packets
                    range_item.rtt = packet.timestamp - range_item.timestamp
                self[packet_key] = range_item
                self.packet_tracker_ref.update(packet_key, range_item)
            else:
                assert len(self) <= self.capacity, "Range tracker is full"
                # flow not in range tracker, check packet tracker
                # if exists, then this is a retransmission and we can drop
                # the entry in the packet tracker
                eack = packet.seq + packet.packet_size
                if (packet_key, eack) in self.packet_tracker_ref:
                    self.packet_tracker_ref.pop((packet_key, eack))
                    return
                # if not, then this is a new flow, we insert in the packet tracker
                packet_value = RangeValueT(
                    packet_key,
                    PacketInfo(
                        packet.src, packet.dst, packet.srcport, packet.dstport, packet.packet_type,
                    ),
                    MeasureRange(0, packet.seq + packet.packet_size),
                    packet.seq, packet.ack, packet.timestamp, None, self.recirc,
                    packet,
                )
                self[packet_key] = packet_value
                self.packet_tracker_ref.update(
                    (packet_key, eack), packet_value)

    def get(self, packet: Union[PacketKeyT, Packet]) -> RangeValueT:
        if isinstance(packet, Packet):
            packet = packet.to_src_dst_key()
        return super().get(packet % self.capacity)

    def __setitem__(self, __key: RangeKeyT, __value: RangeValueT):
        super().__setitem__(__key % self.capacity, __value)

    def __contains__(self, packet: Union[RangeKeyT, Packet]) -> bool:
        if isinstance(packet, Packet):
            packet = packet.to_src_dst_key()
        return super().__contains__(packet % self.capacity)


class PacketTracker(TrackerTrait[PacketKeyT, PacketValueT]):
    def __init__(self, range_tracker: RangeTracker, capacity: int, eviction_policy: object, *, name="DartPacketTracker"):
        self.capacity = capacity
        self.range_tracker_ref = range_tracker
        super().__init__(eviction_policy, name=name)

    def update(self, packet: PacketKeyT, packet_value: PacketValueT):
        packet, eack = packet
        packet = packet % self.capacity
        if packet in self:
            self.evict(packet_value.packet_ref, packet_value)
        else:
            if len(self) < self.capacity:
                super().__setitem__(packet, packet_value)
            else:
                pass

    def evict(self, packet: Packet, insert: PacketValueT):
        assert packet in self
        self.eviction_policy.evict(packet, insert)

    def pop(self, packet: PacketKeyT) -> PacketValueT:
        return super().pop(hash_packet_key(packet) % self.capacity, None)

    def __setitem__(self, __key: PacketKeyT, __value: PacketValueT) -> None:
        return super().__setitem__(hash_packet_key(__key) % self.capacity, __value)

    def __getitem__(self, __key: PacketKeyT) -> PacketKeyT:
        return super().__getitem__(hash_packet_key(__key) % self.capacity)

    def __contains__(self, __key: PacketKeyT) -> bool:
        return super().__contains__(hash_packet_key(__key))


class DartSimulator(SimulatorTrait):
    def __init__(self, packet_tracker: PacketTracker, *, name="DartSim"):
        self.packet_tracker = packet_tracker
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

"""DART simulator re-implementation with better interfaces"""
import enum
import typing
from dataclasses import dataclass
from decimal import Decimal
from functools import wraps
from typing import Tuple, Union

from redart.data import Packet, PacketType
from redart.simulator import EvictionTrait, SimulatorTrait, TrackerTrait
from redart.simulator.exceptions import EntryNotFountException

# Value of range tracker:
# (flow_key, (Seq, Expected Ack), timestamp)
PacketKeyT = int
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
    highest_ack: int
    highest_eack: int


@dataclass
class RangeValueT:
    flow_key: PacketKeyT
    flow_info: PacketInfo
    tracking_range: MeasureRange
    seq: SeqT
    ack: AckT
    timestamp: TimestampT
    recirc_quota: RecircQuotaT
    packet_ref: Packet


RangeKeyT = int

PacketValueT = RangeValueT

PacketTrackerT = typing.NewType(
    "PacketTracker", TrackerTrait[PacketKeyT, PacketValueT])


def _hash_packet_key(packet_key: Tuple[int, int]) -> int:
    a, b = packet_key
    return a * a + a + b if a >= b else a + b * b


def hash_packet_key(packet: Packet) -> int:
    if packet.is_seq():
        return _hash_packet_key((packet.to_src_dst_key(), packet.seq + packet.size))
    return _hash_packet_key((packet.to_src_dst_key(), packet.ack))


def preprocess_key(func):
    @wraps(func)
    def wrapper(self, packet_key: Union[PacketKeyT, Packet], *args, **kwargs):
        if isinstance(packet_key, Packet):
            packet_key = packet_key.to_src_dst_key(), packet_key.seq + \
                packet_key.size
        return func(self, packet_key, *args, **kwargs)
    return wrapper


class RangeTrackerValidateAction(enum.IntEnum):
    VALID = enum.auto()
    IGNORE = enum.auto()
    RESET = enum.auto()


class PacketTrackerEviction(EvictionTrait[Tuple[Packet, PacketValueT]]):
    def evict(self, values: Tuple[Packet, PacketValueT], *args):
        self.logger.info("Evicting %s -> %s @ %s",
                         values[0].src, values[0].dst, values[0].index)
        self.tracker: PacketTracker
        (old_packet, new_value) = values
        assert old_packet in self.tracker
        old_packet_item = self.tracker[old_packet]
        self.tracker[old_packet] = new_value
        current_ts = self.tracker.range_tracker_ref[old_packet].timestamp
        if current_ts < new_value.timestamp:
            return
        if old_packet_item.recirc_quota == 0:
            return
        self.tracker.range_tracker_ref.update(
            old_packet, recirc=old_packet_item.recirc_quota - 1)


class RangeTracker(TrackerTrait[RangeKeyT, RangeValueT]):
    def __init__(self, packet_tracker_capacity: int, packet_tracker_eviction: object, capacity: int, eviction_policy: object, *, name="DartRangeTracker", recirc=3):
        self.capacity = capacity
        self.packet_tracker_ref = PacketTracker(
            self, packet_tracker_capacity, packet_tracker_eviction, name="DartPacketTracker")
        self.recirc = recirc
        super().__init__(eviction_policy, name=name)

    def validate(self, packet_key: RangeKeyT, packet: Packet, recirc: bool) -> RangeTrackerValidateAction:
        if packet_key in self:
            entry = self[packet_key].tracking_range
            if packet.is_seq():
                if entry.highest_eack == packet.seq:
                    return RangeTrackerValidateAction.VALID
                if entry.highest_eack < packet.seq:
                    # Reset Case: SEQ less than right edge, signifying a retransmission
                    self.logger.warning(
                        "Resetting range due to SEQ @ %s", packet.index)
                    return RangeTrackerValidateAction.RESET
                self.logger.warning(
                    "Ignore SEQ (retransmission) %s -> %s @ %s", packet.src, packet.dst, packet.index)
                return RangeTrackerValidateAction.IGNORE
            if packet.is_ack():
                if entry.highest_ack < packet.ack <= entry.highest_eack:
                    return RangeTrackerValidateAction.VALID
                if entry.highest_ack == packet.ack:
                    # Reset Case: ACK coming for the left edge
                    self.logger.warning(
                        "Resetting range due to ACK @ %s", packet.index)
                    return RangeTrackerValidateAction.RESET
                if packet.ack <= entry.highest_ack or packet.ack > entry.highest_eack:
                    self.logger.warning(
                        "Ignoring ACK due to duplicate ACK: %s -> %s @ %s", packet.src, packet.dst, packet.index)
                    return RangeTrackerValidateAction.IGNORE
            self.logger.warning("SYN not supported for now")
            return RangeTrackerValidateAction.IGNORE
        if packet.is_seq():
            return RangeTrackerValidateAction.VALID
        # self.logger.warning("Seeing an ACK before SEQ: %s -> %s @ %s",
        #                     packet.src, packet.dst, packet.timestamp)
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
        if recirc is not None:
            self.logger.info(
                "Recirculating packet: %s -> %s @ %s", packet.src, packet.dst, packet.index)
        rt_packet_key = packet.to_src_dst_key() % self.capacity
        action = self.validate(rt_packet_key, packet, recirc is not None)
        if action == RangeTrackerValidateAction.IGNORE:
            if packet.is_seq():
                self.pop(rt_packet_key)
            return
        if action == RangeTrackerValidateAction.RESET:
            if packet not in self:
                raise EntryNotFountException("Entry not found")
            range_item = self.get(rt_packet_key)
            range_item.tracking_range = MeasureRange(
                range_item.tracking_range.highest_eack, range_item.tracking_range.highest_eack)
            self[rt_packet_key] = range_item

        if action == RangeTrackerValidateAction.VALID:
            if packet in self:
                # if the flow has been recorded before,
                # update the range
                range_item = self.get(rt_packet_key)
                if packet.is_seq():
                    self.logger.info(
                        "Update range due to SEQ %s -> %s @ %s", packet.src, packet.dst, packet.index)
                    eack = packet.seq + packet.size
                    if packet.seq >= range_item.tracking_range.highest_eack:
                        if packet.seq == range_item.tracking_range.highest_eack:
                            range_item.tracking_range = MeasureRange(
                                range_item.tracking_range.highest_ack, eack)
                        else:
                            # exceeding current measurement range
                            range_item.tracking_range = MeasureRange(
                                packet.seq, eack
                            )
                        range_item.packet_ref = packet
                        range_item.timestamp = packet.timestamp
                        self.packet_tracker_ref.update(packet, range_item)
                    else:
                        self.logger.warning(
                            "Measurement Range Violation due to SEQ @ %s", packet.index)
                        self.pop(rt_packet_key)
                elif packet.is_ack():
                    if packet not in self:
                        self.logger.warning(
                            "Record for %s -> %s @ %s not found", packet.src, packet.dst, packet.timestamp)
                        return
                    range_item = self.get(rt_packet_key)
                    # Update measurement range
                    if packet.ack == range_item.tracking_range.highest_eack:
                        # Closing the range, could be removed
                        self.pop(rt_packet_key)
                    else:
                        # Update measurement range
                        self.logger.info(
                            "Update range %s by ACK %s", range_item.tracking_range, packet.ack)
                        range_item.tracking_range = MeasureRange(packet.ack,  # highest_ack
                                                                 range_item.tracking_range.highest_eack)

                        self[rt_packet_key] = range_item
                    self.packet_tracker_ref.match(packet)
            else:
                assert len(self) <= self.capacity, "Range tracker is full"
                # flow not in range tracker, check packet tracker
                # if exists, then this is a retransmission and we can drop
                # the entry in the packet tracker
                eack = packet.seq + packet.size
                if packet in self.packet_tracker_ref:
                    self.logger.info("Drop packet due to retransmission: %s -> %s @ %s",
                                     packet.src, packet.dst, packet.index)
                    self.packet_tracker_ref.pop(packet)
                    return
                # if not, then this is a new flow, we insert in the packet tracker
                packet_value = RangeValueT(
                    rt_packet_key,
                    PacketInfo(
                        packet.src, packet.dst, packet.srcport, packet.dstport, packet.type,
                    ),
                    MeasureRange(packet.seq, eack),
                    packet.seq, eack, packet.timestamp, self.recirc if recirc is None else recirc,
                    packet,
                )
                self[rt_packet_key] = packet_value
                self.packet_tracker_ref.update(
                    packet, packet_value)

    def get(self, packet: Union[RangeKeyT, Packet]) -> RangeValueT:
        if isinstance(packet, Packet):
            packet = packet.to_src_dst_key()
        return super().get(packet % self.capacity)

    def __setitem__(self, __key: RangeKeyT, __value: RangeValueT):
        super().__setitem__(__key % self.capacity, __value)

    def __getitem__(self, __key: Union[RangeKeyT, Packet]) -> RangeValueT:
        return self.get(__key)

    def __contains__(self, packet: Union[RangeKeyT, Packet]) -> bool:
        if isinstance(packet, Packet):
            packet = packet.to_src_dst_key()
        return super().__contains__(packet % self.capacity)


class PacketTracker(TrackerTrait[PacketKeyT, PacketValueT]):
    def __init__(self, range_tracker: RangeTracker, capacity: int, eviction_policy: object, *, name="DartPacketTracker"):
        self.capacity = capacity
        self.range_tracker_ref = range_tracker
        self.peers: set[int] = set()
        self.peers_record: dict[int, Tuple[str, int, str, int]] = {}
        # (src <-> dst) -> (rtt samples)
        self.rtt_samples: dict[int, list[Decimal]] = {}
        # (src, dst, srcport, dstport) -> (src <-> dst)
        self.flow_map: dict[Tuple[str, str, int, int], int] = {}
        super().__init__(eviction_policy, name=name)

    def match(self, packet: Packet):
        self.logger.info("Match packet: %s -> %s", packet.src, packet.dst)
        # packet_key = _hash_packet_key((packet.to_src_dst_key(), packet.ack))
        if packet.to_src_dst_key() not in self.peers_record:
            self.peers_record[packet.to_src_dst_key()] = (
                packet.src, packet.srcport, packet.dst, packet.dstport)
            self.peers.add(packet.to_src_dst_key())
        packet_item = self[packet]
        if packet_item is None:
            self.logger.warning("Flow not found: %s -> %s @ %s",
                                packet.src, packet.dst, packet.index)
        else:
            recorded_key = hash_packet_key(packet_item.packet_ref)
            if recorded_key != hash_packet_key(packet):
                self.logger.warning("Flow changed; drop packet")
            else:
                # recompute rtt
                rtt = packet.timestamp - packet_item.timestamp
                tcp_tuple = (packet.src, packet.dst,
                             packet.srcport, packet.dstport)
                record_key = packet.to_src_dst_key()
                if tcp_tuple not in self.flow_map:
                    self.flow_map[tcp_tuple] = record_key
                if record_key not in self.rtt_samples:
                    self.rtt_samples[record_key] = []
                # self.logger.warning("RTT with %s - %s", packet_item.packet_ref.index)
                self.rtt_samples[record_key].append(rtt)

    def update(self, packet: Packet, packet_value: PacketValueT):
        self.logger.info("Update SEQ packet: %s -> %s @ %s",
                         packet.src, packet.dst, packet.index)
        pt_packet_key = hash_packet_key(packet)
        pt_packet_key = pt_packet_key % self.capacity
        if packet in self:
            self.evict(packet, packet_value)
        else:
            if len(self) < self.capacity:
                self[packet] = packet_value
            else:
                pass

    def evict(self, packet: Packet, insert: PacketValueT):
        assert packet in self
        self.eviction_policy: PacketTrackerEviction
        self.eviction_policy.evict((packet, insert))

    def pop(self, packet: Packet) -> PacketValueT:
        return super().pop(hash_packet_key(packet) % self.capacity, None)

    # @preprocess_key
    def __setitem__(self, __key: Packet, __value: PacketValueT) -> None:
        # if __key.is_ack():
        #     return super().__setitem__(_hash_packet_key((__key.to_src_dst_key(), __key.ack)) % self.capacity, __value)
        return super().__setitem__(hash_packet_key(__key) % self.capacity, __value)

    # @preprocess_key
    def __getitem__(self, __key: Packet) -> PacketValueT:
        if __key not in self:
            return None
        # if __key.is_ack():
        #     return super().__getitem__(_hash_packet_key((__key.to_src_dst_key(), __key.ack)) % self.capacity)
        return super().__getitem__(hash_packet_key(__key) % self.capacity)

    # @preprocess_key
    def __contains__(self, __key: Packet) -> bool:
        # if __key.is_ack():
        #     return super().__contains__(_hash_packet_key((__key.to_src_dst_key(), __key.ack)) % self.capacity)
        return super().__contains__(hash_packet_key(__key) % self.capacity)


class DartSimulator(SimulatorTrait):
    def __init__(self, range_tracker: RangeTracker, *, name="DartSim"):
        self.range_tracker = range_tracker
        super().__init__(self.range_tracker, self.range_tracker.packet_tracker_ref, name=name)

    def run_trace(self, trace: list[Packet]):
        self.logger.info("Start running trace")
        return super().run_trace(trace)

    def process_packet(self, packet: Packet):
        self.range_tracker.update(packet)

    def peer_ids(self) -> list[int]:
        return list(self.range_tracker.packet_tracker_ref.peers)

    def get_peer_name(self, peer_id: int) -> Tuple[str, str]:
        return self.range_tracker.packet_tracker_ref.peers_record[peer_id]

    def peer_list(self) -> list[Tuple[str, str]]:
        return list(self.range_tracker.packet_tracker_ref.peers_record.values())

    def peer_rtt_samples(self, peer_id: int) -> list[Decimal]:
        return self.range_tracker.packet_tracker_ref.rtt_samples[peer_id]

    def rtt_samples(self) -> dict[int, list[Decimal]]:
        return self.range_tracker.packet_tracker_ref.rtt_samples

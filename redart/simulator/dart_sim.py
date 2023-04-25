"""DART simulator re-implementation with better interfaces"""
import datetime
import enum
import random
import typing
from dataclasses import dataclass
from decimal import Decimal
from typing import Tuple, Union

from redart.config import TimestampScale, get_config
from redart.data import Packet, PacketType
from redart.simulator import EvictionTrait, SimulatorTrait, TrackerTrait
from redart.simulator.exceptions import EntryNotFountException

# Value of range tracker:
# (flow_key, (Seq, Expected Ack), timestamp)
PacketKeyT = int
SeqT = int
AckT = int
TimestampT = datetime.datetime
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
    highest_ack: int  # Left edge
    highest_eack: int  # Right edge


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
    """
    Hash function for Packet Tracker.
    If the packet is a SEQ packet, then we hash it with (flow_key, EACK)
    otherwise (if it is an ACK packet), we hash it with (flow_key, ACK)
    This is because the tracker only tracks SEQ packets with the EACKs,
    when we encounter an ACK packet, we need to check whether the ACK corresponds
    to any EACK the tracker preivously encountered.
    """
    if packet.is_seq():
        return _hash_packet_key((packet.to_src_dst_key(), packet.seq + packet.size))
    return _hash_packet_key((packet.to_src_dst_key(), packet.ack))


class RangeTrackerValidateAction(enum.IntEnum):
    VALID = enum.auto()
    IGNORE = enum.auto()
    RESET = enum.auto()


class PacketTrackerEviction(EvictionTrait[Tuple[Packet, PacketValueT]]):
    """
    Eviction policy proposed in the Dart paper.
    """

    def evict(self, values: Tuple[Packet, PacketValueT], *args):
        self.logger.warning("Evicting %s -> %s @ %s",
                            values[0].src, values[0].dst, values[0].index)
        self.tracker: PacketTracker
        (old_packet, new_value) = values
        assert old_packet in self.tracker
        if old_packet in self.tracker.range_tracker_ref:
            rt_entry = self.tracker.range_tracker_ref[old_packet]
            eack = old_packet.seq + old_packet.size
            if rt_entry.tracking_range.highest_ack < eack <= rt_entry.tracking_range.highest_eack:
                return
        self.tracker[old_packet] = new_value


class PacketTrackerEvictionNewPacketWithProbabilityNoRecirculation(EvictionTrait[Tuple[Packet, PacketValueT]]):
    """
    Upon seeing a hash collection, we prefer to store the new packet and discard the old packet with probability.
    """
    probability = 0.5

    def evict(self, values: Tuple[Packet, PacketValueT], *args):
        self.logger.info("Evicting %s -> %s @ %s",
                         values[0].src, values[0].dst, values[0].index)
        self.tracker: PacketTracker
        (old_packet, new_value) = values
        assert old_packet in self.tracker
        if random.uniform(0, 1) < self.probability:
            self.tracker[old_packet] = new_value


class PacketTrackerEvictionNewPacketWithProbabilityWithRecirculation(EvictionTrait[Tuple[Packet, PacketValueT]]):
    """
    Upon seeing a hash collection, we follow what Dart proposes and recirculate the old packet.
    However, if the old packet is valid and it comes back, we prefer new packet over it with probability.
    """

    probability = 1

    def evict(self, values: Tuple[Packet, PacketValueT], *args):
        self.logger.warning("Evicting %s -> %s @ %s",
                            values[0].src, values[0].dst, values[0].index)
        self.tracker: PacketTracker
        (old_packet, new_value) = values
        assert old_packet in self.tracker
        if old_packet in self.tracker.range_tracker_ref:
            rt_entry = self.tracker.range_tracker_ref[old_packet]
            eack = old_packet.seq + old_packet.size
            if rt_entry.tracking_range.highest_ack < eack <= rt_entry.tracking_range.highest_eack:
                if random.uniform(0, 1) < self.probability:
                    self.tracker[old_packet] = new_value
                return
        self.tracker[old_packet] = new_value


class RangeTracker(TrackerTrait[RangeKeyT, RangeValueT]):
    """
    The range tracker tracks the range of SEQ/ACK that
    would possible yield accurate RTT measurement.

    The `update` function is invoked when a flow enters RangeTracker.
    """

    def __init__(self, packet_tracker_capacity: int, packet_tracker_eviction: object, total_capacity: int, eviction_policy: object, *, name="DartRangeTracker", recirc=3):
        self.ignore_syn = get_config().ignore_syn
        assert packet_tracker_capacity < total_capacity
        self.capacity = total_capacity - packet_tracker_capacity
        self.packet_tracker_ref = PacketTracker(
            self, packet_tracker_capacity, packet_tracker_eviction, name="DartPacketTracker")
        self.recirc = recirc
        super().__init__(eviction_policy, name=name)

    def validate(self, packet_key: RangeKeyT, packet: Packet, recirc=False) -> RangeTrackerValidateAction:
        if packet.is_syn() and self.ignore_syn:
            self.logger.warning("Ignoring SYN packet @ %s", packet.index)
            return RangeTrackerValidateAction.IGNORE
        if packet.is_fin():
            self.logger.warning("Flow finished for %s:%s -> %s:%s @ %s",
                                packet.src, packet.srcport, packet.dst, packet.dstport, packet.index)
            return RangeTrackerValidateAction.IGNORE
        if packet_key in self:
            entry = self[packet_key].tracking_range
            if packet.is_seq():
                if entry.highest_eack <= packet.seq:
                    return RangeTrackerValidateAction.VALID
                self.logger.warning(
                    "Ignore SEQ (retransmission) %s:%s -> %s:%s @ %s", packet.src, packet.srcport,
                    packet.dst, packet.dstport, packet.index)
                return RangeTrackerValidateAction.RESET
            if packet.is_ack():
                if entry.highest_ack < packet.ack <= entry.highest_eack:
                    return RangeTrackerValidateAction.VALID
                if entry.highest_ack == packet.ack:
                    # Reset Case: ACK coming for the left edge
                    self.logger.warning(
                        "Dropping range due to ACK @ %s", packet.index)
                    self.pop(packet_key)
                    return RangeTrackerValidateAction.IGNORE
                if packet.ack <= entry.highest_ack or packet.ack > entry.highest_eack:
                    self.logger.warning(
                        "Ignoring ACK due to duplicate ACK: %s:%s -> %s:%s @ %s", packet.src, packet.srcport,
                        packet.dst, packet.dstport, packet.index)
                    return RangeTrackerValidateAction.IGNORE
            self.logger.warning("SYN not supported for now")
            return RangeTrackerValidateAction.IGNORE
        if recirc:
            return RangeTrackerValidateAction.IGNORE
        if packet.is_seq():  # A new flow seen
            return RangeTrackerValidateAction.VALID
        return RangeTrackerValidateAction.IGNORE

    def update(self, packet: Packet, recirc=None):
        """
        Upon receiving a new flow:
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
        action = self.validate(rt_packet_key, packet,
                               recirc=recirc is not None)
        if action == RangeTrackerValidateAction.IGNORE:
            if packet.is_syn():
                return
            if packet.is_seq() or packet.is_fin():
                self.pop(rt_packet_key, None)
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
                            # exceeding current measurement range i.e. the "hole" case
                            range_item.tracking_range = MeasureRange(
                                packet.seq, eack
                            )
                        if range_item.tracking_range.highest_ack == range_item.tracking_range.highest_eack:
                            self.logger.warning(
                                "Delete collapsed range due to SEQ @ %s", packet.index)
                            self.pop(rt_packet_key)
                            return
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
                assert packet.is_seq()
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
            packet = packet.to_src_dst_key()  # Flow key
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
    """
    The packet tracker tracks preivously seen SEQ packets.
    In principle, users are not supposed to mutate the data structure
    but only query the measured RTTs via interfaces provided by `DartSimulator`.

    The instance of a packet tracker is handled by the range tracker.
    """

    def __init__(self, range_tracker: RangeTracker, capacity: int, eviction_policy: object, *, name="DartPacketTracker"):
        self.capacity = capacity
        self.range_tracker_ref = range_tracker
        self.peers: set[int] = set()
        self.peers_record: dict[int, Tuple[str, int, str, int]] = {}
        self.time_scale = get_config().timescale
        # (src <-> dst) -> (rtt samples)
        self.rtt_samples: dict[int, list[Decimal]] = {}
        # (src, dst, srcport, dstport) -> (src <-> dst)
        self.flow_map: dict[Tuple[str, str, int, int], int] = {}
        super().__init__(eviction_policy, name=name)

    def match(self, packet: Packet):
        self.logger.info("Match packet: %s -> %s", packet.src, packet.dst)
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
                tcp_tuple = (packet.src, packet.dst,
                             packet.srcport, packet.dstport)
                record_key = packet.to_src_dst_key()
                if tcp_tuple not in self.flow_map:
                    self.flow_map[tcp_tuple] = record_key
                if record_key not in self.rtt_samples:
                    self.rtt_samples[record_key] = []
                self.rtt_samples[record_key].append(
                    packet.time_since(packet_item.packet_ref))

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

    def __setitem__(self, __key: Packet, __value: PacketValueT) -> None:
        return super().__setitem__(hash_packet_key(__key) % self.capacity, __value)

    def __getitem__(self, __key: Packet) -> PacketValueT:
        if __key not in self:
            return None
        return super().__getitem__(hash_packet_key(__key) % self.capacity)

    def __contains__(self, __key: Packet) -> bool:
        return super().__contains__(hash_packet_key(__key) % self.capacity)


class DartSimulator(SimulatorTrait):
    """
    The DART simulator.
    """

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

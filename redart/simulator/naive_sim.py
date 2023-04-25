import datetime

from redart.config import TimestampScale, get_config
from redart.data import Packet
from redart.simulator.traits import SimulatorTrait


class NaiveSimulator(SimulatorTrait):
    def __init__(self):
        super().__init__(None, {}, name="NaiveSimulator")
        self.record = {}
        self.rtt_samples = {}
        self.time_scale = get_config().timescale
        self.seen = set()

    # A reference rather than ground truth
    # When retransmission, we pessimistically take with the first SEQ packet
    def process_packet(self, packet: Packet):
        key = packet.to_src_dst_key()
        if packet.is_fin():
            # flow finished, clear the peer from record
            # self.record = dict(
            #     filter(lambda x: x[0][0] != key, self.record.items()))
            # self.seen = set(filter(lambda x: not isinstance(
            #     x, tuple) or x[0] != key, self.seen))
            return
        if packet.is_syn():
            return
        if packet.is_seq():
            eack = packet.seq + packet.packet_size
            if (key, eack) not in self.record and (key, eack) not in self.seen:
                self.record[key, eack] = packet
                self.seen.add((key, eack))
        elif packet.is_ack():
            if (key, packet.ack) in self.record:
                if key not in self.rtt_samples:
                    self.rtt_samples[key] = []
                rtt = packet.timestamp - self.record[key, packet.ack].timestamp
                if self.time_scale == TimestampScale.SECOND:
                    self.rtt_samples[key].append(
                        rtt.total_seconds())
                elif self.time_scale == TimestampScale.MILLISECOND:
                    self.rtt_samples[key].append(
                        rtt / datetime.timedelta(milliseconds=1))
                elif self.time_scale == TimestampScale.MICROSECOND:
                    self.rtt_samples[key].append(
                        rtt / datetime.timedelta(microseconds=1))
                if self.rtt_samples[key][-1] < 500:
                    self.rtt_samples[key].pop()
                if self.rtt_samples[key] == []:
                    self.rtt_samples.pop(key)
                self.record.pop((key, packet.ack))

from redart.data import Packet
from redart.simulator import SimulatorTrait


class TCPTraceSim(SimulatorTrait):
    def __init__(self, *, name=None, outgoing_only=False):
        self.flow_key_to_names = {}
        self.rtt_samples = {}
        self.outgoing_only = outgoing_only
        super().__init__({}, {}, name=name)

    def insert_pt(self, packet: Packet, eack: int):
        self.packet_tracker[packet.to_src_dst_key(), eack] = packet

    def warning(self, msg: str, packet: Packet):
        self.logger.warning("%s. %s:%s -> %s:%s @ %s",
                            msg, packet.src, packet.srcport, packet.dst, packet.dstport, packet.index)

    def process_SEQ(self, packet: Packet):
        assert packet.is_seq()
        flow_key = packet.to_src_dst_key()
        eack = packet.seq + packet.packet_size
        if flow_key in self.range_tracker and not self.range_tracker[flow_key][0] == self.range_tracker[flow_key][1]:
            highest_ack, highest_eack = self.range_tracker[flow_key]
            if packet.seq >= highest_eack:
                if packet.seq == highest_eack:
                    self.range_tracker[flow_key] = (highest_ack, eack)
                else:
                    self.range_tracker[flow_key] = (packet.seq, eack)
                self.insert_pt(packet, eack)
            else:
                self.range_tracker[flow_key] = (eack, eack)
        else:
            self.range_tracker[flow_key] = (packet.seq, eack)
            self.insert_pt(packet, eack)

    def process_ACK(self, packet: Packet):
        assert packet.is_ack()
        flow_key = packet.to_src_dst_key()
        if flow_key not in self.range_tracker or self.range_tracker[flow_key][0] == self.range_tracker[flow_key][1]:
            self.range_tracker[flow_key] = (packet.ack, packet.ack)
            return
        ack = packet.ack
        if flow_key in self.range_tracker:
            highest_ack, highest_eack = self.range_tracker[flow_key]
            if ack < highest_ack or ack > highest_eack:
                self.warning("Dropping out-of-range ACK", packet)
            elif ack == highest_ack:
                self.warning(
                    "Retransmission indicated by duplicated ACK", packet)
                self.range_tracker[flow_key] = (highest_eack, highest_eack)
                if (flow_key, highest_eack) in self.packet_tracker:
                    self.packet_tracker.pop((flow_key, highest_eack))
            elif highest_ack < ack <= highest_eack:
                self.range_tracker[flow_key] = (ack, highest_eack)
                if (flow_key, ack) in self.packet_tracker:
                    packet_record = self.packet_tracker.pop((flow_key, ack))
                    if flow_key not in self.flow_key_to_names:
                        self.flow_key_to_names[flow_key] = (packet_record.src, packet_record.srcport,
                                                            packet_record.dst, packet_record.dstport)
                    if flow_key not in self.rtt_samples:
                        self.rtt_samples[flow_key] = []
                    self.rtt_samples[flow_key].append(
                        packet.time_since(packet_record))
        else:
            self.warning("Flow not found in packet tracker", packet)

    def process_packet(self, packet: Packet):
        if self.outgoing_only and not packet.src.startswith("10.") and packet.is_seq():
            return
        if packet.is_fin() or packet.is_syn():
            return
        if packet.is_seq():
            self.process_SEQ(packet)
        elif packet.is_ack():
            self.process_ACK(packet)

from redart.data import Packet
from redart.simulator.traits import SimulatorTrait


class GroundTruthSimulator(SimulatorTrait):
    def __init__(self):
        super().__init__(None, {}, name="GroundTruthSimulator")
        self.record = {}
        self.rtt_samples = {}
        self.highest_eack = {}

    def process_packet(self, packet: Packet):
        key = packet.to_src_dst_key()
        if packet.is_seq():
            eack = packet.seq + packet.packet_size
            if (key, eack) not in self.record:
                if key in self.highest_eack:
                    if self.highest_eack[key] >= eack:
                        return
                self.record[key, eack] = packet
            if key not in self.highest_eack:
                self.highest_eack[key] = eack
            self.highest_eack[key] = max(self.highest_eack[key], eack)
        elif packet.is_ack():
            if (key, packet.ack) in self.record:
                if key not in self.rtt_samples:
                    self.rtt_samples[key] = []
                # self.logger.warning("RTT with %s - %s", packet.timestamp, self.record[key, packet.ack].timestamp)
                self.rtt_samples[key].append(
                    packet.timestamp - self.record[key, packet.ack].timestamp)
                self.record.pop((key, packet.ack))

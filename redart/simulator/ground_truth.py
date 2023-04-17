from redart.data import Packet
from redart.simulator.traits import SimulatorTrait


class GroundTruthSimulator(SimulatorTrait):
    def __init__(self):
        super().__init__(None, {}, name="GroundTruthSimulator")
        self.record = {}
        self.rtt_samples = {}

    def process_packet(self, packet: Packet):
        key = packet.to_src_dst_key()
        if key not in self.record:
            self.record[key] = {}
        if packet.is_ack():
            if (key, packet.ack) in self.record:
                if key not in self.rtt_samples:
                    self.rtt_samples[key] = []
                self.rtt_samples[key].append(
                    packet.timestamp - self.record[key, packet.ack])
        self.record[key, packet.seq + packet.packet_size] = packet.timestamp

from redart.simulator.traits import SimulatorTrait
from redart.data import Packet


class GroundTruthSimulator(SimulatorTrait):
    def __init__(self):
        super().__init__(None, {}, name="GroundTruthSimulator")
        self.record = {}
    
    def run_trace(self, trace: list[Packet]):
        for packet in trace:
            self.process_packet(packet)
    
    def process_packet(self, packet: Packet):
        key = packet.to_src_dst_key()
        if key not in self.record:
            self.record[key] = {}
        if packet.seq not in self.record[key]:
            self.record[key][packet.seq] = packet.timestamp
        if key not in self.packet_tracker:
            self.packet_tracker[key] = (packet.timestamp, [])
        else:
            (_, rtts) = self.packet_tracker[key]
            if packet.ack in self.record[key]:
                self.packet_tracker[key] = (packet.timestamp, rtts + [packet.timestamp - self.record[key][packet.ack]])

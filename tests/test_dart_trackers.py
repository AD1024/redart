import os
from decimal import Decimal

from redart.data import Packet, PacketType
from redart.data.parser import parse_pcap
from redart.simulator.dart_sim import (DartSimulator, PacketTracker,
                                       PacketTrackerEviction, RangeTracker)

os.environ.update({
    "REDART_LOG_LEVEL": "DEBUG"
})

INF = 1145141919810


def test_tracker_operations():
    range_tracker = RangeTracker(
        INF, PacketTrackerEviction, INF, None
    )
    src = "1.1.1.1"
    dst = "0.0.0.0"
    srcport = 114
    dstport = 514

    packet = Packet(src, srcport, dst, dstport, 0, 0,
                    Decimal(0), 1000, PacketType.SEQ)
    ack = Packet(dst, dstport, src, srcport, 1000,
                 0, Decimal(0.5), 0, PacketType.ACK)

    range_tracker.update(packet)
    assert range_tracker.get(packet) is not None
    assert range_tracker.get(ack) is not None
    assert packet in range_tracker
    assert ack in range_tracker.packet_tracker_ref


def test_flow_insertion_inf_space():
    range_tracker = RangeTracker(
        INF, PacketTrackerEviction, INF, None
    )
    # packet_tracker = range_tracker.packet_tracker_ref
    src = "1.1.1.1"
    dst = "0.0.0.0"
    srcport = 114
    dstport = 514

    def seq_packet(seq: int, ts: Decimal, size: int):
        return Packet(src, srcport, dst, dstport, 0, seq, ts, size, PacketType.SEQ)

    def ack_packet(seq_packet: Packet, ts: Decimal):
        return Packet(seq_packet.dst, seq_packet.dstport, seq_packet.src, seq_packet.srcport, seq_packet.seq + seq_packet.packet_size, seq_packet.seq, ts, 0, PacketType.ACK)

    trace = [
        seq_packet(0, Decimal(0), 1000),
        seq_packet(0, Decimal(0.6), 1000),
        ack_packet(seq_packet(0, Decimal(0.1), 1000), Decimal(0.8)),
    ]

    sim = DartSimulator(range_tracker)
    sim.run_trace(trace)
    print(sim.range_tracker.packet_tracker_ref.rtt_samples)
    for pid in sim.peer_ids():
        peer_name = sim.get_peer_name(pid)
        print("RTT for peer %s <-> %s: %s" %
              (peer_name[0], peer_name[1], sim.peer_rtt_samples(pid)))


def test_flow():
    trace = parse_pcap("../data/test.pcap")
    range_tracker = RangeTracker(
        INF, PacketTrackerEviction, INF, None
    )
    sim = DartSimulator(range_tracker)
    sim.run_trace(trace)
    for pid in sim.peer_ids():
        peer_name = sim.get_peer_name(pid)
        try:
            print("RTT for peer %s:%s <-> %s:%s =>\n%s\n" %
                  (*peer_name, sim.peer_rtt_samples(pid)))
        except:
            sim.logger.warning(
                "Failed to get RTT for peer %s:%s <-> %s:%s", *peer_name)


if __name__ == '__main__':
    test_tracker_operations()
    test_flow_insertion_inf_space()
    test_flow()

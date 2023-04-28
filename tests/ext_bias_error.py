import argparse
import functools

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import run_ground_truth
import test_dart_trackers

import redart
from redart.simulator import dart_sim, tcp_trace_sim

parser = argparse.ArgumentParser()
parser.add_argument("--dataset", type=str, default="test")
parser.add_argument("--outgoing-only", action="store_true", default=False)
parser.add_argument("--packet-tracker-size", type=int, default=10001)
parser.add_argument("--total-size", type=int, default=20001)
parser.add_argument("--in-flight-threshold", type=int, default=3)
parser.add_argument("--rt-eviction-prob", type=float, default=0.5)
# parser.add_argument("--pt-policy", type=str, default="dart")
parser.add_argument("--rt-policy", type=str, default="keep-new")

args = parser.parse_args()

eviction_policies = {
    "dart": dart_sim.PacketTrackerEviction,
    "prob": dart_sim.PacketTrackerEvictionNewPacketWithProbabilityNoRecirculation,
    "prob-recirc": dart_sim.PacketTrackerEvictionNewPacketWithProbabilityWithRecirculation,
}

rt_eviction_policies = {
    "keep-new": dart_sim.MkRTProbabilisticEviction(0.0),
    "keep-old": dart_sim.MkRTProbabilisticEviction(1.0),
    "prob": dart_sim.MkRTProbabilisticEviction(args.rt_eviction_prob),
    "refined": dart_sim.MkRTRefinedEviction(args.in_flight_threshold),
}

dataset = args.dataset
f = "../data/{}.pcap".format(dataset)

redart.init(redart.config.TimestampScale.MILLISECOND, ignore_syn=True)

print("===================== TRUTH =====================")
truth = run_ground_truth.main(
    f, cache_file=f+".cache", outgoing_only=args.outgoing_only, constr=tcp_trace_sim.TCPTraceSim)
truth_values = {}

for pkt in truth[0]:
    key = pkt.to_src_dst_key()
    if key not in truth[1]:
        continue
    if pkt.src > pkt.dst:
        truth_values[(pkt.src, pkt.srcport, pkt.dst,
                      pkt.dstport)] = truth[1][key]
    else:
        truth_values[(pkt.dst, pkt.dstport, pkt.src,
                      pkt.srcport)] = truth[1][key]


print("===================== DART =====================")
dart = test_dart_trackers.test_flow(
    f, truth[2], pt_capacity=args.packet_tracker_size,
    pt_policy=eviction_policies["dart"],
    outgoing_only=args.outgoing_only,
    rt_policy=rt_eviction_policies[args.rt_policy],
    total_capacity=args.total_size)
dart_values = {}

for pkt in dart[0]:
    if pkt[0] > pkt[2]:
        dart_values[pkt[0:4]] = pkt[4]
    else:
        dart_values[(pkt[2], pkt[3], pkt[0], pkt[1])] = pkt[4]


print("===================== PROB =====================")
prob = test_dart_trackers.test_flow(
    f, truth[2], pt_capacity=args.packet_tracker_size,
    pt_policy=eviction_policies["prob"],
    outgoing_only=args.outgoing_only,
    rt_policy=rt_eviction_policies[args.rt_policy],
    total_capacity=args.total_size)
prob_values = {}

for pkt in prob[0]:
    if pkt[0] > pkt[2]:
        prob_values[pkt[0:4]] = pkt[4]
    else:
        prob_values[(pkt[2], pkt[3], pkt[0], pkt[1])] = pkt[4]


print("===================== PROB-RECIRC =====================")
prob_recirc = test_dart_trackers.test_flow(
    f, truth[2], pt_capacity=args.packet_tracker_size,
    pt_policy=eviction_policies["prob-recirc"],
    outgoing_only=args.outgoing_only,
    rt_policy=rt_eviction_policies[args.rt_policy],
    total_capacity=args.total_size)
prob_recirc_values = {}

for pkt in prob_recirc[0]:
    if pkt[0] > pkt[2]:
        prob_recirc_values[pkt[0:4]] = pkt[4]
    else:
        prob_recirc_values[(pkt[2], pkt[3], pkt[0], pkt[1])] = pkt[4]


def all_entries(d): return functools.reduce(lambda x, y: x + y, d, [])


dart_entries = all_entries(dart_values.values())
prob_entries = all_entries(prob_values.values())
prob_recirc_entries = all_entries(prob_recirc_values.values())
truth_entries = all_entries(truth_values.values())

dart_entries.sort()
prob_entries.sort()
prob_recirc_entries.sort()
truth_entries.sort()


def calculate_percentile(entry_array, p):
    p = p/100
    # entry_array.sort()
    total = len(entry_array)
    index = int(total*p)
    truth_total = len(truth_entries)
    truth_index = int(truth_total*p)
    # print(f'{p},{total},{index},{truth_total},{truth_index}')
    # print(f'{entry_array[index]},{truth_entries[truth_index]}')
    return (entry_array[index]-truth_entries[truth_index])/truth_entries[truth_index]


def calculate_max_error_percentile(entry_array):
    max_error = -1
    for p in range(5, 96):
        max_error = max(max_error, abs(calculate_percentile(entry_array, p)))
    return max_error


print(f'RTT collection error')
print(f'Dart')
print(f'{calculate_percentile(dart_entries,50)}')
print(f'{calculate_percentile(dart_entries,95)}')
print(f'{calculate_percentile(dart_entries,99)}')
print(f'{calculate_max_error_percentile(dart_entries)}')

print(f'Favor-new')
print(f'{calculate_percentile(prob_entries,50)}')
print(f'{calculate_percentile(prob_entries,95)}')
print(f'{calculate_percentile(prob_entries,99)}')
print(f'{calculate_max_error_percentile(prob_entries)}')

print(f'Recirc-probability')
print(f'{calculate_percentile(prob_recirc_entries,50)}')
print(f'{calculate_percentile(prob_recirc_entries,95)}')
print(f'{calculate_percentile(prob_recirc_entries,99)}')
print(f'{calculate_max_error_percentile(prob_recirc_entries)}')

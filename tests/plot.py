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
parser.add_argument("--pt-policy", type=str, default="dart")
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

redart.init(redart.config.TimestampScale.MILLISECOND,
            ignore_syn=True, logging_level="ERROR")

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
    pt_policy=eviction_policies[args.pt_policy],
    outgoing_only=args.outgoing_only,
    rt_policy=rt_eviction_policies[args.rt_policy],
    total_capacity=args.total_size)
dart_values = {}

# print(dart[0])

for pkt in dart[0]:
    if pkt[0] > pkt[2]:
        dart_values[pkt[0:4]] = pkt[4]
    else:
        dart_values[(pkt[2], pkt[3], pkt[0], pkt[1])] = pkt[4]


def all_entries(d): return functools.reduce(lambda x, y: x + y, d, [])


dart_entries = all_entries(dart_values.values())
truth_entries = all_entries(truth_values.values())

cmap = plt.colormaps["Set1"]


def plot_horizontal_bar(ax):
    ls = [len(dart_entries), len(truth_entries)]
    lb = ["ReDart", "TCPtrace"]
    y_pos = np.arange(len(ls))
    ax.barh(y_pos, ls, alpha=0.8, color=[cmap(0), cmap(1)])
    ax.set_yticks(y_pos, labels=lb)
    for i in range(len(y_pos)):
        ax.text(ls[i], y_pos[i], ls[i])
    ax.set_ylabel("RTT Tool")
    ax.set_xlabel("Number of RTT samples")
    ax.set_title(dataset)


def plot_hist(ax, key):
    mx = float(max(max(truth_values[key]), max(dart_values[key])))
    bins = np.linspace(0, mx, 40)
    ax.hist(truth_values[key], bins, alpha=0.6,
            label="TCPtrace", color=cmap(0))
    ax.hist(dart_values[key], bins, alpha=0.6, label="ReDart", color=cmap(1))
    ax.legend(loc='upper right')
    ax.set_xlabel("RTT(ms)")
    ax.set_title(dataset)


def plot_cdf(ax, ax_large, ub=("y", 1.0)):

    def get_cdf(l):
        x, c = np.unique(l, return_counts=True)
        csum = np.cumsum(c)
        csum = csum / csum[-1]
        idx = (csum if ub[0] == "y" else x).searchsorted(ub[1])
        print("ub", ub, "x[idx]", x[idx-1], "y[idx]", csum[idx-1])
        return x[:idx], csum[:idx], x[idx:], 1 - csum[idx:]

    x_dart, y_dart, x_dart_large, y_dart_large = get_cdf(dart_entries)
    ax.plot(x_dart, y_dart, label="ReDart", color=cmap(0))
    x_truth, y_truth, x_truth_large, y_truth_large = get_cdf(truth_entries)
    ax.plot(x_truth, y_truth, label="TCPtrace", color=cmap(1))
    ax.legend(loc='lower right')
    ax.set_xlabel("RTT(ms)")
    ax.set_ylabel("CDF")
    ax.set_title(dataset)

    # x_dart, y_dart = get_cdf(dart_entries)
    ax_large.plot(x_dart_large, y_dart_large, label="ReDart", color=cmap(0))
    # x_truth, y_truth = get_cdf(truth_entries)
    ax_large.plot(x_truth_large, y_truth_large,
                  label="TCPtrace", color=cmap(1))
    ax_large.legend(loc='upper right')
    ax_large.set_xlabel("RTT(ms)")
    ax_large.set_ylabel("CCDF")
    ax_large.set_title(dataset)


hist, axs = plt.subplots(1, 2)
lens = {}
for key in set(dart_values.keys()).intersection(set(truth_values.keys())):
    lens[key] = len(dart_values[key])
plot_hist(axs[0], max(lens, key=lens.get))
lens.pop(max(lens, key=lens.get))
lens.pop(max(lens, key=lens.get))
plot_hist(axs[1], max(lens, key=lens.get))
hist.savefig("figures/{}_{}_{}_{}_hist.png".format(dataset,
             args.pt_policy, args.rt_policy, args.packet_tracker_size), dpi=300)


bar, axs = plt.subplots(1, 1)
plot_horizontal_bar(axs)
bar.savefig("figures/{}_{}_{}_{}_bar.png".format(dataset,
            args.pt_policy, args.rt_policy, args.packet_tracker_size), dpi=300)


cdf, axs = plt.subplots(1, 2, figsize=(10, 5))
# ub = ("y", 1.0)
ub = ("y", 0.97)
plot_cdf(axs[0], axs[1], ub)
cdf.savefig("figures/{}_{}_{}_{}_cdf.png".format(dataset,
            args.pt_policy, args.rt_policy, args.packet_tracker_size), dpi=300)


def test_dart_for_size(sz):
    dart, ev_count = test_dart_trackers.test_flow(
        f, truth[2], pt_capacity=sz,
        pt_policy=eviction_policies[args.pt_policy],
        outgoing_only=args.outgoing_only,
        rt_policy=rt_eviction_policies[args.rt_policy],
        total_capacity=sz + 20000,
        get_evition_count=True)
    dart_values = {}
    # print(dart[0])

    for pkt in dart[0]:
        if pkt[0] > pkt[2]:
            dart_values[pkt[0:4]] = pkt[4]
        else:
            dart_values[(pkt[2], pkt[3], pkt[0], pkt[1])] = pkt[4]

    dart_entries = all_entries(dart_values.values())
    return dart_entries, ev_count


pt_x = []
pt_y = []
pt_z = []
pt_r50 = []
pt_r95 = []
pt_r99 = []

truth_entries.sort()
t50 = truth_entries[int(len(truth_entries) * 0.5)]
t95 = truth_entries[int(len(truth_entries) * 0.95)]
t99 = truth_entries[int(len(truth_entries) * 0.99)]

for _sz in range(9, 17):
    # for _sz in [13, 14]:
    # __counter.__DIRTY_CODE_NUM_OF_EVICTION = 0
    sz = (2 ** _sz) + 1
    result, ev_count = test_dart_for_size(sz)
    pt_x.append(_sz)

    pt_y.append(100.0 * len(result) / len(truth_entries))
    pt_z.append(ev_count / len(truth[2]))

    result.sort()
    pt_r50.append(abs(result[int(len(result) * 0.5)] / t50 - 1)*100)
    pt_r95.append(abs(result[int(len(result) * 0.95)] / t95 - 1)*100)
    pt_r99.append(abs(result[int(len(result) * 0.99)] / t99 - 1)*100)

print(pt_x, pt_y, pt_z)

sz_plot, axs = plt.subplots(1, 3, figsize=(13, 5))
axs[0].plot(pt_x, pt_r50, "-.o", label="50th percentile")
axs[0].plot(pt_x, pt_r95, "-.o", label="95th percentile")
axs[0].plot(pt_x, pt_r99, "-.o", label="99th percentile")
axs[0].legend(loc='upper right')
axs[0].set_xlabel("log2(Table Size)")
axs[0].set_ylabel("RTT Collection Error (%)")

axs[1].plot(pt_x, pt_y, "-o")
axs[1].set_xlabel("log2(Table Size)")
axs[1].set_ylabel("RTT Count Fraction (%)")


axs[2].plot(pt_x, pt_z, "-o")
axs[2].set_xlabel("log2(Table Size)")
axs[2].set_ylabel("Recirculations Per Packet")

sz_plot.savefig("figures/{}_{}_{}_size.png".format(dataset,
                                                   args.pt_policy, args.rt_policy), dpi=300)


print("truth", t50, t95, t99)

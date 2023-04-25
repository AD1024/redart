import argparse
import functools

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import run_ground_truth
import test_dart_trackers

import redart
from redart.simulator import dart_sim

parser = argparse.ArgumentParser()
parser.add_argument("--dataset", type=str, default="test")
parser.add_argument("--tracker-size", type=int, default=10001)
parser.add_argument("--policy", type=str, default="dart")

eviction_policies = {
    "dart": dart_sim.PacketTrackerEviction,
    "prob": dart_sim.PacketTrackerEvictionNewPacketWithProbabilityNoRecirculation,
    "prob_recirc": dart_sim.PacketTrackerEvictionNewPacketWithProbabilityWithRecirculation,
}

args = parser.parse_args()

dataset = args.dataset
f = "../data/{}.pcap".format(dataset)

redart.init(redart.config.TimestampScale.MICROSECOND, ignore_syn=True)

print("===================== TRUTH =====================")
truth = run_ground_truth.main(f, cache_file=f+".cache")
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
    f, truth[2], capacity=args.tracker_size, policy=eviction_policies[args.policy])
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
    bins = np.linspace(0, 20000, 40)
    ax.hist(truth_values[key], bins, alpha=0.6,
            label="TCPtrace", color=cmap(0))
    ax.hist(dart_values[key], bins, alpha=0.6, label="ReDart", color=cmap(1))
    ax.legend(loc='upper right')
    ax.set_xlabel("RTT(us)")
    ax.set_title(dataset)


def plot_cdf(ax, ub=("y", 1.0)):

    def get_cdf(l):
        x, c = np.unique(l, return_counts=True)
        csum = np.cumsum(c)
        csum = csum / csum[-1]
        idx = (csum if ub[0] == "y" else x).searchsorted(ub[1])
        # idx2 = x.searchsorted(1000)
        idx2 = 0
        print("ub", ub, "x[idx]", x[idx-1], "y[idx]", csum[idx-1])
        return x[idx2:idx], csum[idx2:idx]

    x_dart, y_dart = get_cdf(dart_entries)
    ax.plot(x_dart, y_dart, label="ReDart", color=cmap(0))
    x_truth, y_truth = get_cdf(truth_entries)
    ax.plot(x_truth, y_truth, label="TCPtrace", color=cmap(1))
    ax.legend(loc='lower right')
    ax.set_xlabel("RTT(us)")
    ax.set_ylabel("CDF")
    ax.set_title(dataset)


hist, axs = plt.subplots(1, 2)
lens = {}
for key in set(dart_values.keys()).intersection(set(truth_values.keys())):
    lens[key] = len(dart_values[key])
plot_hist(axs[0], max(lens, key=lens.get))
lens.pop(max(lens, key=lens.get))
lens.pop(max(lens, key=lens.get))
plot_hist(axs[1], max(lens, key=lens.get))
hist.savefig("figures/{}_hist.png".format(dataset), dpi=300)


bar, axs = plt.subplots(1, 1)
plot_horizontal_bar(axs)
bar.savefig("figures/{}_bar.png".format(dataset), dpi=300)


cdf, axs = plt.subplots(1, 1)
# ub = ("y", 1.0)
ub = ("x", 120000)
plot_cdf(axs, ub)
cdf.savefig("figures/{}_cdf.png".format(dataset), dpi=300)

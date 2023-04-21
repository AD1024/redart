import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import run_ground_truth
import test_dart_trackers
import functools

import redart

f = "../data/smallFlows.pcap"
# f = "../data/test.pcap"

redart.init(redart.config.TimestampScale.MICROSECOND)

truth = run_ground_truth.main(f, cache_file="../data/smallFlows.cache")
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

dart = test_dart_trackers.test_flow(f, truth[2])
dart_values = {}

# print(dart[0])

for pkt in dart[0]:
    if pkt[0] > pkt[2]:
        dart_values[pkt[0:4]] = pkt[4]
    else:
        dart_values[(pkt[2], pkt[3], pkt[0], pkt[1])] = pkt[4]


# print("==================")
# print(dart_values.keys())
# print(truth_values.keys())


cmap = plt.colormaps["Set1"]

def plot_horizontal_bar(ax, ls, labels, colors):
    y_pos = np.arange(len(ls))
    ax.barh(y_pos, ls, alpha=0.8, color=colors)
    ax.set_yticks(y_pos, labels=labels)
    for i in range(len(y_pos)):
        ax.text(ls[i], y_pos[i], ls[i])
    ax.set_ylabel("RTT Tool")
    ax.set_title("Number of RTT samples")

def plot_hist(ax, key, title):
    mx = float(max(max(truth_values[key]), max(dart_values[key])))
    bins = np.linspace(0, 200, 40)
    ax.hist(truth_values[key], bins, alpha=0.6, label="TCPtrace", color=cmap(0))
    ax.hist(dart_values[key], bins, alpha=0.6, label="ReDart", color=cmap(1))
    ax.legend(loc='upper right')
    ax.set_title(title)



lens = {}
for key in set(dart_values.keys()).intersection(set(truth_values.keys())):
    lens[key] = len(dart_values[key])

hist, axs = plt.subplots(1, 2)

max_key = max(lens, key=lens.get)
plot_hist(axs[0], max_key, "")
lens.pop(max_key)
max_key = max(lens, key=lens.get)
plot_hist(axs[1], max_key, "")

hist.savefig("hist.png", dpi=300)

bar, axs = plt.subplots(1, 1)
count_entries = lambda d: functools.reduce(lambda x, y: x + len(y), d, 0)
plot_horizontal_bar(axs, [count_entries(dart_values), count_entries(truth_values)], ["ReDart", "TCPtrace"], [cmap(0), cmap(1)])
bar.savefig("bar.png", dpi=300)


print(len(truth_values), len(dart_values))
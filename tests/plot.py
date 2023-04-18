import matplotlib.pyplot as plt
import numpy
import run_ground_truth
import test_dart_trackers

# f = "../data/smallFlows.pcap"
f = "../data/test.pcap"


truth = run_ground_truth.main(f)
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


max_key = ""
max_val = -1
for key in set(dart_values.keys()).intersection(set(truth_values.keys())):
    if len(dart_values[key]) > max_val:
        max_val = len(dart_values[key])
        max_key = key


mx = float(max(max(truth_values[max_key]), max(dart_values[max_key])))
bins = numpy.linspace(0, 0.25, 40)

print("truth", truth_values[max_key])
print("")
print("dart", dart_values[max_key])

plt.hist(truth_values[max_key], bins, alpha=0.5, label="Ground Truth")
plt.hist(dart_values[max_key], bins, alpha=0.5, label="ReDart")
plt.legend(loc='upper right')
plt.show()

# for key in dart_values.keys():
#     try:
#         print(key, truth_values[key], dart_values[key])
#         if len(truth_values[key]) > 10:
#             mx = float(max(max(truth_values[key]), max(dart_values[key])))
#             # print("mx = ", mx)
#             bins = numpy.linspace(0, mx, 30)
#             plt.hist(truth_values[key], bins, alpha=0.5, label="Ground Truth")
#             plt.hist(dart_values[key], bins, alpha=0.5, label="ReDart")
#             plt.legend(loc='upper right')
#             plt.show()
#     except Exception as e:
#         raise e

# COS561 Final Project: Reimplementing Continuous In-Network Round-Trip Time Monitoring with DART

**Group Members**: Haichen Dong (hd5234), Deyuan (Mike) He (dh7120), Ann Zhou (az6922) and Kaiqu Liang (kl2471)

**Keywords**: RTT Measurement, Simulation

# Dependencies

We have tested our implementation on macOS 12.6. To install Python dependencies:
```
python3 -m pip install -r requirements.txt
```

In addition to these dependencies, our simulation requires [Wireshark](https://www.wireshark.org/) in order to parse trace files.

## macOS

Install [Homebrew](https://brew.sh/) first, then:
```
brew install wireshark
```

## Linux
```
sudo apt update && sudo apt-get install wireshark
```

## Windows

Available at [Wireshark](https://www.wireshark.org/) official site.

If the installation and path configuration is properly done,
you will be able to run `tshark` through command line tools.

# Reproducing Plots

`plot.py` under `tests` directory can be used to reproduce figures in our report.

Specifically, to run simulation on a trace file, first place the `pcap` file under `data` directory, then run `plot.py` with `--dataset <name of pcap>`

For instance, to run simulation with `capture_1.pcap`, simply execute
```
$ python3 plot.py --dataset capture_1
```

By default, the capacity of Range Table and Packet Table is infinite.
`plot.py` accepts command line arguments to run customized settings.
Available options and values are:
- `--dataset <str>`: default `"test"`; name of the trace file under `data` directory to run simulation on;
- `--outgoing-only`: default `False`; if the flag is passed, all SEQ packets that are not sent by host with IP address starting with "10." will be filtered (as the tracing was done on computer connected to the Princeton network); this option helps filtering out "short legs" of RTT measurements since we are running packet tracing on the end host instead of on some intermediate switches.
- `--total-size <nat>`: default `20001`. The total capacity (number of entries can be held) in Range Table and Packet Table.
- `--packet-tracker-size <nat>`: default `10001`. The capacity of Packet Table; this number should be less than the value passed to `--total-size`; the size of Range Table will be computed accordingly.
- `--pt-policy <str>`: default `dart`; the eviction policy for the Packet Tracker. By default, it uses *Lazy Eviction* introduced in the Dart paper. In addition, as an extenstion, we provide two additional tunable eviction policies;
    - `prob`: Keep old/new entries with some probability without any recirculation (see Dart paper or our report for "recirculation").
    - `prob-recirc`: Recirculation first, then keep the recirculated entry with some probability
- `--rt-policy <str>`: default `"keep-new"`. the eviction policy of Range Table. Options are
    - `keep-new`: Always keep the new entry
    - `keep-old`: Always keep the old entry
    - `prob`: Keep the old entry with some probability (configurable through `--rt-eviction-prob <float>`)
    - `refined`: Keep the old entry if the number of in-flight packet is above some threshold, which is configurable through `--in-flight-threshold <int>`
- `--rt-evcition-prob <float>`: default `0.5`; the probability of keeping the old entry upon a Range Table hash collision. This option is effective if `--rt-policy` is set to `prob`.
- `--in-flight-threshold <int>`: default `3`. The eviction threshold of old entries in Range Table. This option is effective if `--rt-policy` is set to `refined`.

## Reproduce Figures

We provide commands we executed to generate figures in our report. Specifically:

## Reproduce Results in Extension
First, `cd tests && mkdir figures`.
Figure 9 and 11 can be reproduced by running
```
python3 plot.py --dataset capture_bili_20k
```

## Unbiased RTT Measurements

### CDF plots
```
python3 ext_bias_cdf.py --dataset smallFlows --packet-tracker-size {32,256}
```

```
python3 ext_bias_cdf.py --dataset capture_4 --outgoing-only --packet-tracker-size 16
```

### Count calculation
```
python3 ext_bias_count.py --dataset capture_4 --outgoing-only --packet-tracker-size {64,128,256,512,1024,2048}
```

### Collection error calculation
```
python3 ext_bias_error.py --dataset smallFlows --packet-tracker-size 15000
```

## Switch Memory Allocation

### Count calculation
```
python3 ext_memory_count.py --dataset smallFlows --total-size 15000
```

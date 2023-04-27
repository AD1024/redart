import redart
from redart.data.parser import parse_pcap
from redart.logger import get_logger
from redart.simulator import NaiveSimulator


def main(file: str, trace=None, cache_file: str = None, outgoing_only=False, constr=NaiveSimulator):
    logging = get_logger("RunNaiveSim")
    logging.info("Running ground truth simulator on %s", file)
    simulator = constr(outgoing_only=outgoing_only)
    if trace is None:
        trace = parse_pcap(file, cache_file)
    simulator.run_trace(trace)

    vis = set()
    for packet in trace:
        key = packet.to_src_dst_key()
        if key not in vis:
            vis.add(key)
            if key in simulator.rtt_samples:
                print(
                    f"RTTs for ({packet.src}:{packet.srcport} <-> {packet.dst}:{packet.dstport}):\n{simulator.rtt_samples[key]}\n",
                )

    return trace, simulator.rtt_samples, trace


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=str, help="The path to the PCAP file")
    parser.add_argument("cache_file", type=str,
                        help="The path to the cache file")
    args = parser.parse_args()
    redart.init(redart.config.TimestampScale.MICROSECOND)
    main(args.file, cache_file=args.cache_file)

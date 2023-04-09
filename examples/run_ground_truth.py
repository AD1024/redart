from redart.simulator import GroundTruthSimulator
from redart.data.parser import parse_pcap
from redart.logger import get_logger

logging = get_logger("RunGroundTruth", default_level="DEBUG")

def main(file: str):
    logging.info("Running ground truth simulator on %s", file)
    simulator = GroundTruthSimulator()
    trace = parse_pcap(file)
    simulator.run_trace(trace)

    vis = set()
    for packet in trace:
        key = packet.to_src_dst_key()
        if key not in vis:
            vis.add(key)
            if simulator.packet_tracker[key][1]:
                print(
                    f"RTTs for ({packet.src} <-> {packet.dst}):\n{simulator.packet_tracker[key][1]}\n",
                )
            
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=str, help="The path to the PCAP file")
    args = parser.parse_args()
    main(args.file)
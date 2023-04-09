"""PCAP file parser utilities"""
import pcapkit
from pcapkit import interface
from pcapkit.utilities.exceptions import ProtocolNotFound

import redart.logger as logger
from redart.data.packet import Packet

logging = logger.get_logger("Parser")


def parse_pcap(file: str, cache_file=None) -> list[Packet]:
    """Parse a PCAP file and return a list of packets.

    Args:
        file (str): The path to the PCAP file.
        cache_file (str, optional): The path to the cache file. Defaults to None.
                                    if not None, the parsed packets will be cached
                                    into the path provided

    Returns:
        list: A list of packets.
    """
    extractor = interface.extract(file,
                                  nofile=True,
                                  engine='default')
    # Frame structure:
    # frame: Frame
    # frame[IP]: IP-level Packets
    # frame[IP].packet: Packet data
    # frame[IP].payload: meta data of the packet
    #                    contains what we want to extract (src, srcport, dst, dstport, ack, seq)
    frames = extractor.frame
    extracted_trace = []

    for frame in frames:
        try:
            tcp_info = frame[pcapkit.TCP]
        except ProtocolNotFound:
            logging.warning('Packet %s is not a TCP packet',
                            frame.name, exc_info=True)
        try:
            packet = Packet(
                frame.payload.src,
                tcp_info.src,
                frame.payload.dst,
                tcp_info.dst,
                tcp_info.info.ack,
                tcp_info.info.seq,
                frame.info.time_epoch,
            )
            extracted_trace.append(packet)
        except KeyError:
            logging.warning('Packet %s is not an IP packet',
                            str(frame), exc_info=True)

    if cache_file is not None:
        import pickle
        with open(cache_file, 'wb') as f:
            pickle.dump(extracted_trace, f)

    return extracted_trace

"""PCAP file parser utilities"""
import os
import pickle
from functools import lru_cache

from pcapkit import interface

import redart.logger as logger
from redart.data.packet import Packet, PacketType


def build_packet_type(tcp_info):
    if int(tcp_info.len) == 0:
        assert tcp_info.flags_ack == '1'
        ptype = PacketType.ACK
    else:
        ptype = PacketType.SEQ

    if int(tcp_info.flags_syn):
        ptype |= PacketType.SYN
    if int(tcp_info.flags_fin):
        ptype |= PacketType.FIN
    return ptype


@lru_cache(typed=True)
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
    logging = logger.get_logger("Parser")
    if cache_file is not None and os.path.isfile(cache_file):
        with open(cache_file, 'rb') as fd:
            return pickle.load(fd)

    extractor = interface.extract(file,
                                  nofile=True,
                                  engine='pyshark')
    # Frame structure:
    # frame: Frame
    # frame[IP]: IP-level Packets
    # frame[IP].packet: Packet data
    # frame[IP].payload: meta data of the packet
    #                    contains what we want to extract (src, srcport, dst, dstport, ack, seq)
    frames = extractor.frame
    extracted_trace = []

    for (i, frame) in enumerate(frames):
        if not hasattr(frame, 'tcp') or not hasattr(frame, 'ip'):
            continue
        try:
            packet = Packet(
                frame.ip.src,
                int(frame.tcp.srcport),
                frame.ip.dst,
                int(frame.tcp.dstport),
                int(frame.tcp.ack),
                int(frame.tcp.seq),
                frame.sniff_time,
                int(frame.tcp.len),
                build_packet_type(frame.tcp),
                index=i
            )
            extracted_trace.append(packet)
        except KeyError:
            logging.warning('Packet %s is not an IP packet',
                            str(frame), exc_info=True)
        except AssertionError:
            continue

    if cache_file is not None:
        with open(cache_file, 'wb') as fd:
            pickle.dump(extracted_trace, fd)

    return extracted_trace

"""PCAP file parser utilities"""
from decimal import Decimal

import pcapkit
from pcapkit import interface
from pcapkit.utilities.exceptions import ProtocolNotFound

import redart.logger as logger
from redart.data.packet import Packet, PacketType

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
                Decimal(frame.sniff_timestamp),
                int(frame.tcp.len),
                PacketType.SEQ if int(frame.tcp.len) != 0
                else PacketType.ACK if int(frame.tcp.flags_ack) == 1 else PacketType.SYN,
                index=i
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

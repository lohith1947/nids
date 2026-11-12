"""
Packet capture module for the NIDS.

Uses Scapy to capture live network traffic from a specified interface and
feed individual packets to a caller-supplied callback (typically the
FlowManager.process_packet method).

On Ubuntu this captures from the host-only interface (e.g. ``enp0s8``).
On Windows in a development/test context, it can capture from the loopback
or any available interface.

Verified functionality (section 13):
  - Live packet capture from a network interface
  - Extraction of: source IP, destination IP, protocol, packet length,
    source port, destination port, TCP flags, UDP info
"""

from scapy.all import (
    sniff,
    IP,
    TCP,
    UDP,
    ICMP,
)

# Default interface — override when instantiating / calling capture().
DEFAULT_INTERFACE = None  # None lets Scapy pick the default route interface


def capture_packets(interface: str = None, callback=None, count: int = 0,
                    store: bool = False, stop_callback=None):
    """
    Start live packet capture on *interface*.

    Args:
        interface: Scapy interface name (e.g. ``"enp0s8"``).  If *None*,
            Scapy uses the default interface.
        callback: Function called for each captured packet.  Typically
            ``FlowManager.process_packet``.
        count: Number of packets to capture (0 = capture indefinitely).
        store: If True, Scapy stores packets (useful for analysis).
        stop_callback: Optional callable returning bool.  When it returns
            True, ``sniff()`` stops cleanly without relying on
            KeyboardInterrupt.  This enables programmatic shutdown from
            another thread.

    This function blocks until *count* packets are captured, until
    *stop_callback* returns True, or until the user interrupts with Ctrl-C.
    """
    sniff(
        iface=interface or DEFAULT_INTERFACE,
        prn=callback,
        count=count,
        store=store,
        stop_filter=stop_callback,
    )


def parse_packet_info(packet):
    """
    Extract basic information from a Scapy packet.

    Returns a dict with keys:
        src_ip, dst_ip, protocol, packet_len, src_port, dst_port,
        tcp_flags, has_tcp, has_udp, has_icmp

    Returns None if the packet has no network layer.
    """
    if IP not in packet:
        return None

    pkt_len = len(packet)

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = packet[IP].proto

    info = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "packet_len": pkt_len,
        "src_port": 0,
        "dst_port": 0,
        "tcp_flags": 0,
        "has_tcp": TCP in packet,
        "has_udp": UDP in packet,
        "has_icmp": ICMP in packet,
    }

    if TCP in packet:
        info["src_port"] = int(packet[TCP].sport)
        info["dst_port"] = int(packet[TCP].dport)
        info["tcp_flags"] = int(packet[TCP].flags)
    elif UDP in packet:
        info["src_port"] = int(packet[UDP].sport)
        info["dst_port"] = int(packet[UDP].dport)

    return info

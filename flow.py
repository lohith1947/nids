"""
Flow dataclass for the NIDS flow-based detection system.

Implements the flow model described in sections 14-19 of the project design
document:
  - 5-tuple identification (src_ip, dst_ip, src_port, dst_port, protocol)
  - Bidirectional flow handling (forward / backward packet accounting)
  - Timing statistics (start_time, last_time, duration)
  - Packet / byte statistics (count, sizes, std)
  - Traffic rates (packets_per_second, bytes_per_second)
  - TCP flag counts (SYN, ACK, FIN, RST, PSH)

The ``get_features()`` and ``get_feature_dict()`` methods provide the numeric
feature vector at a stable, documented order (see ``features.NUMERIC_FEATURE_NAMES``)
so that the rule engine and future ML model share a compatible schema.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List

from .features import (
    TCP_ACK,
    TCP_FIN,
    TCP_PSH,
    TCP_RST,
    TCP_SYN,
    NUMERIC_FEATURE_NAMES,
)


@dataclass
class Flow:
    """
    Represents a bidirectional network flow.

    A flow is identified by the standard 5-tuple:
    (src_ip, dst_ip, src_port, dst_port, protocol)

    Bidirectional: packets matching either direction are aggregated into
    the same Flow object.  The direction of the *first* packet seen for a
    flow establishes the "forward" direction; subsequent packets are
    classified as forward or backward relative to that direction.
    """

    # ---- Identity (5-tuple) ----
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # IANA protocol number (6=TCP, 17=UDP, 1=ICMP)

    # ---- Timing ----
    start_time: float = 0.0      # timestamp of first packet
    last_time: float = 0.0       # timestamp of most recent packet

    # ---- Packet / byte statistics ----
    packet_count: int = 0
    byte_count: int = 0
    _packet_sizes: List[int] = field(default_factory=list)

    # ---- Directional statistics ----
    forward_packets: int = 0
    backward_packets: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0

    # ---- TCP flag counts ----
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0

    # ------------------------------------------------------------------
    # Computed properties
    # ------------------------------------------------------------------

    @property
    def duration(self) -> float:
        """Flow duration in seconds (last_time - start_time)."""
        if self.start_time == 0.0 or self.last_time == 0.0:
            return 0.0
        return self.last_time - self.start_time

    @property
    def average_packet_size(self) -> float:
        """Mean packet size in bytes."""
        if self.packet_count == 0:
            return 0.0
        return self.byte_count / self.packet_count

    @property
    def minimum_packet_size(self) -> int:
        """Smallest packet size observed in this flow."""
        if not self._packet_sizes:
            return 0
        return min(self._packet_sizes)

    @property
    def maximum_packet_size(self) -> int:
        """Largest packet size observed in this flow."""
        if not self._packet_sizes:
            return 0
        return max(self._packet_sizes)

    @property
    def packet_size_std(self) -> float:
        """Standard deviation of packet sizes (population std)."""
        n = len(self._packet_sizes)
        if n < 2:
            return 0.0
        mean = sum(self._packet_sizes) / n
        variance = sum((x - mean) ** 2 for x in self._packet_sizes) / n
        return math.sqrt(variance)

    @property
    def packets_per_second(self) -> float:
        """Packet rate (packets / duration)."""
        dur = self.duration
        if dur <= 0:
            return float(self.packet_count)
        return self.packet_count / dur

    @property
    def bytes_per_second(self) -> float:
        """Byte rate (bytes / duration)."""
        dur = self.duration
        if dur <= 0:
            return float(self.byte_count)
        return self.byte_count / dur

    # ------------------------------------------------------------------
    # Packet ingestion
    # ------------------------------------------------------------------

    def add_packet(
        self,
        timestamp: float,
        packet_size: int,
        direction: str,
        tcp_flags: int = 0,
    ) -> None:
        """
        Record a single packet into this flow.

        Args:
            timestamp: Packet capture timestamp (Unix epoch float).
            packet_size: Total length of the packet in bytes.
            direction: ``'forward'`` or ``'backward'``.
            tcp_flags: Raw TCP flags byte (only meaningful for TCP flows).
        """
        if self.start_time == 0.0:
            self.start_time = timestamp
        self.last_time = timestamp

        self.packet_count += 1
        self.byte_count += packet_size
        self._packet_sizes.append(packet_size)

        if direction == "forward":
            self.forward_packets += 1
            self.forward_bytes += packet_size
        else:
            self.backward_packets += 1
            self.backward_bytes += packet_size

        # Extract TCP flags via bit masks (see features.py section 17)
        if tcp_flags:
            if tcp_flags & TCP_SYN:
                self.syn_count += 1
            if tcp_flags & TCP_ACK:
                self.ack_count += 1
            if tcp_flags & TCP_FIN:
                self.fin_count += 1
            if tcp_flags & TCP_RST:
                self.rst_count += 1
            if tcp_flags & TCP_PSH:
                self.psh_count += 1

    # ------------------------------------------------------------------
    # Feature access
    # ------------------------------------------------------------------

    def get_features(self) -> List[float]:
        """
        Return numeric features as a list in the canonical order defined by
        ``features.NUMRIC_FEATURES_NAMES``.
        """
        return [
            self.duration,
            self.packet_count,
            self.byte_count,
            self.average_packet_size,
            self.minimum_packet_size,
            self.maximum_packet_size,
            self.packet_size_std,
            self.packets_per_second,
            self.bytes_per_second,
            self.forward_packets,
            self.backward_packets,
            self.forward_bytes,
            self.backward_bytes,
            self.syn_count,
            self.ack_count,
            self.fin_count,
            self.rst_count,
            self.psh_count,
        ]

    def get_feature_dict(self) -> dict:
        """
        Return numeric features as a dictionary keyed by feature name.
        Useful for rule-based logic that references features by name.
        """
        return dict(zip(NUMERIC_FEATURE_NAMES, self.get_features()))

    def __repr__(self) -> str:
        return (
            f"Flow(src={self.src_ip}:{self.src_port} -> "
            f"dst={self.dst_ip}:{self.dst_port}, proto={self.protocol}, "
            f"pkts={self.packet_count}, bytes={self.byte_count}, "
            f"dur={self.duration:.4f}, pps={self.packets_per_second:.2f})"
        )

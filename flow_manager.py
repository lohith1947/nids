"""
Flow manager for the NIDS.

Implements the flow-based packet processing pipeline described in sections
14-20 of the project design document:

  1. Packet capture (receives packets from packet_capture module)
  2. Packet parsing (extracts 5-tuple via parse_packet_info)
  3. Flow identification (canonical 5-tuple key)
  4. Bidirectional flow creation (both directions map to the same Flow)
  5. Flow updates (packet/byte counting, TCP flag extraction)
  6. Direction detection (forward / backward relative to first-seen direction)
  7. Packet/byte counting (with directional split)
  8. TCP flag extraction (SYN, ACK, FIN, RST, PSH via bit masks)
  9. Feature calculation (delegated to Flow properties)
  10. Flow closing (timeout-based; returns completed flows)

Known limitation (section 20):
    Timeout checking is triggered only when new packets are processed.
    If traffic completely stops, flows that should have timed out are not
    closed until the next packet arrives.  A future improvement will add
    background timer / periodic timeout checking.
"""

from __future__ import annotations

import heapq
import time
from collections import defaultdict
from typing import List, Optional

from .features import TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, PROTOCOL_TCP
from .flow import Flow
from .packet_capture import parse_packet_info

# ---------------------------------------------------------------------------
# Flow timeout configuration
# ---------------------------------------------------------------------------
FLOW_TIMEOUT = 10  # seconds — from section 20 of the design document


class FlowManager:
    """
    Manages the creation, update, and expiration of bidirectional network flows.

    Flows are keyed by a canonical representation of the 5-tuple so that
    both directions of the same communication map to a single Flow object.
    """

    def __init__(self, flow_timeout: float = FLOW_TIMEOUT):
        self.flow_timeout = flow_timeout
        # canonical_key -> Flow
        self._flows: dict = {}
        # Track flow creation time for timeout expiry using a heap.
        self._expiry_heap: list = []

    # ------------------------------------------------------------------
    # Flow key management
    # ------------------------------------------------------------------

    @staticmethod
    def _canonical_key(src_ip: str, src_port: int,
                       dst_ip: str, dst_port: int,
                       protocol: int) -> tuple:
        """
        Create a canonical flow key that is the same regardless of which
        direction a packet arrives in.

        The two endpoints are sorted so that packets from either direction
        of the same 5-tuple produce the same key.
        """
        ep_a = (src_ip, src_port)
        ep_b = (dst_ip, dst_port)
        if ep_a <= ep_b:
            return (ep_a, ep_b, protocol)
        else:
            return (ep_b, ep_a, protocol)

    @staticmethod
    def _flow_key_for_lookup(src_ip: str, src_port: int,
                             dst_ip: str, dst_port: int,
                             protocol: int) -> tuple:
        """
        Look up a flow by canonical key.
        Delegates to _canonical_key.
        """
        return FlowManager._canonical_key(
            src_ip, src_port, dst_ip, dst_port, protocol
        )

    # ------------------------------------------------------------------
    # Direction detection
    # ------------------------------------------------------------------

    def _determine_direction(self, flow: Flow, src_ip: str,
                             src_port: int) -> str:
        """
        Determine whether a packet is 'forward' or 'backward' relative to
        the flow's original direction (first packet seen).

        Forward = packet matches the flow's stored src_ip:src_port.
        Backward = packet comes from the opposite direction.
        """
        if src_ip == flow.src_ip and src_port == flow.src_port:
            return "forward"
        return "backward"

    # ------------------------------------------------------------------
    # Main packet processing
    # ------------------------------------------------------------------

    def process_packet(self, packet) -> List[Flow]:
        """
        Process a single Scapy packet.

        Steps:
            1. Parse the packet (5-tuple, flags, size).
            2. Look up or create a bidirectional Flow.
            3. Determine forward / backward direction.
            4. Add the packet to the flow (updates all statistics).
            5. Check for timed-out flows and return any completed ones.

        Returns:
            List of completed (expired) Flow objects.  May be empty.
        """
        info = parse_packet_info(packet)
        if info is None:
            return []

        src_ip = info["src_ip"]
        dst_ip = info["dst_ip"]
        src_port = info["src_port"]
        dst_port = info["dst_port"]
        protocol = info["protocol"]
        packet_size = info["packet_len"]
        tcp_flags = info["tcp_flags"] if info["has_tcp"] else 0

        timestamp = float(packet.time) if hasattr(packet, "time") else time.time()

        # --- Flow lookup / creation ---
        key = self._canonical_key(src_ip, src_port, dst_ip, dst_port, protocol)

        if key in self._flows:
            flow = self._flows[key]
        else:
            flow = Flow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
            )
            self._flows[key] = flow

        # --- Direction detection ---
        direction = self._determine_direction(flow, src_ip, src_port)

        # --- Packet ingestion ---
        flow.add_packet(timestamp, packet_size, direction, tcp_flags)

        # --- Refresh inactivity expiry on every packet ---
        # Push a fresh (timestamp + flow_timeout, key) entry so that
        # _check_timeouts closes the flow only when it has been inactive
        # for flow_timeout seconds (last-activity based), not when the
        # flow's first packet is older than flow_timeout.
        expiry_time = timestamp + self.flow_timeout
        heapq.heappush(self._expiry_heap, (expiry_time, key))

        # --- Timeout check ---
        completed = self._check_timeouts(timestamp)

        return completed

    # ------------------------------------------------------------------
    # Flow timeout / expiration
    # ------------------------------------------------------------------

    def _check_timeouts(self, current_time: float) -> List[Flow]:
        """
        Close and return any flows that have been inactive longer than
        ``self.flow_timeout``.

        Inactivity-based: a flow is closed only when
        ``current_time - flow.last_time >= self.flow_timeout``, i.e. no
        packet has been seen for ``flow_timeout`` seconds.  Each call to
        ``process_packet`` / ``process_packet_info`` pushes a fresh heap
        entry, so older entries become stale and are lazily skipped here.

        Known limitation: this only runs when a new packet arrives.
        Completely silent traffic will not trigger expiry until the next
        packet is processed.  A background expiry thread would close that
        gap (see audit finding 4.1).
        """
        completed: List[Flow] = []

        while self._expiry_heap:
            expiry_time, key = self._expiry_heap[0]
            if expiry_time > current_time:
                break

            heapq.heappop(self._expiry_heap)

            if key not in self._flows:
                # Stale entry: flow was already closed by a newer heap entry.
                continue

            flow = self._flows[key]
            # Lazy deletion: if the flow has been active since this heap
            # entry was pushed, this entry is stale — skip it.  The newer
            # entry (pushed at the last packet) will expire later.
            if current_time - flow.last_time < self.flow_timeout:
                continue

            # Genuine inactivity timeout: close and return the flow.
            flow = self._flows.pop(key)
            completed.append(flow)

        return completed

    def close_flow(self, key: tuple) -> Optional[Flow]:
        """Explicitly close a flow by its canonical key."""
        return self._flows.pop(key, None)

    def get_active_flow_count(self) -> int:
        return len(self._flows)

    def get_all_flows(self) -> List[Flow]:
        """Return all currently active (unclosed) flows."""
        return list(self._flows.values())

    def reset(self):
        """Clear all active flows and state."""
        self._flows.clear()
        self._expiry_heap.clear()

    # ------------------------------------------------------------------
    # Convenience: batch process from a list of parsed packets
    # ------------------------------------------------------------------

    def process_packet_info(self, info: dict, timestamp: float) -> List[Flow]:
        """
        Process a pre-parsed packet dict (as produced by parse_packet_info).

        This is primarily for testing without a real Scapy capture.
        """
        if info is None:
            return []

        src_ip = info["src_ip"]
        dst_ip = info["dst_ip"]
        src_port = info["src_port"]
        dst_port = info["dst_port"]
        protocol = info["protocol"]
        packet_size = info["packet_len"]

        # Extract individual TCP flags
        tcp_flags_raw = info.get("tcp_flags", 0)
        # Scapy TCP flags is a FlagsValue; convert to int for bit-masking
        flags_int = int(tcp_flags_raw) if tcp_flags_raw else 0

        key = self._canonical_key(src_ip, src_port, dst_ip, dst_port, protocol)

        if key in self._flows:
            flow = self._flows[key]
        else:
            flow = Flow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
            )
            self._flows[key] = flow

        direction = self._determine_direction(flow, src_ip, src_port)
        flow.add_packet(timestamp, packet_size, direction, flags_int)

        # --- Refresh inactivity expiry on every packet ---
        expiry_time = timestamp + self.flow_timeout
        heapq.heappush(self._expiry_heap, (expiry_time, key))

        return self._check_timeouts(timestamp)

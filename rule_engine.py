"""
Rule Engine for the NIDS.

Analyzes completed flows and produces rule-based attack predictions using
two detection mechanisms:

  1. **Per-flow rules** — evaluated on a single flow's features.
     Applicable to: DOS (high packet/byte rate, SYN-flood pattern).

  2. **Cross-flow stateful rules** — aggregate information across multiple
     flows from the same source IP (or source -> destination pair).
     Applicable to: PORT_SCAN (many unique dst ports),
                    BRUTE_FORCE (repeated connections to same service),
                    RECONNAISSANCE (many unique dst IPs).

All thresholds are configurable via ``RuleConfig`` (see ``config.py``).
Some are initial values and others have been calibrated against lab traffic;
their rationale and known limitations are documented beside each setting.

The Rule Engine is designed to be called by the main NIDS pipeline whenever
the FlowManager closes a flow:

    flow_manager = FlowManager()
    rule_engine  = RuleEngine()

    for packet in capture_packets(...):
        for flow in flow_manager.process_packet(packet):
            result = rule_engine.process_flow(flow)
            # ... feed result to correlation / alerts (future stages)
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Optional

from .flow import Flow
from .config import RuleConfig
from .features import PROTOCOL_TCP

# ---------------------------------------------------------------------------
# Loopback address prefixes (RFC 3330)
# ---------------------------------------------------------------------------
_LOOPBACK_PREFIXES = ("127.",)

def _is_loopback(ip: str) -> bool:
    """Return True if the IP address is a loopback address (127.0.0.0/8)."""
    return ip.startswith(_LOOPBACK_PREFIXES)

# ---------------------------------------------------------------------------
# Attack class constants — exactly the 5 classes from the project design
# ---------------------------------------------------------------------------

BENIGN = "BENIGN"
PORT_SCAN = "PORT_SCAN"
BRUTE_FORCE = "BRUTE_FORCE"
DOS = "DOS"
RECONNAISSANCE = "RECONNAISSANCE"

ALL_ATTACK_CLASSES = [BENIGN, PORT_SCAN, BRUTE_FORCE, DOS, RECONNAISSANCE]


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class RuleResult:
    """
    Detection result produced by the Rule Engine for a single flow.

    Fields (matching the structure requested in the project design, Step 5):

        rule_prediction   — The predicted attack class (one of ALL_ATTACK_CLASSES).
        rule_confidence   — Confidence in the prediction, 0.0 – 1.0.
        triggered_rules   — List of internal rule names that fired.
        rule_reason       — Human-readable explanation of the prediction.
    """
    rule_prediction: str
    rule_confidence: float
    triggered_rules: List[str] = field(default_factory=list)
    rule_reason: str = ""


@dataclass
class _RuleMatch:
    """Internal: a single rule match with its confidence."""
    attack_type: str
    confidence: float
    triggered_rules: List[str]
    reason: str


class RuleEngine:
    """
    Rule-based detection engine for the NIDS.

    Maintains lightweight cross-flow state to detect attack patterns that
    span multiple flows (port scans, brute-force campaigns, reconnaissance).
    """

    def __init__(self, config: RuleConfig = None):
        self.config: RuleConfig = config or RuleConfig()
        self._reset_state()

    # ------------------------------------------------------------------
    # State management
    # ------------------------------------------------------------------

    def _reset_state(self):
        """Clear all cross-flow tracking state."""
        # src_ip -> {dst_port: [timestamps]}
        # For PORT_SCAN: how many distinct dst ports a source has contacted
        self._port_activity: defaultdict = defaultdict(
            lambda: defaultdict(list)
        )

        # src_ip -> {dst_ip: [timestamps]}
        # For RECONNAISSANCE: how many distinct dst hosts a source has contacted
        self._host_activity: defaultdict = defaultdict(
            lambda: defaultdict(list)
        )

        # (src_ip, dst_ip, dst_port) -> [timestamps]
        # For BRUTE_FORCE: repeated connections to the same service
        self._auth_attempts: defaultdict = defaultdict(list)

        # src_ip -> [timestamps of SYN packets]
        # For cross-flow DOS: aggregate SYN packets across multiple flows
        # from the same source to detect SYN flood campaigns.
        self._syn_activity: defaultdict = defaultdict(list)

    def reset(self):
        """Public reset — call between independent test runs."""
        self._reset_state()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_flow(self, flow: Flow) -> RuleResult:
        """
        Process a completed Flow and return a rule-based detection result.

        Pipeline:
            1. Update cross-flow state with this flow's identity.
            2. Prune expired state entries (older than configured windows).
            3. Evaluate per-flow rules (DOS).
            4. Evaluate cross-flow rules (PORT_SCAN, BRUTE_FORCE, RECONNAISSANCE).
            5. If multiple rules match, return the one with highest confidence.
               If none match, return BENIGN.
        """
        ref_time = flow.last_time

        # 1. Update state
        self._update_state(flow, ref_time)

        # 2. Prune old entries
        self._prune_state(ref_time)

        # 3-4. Evaluate rules
        matches: List[_RuleMatch] = []

        for checker in (
            self._check_dos,
            self._check_dos_cross_flow,
            self._check_port_scan,
            self._check_brute_force,
            self._check_reconnaissance,
        ):
            m = checker(flow, ref_time)
            if m is not None:
                matches.append(m)

        # 5. Pick best match
        if not matches:
            return RuleResult(
                rule_prediction=BENIGN,
                rule_confidence=0.0,
                triggered_rules=[],
                rule_reason="No malicious patterns detected.",
            )

        best = max(matches, key=lambda m: m.confidence)
        return RuleResult(
            rule_prediction=best.attack_type,
            rule_confidence=round(best.confidence, 2),
            triggered_rules=best.triggered_rules,
            rule_reason=best.reason,
        )

    # ------------------------------------------------------------------
    # State update & pruning
    # ------------------------------------------------------------------

    def _update_state(self, flow: Flow, ref_time: float):
        """Add this flow's identity to cross-flow tracking state."""
        src_ip = flow.src_ip
        dst_ip = flow.dst_ip
        dst_port = flow.dst_port

        # Port activity (for port scan)
        self._port_activity[src_ip][dst_port].append(ref_time)

        # Host activity (for reconnaissance)
        self._host_activity[src_ip][dst_ip].append(ref_time)

        # Auth attempts (for brute force)
        # Do not count a refused SYN probe as a login attempt. A completed
        # handshake has both SYN and SYN-ACK and remains eligible.
        refused_probe = (
            self.config.BRUTE_FORCE_RST_IS_REFUSAL
            and flow.rst_count > 0
            and flow.syn_count < 2
        )
        if not refused_probe:
            self._auth_attempts[(src_ip, dst_ip, dst_port)].append(ref_time)

        # SYN activity (for cross-flow DOS detection)
        # Each SYN packet in a flow is recorded as a separate timestamp
        # so we can compute SYN rate across flows.
        for _ in range(flow.syn_count):
            self._syn_activity[src_ip].append(ref_time)

    def _prune_state(self, ref_time: float):
        """Remove timestamps older than the longest configured time window."""
        max_window = max(
            self.config.PORT_SCAN_TIME_WINDOW,
            self.config.BRUTE_FORCE_TIME_WINDOW,
            self.config.RECON_TIME_WINDOW,
            self.config.DOS_CROSS_FLOW_WINDOW,
        )
        cutoff = ref_time - max_window

        # --- Prune port activity ---
        for src_ip in list(self._port_activity.keys()):
            src_ports = self._port_activity[src_ip]
            for port in list(src_ports.keys()):
                src_ports[port] = [t for t in src_ports[port] if t >= cutoff]
                if not src_ports[port]:
                    del src_ports[port]
            if not src_ports:
                del self._port_activity[src_ip]

        # --- Prune host activity ---
        for src_ip in list(self._host_activity.keys()):
            src_hosts = self._host_activity[src_ip]
            for host in list(src_hosts.keys()):
                src_hosts[host] = [t for t in src_hosts[host] if t >= cutoff]
                if not src_hosts[host]:
                    del src_hosts[host]
            if not src_hosts:
                del self._host_activity[src_ip]

        # --- Prune auth attempts ---
        for key in list(self._auth_attempts.keys()):
            self._auth_attempts[key] = [
                t for t in self._auth_attempts[key] if t >= cutoff
            ]
            if not self._auth_attempts[key]:
                del self._auth_attempts[key]

        # --- Prune SYN activity to its dedicated short rate window ---
        syn_cutoff = ref_time - self.config.DOS_CROSS_FLOW_WINDOW
        for src_ip in list(self._syn_activity.keys()):
            self._syn_activity[src_ip] = [
                t for t in self._syn_activity[src_ip] if t >= syn_cutoff
            ]
            if not self._syn_activity[src_ip]:
                del self._syn_activity[src_ip]

    # ------------------------------------------------------------------
    # Rule: DOS  (per-flow)
    # ------------------------------------------------------------------

    def _check_dos(self, flow: Flow, ref_time: float) -> Optional[_RuleMatch]:
        """
        Detect DoS patterns from a single flow's features.

        Indicators:
          - **high_packet_rate** — packets_per_second exceeds threshold and
            the flow has enough packets and duration to be meaningful.
          - **high_byte_rate** — bytes_per_second exceeds threshold for a
            flow long enough to produce a reliable rate estimate.
          - **syn_flood_pattern** — SYN packets dominate the flow (high
            SYN-to-total ratio with an absolute minimum SYN count).

        Each indicator is independent; more indicators increase confidence.
        """
        cfg = self.config
        triggered: List[str] = []
        confidence = 0.6  # base when any DoS rule fires

        # Condition 1: high packet rate
        # Timestamp subtraction can undershoot an exact threshold slightly
        # (e.g. 1000.001 - 1000.0); tolerate float representation noise only.
        #
        # The rate sub-rules also require a meaningful packet volume.  A short
        # flow — a connect-scan handshake to an open port is SYN, SYN-ACK, ACK
        # (and RST) over about a millisecond — divides its few packets by that
        # tiny duration and looks like thousands of packets per second.  That
        # is an artefact of the short observation window, not a flood, so
        # DOS_MIN_RATE_PACKETS keeps such exchanges out of the rate rules.
        # Real floods carry far more packets per flow, and short SYN floods
        # made of many 1-2 packet flows are still caught by the cross-flow
        # check in _check_dos_cross_flow().
        rate_is_reliable = (
            flow.duration + 1e-9 >= cfg.DOS_MIN_RATE_DURATION
            and flow.packet_count >= cfg.DOS_MIN_RATE_PACKETS
        )
        if (rate_is_reliable
                and flow.packets_per_second > cfg.DOS_PACKETS_PER_SECOND
                and flow.packet_count >= cfg.DOS_MIN_PACKET_COUNT):
            triggered.append("high_packet_rate")
            confidence += 0.1

        # Condition 2: high byte rate
        # Guarded by DOS_MIN_RATE_PACKETS / DOS_MIN_BYTE_RATE_PACKETS to
        # prevent short flows from producing astronomical byte rates.  A flow
        # with only a handful of packets and a millisecond-scale duration is
        # not a meaningful DoS signal.
        if (rate_is_reliable
                and flow.bytes_per_second > cfg.DOS_BYTES_PER_SECOND
                and flow.byte_count > 0
                and flow.packet_count >= cfg.DOS_MIN_BYTE_RATE_PACKETS):
            triggered.append("high_byte_rate")
            confidence += 0.1

        # Condition 3: SYN-flood pattern
        if flow.packet_count > 0:
            syn_ratio = flow.syn_count / flow.packet_count
            if (syn_ratio > cfg.DOS_SYN_RATIO
                    and flow.syn_count >= cfg.DOS_MIN_SYN_COUNT):
                triggered.append("syn_flood_pattern")
                confidence += 0.15

        if not triggered:
            return None

        confidence = min(confidence, 0.95)

        ratio = flow.syn_count / max(flow.packet_count, 1)
        reason = (
            f"DOS indicators: {', '.join(triggered)}. "
            f"pps={flow.packets_per_second:.1f}, "
            f"bps={flow.bytes_per_second:.1f}, "
            f"syn_ratio={ratio:.2f} "
            f"({flow.syn_count}/{flow.packet_count})."
        )
        return _RuleMatch(
            attack_type=DOS,
            confidence=confidence,
            triggered_rules=triggered,
            reason=reason,
        )

    def _check_dos_cross_flow(self, flow: Flow, ref_time: float) -> Optional[_RuleMatch]:
        """
        Detect DoS SYN-flood patterns across multiple flows from the same source.

        hping3 SYN flood sends individual SYN packets as separate flows, each
        with just 1-2 packets.  The per-flow DOS check misses these because
        no single flow has enough packets.  This cross-flow check aggregates
        SYN packets across all flows from the same source IP within the time
        window and flags a flood when the SYN rate exceeds the threshold.
        """
        cfg = self.config
        src_ip = flow.src_ip

        # Use a fixed rolling window and its full duration. Dividing by the
        # time between first and last SYN overstates short scan bursts.
        window = cfg.DOS_CROSS_FLOW_WINDOW
        if window <= 0:
            return None
        window_start = ref_time - window
        syn_timestamps = [
            timestamp
            for timestamp in self._syn_activity.get(src_ip, [])
            if timestamp >= window_start
        ]
        syn_count = len(syn_timestamps)

        if syn_count < cfg.DOS_MIN_SYN_COUNT:
            return None

        # Include the full configured window, even while the detector warms up.
        syn_rate = syn_count / window

        if syn_rate < cfg.DOS_PACKETS_PER_SECOND:
            return None

        triggered = ["syn_flood_cross_flow"]
        excess = syn_rate - cfg.DOS_PACKETS_PER_SECOND
        confidence = min(0.6 + 0.05 * excess / cfg.DOS_PACKETS_PER_SECOND, 0.9)

        reason = (
            f"Cross-flow DOS SYN flood: {syn_count} SYN packets from {src_ip} "
            f"in window, rate={syn_rate:.1f} pps "
            f"(threshold: {cfg.DOS_PACKETS_PER_SECOND} pps)."
        )
        return _RuleMatch(
            attack_type=DOS,
            confidence=confidence,
            triggered_rules=triggered,
            reason=reason,
        )

    # ------------------------------------------------------------------
    # Rule: PORT_SCAN  (cross-flow + per-flow)
    # ------------------------------------------------------------------

    def _check_port_scan(self, flow: Flow, ref_time: float) -> Optional[_RuleMatch]:
        """
        Detect port scan activity.

        Port scanning spans multiple flows, so **cross-flow state** is the
        primary detector.  Each completed flow from the same source IP
        contributes one probed destination port to the aggregate.

        Per-flow check (lower confidence): a single SYN-only probe with
        very few packets — could be the first packet of a scan campaign.

        Limitations:
          - Tracks unique dst_ports per source IP (not per destination host).
            A source legitimately accessing >10 distinct service ports
            across different hosts could trigger a false positive.  The
            threshold (PORT_SCAN_MIN_UNIQUE_PORTS) mitigates this.
          - Does NOT track inter-flow timing gaps in detail; only a sliding
            time window is used.

        Loopback guard:
          On loopback (127.0.0.0/8) traffic, many unrelated local processes
          originate from the same source IP (127.0.0.1).  This causes the
          cross-flow port-scan check to pool unrelated local connections into
          a single scan campaign — a significant source of false positives
          on development machines.  The cross-flow check is therefore
          skipped for loopback source IPs; the per-flow SYN-only-probe check
          still fires for genuinely suspicious probes.
        """
        cfg = self.config
        triggered: List[str] = []
        confidence = 0.0
        src_ip = flow.src_ip

        # --- Cross-flow: unique dst ports from this source ---
        # Skip for loopback sources to avoid false positives from unrelated
        # local OS activity (see Limitations / Loopback guard above).
        if not _is_loopback(src_ip):
            unique_ports = len(self._port_activity.get(src_ip, {}))

            if unique_ports >= cfg.PORT_SCAN_MIN_UNIQUE_PORTS:
                triggered.append("cross_flow_port_scan")
                excess = unique_ports - cfg.PORT_SCAN_MIN_UNIQUE_PORTS
                confidence = min(0.5 + 0.05 * excess, 0.85)

        # --- Per-flow: SYN-only probe ---
        is_syn_only = flow.syn_count > 0 and flow.ack_count == 0
        few_packets = flow.packet_count <= cfg.PORT_SCAN_MAX_PACKETS

        if is_syn_only and few_packets:
            triggered.append("syn_only_probe")
            if confidence == 0.0:
                # Only single-flow evidence
                confidence = 0.4
            else:
                confidence += 0.1

        if not triggered:
            return None

        confidence = min(confidence, 0.95)

        reason = f"PORT_SCAN indicators: {', '.join(triggered)}. "
        if "cross_flow_port_scan" in triggered:
            reason += (
                f"Unique dst ports from {src_ip} in window: {unique_ports} "
                f"(threshold: {cfg.PORT_SCAN_MIN_UNIQUE_PORTS}). "
            )
        if "syn_only_probe" in triggered:
            reason += (
                f"SYN-only probe: syn={flow.syn_count}, ack={flow.ack_count}, "
                f"pkts={flow.packet_count}."
            )
        return _RuleMatch(
            attack_type=PORT_SCAN,
            confidence=confidence,
            triggered_rules=triggered,
            reason=reason,
        )

    # ------------------------------------------------------------------
    # Rule: BRUTE_FORCE  (cross-flow + per-flow)
    # ------------------------------------------------------------------

    def _check_brute_force(self, flow: Flow, ref_time: float) -> Optional[_RuleMatch]:
        """
        Detect brute-force attack patterns.

        Brute force involves repeated connection attempts to the same service
        (same src_ip, dst_ip, dst_port).  This is inherently cross-flow.

        Per-flow check (lower confidence): a short-lived flow on a known
        service port with few packets — could be a single failed
        authentication attempt.

        Limitations:
          - Requires the destination port to be in BRUTE_FORCE_PORTS for
            the cross-flow check to fire.  Services not in this list will
            not be detected as brute force even with many attempts.
          - Does not inspect application-layer authentication data; relies
            purely on connection frequency and port heuristics.
          - Flows containing a TCP RST are excluded from the per-flow check:
            SYN answered by RST+ACK is a refused connection (a scan probe
            against a closed port), not an authentication attempt.
        """
        cfg = self.config
        triggered: List[str] = []
        confidence = 0.0
        src_ip = flow.src_ip
        dst_ip = flow.dst_ip
        dst_port = flow.dst_port

        on_common_port = dst_port in cfg.BRUTE_FORCE_PORTS

        # --- Cross-flow: repeated connections to same service ---
        attempts = len(self._auth_attempts.get((src_ip, dst_ip, dst_port), []))

        if attempts >= cfg.BRUTE_FORCE_MIN_ATTEMPTS and on_common_port:
            triggered.append("repeated_connections")
            excess = attempts - cfg.BRUTE_FORCE_MIN_ATTEMPTS
            confidence = min(0.5 + 0.05 * excess, 0.85)

        # --- Per-flow: failed authentication attempt ---
        # A single failed auth is a short flow on a service port with no
        # data transfer.  We require NO PSH flags (no application data)
        # so that legitimate sessions that transfer data are not flagged.
        no_data = flow.psh_count == 0
        short_duration = flow.duration <= cfg.BRUTE_FORCE_MAX_DURATION
        few_packets = flow.packet_count <= cfg.BRUTE_FORCE_MAX_PACKETS_PER_FLOW

        # A flow carrying a RST was refused or aborted, not authenticated
        # against.  A SYN answered by RST+ACK is a closed port rejecting the
        # probe (a scan artefact), so it must not count as an auth attempt.
        connection_reset = (cfg.BRUTE_FORCE_RST_IS_REFUSAL
                            and flow.rst_count > 0)

        if (on_common_port and few_packets and short_duration
                and not connection_reset):
            if cfg.BRUTE_FORCE_NO_PSH_REQUIRED:
                if not no_data:
                    pass  # data transferred → not a failed auth
                else:
                    triggered.append("short_auth_attempt")
                    if confidence == 0.0:
                        confidence = 0.30
                    else:
                        confidence += 0.1
            else:
                triggered.append("short_auth_attempt")
                if confidence == 0.0:
                    confidence = 0.30
                else:
                    confidence += 0.1

        if not triggered:
            return None

        confidence = min(confidence, 0.95)

        reason = f"BRUTE_FORCE indicators: {', '.join(triggered)}. "
        if "repeated_connections" in triggered:
            reason += (
                f"Connections to {src_ip} -> {dst_ip}:{dst_port} "
                f"in window: {attempts} "
                f"(threshold: {cfg.BRUTE_FORCE_MIN_ATTEMPTS}). "
            )
        if "short_auth_attempt" in triggered:
            reason += (
                f"Short flow on port {dst_port}: pkts={flow.packet_count}, "
                f"dur={flow.duration:.4f}s."
            )
        return _RuleMatch(
            attack_type=BRUTE_FORCE,
            confidence=confidence,
            triggered_rules=triggered,
            reason=reason,
        )

    # ------------------------------------------------------------------
    # Rule: RECONNAISSANCE  (cross-flow)
    # ------------------------------------------------------------------

    def _check_reconnaissance(self, flow: Flow, ref_time: float) -> Optional[_RuleMatch]:
        """
        Detect reconnaissance activity.

        Reconnaissance involves a source contacting many different hosts
        and/or services.  This is inherently cross-flow and requires
        tracking unique destination IPs per source.

        Indicators:
          - **multi_host_scan** — source contacted >= threshold unique
            destination IPs within the time window.
          - **multi_port_scan** — source contacted >= threshold unique
            destination ports across all targets within the time window.

        Limitations:
          - Legitimate network scanning tools or monitoring systems
            contacting many hosts could trigger false positives.  The
            threshold (RECON_MIN_UNIQUE_IPS) mitigates this.
          - Does not distinguish between active scanning and passive
            service discovery; relies purely on connection diversity.
          - The multi_port_scan indicator is skipped for loopback source
            IPs, because on loopback all local OS service connections
            appear to originate from 127.0.0.1, making the unique-port
            count unreliable (same root cause as the cross_flow_port_scan
            guard in _check_port_scan).
        """
        cfg = self.config
        triggered: List[str] = []
        confidence = 0.0
        src_ip = flow.src_ip

        # --- Cross-flow: unique destination IPs ---
        unique_ips = len(self._host_activity.get(src_ip, {}))

        if unique_ips >= cfg.RECON_MIN_UNIQUE_IPS:
            triggered.append("multi_host_scan")
            excess = unique_ips - cfg.RECON_MIN_UNIQUE_IPS
            confidence = min(0.5 + 0.05 * excess, 0.85)

        # --- Cross-flow: unique destination ports across all targets ---
        # Skip for loopback sources: on loopback, many unrelated local
        # services appear to originate from 127.0.0.1, making the
        # multi_port_scan check unreliable (same root cause as the
        # cross_flow_port_scan guard in _check_port_scan).
        if not _is_loopback(src_ip):
            unique_ports_all = len(self._port_activity.get(src_ip, {}))

            if unique_ports_all >= cfg.RECON_MIN_UNIQUE_PORTS:
                triggered.append("multi_port_scan")
                if confidence == 0.0:
                    excess = unique_ports_all - cfg.RECON_MIN_UNIQUE_PORTS
                    confidence = min(0.5 + 0.05 * excess, 0.85)
                else:
                    confidence += 0.1

        if not triggered:
            return None

        confidence = min(confidence, 0.95)

        reason = f"RECONNAISSANCE indicators: {', '.join(triggered)}. "
        reason += (
            f"Unique dst IPs from {src_ip} in window: {unique_ips} "
            f"(threshold: {cfg.RECON_MIN_UNIQUE_IPS}). "
        )
        if "multi_port_scan" in triggered:
            reason += (
                f"Unique dst ports: {unique_ports_all} "
                f"(threshold: {cfg.RECON_MIN_UNIQUE_PORTS})."
            )
        return _RuleMatch(
            attack_type=RECONNAISSANCE,
            confidence=confidence,
            triggered_rules=triggered,
            reason=reason,
        )


__all__ = [
    "RuleEngine",
    "RuleResult",
    "BENIGN",
    "PORT_SCAN",
    "BRUTE_FORCE",
    "DOS",
    "RECONNAISSANCE",
    "ALL_ATTACK_CLASSES",
]

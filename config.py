"""
Centralised configuration for the NIDS project.

All tunable parameters live here so that thresholds can be adjusted in one
place without scattering magic numbers across the codebase.

Thresholds marked ``initial`` have NOT been experimentally validated against
real lab traffic (Kali attack traffic on the 192.168.56.x host-only network).
They are starting points that must be calibrated during Stage 7 testing.
"""

from dataclasses import dataclass, field
from typing import List

# ---------------------------------------------------------------------------
# Flow-level configuration
# ---------------------------------------------------------------------------

@dataclass
class FlowConfig:
    """Flow manager timing configuration."""
    # Seconds of inactivity before a flow is considered closed.
    # This is the basic timeout from the verified implementation (section 20).
    FLOW_TIMEOUT: float = 10.0  # initial


# ---------------------------------------------------------------------------
# Rule Engine configuration
# ---------------------------------------------------------------------------

@dataclass
class RuleConfig:
    """
    Configurable thresholds for the Rule Engine.

    Every threshold below is marked with its rationale and validation status.
    """

    # ---- DOS thresholds ----
    # High sustained packet rate on a single flow indicates flooding.
    # Calibrated against Kali lab traffic on 192.168.56.x host-only network.
    # hping3 SYN flood produces very high pps even with small packets.
    DOS_PACKETS_PER_SECOND: float = 100.0

    # Fixed rolling window for cross-flow SYN rate. The full window is used
    # from startup so a short scan burst cannot look like a sustained flood.
    DOS_CROSS_FLOW_WINDOW: float = 1.0

    # Rate estimates from extremely short flows are dominated by timestamp
    # precision and are not reliable evidence of sustained flooding.
    DOS_MIN_RATE_DURATION: float = 0.001

    # Minimum packet count in a single flow before the rate-based DoS
    # sub-rules (high_packet_rate, high_byte_rate) may fire.
    # A completed TCP handshake to an OPEN port is 3-4 packets spread over a
    # millisecond or two; dividing that by its duration yields thousands of
    # "packets per second" with no flooding involved.  Live Kali -> Ubuntu
    # connect scans produced CRITICAL DOS alerts from exactly this pattern.
    # Genuine floods carry far more packets in one flow, and short SYN floods
    # (1-2 packets per flow) are still caught by the cross-flow SYN check.
    DOS_MIN_RATE_PACKETS: int = 20

    # High sustained byte rate on a single flow.
    # Calibrated — reduced from 500KB/s to detect small-packet floods.
    DOS_BYTES_PER_SECOND: float = 100_000.0

    # Minimum packet count in a single flow to even consider it for DoS.
    # Lowered to detect SYN floods that use just 1-2 packets per flow.
    DOS_MIN_PACKET_COUNT: int = 2

    # Minimum packet count for the high-byte-rate sub-rule.
    # Lowered to match DOS_MIN_PACKET_COUNT.
    DOS_MIN_BYTE_RATE_PACKETS: int = 2

    # If SYN packets make up more than this fraction of all packets in a flow,
    # it suggests a SYN-flood pattern.  Calibrated — SYN floods are nearly
    # 100% SYN, so 0.5 is sufficient to catch them while excluding normal
    # TCP traffic which has ACKs mixed in.
    DOS_SYN_RATIO: float = 0.5

    # Absolute minimum SYN count to trigger the SYN-flood sub-rule.
    # Lowered from 20 to 3 — even a few SYN packets at high rate is a flood.
    DOS_MIN_SYN_COUNT: int = 3


    # ---- Port Scan thresholds ----
    # Number of distinct destination ports probed by one source within the
    # time window before the flow is flagged as PORT_SCAN.
    # Calibrated — 10 is appropriate for nmap scans which probe 100+ ports.
    PORT_SCAN_MIN_UNIQUE_PORTS: int = 10

    # Time window (seconds) for aggregating port-scan activity across flows.
    PORT_SCAN_TIME_WINDOW: float = 10.0

    # If a single flow's SYN-to-total-packet ratio exceeds this AND the flow
    # has very few packets, it looks like a scan probe (SYN with no follow-up).
    PORT_SCAN_SYN_ONLY_RATIO: float = 0.8

    # Maximum packet count in a flow that can still be considered a scan probe.
    # Scan probes typically complete in 1-2 packets.
    PORT_SCAN_MAX_PACKETS: int = 5


    # ---- Brute Force thresholds ----
    # Number of repeated connections from one source to the same destination
    # port within the time window before it is flagged as BRUTE_FORCE.
    # Calibrated — lowered from 10 to 5.  20 SSH connections over ~13 seconds
    # was not detected with threshold of 10.
    BRUTE_FORCE_MIN_ATTEMPTS: int = 5

    # Time window (seconds) for counting repeated authentication attempts.
    # Increased from 10 to 30 to capture slower brute-force campaigns.
    BRUTE_FORCE_TIME_WINDOW: float = 30.0

    # Ports commonly targeted by brute-force attacks.
    # Based on section 24 of the design document (SSH, telnet, web, SMB).
    BRUTE_FORCE_PORTS: List[int] = field(
        default_factory=lambda: [22, 23, 2323, 80, 443, 139, 445]
    )

    # Maximum packets per individual flow to a single service that is still
    # considered a single failed/failing authentication attempt.
    # Legitimate interactive sessions carry data (PSH) and exceed this count.
    # Initial.
    BRUTE_FORCE_MAX_PACKETS_PER_FLOW: int = 3

    # Maximum duration (seconds) for a per-flow brute-force indicator.
    # Failed auth attempts close almost instantly.  Initial.
    BRUTE_FORCE_MAX_DURATION: float = 1.0

    # If True, the per-flow brute-force check additionally requires that the
    # flow has NO PSH flags (no application data transferred).  A legitimate
    # SSH session that transfers any data is not a brute-force attempt.
    BRUTE_FORCE_NO_PSH_REQUIRED: bool = True

    # If True, a flow that contains a TCP RST is not treated as a single
    # authentication attempt.  A SYN answered by RST+ACK is a connection
    # refused by a closed port — a scan probe, not a login attempt.
    # Live Kali -> Ubuntu run: port 445 produced a HIGH BRUTE_FORCE alert from
    # a 2-packet SYN / RST+ACK flow (145 us, syn=1 ack=1 rst=1 psh=0).
    BRUTE_FORCE_RST_IS_REFUSAL: bool = True


    # ---- Reconnaissance thresholds ----
    # Number of distinct destination IPs contacted by one source within the
    # time window before it is flagged as RECONNAISSANCE.
    # Calibrated — lowered from 5 to 3.  nmap ping sweep contacts multiple
    # hosts quickly; 3 is sufficient to catch recon while avoiding false
    # positives from normal multi-host browsing.
    RECON_MIN_UNIQUE_IPS: int = 3

    # Time window (seconds) for aggregating recon activity across flows.
    # Increased from 10 to 30 to capture slower reconnaissance campaigns.
    RECON_TIME_WINDOW: float = 30.0

    # Minimum distinct destination ports seen across targets to also count
    # as reconnaissance.  Calibrated — lowered from 10 to 5.
    RECON_MIN_UNIQUE_PORTS: int = 5


# ---- Severity mapping (section 35 of design doc) ----
# Used by risk scoring in a later stage, but defined here for centralisation.

SEVERITY_MAP = {
    "BENIGN": "INFORMATIONAL",
    "PORT_SCAN": "MEDIUM",
    "RECONNAISSANCE": "MEDIUM",
    "BRUTE_FORCE": "HIGH",
    "DOS": "CRITICAL",
}


def get_default_rule_config() -> RuleConfig:
    """Return a RuleConfig instance with default (initial) thresholds."""
    return RuleConfig()

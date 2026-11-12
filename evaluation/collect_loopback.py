"""
STAGE 11.3: Benign Loopback Traffic Collector
==============================================

Collects labeled benign loopback traffic for evaluation.

Supports:
  - ICMP (ping)
  - TCP (connection probes)
  - UDP (datagram sends)
  - DNS (Scapy-generated queries)

All traffic is generated against localhost (127.0.0.1) and labeled
BENIGN by construction. Ground truth is assigned by the collection
script itself, independent of any NIDS prediction.

Output: JSON Lines file conforming to EvaluationRecord schema.
"""

from __future__ import annotations

import logging
import queue
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scapy.all import IP, ICMP, UDP, DNS, DNSQR, TCP, send, sniff

from NIDS.flow import Flow
from NIDS.flow_manager import FlowManager
from NIDS.packet_capture import parse_packet_info
from NIDS.evaluation.schema import (
    CLASS_LABELS,
    EvaluationDataset,
    EvaluationRecord,
    EvaluationSession,
    TRAFFIC_CATEGORY_BENIGN,
    ValidationIssue,
    ValidationVerdict,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class LoopbackCollectionConfig:
    """Configuration for a benign loopback collection run."""
    session_id: str
    duration_seconds: float = 60.0
    interface: Optional[str] = None  # None = auto-detect loopback
    flow_timeout: float = 10.0
    output_dir: Path = field(default_factory=lambda: PROJECT_ROOT / "NIDS" / "evaluation" / "datasets")
    save_pcap: bool = False
    pcap_dir: Optional[Path] = None

    # Traffic generation parameters
    icmp_count: int = 10
    icmp_interval: float = 0.5
    tcp_ports: List[int] = field(default_factory=lambda: list(range(9000, 9010)))
    tcp_interval: float = 0.2
    udp_count: int = 10
    udp_port: int = 12345
    udp_interval: float = 0.1
    dns_count: int = 5
    dns_interval: float = 0.3

    # Metadata
    source_machine: str = "localhost"
    target_machine: str = "localhost"
    generator_notes: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_loopback_iface() -> Optional[str]:
    """Auto-detect the loopback interface name for Scapy."""
    try:
        from scapy.all import conf
        for name, iface in conf.ifaces.items():
            if "Loopback" in iface.name or "loopback" in name.lower():
                return name
    except Exception:
        pass
    return None


def _generate_icmp(count: int = 10, interval: float = 0.5) -> None:
    """Generate ICMP ping traffic to localhost."""
    try:
        subprocess.run(
            ["ping", "-n", str(count), "127.0.0.1"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except Exception as e:
        logger.warning(f"ICMP generation failed: {e}")


def _generate_tcp(ports: List[int], interval: float = 0.2) -> None:
    """Generate TCP connection probes to localhost ports."""
    import socket
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            s.connect(("127.0.0.1", port))
            s.close()
        except Exception:
            pass
        time.sleep(interval)


def _generate_udp(count: int = 10, port: int = 12345, interval: float = 0.1) -> None:
    """Generate UDP datagrams to localhost."""
    import socket
    for _ in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.1)
            s.sendto(b"benign_eval_data_" * 4, ("127.0.0.1", port))
            s.close()
        except Exception:
            pass
        time.sleep(interval)


def _generate_dns(count: int = 5, interval: float = 0.3) -> None:
    """Generate DNS query traffic to localhost via Scapy."""
    for _ in range(count):
        try:
            pkt = IP(dst="127.0.0.1") / UDP(dport=53) / DNS(id=1, rd=1, qd=DNSQR(qname=b"example.com"))
            send(pkt, verbose=0, count=1)
        except Exception as e:
            logger.warning(f"DNS generation failed: {e}")
        time.sleep(interval)


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class LoopbackCollector:
    """
    Collects labeled benign loopback flows and writes them to an
    evaluation dataset file.

    Ground truth is BENIGN by construction because all generated traffic
    is localhost ICMP/TCP/UDP/DNS from known benign generators.

    The collector does NOT run the NIDS model or rule engine.
    It only extracts raw flows for later offline evaluation.
    """

    def __init__(self, config: LoopbackCollectionConfig):
        self.config = config
        self.output_dir = config.output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.iface = config.interface or _get_loopback_iface()

        # Runtime state
        self._flow_manager = FlowManager(flow_timeout=config.flow_timeout)
        self._dataset = EvaluationDataset(name=config.session_id)
        self._captured_packets: List[Any] = []
        self._capture_start: float = 0.0
        self._capture_end: float = 0.0
        self._generator_log: List[str] = []
        self._lock = threading.Lock()

    def _packet_callback(self, packet: Any) -> None:
        """Capture callback — stores packets and extracts flows."""
        with self._lock:
            self._captured_packets.append(packet)
            try:
                flows = self._flow_manager.process_packet(packet)
                for flow in flows:
                    record = self._flow_to_record(flow)
                    self._dataset.add_record(record)
            except Exception as e:
                logger.error(f"Flow extraction failed: {e}")

    def _flow_to_record(self, flow: Flow) -> EvaluationRecord:
        """Convert a completed Flow to an EvaluationRecord with BENIGN label."""
        features = flow.get_features()
        return EvaluationRecord(
            evaluation_session_id=self.config.session_id,
            collection_timestamp=flow.start_time,
            traffic_category=TRAFFIC_CATEGORY_BENIGN,
            traffic_subtype="loopback_benign",
            ground_truth_label="BENIGN",
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            features=features,
            flow_duration=flow.duration,
            packet_count=flow.packet_count,
            byte_count=flow.byte_count,
            collection_interface=self.iface or "unknown",
            source_machine=self.config.source_machine,
            target_machine=self.config.target_machine,
            generator_command="loopback_benign_collector",
            generator_log="\n".join(self._generator_log),
            extra_metadata={
                "flow_timeout": self.config.flow_timeout,
                "collector_version": "stage11.3",
            },
        )

    def collect(self) -> EvaluationDataset:
        """
        Run the collection session: capture + generate + extract.

        Returns the EvaluationDataset with all captured flows.
        """
        session_id = self.config.session_id
        logger.info(f"Starting loopback collection session: {session_id}")
        self._capture_start = time.time()

        # Start capture in a separate thread
        stop_event = threading.Event()
        capture_error: List[Optional[str]] = [None]

        def capture_loop():
            try:
                sniff(
                    iface=self.iface,
                    prn=self._packet_callback,
                    count=0,
                    store=False,
                    stop_filter=lambda pkt=None: stop_event.is_set(),
                )
            except Exception as e:
                capture_error[0] = f"{type(e).__name__}: {e}"

        cap_thread = threading.Thread(target=capture_loop, daemon=True)
        cap_thread.start()

        # Generate traffic in phases
        self._generator_log.append(f"[{datetime.now(timezone.utc).isoformat()}] Phase 1: ICMP")
        _generate_icmp(count=self.config.icmp_count, interval=self.config.icmp_interval)
        time.sleep(1.0)

        self._generator_log.append(f"[{datetime.now(timezone.utc).isoformat()}] Phase 2: TCP")
        _generate_tcp(ports=self.config.tcp_ports, interval=self.config.tcp_interval)
        time.sleep(1.0)

        self._generator_log.append(f"[{datetime.now(timezone.utc).isoformat()}] Phase 3: UDP")
        _generate_udp(count=self.config.udp_count, port=self.config.udp_port, interval=self.config.udp_interval)
        time.sleep(1.0)

        self._generator_log.append(f"[{datetime.now(timezone.utc).isoformat()}] Phase 4: DNS")
        _generate_dns(count=self.config.dns_count, interval=self.config.dns_interval)
        time.sleep(1.0)

        # Wait for flows to timeout and be captured
        time.sleep(self.config.flow_timeout + 1.0)

        # Stop capture
        stop_event.set()
        cap_thread.join(timeout=5.0)
        self._capture_end = time.time()

        # Register session
        session = EvaluationSession(
            session_id=session_id,
            start_timestamp=self._capture_start,
            end_timestamp=self._capture_end,
            traffic_category=TRAFFIC_CATEGORY_BENIGN,
            traffic_subtype="loopback_benign",
            interface=self.iface or "unknown",
            source_machine=self.config.source_machine,
            target_machine=self.config.target_machine,
            generator_command="loopback_benign_collector",
            generator_log_path=None,
            output_path=None,
            record_count=len(self._dataset.records),
            extra_metadata={
                "icmp_count": self.config.icmp_count,
                "tcp_ports": self.config.tcp_ports,
                "udp_count": self.config.udp_count,
                "dns_count": self.config.dns_count,
            },
        )
        self._dataset.add_session(session)

        logger.info(
            f"Session {session_id} complete: {len(self._dataset.records)} flows captured "
            f"in {session.duration_seconds():.1f}s"
        )

        if capture_error[0]:
            logger.warning(f"Capture error: {capture_error[0]}")

        return self._dataset

    def save(self) -> Path:
        """Save the dataset to a JSON Lines file."""
        output_path = self.output_dir / f"loopback_benign_{self.config.session_id}.jsonl"
        self._dataset.to_jsonl(output_path)
        logger.info(f"Dataset saved to {output_path}")
        return output_path

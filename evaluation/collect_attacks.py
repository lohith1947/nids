"""
STAGE 11.3: Controlled Attack Collection Framework
===================================================

IMPORTANT: This module is a SAFE COLLECTION FRAMEWORK.

It does NOT automatically execute offensive commands or tools.
Instead, it provides:
  - attack session metadata
  - expected label
  - target identifier
  - capture window
  - session ID
  - start/end timestamps
  - collection state
  - output format

Controlled attack traffic can later be generated against the dedicated
lab target by an authorized operator using the documented procedures.

The framework prevents accidental collection against arbitrary external
systems by enforcing:
  - explicit target allow-list
  - explicit interface binding
  - explicit session authorization
  - mandatory safety checks before any packet generation
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import numpy as np

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scapy.all import IP, ICMP, UDP, TCP, send, sniff

from NIDS.flow import Flow
from NIDS.flow_manager import FlowManager
from NIDS.packet_capture import parse_packet_info
from NIDS.evaluation.schema import (
    CLASS_LABELS,
    EvaluationDataset,
    EvaluationRecord,
    EvaluationSession,
    TRAFFIC_CATEGORY_ATTACK,
    ValidationVerdict,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Safety / allow-list
# ---------------------------------------------------------------------------

# Default allowed target networks for attack collection.
# Only these networks may be targeted. Collection against any other
# destination is rejected by the safety check.
DEFAULT_ALLOWED_TARGETS: List[str] = [
    "127.0.0.1",           # loopback (local testing only)
    "192.168.56.0/24",     # VirtualBox host-only network (Kali lab)
    "10.0.0.0/24",         # Alternative lab network
]

# Attack types that this framework supports
SUPPORTED_ATTACK_TYPES = [
    "PORT_SCAN",
    "BRUTE_FORCE",
    "DOS",
    "RECONNAISSANCE",
]


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class AttackCollectionConfig:
    """
    Configuration for a controlled attack collection session.

    All fields are explicit and must be provided by the operator.
    """
    session_id: str
    attack_type: str
    expected_label: str
    target_ip: str
    target_ports: List[int]
    interface: Optional[str] = None
    duration_seconds: float = 120.0
    flow_timeout: float = 10.0
    output_dir: Path = field(default_factory=lambda: PROJECT_ROOT / "NIDS" / "evaluation" / "datasets")
    save_pcap: bool = False
    pcap_dir: Optional[Path] = None
    authorized_by: str = ""
    authorization_note: str = ""
    generator_command: str = ""
    generator_args: List[str] = field(default_factory=list)
    source_machine: str = "kali-vm"
    target_machine: str = "victim-vm"
    extra_metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.attack_type not in SUPPORTED_ATTACK_TYPES:
            raise ValueError(f"Unsupported attack type: {self.attack_type}. Must be one of {SUPPORTED_ATTACK_TYPES}")
        if self.expected_label not in CLASS_LABELS:
            raise ValueError(f"Invalid expected_label: {self.expected_label}. Must be one of {CLASS_LABELS}")
        if self.expected_label != self.attack_type:
            raise ValueError(f"attack_type '{self.attack_type}' != expected_label '{self.expected_label}'")
        if not self.authorized_by:
            logger.warning("Attack collection session has no authorization; set authorized_by")


# ---------------------------------------------------------------------------
# Safety checks
# ---------------------------------------------------------------------------

def _is_target_allowed(target_ip: str, allowed_targets: List[str] = DEFAULT_ALLOWED_TARGETS) -> bool:
    """Check if the target IP is in the allowed list."""
    import ipaddress
    try:
        target = ipaddress.ip_address(target_ip)
        for allowed in allowed_targets:
            network = ipaddress.ip_network(allowed, strict=False)
            if target in network:
                return True
    except ValueError:
        # If target is not a valid IP (e.g., hostname), reject
        return False
    return False


def safety_check(config: AttackCollectionConfig, allowed_targets: List[str] = DEFAULT_ALLOWED_TARGETS) -> List[str]:
    """
    Perform safety checks on the attack collection configuration.

    Returns a list of violation strings. Empty list means safe to proceed.
    """
    violations = []

    if not _is_target_allowed(config.target_ip, allowed_targets):
        violations.append(
            f"Target IP {config.target_ip} is NOT in the allowed target list: {allowed_targets}"
        )

    if config.interface and "lo" in config.interface.lower() and config.target_ip != "127.0.0.1":
        violations.append(
            "Loopback interface can only be used with 127.0.0.1 target"
        )

    if not config.authorized_by:
        violations.append("No authorization provided (authorized_by is empty)")

    if config.duration_seconds > 600:
        violations.append(
            f"Duration {config.duration_seconds}s exceeds maximum 600s"
        )

    return violations


# ---------------------------------------------------------------------------
# Attack session metadata (the "safe framework" output)
# ---------------------------------------------------------------------------

@dataclass
class AttackSessionPlan:
    """
    A planned attack collection session.

    This is the primary output of the safe framework. It documents
    exactly what would be collected, where, and by whom, without
    executing any attack traffic.
    """
    session_id: str
    attack_type: str
    expected_label: str
    target_ip: str
    target_ports: List[int]
    interface: Optional[str]
    duration_seconds: float
    capture_window_start: float
    capture_window_end: float
    generator_command: str
    generator_args: List[str]
    authorized_by: str
    authorization_note: str
    source_machine: str
    target_machine: str
    safety_violations: List[str] = field(default_factory=list)
    is_safe: bool = True
    extra_metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.safety_violations:
            self.is_safe = False


def plan_attack_session(config: AttackCollectionConfig) -> AttackSessionPlan:
    """
    Create an AttackSessionPlan from a configuration and run safety checks.

    Returns a plan that can be reviewed before execution.
    """
    now = time.time()
    violations = safety_check(config)

    plan = AttackSessionPlan(
        session_id=config.session_id,
        attack_type=config.attack_type,
        expected_label=config.expected_label,
        target_ip=config.target_ip,
        target_ports=config.target_ports,
        interface=config.interface,
        duration_seconds=config.duration_seconds,
        capture_window_start=now,
        capture_window_end=now + config.duration_seconds,
        generator_command=config.generator_command,
        generator_args=config.generator_args,
        authorized_by=config.authorized_by,
        authorization_note=config.authorization_note,
        source_machine=config.source_machine,
        target_machine=config.target_machine,
        safety_violations=violations,
        is_safe=len(violations) == 0,
        extra_metadata=config.extra_metadata,
    )
    return plan


# ---------------------------------------------------------------------------
# Safe collector (executes only if safety checks pass)
# ---------------------------------------------------------------------------

class AttackCollector:
    """
    Collects labeled attack flows and writes them to an evaluation dataset.

    The collector enforces safety checks before any packet generation.
    It extracts flows using the same FlowManager as the benign collector,
    ensuring consistent feature extraction.

    Ground truth is assigned by the collection script (based on the
    planned attack type), NOT by the NIDS.
    """

    def __init__(self, config: AttackCollectionConfig):
        self.config = config
        self.output_dir = config.output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.iface = config.interface
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
                logger.error(f"Flow extraction failed during attack collection: {e}")

    def _flow_to_record(self, flow: Flow) -> EvaluationRecord:
        """Convert a completed Flow to an EvaluationRecord with attack label."""
        features = flow.get_features()
        return EvaluationRecord(
            evaluation_session_id=self.config.session_id,
            collection_timestamp=flow.start_time,
            traffic_category=TRAFFIC_CATEGORY_ATTACK,
            traffic_subtype=self.config.attack_type.lower(),
            ground_truth_label=self.config.expected_label,
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
            generator_command=self.config.generator_command,
            generator_log="\n".join(self._generator_log),
            extra_metadata={
                "attack_type": self.config.attack_type,
                "target_ports": self.config.target_ports,
                "authorized_by": self.config.authorized_by,
                "collector_version": "stage11.3",
                **self.config.extra_metadata,
            },
        )

    def _run_safety_check(self) -> List[str]:
        """Run safety checks and return violations."""
        return safety_check(self.config)

    def collect(self) -> EvaluationDataset:
        """
        Run the attack collection session.

        Raises RuntimeError if safety checks fail.
        """
        violations = self._run_safety_check()
        if violations:
            raise RuntimeError(
                f"Attack collection ABORTED due to safety violations: {violations}"
            )

        session_id = self.config.session_id
        logger.info(f"Starting attack collection session: {session_id} ({self.config.attack_type})")
        self._capture_start = time.time()

        # Start capture
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

        # Execute the generator command
        self._generator_log.append(
            f"[{datetime.now(timezone.utc).isoformat()}] Executing: "
            f"{self.config.generator_command} {' '.join(self.config.generator_args)}"
        )
        try:
            result = subprocess.run(
                [self.config.generator_command] + self.config.generator_args,
                capture_output=True,
                text=True,
                timeout=self.config.duration_seconds,
            )
            self._generator_log.append(f"stdout: {result.stdout[:2000]}")
            self._generator_log.append(f"stderr: {result.stderr[:2000]}")
            self._generator_log.append(f"returncode: {result.returncode}")
        except subprocess.TimeoutExpired:
            self._generator_log.append("Generator command timed out")
        except Exception as e:
            self._generator_log.append(f"Generator execution failed: {e}")

        # Wait for capture window
        time.sleep(self.config.duration_seconds)

        # Stop capture
        stop_event.set()
        cap_thread.join(timeout=5.0)
        self._capture_end = time.time()

        # Register session
        session = EvaluationSession(
            session_id=session_id,
            start_timestamp=self._capture_start,
            end_timestamp=self._capture_end,
            traffic_category=TRAFFIC_CATEGORY_ATTACK,
            traffic_subtype=self.config.attack_type.lower(),
            interface=self.iface or "unknown",
            source_machine=self.config.source_machine,
            target_machine=self.config.target_machine,
            generator_command=self.config.generator_command,
            generator_log_path=None,
            output_path=None,
            record_count=len(self._dataset.records),
            extra_metadata={
                "attack_type": self.config.attack_type,
                "target_ip": self.config.target_ip,
                "target_ports": self.config.target_ports,
                "authorized_by": self.config.authorized_by,
            },
        )
        self._dataset.add_session(session)

        logger.info(
            f"Attack session {session_id} complete: {len(self._dataset.records)} flows captured "
            f"in {session.duration_seconds():.1f}s"
        )

        if capture_error[0]:
            logger.warning(f"Capture error: {capture_error[0]}")

        return self._dataset

    def save(self) -> Path:
        """Save the dataset to a JSON Lines file."""
        output_path = self.output_dir / f"attack_{self.config.session_id}.jsonl"
        self._dataset.to_jsonl(output_path)
        logger.info(f"Attack dataset saved to {output_path}")
        return output_path

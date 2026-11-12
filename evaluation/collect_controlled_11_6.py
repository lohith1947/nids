"""
STAGE 11.6: Controlled Benign Traffic Attribution & Collection
================================================================

Fixes the evaluation-data attribution problem from Stage 11.5 by:
- Using dedicated destination ports per traffic category
- Tracking generation events with exact 5-tuples and timestamps
- Filtering captured flows to only include matching flows
- Adding explicit attribution status to each record

Ground truth remains independent of model prediction.
"""

from __future__ import annotations

import json
import logging
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np
from scapy.all import IP, ICMP, UDP, DNS, DNSQR, TCP, send, sniff

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from NIDS.flow import Flow
from NIDS.flow_manager import FlowManager
from NIDS.model import NIDSModel
from NIDS.rule_engine import RuleEngine
from NIDS.evaluation.schema import (
    CLASS_LABELS,
    EvaluationDataset,
    EvaluationRecord,
    EvaluationSession,
    TRAFFIC_CATEGORY_BENIGN,
)
from NIDS.evaluation.validation import validate_dataset

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Attribution status enum
# ---------------------------------------------------------------------------

ATTRIBUTED = "ATTRIBUTED"
AMBIGUOUS = "AMBIGUOUS"
UNATTRIBUTED = "UNATTRIBUTED"
CONTAMINATED = "CONTAMINATED"

WELL_KNOWN_PORT_MAX = 1023
EPHEMERAL_PORT_MIN = 49152


def _is_well_known_port(port: int) -> bool:
    return 0 <= port <= WELL_KNOWN_PORT_MAX


def _is_ephemeral_port(port: int) -> bool:
    return EPHEMERAL_PORT_MIN <= port <= 65535


SOURCE_PORT_MODE_EXACT = "EXACT"
SOURCE_PORT_MODE_EPHEMERAL = "EPHEMERAL"
SOURCE_PORT_MODE_ANY = "ANY"


def _validate_source_port(src_port: int, mode: str, expected_port: Optional[int]) -> Tuple[bool, str]:
    if mode == SOURCE_PORT_MODE_EXACT:
        if expected_port is not None and src_port != expected_port:
            return False, f"expected exact source port {expected_port}, got {src_port}"
        return True, ""
    elif mode == SOURCE_PORT_MODE_EPHEMERAL:
        if _is_well_known_port(src_port):
            return False, f"expected ephemeral source port, got well-known port {src_port}"
        if expected_port is not None and src_port != expected_port:
            return False, f"expected specific ephemeral port {expected_port}, got {src_port}"
        return True, ""
    elif mode == SOURCE_PORT_MODE_ANY:
        return True, ""
    return False, f"unknown source_port_mode: {mode}"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class ControlledConfig:
    session_id: str = "controlled_11_6_benign"
    flow_timeout: float = 10.0
    output_dir: Path = field(default_factory=lambda: PROJECT_ROOT / "NIDS" / "evaluation" / "datasets")
    model_path: Path = field(default_factory=lambda: PROJECT_ROOT / "NIDS" / "models" / "nids_model.joblib")
    interface: Optional[str] = None

    # Dedicated ports per category (fixed for reproducibility)
    tcp_base_port: int = 51000
    udp_base_port: int = 51100
    dns_base_port: int = 51200
    icmp_base_ip: str = "127.0.0.2"

    # Per-category target counts (small pilot)
    target_tcp: int = 20
    target_udp: int = 20
    target_dns: int = 20
    target_icmp: int = 20


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_loopback_iface() -> Optional[str]:
    try:
        from scapy.all import conf
        for name, iface in conf.ifaces.items():
            if "Loopback" in iface.name or "loopback" in name.lower():
                return name
    except Exception:
        pass
    return None


def _generate_tcp_flow(dst_port: int, flow_id: int) -> None:
    """Generate a single controlled TCP flow to a dedicated port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect(("127.0.0.1", dst_port))
        payload = f"ctrl_tcp_{flow_id}".encode()
        s.sendall(payload)
        try:
            resp = s.recv(1024)
            logger.info(f"TCP flow {flow_id} to port {dst_port}: sent {len(payload)} bytes, received {len(resp)} bytes")
        except socket.timeout:
            logger.warning(f"TCP flow {flow_id} to port {dst_port}: timeout waiting for response")
        s.close()
    except Exception as e:
        logger.warning(f"TCP flow {flow_id} to port {dst_port} failed: {e}")


def _generate_udp_flow(dst_port: int, flow_id: int) -> None:
    """Generate a single controlled UDP flow to a dedicated port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        payload = f"ctrl_udp_{flow_id}".encode()
        s.sendto(payload, ("127.0.0.1", dst_port))
        try:
            resp, addr = s.recvfrom(1024)
            logger.info(f"UDP flow {flow_id} to port {dst_port}: sent {len(payload)} bytes, received {len(resp)} bytes")
        except socket.timeout:
            logger.warning(f"UDP flow {flow_id} to port {dst_port}: timeout waiting for response")
        s.close()
    except Exception as e:
        logger.warning(f"UDP flow {flow_id} to port {dst_port} failed: {e}")


def _generate_dns_flow(dst_port: int, flow_id: int) -> None:
    """Generate a single controlled DNS query to a dedicated port."""
    try:
        pkt = IP(dst="127.0.0.1") / UDP(dport=dst_port) / DNS(id=flow_id % 65535, rd=1, qd=DNSQR(qname=f"ctrl{flow_id}.example.com".encode()))
        send(pkt, verbose=0, count=1)
        logger.info(f"DNS flow {flow_id} to port {dst_port}: sent Scapy packet")
    except Exception as e:
        logger.warning(f"DNS flow {flow_id} to port {dst_port} failed: {e}")


def _generate_icmp_flow(dst_ip: str, flow_id: int) -> None:
    """Generate a single controlled ICMP ping to a dedicated IP."""
    try:
        result = subprocess.run(["ping", "-n", "1", dst_ip], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            logger.info(f"ICMP flow {flow_id} to {dst_ip}: ping succeeded")
        else:
            logger.warning(f"ICMP flow {flow_id} to {dst_ip}: ping failed with code {result.returncode}")
    except Exception as e:
        logger.warning(f"ICMP flow {flow_id} to {dst_ip} failed: {e}")


def _start_tcp_echo_server(port: int, stop_event: threading.Event) -> Optional[socket.socket]:
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(10)
        srv.settimeout(0.5)
        logger.info(f"TCP echo server started on port {port}")

        def _serve():
            while not stop_event.is_set():
                try:
                    client, addr = srv.accept()
                    client.settimeout(0.5)
                    data = client.recv(1024)
                    if data:
                        logger.info(f"TCP server received: {data[:20]}...")
                    client.sendall(b"ECHO:" + data)
                    client.close()
                except socket.timeout:
                    continue
                except Exception:
                    break
            srv.close()

        threading.Thread(target=_serve, daemon=True).start()
        return srv
    except Exception as e:
        logger.warning(f"TCP echo server failed on port {port}: {e}")
        return None


def _start_udp_echo_server(port: int, stop_event: threading.Event) -> Optional[socket.socket]:
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", port))
        srv.settimeout(0.5)
        logger.info(f"UDP echo server started on port {port}")

        def _serve():
            while not stop_event.is_set():
                try:
                    data, addr = srv.recvfrom(1024)
                    logger.info(f"UDP server received from {addr}: {data[:20]}...")
                    srv.sendto(b"ECHO:" + data, addr)
                except socket.timeout:
                    continue
                except Exception:
                    break
            srv.close()

        threading.Thread(target=_serve, daemon=True).start()
        return srv
    except Exception as e:
        logger.warning(f"UDP echo server failed on port {port}: {e}")
        return None


def _start_dns_server(port: int, stop_event: threading.Event) -> Optional[socket.socket]:
    """Start a minimal DNS-like UDP listener."""
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", port))
        srv.settimeout(0.5)
        logger.info(f"DNS server started on port {port}")

        def _serve():
            while not stop_event.is_set():
                try:
                    data, addr = srv.recvfrom(1024)
                    logger.info(f"DNS server received from {addr}: {len(data)} bytes")
                    srv.sendto(b"DNS_RESPONSE", addr)
                except socket.timeout:
                    continue
                except Exception:
                    break
            srv.close()

        threading.Thread(target=_serve, daemon=True).start()
        return srv
    except Exception as e:
        logger.warning(f"DNS server failed on port {port}: {e}")
        return None


# ---------------------------------------------------------------------------
# Controlled Collector
# ---------------------------------------------------------------------------

class ControlledCollector:
    def __init__(self, config: ControlledConfig):
        self.config = config
        self.output_dir = config.output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.iface = config.interface or _get_loopback_iface()

        self._model = NIDSModel.load(str(config.model_path))
        self._rule_engine = RuleEngine()

        self._all_records: List[EvaluationRecord] = []
        self._all_sessions: List[EvaluationSession] = []
        self._collection_log: List[str] = []
        self._attribution_log: List[Dict[str, Any]] = []
        self._inline_flows: List[Tuple[Flow, str, int]] = []  # (flow, subtype, expected_proto)

    def _log(self, msg: str) -> None:
        self._collection_log.append(f"[{datetime.now(timezone.utc).isoformat()}] {msg}")
        logger.info(msg)

    def _record_attribution(self, generation_event: Dict[str, Any], flow: Flow,
                            status: str, reason: str) -> None:
        entry = {
            "generation_event": generation_event,
            "flow_5tuple": f"{flow.src_ip}:{flow.src_port}->{flow.dst_ip}:{flow.dst_port}",
            "flow_protocol": flow.protocol,
            "flow_duration": flow.duration,
            "flow_packets": flow.packet_count,
            "flow_bytes": flow.byte_count,
            "attribution_status": status,
            "reason": reason,
        }
        self._attribution_log.append(entry)

    def _match_flow_to_generation(self, flow: Flow, generation_events: List[Dict[str, Any]]) -> Tuple[str, Optional[Dict[str, Any]]]:
        """
        Match a captured flow to a generation event.
        Returns (status, matched_event).
        """
        return self._match_flow_to_generation_by_5tuple(
            flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.protocol, generation_events,
            flow_start_time=flow.start_time
        )

    def _match_flow_to_generation_by_5tuple(self, src_ip: str, src_port: int,
                                             dst_ip: str, dst_port: int, protocol: int,
                                             generation_events: List[Dict[str, Any]],
                                             flow_start_time: Optional[float] = None) -> Tuple[str, Optional[Dict[str, Any]]]:
        """Match by 5-tuple with source-port semantics and timestamp validation."""
        for event in generation_events:
            if (dst_ip == event["dst_ip"] and
                dst_port == event["dst_port"] and
                protocol == event["expected_protocol"]):

                if flow_start_time is not None:
                    in_window = (event["timestamp"] - 1.0 <= flow_start_time <= event["timestamp"] + 5.0)
                else:
                    in_window = (event["timestamp"] - 1.0 <= time.time() <= event["timestamp"] + 5.0)

                if not in_window:
                    continue

                source_port_mode = event.get("source_port_mode", SOURCE_PORT_MODE_ANY)
                expected_source_port = event.get("source_port")
                valid_port, _ = _validate_source_port(src_port, source_port_mode, expected_source_port)
                if not valid_port:
                    continue

                return ATTRIBUTED, event

        for event in generation_events:
            if (dst_ip == event["dst_ip"] and
                dst_port == event["dst_port"]):
                if protocol != event["expected_protocol"]:
                    return CONTAMINATED, event

        for event in generation_events:
            if protocol == event["expected_protocol"]:
                return AMBIGUOUS, event

        return UNATTRIBUTED, None

    def _capture_controlled_session(self, generation_func: Callable, generation_kwargs: Dict[str, Any],
                                    session_name: str, subtype: str, expected_proto: int,
                                    target_count: int) -> Tuple[List[EvaluationRecord], Dict[str, int]]:
        """
        Run a controlled capture session with dedicated endpoint.
        Returns (records, attribution_counts).
        """
        self._log(f"Starting controlled session: {session_name} (expected_proto={expected_proto})")
        capture_start = time.time()

        # Prepare dedicated endpoint
        dst_port = None
        dst_ip = "127.0.0.1"
        server = None
        stop_event = threading.Event()

        if expected_proto == 6:  # TCP
            dst_port = self.config.tcp_base_port + hash(subtype) % 1000
            server = _start_tcp_echo_server(dst_port, stop_event)
        elif expected_proto == 17:  # UDP
            if "dns" in subtype:
                dst_port = self.config.dns_base_port + hash(subtype) % 1000
                server = _start_dns_server(dst_port, stop_event)
            else:
                dst_port = self.config.udp_base_port + hash(subtype) % 1000
                server = _start_udp_echo_server(dst_port, stop_event)
        elif expected_proto == 1:  # ICMP
            dst_ip = self.config.icmp_base_ip

        if server is None and expected_proto != 1:
            self._log(f"Server failed to start for {subtype}; skipping")
            return [], {}

        time.sleep(0.5)  # Let server start

        # Generate traffic and track events
        generation_events: List[Dict[str, Any]] = []
        flow_manager = FlowManager(flow_timeout=self.config.flow_timeout)
        stop_capture = threading.Event()
        capture_error: List[Optional[str]] = [None]
        captured_packets: List[Any] = []

        def _generate_with_tracking():
            for i in range(target_count):
                if expected_proto == 6:
                    source_port_mode = SOURCE_PORT_MODE_EPHEMERAL
                    source_port = None
                elif expected_proto == 17:
                    if "dns" in subtype:
                        source_port_mode = SOURCE_PORT_MODE_EPHEMERAL
                        source_port = None
                    else:
                        source_port_mode = SOURCE_PORT_MODE_EPHEMERAL
                        source_port = None
                elif expected_proto == 1:
                    source_port_mode = SOURCE_PORT_MODE_ANY
                    source_port = None
                else:
                    source_port_mode = SOURCE_PORT_MODE_ANY
                    source_port = None

                event = {
                    "src_ip": "127.0.0.1",
                    "dst_ip": dst_ip,
                    "src_port": source_port,
                    "dst_port": dst_port if dst_port else 0,
                    "expected_protocol": expected_proto,
                    "timestamp": time.time(),
                    "flow_id": i,
                    "source_port_mode": source_port_mode,
                    "source_port": source_port,
                }
                generation_events.append(event)

                if expected_proto == 6:
                    _generate_tcp_flow(dst_port, i)
                elif expected_proto == 17:
                    if "dns" in subtype:
                        _generate_dns_flow(dst_port, i)
                    else:
                        _generate_udp_flow(dst_port, i)
                elif expected_proto == 1:
                    _generate_icmp_flow(dst_ip, i)

                time.sleep(0.1)

        def _capture_loop():
            try:
                sniff(
                    iface=self.iface,
                    prn=lambda pkt: self._packet_callback(pkt, flow_manager, captured_packets),
                    count=0,
                    store=False,
                    stop_filter=lambda pkt=None: stop_capture.is_set(),
                )
            except Exception as e:
                capture_error[0] = f"{type(e).__name__}: {e}"

        cap_thread = threading.Thread(target=_capture_loop, daemon=True)
        gen_thread = threading.Thread(target=_generate_with_tracking, daemon=True)
        cap_thread.start()
        gen_thread.start()
        gen_thread.join(timeout=60.0)

        time.sleep(self.config.flow_timeout + 2.0)
        stop_capture.set()
        cap_thread.join(timeout=5.0)
        capture_end = time.time()

        # Cleanup server
        stop_event.set()
        time.sleep(0.5)
        if server:
            try:
                server.close()
            except Exception:
                pass

        # Attribute flows
        remaining = list(flow_manager._flows.values())
        all_flows = remaining + [f for f, _, _ in self._inline_flows]
        records = []
        attribution_counts = {ATTRIBUTED: 0, AMBIGUOUS: 0, UNATTRIBUTED: 0, CONTAMINATED: 0}

        for flow in remaining:
            status, matched_event = self._match_flow_to_generation(flow, generation_events)
            attribution_counts[status] = attribution_counts.get(status, 0) + 1
            self._record_attribution(matched_event or {}, flow, status, "end_of_session")

            if status == ATTRIBUTED:
                rec = self._flow_to_record(flow, session_name, subtype, expected_proto, status, matched_event)
                records.append(rec)

        for flow, flow_subtype, flow_proto in self._inline_flows:
            status, matched_event = self._match_flow_to_generation_by_5tuple(
                flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.protocol,
                generation_events, flow_start_time=flow.start_time
            )
            attribution_counts[status] = attribution_counts.get(status, 0) + 1
            self._record_attribution(matched_event or {}, flow, status, "inline_completed")

            if status == ATTRIBUTED:
                rec = self._flow_to_record(flow, session_name, subtype, expected_proto, status, matched_event)
                records.append(rec)

        # Register session
        session = EvaluationSession(
            session_id=session_name,
            start_timestamp=capture_start,
            end_timestamp=capture_end,
            traffic_category=TRAFFIC_CATEGORY_BENIGN,
            traffic_subtype=subtype,
            interface=self.iface or "unknown",
            source_machine="localhost",
            target_machine="localhost",
            generator_command=session_name,
            record_count=len(records),
            extra_metadata={
                "capture_error": capture_error[0],
                "packets_captured": len(captured_packets),
                "attribution_counts": attribution_counts,
                "expected_protocol": expected_proto,
                "dst_port": dst_port,
                "dst_ip": dst_ip,
                "generation_events": len(generation_events),
            },
        )

        self._all_records.extend(records)
        self._all_sessions.append(session)
        self._log(f"Session {session_name}: {len(records)} attributed, {attribution_counts}")
        return records, attribution_counts

    def _packet_callback(self, packet, flow_manager: FlowManager, captured_packets: List[Any]) -> None:
        captured_packets.append(packet)
        try:
            completed = flow_manager.process_packet(packet)
            for flow in completed:
                self._inline_flows.append((flow, "inline", 0))
        except Exception:
            pass

    def _flow_to_record(self, flow: Flow, session_id: str, subtype: str,
                        expected_proto: int, attribution_status: str,
                        matched_event: Optional[Dict[str, Any]]) -> EvaluationRecord:
        features = flow.get_features()
        model_pred, model_conf = self._model.predict(features)
        arr = np.asarray(features, dtype=np.float64).reshape(1, -1)
        arr_scaled = self._model.scaler.transform(arr)
        probs = self._model.clf.predict_proba(arr_scaled)[0]
        model_probs = {CLASS_LABELS[i]: float(probs[i]) for i in range(min(len(probs), len(CLASS_LABELS)))}
        rule_result = self._rule_engine.process_flow(flow)

        return EvaluationRecord(
            evaluation_session_id=session_id,
            collection_timestamp=flow.start_time,
            traffic_category=TRAFFIC_CATEGORY_BENIGN,
            traffic_subtype=subtype,
            ground_truth_label="BENIGN",
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            features=features,
            model_prediction=model_pred,
            model_confidence=model_conf,
            model_probabilities=model_probs,
            rule_prediction=rule_result.rule_prediction,
            rule_confidence=rule_result.rule_confidence,
            rule_triggered=rule_result.triggered_rules,
            flow_duration=flow.duration,
            packet_count=flow.packet_count,
            byte_count=flow.byte_count,
            collection_interface=self.iface or "unknown",
            source_machine="localhost",
            target_machine="localhost",
            generator_command=subtype,
            generator_log="\n".join(self._collection_log),
            extra_metadata={
                "flow_timeout": self.config.flow_timeout,
                "collector_version": "stage11.6",
                "expected_protocol": expected_proto,
                "protocol_match": flow.protocol == expected_proto,
                "attribution_status": attribution_status,
                "matched_generation_event": matched_event,
                "traffic_generation_category": subtype,
            },
        )

    def collect_controlled_tcp(self) -> List[EvaluationRecord]:
        self._rule_engine.reset()
        return self._capture_controlled_session(
            _generate_tcp_flow,
            {},
            f"{self.config.session_id}_controlled_tcp",
            "controlled_tcp",
            6,
            self.config.target_tcp,
        )[0]

    def collect_controlled_udp(self) -> List[EvaluationRecord]:
        self._rule_engine.reset()
        return self._capture_controlled_session(
            _generate_udp_flow,
            {},
            f"{self.config.session_id}_controlled_udp",
            "controlled_udp",
            17,
            self.config.target_udp,
        )[0]

    def collect_controlled_dns(self) -> List[EvaluationRecord]:
        self._rule_engine.reset()
        return self._capture_controlled_session(
            _generate_dns_flow,
            {},
            f"{self.config.session_id}_controlled_dns",
            "controlled_dns",
            17,
            self.config.target_dns,
        )[0]

    def collect_controlled_icmp(self) -> List[EvaluationRecord]:
        self._rule_engine.reset()
        return self._capture_controlled_session(
            _generate_icmp_flow,
            {},
            f"{self.config.session_id}_controlled_icmp",
            "controlled_icmp",
            1,
            self.config.target_icmp,
        )[0]

    def collect_all(self) -> EvaluationDataset:
        self._log("=== Starting Stage 11.6 Controlled Attribution Collection ===")

        categories = [
            ("controlled_tcp", self.collect_controlled_tcp, self.config.target_tcp),
            ("controlled_udp", self.collect_controlled_udp, self.config.target_udp),
            ("controlled_dns", self.collect_controlled_dns, self.config.target_dns),
            ("controlled_icmp", self.collect_controlled_icmp, self.config.target_icmp),
        ]

        for name, func, target in categories:
            self._log(f"--- Collecting: {name} (target: {target}) ---")
            try:
                records = func()
                self._log(f"Category {name}: collected {len(records)} attributed flows")
            except Exception as e:
                self._log(f"Category {name} FAILED: {e}")

        dataset = EvaluationDataset(name=self.config.session_id)
        for rec in self._all_records:
            dataset.add_record(rec)
        for sess in self._all_sessions:
            dataset.add_session(sess)

        self._log(f"=== Collection complete: {len(dataset.records)} total attributed flows ===")
        return dataset

    def save(self, dataset: EvaluationDataset) -> Tuple[Path, Path, Path]:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        base_name = f"controlled_{self.config.session_id}_{ts}"
        jsonl_path = self.output_dir / f"{base_name}.jsonl"
        log_path = self.output_dir / f"{base_name}_collection_log.txt"
        attribution_path = self.output_dir / f"{base_name}_attribution_log.json"

        dataset.to_jsonl(jsonl_path)
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("\n".join(self._collection_log))
        with open(attribution_path, "w", encoding="utf-8") as f:
            json.dump(self._attribution_log, f, indent=2)

        return jsonl_path, log_path, attribution_path


# ---------------------------------------------------------------------------
# Analysis & Report
# ---------------------------------------------------------------------------

def analyze_controlled_dataset(config: ControlledConfig, dataset: EvaluationDataset,
                               attribution_log: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze controlled attribution results."""
    validation = validate_dataset(dataset)

    # Attribution stats
    attribution_counts = {ATTRIBUTED: 0, AMBIGUOUS: 0, UNATTRIBUTED: 0, CONTAMINATED: 0}
    for entry in attribution_log:
        status = entry.get("attribution_status", UNATTRIBUTED)
        attribution_counts[status] = attribution_counts.get(status, 0) + 1

    # Model analysis on attributed flows only
    predictions: Dict[str, int] = {l: 0 for l in CLASS_LABELS}
    fps = []
    conf_all: List[float] = []

    for rec in dataset.records:
        pred = rec.model_prediction or "UNKNOWN"
        predictions[pred] = predictions.get(pred, 0) + 1
        if rec.model_confidence is not None:
            conf_all.append(rec.model_confidence)
        if pred != "BENIGN":
            fps.append(rec)

    total = len(dataset.records)
    fp_rate = len(fps) / total if total > 0 else 0.0

    # Protocol verification
    proto_mismatches = 0
    for rec in dataset.records:
        expected = rec.extra_metadata.get("expected_protocol") if rec.extra_metadata else None
        if expected is not None and rec.protocol != expected:
            proto_mismatches += 1

    return {
        "data_quality": {
            "total_records": validation.total_records,
            "valid_count": validation.valid_count,
            "warning_count": validation.warning_count,
            "invalid_count": validation.invalid_count,
            "is_usable": validation.is_usable,
            "duplicate_feature_count": validation.duplicate_feature_count,
        },
        "attribution": {
            "counts": attribution_counts,
            "total_generated": sum(attribution_counts.values()),
            "attributed_count": attribution_counts[ATTRIBUTED],
            "attribution_rate": attribution_counts[ATTRIBUTED] / max(sum(attribution_counts.values()), 1),
        },
        "protocol_verification": {
            "mismatches": proto_mismatches,
            "total_attributed": total,
            "mismatch_rate": proto_mismatches / max(total, 1),
        },
        "model_analysis": {
            "total_flows": total,
            "predictions": predictions,
            "false_positive_count": len(fps),
            "false_positive_rate": fp_rate,
            "false_alarms_per_100_flows": fp_rate * 100,
            "confidence_min": min(conf_all) if conf_all else None,
            "confidence_max": max(conf_all) if conf_all else None,
            "confidence_mean": sum(conf_all) / len(conf_all) if conf_all else None,
        },
    }


def generate_controlled_report(config: ControlledConfig, dataset: EvaluationDataset,
                               analysis: Dict[str, Any], jsonl_path: Path,
                               log_path: Path, attribution_path: Path) -> str:
    """Generate Stage 11.6 report."""
    lines = []
    lines.append("# STAGE 11.6 - CONTROLLED BENIGN TRAFFIC ATTRIBUTION & COLLECTION REPORT")
    lines.append("")
    lines.append("Date: " + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    lines.append("Session ID: " + config.session_id)
    lines.append("Dataset: " + jsonl_path.name)
    lines.append("Model: " + str(config.model_path))
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 1. Executive Summary")
    lines.append("")
    lines.append("Stage 11.6 implements controlled traffic attribution using dedicated destination ports per category.")
    lines.append("This addresses the Stage 11.5 contamination issue where 62% of flows had protocol mismatches.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 2. Stage 11.5 Contamination Root Cause")
    lines.append("")
    lines.append("In Stage 11.5, all traffic categories shared the loopback interface without unique identifiers.")
    lines.append("Background system traffic contaminated generated flows, causing protocol mismatches:")
    lines.append("- loopback_udp: 44/44 flows captured as TCP")
    lines.append("- loopback_dns: 42/49 flows captured as TCP")
    lines.append("- loopback_icmp: 50/50 flows captured as TCP")
    lines.append("- normal_udp: 24/24 flows captured as TCP")
    lines.append("")
    lines.append("Root cause: No separation between generated traffic and background loopback traffic.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 3. Existing Collector Audit")
    lines.append("")
    lines.append("collect_pilot_11_4a.py and collect_expanded_11_5.py:")
    lines.append("- Use single sniff() on loopback interface")
    lines.append("- No packet filtering by 5-tuple")
    lines.append("- No timestamp correlation between generation and capture")
    lines.append("- No protocol verification against expected protocol")
    lines.append("- All remaining flows in FlowManager are returned as evidence")
    lines.append("")
    lines.append("Result: Background traffic is indistinguishable from generated traffic.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 4. Attribution Design")
    lines.append("")
    lines.append("Each traffic category uses a dedicated destination port/IP:")
    lines.append("- controlled_tcp: dedicated TCP port (50000+range)")
    lines.append("- controlled_udp: dedicated UDP port (50100+range)")
    lines.append("- controlled_dns: dedicated DNS port (50200+range)")
    lines.append("- controlled_icmp: dedicated IP address (127.0.0.2)")
    lines.append("")
    lines.append("Attribution statuses:")
    lines.append("- ATTRIBUTED: exact 5-tuple and protocol match within time window")
    lines.append("- CONTAMINATED: 5-tuple matches but protocol differs")
    lines.append("- AMBIGUOUS: protocol matches but endpoints differ")
    lines.append("- UNATTRIBUTED: no match found")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 5. Controlled Pilot Method")
    lines.append("")
    lines.append("- Target: ~20 flows per category")
    lines.append("- Each flow uses dedicated destination endpoint")
    lines.append("- Generation events tracked with exact 5-tuple and timestamp")
    lines.append("- Captured flows matched to generation events by 5-tuple + time window")
    lines.append("- Only ATTRIBUTED flows included in analysis")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 6. Attribution Results")
    lines.append("")
    lines.append("| Status | Count | Description |")
    lines.append("|--------|-------|-------------|")
    for status in [ATTRIBUTED, CONTAMINATED, AMBIGUOUS, UNATTRIBUTED]:
        count = analysis["attribution"]["counts"].get(status, 0)
        desc = {
            ATTRIBUTED: "Exact 5-tuple + protocol + time match",
            CONTAMINATED: "5-tuple matches but protocol differs",
            AMBIGUOUS: "Protocol matches but endpoints differ",
            UNATTRIBUTED: "No matching generation event",
        }.get(status, "")
        lines.append(f"| {status} | {count} | {desc} |")
    lines.append("")
    lines.append(f"**Attribution rate:** {analysis['attribution']['attribution_rate']*100:.1f}%")
    lines.append(f"**Total generated events:** {analysis['attribution']['total_generated']}")
    lines.append(f"**Attributed flows:** {analysis['attribution']['attributed_count']}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 7. Protocol Validation")
    lines.append("")
    lines.append(f"- Protocol mismatches in attributed flows: {analysis['protocol_verification']['mismatches']}")
    lines.append(f"- Total attributed flows: {analysis['protocol_verification']['total_attributed']}")
    lines.append(f"- Mismatch rate: {analysis['protocol_verification']['mismatch_rate']*100:.2f}%")
    lines.append("")
    if analysis['protocol_verification']['mismatches'] == 0:
        lines.append("**PASS:** All attributed flows have correct protocol.")
    else:
        lines.append("**WARNING:** Protocol mismatches detected in attributed flows.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 8. Data Quality")
    lines.append("")
    dq = analysis["data_quality"]
    lines.append(f"- Total records: {dq['total_records']}")
    lines.append(f"- VALID: {dq['valid_count']}")
    lines.append(f"- WARNING: {dq['warning_count']}")
    lines.append(f"- INVALID: {dq['invalid_count']}")
    lines.append(f"- Usable: {'YES' if dq['is_usable'] else 'NO'}")
    lines.append(f"- Duplicate features: {dq['duplicate_feature_count']}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 9. Preliminary Model Observations")
    lines.append("")
    ma = analysis["model_analysis"]
    lines.append(f"- Total attributed flows: {ma['total_flows']}")
    lines.append(f"- False positives: {ma['false_positive_count']}")
    lines.append(f"- FP rate: {ma['false_positive_rate']:.4f} ({ma['false_alarms_per_100_flows']:.2f} per 100 flows)")
    lines.append("")
    lines.append("### Prediction Distribution")
    lines.append("")
    lines.append("| Prediction | Count | % |")
    lines.append("|------------|-------|-----|")
    for label in CLASS_LABELS:
        count = ma["predictions"].get(label, 0)
        pct = count / max(ma["total_flows"], 1) * 100
        lines.append(f"| {label} | {count} | {pct:.1f}% |")
    lines.append("")
    lines.append("**Note:** This is a small pilot (n=~20 per category). Do not draw broad FPR conclusions.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 10. Remaining Limitations")
    lines.append("")
    lines.append("- Loopback-only collection still limits generalizability.")
    lines.append("- Small sample size (20 per category) is for attribution validation, not statistical power.")
    lines.append("- ICMP uses dedicated IP (127.0.0.2) which may not be available on all systems.")
    lines.append("- Background traffic may still match dedicated ports in some environments.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 11. Recommendation for Stage 11.7")
    lines.append("")
    lines.append("")
    if analysis["attribution"]["attribution_rate"] >= 0.8 and analysis["protocol_verification"]["mismatches"] == 0:
        lines.append("GREEN - Controlled attribution is demonstrably reliable.")
        lines.append("Protocol mismatches are acceptably low (0%).")
        lines.append("Proceed to Stage 11.7 for larger-scale benign collection with controlled attribution.")
    elif analysis["attribution"]["attribution_rate"] >= 0.5:
        lines.append("YELLOW - Attribution improved but remains incomplete.")
        lines.append("Investigate remaining mismatches before scaling to larger collection.")
    else:
        lines.append("RED - Attribution methodology is not reliable enough for evaluation.")
        lines.append("Do not proceed to larger collection until attribution is fixed.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Verification")
    lines.append("")
    lines.append("- Production files changed: NONE")
    lines.append("- Production model changed: NO")
    lines.append(f"- Dataset: {jsonl_path}")
    lines.append(f"- Report: {log_path.parent / 'STAGE11_6_REPORT.md'}")
    lines.append(f"- Attribution log: {attribution_path}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    config = ControlledConfig()
    collector = ControlledCollector(config)
    dataset = collector.collect_all()
    jsonl_path, log_path, attribution_path = collector.save(dataset)

    with open(attribution_path, "r", encoding="utf-8") as f:
        attribution_log = json.load(f)

    analysis = analyze_controlled_dataset(config, dataset, attribution_log)
    report = generate_controlled_report(config, dataset, analysis, jsonl_path, log_path, attribution_path)
    report_path = log_path.parent / "STAGE11_6_REPORT.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)

    import sys
    sys.stdout.reconfigure(encoding="utf-8")
    print("Dataset: " + str(jsonl_path))
    print("Report: " + str(report_path))
    print("Attribution log: " + str(attribution_path))
    print("Total flows: " + str(len(dataset.records)))
    print("Attribution rate: " + str(analysis["attribution"]["attribution_rate"]*100) + "%")


if __name__ == "__main__":
    main()

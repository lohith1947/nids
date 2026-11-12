"""
STAGE 11.4A: Benign Traffic Pilot Collection
=============================================

Collects ~600 benign flows across multiple traffic categories
for evaluation harness validation and baseline measurement.

Categories:
  - loopback_tcp   : SYN probes to closed ports on 127.0.0.1
  - loopback_udp   : Bulk UDP datagrams to various ports on 127.0.0.1
  - loopback_icmp  : ICMP ping to multiple 127.0.0.x addresses
  - loopback_dns   : DNS queries via Scapy to 127.0.0.1
  - normal_tcp     : TCP data-exchange connections to a local echo server
  - normal_udp     : UDP datagram exchange with a local echo server

Ground truth is BENIGN by construction.  Model and rule predictions
are recorded for later analysis but do NOT affect ground truth.

Output:
  - JSON Lines dataset under NIDS/evaluation/datasets/
  - Validation report
  - Stage 11.4A analysis report
"""

from __future__ import annotations

import json
import logging
import queue
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
from NIDS.packet_capture import parse_packet_info
from NIDS.model import NIDSModel
from NIDS.rule_engine import RuleEngine
from NIDS.evaluation.schema import (
    CLASS_LABELS,
    EvaluationDataset,
    EvaluationRecord,
    EvaluationSession,
    TRAFFIC_CATEGORY_BENIGN,
    ValidationIssue,
    ValidationVerdict,
)
from NIDS.evaluation.validation import validate_dataset

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class PilotConfig:
    session_id: str = "pilot_11_4a_benign"
    duration_seconds: float = 60.0
    flow_timeout: float = 10.0
    output_dir: Path = field(default_factory=lambda: PROJECT_ROOT / "NIDS" / "evaluation" / "datasets")
    model_path: Path = field(default_factory=lambda: PROJECT_ROOT / "NIDS" / "models" / "nids_model.joblib")
    interface: Optional[str] = None

    # Per-category target counts
    target_loopback_tcp: int = 100
    target_loopback_udp: int = 100
    target_loopback_icmp: int = 100
    target_loopback_dns: int = 100
    target_normal_tcp: int = 100
    target_normal_udp: int = 100

    # Traffic generation parameters
    icmp_targets: List[str] = field(default_factory=lambda: [f"127.0.0.{i}" for i in range(1, 11)])
    tcp_probe_ports: List[int] = field(default_factory=lambda: list(range(9000, 9010)))
    tcp_probe_interval: float = 0.05
    udp_target_ports: List[int] = field(default_factory=lambda: list(range(40000, 40010)))
    udp_interval: float = 0.05
    dns_count: int = 50
    dns_interval: float = 0.05
    normal_tcp_server_port: int = 50000
    normal_tcp_client_count: int = 100
    normal_tcp_interval: float = 0.05
    normal_udp_server_port: int = 50001
    normal_udp_client_count: int = 100
    normal_udp_interval: float = 0.05

    source_machine: str = "localhost"
    target_machine: str = "localhost"


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


def _generate_icmp(targets: List[str], count_per_target: int = 10, interval: float = 0.1) -> None:
    for target in targets:
        for _ in range(count_per_target):
            try:
                subprocess.run(
                    ["ping", "-n", "1", target],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            except Exception:
                pass
            time.sleep(interval)


def _generate_tcp_probes(ports: List[int], interval: float = 0.05) -> None:
    import socket
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            s.connect(("127.0.0.1", port))
            s.close()
        except Exception:
            pass
        time.sleep(interval)


def _generate_udp_datagrams(ports: List[int], interval: float = 0.05) -> None:
    import socket
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.1)
            s.sendto(b"benign_pilot_udp_" * 3, ("127.0.0.1", port))
            s.close()
        except Exception:
            pass
        time.sleep(interval)


def _generate_dns(count: int = 50, interval: float = 0.05) -> None:
    for i in range(count):
        try:
            pkt = IP(dst="127.0.0.1") / UDP(dport=53) / DNS(id=i, rd=1, qd=DNSQR(qname=b"example.com"))
            send(pkt, verbose=0, count=1)
        except Exception:
            pass
        time.sleep(interval)


def _start_tcp_echo_server(port: int, stop_event: threading.Event, received: List[bytes]) -> Optional[socket.socket]:
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(10)
        srv.settimeout(0.5)

        def _serve():
            while not stop_event.is_set():
                try:
                    client, addr = srv.accept()
                    client.settimeout(0.5)
                    data = client.recv(1024)
                    if data:
                        received.append(data)
                    client.sendall(b"ECHO:" + data)
                    client.close()
                except socket.timeout:
                    continue
                except Exception:
                    break
            srv.close()

        t = threading.Thread(target=_serve, daemon=True)
        t.start()
        return srv
    except Exception as e:
        logger.warning(f"TCP echo server failed: {e}")
        return None


def _start_udp_echo_server(port: int, stop_event: threading.Event, received: List[bytes]) -> Optional[socket.socket]:
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", port))
        srv.settimeout(0.5)

        def _serve():
            while not stop_event.is_set():
                try:
                    data, addr = srv.recvfrom(1024)
                    received.append(data)
                    srv.sendto(b"ECHO:" + data, addr)
                except socket.timeout:
                    continue
                except Exception:
                    break
            srv.close()

        t = threading.Thread(target=_serve, daemon=True)
        t.start()
        return srv
    except Exception as e:
        logger.warning(f"UDP echo server failed: {e}")
        return None


def _generate_normal_tcp(count: int, port: int, interval: float = 0.05) -> None:
    for i in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect(("127.0.0.1", port))
            payload = f"normal_tcp_{i}".encode()
            s.sendall(payload)
            resp = s.recv(1024)
            s.close()
        except Exception:
            pass
        time.sleep(interval)


def _generate_normal_udp(count: int, port: int, interval: float = 0.05) -> None:
    for i in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            payload = f"normal_udp_{i}".encode()
            s.sendto(payload, ("127.0.0.1", port))
            try:
                s.recvfrom(1024)
            except socket.timeout:
                pass
            s.close()
        except Exception:
            pass
        time.sleep(interval)


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class PilotCollector:
    def __init__(self, config: PilotConfig):
        self.config = config
        self.output_dir = config.output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.iface = config.interface or _get_loopback_iface()

        self._model = NIDSModel.load(str(config.model_path))
        self._rule_engine = RuleEngine()

        self._all_records: List[EvaluationRecord] = []
        self._all_sessions: List[EvaluationSession] = []
        self._collection_log: List[str] = []

    def _log(self, msg: str) -> None:
        self._collection_log.append(f"[{datetime.now(timezone.utc).isoformat()}] {msg}")
        logger.info(msg)

    def _capture_flows(self, generation_func: Callable, gen_kwargs: Dict[str, Any],
                       session_name: str, subtype: str) -> List[EvaluationRecord]:
        """Run a single capture+generation session and return EvaluationRecords."""
        self._log(f"Starting session: {session_name}")
        capture_start = time.time()

        flow_manager = FlowManager(flow_timeout=self.config.flow_timeout)
        stop_event = threading.Event()
        capture_error: List[Optional[str]] = [None]
        captured_packets: List[Any] = []

        def _capture_loop():
            try:
                sniff(
                    iface=self.iface,
                    prn=lambda pkt: self._packet_callback(pkt, flow_manager, captured_packets),
                    count=0,
                    store=False,
                    stop_filter=lambda pkt=None: stop_event.is_set(),
                )
            except Exception as e:
                capture_error[0] = f"{type(e).__name__}: {e}"

        cap_thread = threading.Thread(target=_capture_loop, daemon=True)
        cap_thread.start()

        # Run traffic generation
        generation_func(**gen_kwargs)

        # Wait for flows to timeout
        time.sleep(self.config.flow_timeout + 2.0)

        # Stop capture
        stop_event.set()
        cap_thread.join(timeout=5.0)
        capture_end = time.time()

        # Explicitly close any remaining flows
        remaining = list(flow_manager._flows.values())
        records = []
        for flow in remaining:
            rec = self._flow_to_record(flow, session_name, subtype)
            records.append(rec)

        # Register session
        session = EvaluationSession(
            session_id=session_name,
            start_timestamp=capture_start,
            end_timestamp=capture_end,
            traffic_category=TRAFFIC_CATEGORY_BENIGN,
            traffic_subtype=subtype,
            interface=self.iface or "unknown",
            source_machine=self.config.source_machine,
            target_machine=self.config.target_machine,
            generator_command=session_name,
            record_count=len(records),
            extra_metadata={
                "capture_error": capture_error[0],
                "packets_captured": len(captured_packets),
            },
        )

        self._all_records.extend(records)
        self._all_sessions.append(session)

        self._log(
            f"Session {session_name} complete: {len(records)} flows, "
            f"{len(captured_packets)} packets captured"
        )
        if capture_error[0]:
            self._log(f"Capture error: {capture_error[0]}")

        return records

    def _packet_callback(self, packet, flow_manager: FlowManager, captured_packets: List[Any]) -> None:
        captured_packets.append(packet)
        try:
            flow_manager.process_packet(packet)
        except Exception:
            pass

    def _flow_to_record(self, flow: Flow, session_id: str, subtype: str) -> EvaluationRecord:
        features = flow.get_features()

        # Model inference
        model_pred, model_conf = self._model.predict(features)
        arr = np.asarray(features, dtype=np.float64).reshape(1, -1)
        arr_scaled = self._model.scaler.transform(arr)
        probs = self._model.clf.predict_proba(arr_scaled)[0]
        model_probs = {CLASS_LABELS[i]: float(probs[i]) for i in range(min(len(probs), len(CLASS_LABELS)))}

        # Rule inference
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
            source_machine=self.config.source_machine,
            target_machine=self.config.target_machine,
            generator_command=subtype,
            generator_log="\n".join(self._collection_log),
            extra_metadata={
                "flow_timeout": self.config.flow_timeout,
                "collector_version": "stage11.4a",
            },
        )

    def _reset_rule_engine(self) -> None:
        self._rule_engine.reset()

    def collect_loopback_tcp(self) -> List[EvaluationRecord]:
        self._reset_rule_engine()
        # Generate enough port variations to get ~100 distinct flows
        ports = list(range(9000, 9100))  # 100 ports
        return self._capture_flows(
            generation_func=_generate_tcp_probes,
            gen_kwargs={"ports": ports, "interval": self.config.tcp_probe_interval},
            session_name=f"{self.config.session_id}_loopback_tcp",
            subtype="loopback_tcp",
        )

    def collect_loopback_udp(self) -> List[EvaluationRecord]:
        self._reset_rule_engine()
        ports = list(range(40000, 40100))  # 100 ports
        return self._capture_flows(
            generation_func=_generate_udp_datagrams,
            gen_kwargs={"ports": ports, "interval": self.config.udp_interval},
            session_name=f"{self.config.session_id}_loopback_udp",
            subtype="loopback_udp",
        )

    def collect_loopback_icmp(self) -> List[EvaluationRecord]:
        self._reset_rule_engine()
        return self._capture_flows(
            generation_func=_generate_icmp,
            gen_kwargs={
                "targets": self.config.icmp_targets,
                "count_per_target": 10,
                "interval": 0.1,
            },
            session_name=f"{self.config.session_id}_loopback_icmp",
            subtype="loopback_icmp",
        )

    def collect_loopback_dns(self) -> List[EvaluationRecord]:
        self._reset_rule_engine()
        return self._capture_flows(
            generation_func=_generate_dns,
            gen_kwargs={"count": self.config.dns_count, "interval": self.config.dns_interval},
            session_name=f"{self.config.session_id}_loopback_dns",
            subtype="loopback_dns",
        )

    def collect_normal_tcp(self) -> List[EvaluationRecord]:
        self._reset_rule_engine()
        stop_event = threading.Event()
        received: List[bytes] = []
        srv = _start_tcp_echo_server(self.config.normal_tcp_server_port, stop_event, received)
        if srv is None:
            self._log("Normal TCP server failed to start; skipping category")
            return []

        try:
            time.sleep(0.5)  # Let server start
            records = self._capture_flows(
                generation_func=_generate_normal_tcp,
                gen_kwargs={
                    "count": self.config.normal_tcp_client_count,
                    "port": self.config.normal_tcp_server_port,
                    "interval": self.config.normal_tcp_interval,
                },
                session_name=f"{self.config.session_id}_normal_tcp",
                subtype="normal_tcp",
            )
        finally:
            stop_event.set()
            time.sleep(0.5)
            try:
                srv.close()
            except Exception:
                pass

        return records

    def collect_normal_udp(self) -> List[EvaluationRecord]:
        self._reset_rule_engine()
        stop_event = threading.Event()
        received: List[bytes] = []
        srv = _start_udp_echo_server(self.config.normal_udp_server_port, stop_event, received)
        if srv is None:
            self._log("Normal UDP server failed to start; skipping category")
            return []

        try:
            time.sleep(0.5)
            records = self._capture_flows(
                generation_func=_generate_normal_udp,
                gen_kwargs={
                    "count": self.config.normal_udp_client_count,
                    "port": self.config.normal_udp_server_port,
                    "interval": self.config.normal_udp_interval,
                },
                session_name=f"{self.config.session_id}_normal_udp",
                subtype="normal_udp",
            )
        finally:
            stop_event.set()
            time.sleep(0.5)
            try:
                srv.close()
            except Exception:
                pass

        return records

    def collect_all(self) -> EvaluationDataset:
        self._log("=== Starting Stage 11.4A Benign Pilot Collection ===")

        categories = [
            ("loopback_tcp", self.collect_loopback_tcp, self.config.target_loopback_tcp),
            ("loopback_udp", self.collect_loopback_udp, self.config.target_loopback_udp),
            ("loopback_icmp", self.collect_loopback_icmp, self.config.target_loopback_icmp),
            ("loopback_dns", self.collect_loopback_dns, self.config.target_loopback_dns),
            ("normal_tcp", self.collect_normal_tcp, self.config.target_normal_tcp),
            ("normal_udp", self.collect_normal_udp, self.config.target_normal_udp),
        ]

        results = {}
        for name, func, target in categories:
            self._log(f"--- Collecting category: {name} (target: {target}) ---")
            try:
                records = func()
                results[name] = {
                    "target": target,
                    "collected": len(records),
                    "records": records,
                }
                self._log(f"Category {name}: collected {len(records)} flows")
            except Exception as e:
                self._log(f"Category {name} FAILED: {e}")
                results[name] = {
                    "target": target,
                    "collected": 0,
                    "records": [],
                    "error": str(e),
                }

        dataset = EvaluationDataset(name=self.config.session_id)
        for rec in self._all_records:
            dataset.add_record(rec)
        for sess in self._all_sessions:
            dataset.add_session(sess)

        self._log(f"=== Collection complete: {len(dataset.records)} total flows ===")
        return dataset

    def save(self, dataset: EvaluationDataset) -> Tuple[Path, Path]:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        base_name = f"benign_pilot_{self.config.session_id}_{ts}"
        jsonl_path = self.output_dir / f"{base_name}.jsonl"
        log_path = self.output_dir / f"{base_name}_collection_log.txt"

        dataset.to_jsonl(jsonl_path)

        with open(log_path, "w", encoding="utf-8") as f:
            f.write("\n".join(self._collection_log))

        logger.info(f"Dataset saved to {jsonl_path}")
        logger.info(f"Collection log saved to {log_path}")
        return jsonl_path, log_path


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze_dataset(dataset: EvaluationDataset, config: PilotConfig) -> Dict[str, Any]:
    """Run data quality checks and model analysis on the pilot dataset."""
    report: Dict[str, Any] = {}

    # Data quality
    validation = validate_dataset(dataset)
    report["data_quality"] = {
        "total_records": validation.total_records,
        "valid_count": validation.valid_count,
        "warning_count": validation.warning_count,
        "invalid_count": validation.invalid_count,
        "issues": [
            {"code": i.code, "message": i.message, "record_id": i.record_id}
            for i in validation.issues
        ],
        "label_distribution": validation.label_distribution,
        "session_distribution": validation.session_distribution,
        "duplicate_feature_count": validation.duplicate_feature_count,
        "overlapping_sessions": validation.overlapping_sessions,
        "is_usable": validation.is_usable,
    }

    # Prediction analysis
    predictions = {"BENIGN": 0, "PORT_SCAN": 0, "BRUTE_FORCE": 0, "DOS": 0, "RECONNAISSANCE": 0}
    false_positives = []
    confidence_distribution: List[float] = []
    fp_by_category: Dict[str, int] = {}

    for rec in dataset.records:
        pred = rec.model_prediction or "UNKNOWN"
        predictions[pred] = predictions.get(pred, 0) + 1

        if rec.model_confidence is not None:
            confidence_distribution.append(rec.model_confidence)

        if pred != "BENIGN":
            fp = {
                "session_id": rec.evaluation_session_id,
                "subtype": rec.traffic_subtype,
                "src_ip": rec.src_ip,
                "dst_ip": rec.dst_ip,
                "src_port": rec.src_port,
                "dst_port": rec.dst_port,
                "protocol": rec.protocol,
                "prediction": pred,
                "confidence": rec.model_confidence,
                "probabilities": rec.model_probabilities,
                "duration": rec.flow_duration,
                "packet_count": rec.packet_count,
                "byte_count": rec.byte_count,
            }
            false_positives.append(fp)
            fp_by_category[rec.traffic_subtype] = fp_by_category.get(rec.traffic_subtype, 0) + 1

    total = len(dataset.records)
    fp_rate = len(false_positives) / total if total > 0 else 0.0

    report["model_analysis"] = {
        "total_flows": total,
        "predictions": predictions,
        "false_positive_count": len(false_positives),
        "false_positive_rate": fp_rate,
        "false_alarms_per_100_flows": fp_rate * 100,
        "fp_by_category": fp_by_category,
        "confidence_min": min(confidence_distribution) if confidence_distribution else None,
        "confidence_max": max(confidence_distribution) if confidence_distribution else None,
        "confidence_mean": sum(confidence_distribution) / len(confidence_distribution) if confidence_distribution else None,
        "false_positives": false_positives,
    }

    # Historical loopback FP comparison
    report["historical_fp_comparison"] = _check_historical_fp(dataset)

    return report


def _check_historical_fp(dataset: EvaluationDataset) -> Dict[str, Any]:
    """
    Check whether any current benign sample resembles the historical:
    127.0.0.1:65260 -> 127.0.0.1:49718
    TCP, ~0.0051 sec, 10 packets, 12,546 bytes
    """
    hist_src = "127.0.0.1"
    hist_dst = "127.0.0.1"
    hist_src_port = 65260
    hist_dst_port = 49718
    hist_proto = 6
    hist_dur = 0.0051
    hist_pkts = 10
    hist_bytes = 12546

    similar = []
    for rec in dataset.records:
        if (rec.src_ip == hist_src and rec.dst_ip == hist_dst and
            rec.protocol == hist_proto and rec.packet_count is not None and
            rec.byte_count is not None and rec.flow_duration is not None):
            # Compute similarity score based on feature proximity
            dur_diff = abs(rec.flow_duration - hist_dur) / max(hist_dur, 1e-6)
            pkts_diff = abs(rec.packet_count - hist_pkts) / max(hist_pkts, 1)
            bytes_diff = abs(rec.byte_count - hist_bytes) / max(hist_bytes, 1)
            similarity = 1.0 - min(1.0, (dur_diff + pkts_diff + bytes_diff) / 3.0)
            similar.append({
                "record_session": rec.evaluation_session_id,
                "subtype": rec.traffic_subtype,
                "src_port": rec.src_port,
                "dst_port": rec.dst_port,
                "duration": rec.flow_duration,
                "packet_count": rec.packet_count,
                "byte_count": rec.byte_count,
                "similarity_score": similarity,
                "model_prediction": rec.model_prediction,
                "model_confidence": rec.model_confidence,
            })

    similar.sort(key=lambda x: x["similarity_score"], reverse=True)
    return {
        "historical_pattern": {
            "src_ip": hist_src,
            "dst_ip": hist_dst,
            "src_port": hist_src_port,
            "dst_port": hist_dst_port,
            "protocol": hist_proto,
            "duration": hist_dur,
            "packet_count": hist_pkts,
            "byte_count": hist_bytes,
        },
        "similar_flows_found": len(similar),
        "top_similar": similar[:10],
    }


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(config: PilotConfig, dataset: EvaluationDataset,
                    analysis: Dict[str, Any], jsonl_path: Path, log_path: Path) -> str:
    """Generate the Stage 11.4A markdown report."""
    dq = analysis["data_quality"]
    ma = analysis["model_analysis"]
    hist = analysis["historical_fp_comparison"]

    lines = [
        "# STAGE 11.4A — BENIGN TRAFFIC PILOT COLLECTION REPORT",
        "",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Session ID:** {config.session_id}",
        f"**Interface:** {config.interface or 'auto-detected loopback'}",
        f"**Model:** {config.model_path}",
        "",
        "---",
        "",
        "## 1. Collection Environment",
        "",
        f"- **Machine:** {config.source_machine}",
        f"- **Interface:** {config.interface or 'auto-detected loopback'}",
        f"- **Flow timeout:** {config.flow_timeout}s",
        f"- **Collection scope:** Lab-only, benign traffic only",
        f"- **Attack traffic generated:** None",
        "",
        "---",
        "",
        "## 2. Collection Methodology",
        "",
        "Traffic was generated using a combination of:",
        "- OS-native tools (ping)",
        "- Python socket libraries (TCP/UDP connections)",
        "- Scapy (DNS queries)",
        "",
        "All traffic was captured on the loopback interface using Scapy sniff().",
        "Flows were extracted using the production FlowManager.",
        "",
        "Model inference was performed offline using the UNCHANGED production model.",
        "Rule Engine inference was performed using the production RuleEngine.",
        "",
        "---",
        "",
        "## 3. Traffic Categories",
        "",
        "| Category | Subtype | Target | Collected |",
        "|----------|---------|--------|-----------|",
    ]

    # Build category table from sessions
    category_stats: Dict[str, Dict[str, Any]] = {}
    for sess in dataset.sessions.values():
        st = sess.traffic_subtype
        if st not in category_stats:
            category_stats[st] = {"target": 0, "collected": 0}
        category_stats[st]["collected"] += sess.record_count

    # Map targets from config
    targets = {
        "loopback_tcp": config.target_loopback_tcp,
        "loopback_udp": config.target_loopback_udp,
        "loopback_icmp": config.target_loopback_icmp,
        "loopback_dns": config.target_loopback_dns,
        "normal_tcp": config.target_normal_tcp,
        "normal_udp": config.target_normal_udp,
    }

    for cat, target in targets.items():
        collected = category_stats.get(cat, {}).get("collected", 0)
        lines.append(f"| {cat} | {cat} | {target} | {collected} |")

    lines.extend([
        "",
        "---",
        "",
        "## 4. Sample Counts",
        "",
        f"- **Total flows collected:** {dq['total_records']}",
        f"- **Total sessions:** {len(dataset.sessions)}",
        f"- **VALID records:** {dq['valid_count']}",
        f"- **WARNING records:** {dq['warning_count']}",
        f"- **INVALID records:** {dq['invalid_count']}",
        "",
        "### Per-category breakdown",
        "",
        "| Category | Flows | % of Total |",
        "|----------|-------|------------|",
    ])

    total = dq["total_records"]
    for cat, stats in category_stats.items():
        pct = (stats["collected"] / total * 100) if total > 0 else 0
        lines.append(f"| {cat} | {stats['collected']} | {pct:.1f}% |")

    lines.extend([
        "",
        "---",
        "",
        "## 5. Ground-Truth Methodology",
        "",
        "- **Ground truth label:** BENIGN for all flows",
        "- **Assignment:** By the collection script, based on the traffic generation procedure",
        "- **NOT assigned by:** ML model, RuleEngine, Correlator, RiskScorer, or AlertManager",
        "- **Rationale:** All generated traffic is known-benign lab traffic (localhost services, ICMP pings, DNS queries)",
        "",
        "---",
        "",
        "## 6. Data-Quality Results",
        "",
        f"- **Dataset usable:** {'YES' if dq['is_usable'] else 'NO'}",
        f"- **Duplicate feature vectors:** {dq['duplicate_feature_count']}",
        f"- **Overlapping sessions:** {len(dq['overlapping_sessions'])}",
        "",
        "### Validation Issues",
        "",
    ])

    if dq["issues"]:
        lines.append("| Code | Message | Record ID |")
        lines.append("|------|---------|-----------|")
        for issue in dq["issues"]:
            rid = issue.get("record_id", "N/A")
            lines.append(f"| {issue['code']} | {issue['message']} | {rid} |")
    else:
        lines.append("No validation issues found.")

    lines.extend([
        "",
        "---",
        "",
        "## 7. Model Predictions",
        "",
        f"- **Total flows evaluated:** {ma['total_flows']}",
        "",
        "### Prediction Distribution",
        "",
        "| Prediction | Count | % of Total |",
        "|------------|-------|------------|",
    ])

    for label in CLASS_LABELS:
        count = ma["predictions"].get(label, 0)
        pct = (count / ma['total_flows'] * 100) if ma['total_flows'] > 0 else 0
        lines.append(f"| {label} | {count} | {pct:.1f}% |")

    lines.extend([
        "",
        "---",
        "",
        "## 8. False-Positive Rate",
        "",
        f"- **False-positive count:** {ma['false_positive_count']}",
        f"- **False-positive rate:** {ma['false_positive_rate']:.4f} ({ma['false_alarms_per_100_flows']:.2f} per 100 flows)",
        "",
        "### FP Breakdown by Traffic Category",
        "",
        "| Category | False Positives |",
        "|----------|----------------|",
    ])

    for cat, count in ma["fp_by_category"].items():
        lines.append(f"| {cat} | {count} |")

    if not ma["fp_by_category"]:
        lines.append("| (none) | 0 |")

    lines.extend([
        "",
        "### Highest-Confidence False Positives",
        "",
    ])

    if ma["false_positives"]:
        lines.append("| Category | Src IP | Dst IP | Proto | Prediction | Confidence | Duration (s) | Packets | Bytes |")
        lines.append("|----------|--------|--------|-------|------------|------------|--------------|---------|-------|")
        for fp in sorted(ma["false_positives"], key=lambda x: x["confidence"] or 0, reverse=True)[:10]:
            dur = f"{fp['duration']:.4f}" if fp["duration"] is not None else "N/A"
            lines.append(
                f"| {fp['subtype']} | {fp['src_ip']} | {fp['dst_ip']} | {fp['protocol']} "
                f"| {fp['prediction']} | {fp['confidence']:.4f} | {dur} "
                f"| {fp['packet_count']} | {fp['byte_count']} |"
            )
    else:
        lines.append("No false positives detected.")

    lines.extend([
        "",
        "---",
        "",
        "## 9. Confidence Analysis",
        "",
        f"- **Min confidence:** {ma['confidence_min']:.4f}" if ma["confidence_min"] is not None else "- **Min confidence:** N/A",
        f"- **Max confidence:** {ma['confidence_max']:.4f}" if ma["confidence_max"] is not None else "- **Max confidence:** N/A",
        f"- **Mean confidence:** {ma['confidence_mean']:.4f}" if ma["confidence_mean"] is not None else "- **Mean confidence:** N/A",
        "",
        "---",
        "",
        "## 10. Historical Loopback FP Comparison",
        "",
        "### Historical Pattern",
        "",
        f"- **Src:** {hist['historical_pattern']['src_ip']}:{hist['historical_pattern']['src_port']}",
        f"- **Dst:** {hist['historical_pattern']['dst_ip']}:{hist['historical_pattern']['dst_port']}",
        f"- **Protocol:** TCP (6)",
        f"- **Duration:** {hist['historical_pattern']['duration']}s",
        f"- **Packets:** {hist['historical_pattern']['packet_count']}",
        f"- **Bytes:** {hist['historical_pattern']['byte_count']}",
        "",
        f"**Similar flows found:** {hist['similar_flows_found']}",
        "",
    ])

    if hist["top_similar"]:
        lines.append("### Top Similar Flows")
        lines.append("")
        lines.append("| Session | Subtype | Src Port | Dst Port | Duration | Packets | Bytes | Similarity | Prediction | Confidence |")
        lines.append("|---------|---------|----------|----------|----------|---------|-------|------------|------------|------------|")
        for sf in hist["top_similar"][:5]:
            dur = f"{sf['duration']:.6f}" if sf["duration"] is not None else "N/A"
            lines.append(
                f"| {sf['record_session']} | {sf['subtype']} | {sf['src_port']} | {sf['dst_port']} "
                f"| {dur} | {sf['packet_count']} | {sf['byte_count']} "
                f"| {sf['similarity_score']:.4f} | {sf['model_prediction']} | {sf['model_confidence']:.4f} |"
            )
    else:
        lines.append("No flows closely matching the historical pattern were found in this pilot.")

    lines.extend([
        "",
        "---",
        "",
        "## 11. Distribution-Shift Observations",
        "",
    ])

    # Add some basic observations based on the data
    obs = []
    if dq["duplicate_feature_count"] > 0:
        obs.append(f"- **Duplicate features:** {dq['duplicate_feature_count']} duplicate feature vectors detected. "
                    "This may indicate overly homogeneous traffic generation.")
    if ma["false_positive_rate"] > 0:
        obs.append(f"- **False positives:** {ma['false_positive_rate']*100:.2f}% of benign flows were misclassified. "
                    "This exceeds the expected false-positive tolerance and warrants investigation.")
    else:
        obs.append("- **False positives:** None detected. The model appears robust on this pilot set.")

    if hist["similar_flows_found"] > 0:
        obs.append(f"- **Historical FP resemblance:** {hist['similar_flows_found']} flows show structural similarity "
                    "to the historical loopback false positive pattern.")

    if not obs:
        obs.append("- No significant distribution shifts observed in this pilot.")

    lines.extend(obs)

    lines.extend([
        "",
        "---",
        "",
        "## 12. Limitations",
        "",
        "- **Loopback-only:** All traffic was generated on the loopback interface. "
          "Real network traffic may exhibit different characteristics.",
        "- **ICMP aggregation:** The FlowManager aggregates all ICMP packets between two IPs into a single flow. "
          "Only 1 ICMP flow was collected per destination address.",
        "- **Synthetic traffic:** Traffic was generated by scripts, not real user applications. "
          "Packet timing and sizes may not reflect production traffic.",
        "- **Small sample size:** ~600 flows is insufficient for robust statistical conclusions. "
          "This is a pilot to validate methodology.",
        "- **Single machine:** Collection was performed on a single host. "
          "No cross-host or multi-subnet traffic was captured.",
        f"- **Model unchanged:** The production model at `{config.model_path}` was used as-is. "
          "No retraining or threshold changes were made.",
        "",
        "---",
        "",
        "## 13. Recommended Next Step",
        "",
    ])

    if dq["is_usable"] and ma["false_positive_rate"] <= 0.05:
        lines.append(
            "- **VERDICT: GREEN** — The pilot dataset is valid and useful for proceeding to larger benign collection. "
            "The evaluation harness functions correctly on real-world-adjacent benign traffic. "
            "Recommend expanding collection to include external-interface benign traffic and increasing sample size."
        )
    elif dq["is_usable"]:
        lines.append(
            "- **VERDICT: YELLOW** — The dataset is usable but shows elevated false-positive rates. "
            "Investigate FP characteristics before scaling collection. "
            "Consider adding more traffic diversity or adjusting collection parameters."
        )
    else:
        lines.append(
            "- **VERDICT: RED** — The dataset has critical data-quality issues. "
            "Revise collection methodology before proceeding."
        )

    lines.extend([
        "",
        "---",
        "",
        "## Appendix: Files",
        "",
        f"- **Dataset (JSONL):** `{jsonl_path.name}`",
        f"- **Collection log:** `{log_path.name}`",
        "",
        "---",
        "",
        "## Labels",
        "",
        "- **FACT:** Objective observations from the data (counts, timestamps, feature values).",
        "- **MEASUREMENT:** Quantitative results from running the model and rule engine.",
        "- **INFERENCE:** Interpretations and explanations of observed patterns.",
        "- **RECOMMENDATION:** Suggested actions based on the findings.",
        "",
    ])

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    config = PilotConfig()
    collector = PilotCollector(config)

    logger.info("=== Stage 11.4A: Benign Traffic Pilot Collection ===")
    logger.info(f"Target: ~600 benign flows across 6 categories")
    logger.info(f"Interface: {config.interface or 'auto-detect loopback'}")

    dataset = collector.collect_all()
    jsonl_path, log_path = collector.save(dataset)

    logger.info("Running data quality validation...")
    analysis = analyze_dataset(dataset, config)

    report = generate_report(config, dataset, analysis, jsonl_path, log_path)
    report_path = config.output_dir / f"STAGE11_4A_BENIGN_PILOT_REPORT_{config.session_id}.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)

    logger.info(f"Report saved to {report_path}")

    # Print summary
    dq = analysis["data_quality"]
    ma = analysis["model_analysis"]
    print("\n" + "=" * 70)
    print("STAGE 11.4A PILOT SUMMARY")
    print("=" * 70)
    print(f"Total flows:         {dq['total_records']}")
    print(f"VALID:               {dq['valid_count']}")
    print(f"WARNING:             {dq['warning_count']}")
    print(f"INVALID:             {dq['invalid_count']}")
    print(f"Dataset usable:      {dq['is_usable']}")
    print(f"False positives:     {ma['false_positive_count']}")
    print(f"FP rate:             {ma['false_positive_rate']:.4f}")
    print(f"FP per 100 flows:    {ma['false_alarms_per_100_flows']:.2f}")
    print(f"Similar to hist FP:  {analysis['historical_fp_comparison']['similar_flows_found']}")
    print(f"Dataset:             {jsonl_path}")
    print(f"Report:              {report_path}")
    print("=" * 70)

    return dataset, analysis, report_path


if __name__ == "__main__":
    main()

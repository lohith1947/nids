#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Stage 11.8.2 — Evaluation Fidelity Upgrade
Scapy-based packet capture + production FlowManager for real TCP flag evidence.
"""

import os
import sys
import json
import time
import socket
import random
import hashlib
import threading
import logging
import statistics
import csv
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional
from collections import defaultdict, Counter

sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, PROJECT_ROOT)

# ---------------------------------------------------------------------------
# Lazy imports.
#
# Generator mode (--mode generator) must run on Kali WITHOUT the production
# NIDS package or the frozen model.  All non-stdlib imports that the four
# traffic generators actually need are stdlib (socket, os, random, time).
#
# Every production/scapy import is deferred to the methods that genuinely
# require it, so importing this module on Kali never touches NIDS.* or
# scapy sniffing.
# ---------------------------------------------------------------------------

REPORT_DIR = os.path.join(os.path.dirname(__file__), "datasets")
os.makedirs(REPORT_DIR, exist_ok=True)

MODEL_PATH = os.path.join(PROJECT_ROOT, "NIDS", "models", "nids_model.joblib")
DEFAULT_INTERFACE = "Loopback Pseudo-Interface 1"
FLOW_TIMEOUT = 8.0

SERVICE_PORTS = {20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 5900, 6667}


def _is_loopback_interface(interface: str) -> bool:
    if not interface:
        return False
    lower = interface.lower()
    return "loopback" in lower or lower.startswith("lo") or "127.0.0.1" in lower


def _validate_non_loopback_config(interface: str, target_ip: str, recon_target_ips: List[str]) -> None:
    if _is_loopback_interface(interface):
        return
    if target_ip == "127.0.0.1" or target_ip.startswith("127."):
        raise ValueError(
            f"Non-loopback interface '{interface}' selected but target_ip is loopback ({target_ip}). "
            "Provide a non-loopback target IP for Stage 11.8.7."
        )
    for ip in recon_target_ips:
        if ip == "127.0.0.1" or ip.startswith("127."):
            raise ValueError(
                f"Non-loopback interface '{interface}' selected but recon target {ip} is loopback. "
                "Provide non-loopback target IPs for Stage 11.8.7."
            )


# ---------------------------------------------------------------------------
# Lazy import helpers.
#
# These are invoked ONLY by code paths that need the production NIDS package
# or Scapy sniffing (i.e. full/legacy capture mode).  Generator mode never
# calls them, so importing this module on Kali never loads NIDS.* or scapy.
# ---------------------------------------------------------------------------

def _import_scapy():
    """Import scapy symbols.  Called only by capture paths, never by generators."""
    from scapy.all import sniff, IP, TCP, UDP
    return sniff, IP, TCP, UDP


def _import_schema():
    """Import evaluation schema.  stdlib-only; safe to call from any path."""
    from NIDS.evaluation.schema import (
        CLASS_LABELS,
        EvaluationDataset,
        EvaluationRecord,
        EvaluationSession,
        TRAFFIC_CATEGORY_ATTACK,
    )
    return (
        CLASS_LABELS,
        EvaluationDataset,
        EvaluationRecord,
        EvaluationSession,
        TRAFFIC_CATEGORY_ATTACK,
    )


class _GeneratorDataset:
    """Minimal stand-in for EvaluationDataset used ONLY by generator mode.

    Generator mode produces no records and never needs the schema module,
    so this keeps the module importable on Kali without the NIDS package.
    Exposes the same `.records` / `.sessions` attributes used by callers
    and tests, defaulting to empty lists.
    """

    def __init__(self, name: str = "stage_11_8_7_generator_only"):
        self.name = name
        self.records = []
        self.sessions = []

    def add_record(self, record):
        self.records.append(record)

    def add_session(self, session):
        self.sessions.append(session)


def _import_scapy_and_pipeline():
    """Import scapy + production pipeline in one shot.

    Only called by full/legacy capture mode.  Generator mode never calls
    this, so importing this module on Kali never loads NIDS.* or scapy.
    """
    sniff, IP, TCP, UDP = _import_scapy()
    (
        Flow,
        FlowManager,
        NIDSModel,
        RuleEngine,
        BENIGN,
        PORT_SCAN,
        BRUTE_FORCE,
        DOS,
        RECONNAISSANCE,
        CorrelationEngine,
        RiskScorer,
        AlertManager,
        AlertManagerConfig,
    ) = _import_pipeline()
    (
        CLASS_LABELS,
        EvaluationDataset,
        EvaluationRecord,
        EvaluationSession,
        TRAFFIC_CATEGORY_ATTACK,
    ) = _import_schema()
    return (
        sniff,
        IP,
        TCP,
        UDP,
        Flow,
        FlowManager,
        NIDSModel,
        RuleEngine,
        BENIGN,
        PORT_SCAN,
        BRUTE_FORCE,
        DOS,
        RECONNAISSANCE,
        CorrelationEngine,
        RiskScorer,
        AlertManager,
        AlertManagerConfig,
        CLASS_LABELS,
        EvaluationDataset,
        EvaluationRecord,
        EvaluationSession,
        TRAFFIC_CATEGORY_ATTACK,
    )


def _import_pipeline():
    """Import production pipeline components.  Called only by full mode."""
    from NIDS.flow import Flow
    from NIDS.flow_manager import FlowManager
    from NIDS.model import NIDSModel
    from NIDS.rule_engine import RuleEngine, BENIGN, PORT_SCAN, BRUTE_FORCE, DOS, RECONNAISSANCE
    from NIDS.correlator import CorrelationEngine
    from NIDS.risk_scorer import RiskScorer
    from NIDS.alerts import AlertManager, AlertManagerConfig
    return (
        Flow,
        FlowManager,
        NIDSModel,
        RuleEngine,
        BENIGN,
        PORT_SCAN,
        BRUTE_FORCE,
        DOS,
        RECONNAISSANCE,
        CorrelationEngine,
        RiskScorer,
        AlertManager,
        AlertManagerConfig,
    )


def model_hash(path):
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()[:16]


# ============================================================================
# Attack generators (improved with diversity)
# ============================================================================

def generate_port_scan(target_ip, target_ports, count_per_port, interval, payload_size=64):
    """Generate TCP connection attempts to many ports with varied payloads."""
    random.shuffle(target_ports)
    for port in target_ports:
        for i in range(count_per_port):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            try:
                s.connect((target_ip, port))
                payload = os.urandom(random.randint(4, payload_size))
                s.sendall(payload)
                try:
                    s.recv(1024)
                except socket.timeout:
                    pass
            except Exception:
                pass
            finally:
                try:
                    s.close()
                except Exception:
                    pass
            time.sleep(interval + random.uniform(-0.005, 0.005))


def generate_brute_force(target_ip, target_port, count, interval, payload_size=64):
    """Generate repeated short connections to same service port."""
    for i in range(count):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        try:
            s.connect((target_ip, target_port))
            payload = os.urandom(random.randint(4, payload_size))
            s.sendall(payload)
            try:
                s.recv(1024)
            except socket.timeout:
                pass
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
        time.sleep(interval + random.uniform(-0.005, 0.005))


def generate_dos_udp(target_ip, target_port, packets_per_flow, flows, interval_between_flows, payload_size=64):
    """Generate high-rate UDP traffic from distinct sockets."""
    for f in range(flows):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", 0))
        s.settimeout(0.5)
        try:
            for p in range(packets_per_flow):
                payload = os.urandom(random.randint(32, payload_size))
                s.sendto(payload, (target_ip, target_port))
                if p % 100 == 0:
                    time.sleep(0.001)
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
        time.sleep(interval_between_flows)


def generate_reconnaissance(target_ips, target_port, count_per_ip, interval, payload_size=64):
    """Generate connections to many different destination IPs in randomized order."""
    ips = target_ips.copy()
    random.shuffle(ips)
    for ip in ips:
        for i in range(count_per_ip):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            try:
                s.connect((ip, target_port))
                payload = os.urandom(random.randint(4, payload_size))
                s.sendall(payload)
                try:
                    s.recv(1024)
                except socket.timeout:
                    pass
            except Exception:
                pass
            finally:
                try:
                    s.close()
                except Exception:
                    pass
            time.sleep(interval + random.uniform(-0.005, 0.005))


# ============================================================================
# Server threads for local targets
# ============================================================================

def tcp_server_thread(port, ip, stop_event, ready_event):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((ip, port))
        sock.listen(20)
        sock.settimeout(0.5)
        ready_event.set()
        while not stop_event.is_set():
            try:
                client, addr = sock.accept()
                client.settimeout(0.5)
                client_ip, client_port = addr
                try:
                    while True:
                        chunk = client.recv(4096)
                        if not chunk:
                            break
                        try:
                            client.sendall(b"ECHO")
                        except Exception:
                            pass
                except socket.timeout:
                    pass
                except Exception:
                    pass
                try:
                    client.close()
                except Exception:
                    pass
            except socket.timeout:
                continue
            except Exception:
                if not stop_event.is_set():
                    time.sleep(0.1)
    except OSError as e:
        logger.error(f"TCP server bind failed for {ip}:{port}: {e}")
    finally:
        ready_event.set()
        try:
            sock.close()
        except Exception:
            pass


def udp_server_thread(port, ip, stop_event, ready_event):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((ip, port))
        sock.settimeout(0.5)
        ready_event.set()
        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(65536)
                try:
                    sock.sendto(b"ECHO", addr)
                except Exception:
                    pass
            except socket.timeout:
                continue
            except Exception:
                if not stop_event.is_set():
                    time.sleep(0.1)
    except OSError as e:
        logger.error(f"UDP server bind failed for {ip}:{port}: {e}")
    finally:
        ready_event.set()
        try:
            sock.close()
        except Exception:
            pass


# ============================================================================
# Scapy-based capture collector
# ============================================================================

class ScapyCaptureCollector:
    def __init__(
        self,
        interface: str = DEFAULT_INTERFACE,
        target_ip: str = "127.0.0.1",
        recon_target_ips: Optional[List[str]] = None,
        source_machine: str = "localhost",
        target_machine: str = "localhost",
        mode: str = "full",
    ):
        if mode not in ("generator", "listener", "full"):
            raise ValueError(f"Invalid mode '{mode}'. Must be 'generator', 'listener', or 'full'.")

        self.interface = interface
        self.target_ip = target_ip
        self.recon_target_ips = recon_target_ips or ["127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5", "127.0.0.6"]
        self.source_machine = source_machine
        self.target_machine = target_machine
        self.mode = mode

        _validate_non_loopback_config(self.interface, self.target_ip, self.recon_target_ips)

        self.records = []
        self.sessions = []
        self.logs = []
        self.attribution_log = []
        self.latencies = []
        self.failed_generations = []
        self.packet_count = 0
        self.capture_error = None
        self.stop_capture = threading.Event()
        self.flow_manager = None
        self.rule_engine = None
        self.correlation_engine = None
        self.risk_scorer = None
        self.alert_manager = None
        self.model = None

        # Pipeline objects are created lazily only for modes that require them.
        # Generator mode never needs the production NIDS package or frozen model.
        if self.mode != "generator":
            self._init_pipeline()

    def _init_pipeline(self):
        """Initialize NIDS pipeline components.

        Only called for modes that actually run the pipeline (full mode).
        Generator mode never invokes this, so it can run on Kali without
        the production NIDS package or the frozen model.
        """
        (
            Flow,
            FlowManager,
            NIDSModel,
            RuleEngine,
            _BENIGN,
            _PORT_SCAN,
            _BRUTE_FORCE,
            _DOS,
            _RECONNAISSANCE,
            CorrelationEngine,
            RiskScorer,
            AlertManager,
            _AlertManagerConfig,
        ) = _import_pipeline()

        self.model = NIDSModel.load(MODEL_PATH)
        self.rule_engine = RuleEngine()
        self.correlation_engine = CorrelationEngine(model_path=MODEL_PATH)
        self.risk_scorer = RiskScorer()
        self.alert_manager = AlertManager()

    def log(self, msg):
        self.logs.append(f"[{datetime.now(timezone.utc).isoformat()}] {msg}")
        logger.info(msg)

    def _packet_callback(self, packet):
        if self.capture_error:
            return
        try:
            _sniff, IP, _TCP, _UDP = _import_scapy()
            if IP not in packet:
                return
            if packet[IP].proto not in (6, 17):
                return
            self.packet_count += 1
            if self.flow_manager is not None:
                self.flow_manager.process_packet(packet)
        except Exception as e:
            self.capture_error = f"{type(e).__name__}: {e}"

    def _start_servers(self, attack_class, generator_kwargs):
        servers = []
        stop_event = threading.Event()
        ready_events = []

        if attack_class == "PORT_SCAN":
            for port in generator_kwargs["target_ports"]:
                ready = threading.Event()
                t = threading.Thread(
                    target=tcp_server_thread,
                    args=(port, generator_kwargs["target_ip"], stop_event, ready),
                    daemon=True
                )
                t.start()
                servers.append((port, t, stop_event))
                ready_events.append(ready)

        elif attack_class == "BRUTE_FORCE":
            ready = threading.Event()
            t = threading.Thread(
                target=tcp_server_thread,
                args=(generator_kwargs["target_port"], generator_kwargs["target_ip"], stop_event, ready),
                daemon=True
            )
            t.start()
            servers.append((generator_kwargs["target_port"], t, stop_event))
            ready_events.append(ready)

        elif attack_class == "DOS":
            ready = threading.Event()
            if generator_kwargs.get("protocol") == "udp":
                t = threading.Thread(
                    target=udp_server_thread,
                    args=(generator_kwargs["target_port"], generator_kwargs["target_ip"], stop_event, ready),
                    daemon=True
                )
            else:
                t = threading.Thread(
                    target=tcp_server_thread,
                    args=(generator_kwargs["target_port"], generator_kwargs["target_ip"], stop_event, ready),
                    daemon=True
                )
            t.start()
            servers.append((generator_kwargs["target_port"], t, stop_event))
            ready_events.append(ready)

        elif attack_class == "RECONNAISSANCE":
            for ip in generator_kwargs["target_ips"]:
                ready = threading.Event()
                t = threading.Thread(
                    target=tcp_server_thread,
                    args=(generator_kwargs["target_port"], ip, stop_event, ready),
                    daemon=True
                )
                t.start()
                servers.append((ip, t, stop_event))
                ready_events.append(ready)

        return servers, ready_events, stop_event

    def _run_pipeline(self, flow, attack_class, first_packet_ts, alert_ts):
        features = flow.get_features()
        rule_result = self.rule_engine.process_flow(flow)
        detection = self.correlation_engine.correlate(features, rule_result)
        risk_result = self.risk_scorer.score(detection)
        alert = self.alert_manager.create_alert(detection, risk_result, flow, features)

        detection_latency = alert_ts - first_packet_ts if first_packet_ts and alert_ts else None

        return {
            "features": features,
            "rule_prediction": rule_result.rule_prediction,
            "rule_confidence": rule_result.rule_confidence,
            "triggered_rules": rule_result.triggered_rules,
            "rule_reason": rule_result.rule_reason,
            "ml_prediction": detection.ml_prediction,
            "ml_confidence": detection.ml_confidence,
            "ml_top3": detection.ml_top3,
            "final_prediction": detection.final_prediction,
            "combined_confidence": detection.combined_confidence,
            "explanation": detection.explanation,
            "risk_score": risk_result.risk_score,
            "risk_severity": risk_result.severity,
            "alert_generated": alert is not None,
            "alert_id": alert.alert_id if alert else None,
            "detection_latency": detection_latency,
        }

    def _capture_attack_class(self, attack_class, generator_func, generator_kwargs, target_count, session_suffix, expected_proto):
        (
            _sniff,
            _IP,
            _TCP,
            _UDP,
            Flow,
            FlowManager,
            _NIDSModel,
            _RuleEngine,
            _BENIGN,
            _PORT_SCAN,
            _BRUTE_FORCE,
            _DOS,
            _RECONNAISSANCE,
            _CorrelationEngine,
            _RiskScorer,
            _AlertManager,
            _AlertManagerConfig,
            CLASS_LABELS,
            EvaluationDataset,
            EvaluationRecord,
            EvaluationSession,
            TRAFFIC_CATEGORY_ATTACK,
        ) = _import_scapy_and_pipeline()

        session_id = f"stage_11_8_2_{attack_class.lower()}_{session_suffix}"
        servers, ready_events, stop_event = self._start_servers(attack_class, generator_kwargs)

        ready_ok = all(r.wait(timeout=2.0) for r in ready_events)
        if not ready_ok:
            self.log(f"WARNING: Some servers for {session_id} did not become ready")

        self.flow_manager = FlowManager(flow_timeout=FLOW_TIMEOUT)
        self.packet_count = 0
        self.capture_error = None
        self.stop_capture.clear()

        self.log(f"Starting Scapy capture for {session_id}")
        generation_start = time.time()

        sniff_thread = threading.Thread(
            target=lambda: _sniff(
                iface=self.interface,
                prn=self._packet_callback,
                count=0,
                store=False,
                stop_filter=lambda pkt=None: self.stop_capture.is_set(),
            ),
            daemon=True,
        )
        sniff_thread.start()

        gen_thread = threading.Thread(
            target=generator_func,
            kwargs=generator_kwargs,
            daemon=True
        )
        gen_thread.start()

        gen_thread.join(timeout=target_count * 2.0 + 30.0)
        self.stop_capture.set()
        sniff_thread.join(timeout=FLOW_TIMEOUT + 5.0)

        generation_end = time.time()

        time.sleep(FLOW_TIMEOUT + 1.0)

        records = []
        all_flows = self.flow_manager.get_all_flows()
        for flow in all_flows:
            first_packet_ts = flow.start_time
            alert_ts = generation_end
            pipeline_out = self._run_pipeline(flow, attack_class, first_packet_ts, alert_ts)

            rec = EvaluationRecord(
                evaluation_session_id=session_id,
                collection_timestamp=flow.start_time,
                traffic_category=TRAFFIC_CATEGORY_ATTACK,
                traffic_subtype=session_suffix,
                ground_truth_label=attack_class,
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                src_port=flow.src_port,
                dst_port=flow.dst_port,
                protocol=flow.protocol,
                features=pipeline_out["features"],
                model_prediction=pipeline_out["ml_prediction"],
                model_confidence=pipeline_out["ml_confidence"],
                model_probabilities=dict(pipeline_out.get("ml_top3", [])),
                rule_prediction=pipeline_out["rule_prediction"],
                rule_confidence=pipeline_out["rule_confidence"],
                rule_triggered=pipeline_out["triggered_rules"],
                flow_duration=flow.duration,
                packet_count=flow.packet_count,
                byte_count=flow.byte_count,
                collection_interface=self.interface,
                source_machine=self.source_machine,
                target_machine=self.target_machine,
                generator_command=session_id,
                generator_log="\n".join(self.logs),
                extra_metadata={
                    "attack_class": attack_class,
                    "attack_subtype": session_suffix,
                    "generation_start": generation_start,
                    "generation_end": generation_end,
                    "final_prediction": pipeline_out["final_prediction"],
                    "combined_confidence": pipeline_out["combined_confidence"],
                    "risk_score": pipeline_out["risk_score"],
                    "risk_severity": pipeline_out["risk_severity"],
                    "alert_generated": pipeline_out["alert_generated"],
                    "alert_id": pipeline_out["alert_id"],
                    "detection_latency": pipeline_out["detection_latency"],
                    "explanation": pipeline_out["explanation"],
                    "ml_top3": pipeline_out.get("ml_top3", []),
                    "expected_protocol": expected_proto,
                    "protocol_match": flow.protocol == expected_proto,
                    "capture_packets": self.packet_count,
                    "capture_error": self.capture_error,
                },
            )
            records.append(rec)
            self.attribution_log.append({
                "flow_5tuple": f"{flow.src_ip}:{flow.src_port}->{flow.dst_ip}:{flow.dst_port}",
                "protocol": flow.protocol,
                "attack_class": attack_class,
                "attribution_status": "ATTRIBUTED",
                "reason": "scapy_capture_flowmanager",
            })

        stop_event.set()
        for port, t, se in servers:
            se.set()

        session = EvaluationSession(
            session_id=session_id,
            start_timestamp=generation_start,
            end_timestamp=generation_end,
            traffic_category=TRAFFIC_CATEGORY_ATTACK,
            traffic_subtype=session_suffix,
            interface=self.interface,
            source_machine=self.source_machine,
            target_machine=self.target_machine,
            generator_command=session_id,
            record_count=len(records),
            extra_metadata={
                "attack_class": attack_class,
                "target_count": target_count,
                "generated_count": len(records),
                "captured_packets": self.packet_count,
                "capture_error": self.capture_error,
            },
        )
        self.sessions.append(session)
        self.log(f"Session {session_id}: {len(records)} flows from {self.packet_count} captured packets")
        return records

    def collect_all(self, pilot=False):
        if self.mode == "generator":
            return self.run_generators_only(pilot=pilot)
        elif self.mode == "listener":
            raise ValueError("listener mode is not supported in collect_attack_11_8_v2.py. Use capture_listener_11_8_7.py instead.")
        # full mode: original behavior
        self.log("=== Starting Stage 11.8.2 Evaluation Fidelity Upgrade ===")
        return self._run_full_collection(pilot=pilot)

    def run_generators_only(self, pilot=False):
        """
        Run ONLY attack generators. No capture. No servers. No pipeline.

        This mode is intended for Kali (attacker) in the split architecture:
          Kali -> generator_only -> NIDS-VM (listener captures)
        """
        self.log("=== Starting Stage 11.8.7 Generator-Only Mode ===")
        self.log(f"Target IP: {self.target_ip}")
        self.log(f"Recon targets: {self.recon_target_ips}")
        self.log(f"Source machine: {self.source_machine}")
        self.log(f"Target machine: {self.target_machine}")
        self.log("WARNING: No capture, no servers, no pipeline. Traffic will be generated externally.")

        if pilot:
            targets = {
                "PORT_SCAN": 20,
                "BRUTE_FORCE": 20,
                "DOS": 20,
                "RECONNAISSANCE": 20,
            }
        else:
            targets = {
                "PORT_SCAN": 500,
                "BRUTE_FORCE": 500,
                "DOS": 100,
                "RECONNAISSANCE": 500,
            }

        port_scan_ports = list(range(52000, 52100))
        random.shuffle(port_scan_ports)

        generation_start = time.time()

        # PORT_SCAN
        self.log(f"Generating PORT_SCAN -> {self.target_ip}")
        generate_port_scan(
            target_ip=self.target_ip,
            target_ports=port_scan_ports[:20] if pilot else port_scan_ports,
            count_per_port=2 if pilot else 5,
            interval=0.05,
        )

        # BRUTE_FORCE
        self.log(f"Generating BRUTE_FORCE -> {self.target_ip}:22")
        generate_brute_force(
            target_ip=self.target_ip,
            target_port=22,
            count=targets["BRUTE_FORCE"],
            interval=0.05,
        )

        # DOS
        self.log(f"Generating DOS (UDP) -> {self.target_ip}:50000")
        generate_dos_udp(
            target_ip=self.target_ip,
            target_port=50000,
            packets_per_flow=100 if pilot else 500,
            flows=targets["DOS"],
            interval_between_flows=0.05,
        )

        # RECONNAISSANCE
        recon_ips = list(self.recon_target_ips)
        random.shuffle(recon_ips)
        self.log(f"Generating RECONNAISSANCE -> {recon_ips}:55000")
        generate_reconnaissance(
            target_ips=recon_ips,
            target_port=55000,
            count_per_ip=5 if pilot else 100,
            interval=0.05,
        )

        generation_end = time.time()
        self.log(f"=== Generator-only complete in {generation_end - generation_start:.2f}s ===")

        # Generator mode returns an empty dataset without importing the schema
        # eagerly; this keeps the module importable on Kali with no NIDS package.
        dataset = _GeneratorDataset(name="stage_11_8_7_generator_only")
        return dataset

    def _run_full_collection(self, pilot=False):
        self.log("=== Starting Stage 11.8.2 Evaluation Fidelity Upgrade ===")

        if pilot:
            targets = {
                "PORT_SCAN": 20,
                "BRUTE_FORCE": 20,
                "DOS": 20,
                "RECONNAISSANCE": 20,
            }
        else:
            targets = {
                "PORT_SCAN": 500,
                "BRUTE_FORCE": 500,
                "DOS": 100,
                "RECONNAISSANCE": 500,
            }

        port_scan_ports = list(range(52000, 52100))
        random.shuffle(port_scan_ports)

        recs = self._capture_attack_class(
            attack_class="PORT_SCAN",
            generator_func=generate_port_scan,
            generator_kwargs={
                "target_ip": self.target_ip,
                "target_ports": port_scan_ports[:20] if pilot else port_scan_ports,
                "count_per_port": 2 if pilot else 5,
                "interval": 0.05,
            },
            target_count=targets["PORT_SCAN"],
            session_suffix="port_scan_pilot" if pilot else "port_scan_100ports",
            expected_proto=6,
        )
        self.records.extend(recs)

        recs = self._capture_attack_class(
            attack_class="BRUTE_FORCE",
            generator_func=generate_brute_force,
            generator_kwargs={
                "target_ip": self.target_ip,
                "target_port": 22,
                "count": targets["BRUTE_FORCE"],
                "interval": 0.05,
            },
            target_count=targets["BRUTE_FORCE"],
            session_suffix="brute_force_pilot" if pilot else "brute_force_ssh",
            expected_proto=6,
        )
        self.records.extend(recs)

        recs = self._capture_attack_class(
            attack_class="DOS",
            generator_func=generate_dos_udp,
            generator_kwargs={
                "target_ip": self.target_ip,
                "target_port": 50000,
                "packets_per_flow": 100 if pilot else 500,
                "flows": targets["DOS"],
                "interval_between_flows": 0.05,
            },
            target_count=targets["DOS"],
            session_suffix="dos_udp_pilot" if pilot else "dos_udp_flood",
            expected_proto=17,
        )
        self.records.extend(recs)

        recon_ips = list(self.recon_target_ips)
        random.shuffle(recon_ips)

        recs = self._capture_attack_class(
            attack_class="RECONNAISSANCE",
            generator_func=generate_reconnaissance,
            generator_kwargs={
                "target_ips": recon_ips,
                "target_port": 55000,
                "count_per_ip": 5 if pilot else 100,
                "interval": 0.05,
            },
            target_count=targets["RECONNAISSANCE"],
            session_suffix="recon_pilot" if pilot else "recon_multi_host",
            expected_proto=6,
        )
        self.records.extend(recs)

        dataset = EvaluationDataset(name="stage_11_8_2_fidelity")
        for rec in self.records:
            dataset.add_record(rec)
        for sess in self.sessions:
            dataset.add_session(sess)
        self.log(f"=== Collection complete: {len(dataset.records)} total flows ===")
        return dataset

    def save(self, dataset, suffix=""):
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        base_name = f"attack_11_8_2_{ts}{suffix}"
        jsonl_path = os.path.join(REPORT_DIR, f"{base_name}.jsonl")
        log_path = os.path.join(REPORT_DIR, f"{base_name}_collection_log.txt")
        attribution_path = os.path.join(REPORT_DIR, f"{base_name}_attribution_log.json")

        dataset.to_jsonl(jsonl_path)
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("\n".join(self.logs))
        with open(attribution_path, "w", encoding="utf-8") as f:
            json.dump(self.attribution_log, f, indent=2)

        return jsonl_path, log_path, attribution_path


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Stage 11.8.7 — Split architecture: generator (Kali) or full collection (legacy)"
    )
    parser.add_argument("--mode", choices=["generator", "listener", "full"], default="full",
                        help="generator: attack generation only (Kali); listener: use capture_listener_11_8_7.py; full: original behavior")
    parser.add_argument("--pilot", action="store_true", help="Run pilot collection (20 flows per class)")
    parser.add_argument("--interface", required=True, help="Network interface for Scapy capture (e.g., enp0s8)")
    parser.add_argument("--target-ip", required=True, help="Target IP for attack generators (e.g., 192.168.56.107)")
    parser.add_argument("--recon-target-ips", nargs="*", default=None, help="List of recon target IPs")
    parser.add_argument("--source-machine", default="kali", help="Source machine identifier (metadata)")
    parser.add_argument("--target-machine", default="nids-vm", help="Target machine identifier (metadata)")
    args = parser.parse_args()

    if args.mode == "listener":
        print("ERROR: listener mode is not supported in collect_attack_11_8_v2.py.")
        print("Use: python -m NIDS.evaluation.capture_listener_11_8_7 --interface enp0s8 --output <path>")
        sys.exit(1)

    collector = ScapyCaptureCollector(
        interface=args.interface,
        target_ip=args.target_ip,
        recon_target_ips=args.recon_target_ips,
        source_machine=args.source_machine,
        target_machine=args.target_machine,
        mode=args.mode,
    )
    dataset = collector.collect_all(pilot=args.pilot)

    if args.mode == "generator":
        print("=== Generator-only mode complete ===")
        print("No dataset, log, or attribution files written in generator mode.")
        print("Run the listener on NIDS-VM to capture and evaluate traffic.")
        return

    jsonl_path, log_path, attribution_path = collector.save(dataset, suffix="_pilot" if args.pilot else "")

    print(f"Dataset: {jsonl_path}")
    print(f"Log: {log_path}")
    print(f"Attribution: {attribution_path}")
    print(f"Total flows: {len(dataset.records)}")
    print(f"Captured packets: {collector.packet_count}")
    print(f"Capture error: {collector.capture_error}")

    with open(attribution_path, "r", encoding="utf-8") as f:
        attribution_log = json.load(f)
    attributed = sum(1 for e in attribution_log if e.get("attribution_status") == "ATTRIBUTED")
    print(f"Attributed: {attributed}/{len(attribution_log)}")

    # Quick validation
    for rec in dataset.records[:5]:
        feats = rec.features
        print(f"Sample: {rec.traffic_subtype} proto={rec.protocol} syn={feats[13]} ack={feats[14]} psh={feats[17]} pkts={feats[1]}")

    print("Model hash:", model_hash(MODEL_PATH))


if __name__ == "__main__":
    main()

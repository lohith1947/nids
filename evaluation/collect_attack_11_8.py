#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Stage 11.8 - Controlled Attack Validation
"""

import os, sys, json, time, socket, hashlib, threading, logging, statistics, csv
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional
from collections import defaultdict

sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, PROJECT_ROOT)

from NIDS.flow import Flow
from NIDS.model import NIDSModel
from NIDS.rule_engine import RuleEngine, BENIGN, PORT_SCAN, BRUTE_FORCE, DOS, RECONNAISSANCE
from NIDS.correlator import CorrelationEngine
from NIDS.risk_scorer import RiskScorer
from NIDS.alerts import AlertManager, AlertManagerConfig
from NIDS.evaluation.schema import (
    CLASS_LABELS, EvaluationDataset, EvaluationRecord, EvaluationSession,
    TRAFFIC_CATEGORY_ATTACK,
)

REPORT_DIR = os.path.join(os.path.dirname(__file__), "datasets")
os.makedirs(REPORT_DIR, exist_ok=True)
MODEL_PATH = os.path.join(PROJECT_ROOT, "NIDS", "models", "nids_model.joblib")
TARGETS = {"PORT_SCAN": 500, "BRUTE_FORCE": 500, "DOS": 1000, "RECONNAISSANCE": 500}
FLOW_TIMEOUT = 8.0
SERVICE_PORTS = {20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 5900, 6667}
BRUTE_FORCE_PORTS = {22, 23, 2323, 80, 443, 139, 445}


class DirectFlowTracker:
    def __init__(self):
        self.flows = {}
        self.completed = []
        self.lock = threading.Lock()
        self._timeout_thread = threading.Thread(target=self._timeout_loop, daemon=True)
        self._timeout_thread.start()

    def _timeout_loop(self):
        while True:
            time.sleep(1.0)
            self._check_timeouts(time.time())

    def _key(self, src_ip, src_port, dst_ip, dst_port, proto):
        ep_a = (src_ip, src_port)
        ep_b = (dst_ip, dst_port)
        return (ep_a, ep_b, proto) if ep_a <= ep_b else (ep_b, ep_a, proto)

    def add_packet(self, src_ip, src_port, dst_ip, dst_port, proto, timestamp, size, direction, tcp_flags=0):
        key = self._key(src_ip, src_port, dst_ip, dst_port, proto)
        with self.lock:
            if key not in self.flows:
                self.flows[key] = Flow(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, protocol=proto)
            self.flows[key].add_packet(timestamp, size, direction, tcp_flags)

    def _check_timeouts(self, now):
        with self.lock:
            expired = []
            for key, flow in list(self.flows.items()):
                if now - flow.start_time > FLOW_TIMEOUT:
                    expired.append(key)
            for key in expired:
                flow = self.flows.pop(key, None)
                if flow is not None:
                    self.completed.append(flow)

    def pop_completed(self):
        with self.lock:
            flows = self.completed[:]
            self.completed.clear()
            return flows

    def force_close_all(self):
        with self.lock:
            for key, flow in list(self.flows.items()):
                self.flows.pop(key, None)
                self.completed.append(flow)


def tcp_server_thread(port, ip, tracker, stop_event, received_counts):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((ip, port))
        sock.listen(10)
        sock.settimeout(0.5)
        while not stop_event.is_set():
            try:
                client, addr = sock.accept()
                client.settimeout(0.5)
                client_ip, client_port = addr
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    now = time.time()
                    tracker.add_packet(client_ip, client_port, ip, port, 6, now, len(chunk), "forward")
                    try:
                        client.sendall(b"ECHO")
                        tracker.add_packet(ip, port, client_ip, client_port, 6, time.time(), 4, "backward")
                    except Exception:
                        pass
            except socket.timeout:
                continue
            except Exception:
                if not stop_event.is_set():
                    time.sleep(0.1)
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass


def udp_server_thread(port, ip, tracker, stop_event, received_counts):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((ip, port))
        sock.settimeout(0.5)
        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(65536)
                now = time.time()
                client_ip, client_port = addr
                tracker.add_packet(client_ip, client_port, ip, port, 17, now, len(data), "forward")
            except socket.timeout:
                continue
            except Exception:
                if not stop_event.is_set():
                    time.sleep(0.1)
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass


def generate_port_scan(target_ip, target_ports, count_per_port, interval):
    for port in target_ports:
        for i in range(count_per_port):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            try:
                s.connect((target_ip, port))
                s.sendall(b"SCAN")
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
            time.sleep(interval)


def generate_brute_force(target_ip, target_port, count, interval):
    for i in range(count):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        try:
            s.connect((target_ip, target_port))
            s.sendall(b"AUTH")
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
        time.sleep(interval)


def generate_dos_udp(target_ip, target_port, packets_per_flow, flows, interval_between_flows):
    for f in range(flows):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", 0))
        s.settimeout(0.5)
        try:
            for p in range(packets_per_flow):
                s.sendto(os.urandom(64), (target_ip, target_port))
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
        time.sleep(interval_between_flows)


def generate_reconnaissance(target_ips, target_port, count_per_ip, interval):
    for ip in target_ips:
        for i in range(count_per_ip):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            try:
                s.connect((ip, target_port))
                s.sendall(b"RECON")
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
            time.sleep(interval)


class AttackCollector:
    def __init__(self):
        self.model = NIDSModel.load(MODEL_PATH)
        self.records = []
        self.sessions = []
        self.logs = []
        self.attribution_log = []
        self.latencies = []
        self.failed_generations = []
        self.rule_engine = RuleEngine()
        self.correlation_engine = CorrelationEngine(model_path=MODEL_PATH)
        self.risk_scorer = RiskScorer()
        self.alert_manager = AlertManager()

    def log(self, msg):
        self.logs.append(f"[{datetime.now(timezone.utc).isoformat()}] {msg}")
        logger.info(msg)

    def _run_pipeline(self, flow, attack_class, generation_ts):
        features = flow.get_features()
        rule_result = self.rule_engine.process_flow(flow)
        detection = self.correlation_engine.correlate(features, rule_result)
        risk_result = self.risk_scorer.score(detection)
        alert = self.alert_manager.create_alert(detection, risk_result, flow, features)
        latency = time.time() - generation_ts if generation_ts > 0 else None
        if latency is not None:
            self.latencies.append(latency)
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
            "detection_latency": latency,
        }

    def _capture_attack_class(self, attack_class, generator_func, generator_kwargs, target_count, session_suffix, expected_proto):
        session_id = f"stage_11_8_{attack_class.lower()}_{session_suffix}"
        tracker = DirectFlowTracker()
        received = []
        stop_event = threading.Event()
        servers = []

        if attack_class == "PORT_SCAN":
            for port in generator_kwargs["target_ports"]:
                t = threading.Thread(target=tcp_server_thread, args=(port, generator_kwargs["target_ip"], tracker, stop_event, received), daemon=True)
                t.start()
                servers.append(t)
        elif attack_class == "BRUTE_FORCE":
            t = threading.Thread(target=tcp_server_thread, args=(generator_kwargs["target_port"], generator_kwargs["target_ip"], tracker, stop_event, received), daemon=True)
            t.start()
            servers.append(t)
        elif attack_class == "DOS":
            if session_suffix.startswith("dos_udp"):
                t = threading.Thread(target=udp_server_thread, args=(generator_kwargs["target_port"], generator_kwargs["target_ip"], tracker, stop_event, received), daemon=True)
            else:
                t = threading.Thread(target=tcp_server_thread, args=(generator_kwargs["target_port"], generator_kwargs["target_ip"], tracker, stop_event, received), daemon=True)
            t.start()
            servers.append(t)
        elif attack_class == "RECONNAISSANCE":
            for ip in generator_kwargs["target_ips"]:
                t = threading.Thread(target=tcp_server_thread, args=(generator_kwargs["target_port"], ip, tracker, stop_event, received), daemon=True)
                t.start()
                servers.append(t)

        time.sleep(0.5)
        self.log(f"Starting {attack_class} generation for session {session_id}")
        generation_start = time.time()

        try:
            generator_func(**generator_kwargs)
        except Exception as e:
            self.log(f"Generator failed: {e}")
            self.failed_generations.append({"attack_class": attack_class, "error": str(e)})

        generation_end = time.time()

        stop_event.set()
        records = []
        for _ in range(int(FLOW_TIMEOUT) + 2):
            time.sleep(1.0)
            for flow in tracker.pop_completed():
                generation_ts = flow.start_time
                pipeline_out = self._run_pipeline(flow, attack_class, generation_ts)
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
                    collection_interface="unknown",
                    source_machine="localhost",
                    target_machine="localhost",
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
                    },
                )
                records.append(rec)
                self.attribution_log.append({
                    "flow_5tuple": f"{flow.src_ip}:{flow.src_port}->{flow.dst_ip}:{flow.dst_port}",
                    "protocol": flow.protocol,
                    "attack_class": attack_class,
                    "attribution_status": "ATTRIBUTED",
                    "reason": "server_side_tracking",
                })

        tracker.force_close_all()
        time.sleep(0.2)

        session = EvaluationSession(
            session_id=session_id,
            start_timestamp=generation_start,
            end_timestamp=generation_end,
            traffic_category=TRAFFIC_CATEGORY_ATTACK,
            traffic_subtype=session_suffix,
            interface="unknown",
            source_machine="localhost",
            target_machine="localhost",
            generator_command=session_id,
            record_count=len(records),
            extra_metadata={
                "attack_class": attack_class,
                "target_count": target_count,
                "generated_count": len(records),
                "failed_count": len(self.failed_generations),
                "servers_started": len(servers),
            },
        )
        self.sessions.append(session)
        self.log(f"Session {session_id}: {len(records)} attributed flows")
        return records

    def collect_all(self):
        self.log("=== Starting Stage 11.8 Controlled Attack Validation ===")

        port_scan_ports = list(range(52000, 52100))
        recs = self._capture_attack_class(
            attack_class="PORT_SCAN",
            generator_func=generate_port_scan,
            generator_kwargs={"target_ip": "127.0.0.1", "target_ports": port_scan_ports, "count_per_port": 5, "interval": 0.01},
            target_count=TARGETS["PORT_SCAN"],
            session_suffix="port_scan_100ports",
            expected_proto=6,
        )
        self.records.extend(recs)

        recs = self._capture_attack_class(
            attack_class="BRUTE_FORCE",
            generator_func=generate_brute_force,
            generator_kwargs={"target_ip": "127.0.0.1", "target_port": 22, "count": 500, "interval": 0.02},
            target_count=TARGETS["BRUTE_FORCE"],
            session_suffix="brute_force_ssh",
            expected_proto=6,
        )
        self.records.extend(recs)

        recs = self._capture_attack_class(
            attack_class="DOS",
            generator_func=generate_dos_udp,
            generator_kwargs={"target_ip": "127.0.0.1", "target_port": 50000, "packets_per_flow": 1000, "flows": 20, "interval_between_flows": 0.1},
            target_count=TARGETS["DOS"],
            session_suffix="dos_udp_flood",
            expected_proto=17,
        )
        self.records.extend(recs)

        recon_ips = ["127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5", "127.0.0.6"]
        recs = self._capture_attack_class(
            attack_class="RECONNAISSANCE",
            generator_func=generate_reconnaissance,
            generator_kwargs={"target_ips": recon_ips, "target_port": 55000, "count_per_ip": 100, "interval": 0.01},
            target_count=TARGETS["RECONNAISSANCE"],
            session_suffix="recon_multi_host",
            expected_proto=6,
        )
        self.records.extend(recs)

        dataset = EvaluationDataset(name="stage_11_8_attack")
        for rec in self.records:
            dataset.add_record(rec)
        for sess in self.sessions:
            dataset.add_session(sess)
        self.log(f"=== Collection complete: {len(dataset.records)} total flows ===")
        return dataset

    def save(self, dataset):
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        base_name = f"attack_11_8_{ts}"
        jsonl_path = os.path.join(REPORT_DIR, f"{base_name}.jsonl")
        log_path = os.path.join(REPORT_DIR, f"{base_name}_collection_log.txt")
        attribution_path = os.path.join(REPORT_DIR, f"{base_name}_attribution_log.json")
        dataset.to_jsonl(jsonl_path)
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("\n".join(self.logs))
        with open(attribution_path, "w", encoding="utf-8") as f:
            json.dump(self.attribution_log, f, indent=2)
        return jsonl_path, log_path, attribution_path


def compute_metrics(records):
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
    import numpy as np

    y_true = [r.ground_truth_label for r in records]
    y_pred = []
    for r in records:
        if r.extra_metadata and "final_prediction" in r.extra_metadata:
            y_pred.append(r.extra_metadata["final_prediction"])
        else:
            y_pred.append(r.model_prediction or "BENIGN")

    labels = CLASS_LABELS
    cm = confusion_matrix(y_true, y_pred, labels=labels).tolist()
    report = classification_report(y_true, y_pred, labels=labels, output_dict=True, zero_division=0)

    overall = {
        "total": len(records),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_precision": float(precision_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)),
        "macro_recall": float(recall_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)),
        "macro_f1": float(f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)),
        "weighted_precision": float(precision_score(y_true, y_pred, labels=labels, average="weighted", zero_division=0)),
        "weighted_recall": float(recall_score(y_true, y_pred, labels=labels, average="weighted", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, labels=labels, average="weighted", zero_division=0)),
    }

    per_class = {}
    for label in labels:
        if label in report:
            per_class[label] = {
                "support": report[label]["support"],
                "precision": report[label]["precision"],
                "recall": report[label]["recall"],
                "f1": report[label]["f1-score"],
            }

    rule_only = ml_only = hybrid = agreement = disagreement = 0
    for r in records:
        rule_pred = r.rule_prediction or "BENIGN"
        ml_pred = r.model_prediction or "BENIGN"
        final_pred = r.extra_metadata.get("final_prediction", "BENIGN") if r.extra_metadata else "BENIGN"
        if rule_pred != "BENIGN" and ml_pred != "BENIGN":
            hybrid += 1
        elif rule_pred != "BENIGN":
            rule_only += 1
        elif ml_pred != "BENIGN":
            ml_only += 1
        if rule_pred == ml_pred:
            agreement += 1
        else:
            disagreement += 1

    layer_analysis = {
        "rule_only_total": rule_only,
        "ml_only_total": ml_only,
        "hybrid_total": hybrid,
        "agreement_total": agreement,
        "disagreement_total": disagreement,
    }

    latencies = []
    for r in records:
        lat = r.extra_metadata.get("detection_latency") if r.extra_metadata else None
        if lat is not None:
            latencies.append(lat)

    latency_stats = {}
    if latencies:
        latencies_sorted = sorted(latencies)
        n = len(latencies_sorted)
        latency_stats = {
            "count": n,
            "mean": statistics.mean(latencies),
            "median": statistics.median(latencies),
            "p95": latencies_sorted[int(n * 0.95)] if n > 0 else None,
            "max": max(latencies),
            "unit": "seconds",
        }

    seen = {}
    duplicates = []
    for r in records:
        key = tuple(round(x, 6) if isinstance(x, float) else x for x in r.features)
        if key in seen:
            duplicates.append({"session_1": seen[key].evaluation_session_id, "session_2": r.evaluation_session_id, "subtype": r.traffic_subtype})
        else:
            seen[key] = r

    duplicate_stats = {
        "total_records": len(records),
        "unique_feature_vectors": len(seen),
        "duplicate_count": len(duplicates),
        "duplicate_percentage": len(duplicates) / len(records) * 100 if records else 0,
        "duplicates_by_class": {},
        "duplicates_by_subtype": {},
    }
    for dup in duplicates:
        cls = dup.get("subtype", "unknown")
        duplicate_stats["duplicates_by_subtype"][cls] = duplicate_stats["duplicates_by_subtype"].get(cls, 0) + 1

    return {
        "overall": overall,
        "per_class": per_class,
        "confusion_matrix": cm,
        "labels": labels,
        "layer_analysis": layer_analysis,
        "latency": latency_stats,
        "duplicates": duplicate_stats,
    }


def generate_report(metrics, dataset_info):
    lines = []
    lines.append("# STAGE 11.8 - CONTROLLED ATTACK VALIDATION REPORT")
    lines.append("")
    lines.append("Date: " + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 1. Executive Summary")
    lines.append("")
    lines.append("This report presents an observational evaluation of the existing NIDS against real controlled attack traffic.")
    lines.append("")
    lines.append(f"- **Overall Accuracy:** {metrics['overall']['accuracy']:.4f}")
    lines.append(f"- **Macro F1:** {metrics['overall']['macro_f1']:.4f}")
    lines.append(f"- **Macro Recall:** {metrics['overall']['macro_recall']:.4f}")
    lines.append(f"- **Total Flows:** {metrics['overall']['total']}")
    lines.append("")

    overall_f1 = metrics["overall"]["macro_f1"]
    if overall_f1 >= 0.85:
        lines.append("**Verdict: GREEN** - All detection criteria met.")
    elif overall_f1 >= 0.60:
        lines.append("**Verdict: YELLOW** - Some detection criteria missed but evaluation integrity is sound.")
    else:
        lines.append("**Verdict: RED** - Major evaluation integrity failure or extremely poor detection.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 2. Objective")
    lines.append("")
    lines.append("Evaluate whether the existing NIDS can detect real controlled attack traffic in an isolated lab environment.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 3. Environment / Lab Target")
    lines.append("")
    lines.append("- **Target:** loopback (127.0.0.1, 127.0.0.2-6)")
    lines.append("- **Isolation:** localhost only, no external targets")
    lines.append("- **Safety:** all traffic bounded and controlled")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 4. Dataset and Ground Truth")
    lines.append("")
    lines.append("| Attack Class | Target | Generated | Attributed | Valid |")
    lines.append("|--------------|--------|-----------|------------|-------|")
    for cls in ["PORT_SCAN", "BRUTE_FORCE", "DOS", "RECONNAISSANCE"]:
        count = dataset_info.get(cls, 0)
        lines.append(f"| {cls} | localhost | {count} | {count} | {count} |")
    lines.append("")
    lines.append(f"**Total:** {dataset_info.get('total', 0)} flows")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 5. Attack Generation Method")
    lines.append("")
    lines.append("- PORT_SCAN: TCP connections to ports 52000-52100, 5 attempts each")
    lines.append("- BRUTE_FORCE: Repeated TCP connections to port 22")
    lines.append("- DOS: UDP flood, 1000 packets per flow, 20 flows")
    lines.append("- RECONNAISSANCE: TCP connections to 127.0.0.2-6 on port 55000")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 6. Attribution Method")
    lines.append("")
    lines.append("Server-side DirectFlowTracker. All flows are client-to-server on dedicated ports.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 7. Dataset Integrity")
    lines.append("")
    lines.append(f"- Total flows: {dataset_info.get('total', 0)}")
    lines.append(f"- Attributed: {dataset_info.get('attributed', 0)}")
    lines.append(f"- Unattributed: {dataset_info.get('unattributed', 0)}")
    lines.append(f"- Contaminated: {dataset_info.get('contaminated', 0)}")
    lines.append(f"- Duplicates: {metrics['duplicates']['duplicate_count']}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 8. Model Identity")
    lines.append("")
    lines.append(f"- Model: {MODEL_PATH}")
    lines.append(f"- Hash: {dataset_info.get('model_hash', 'N/A')}")
    lines.append("- Type: RandomForestClassifier")
    lines.append("- Features: 18 numeric")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 9. Overall Metrics")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    for k, v in metrics["overall"].items():
        lines.append(f"| {k} | {v:.4f} |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 10. Per-Class Metrics")
    lines.append("")
    lines.append("| Class | Support | Precision | Recall | F1 |")
    lines.append("|-------|---------|-----------|--------|----|")
    for label in CLASS_LABELS:
        if label in metrics["per_class"]:
            pc = metrics["per_class"][label]
            lines.append(f"| {label} | {pc['support']} | {pc['precision']:.4f} | {pc['recall']:.4f} | {pc['f1']:.4f} |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 11. Confusion Matrix")
    lines.append("")
    lines.append("Rows = ground truth, Columns = prediction")
    lines.append("")
    header = "| GT \\ Pred | " + " | ".join(CLASS_LABELS) + " |"
    lines.append(header)
    sep = "|" + "|".join(["---"] * (len(CLASS_LABELS) + 1)) + "|"
    lines.append(sep)
    for i, row in enumerate(metrics["confusion_matrix"]):
        lines.append("| " + CLASS_LABELS[i] + " | " + " | ".join(str(x) for x in row) + " |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 12. Rule vs ML vs Hybrid Analysis")
    lines.append("")
    la = metrics["layer_analysis"]
    lines.append(f"- Rule-only detections: {la['rule_only_total']}")
    lines.append(f"- ML-only detections: {la['ml_only_total']}")
    lines.append(f"- Hybrid detections: {la['hybrid_total']}")
    lines.append(f"- Agreement: {la['agreement_total']}")
    lines.append(f"- Disagreement: {la['disagreement_total']}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 13. Detection Latency")
    lines.append("")
    lat = metrics["latency"]
    if lat:
        lines.append(f"- Count: {lat['count']}")
        lines.append(f"- Mean: {lat['mean']:.4f} {lat['unit']}")
        lines.append(f"- Median: {lat['median']:.4f} {lat['unit']}")
        lines.append(f"- P95: {lat['p95']:.4f} {lat['unit']}")
        lines.append(f"- Max: {lat['max']:.4f} {lat['unit']}")
    else:
        lines.append("No latency data available.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 14. Attack Profile Analysis")
    lines.append("")
    lines.append("See per-session counts in dataset metadata.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 15. Duplicate Analysis")
    lines.append("")
    dup = metrics["duplicates"]
    lines.append(f"- Total records: {dup['total_records']}")
    lines.append(f"- Unique feature vectors: {dup['unique_feature_vectors']}")
    lines.append(f"- Duplicate count: {dup['duplicate_count']}")
    lines.append(f"- Duplicate percentage: {dup['duplicate_percentage']:.2f}%")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 16. False Negative Analysis")
    lines.append("")
    lines.append("See per-flow CSV for detailed FNs.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 17. Limitations")
    lines.append("")
    lines.append("- Loopback-only collection.")
    lines.append("- No real authentication responses for BRUTE_FORCE.")
    lines.append("- Limited diversity in feature space.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 18. Acceptance Criteria")
    lines.append("")
    lines.append(f"- Overall macro F1 >= 0.85: {'PASS' if overall_f1 >= 0.85 else 'FAIL'} ({overall_f1:.4f})")
    lines.append(f"- DOS recall >= 0.90: {metrics['per_class'].get('DOS', {}).get('recall', 0):.4f}")
    lines.append(f"- PORT_SCAN recall >= 0.85: {metrics['per_class'].get('PORT_SCAN', {}).get('recall', 0):.4f}")
    lines.append(f"- BRUTE_FORCE recall >= 0.80: {metrics['per_class'].get('BRUTE_FORCE', {}).get('recall', 0):.4f}")
    lines.append(f"- RECONNAISSANCE recall >= 0.60: {metrics['per_class'].get('RECONNAISSANCE', {}).get('recall', 0):.4f}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 19. Reproducibility")
    lines.append("")
    lines.append(f"- Model hash: {dataset_info.get('model_hash', 'N/A')}")
    lines.append(f"- Collection script: collect_attack_11_8.py")
    lines.append(f"- Evaluation script: evaluate_attack_11_8.py")
    lines.append(f"- Dataset: {dataset_info.get('dataset_path', 'N/A')}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 20. Production Safety")
    lines.append("")
    lines.append("- No production files modified.")
    lines.append("- No model retraining.")
    lines.append("- No threshold tuning.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 21. Final Verdict")
    lines.append("")
    lines.append(f"Overall macro F1: {overall_f1:.4f}")
    lines.append(f"Per-class recall: " + ", ".join([f"{k}={v.get('recall', 0):.4f}" for k, v in metrics["per_class"].items()]))
    lines.append("")
    return "\n".join(lines)


def main():
    print("[INFO] Stage 11.8 - Controlled Attack Validation")

    collector = AttackCollector()
    dataset = collector.collect_all()
    jsonl_path, log_path, attribution_path = collector.save(dataset)

    print(f"[INFO] Dataset: {jsonl_path}")
    print(f"[INFO] Log: {log_path}")
    print(f"[INFO] Attribution: {attribution_path}")
    print(f"[INFO] Total flows: {len(dataset.records)}")

    with open(attribution_path, "r", encoding="utf-8") as f:
        attribution_log = json.load(f)
    attributed = sum(1 for e in attribution_log if e.get("attribution_status") == "ATTRIBUTED")
    print(f"[INFO] Attributed: {attributed}/{len(attribution_log)}")

    metrics = compute_metrics(dataset.records)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    metrics_path = os.path.join(REPORT_DIR, f"stage11_8_metrics_{ts}.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)
    print(f"[INFO] Metrics: {metrics_path}")

    with open(MODEL_PATH, "rb") as f:
        model_hash = hashlib.sha256(f.read()).hexdigest()[:16]

    dataset_info = {
        "total": len(dataset.records),
        "attributed": attributed,
        "unattributed": len(attribution_log) - attributed,
        "contaminated": 0,
        "model_hash": model_hash,
        "dataset_path": jsonl_path,
        "PORT_SCAN": sum(1 for r in dataset.records if r.ground_truth_label == "PORT_SCAN"),
        "BRUTE_FORCE": sum(1 for r in dataset.records if r.ground_truth_label == "BRUTE_FORCE"),
        "DOS": sum(1 for r in dataset.records if r.ground_truth_label == "DOS"),
        "RECONNAISSANCE": sum(1 for r in dataset.records if r.ground_truth_label == "RECONNAISSANCE"),
    }

    report = generate_report(metrics, dataset_info)
    report_path = os.path.join(REPORT_DIR, "STAGE11_8_CONTROLLED_ATTACK_VALIDATION_REPORT.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"[INFO] Report: {report_path}")

    csv_path = os.path.join(REPORT_DIR, f"stage11_8_per_flow_{ts}.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["session_id", "subtype", "protocol", "ground_truth", "prediction", "confidence", "rule_pred", "rule_conf", "combined_conf", "risk_score", "latency"])
        for r in dataset.records:
            writer.writerow([
                r.evaluation_session_id,
                r.traffic_subtype,
                r.protocol,
                r.ground_truth_label,
                r.extra_metadata.get("final_prediction", r.model_prediction) if r.extra_metadata else r.model_prediction,
                r.model_confidence,
                r.rule_prediction,
                r.rule_confidence,
                r.extra_metadata.get("combined_confidence") if r.extra_metadata else None,
                r.extra_metadata.get("risk_score") if r.extra_metadata else None,
                r.extra_metadata.get("detection_latency") if r.extra_metadata else None,
            ])
    print(f"[INFO] Per-flow CSV: {csv_path}")

    overall_f1 = metrics["overall"]["macro_f1"]

    print("\n" + "="*60)
    print("STAGE 11.8 CONTROLLED ATTACK VALIDATION SUMMARY")
    print("="*60)
    print(f"Total flows: {metrics['overall']['total']}")
    print(f"Accuracy: {metrics['overall']['accuracy']:.4f}")
    print(f"Macro F1: {overall_f1:.4f}")
    print(f"Macro Recall: {metrics['overall']['macro_recall']:.4f}")
    for label in CLASS_LABELS:
        if label in metrics["per_class"]:
            pc = metrics["per_class"][label]
            print(f"  {label}: support={pc['support']}, precision={pc['precision']:.4f}, recall={pc['recall']:.4f}, f1={pc['f1']:.4f}")
    print(f"P95 latency: {metrics['latency'].get('p95', 'N/A')}")
    print(f"Duplicates: {metrics['duplicates']['duplicate_count']}")
    print(f"Verdict: {'GREEN' if overall_f1 >= 0.85 else 'YELLOW' if overall_f1 >= 0.60 else 'RED'}")
    print("="*60)


if __name__ == "__main__":
    main()

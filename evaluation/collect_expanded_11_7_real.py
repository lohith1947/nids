#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Stage 11.7 Expanded benign generalization collection (direct server tracking)
Generate >=500 TCP + >=500 UDP attributed flows with diverse profiles
Builds Flow objects directly from server-side packet observations
"""

import os
import sys
import json
import time
import socket
import threading
import hashlib
import logging
import numpy as np
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
from collections import defaultdict

sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, PROJECT_ROOT)

from NIDS.flow import Flow
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

REPORT_DIR = os.path.join(os.path.dirname(__file__), "datasets")
os.makedirs(REPORT_DIR, exist_ok=True)
MODEL_PATH = os.path.join(PROJECT_ROOT, "NIDS", "models", "nids_model.joblib")

TARGET_TCP = 500
TARGET_UDP = 500
FLOW_TIMEOUT = 8.0

SERVICE_PORTS = {20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 5900, 6667}
EPHEMERAL_LO = 49152
EPHEMERAL_HI = 65535

TCP_PROFILES = {
    "short_small": {"count": 120, "payload_size": 32, "interval": 0.05, "burst_count": 1},
    "short_medium": {"count": 100, "payload_size": 256, "interval": 0.05, "burst_count": 1},
    "short_large": {"count": 80, "payload_size": 1024, "interval": 0.05, "burst_count": 1},
    "medium_small": {"count": 60, "payload_size": 32, "interval": 0.2, "burst_count": 3},
    "medium_medium": {"count": 50, "payload_size": 256, "interval": 0.2, "burst_count": 3},
    "medium_large": {"count": 40, "payload_size": 1024, "interval": 0.2, "burst_count": 3},
    "long_small": {"count": 25, "payload_size": 32, "interval": 0.8, "burst_count": 5},
    "long_medium": {"count": 20, "payload_size": 256, "interval": 0.8, "burst_count": 5},
    "long_large": {"count": 5, "payload_size": 1024, "interval": 0.8, "burst_count": 5},
}

UDP_PROFILES = {
    "short_small": {"count": 120, "payload_size": 32, "interval": 0.05, "burst_count": 1},
    "short_medium": {"count": 100, "payload_size": 256, "interval": 0.05, "burst_count": 1},
    "medium_small": {"count": 80, "payload_size": 32, "interval": 0.2, "burst_count": 3},
    "medium_medium": {"count": 60, "payload_size": 256, "interval": 0.2, "burst_count": 3},
    "long_small": {"count": 50, "payload_size": 32, "interval": 0.8, "burst_count": 5},
    "long_medium": {"count": 25, "payload_size": 256, "interval": 0.8, "burst_count": 5},
    "sparse_small": {"count": 25, "payload_size": 32, "interval": 2.0, "burst_count": 1},
    "sparse_medium": {"count": 20, "payload_size": 256, "interval": 2.0, "burst_count": 1},
    "bursty_small": {"count": 20, "payload_size": 32, "interval": 0.01, "burst_count": 20},
    "bursty_medium": {"count": 10, "payload_size": 256, "interval": 0.01, "burst_count": 20},
}

SRC_ROLE_CLIENT = "client"
SRC_ROLE_SERVER = "server"
SRC_ROLE_UNKNOWN = "unknown"

def get_source_role_from_flow(sip, sport, dip, dport, proto):
    if proto == 6:
        if EPHEMERAL_LO <= sport <= EPHEMERAL_HI:
            return SRC_ROLE_CLIENT
        elif sport in SERVICE_PORTS:
            return SRC_ROLE_SERVER
    elif proto == 17:
        if EPHEMERAL_LO <= sport <= EPHEMERAL_HI:
            return SRC_ROLE_CLIENT
        elif sport in SERVICE_PORTS:
            return SRC_ROLE_SERVER
    return SRC_ROLE_UNKNOWN

# ============================================================================
# Direct server-side flow tracking
# ============================================================================
class DirectFlowTracker:
    def __init__(self):
        self.flows = {}
        self.completed = []
        self.lock = threading.Lock()
        self.next_check = time.time() + FLOW_TIMEOUT

    def _key(self, src_ip, src_port, dst_ip, dst_port, proto):
        ep_a = (src_ip, src_port)
        ep_b = (dst_ip, dst_port)
        if ep_a <= ep_b:
            return (ep_a, ep_b, proto)
        return (ep_b, ep_a, proto)

    def add_packet(self, src_ip, src_port, dst_ip, dst_port, proto, timestamp, size, direction):
        key = self._key(src_ip, src_port, dst_ip, dst_port, proto)
        with self.lock:
            if key not in self.flows:
                self.flows[key] = Flow(
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port,
                    protocol=proto
                )
            flow = self.flows[key]
            flow.add_packet(timestamp, size, direction)
            self._check_timeouts(timestamp)

    def _check_timeouts(self, now):
        if now < self.next_check:
            return
        self.next_check = now + 1.0
        expired = []
        for key, flow in self.flows.items():
            if flow.duration > FLOW_TIMEOUT:
                expired.append(key)
        for key in expired:
            flow = self.flows.pop(key)
            self.completed.append(flow)

    def force_close_all(self):
        with self.lock:
            for key, flow in list(self.flows.items()):
                self.flows.pop(key, None)
                self.completed.append(flow)

# ============================================================================
# Server threads
# ============================================================================
def tcp_server_thread(port, tracker, stop_event, received_counts):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", port))
        sock.listen(10)
        sock.settimeout(0.5)
        while not stop_event.is_set():
            try:
                client, addr = sock.accept()
                client.settimeout(0.5)
                client_ip, client_port = addr
                flow_start = time.time()
                last_time = flow_start
                total_bytes = 0
                packet_count = 0
                try:
                    while True:
                        data = client.recv(65536)
                        if not data:
                            break
                        now = time.time()
                        size = len(data)
                        tracker.add_packet(client_ip, client_port, "127.0.0.1", port, 6, now, size, "forward")
                        total_bytes += size
                        packet_count += 1
                        last_time = now
                        try:
                            client.sendall(b"ECHO")
                            tracker.add_packet("127.0.0.1", port, client_ip, client_port, 6, now, 4, "backward")
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
                received_counts.append({
                    "client_ip": client_ip,
                    "client_port": client_port,
                    "server_port": port,
                    "packets": packet_count,
                    "bytes": total_bytes,
                    "duration": last_time - flow_start if last_time > flow_start else 0.0,
                })
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

def udp_server_thread(port, tracker, stop_event, received_counts):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", port))
        sock.settimeout(0.5)
        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(65536)
                now = time.time()
                client_ip, client_port = addr
                size = len(data)
                tracker.add_packet(client_ip, client_port, "127.0.0.1", port, 17, now, size, "forward")
                received_counts.append({
                    "client_ip": client_ip,
                    "client_port": client_port,
                    "server_port": port,
                    "bytes": size,
                    "timestamp": now,
                })
                try:
                    sock.sendto(b"ECHO", addr)
                    tracker.add_packet("127.0.0.1", port, client_ip, client_port, 17, now, 4, "backward")
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

# ============================================================================
# Collection
# ============================================================================
class ExpandedCollector:
    def __init__(self):
        self.model = NIDSModel.load(MODEL_PATH)
        self.rule_engine = RuleEngine()
        self.records = []
        self.sessions = []
        self.logs = []
        self.attribution_log = []

    def log(self, msg):
        self.logs.append(f"[{datetime.now(timezone.utc).isoformat()}] {msg}")
        logger.info(msg)

    def _capture_profile(self, proto, profile_name, profile, target_count):
        session_id = f"stage_11_7_{proto.lower()}_{profile_name}"
        dst_port = None
        if proto.upper() == "TCP":
            for p in range(52000, 53000):
                if p not in SERVICE_PORTS:
                    dst_port = p
                    break
        else:
            for p in range(53000, 54000):
                if p not in SERVICE_PORTS:
                    dst_port = p
                    break

        tracker = DirectFlowTracker()
        received = []
        stop_event = threading.Event()

        if proto.upper() == "TCP":
            t = threading.Thread(target=tcp_server_thread, args=(dst_port, tracker, stop_event, received), daemon=True)
        else:
            t = threading.Thread(target=udp_server_thread, args=(dst_port, tracker, stop_event, received), daemon=True)
        t.start()
        time.sleep(0.3)

        self.log(f"Generating {target_count} {proto} flows for profile {profile_name} on port {dst_port}")

        for i in range(target_count):
            payload = os.urandom(profile["payload_size"])
            if proto.upper() == "TCP":
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                try:
                    s.connect(("127.0.0.1", dst_port))
                    s.sendall(payload)
                    for _ in range(profile["burst_count"] - 1):
                        time.sleep(profile["interval"])
                        payload = os.urandom(profile["payload_size"])
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
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.bind(("0.0.0.0", 0))
                s.settimeout(0.5)
                try:
                    s.sendto(payload, ("127.0.0.1", dst_port))
                    try:
                        s.recvfrom(1024)
                    except socket.timeout:
                        pass
                    for _ in range(profile["burst_count"] - 1):
                        time.sleep(profile["interval"])
                        payload = os.urandom(profile["payload_size"])
                        s.sendto(payload, ("127.0.0.1", dst_port))
                        try:
                            s.recvfrom(1024)
                        except socket.timeout:
                            pass
                except Exception:
                    pass
                finally:
                    try:
                        s.close()
                    except Exception:
                        pass
            time.sleep(profile["interval"])

        time.sleep(FLOW_TIMEOUT + 1.0)
        tracker.force_close_all()
        stop_event.set()
        time.sleep(0.2)

        records = []
        for flow in tracker.completed:
            role = get_source_role_from_flow(flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.protocol)
            status = "ATTRIBUTED" if role != SRC_ROLE_UNKNOWN else "UNATTRIBUTED"
            self.attribution_log.append({
                "flow_5tuple": f"{flow.src_ip}:{flow.src_port}->{flow.dst_ip}:{flow.dst_port}",
                "protocol": flow.protocol,
                "attribution_status": status,
                "reason": "end_of_session",
            })
            if status == "ATTRIBUTED":
                rec = self._flow_to_record(flow, session_id, profile_name, 6 if proto.upper() == "TCP" else 17)
                records.append(rec)

        session = EvaluationSession(
            session_id=session_id,
            start_timestamp=time.time() - 300,
            end_timestamp=time.time(),
            traffic_category=TRAFFIC_CATEGORY_BENIGN,
            traffic_subtype=profile_name,
            interface="unknown",
            source_machine="localhost",
            target_machine="localhost",
            generator_command=session_id,
            record_count=len(records),
            extra_metadata={
                "expected_protocol": 6 if proto.upper() == "TCP" else 17,
                "dst_port": dst_port,
                "generation_events": target_count,
                "profile": profile_name,
                "payload_size": profile["payload_size"],
                "interval": profile["interval"],
                "burst_count": profile["burst_count"],
            },
        )
        self.sessions.append(session)
        self.log(f"Profile {profile_name}: {len(records)} attributed flows")
        return records

    def _flow_to_record(self, flow, session_id, subtype, expected_proto):
        features = flow.get_features()
        model_pred, model_conf = self.model.predict(features)
        arr = np.asarray(features, dtype=np.float64).reshape(1, -1)
        arr_scaled = self.model.scaler.transform(arr)
        probs = self.model.clf.predict_proba(arr_scaled)[0]
        model_probs = {CLASS_LABELS[i]: float(probs[i]) for i in range(min(len(probs), len(CLASS_LABELS)))}
        rule_result = self.rule_engine.process_flow(flow)

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
            collection_interface="unknown",
            source_machine="localhost",
            target_machine="localhost",
            generator_command=subtype,
            generator_log="\n".join(self.logs),
            extra_metadata={
                "flow_timeout": FLOW_TIMEOUT,
                "collector_version": "stage11.7",
                "expected_protocol": expected_proto,
                "protocol_match": flow.protocol == expected_proto,
                "attribution_status": "ATTRIBUTED",
                "traffic_generation_category": subtype,
            },
        )

    def collect_all(self):
        self.log("=== Starting Stage 11.7 Expanded Benign Collection (direct tracking) ===")
        for profile_name, profile in TCP_PROFILES.items():
            target = min(profile["count"], TARGET_TCP - sum(1 for r in self.records if r.protocol == 6))
            if target <= 0:
                continue
            recs = self._capture_profile("TCP", profile_name, profile, target)
            self.records.extend(recs)

        for profile_name, profile in UDP_PROFILES.items():
            target = min(profile["count"], TARGET_UDP - sum(1 for r in self.records if r.protocol == 17))
            if target <= 0:
                continue
            recs = self._capture_profile("UDP", profile_name, profile, target)
            self.records.extend(recs)

        dataset = EvaluationDataset(name="stage_11_7_expanded")
        for rec in self.records:
            dataset.add_record(rec)
        for sess in self.sessions:
            dataset.add_session(sess)
        self.log(f"=== Collection complete: {len(dataset.records)} total attributed flows ===")
        return dataset

    def save(self, dataset):
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        base_name = f"expanded_11_7_{ts}"
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
    collector = ExpandedCollector()
    dataset = collector.collect_all()
    jsonl_path, log_path, attribution_path = collector.save(dataset)

    print(f"Dataset: {jsonl_path}")
    print(f"Log: {log_path}")
    print(f"Attribution log: {attribution_path}")
    print(f"Total flows: {len(dataset.records)}")

    with open(attribution_path, "r", encoding="utf-8") as f:
        attribution_log = json.load(f)
    attributed = sum(1 for e in attribution_log if e.get("attribution_status") == "ATTRIBUTED")
    print(f"Attributed: {attributed}/{len(attribution_log)}")

if __name__ == "__main__":
    main()

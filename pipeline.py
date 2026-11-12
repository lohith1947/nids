"""
NIDS End-to-End Pipeline (Stage 5)

Orchestrates the full detection chain from packet capture through
alert creation:

    Scapy packet
        -> FlowManager.process_packet(packet)
        -> Completed Flow(s)
        -> For each completed Flow:
             1. flow.get_features()
             2. RuleEngine.process_flow(flow)
             3. CorrelationEngine.correlate(features, rule_result)
             4. RiskScorer.score(detection_result)
             5. AlertManager.create_alert(detection_result, risk_result, flow)

Design:
    - Single-threaded, sequential processing.
    - FlowManager and RuleEngine are stateful and shared across all
      flows for the entire capture session.
    - The ML model is loaded once in __init__, not per-flow.
    - Each stage is wrapped in try/except so a failure on one flow
      does not crash the pipeline.
    - Scapy's capture_packets blocking call is used directly; no
      second capture implementation.

Limitations:
    - FlowManager timeouts only trigger on packet arrival (existing
      behavior).  Outstanding flows at shutdown are not finalized
      unless a new packet triggers the timeout check.
      The close_all_flows() method provides a best-effort finalization
      using FlowManager.reset(), but this discards unprocessed flows.
      A background timeout thread would require modifying FlowManager,
      which is outside scope.
    - capture_packets is blocking.  stop() sets a flag but cannot
      interrupt a blocking sniff() call without KeyboardInterrupt.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from pathlib import Path
from typing import List, Optional, Dict, Any

from .flow import Flow
from .flow_manager import FlowManager
from .rule_engine import RuleEngine
from .model import NIDSModel
from .correlator import CorrelationEngine, DetectionResult
from .risk_scorer import RiskScorer, RiskResult
from .alerts import AlertManager, Alert, AlertManagerConfig
from .packet_capture import capture_packets

logger = logging.getLogger(__name__)

# Default model path
DEFAULT_MODEL_PATH = str(Path(__file__).resolve().parent / "models" / "nids_model.joblib")


class NIDSPipeline:
    """
    End-to-end NIDS pipeline that connects packet capture through alert
    generation using all existing, unmodified components.

    The pipeline owns:
        - FlowManager (stateful, packet -> flow)
        - RuleEngine (stateful, cross-flow rules)
        - CorrelationEngine (ML + rule fusion)
        - RiskScorer (risk score)
        - AlertManager (alert storage, dedup, rate limiting)
    """

    def __init__(
        self,
        flow_manager: Optional[FlowManager] = None,
        rule_engine: Optional[RuleEngine] = None,
        correlation_engine: Optional[CorrelationEngine] = None,
        risk_scorer: Optional[RiskScorer] = None,
        alert_manager: Optional[AlertManager] = None,
        model_path: Optional[str] = None,
        flow_timeout: float = 10.0,
    ):
        """
        Initialise the pipeline with optional dependency injection.

        Any component not supplied is created with defaults.  The ML model
        is loaded once (not per-flow) when creating a CorrelationEngine.

        Args:
            flow_manager:     Optional pre-configured FlowManager.
            rule_engine:      Optional pre-configured RuleEngine.
            correlation_engine: Optional pre-configured CorrelationEngine.
            risk_scorer:      Optional pre-configured RiskScorer.
            alert_manager:    Optional pre-configured AlertManager.
            model_path:       Path to the trained model joblib file.
                              If correlation_engine is also supplied, this is ignored.
            flow_timeout:     Seconds of inactivity before a flow is closed.
        """
        self.flow_timeout = flow_timeout

        # FlowManager — stateful, owns all active flows
        self.flow_manager = flow_manager or FlowManager(flow_timeout=flow_timeout)

        # RuleEngine — stateful, owns cross-flow detection state
        self.rule_engine = rule_engine or RuleEngine()

        # CorrelationEngine — wraps the ML model
        if correlation_engine is not None:
            self.correlation_engine = correlation_engine
        else:
            path = model_path or DEFAULT_MODEL_PATH
            model = NIDSModel.load(path)
            self.correlation_engine = CorrelationEngine(model=model)

        # RiskScorer — stateless
        self.risk_scorer = risk_scorer or RiskScorer()

        # AlertManager — owns alert store with locks
        self.alert_manager = alert_manager or AlertManager(
            config=AlertManagerConfig()
        )

        # Statistics counters — protected by _stats_lock so that reads from
        # the Streamlit main thread never observe a half-updated dict.
        self._stats = {
            "packets_processed": 0,
            "flows_completed": 0,
            "flows_processed": 0,
            "alerts_created": 0,
            "flows_failed": 0,
        }
        self._stats_lock = threading.Lock()

        # Shutdown flag for graceful stop
        self._stop_flag = False

        # Last packet timestamp — updated on every packet processed.
        # Thread-safe: read under _stats_lock, written by ProcessingWorker.
        self._last_packet_ts: Optional[float] = None

        logger.info("NIDSPipeline initialised: flow_timeout=%.1fs, model=%s",
                     flow_timeout,
                     getattr(self.correlation_engine.model, 'classes_', 'unknown'))

    # ------------------------------------------------------------------
    # Public API: packet processing
    # ------------------------------------------------------------------

    def process_packet(self, packet=None, packet_info=None, timestamp=None) -> List[Alert]:
        """
        Process a single packet through the pipeline.

        Either a raw Scapy packet or a pre-parsed packet_info dict can be
        passed.  This flexibility supports both live capture and testing.

        Args:
            packet:      Raw Scapy packet (passed to FlowManager.process_packet).
            packet_info: Pre-parsed dict (passed to FlowManager.process_packet_info).
            timestamp:   Optional explicit timestamp (for packet_info mode).

        Returns:
            List of Alert objects generated from any completed flows
            spawned by this packet.  May be empty.
        """
        with self._stats_lock:
            self._stats["packets_processed"] += 1
            # Update last packet timestamp from actual packet
            if packet is not None and hasattr(packet, "time"):
                self._last_packet_ts = float(packet.time)
            elif packet_info is not None and timestamp is not None:
                self._last_packet_ts = timestamp

        if self._stop_flag:
            return []

        # Step 1: FlowManager — packet -> completed flows
        try:
            completed_flows = self._extract_flows(packet, packet_info, timestamp)
        except Exception as e:
            with self._stats_lock:
                self._stats["flows_failed"] += 1
            logger.error(
                "Pipeline [flow_extraction] failed: %s", e, exc_info=True
            )
            return []

        if not completed_flows:
            return []

        # Step 2: Process each completed flow
        alerts: List[Alert] = []
        for flow in completed_flows:
            with self._stats_lock:
                self._stats["flows_completed"] += 1
            try:
                flow_alerts = self._process_flow(flow)
                alerts.extend(flow_alerts)
            except Exception as e:
                with self._stats_lock:
                    self._stats["flows_failed"] += 1
                logger.error(
                    "Pipeline: failed to process flow (src=%s:%d -> dst=%s:%d, proto=%d): %s",
                    flow.src_ip, flow.src_port,
                    flow.dst_ip, flow.dst_port,
                    flow.protocol,
                    e,
                    exc_info=True,
                )
                continue

        return alerts

    def process_packet_info(
        self,
        packet_info: dict,
        timestamp: float,
    ) -> List[Alert]:
        """
        Convenience wrapper for testing: process a pre-parsed packet dict.
        """
        return self.process_packet(packet_info=packet_info, timestamp=timestamp)

    # ------------------------------------------------------------------
    # Public API: capture
    # ------------------------------------------------------------------

    def start_capture(
        self,
        interface: Optional[str] = None,
        count: int = 0,
    ) -> None:
        """
        Start live packet capture using the existing capture_packets function.

        This is a blocking call.  It will run until `count` packets are
        captured (if count > 0) or until interrupted with Ctrl-C.

        The pipeline's process_packet method is used as the Scapy callback.

        Args:
            interface: Scapy interface name (e.g. "enp0s8").  None = default.
            count:     Number of packets to capture (0 = unlimited).
        """
        self._stop_flag = False
        logger.info("Starting capture: interface=%s, count=%d", interface, count)

        def packet_callback(packet):
            if self._stop_flag:
                return
            try:
                self.process_packet(packet=packet)
            except Exception as e:
                logger.error("Pipeline: unhandled error in capture callback: %s", e,
                             exc_info=True)

        try:
            capture_packets(
                interface=interface,
                callback=packet_callback,
                count=count,
                store=False,
            )
        except KeyboardInterrupt:
            logger.info("Capture interrupted by user (Ctrl-C). Shutting down gracefully.")
        finally:
            self._stop_flag = True
            logger.info("Capture stopped. Final stats: %s", self._stats)

    def stop(self) -> None:
        """
        Signal the pipeline to stop.

        This sets a flag that prevents further packet processing.  It does
        NOT interrupt a blocking capture_packets() call — that requires
        KeyboardInterrupt (Ctrl-C).

        Limitation: Scapy's sniff() cannot be programmatically interrupted
        without modifying packet_capture.py.  The stop flag ensures no new
        alerts are created after shutdown is requested.
        """
        self._stop_flag = True
        logger.info("Stop signal received. Pipeline will finish current packet and halt.")

    # ------------------------------------------------------------------
    # Public API: finalization
    # ------------------------------------------------------------------

    def finalize_flows(self) -> List[Alert]:
        """
        Best-effort finalization of outstanding flows at shutdown.

        FlowManager's timeout only triggers on new packet arrival (existing
        limitation).  This method retrieves all currently active flows,
        processes them, and clears the FlowManager state.

        Returns:
            List of Alert objects from the finalized flows.
        """
        all_alerts: List[Alert] = []
        active_flows = self.flow_manager.get_all_flows()

        for flow in active_flows:
            try:
                with self._stats_lock:
                    self._stats["flows_completed"] += 1
                flow_alerts = self._process_flow(flow)
                all_alerts.extend(flow_alerts)
            except Exception as e:
                with self._stats_lock:
                    self._stats["flows_failed"] += 1
                logger.error("Pipeline: error finalizing flow: %s", e, exc_info=True)

        self.flow_manager.reset()
        logger.info("Finalized %d outstanding flows.", len(active_flows))
        return all_alerts

    # ------------------------------------------------------------------
    # Public API: statistics and alert access
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, int]:
        """
        Return pipeline processing statistics (thread-safe copy).

        Includes both the atomic counter snapshot (under _stats_lock) and
        live values derived from the owned FlowManager and AlertManager.
        The ``flows_in_progress`` value is read directly from
        FlowManager.get_active_flow_count() (a GIL-atomic ``len()`` on the
        flow dict), and ``alerts_suppressed`` is read from AlertManager's
        authoritative ``total_suppressed`` counter (protected by its own
        lock).  Neither value is maintained as a duplicate counter.
        """
        with self._stats_lock:
            result = dict(self._stats)
        # Augment with live values from owned components.
        # FlowManager is single-owner (ProcessingWorker), so len() is safe.
        result["flows_in_progress"] = self.flow_manager.get_active_flow_count()
        # AlertManager has its own lock; get_stats() is thread-safe.
        result["alerts_suppressed"] = self.alert_manager.get_stats()["total_suppressed"]
        result["last_packet_ts"] = self._last_packet_ts
        return result

    def get_alerts(self) -> List[Alert]:
        """Delegate to AlertManager.get_all_alerts()."""
        return self.alert_manager.get_all_alerts()

    def get_recent_alerts(self, n: int = 10) -> List[Alert]:
        """Delegate to AlertManager.get_recent_alerts()."""
        return self.alert_manager.get_recent_alerts(n)

    def get_alert_stats(self) -> Dict[str, int]:
        """Delegate to AlertManager.get_stats()."""
        return self.alert_manager.get_stats()

    def count_alerts_by_severity(self) -> Dict[str, int]:
        """Delegate to AlertManager.count_by_severity()."""
        return self.alert_manager.count_by_severity()

    def count_alerts_by_attack_type(self) -> Dict[str, int]:
        """Delegate to AlertManager.count_by_attack_type()"""
        return self.alert_manager.count_by_attack_type()

    # ------------------------------------------------------------------
    # Internal: flow extraction
    # ------------------------------------------------------------------

    def _extract_flows(self, packet, packet_info, timestamp) -> List[Flow]:
        """
        Route the packet to the appropriate FlowManager method.
        """
        if packet_info is not None and timestamp is not None:
            return self.flow_manager.process_packet_info(packet_info, timestamp)
        elif packet is not None:
            return self.flow_manager.process_packet(packet)
        else:
            return []

    # ------------------------------------------------------------------
    # Internal: per-flow processing
    # ------------------------------------------------------------------

    def _process_flow(self, flow: Flow) -> List[Alert]:
        """
        Process a single completed Flow through the full detection chain.

        Returns a list of Alert objects (0 or 1 typically).  Each stage is
        wrapped in try/except so failures are logged but don't crash the
        pipeline.

        Returns:
            List containing 0 or 1 Alert objects.  Returns empty list if
            no alert was created (e.g., BENIGN below severity filter, or
            an intermediate stage failed).
        """
        # --- Stage 1: Feature extraction ---
        try:
            features = flow.get_features()
        except Exception as e:
            with self._stats_lock:
                self._stats["flows_failed"] += 1
            logger.error(
                "Pipeline [feature_extraction] failed for flow %s:%d -> %s:%d: %s",
                flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, e,
                exc_info=True,
            )
            return []

        # --- Stage 2: Rule Engine ---
        try:
            rule_result = self.rule_engine.process_flow(flow)
        except Exception as e:
            with self._stats_lock:
                self._stats["flows_failed"] += 1
            logger.error(
                "Pipeline [rule_engine] failed for flow %s:%d -> %s:%d: %s",
                flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, e,
                exc_info=True,
            )
            return []

        # --- Stage 3: Correlation Engine (ML + Rule fusion) ---
        try:
            detection = self.correlation_engine.correlate(features, rule_result)
        except Exception as e:
            with self._stats_lock:
                self._stats["flows_failed"] += 1
            logger.error(
                "Pipeline [correlation] failed for flow %s:%d -> %s:%d: %s",
                flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, e,
                exc_info=True,
            )
            return []

        # --- Stage 4: Risk Scoring ---
        try:
            risk = self.risk_scorer.score(detection)
        except Exception as e:
            with self._stats_lock:
                self._stats["flows_failed"] += 1
            logger.error(
                "Pipeline [risk_scoring] failed for flow %s:%d -> %s:%d: %s",
                flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, e,
                exc_info=True,
            )
            return []

        # --- Stage 5: Alert Creation ---
        try:
            alert = self.alert_manager.create_alert(detection, risk, flow, features=features)
            with self._stats_lock:
                self._stats["flows_processed"] += 1
                if alert is not None:
                    self._stats["alerts_created"] += 1
            if alert is not None:
                return [alert]
            return []
        except Exception as e:
            with self._stats_lock:
                self._stats["flows_failed"] += 1
            logger.error(
                "Pipeline [alert_creation] failed for flow %s:%d -> %s:%d: %s",
                flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, e,
                exc_info=True,
            )
            return []


__all__ = [
    "NIDSPipeline",
    "ProcessingWorker",
    "DetectionResult",
    "RiskResult",
    "Alert",
    "AlertManagerConfig",
]


class ProcessingWorker:
    """
    Single-owner worker thread that processes packets from a queue.

    This class guarantees that FlowManager and RuleEngine are touched by
    exactly one execution context — the worker thread.  Streamlit (the
    main thread) only reads published snapshots (alerts, stats) produced
    by this worker.

    Architecture:
        queue.Queue  (producer: capture thread)
            │
            ▼
        ProcessingWorker.run()  ← single owner of FlowManager + RuleEngine
            │
            ├── self._pipeline.process_packet(packet)
            ├── publishes snapshots every N packets
            └── on stop_event: finalize_flows(), join

    Lifecycle:
        start()  → spawns daemon thread, blocks on queue.get(timeout=0.5)
        stop()   → sets event, joins thread, drains queue
    """

    def __init__(
        self,
        pipeline: NIDSPipeline,
        packet_queue: queue.Queue,
        stop_event: threading.Event,
        snapshot_interval: int = 100,
    ):
        self._pipeline = pipeline
        self._packet_queue = packet_queue
        self._stop_event = stop_event
        self._snapshot_interval = snapshot_interval
        self._thread: Optional[threading.Thread] = None
        self._packets_processed_by_worker: int = 0

    def start(self) -> None:
        """Start the worker thread. Idempotent — only one thread can start."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="NIDSProcessingWorker"
        )
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        """Signal the worker to stop and join. Drains remaining queue."""
        self._stop_event.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def is_running(self) -> bool:
        """Return True if the worker thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    def _run(self) -> None:
        """Main processing loop — single owner of FlowManager + RuleEngine."""
        while not self._stop_event.is_set():
            try:
                item = self._packet_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                self._process_queue_item(item)
                self._packets_processed_by_worker += 1
            except Exception as e:
                logger.error(
                    "ProcessingWorker: error processing packet: %s",
                    e, exc_info=True,
                )
            finally:
                self._packet_queue.task_done()

        # Drain any remaining packets in the queue
        while True:
            try:
                item = self._packet_queue.get_nowait()
            except queue.Empty:
                break
            try:
                self._process_queue_item(item)
                self._packets_processed_by_worker += 1
            except Exception as e:
                logger.error(
                    "ProcessingWorker: error draining packet: %s",
                    e, exc_info=True,
                )
            finally:
                self._packet_queue.task_done()

        # Finalize outstanding flows
        try:
            self._pipeline.finalize_flows()
        except Exception as e:
            logger.error(
                "ProcessingWorker: error finalizing flows: %s",
                e, exc_info=True,
            )

    def _process_queue_item(self, item) -> None:
        """
        Dispatch a queue item to the pipeline.

        The queue may contain either:
          - A raw Scapy packet (most common from capture thread)
          - A (packet_info, timestamp) tuple (for testing)
        """
        if isinstance(item, tuple):
            packet_info, timestamp = item
            self._pipeline.process_packet_info(packet_info, timestamp)
        else:
            self._pipeline.process_packet(packet=item)

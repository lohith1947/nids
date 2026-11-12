"""Privileged live-capture smoke test; safe to collect with ordinary pytest."""

from __future__ import annotations

import ctypes
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from NIDS.correlator import CorrelationEngine
from NIDS.model import NIDSModel
from NIDS.packet_capture import capture_packets
from NIDS.pipeline import NIDSPipeline, ProcessingWorker


def _has_capture_privileges() -> bool:
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _loopback_interface() -> str | None:
    from scapy.all import conf

    for name, interface in conf.ifaces.items():
        if "loopback" in interface.name.lower() or "loopback" in name.lower():
            return name
    return None


def test_capture_continues_and_stops_cleanly() -> None:
    if not _has_capture_privileges():
        pytest.skip("Live packet capture requires Administrator/root privileges and a working Npcap/libpcap interface.")

    interface = _loopback_interface()
    if interface is None:
        pytest.skip("Scapy could not find a loopback capture interface.")

    model_path = Path(__file__).resolve().parent.parent / "models" / "nids_model.joblib"
    model = NIDSModel.load(str(model_path))
    pipeline = NIDSPipeline(correlation_engine=CorrelationEngine(model=model))
    stop_event = threading.Event()
    packet_queue: queue.Queue = queue.Queue(maxsize=10000)
    worker = ProcessingWorker(pipeline=pipeline, packet_queue=packet_queue, stop_event=stop_event)
    worker.start()

    captured_count = 0
    capture_error: Exception | None = None

    def packet_callback(packet: object) -> None:
        nonlocal captured_count
        if stop_event.is_set():
            return
        try:
            packet_queue.put(packet, timeout=0.1)
            captured_count += 1
        except queue.Full:
            pass

    def capture_loop() -> None:
        nonlocal capture_error
        try:
            capture_packets(
                interface=interface,
                callback=packet_callback,
                count=0,
                store=False,
                stop_callback=lambda packet=None: stop_event.is_set(),
            )
        except Exception as exc:  # checked after cleanup below
            capture_error = exc

    capture_thread = threading.Thread(target=capture_loop, daemon=True, name="NIDSCaptureThread")
    capture_thread.start()
    try:
        time.sleep(1)
        subprocess.run(["ping", "-n", "15", "127.0.0.1"], capture_output=True, text=True, timeout=15)
        time.sleep(2)
        stats = pipeline.get_stats()
    finally:
        stop_event.set()
        # Wake sniff's stop_filter so the capture thread can exit promptly.
        try:
            subprocess.run(["ping", "-n", "1", "127.0.0.1"], capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
        worker.stop(timeout=10.0)
        capture_thread.join(timeout=5.0)

    if capture_error and ("permission" in str(capture_error).lower() or "access" in str(capture_error).lower()):
        pytest.skip(f"Npcap denied loopback capture: {capture_error}")

    assert capture_error is None, f"Capture failed: {capture_error}"
    assert captured_count > 10
    assert stats["packets_processed"] > 10
    assert stats["flows_failed"] == 0
    assert packet_queue.empty()
    assert not worker.is_running()
    assert not capture_thread.is_alive()
    assert not any(thread.name == "NIDSProcessingWorker" and thread.is_alive() for thread in threading.enumerate())


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))

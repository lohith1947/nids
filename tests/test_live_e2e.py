"""
Stage 9 Validation Script: End-to-End Live Pipeline Test
Tests the complete pipeline with live Scapy loopback capture.
Uses BENIGN traffic only (ping, local HTTP-like TCP, loopback DNS).
"""
import sys, os, time, threading, queue, subprocess, logging
from pathlib import Path
from contextlib import contextmanager

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

from NIDS.pipeline import NIDSPipeline, ProcessingWorker
from NIDS.correlator import CorrelationEngine
from NIDS.model import NIDSModel

# --- Initialize pipeline ---
model_path = Path(__file__).resolve().parent.parent / "models" / "nids_model.joblib"
model = NIDSModel.load(str(model_path))
engine = CorrelationEngine(model=model)
pipeline = NIDSPipeline(correlation_engine=engine)

# --- Setup capture ---
from scapy.all import conf
lb_iface = None
for name, iface in conf.ifaces.items():
    if "Loopback" in iface.name or "loopback" in name.lower():
        lb_iface = iface
        break
print(f"Loopback interface: {lb_iface.name!r} (index={lb_iface.index})")

stop_event = threading.Event()
packet_queue = queue.Queue(maxsize=10000)

worker = ProcessingWorker(
    pipeline=pipeline,
    packet_queue=packet_queue,
    stop_event=stop_event,
)
worker.start()

# Capture thread using the CURRENT code's stop_callback style
captured_count = [0]  # mutable container for thread communication
capture_error = [None]
def capture_loop():
    from NIDS.packet_capture import capture_packets
    def packet_callback(packet):
        if stop_event.is_set():
            return
        try:
            packet_queue.put(packet, timeout=0.1)
            captured_count[0] += 1
        except queue.Full:
            pass
    # NOTE: Using current code's lambda style (0-arg)
    try:
        capture_packets(
            interface=lb_iface,
            callback=packet_callback,
            count=0,
            store=False,
            stop_callback=lambda: stop_event.is_set(),
        )
    except Exception as e:
        capture_error[0] = f"{type(e).__name__}: {e}"

cap_thread = threading.Thread(target=capture_loop, daemon=True, name="NIDSCaptureThread")
cap_thread.start()

print(f"Capture started. Waiting for traffic...")

# Generate benign traffic
print("\n--- Generating ICMP (ping) traffic ---")
subprocess.run(["ping", "-n", "3", "127.0.0.1"], capture_output=True, text=True, timeout=10)
time.sleep(1)

print("\n--- Generating TCP loopback traffic ---")
# Generate TCP loopback traffic by making multiple local connections
for port in [8080, 8081, 8082]:
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", port))
        s.close()
    except:
        pass

time.sleep(2)

# Check stats
stats = pipeline.get_stats()
print(f"\nPipeline stats: {stats}")
print(f"Dashboard captured_packet_count: {captured_count[0]}")
print(f"Queue size: {packet_queue.qsize()}")
print(f"Worker alive: {worker.is_running()}")
print(f"Capture thread alive: {cap_thread.is_alive()}")
if capture_error[0]:
    print(f"Capture thread error: {capture_error[0]}")

print("\n--- Stopping ---")
stop_event.set()
worker.stop(timeout=5)
cap_thread.join(timeout=5)
time.sleep(0.5)

stats_final = pipeline.get_stats()
print(f"Final stats: {stats_final}")
print(f"Alerts: {len(pipeline.get_alerts())}")

# Check if any ICMP packets were actually captured
print(f"\nTotal packets captured by capture thread: {captured_count[0]}")
print(f"Total packets processed by worker: {stats_final['packets_processed']}")
print(f"Queue items remaining: {packet_queue.qsize()}")

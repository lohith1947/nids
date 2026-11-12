"""Simple Streamlit UI for the NIDS Sentinel detection pipeline."""

from __future__ import annotations

import io
import queue
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st
from scapy.utils import rdpcap

# The project directory is the NIDS package. Add its parent so this file also
# works when launched with ``python -m streamlit run dashboard.py`` from here.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from NIDS.pipeline import NIDSPipeline  # noqa: E402
from NIDS.dashboard_data import compute_kpis  # noqa: E402


SEVERITY_ORDER = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_LABEL = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH": "🟠 HIGH",
    "MEDIUM": "🟡 MEDIUM",
    "LOW": "⚪ LOW",
    "INFORMATIONAL": "⚪ INFO",
}
PROTOCOL_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP"}


def _init_state() -> None:
    defaults = {
        "pipeline": None,
        "pipeline_error": None,
        "capture_running": False,
        "has_started": False,
        "worker": None,
        "worker_mode": None,
        "worker_stop": threading.Event(),
        "worker_messages": queue.Queue(),
        "stop_notice": False,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def _worker_alive() -> bool:
    worker = st.session_state.worker
    return worker is not None and worker.is_alive()


def _mark_finished_worker() -> None:
    if st.session_state.capture_running and not _worker_alive():
        st.session_state.capture_running = False
        st.session_state.worker_mode = None


def _capture_worker(pipeline: NIDSPipeline, interface: str | None, messages: queue.Queue) -> None:
    try:
        pipeline.start_capture(interface=interface)
    except Exception as exc:  # report worker failures in the Streamlit thread
        messages.put(("error", f"Capture failed: {exc}"))


def _replay_worker(
    pipeline: NIDSPipeline,
    pcap_bytes: bytes,
    stop_event: threading.Event,
    messages: queue.Queue,
) -> None:
    try:
        packets = rdpcap(io.BytesIO(pcap_bytes))
        completed = True
        for packet in packets:
            if stop_event.is_set():
                completed = False
                break
            pipeline.process_packet(packet)
            time.sleep(0.005)
        if completed:
            finalized = pipeline.finalize_flows()
            messages.put((
                "info",
                f"PCAP replay finished ({len(packets)} packets read; {len(finalized)} final alerts).",
            ))
        else:
            messages.put(("info", "PCAP replay stopped before the file ended."))
    except Exception as exc:
        messages.put(("error", f"Could not replay this PCAP: {exc}"))


def _start_worker(mode: str, *, interface: str | None = None, pcap_bytes: bytes | None = None) -> bool:
    """Start one daemon worker, refusing a second worker while one is alive."""
    if _worker_alive():
        return False

    pipeline = st.session_state.pipeline
    stop_event = st.session_state.worker_stop
    stop_event.clear()
    if mode == "capture":
        target = _capture_worker
        args = (pipeline, interface, st.session_state.worker_messages)
    else:
        target = _replay_worker
        args = (pipeline, pcap_bytes or b"", stop_event, st.session_state.worker_messages)

    worker = threading.Thread(target=target, args=args, daemon=True, name=f"nids-{mode}")
    st.session_state.worker = worker
    st.session_state.worker_mode = mode
    st.session_state.capture_running = True
    st.session_state.has_started = True
    st.session_state.stop_notice = False
    worker.start()
    return True


def _protocol(value: Any) -> str:
    try:
        return PROTOCOL_NAMES.get(int(value), str(value))
    except (TypeError, ValueError):
        return str(value)


def _alert_value(alert: Any, name: str, default: Any = "") -> Any:
    return getattr(alert, name, default)


def _alert_rows(alerts: list[Any]) -> list[dict[str, Any]]:
    rows = []
    for alert in sorted(alerts, key=lambda item: _alert_value(item, "timestamp", 0), reverse=True)[:200]:
        timestamp = _alert_value(alert, "timestamp", 0)
        rows.append({
            "Time": datetime.fromtimestamp(timestamp).strftime("%H:%M:%S") if timestamp else "—",
            "Severity": SEVERITY_LABEL.get(_alert_value(alert, "severity", ""), _alert_value(alert, "severity", "—")),
            "Attack type": _alert_value(alert, "attack_type", "—"),
            "Risk": round(float(_alert_value(alert, "risk_score", 0)), 1),
            "Source → destination": (
                f"{_alert_value(alert, 'source_ip', '?')}:{_alert_value(alert, 'source_port', '?')} → "
                f"{_alert_value(alert, 'destination_ip', '?')}:{_alert_value(alert, 'destination_port', '?')}"
            ),
            "Protocol": _protocol(_alert_value(alert, "protocol", "—")),
            "Count": _alert_value(alert, "count", 1),
            "_alert": alert,
        })
    return rows


def _render_alert_detail(alert: Any) -> None:
    st.write(_alert_value(alert, "explanation", "No explanation was provided."))
    rules = _alert_value(alert, "triggered_rules", []) or []
    st.markdown("**Triggered rules**")
    st.write(", ".join(rules) if rules else "None")

    left, right = st.columns(2)
    with left:
        rule_prediction = _alert_value(alert, "rule_prediction", "—")
        rule_confidence = float(_alert_value(alert, "rule_confidence", 0) or 0)
        st.markdown(f"**Rule engine:** {rule_prediction} · {rule_confidence:.0%}")
    with right:
        ml_prediction = _alert_value(alert, "ml_prediction", "—")
        ml_confidence = float(_alert_value(alert, "ml_confidence", 0) or 0)
        st.markdown(f"**ML model:** {ml_prediction} · {ml_confidence:.0%}")

    top3 = _alert_value(alert, "ml_top3", None)
    if top3:
        st.markdown("**ML top predictions**")
        st.write(" · ".join(f"{label}: {probability:.1%}" for label, probability in top3))
    st.caption(f"Risk score: {_alert_value(alert, 'risk_score', 0):.1f} / 100")


def _render_live_data() -> None:
    """Fragment refreshes stats, charts and alerts without resetting controls."""
    pipeline: NIDSPipeline = st.session_state.pipeline
    while True:
        try:
            message_type, message = st.session_state.worker_messages.get_nowait()
        except queue.Empty:
            break
        if message_type == "error":
            st.error(message)
        else:
            st.info(message)

    stats = pipeline.get_stats()
    kpis = compute_kpis(pipeline.get_alerts(), stats)

    metric_columns = st.columns(5)
    metrics = [
        ("Packets", kpis["packets_processed"]),
        ("Flows", kpis["flows_completed"]),
        ("Alerts", kpis["alerts_created"]),
        ("Suppressed", kpis["alerts_suppressed"]),
        ("In progress", kpis["flows_in_progress"]),
    ]
    for column, (label, value) in zip(metric_columns, metrics):
        with column:
            st.metric(label, f"{value:,}" if value is not None else "—")

    if not st.session_state.has_started:
        st.info("No capture running — start capture or replay a PCAP to begin monitoring.")
    severity_counts = pipeline.count_alerts_by_severity()
    attack_counts = pipeline.count_alerts_by_attack_type()
    chart_left, chart_right = st.columns(2)
    with chart_left:
        st.markdown("#### Alerts by severity")
        severity_data = {name: int(severity_counts.get(name, 0)) for name in SEVERITY_ORDER}
        severity_data = {key: value for key, value in severity_data.items() if value}
        if severity_data:
            st.bar_chart(pd.Series(severity_data, name="Alerts"), height=220, color="#53e0ae")
        else:
            st.markdown('<div class="chart-empty">No alerts yet</div>', unsafe_allow_html=True)
    with chart_right:
        st.markdown("#### Alerts by attack type")
        attack_data = {key: int(value) for key, value in attack_counts.items() if value}
        if attack_data:
            st.bar_chart(pd.Series(attack_data, name="Alerts"), height=220, color="#71aaff")
        else:
            st.markdown('<div class="chart-empty">No alerts yet</div>', unsafe_allow_html=True)

    st.markdown("#### Recent alerts")
    all_alerts = pipeline.get_alerts()
    rows = _alert_rows(all_alerts)
    controls = st.columns([1, 1, 1.2])
    severities = ["All severities"] + SEVERITY_ORDER[::-1]
    attack_types = sorted({str(row["Attack type"]) for row in rows})
    with controls[0]:
        severity_filter = st.selectbox("Severity", severities, key="severity_filter")
    with controls[1]:
        attack_filter = st.selectbox("Attack type", ["All attack types"] + attack_types, key="attack_filter")
    with controls[2]:
        include_benign = st.toggle("Show benign / informational", value=False, key="include_benign")

    filtered = []
    for row in rows:
        alert = row["_alert"]
        severity = str(_alert_value(alert, "severity", ""))
        attack_type = str(_alert_value(alert, "attack_type", ""))
        if not include_benign and (attack_type == "BENIGN" or severity == "INFORMATIONAL"):
            continue
        if severity_filter != "All severities" and severity != severity_filter:
            continue
        if attack_filter != "All attack types" and attack_type != attack_filter:
            continue
        filtered.append(row)

    display_rows = [{key: value for key, value in row.items() if key != "_alert"} for row in filtered]
    if display_rows:
        st.dataframe(pd.DataFrame(display_rows), use_container_width=True, hide_index=True)
        for row in filtered:
            alert = row["_alert"]
            title = (
                f"{row['Time']}  ·  {row['Severity']}  ·  {row['Attack type']}  ·  "
                f"{row['Source → destination']}"
            )
            with st.expander(title):
                _render_alert_detail(alert)
    elif st.session_state.has_started:
        st.markdown('<div class="chart-empty">No alerts match these filters.</div>', unsafe_allow_html=True)


st.set_page_config(page_title="Sentinel · NIDS Dashboard", page_icon="🛡️", layout="wide")
st.markdown(
    """
    <style>
      :root{color-scheme:dark}
      .stApp{background:radial-gradient(ellipse at 75% -15%,#182638 0,transparent 42%),#090d14;color:#e9eff7}
      .block-container{max-width:1440px;padding-top:1.6rem;padding-bottom:2.5rem}
      h1,h2,h3,h4{letter-spacing:-.025em}
      h1{font-size:1.9rem!important}
      [data-testid="stMetric"]{background:linear-gradient(145deg,#111a25,#0f151f);border:1px solid #1f2a39;border-radius:14px;padding:15px 17px}
      [data-testid="stMetricLabel"]{color:#94a1b1}
      [data-testid="stMetricValue"]{font-size:1.65rem}
      [data-testid="stVerticalBlockBorderWrapper"]{border-color:#1f2a39}
      .status-pill{display:inline-flex;align-items:center;gap:8px;padding:7px 11px;border-radius:999px;font-size:10px;letter-spacing:.07em;font-weight:750;margin:.25rem 0 1rem}
      .status-pill.on{border:1px solid #245a48;background:#10251f;color:#9ce9ca}
      .status-pill.off{border:1px solid #303b49;background:#151d27;color:#aab5c3}
      .status-dot{width:7px;height:7px;border-radius:50%;background:#53e0ae;box-shadow:0 0 10px #53e0ae88}
      .status-pill.off .status-dot{background:#748195;box-shadow:none}
      .chart-empty{min-height:210px;border:1px dashed #293648;border-radius:12px;display:grid;place-content:center;color:#8290a2;font-size:12px;text-align:center;background:#0e151e}
      [data-testid="stDataFrame"]{border:1px solid #1f2a39;border-radius:10px;overflow:hidden}
      [data-testid="stExpander"]{border-color:#202b39;background:#101722}
      div.stButton>button{border-radius:8px;font-weight:650}
      div.stButton>button[kind="primary"]{background:#53e0ae;border-color:#53e0ae;color:#082017}
      [data-testid="stFileUploader"]{border:1px dashed #293648;border-radius:9px;background:#0c131c}
      @media(max-width:700px){.block-container{padding-left:1rem;padding-right:1rem}[data-testid="stMetric"]{padding:12px}}
    </style>
    """,
    unsafe_allow_html=True,
)

_init_state()
if st.session_state.pipeline is None and st.session_state.pipeline_error is None:
    try:
        st.session_state.pipeline = NIDSPipeline()
    except Exception as exc:
        st.session_state.pipeline_error = exc

if st.session_state.pipeline_error is not None:
    st.error("Trained model not found at models/nids_model.joblib — run train_model.py first")
    st.stop()

_mark_finished_worker()
st.markdown(
    '<div style="display:flex;align-items:center;gap:12px;margin-bottom:2px">'
    '<div style="width:38px;height:38px;border:1px solid #294237;border-radius:11px;'
    'display:grid;place-items:center;color:#53e0ae;background:#101a1e;font-size:20px">♧</div>'
    '<div><div style="font-weight:750;letter-spacing:.06em">SENTINEL</div>'
    '<div style="font-size:10px;color:#8290a2;letter-spacing:.1em;text-transform:uppercase">Network intelligence</div></div>'
    '</div>',
    unsafe_allow_html=True,
)
title_col, status_col = st.columns([4, 1])
with title_col:
    st.markdown("## Network overview")
    st.caption("Live traffic analysis and intrusion alerts")
with status_col:
    status_slot = st.empty()

st.markdown("#### Capture controls")
control_cols = st.columns([1.3, 1, 1, 1.25, 2.1])
with control_cols[0]:
    interface = st.text_input("Network interface", value="auto", help="Leave blank or use auto to let Scapy choose.")
with control_cols[1]:
    start_clicked = st.button("▶  Start capture", type="primary", use_container_width=True)
with control_cols[2]:
    stop_clicked = st.button("■  Stop", use_container_width=True)
with control_cols[3]:
    replay_clicked = st.button("↻  Replay PCAP", use_container_width=True)
with control_cols[4]:
    uploaded_pcap = st.file_uploader("PCAP file", type=["pcap", "pcapng"], label_visibility="collapsed")

if start_clicked:
    if _start_worker("capture", interface=None if not interface.strip() or interface.strip().lower() == "auto" else interface.strip()):
        st.rerun()
    st.warning("A capture or replay worker is already running.")

if replay_clicked:
    if uploaded_pcap is None:
        st.warning("Choose a .pcap or .pcapng file first.")
    elif _start_worker("replay", pcap_bytes=uploaded_pcap.getvalue()):
        st.rerun()
    else:
        st.warning("A capture or replay worker is already running.")

if stop_clicked:
    st.session_state.worker_stop.set()
    if st.session_state.worker_mode == "capture":
        st.session_state.pipeline.stop()
    st.session_state.capture_running = False
    st.session_state.stop_notice = st.session_state.worker_mode == "capture"
    st.rerun()

if st.session_state.capture_running:
    st.caption("Live capture runs in a background thread. On Windows, live capture may require Administrator privileges and Npcap.")
if st.session_state.stop_notice:
    st.info("Stop requested. The OS-level sniff may stop on the next packet or when the app exits.")


@st.fragment(run_every="2s")
def live_dashboard() -> None:
    _mark_finished_worker()
    status_text = "CAPTURE ON" if st.session_state.capture_running and st.session_state.worker_mode == "capture" else (
        "REPLAYING PCAP" if st.session_state.capture_running and st.session_state.worker_mode == "replay" else "INACTIVE"
    )
    status_style = "on" if st.session_state.capture_running else "off"
    status_slot.markdown(
        f'<div class="status-pill {status_style}"><span class="status-dot"></span>{status_text}</div>',
        unsafe_allow_html=True,
    )
    _render_live_data()


live_dashboard()

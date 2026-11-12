"""
Regression tests for Stage 11.6.2 attribution correctness fix.

Tests A-G from the Stage 11.6.2 specification.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from NIDS.evaluation.collect_controlled_11_6 import (
    ATTRIBUTED,
    AMBIGUOUS,
    UNATTRIBUTED,
    CONTAMINATED,
    SOURCE_PORT_MODE_EXACT,
    SOURCE_PORT_MODE_EPHEMERAL,
    SOURCE_PORT_MODE_ANY,
    ControlledCollector,
    _validate_source_port,
)


def _match(src_ip, src_port, dst_ip, dst_port, protocol, events, flow_start_time=None):
    collector = ControlledCollector.__new__(ControlledCollector)
    return collector._match_flow_to_generation_by_5tuple(
        src_ip, src_port, dst_ip, dst_port, protocol, events, flow_start_time
    )


def test_dns_false_attribution_rejected():
    """Test A: DNS background traffic (53 -> 51604) must NOT be attributed."""
    events = [{
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "src_port": None,
        "dst_port": 51604,
        "expected_protocol": 17,
        "timestamp": time.time(),
        "flow_id": 0,
        "source_port_mode": SOURCE_PORT_MODE_EPHEMERAL,
        "source_port": None,
    }]
    status, _ = _match("127.0.0.1", 53, "127.0.0.1", 51604, 17, events, time.time())
    assert status != ATTRIBUTED, f"DNS false attribution should be rejected, got {status}"
    print("PASS: Test A - DNS false attribution rejected")


def test_ephemeral_source_port_attributed():
    """Test B: Ephemeral source port to expected dst should be attributed."""
    events = [{
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "src_port": None,
        "dst_port": 51604,
        "expected_protocol": 17,
        "timestamp": time.time(),
        "flow_id": 0,
        "source_port_mode": SOURCE_PORT_MODE_EPHEMERAL,
        "source_port": None,
    }]
    status, _ = _match("127.0.0.1", 50000, "127.0.0.1", 51604, 17, events, time.time())
    assert status == ATTRIBUTED, f"Ephemeral source port should be attributed, got {status}"
    print("PASS: Test B - Ephemeral source port attributed")


def test_exact_source_port_match():
    """Test C: EXACT source port match should be attributed."""
    events = [{
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "src_port": 40000,
        "dst_port": 51604,
        "expected_protocol": 17,
        "timestamp": time.time(),
        "flow_id": 0,
        "source_port_mode": SOURCE_PORT_MODE_EXACT,
        "source_port": 40000,
    }]
    status, _ = _match("127.0.0.1", 40000, "127.0.0.1", 51604, 17, events, time.time())
    assert status == ATTRIBUTED, f"Exact source port match should be attributed, got {status}"
    print("PASS: Test C - EXACT source port match attributed")


def test_exact_source_port_mismatch():
    """Test D: EXACT source port mismatch should NOT be attributed."""
    events = [{
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "src_port": 40000,
        "dst_port": 51604,
        "expected_protocol": 17,
        "timestamp": time.time(),
        "flow_id": 0,
        "source_port_mode": SOURCE_PORT_MODE_EXACT,
        "source_port": 40000,
    }]
    status, _ = _match("127.0.0.1", 40001, "127.0.0.1", 51604, 17, events, time.time())
    assert status != ATTRIBUTED, f"Exact source port mismatch should not be attributed, got {status}"
    print("PASS: Test D - EXACT source port mismatch rejected")


def test_timestamp_outside_window():
    """Test E: Timestamp outside generation window should NOT be attributed."""
    events = [{
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "src_port": None,
        "dst_port": 51604,
        "expected_protocol": 17,
        "timestamp": time.time() - 100,
        "flow_id": 0,
        "source_port_mode": SOURCE_PORT_MODE_EPHEMERAL,
        "source_port": None,
    }]
    status, _ = _match("127.0.0.1", 50000, "127.0.0.1", 51604, 17, events, time.time())
    assert status != ATTRIBUTED, f"Flow outside time window should not be attributed, got {status}"
    print("PASS: Test E - Timestamp outside window rejected")


def test_dst_port_match_but_protocol_differs():
    """Test F: Destination port matches but protocol differs should be CONTAMINATED."""
    events = [{
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "src_port": None,
        "dst_port": 51604,
        "expected_protocol": 17,
        "timestamp": time.time(),
        "flow_id": 0,
        "source_port_mode": SOURCE_PORT_MODE_EPHEMERAL,
        "source_port": None,
    }]
    status, _ = _match("127.0.0.1", 50000, "127.0.0.1", 51604, 6, events, time.time())
    assert status == CONTAMINATED, f"Protocol mismatch should be CONTAMINATED, got {status}"
    print("PASS: Test F - Protocol mismatch is CONTAMINATED")


def test_icmp_not_accidentally_attributed():
    """Test G: ICMP flow should not be attributed solely because protocol=1 and dst IP matches."""
    events = [{
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.2",
        "src_port": None,
        "dst_port": 0,
        "expected_protocol": 1,
        "timestamp": time.time(),
        "flow_id": 0,
        "source_port_mode": SOURCE_PORT_MODE_ANY,
        "source_port": None,
    }]
    status, _ = _match("127.0.0.1", 0, "127.0.0.1", 0, 1, events, time.time())
    assert status != ATTRIBUTED, f"ICMP to wrong destination should not be attributed, got {status}"
    print("PASS: Test G - ICMP to wrong destination not attributed")


def test_validate_source_port_exact():
    valid, _ = _validate_source_port(40000, SOURCE_PORT_MODE_EXACT, 40000)
    assert valid, "EXACT match should be valid"

    valid, _ = _validate_source_port(40001, SOURCE_PORT_MODE_EXACT, 40000)
    assert not valid, "EXACT mismatch should be invalid"
    print("PASS: Source port EXACT validation")


def test_validate_source_port_ephemeral():
    valid, _ = _validate_source_port(50000, SOURCE_PORT_MODE_EPHEMERAL, None)
    assert valid, "Ephemeral port should be valid"

    valid, _ = _validate_source_port(53, SOURCE_PORT_MODE_EPHEMERAL, None)
    assert not valid, "Well-known port should be invalid for EPHEMERAL"
    print("PASS: Source port EPHEMERAL validation")


def test_validate_source_port_any():
    valid, _ = _validate_source_port(53, SOURCE_PORT_MODE_ANY, None)
    assert valid, "ANY mode should accept any port"
    print("PASS: Source port ANY validation")


if __name__ == "__main__":
    test_dns_false_attribution_rejected()
    test_ephemeral_source_port_attributed()
    test_exact_source_port_match()
    test_exact_source_port_mismatch()
    test_timestamp_outside_window()
    test_dst_port_match_but_protocol_differs()
    test_icmp_not_accidentally_attributed()
    test_validate_source_port_exact()
    test_validate_source_port_ephemeral()
    test_validate_source_port_any()
    print("\nAll attribution regression tests passed.")

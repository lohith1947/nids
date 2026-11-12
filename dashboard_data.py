"""Small, framework-independent dashboard calculations."""

from __future__ import annotations

from typing import Any, Mapping, Sequence


def compute_kpis(alerts: Sequence[Any], stats: Mapping[str, Any]) -> dict[str, Any]:
    """Return dashboard counts from a pipeline snapshot and its alert list."""
    return {
        "packets_processed": int(stats.get("packets_processed", 0) or 0),
        "flows_completed": int(stats.get("flows_completed", 0) or 0),
        "alerts_created": int(stats.get("alerts_created", len(alerts)) or 0),
        "total_alerts": len(alerts),
        "alerts_suppressed": int(stats.get("alerts_suppressed", 0) or 0),
        "flows_in_progress": int(stats.get("flows_in_progress", 0) or 0),
        # Retained for the older validation report; the dashboard uses the
        # instrumented flows_in_progress counter above.
        "active_flows": "Not instrumented",
    }


def classify_detection_source(alert: Any) -> str:
    """Classify whether a non-benign verdict came from rules, ML, or both."""
    rule = str(getattr(alert, "rule_prediction", "BENIGN") or "BENIGN").upper()
    ml = str(getattr(alert, "ml_prediction", "BENIGN") or "BENIGN").upper()
    rule_fired = rule != "BENIGN"
    ml_fired = ml != "BENIGN"
    if rule_fired and ml_fired:
        return "RULE + ML"
    if rule_fired:
        return "RULE"
    if ml_fired:
        return "ML"
    return "BENIGN"

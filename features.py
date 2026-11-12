"""
Feature definitions for the NIDS flow-based detection system.

This module defines the canonical feature names and order used by:
  - The live flow extractor (Flow.get_features() / get_feature_dict())
  - The rule engine
  - The ML model (Random Forest) — to be added in a later stage

IMPORTANT: The feature order and definitions here must be preserved so that
live-extracted features are directly compatible with the trained ML model.
"""

# TCP flag bit masks (per section 17 of the project design document)
TCP_SYN = 0x02
TCP_ACK = 0x10
TCP_FIN = 0x01
TCP_RST = 0x04
TCP_PSH = 0x08

# Numeric feature names in the exact order returned by Flow.get_features().
# This order is binding for ML model compatibility.
# These are the numeric, per-flow statistical features used for detection.
NUMERIC_FEATURE_NAMES = [
    # Timing
    "duration",                 # float — seconds
    # Packet volume statistics
    "packet_count",             # int
    "byte_count",               # int
    "average_packet_size",      # float
    "minimum_packet_size",      # int
    "maximum_packet_size",      # int
    "packet_size_std",          # float
    # Traffic rates
    "packets_per_second",       # float
    "bytes_per_second",         # float
    # Directional statistics
    "forward_packets",          # int
    "backward_packets",         # int
    "forward_bytes",            # int
    "backward_bytes",           # int
    # TCP flag counts
    "syn_count",                # int
    "ack_count",                # int
    "fin_count",                # int
    "rst_count",                # int
    "psh_count",                # int
]

# Identity fields — not numeric features, but needed for flow identification
# and for cross-flow (stateful) rule logic.
FLOW_IDENTITY_FIELDS = [
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
]

# All feature names (identity + numeric) for reference
ALL_FEATURE_NAMES = FLOW_IDENTITY_FIELDS + NUMERIC_FEATURE_NAMES

# Protocol numbers
PROTOCOL_TCP = 6
PROTOCOL_UDP = 17
PROTOCOL_ICMP = 1

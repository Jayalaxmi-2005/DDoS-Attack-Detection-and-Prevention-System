"""
simulator.py — Synthetic Traffic Generator
==========================================
Generates realistic-looking synthetic network traffic packets for safe
demo purposes. This module does NOT send any real packets.
All traffic data is created entirely in memory.

Traffic types generated:
  - normal      : Legitimate web/DNS/HTTPS traffic
  - syn_flood   : High-volume TCP SYN from spoofed IPs (known DDoS)
  - udp_flood   : Large UDP packet bursts (known DDoS)
  - http_flood  : Rapid HTTP GET floods (known DDoS)
  - icmp_flood  : Ping / ICMP flood (known DDoS)
  - slowloris   : Slow HTTP connection exhaustion (known DDoS)
  - unknown     : Novel / anomalous traffic (for anomaly detector)
"""

import random
import time
import numpy as np


# ---------------------------------------------------------------------------
# Feature names — must match order expected by the ML models
# ---------------------------------------------------------------------------
FEATURE_NAMES = [
    "pkt_rate",          # packets per second from this IP
    "byte_rate",         # bytes per second from this IP
    "avg_pkt_size",      # average packet size (bytes)
    "syn_ratio",         # fraction of SYN-only packets (0‥1)
    "udp_ratio",         # fraction of UDP packets (0‥1)
    "icmp_ratio",        # fraction of ICMP packets (0‥1)
    "unique_dports",     # distinct destination ports targeted
    "flow_duration",     # seconds this flow has been active
    "ttl_avg",           # average Time-To-Live value
    "flag_entropy",      # Shannon entropy of TCP flag byte distribution
]

ATTACK_LABELS = ["normal", "syn_flood", "udp_flood", "http_flood", "icmp_flood", "slowloris"]


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------
def _rand(lo, hi, decimals=2):
    """Uniform random float, rounded."""
    return round(random.uniform(lo, hi), decimals)


def _entropy(probs):
    """Shannon entropy of a probability list."""
    probs = np.array(probs, dtype=float)
    probs = probs[probs > 0]
    return float(-np.sum(probs * np.log2(probs)))


def _random_ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


# ---------------------------------------------------------------------------
# Feature generators per traffic type
# ---------------------------------------------------------------------------
def _gen_normal():
    return {
        "pkt_rate":       _rand(1, 50),
        "byte_rate":      _rand(500, 50_000),
        "avg_pkt_size":   _rand(200, 1400),
        "syn_ratio":      _rand(0.0, 0.15),
        "udp_ratio":      _rand(0.0, 0.3),
        "icmp_ratio":     _rand(0.0, 0.05),
        "unique_dports":  random.randint(1, 5),
        "flow_duration":  _rand(0.5, 120),
        "ttl_avg":        _rand(55, 128),
        "flag_entropy":   _rand(1.0, 2.5),
    }


def _gen_syn_flood():
    return {
        "pkt_rate":       _rand(5_000, 50_000),
        "byte_rate":      _rand(200_000, 2_000_000),
        "avg_pkt_size":   _rand(40, 60),   # tiny SYN packets
        "syn_ratio":      _rand(0.85, 1.0),
        "udp_ratio":      _rand(0.0, 0.02),
        "icmp_ratio":     _rand(0.0, 0.01),
        "unique_dports":  random.randint(1, 3),
        "flow_duration":  _rand(0.01, 5),
        "ttl_avg":        _rand(30, 64),   # spoofed TTLs vary
        "flag_entropy":   _rand(0.0, 0.5), # nearly all SYN → low entropy
    }


def _gen_udp_flood():
    return {
        "pkt_rate":       _rand(3_000, 40_000),
        "byte_rate":      _rand(1_000_000, 10_000_000),
        "avg_pkt_size":   _rand(512, 1472),
        "syn_ratio":      _rand(0.0, 0.02),
        "udp_ratio":      _rand(0.90, 1.0),
        "icmp_ratio":     _rand(0.0, 0.02),
        "unique_dports":  random.randint(1, 65535),
        "flow_duration":  _rand(0.01, 10),
        "ttl_avg":        _rand(50, 128),
        "flag_entropy":   _rand(0.0, 0.3),
    }


def _gen_http_flood():
    return {
        "pkt_rate":       _rand(500, 10_000),
        "byte_rate":      _rand(50_000, 500_000),
        "avg_pkt_size":   _rand(200, 800),
        "syn_ratio":      _rand(0.10, 0.30),
        "udp_ratio":      _rand(0.0, 0.05),
        "icmp_ratio":     _rand(0.0, 0.01),
        "unique_dports":  random.randint(1, 2),  # port 80/443
        "flow_duration":  _rand(0.1, 30),
        "ttl_avg":        _rand(50, 120),
        "flag_entropy":   _rand(1.5, 2.8),
    }


def _gen_icmp_flood():
    return {
        "pkt_rate":       _rand(1_000, 20_000),
        "byte_rate":      _rand(100_000, 1_000_000),
        "avg_pkt_size":   _rand(64, 1500),
        "syn_ratio":      _rand(0.0, 0.01),
        "udp_ratio":      _rand(0.0, 0.02),
        "icmp_ratio":     _rand(0.85, 1.0),
        "unique_dports":  random.randint(0, 2),
        "flow_duration":  _rand(0.01, 20),
        "ttl_avg":        _rand(48, 128),
        "flag_entropy":   _rand(0.0, 0.2),
    }


def _gen_slowloris():
    return {
        "pkt_rate":       _rand(1, 20),    # very slow
        "byte_rate":      _rand(100, 5_000),
        "avg_pkt_size":   _rand(30, 120),  # small partial headers
        "syn_ratio":      _rand(0.40, 0.80),
        "udp_ratio":      _rand(0.0, 0.02),
        "icmp_ratio":     _rand(0.0, 0.01),
        "unique_dports":  random.randint(1, 2),
        "flow_duration":  _rand(60, 900),  # very long-lived
        "ttl_avg":        _rand(50, 128),
        "flag_entropy":   _rand(0.5, 1.2),
    }


def _gen_unknown_anomaly():
    """
    Unusual traffic that doesn't fit known patterns.
    Used to test the anomaly detector.
    """
    return {
        "pkt_rate":       _rand(200, 800),
        "byte_rate":      _rand(5_000, 30_000),
        "avg_pkt_size":   _rand(1, 30),    # abnormally tiny
        "syn_ratio":      _rand(0.3, 0.5),
        "udp_ratio":      _rand(0.3, 0.5),
        "icmp_ratio":     _rand(0.3, 0.5),
        "unique_dports":  random.randint(100, 1000),
        "flow_duration":  _rand(0.001, 0.1),
        "ttl_avg":        _rand(1, 10),    # very low TTL
        "flag_entropy":   _rand(2.8, 3.5), # high entropy (mixed flags)
    }


_GENERATORS = {
    "normal":    _gen_normal,
    "syn_flood": _gen_syn_flood,
    "udp_flood": _gen_udp_flood,
    "http_flood": _gen_http_flood,
    "icmp_flood": _gen_icmp_flood,
    "slowloris": _gen_slowloris,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def generate_packet(traffic_type=None, include_metadata=True):
    """
    Generate a single synthetic traffic packet.

    Parameters
    ----------
    traffic_type : str or None
        One of the ATTACK_LABELS or 'unknown'. If None, chosen randomly
        with realistic class weights (mostly normal traffic).
    include_metadata : bool
        If True, include source IP, destination IP, timestamp, and label.

    Returns
    -------
    dict  — feature values + optional metadata
    """
    if traffic_type is None:
        # Weighted: 60% normal, rest split among attacks
        traffic_type = random.choices(
            ["normal", "syn_flood", "udp_flood", "http_flood", "icmp_flood", "slowloris", "unknown"],
            weights=[60, 8, 8, 8, 8, 4, 4],
            k=1,
        )[0]

    gen = _GENERATORS.get(traffic_type, _gen_unknown_anomaly)
    features = gen()

    packet = dict(features)  # copy so we don't mutate the generator output

    if include_metadata:
        packet["src_ip"]       = _random_ip()
        packet["dst_ip"]       = "10.0.0.1"  # simulated server
        packet["timestamp"]    = time.time()
        packet["traffic_type"] = traffic_type  # true label (for evaluation)

    return packet


def generate_batch(n=100, traffic_type=None):
    """Generate a list of n synthetic packets."""
    return [generate_packet(traffic_type=traffic_type) for _ in range(n)]


def generate_training_dataset(n_samples=5000):
    """
    Generate a balanced (per-class) training dataset.

    Returns
    -------
    list of dicts (features + 'label' key)
    """
    per_class = n_samples // len(ATTACK_LABELS)
    dataset = []
    for label in ATTACK_LABELS:
        for _ in range(per_class):
            pkt = generate_packet(traffic_type=label, include_metadata=False)
            pkt["label"] = label
            dataset.append(pkt)
    random.shuffle(dataset)
    return dataset

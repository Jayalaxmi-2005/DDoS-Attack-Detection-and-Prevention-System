"""
mitigation.py — Simulated Mitigation Engine
============================================
Demonstrates automated DDoS mitigation responses.

IMPORTANT SAFETY NOTICE
-----------------------
This module is 100% SIMULATED. It does NOT:
  - Modify iptables / Windows Firewall rules
  - Drop or redirect real network packets
  - Communicate with any external system

All "blocked" IPs and "rate limits" are stored in an in-memory set and a
local JSON log. They have zero effect on the host computer's actual network.

Mitigation strategies demonstrated
------------------------------------
1. IP Blacklisting  — add source IP to a simulated block list
2. Rate Limiting    — simulate a token-bucket rate limiter per IP
3. Traffic Scrubbing note — describe what a scrubbing centre would do
4. Auto-unblock     — remove IPs after a configurable cooldown period
"""

import time
import threading
from collections import defaultdict
from logger import get_logger

logger = get_logger("mitigation")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BLOCK_DURATION_SEC   = 60    # auto-unblock after 60 simulated seconds
RATE_LIMIT_THRESHOLD = 1000  # packets/sec — trigger rate limit
CONFIDENCE_THRESHOLD = 0.75  # ML confidence to trigger mitigation


# ---------------------------------------------------------------------------
# In-memory state  (thread-safe with lock)
# ---------------------------------------------------------------------------
_lock       = threading.Lock()
_blocked    = {}        # ip → unblock_time (epoch seconds)
_rate_info  = defaultdict(lambda: {"limited": False, "since": None})
_action_log = []        # list of action dicts (most recent first)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _log_action(action_type: str, ip: str, reason: str, details: str = ""):
    entry = {
        "timestamp":   time.time(),
        "action":      action_type,
        "src_ip":      ip,
        "reason":      reason,
        "details":     details,
        "simulated":   True,   # always True — never real firewall
    }
    with _lock:
        _action_log.insert(0, entry)
        if len(_action_log) > 500:
            _action_log.pop()

    logger.info(
        "[SIMULATED] %s — IP: %s — Reason: %s — %s",
        action_type, ip, reason, details,
    )
    return entry


def _cleanup_expired():
    """Unblock IPs whose block duration has elapsed."""
    now = time.time()
    with _lock:
        expired = [ip for ip, t in _blocked.items() if now >= t]
        for ip in expired:
            del _blocked[ip]
            _rate_info[ip]["limited"] = False
            logger.info("[SIMULATED] Auto-unblocked %s (cooldown expired)", ip)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def respond(packet: dict, ml_result: dict, anomaly_result: dict) -> dict:
    """
    Decide and apply a mitigation action for the given packet.

    Logic
    -----
    1. If ML confidence ≥ threshold AND label is a known attack → block IP.
    2. Else if anomaly score is high → apply rate limit.
    3. Else → no action.

    Parameters
    ----------
    packet         : dict — synthetic packet (must have 'src_ip', 'pkt_rate')
    ml_result      : dict — output of MLDetector.predict()
    anomaly_result : dict — output of AnomalyDetector.score()

    Returns
    -------
    dict — action taken (or 'none')
    """
    _cleanup_expired()

    src_ip = packet.get("src_ip", "0.0.0.0")
    label  = ml_result.get("label", "normal")
    conf   = ml_result.get("confidence", 0.0)
    a_score = anomaly_result.get("anomaly_score", 0.0)

    # --- Already blocked? ---
    with _lock:
        if src_ip in _blocked:
            return {
                "action":  "already_blocked",
                "src_ip":  src_ip,
                "details": "IP already in simulated block list.",
            }

    # --- Strategy 1: Block on confident attack detection ---
    if label != "normal" and conf >= CONFIDENCE_THRESHOLD:
        unblock_at = time.time() + BLOCK_DURATION_SEC
        with _lock:
            _blocked[src_ip] = unblock_at

        return _log_action(
            action_type="IP_BLOCK",
            ip=src_ip,
            reason=f"Supervised ML detected '{label}' (confidence {conf:.0%})",
            details=f"[SIMULATED] Block for {BLOCK_DURATION_SEC}s. No real firewall rule added.",
        )

    # --- Strategy 2: Rate limit on high anomaly score ---
    if anomaly_result.get("is_anomaly") and a_score > 0.65:
        with _lock:
            if not _rate_info[src_ip]["limited"]:
                _rate_info[src_ip] = {"limited": True, "since": time.time()}
                return _log_action(
                    action_type="RATE_LIMIT",
                    ip=src_ip,
                    reason=f"Anomaly detector flagged (score {a_score:.2f})",
                    details="[SIMULATED] Rate limit enforced. No real traffic dropped.",
                )

    # --- No action needed ---
    return {"action": "none", "src_ip": src_ip}


def is_blocked(ip: str) -> bool:
    """Check if an IP is currently in the simulated block list."""
    _cleanup_expired()
    with _lock:
        return ip in _blocked


def get_blocked_ips() -> list:
    """Return list of currently blocked IPs with remaining block time."""
    _cleanup_expired()
    now = time.time()
    with _lock:
        return [
            {
                "ip":             ip,
                "unblocks_in_sec": round(t - now, 1),
            }
            for ip, t in _blocked.items()
        ]


def get_action_log(limit=50) -> list:
    """Return the most recent mitigation actions."""
    with _lock:
        return _action_log[:limit]


def get_stats() -> dict:
    """Summary statistics for the dashboard."""
    _cleanup_expired()
    with _lock:
        n_blocked   = len(_blocked)
        n_limited   = sum(1 for v in _rate_info.values() if v["limited"])
        total_actions = len(_action_log)
    return {
        "currently_blocked":    n_blocked,
        "currently_rate_limited": n_limited,
        "total_actions":        total_actions,
        "block_duration_sec":   BLOCK_DURATION_SEC,
        "simulated":            True,
    }

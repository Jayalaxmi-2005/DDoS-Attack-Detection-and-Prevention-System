"""
logger.py — Event Logging
==========================
Provides a simple logger for all system events (detections, mitigations,
system messages). Logs are saved to data/logs/ as JSON files.
"""

import os
import json
import logging
import time
from datetime import datetime
from threading import Lock

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
LOG_DIR      = os.path.join(os.path.dirname(__file__), "..", "data", "logs")
EVENTS_FILE  = os.path.join(LOG_DIR, "events.json")
_file_lock   = Lock()

os.makedirs(LOG_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Standard Python logger (console + file)
# ---------------------------------------------------------------------------
def get_logger(name: str) -> logging.Logger:
    """Return a configured logger for the given module name."""
    logger = logging.getLogger(f"ddos.{name}")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s",
                              datefmt="%H:%M:%S")
        )
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


# ---------------------------------------------------------------------------
# Event store — persists detection + mitigation events to disk
# ---------------------------------------------------------------------------
_events: list = []          # in-memory ring buffer
MAX_EVENTS    = 2000        # keep last N events in memory


def record_event(event_type: str, data: dict) -> dict:
    """
    Append one structured event to the in-memory list and write to disk.

    Parameters
    ----------
    event_type : str  — e.g. 'detection', 'mitigation', 'system'
    data       : dict — arbitrary payload

    Returns
    -------
    The complete event dict (including generated id + timestamp).
    """
    event = {
        "id":        f"{event_type}_{int(time.time()*1000)}",
        "type":      event_type,
        "timestamp": time.time(),
        "datetime":  datetime.now().isoformat(timespec="seconds"),
        **data,
    }

    _events.append(event)
    if len(_events) > MAX_EVENTS:
        _events.pop(0)

    # Persist to disk (append JSON line to events.json)
    try:
        with _file_lock:
            with open(EVENTS_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
    except OSError as exc:
        get_logger("logger").warning("Could not write event to disk: %s", exc)

    return event


def get_recent_events(limit=100, event_type=None) -> list:
    """
    Return the most recent events, newest first.

    Parameters
    ----------
    limit      : int  — max number to return
    event_type : str or None — filter by type (None → all)
    """
    filtered = (
        [e for e in _events if e["type"] == event_type]
        if event_type
        else _events
    )
    return list(reversed(filtered[-limit:]))


def get_stats() -> dict:
    """Return aggregate counts for the dashboard stats panel."""
    total      = len(_events)
    by_type    = {}
    by_label   = {}
    anomalies  = 0

    for e in _events:
        by_type[e["type"]] = by_type.get(e["type"], 0) + 1
        if e["type"] == "detection":
            lbl = e.get("ml_label", "unknown")
            by_label[lbl] = by_label.get(lbl, 0) + 1
            if e.get("is_anomaly"):
                anomalies += 1

    return {
        "total_events":    total,
        "by_type":         by_type,
        "ml_label_counts": by_label,
        "anomaly_count":   anomalies,
    }

"""
app.py — Flask Web Server & REST API
=====================================
Entry point for the DDoS Detection System.

Starts:
  1. Background simulation thread (generates synthetic traffic)
  2. Detection pipeline (ML + anomaly scoring per packet)
  3. Mitigation engine (simulated)
  4. Flask HTTP server serving the dashboard + REST endpoints

REST API endpoints
------------------
  GET  /                    → dashboard (index.html)
  GET  /api/status          → system status + model stats
  GET  /api/events          → recent detection events
  GET  /api/traffic         → live traffic statistics feed
  GET  /api/mitigation      → blocked IPs + action log
  GET  /api/alerts          → recent high-confidence alerts
  POST /api/simulate/attack → trigger a specific attack type for testing
  POST /api/simulate/stop   → stop any forced attack simulation
"""

import os
import sys
import time
import threading
import random
import math
from collections import deque

from flask import Flask, jsonify, request, send_from_directory

# ---------------------------------------------------------------------------
# Make sure backend/ is on the path when run from any directory
# ---------------------------------------------------------------------------
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from simulator     import generate_packet, ATTACK_LABELS
from ml_detector   import MLDetector
from anomaly_detector import AnomalyDetector
from mitigation    import respond, get_blocked_ips, get_action_log, get_stats as mitigation_stats
from logger        import record_event, get_recent_events, get_stats as log_stats, get_logger

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
FRONTEND_DIR = os.path.join(os.path.dirname(BACKEND_DIR), "frontend")

app    = Flask(__name__, static_folder=FRONTEND_DIR)
logger = get_logger("app")

# Enable CORS for local cross-origin access (e.g. Live Server or direct file access)
@app.before_request
def handle_options():
    if request.method == "OPTIONS":
        response = app.make_default_options_response()
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return response

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
ml_detector      = MLDetector()
anomaly_detector = AnomalyDetector()

# Ring buffer of per-second traffic stats (last 60 seconds)
traffic_history = deque(maxlen=60)

# Counters for current second
_current_window = {
    "pkt_count":    0,
    "attack_count": 0,
    "byte_total":   0,
    "window_start": time.time(),
}
_window_lock = threading.Lock()

# Force-attack override for the demo button
_forced_attack_type: str | None = None
_forced_lock = threading.Lock()

# Total counters
_total_packets  = 0
_total_attacks  = 0
_total_anomalies = 0
_alerts = deque(maxlen=200)

# ---------------------------------------------------------------------------
# Background pipeline thread
# ---------------------------------------------------------------------------
PACKETS_PER_TICK  = 5      # packets processed per tick
TICK_INTERVAL_SEC = 0.2    # seconds between ticks  (5 ticks/sec)


def _pipeline_tick():
    """Process one batch of synthetic packets through the full pipeline."""
    global _total_packets, _total_attacks, _total_anomalies

    with _forced_lock:
        forced = _forced_attack_type

    for _ in range(PACKETS_PER_TICK):
        # 1. Generate packet
        packet = generate_packet(traffic_type=forced)

        # 2. ML classification
        ml_result = ml_detector.predict(packet)

        # 3. Anomaly scoring
        anomaly_result = anomaly_detector.score(packet)

        # 4. Mitigation decision
        action = respond(packet, ml_result, anomaly_result)

        # 5. Update counters
        is_attack   = ml_result["label"] != "normal"
        is_anomaly  = anomaly_result["is_anomaly"]
        pkt_bytes   = int(packet.get("avg_pkt_size", 500))

        with _window_lock:
            _current_window["pkt_count"]    += 1
            _current_window["byte_total"]   += pkt_bytes
            if is_attack:
                _current_window["attack_count"] += 1

        _total_packets   += 1
        if is_attack:
            _total_attacks   += 1
        if is_anomaly:
            _total_anomalies += 1

        # 6. Record event
        event_data = {
            "src_ip":       packet.get("src_ip"),
            "ml_label":     ml_result["label"],
            "confidence":   ml_result["confidence"],
            "anomaly_score": anomaly_result["anomaly_score"],
            "is_anomaly":   is_anomaly,
            "action":       action.get("action", "none"),
            "pkt_rate":     packet.get("pkt_rate", 0),
        }
        record_event("detection", event_data)

        # 7. Generate alert for high-confidence attacks or strong anomalies
        if (is_attack and ml_result["confidence"] >= 0.8) or (is_anomaly and anomaly_result["anomaly_score"] > 0.7):
            alert = {
                "timestamp": time.time(),
                "severity":  "HIGH" if ml_result["confidence"] > 0.9 else "MEDIUM",
                "src_ip":    packet.get("src_ip"),
                "ml_label":  ml_result["label"],
                "confidence": ml_result["confidence"],
                "anomaly_score": anomaly_result["anomaly_score"],
                "action":    action.get("action", "none"),
            }
            _alerts.appendleft(alert)


def _stats_window_tick():
    """Every second, snapshot the current window into traffic_history."""
    with _window_lock:
        now = time.time()
        elapsed = now - _current_window["window_start"]
        if elapsed < 0.5:
            return  # not a full second yet

        snapshot = {
            "time":       now,
            "pkt_rate":   round(_current_window["pkt_count"] / elapsed, 1),
            "attack_rate": round(_current_window["attack_count"] / elapsed, 1),
            "byte_rate":  round(_current_window["byte_total"] / elapsed, 0),
        }
        traffic_history.append(snapshot)

        # Reset window
        _current_window["pkt_count"]    = 0
        _current_window["attack_count"] = 0
        _current_window["byte_total"]   = 0
        _current_window["window_start"] = now


def _background_loop():
    """Main background simulation loop."""
    logger.info("Simulation loop started.")
    window_timer = time.time()

    while True:
        _pipeline_tick()

        now = time.time()
        if now - window_timer >= 1.0:
            _stats_window_tick()
            window_timer = now

        time.sleep(TICK_INTERVAL_SEC)


# ---------------------------------------------------------------------------
# Flask routes — Static files
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(FRONTEND_DIR, filename)


# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------
@app.route("/api/status")
def api_status():
    return jsonify({
        "status":         "running",
        "mode":           "safe_simulation",
        "uptime_sec":     round(time.time() - _start_time, 1),
        "total_packets":  _total_packets,
        "total_attacks":  _total_attacks,
        "total_anomalies": _total_anomalies,
        "ml_model":       ml_detector.get_model_stats(),
        "anomaly_model":  anomaly_detector.get_model_stats(),
        "mitigation":     mitigation_stats(),
        "log":            log_stats(),
    })


@app.route("/api/events")
def api_events():
    limit = min(int(request.args.get("limit", 50)), 200)
    etype = request.args.get("type", None)
    return jsonify(get_recent_events(limit=limit, event_type=etype))


@app.route("/api/traffic")
def api_traffic():
    return jsonify({
        "history": list(traffic_history),
        "current": {
            "total_packets":   _total_packets,
            "total_attacks":   _total_attacks,
            "total_anomalies": _total_anomalies,
        },
    })


@app.route("/api/mitigation")
def api_mitigation():
    return jsonify({
        "blocked_ips":  get_blocked_ips(),
        "action_log":   get_action_log(limit=30),
        "stats":        mitigation_stats(),
    })


@app.route("/api/alerts")
def api_alerts():
    limit = min(int(request.args.get("limit", 20)), 100)
    return jsonify(list(_alerts)[:limit])


@app.route("/api/simulate/attack", methods=["POST"])
def api_simulate_attack():
    """Force a specific attack type into the simulation stream."""
    data         = request.get_json(silent=True) or {}
    attack_type  = data.get("type", "syn_flood")
    valid_types  = ATTACK_LABELS + ["unknown", None]

    if attack_type not in valid_types:
        return jsonify({"error": f"Unknown attack type. Valid: {ATTACK_LABELS}"}), 400

    with _forced_lock:
        global _forced_attack_type
        _forced_attack_type = attack_type

    logger.info("Demo: forced attack type set to '%s'", attack_type)
    return jsonify({"status": "ok", "forced_type": attack_type})


@app.route("/api/simulate/stop", methods=["POST"])
def api_simulate_stop():
    """Return simulation to random mixed traffic."""
    with _forced_lock:
        global _forced_attack_type
        _forced_attack_type = None
    return jsonify({"status": "ok", "forced_type": None})


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
_start_time = time.time()

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("DDoS Detection System — SAFE SIMULATION MODE")
    logger.info("=" * 60)

    # Load / train models
    logger.info("Loading ML models …")
    ml_detector.load()
    anomaly_detector.load()
    logger.info("Models ready.")

    # Start background simulation thread
    sim_thread = threading.Thread(target=_background_loop, daemon=True, name="SimLoop")
    sim_thread.start()

    logger.info("Starting Flask server on http://localhost:5000")
    logger.info("Open your browser and go to: http://localhost:5000")
    logger.info("-" * 60)

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,   # Keep False — debug mode conflicts with background threads
        use_reloader=False,
    )

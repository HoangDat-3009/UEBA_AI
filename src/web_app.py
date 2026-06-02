# File: src/web_app.py
# ===========================================================================
# Flask Web Server for UEBA Dashboard
# ===========================================================================

import os
import sys
import json
import logging
import threading
import sqlite3
from datetime import datetime

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO

# ---------------------------------------------------------------------------
# Ensure the src/ directory is on sys.path so we can import the pipeline
# ---------------------------------------------------------------------------
_script_dir = os.path.dirname(os.path.abspath(__file__))
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)

from ueba_pipeline import UEBAPipeline
from online_detector import OnlineDetector
from offline_profiler import run_offline_profiling

# ---------------------------------------------------------------------------
# Flask application setup
# ---------------------------------------------------------------------------
app = Flask(
    __name__,
    template_folder=os.path.join(_script_dir, "templates"),
    static_folder=os.path.join(_script_dir, "static"),
)
socketio = SocketIO(app, cors_allowed_origins="*")

logger = logging.getLogger(__name__)

_data_dir = os.path.normpath(os.path.join(_script_dir, "..", "data", "r4.2"))
_alerts_db_path = os.path.join(_data_dir, "alerts.db")
_pipeline = UEBAPipeline(data_dir=_data_dir, contamination=0.05)

_cached_result: dict | None = None
_last_updated: str | None = None

detector = OnlineDetector(socketio_ext=socketio)
detector_thread = None


def _run_pipeline() -> dict:
    global _cached_result, _last_updated
    _cached_result = _pipeline.run_for_web()
    _last_updated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _cached_result["last_updated"] = _last_updated
    return _cached_result

_run_pipeline()

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/data")
def api_data():
    if _cached_result is None:
        _run_pipeline()
    return jsonify(_cached_result)

@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    result = _run_pipeline()
    return jsonify(result)

# --- New Real-time API Routes ---

@app.route("/api/alerts")
def api_alerts():
    limit = request.args.get("limit", 50)
    try:
        conn = sqlite3.connect(_alerts_db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?', (limit,))
        rows = c.fetchall()
        alerts = [dict(r) for r in rows]
        # Parse feature_deviations JSON
        for a in alerts:
            if a["feature_deviations"]:
                a["feature_deviations"] = json.loads(a["feature_deviations"])
        conn.close()
        return jsonify({"alerts": alerts})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/alerts/history")
def api_alerts_history():
    """Get alerts with optional date range filtering + aggregated stats for charts."""
    date_from = request.args.get("from")   # YYYY-MM-DD
    date_to = request.args.get("to")       # YYYY-MM-DD

    try:
        conn = sqlite3.connect(_alerts_db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # Build query with optional date filters
        query = "SELECT * FROM alerts"
        params = []
        conditions = []

        if date_from:
            conditions.append("timestamp >= ?")
            params.append(date_from + " 00:00:00")
        if date_to:
            conditions.append("timestamp <= ?")
            params.append(date_to + " 23:59:59")

        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY timestamp DESC"

        c.execute(query, params)
        rows = c.fetchall()
        alerts = [dict(r) for r in rows]
        for a in alerts:
            if a.get("feature_deviations"):
                a["feature_deviations"] = json.loads(a["feature_deviations"])

        # --- Aggregate stats for charts ---
        # Timeline: count alerts per hour
        timeline = {}
        severity_counts = {"CRITICAL": 0, "HIGH": 0}
        user_counts = {}

        for a in alerts:
            # Timeline by hour
            ts = a.get("timestamp", "")
            hour_key = ts[:13] if len(ts) >= 13 else ts  # "YYYY-MM-DD HH"
            timeline[hour_key] = timeline.get(hour_key, 0) + 1

            # Severity
            sev = a.get("severity", "HIGH")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            # Top users
            uid = a.get("user_id", "unknown")
            user_counts[uid] = user_counts.get(uid, 0) + 1

        # Sort timeline by key (chronological)
        sorted_timeline = sorted(timeline.items(), key=lambda x: x[0])
        timeline_labels = [t[0] for t in sorted_timeline]
        timeline_values = [t[1] for t in sorted_timeline]

        # Top users sorted by count desc
        top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        conn.close()

        return jsonify({
            "alerts": alerts,
            "total": len(alerts),
            "stats": {
                "timeline_labels": timeline_labels,
                "timeline_values": timeline_values,
                "severity": severity_counts,
                "top_users": {
                    "labels": [u[0] for u in top_users],
                    "values": [u[1] for u in top_users],
                },
            },
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/offline/run", methods=["POST"])
def api_offline_run():
    try:
        run_offline_profiling()
        # Reload detector models
        detector.load_models()
        detector.load_baselines()
        return jsonify({"status": "success", "message": "Offline profiling completed and models reloaded."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/realtime/status")
def api_realtime_status():
    return jsonify({"running": detector.running})

@app.route("/api/realtime/start", methods=["POST"])
def api_realtime_start():
    global detector_thread
    if not detector.running:
        detector_thread = threading.Thread(target=detector.run, daemon=True)
        detector_thread.start()
        return jsonify({"status": "started"})
    return jsonify({"status": "already running"})

@app.route("/api/realtime/stop", methods=["POST"])
def api_realtime_stop():
    if detector.running:
        detector.stop()
        return jsonify({"status": "stopped"})
    return jsonify({"status": "already stopped"})

# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  [UEBA] Web Dashboard (Real-time Enabled)")
    print("  [URL]  http://127.0.0.1:5000")
    print("=" * 60 + "\n")
    # Start detector automatically
    detector_thread = threading.Thread(target=detector.run, daemon=True)
    detector_thread.start()
    
    socketio.run(app, debug=True, host="127.0.0.1", port=5000, use_reloader=False, allow_unsafe_werkzeug=True)

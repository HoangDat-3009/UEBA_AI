# File: src/web_app.py
# ===========================================================================
# Flask Web Server for UEBA Dashboard
# ===========================================================================
# The web server does NOT load the training dataset (CSV files).
# It uses:
#   - Pre-trained model (joblib) from offline profiling
#   - Baseline statistics (baseline.db)
#   - Real Windows Event Logs for real-time analysis
# ===========================================================================

import os
import sys
import json
import logging
import threading
import sqlite3
import time
from datetime import datetime

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO

# ---------------------------------------------------------------------------
# Ensure the src/ directory is on sys.path so we can import modules
# ---------------------------------------------------------------------------
_script_dir = os.path.dirname(os.path.abspath(__file__))
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)

from live_analyzer import LiveAnalyzer
from online_detector import OnlineDetector
from offline_profiler import run_offline_profiling
from windows_log_collector import WindowsLogCollector

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

# Live analyzer — uses trained model + real Windows Event Logs
_analyzer = LiveAnalyzer()

# Online detector for real-time log monitoring
detector = OnlineDetector(socketio_ext=socketio)
detector_thread = None

# Windows Event Log collector (replaces log_simulator.py)
collector = WindowsLogCollector(poll_interval=3.0)
collector_thread = None


def start_detector_if_needed():
    global detector_thread
    if not detector.running:
        detector_thread = threading.Thread(target=detector.run, daemon=True)
        detector_thread.start()
        for _ in range(20):
            if detector.running:
                break
            time.sleep(0.05)


def start_collector_if_needed():
    global collector_thread
    start_detector_if_needed()
    if not collector.running:
        collector_thread = threading.Thread(target=collector.run, daemon=True)
        collector_thread.start()
        return True
    return False


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/live-analysis")
def api_live_analysis():
    """Analyze live log data using the pre-trained model.

    This endpoint parses system.log, aggregates per-user features,
    and uses the trained Isolation Forest to detect anomalies.

    Query params:
        refresh: if "true", force re-parse even if log hasn't changed
    """
    force = request.args.get("refresh", "").lower() == "true"
    result = _analyzer.analyze(force=force, current_states=detector.user_states)
    result["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return jsonify(result)


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
        limit = min(max(int(request.args.get("limit", 200)), 1), 500)
    except ValueError:
        limit = 200

    try:
        conn = sqlite3.connect(_alerts_db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # Build WHERE clause with optional date filters
        params = []
        conditions = []

        if date_from:
            conditions.append("timestamp >= ?")
            params.append(date_from + " 00:00:00")
        if date_to:
            conditions.append("timestamp <= ?")
            params.append(date_to + " 23:59:59")

        where_sql = (" WHERE " + " AND ".join(conditions)) if conditions else ""

        c.execute("SELECT COUNT(*) FROM alerts" + where_sql, params)
        total_alerts = c.fetchone()[0]

        c.execute(
            "SELECT substr(timestamp, 1, 13) AS hour_key, COUNT(*) AS count "
            "FROM alerts" + where_sql + " GROUP BY hour_key ORDER BY hour_key",
            params,
        )
        timeline_rows = c.fetchall()
        timeline_labels = [r["hour_key"] for r in timeline_rows]
        timeline_values = [r["count"] for r in timeline_rows]

        severity_counts = {"CRITICAL": 0, "HIGH": 0}
        c.execute(
            "SELECT severity, COUNT(*) AS count FROM alerts" + where_sql + " GROUP BY severity",
            params,
        )
        for r in c.fetchall():
            severity_counts[r["severity"] or "HIGH"] = r["count"]

        c.execute(
            "SELECT user_id, COUNT(*) AS count FROM alerts" + where_sql +
            " GROUP BY user_id ORDER BY count DESC LIMIT 10",
            params,
        )
        top_users = c.fetchall()

        c.execute("SELECT * FROM alerts" + where_sql + " ORDER BY timestamp DESC LIMIT ?", params + [limit])
        rows = c.fetchall()
        alerts = [dict(r) for r in rows]
        for a in alerts:
            if a.get("feature_deviations"):
                a["feature_deviations"] = json.loads(a["feature_deviations"])

        conn.close()

        return jsonify({
            "alerts": alerts,
            "total": total_alerts,
            "returned": len(alerts),
            "limit": limit,
            "stats": {
                "timeline_labels": timeline_labels,
                "timeline_values": timeline_values,
                "severity": severity_counts,
                "top_users": {
                    "labels": [u["user_id"] for u in top_users],
                    "values": [u["count"] for u in top_users],
                },
            },
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/offline/run", methods=["POST"])
def api_offline_run():
    try:
        run_offline_profiling()
        # Reload live analyzer with new model + baselines
        _analyzer.reload()
        # Reload detector models
        detector.load_models()
        detector.load_baselines()
        return jsonify({"status": "success", "message": "Offline profiling completed and models reloaded."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/realtime/status")
def api_realtime_status():
    return jsonify({
        "running": detector.running,
        "users_tracked": len(detector.user_states),
    })

@app.route("/api/realtime/start", methods=["POST"])
def api_realtime_start():
    was_running = detector.running
    start_detector_if_needed()
    if not was_running:
        return jsonify({"status": "started"})
    return jsonify({"status": "already running"})

@app.route("/api/realtime/stop", methods=["POST"])
def api_realtime_stop():
    if detector.running:
        detector.stop()
        return jsonify({"status": "stopped"})
    return jsonify({"status": "already stopped"})


# ---------------------------------------------------------------------------
# Collector API routes (Windows Event Log)
# ---------------------------------------------------------------------------

@app.route("/api/collector/status")
def api_collector_status():
    return jsonify(collector.get_status())

@app.route("/api/collector/start", methods=["POST"])
def api_collector_start():
    if start_collector_if_needed():
        return jsonify({"status": "started"})
    return jsonify({"status": "already running"})

@app.route("/api/collector/stop", methods=["POST"])
def api_collector_stop():
    if collector.running:
        collector.stop()
        return jsonify({"status": "stopped"})
    return jsonify({"status": "already stopped"})


# ---------------------------------------------------------------------------
# Alert Detail API (popup support)
# ---------------------------------------------------------------------------

_live_log_path = os.path.join(_data_dir, "live_logs", "system.log")


@app.route("/api/alert/<int:alert_id>/detail")
def api_alert_detail(alert_id):
    """Return full alert details + surrounding raw log lines for popup."""
    try:
        conn = sqlite3.connect(_alerts_db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        row = c.fetchone()
        conn.close()

        if not row:
            return jsonify({"error": "Alert not found"}), 404

        alert = dict(row)
        if alert.get("feature_deviations"):
            alert["feature_deviations"] = json.loads(alert["feature_deviations"])

        # --- Fetch raw log lines around the alert timestamp for context ---
        raw_logs = []
        user_id = alert.get("user_id", "")
        alert_ts = alert.get("timestamp", "")  # "YYYY-MM-DD HH:MM:SS"

        if os.path.exists(_live_log_path) and alert_ts:
            try:
                alert_dt = datetime.strptime(alert_ts, "%Y-%m-%d %H:%M:%S")
                window_seconds = 30  # ±30 seconds around alert time

                with open(_live_log_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            evt = json.loads(line)
                            evt_user = evt.get("user", "")
                            evt_ts_str = evt.get("timestamp", "")
                            if not evt_ts_str:
                                continue
                            if user_id and evt_user.lower() != user_id.lower():
                                continue
                            try:
                                evt_dt = datetime.strptime(evt_ts_str, "%Y-%m-%dT%H:%M:%S")
                            except ValueError:
                                evt_dt = datetime.strptime(evt_ts_str[:19], "%Y-%m-%d %H:%M:%S")
                            diff = abs((evt_dt - alert_dt).total_seconds())
                            if diff <= window_seconds:
                                raw_logs.append(evt)
                        except (json.JSONDecodeError, ValueError):
                            continue
            except Exception:
                pass

        # --- Build user baseline context ---
        baseline_context = {}
        try:
            conn = sqlite3.connect(os.path.join(_data_dir, "baseline.db"))
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute(
                "SELECT feature_name, mean, std FROM baselines WHERE user_id = ?",
                (user_id,),
            )
            for r in c.fetchall():
                baseline_context[r["feature_name"]] = {
                    "mean": round(r["mean"], 2),
                    "std": round(r["std"], 2),
                }
            conn.close()
        except Exception:
            pass

        return jsonify({
            "alert": alert,
            "raw_logs": raw_logs[-50:],
            "raw_log_count": len(raw_logs),
            "baseline": baseline_context,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  [UEBA] Web Dashboard (Real-time Enabled)")
    print("  [URL]  http://127.0.0.1:5000")
    print("  [DATA] Real Windows Event Logs")
    print("=" * 60 + "\n")
    # Start detector before collector so initial collector events can be analyzed.
    start_detector_if_needed()
    start_collector_if_needed()

    socketio.run(app, debug=True, host="127.0.0.1", port=5000, use_reloader=False, allow_unsafe_werkzeug=True)

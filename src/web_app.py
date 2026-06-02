# File: src/web_app.py
# ===========================================================================
# Flask Web Server for UEBA Dashboard
# ===========================================================================
# Serves the interactive dashboard and exposes API endpoints for the
# frontend to fetch pipeline results in JSON format.
# ===========================================================================

import os
import sys
import json
import logging
from datetime import datetime

from flask import Flask, render_template, jsonify

# ---------------------------------------------------------------------------
# Ensure the src/ directory is on sys.path so we can import the pipeline
# ---------------------------------------------------------------------------
_script_dir = os.path.dirname(os.path.abspath(__file__))
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)

from ueba_pipeline import UEBAPipeline

# ---------------------------------------------------------------------------
# Flask application setup
# ---------------------------------------------------------------------------
app = Flask(
    __name__,
    template_folder=os.path.join(_script_dir, "templates"),
    static_folder=os.path.join(_script_dir, "static"),
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pipeline singleton & cached results
# ---------------------------------------------------------------------------
_data_dir = os.path.normpath(os.path.join(_script_dir, "..", "data"))
_pipeline = UEBAPipeline(data_dir=_data_dir, contamination=0.05)

_cached_result: dict | None = None
_last_updated: str | None = None


def _run_pipeline() -> dict:
    """Execute the pipeline and cache the results."""
    global _cached_result, _last_updated
    _cached_result = _pipeline.run_for_web()
    _last_updated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _cached_result["last_updated"] = _last_updated
    return _cached_result


# Run once on startup
_run_pipeline()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Serve the main dashboard page."""
    return render_template("index.html")


@app.route("/api/data")
def api_data():
    """Return the latest pipeline results as JSON."""
    if _cached_result is None:
        _run_pipeline()
    return jsonify(_cached_result)


@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    """Re-run the pipeline and return fresh results."""
    result = _run_pipeline()
    return jsonify(result)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  [UEBA] Web Dashboard")
    print("  [URL]  http://127.0.0.1:5000")
    print("=" * 60 + "\n")
    app.run(debug=True, host="127.0.0.1", port=5000)

# File: src/live_analyzer.py
# ===========================================================================
# Live Log Analyzer — Parse system.log and detect anomalies using trained model
# ===========================================================================
# This module reads the live log file (system.log), aggregates per-user
# behavioral features, and uses the pre-trained Isolation Forest model
# + MinMaxScaler to detect anomalies in real-time data.
#
# The training dataset (CSV files) is NOT used here. Only the trained model
# artifacts (joblib) and baseline statistics (baseline.db) are loaded.
# ===========================================================================

import os
import json
import sqlite3
import logging
import hashlib

import numpy as np
import pandas as pd
import joblib
from sklearn.decomposition import PCA

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | [LIVE] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

_script_dir = os.path.dirname(os.path.abspath(__file__))
_data_dir = os.path.normpath(os.path.join(_script_dir, "..", "data", "r4.2"))
_models_dir = os.path.normpath(os.path.join(_script_dir, "..", "models"))
_live_log_path = os.path.join(_data_dir, "live_logs", "system.log")
_baseline_db_path = os.path.join(_data_dir, "baseline.db")

# Feature order MUST match what the scaler/model were trained on
FEATURE_ORDER = [
    "total_logins", "off_hour_logins",
    "total_usb_connects", "off_hour_usb",
    "total_emails", "external_emails",
    "total_file_access", "exe_zip_downloads",
    "total_http_requests", "off_hour_http",
    "o_score", "c_score", "e_score", "a_score", "n_score", "role_changes"
]

# Features that can be extracted from live log events
LIVE_FEATURES = [
    "total_logins", "off_hour_logins",
    "total_usb_connects", "off_hour_usb",
    "total_emails", "external_emails",
    "total_file_access", "exe_zip_downloads",
]

POWERSHELL_EVENT_IDS = {40961, 40962, 4104}


def is_exe_zip_activity(event: dict) -> bool:
    if event.get("source") == "powershell" or event.get("event_id") in POWERSHELL_EVENT_IDS:
        return False

    fname = str(event.get("filename", "")).lower()
    return ".exe" in fname or ".zip" in fname

# Features that come from static baselines (psychometric, http, etc.)
STATIC_FEATURES = [f for f in FEATURE_ORDER if f not in LIVE_FEATURES]


class LiveAnalyzer:
    """Parse live logs and detect anomalies using pre-trained model.

    This class does NOT touch the training dataset. It only uses:
    - Trained model (ueba_model.joblib)
    - Trained scaler (ueba_scaler.joblib)
    - Baseline statistics (baseline.db)
    - Live log data (system.log)
    """

    def __init__(self):
        self.model = None
        self.scaler = None
        self.pca = PCA(n_components=2, random_state=42)
        self.baselines = {}          # {user_id: {feature: {mean, std}}}
        self.global_baselines = {}   # {feature: {mean, std}}
        self._last_log_hash = None   # For change detection
        self._cached_result = None

        self._load_model()
        self._load_baselines()

    def _load_model(self):
        """Load the pre-trained Isolation Forest and MinMaxScaler."""
        model_path = os.path.join(_models_dir, "ueba_model.joblib")
        scaler_path = os.path.join(_models_dir, "ueba_scaler.joblib")
        try:
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            logger.info("Loaded trained model (%d features)", self.scaler.n_features_in_)
        except Exception as e:
            logger.error("Failed to load model: %s. Run Offline Profiling first.", e)

    def _load_baselines(self):
        """Load per-user and global baselines from baseline.db."""
        try:
            conn = sqlite3.connect(_baseline_db_path)
            c = conn.cursor()

            # Global baselines
            c.execute("SELECT feature_name, mean, std FROM global_baselines")
            for fname, mean, std in c.fetchall():
                self.global_baselines[fname] = {"mean": mean, "std": max(std, 1.0)}

            # Per-user baselines
            c.execute("SELECT user_id, feature_name, mean, std FROM baselines")
            for uid, fname, mean, std in c.fetchall():
                if uid not in self.baselines:
                    self.baselines[uid] = {}
                self.baselines[uid][fname] = {"mean": mean, "std": max(std, 1.0)}

            conn.close()
            logger.info("Loaded baselines for %d users", len(self.baselines))
        except Exception as e:
            logger.error("Failed to load baselines: %s", e)

    def reload(self):
        """Reload model and baselines (after re-profiling)."""
        self._load_model()
        self._load_baselines()
        self._last_log_hash = None
        self._cached_result = None

    # -------------------------------------------------------------------
    # Log Parsing
    # -------------------------------------------------------------------

    def _parse_log(self) -> dict:
        """Parse system.log and aggregate per-user features.

        Returns
        -------
        dict
            {user_id: {feature_name: count, ...}, ...}
        """
        user_states = {}

        if not os.path.exists(_live_log_path):
            logger.warning("Live log not found: %s", _live_log_path)
            return user_states

        with open(_live_log_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                user = event.get("user")
                if not user:
                    continue

                if user not in user_states:
                    user_states[user] = {feat: 0 for feat in LIVE_FEATURES}

                state = user_states[user]
                evt_type = event.get("type")
                hour = event.get("hour", 12)
                is_off_hour = (hour < 7 or hour > 18)

                if evt_type == "logon":
                    state["total_logins"] += 1
                    if is_off_hour:
                        state["off_hour_logins"] += 1
                elif evt_type == "device":
                    if event.get("action") == "connect":
                        state["total_usb_connects"] += 1
                        if is_off_hour:
                            state["off_hour_usb"] += 1
                elif evt_type == "email":
                    state["total_emails"] += 1
                    if event.get("external"):
                        state["external_emails"] += 1
                elif evt_type == "file":
                    state["total_file_access"] += 1
                    if is_exe_zip_activity(event):
                        state["exe_zip_downloads"] += 1

        logger.info("Parsed live log: %d users found", len(user_states))
        return user_states

    def _build_feature_vector(self, user: str, live_features: dict) -> list:
        """Build the full feature vector for a user.

        Live features come from log parsing. Static features (http, psychometric)
        come from the baseline database.
        """
        vector = []
        for feat in FEATURE_ORDER:
            if feat in LIVE_FEATURES:
                vector.append(live_features.get(feat, 0))
            else:
                # Use per-user baseline mean, fallback to global mean
                user_base = self.baselines.get(user, {}).get(feat)
                if user_base:
                    vector.append(user_base["mean"])
                else:
                    global_base = self.global_baselines.get(feat, {"mean": 0})
                    vector.append(global_base["mean"])
        return vector

    # -------------------------------------------------------------------
    # Analysis
    # -------------------------------------------------------------------

    def _get_log_hash(self) -> str | None:
        """Fast hash of log file size + mtime for change detection."""
        try:
            stat = os.stat(_live_log_path)
            return f"{stat.st_size}:{stat.st_mtime}"
        except OSError:
            return None

    def analyze(self, force: bool = False, current_states: dict = None) -> dict:
        """Analyze live log data and return dashboard-ready JSON.

        Uses cached result if log file hasn't changed (unless force=True).
        If current_states is provided, uses in-memory data (instantaneous).

        Returns
        -------
        dict
            Same format as UEBAPipeline.run_for_web() but from live data.
        """
        if not self.model or not self.scaler:
            return {
                "error": "Model not loaded. Run Offline Profiling first.",
                "users": [], "anomalies": [], "pca": {},
                "correlation": {"labels": [], "values": []},
                "feature_names": FEATURE_ORDER,
                "summary": {}, "feature_averages": {},
            }

        # Use in-memory state if provided (O(1) no file parsing)
        if current_states is not None:
            user_states = current_states
        else:
            # Check if log changed
            log_hash = self._get_log_hash()
            if not force and log_hash == self._last_log_hash and self._cached_result:
                return self._cached_result

            # Parse live log
            user_states = self._parse_log()
            self._last_log_hash = log_hash

        if not user_states:
            return {
                "error": "No data available.",
                "users": [], "anomalies": [], "pca": {},
                "correlation": {"labels": [], "values": []},
                "feature_names": FEATURE_ORDER,
                "summary": {"total_users": 0, "anomalous_users": 0,
                            "normal_users": 0, "anomaly_rate": 0},
                "feature_averages": {},
            }

        # Build feature matrix
        user_ids = sorted(user_states.keys())
        feature_matrix = []
        user_feature_dicts = []

        for uid in user_ids:
            vec = self._build_feature_vector(uid, user_states[uid])
            feature_matrix.append(vec)
            user_feature_dicts.append(dict(zip(FEATURE_ORDER, vec)))

        X = np.array(feature_matrix, dtype=np.float64)

        # Scale and predict using trained model
        try:
            X_scaled = self.scaler.transform(X)
            labels = self.model.predict(X_scaled)
            scores = self.model.decision_function(X_scaled)
        except Exception as e:
            logger.error("Prediction failed: %s", e)
            return {"error": str(e), "users": [], "anomalies": [],
                    "pca": {}, "correlation": {"labels": [], "values": []},
                    "feature_names": FEATURE_ORDER,
                    "summary": {}, "feature_averages": {}}

        # PCA projection
        if len(X_scaled) >= 2:
            pca_result = self.pca.fit_transform(X_scaled)
            explained = self.pca.explained_variance_ratio_
        else:
            pca_result = np.zeros((len(X_scaled), 2))
            explained = np.array([0.0, 0.0])

        # Correlation matrix (replace NaN with 0.0 for valid JSON)
        df_features = pd.DataFrame(X, columns=FEATURE_ORDER)
        corr_matrix = df_features.corr().fillna(0.0).round(3)

        # Feature averages
        feature_averages = {f: round(float(df_features[f].mean()), 2) for f in FEATURE_ORDER}

        # Build response
        users_data = []
        for i, uid in enumerate(user_ids):
            entry = {
                "user": uid,
                "anomaly_label": int(labels[i]),
                "anomaly_score": round(float(scores[i]), 4),
                "pc1": round(float(pca_result[i, 0]), 4),
                "pc2": round(float(pca_result[i, 1]), 4),
            }
            for feat in FEATURE_ORDER:
                entry[feat] = int(user_feature_dicts[i][feat])
            users_data.append(entry)

        # Anomalies sorted by score ascending (most dangerous first)
        anomalies_data = []
        anomaly_entries = [u for u in users_data if u["anomaly_label"] == -1]
        anomaly_entries.sort(key=lambda x: x["anomaly_score"])
        for rank, entry in enumerate(anomaly_entries, start=1):
            a = dict(entry)
            a["rank"] = rank
            anomalies_data.append(a)

        n_total = len(users_data)
        n_anomalies = len(anomalies_data)

        result = {
            "users": users_data,
            "anomalies": anomalies_data,
            "pca": {
                "pc1_var": round(float(explained[0] * 100), 1),
                "pc2_var": round(float(explained[1] * 100), 1),
            },
            "correlation": {
                "labels": FEATURE_ORDER,
                "values": corr_matrix.values.tolist(),
            },
            "feature_names": FEATURE_ORDER,
            "summary": {
                "total_users": n_total,
                "anomalous_users": n_anomalies,
                "normal_users": n_total - n_anomalies,
                "anomaly_rate": round(100 * n_anomalies / max(n_total, 1), 2),
                "num_features": len(FEATURE_ORDER),
                "num_log_sources": 4,
                "pca_variance_pc1": round(float(explained[0] * 100), 1),
                "pca_variance_pc2": round(float(explained[1] * 100), 1),
            },
            "feature_averages": feature_averages,
        }

        if current_states is None:
            self._last_log_hash = log_hash
            self._cached_result = result
        logger.info("Live analysis complete: %d users, %d anomalies", n_total, n_anomalies)
        return result

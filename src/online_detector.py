import os
import time
import json
import sqlite3
import logging
import joblib
import numpy as np
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s | [DETECTOR] %(message)s")
logger = logging.getLogger(__name__)

_script_dir = os.path.dirname(os.path.abspath(__file__))
_data_dir = os.path.normpath(os.path.join(_script_dir, "..", "data", "r4.2"))
_models_dir = os.path.normpath(os.path.join(_script_dir, "..", "models"))
_live_logs_dir = os.path.join(_data_dir, "live_logs")
_log_file = os.path.join(_live_logs_dir, "system.log")
_baseline_db_path = os.path.join(_data_dir, "baseline.db")
_alerts_db_path = os.path.join(_data_dir, "alerts.db")

live_feature_names = [
    "total_logins", "off_hour_logins", "total_usb_connects", "off_hour_usb",
    "total_emails", "external_emails", "total_file_access", "exe_zip_downloads"
]

class OnlineDetector:
    def __init__(self, socketio_ext=None):
        self.socketio = socketio_ext
        self.running = False
        self.model = None
        self.scaler = None
        self.user_states = {}
        self.baselines = {}
        self.global_baselines = {}
        self.last_alert_time = {}
        
        # Dynamic feature list determined from database
        self.feature_names = []
        self.live_feature_names = live_feature_names
        
        self.load_models()
        self.load_baselines()

    def load_models(self):
        try:
            self.model = joblib.load(os.path.join(_models_dir, "ueba_model.joblib"))
            self.scaler = joblib.load(os.path.join(_models_dir, "ueba_scaler.joblib"))
            logger.info("Loaded ML models successfully.")
        except Exception as e:
            logger.error(f"Failed to load ML models: {e}. Run Offline Profiling first.")

    def load_baselines(self):
        try:
            conn = sqlite3.connect(_baseline_db_path)
            c = conn.cursor()
            
            # Load global
            c.execute('SELECT feature_name, mean, std FROM global_baselines')
            for row in c.fetchall():
                self.global_baselines[row[0]] = {"mean": row[1], "std": max(row[2], 1.0)}
                
            # Build the dynamic feature list matching the scaler training order
            all_possible_features = [
                "total_logins", "off_hour_logins",
                "total_usb_connects", "off_hour_usb",
                "total_emails", "external_emails",
                "total_file_access", "exe_zip_downloads",
                "total_http_requests", "off_hour_http",
                "o_score", "c_score", "e_score", "a_score", "n_score",
                "role_changes"
            ]
            self.feature_names = [f for f in all_possible_features if f in self.global_baselines]
            logger.info(f"Dynamic feature order determined: {self.feature_names}")
            
            # Load per-user
            c.execute('SELECT user_id, feature_name, mean, std FROM baselines')
            for row in c.fetchall():
                uid, fname, mean, std = row
                if uid not in self.baselines:
                    self.baselines[uid] = {}
                self.baselines[uid][fname] = {"mean": mean, "std": std}

            conn.close()
            logger.info(f"Loaded baselines for {len(self.baselines)} users.")
        except Exception as e:
            logger.error(f"Failed to load baselines: {e}")

    def update_state(self, event):
        user = event.get("user")
        if not user: return None
        
        if user not in self.user_states:
            self.user_states[user] = {f: 0 for f in self.live_feature_names}
            # Fill with personal baseline means if known, else global means
            for f in self.live_feature_names:
                base = self.baselines.get(user, {}).get(f)
                if base:
                    self.user_states[user][f] = base["mean"]
                elif f in self.global_baselines:
                    self.user_states[user][f] = self.global_baselines[f]["mean"]

        state = self.user_states[user]
        evt_type = event.get("type")
        hour = event.get("hour", 12)
        is_off_hour = (hour < 7 or hour > 18)

        if evt_type == "logon":
            state["total_logins"] += 1
            if is_off_hour: state["off_hour_logins"] += 1
        elif evt_type == "device":
            if event.get("action") == "connect":
                state["total_usb_connects"] += 1
                if is_off_hour: state["off_hour_usb"] += 1
        elif evt_type == "email":
            state["total_emails"] += 1
            if event.get("external"): state["external_emails"] += 1
        elif evt_type == "file":
            state["total_file_access"] += 1
            fname = str(event.get("filename", "")).lower()
            if ".exe" in fname or ".zip" in fname:
                state["exe_zip_downloads"] += 1
                
        return user

    def evaluate_user(self, user):
        if not self.model or not self.scaler:
            return

        state = self.user_states[user]
        # Construct feature vector combining live states and static baselines
        vector = []
        for f in self.feature_names:
            if f in self.live_feature_names:
                vector.append(state.get(f, 0))
            else:
                base = self.baselines.get(user, {}).get(f)
                if not base:
                    base = self.global_baselines.get(f, {"mean": 0})
                vector.append(base["mean"])
        
        try:
            v_scaled = self.scaler.transform([vector])
            prediction = self.model.predict(v_scaled)[0]
            score = float(self.model.decision_function(v_scaled)[0])
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return

        # Method 1: Model prediction
        model_triggered = (prediction == -1)

        # Method 2: Baseline deviation check (>1.0σ on at least 2 features)
        deviation_count = 0
        for fname in self.live_feature_names:
            val = state.get(fname, 0)
            base = self.baselines.get(user, {}).get(fname)
            if not base:
                base = self.global_baselines.get(fname, {"mean": 0, "std": 1})
            mean = base["mean"]
            std = max(base["std"], 1.0)
            dev = abs(val - mean) / std
            if dev > 1.0:
                deviation_count += 1

        baseline_triggered = (deviation_count >= 2)

        if model_triggered or baseline_triggered:
            # Check cooldown (avoid spamming alerts)
            now = time.time()
            last_time = self.last_alert_time.get(user, 0)
            if now - last_time < 10:  # 10 seconds cooldown for demo
                return
                
            self.last_alert_time[user] = now
            trigger_reason = "model" if model_triggered else "baseline_deviation"
            logger.info(f"Alert triggered for {user} | reason={trigger_reason} | score={score:.4f} | devs={deviation_count}")
            self.trigger_alert(user, score, vector)

    def trigger_alert(self, user, score, vector):
        severity = "CRITICAL" if score < -0.2 else "HIGH"
        
        # Calculate deviations for explainability
        deviations = {}
        for i, fname in enumerate(self.feature_names):
            if fname not in self.live_feature_names:
                continue
            val = vector[i]
            base = self.baselines.get(user, {}).get(fname)
            if not base:
                base = self.global_baselines.get(fname, {"mean": 0, "std": 1})
            
            mean = base["mean"]
            std = base["std"]
            dev = abs(val - mean) / std
            if dev > 2.0:  # More than 2 sigma
                deviations[fname] = {"observed": val, "mean": round(mean, 2), "deviation_sigma": round(dev, 2)}
                
        desc = f"Anomalous behavior detected. Score: {score:.4f}"
        
        # Save to DB
        try:
            conn = sqlite3.connect(_alerts_db_path)
            c = conn.cursor()
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute('''
                INSERT INTO alerts (timestamp, user_id, severity, anomaly_score, feature_deviations, description)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (now, user, severity, score, json.dumps(deviations), desc))
            alert_id = c.lastrowid
            conn.commit()
            conn.close()
            
            alert_data = {
                "id": alert_id,
                "timestamp": now,
                "user_id": user,
                "severity": severity,
                "anomaly_score": score,
                "deviations": deviations,
                "description": desc
            }
            
            logger.warning(f"ALERT! User: {user} | Score: {score:.4f} | Devs: {len(deviations)}")
            
            if self.socketio:
                self.socketio.emit('new_alert', alert_data)
                
        except Exception as e:
            logger.error(f"Failed to save/emit alert: {e}")

    def run(self):
        self.running = True
        logger.info(f"Detector started. Watching {_log_file}")
        
        # Ensure file exists
        os.makedirs(os.path.dirname(_log_file), exist_ok=True)
        if not os.path.exists(_log_file):
            open(_log_file, 'w').close()

        last_position = 0
        last_inode = None
        event_count = 0

        # Start from end of current file
        try:
            last_position = os.path.getsize(_log_file)
        except OSError:
            last_position = 0

        while self.running:
            try:
                current_size = os.path.getsize(_log_file)
            except OSError:
                time.sleep(0.5)
                continue

            # Detect truncation or new file
            if current_size < last_position:
                logger.info(f"Log file truncated/replaced. Resetting from {last_position} to 0.")
                last_position = 0

            if current_size <= last_position:
                time.sleep(0.1)
                continue

            # Read new content by reopening the file (Windows-safe)
            try:
                with open(_log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(last_position)
                    new_lines = f.readlines()
                    last_position = f.tell()
            except (OSError, IOError) as e:
                logger.error(f"Error reading log file: {e}")
                time.sleep(0.5)
                continue

            events_processed = False
            for line in new_lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    user = self.update_state(event)
                    if user:
                        event_count += 1
                        events_processed = True
                        self.evaluate_user(user)
                        if event_count % 100 == 0:
                            logger.info(f"Processed {event_count} events. Users tracked: {len(self.user_states)}")
                except json.JSONDecodeError:
                    pass
                except Exception as e:
                    logger.error(f"Error processing line: {e}")
            
            if events_processed and self.socketio:
                self.socketio.emit('data_updated', {'status': 'success'})

    def stop(self):
        self.running = False
        logger.info("Detector stopped.")

import os
import sys

_script_dir = os.path.dirname(os.path.abspath(__file__))
_project_dir = os.path.normpath(os.path.join(_script_dir, ".."))
sys.path.insert(0, os.path.join(_project_dir, "src"))

# pyrefly: ignore [missing-import]
from online_detector import OnlineDetector
import json

class MockSocketIO:
    def emit(self, event, data):
        print(f"SOCKETIO EMIT | {event} | {data['user_id']} | score={data['anomaly_score']:.4f}")

detector = OnlineDetector(socketio_ext=MockSocketIO())

print("Loaded baselines:", len(detector.baselines))
print("Loaded global baselines:", len(detector.global_baselines))
print("Model loaded:", detector.model is not None)
print("Scaler loaded:", detector.scaler is not None)

# Read the log file
log_file = os.path.join(_project_dir, "data", "r4.2", "live_logs", "system.log")
print("Reading log file:", log_file)

with open(log_file, 'r', encoding='utf-8') as f:
    lines = f.readlines()

print(f"Total lines in log: {len(lines)}")

event_count = 0
for line in lines:
    line = line.strip()
    if not line:
        continue
    try:
        event = json.loads(line)
        user = detector.update_state(event)
        if user:
            event_count += 1
            detector.evaluate_user(user)
    except Exception as e:
        print("Error processing line:", e)

print(f"Finished processing. Total events: {event_count}")

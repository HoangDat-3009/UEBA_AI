import os
import sys
import sqlite3
import json

_script_dir = os.path.dirname(os.path.abspath(__file__))
_project_dir = os.path.normpath(os.path.join(_script_dir, ".."))
sys.path.insert(0, os.path.join(_project_dir, "src"))

from online_detector import OnlineDetector

# Get a real user from database
conn = sqlite3.connect(os.path.join(_project_dir, "data", "r4.2", "baseline.db"))
c = conn.cursor()
c.execute("SELECT DISTINCT user_id FROM baselines LIMIT 5")
real_users = [row[0] for row in c.fetchall()]
conn.close()

print("Real users from baseline.db:", real_users)

class MockSocketIO:
    def emit(self, event, data):
        desc = data['description'].encode('ascii', errors='replace').decode('ascii')
        print(f"\n>>> SOCKETIO EMIT | {event} | {data['user_id']} | severity={data['severity']} | score={data['anomaly_score']:.4f}")
        print(f"    Description: {desc}")
        print(f"    Deviations: {list(data['deviations'].keys())}")

detector = OnlineDetector(socketio_ext=MockSocketIO())

for user in real_users:
    print(f"\n--- Testing anomaly for user {user} ---")
    
    # 1. Initialize state by processing one normal logon event (detector will load user's baseline)
    event_normal = {
        "timestamp": "2026-06-03T10:00:00",
        "user": user,
        "type": "logon",
        "hour": 10
    }
    detector.update_state(event_normal)
    print("Initial state after normal logon:", detector.user_states[user])
    
    # 2. Inject anomalous file access events (e.g. 150 zip downloads)
    print("Injecting 150 zip file downloads...")
    for _ in range(150):
        event_anom = {
            "timestamp": "2026-06-03T03:00:00", # off-hour
            "user": user,
            "type": "file",
            "hour": 3,
            "filename": "sensitive_data.zip"
        }
        detector.update_state(event_anom)
        detector.evaluate_user(user)

print("\nDone testing.")

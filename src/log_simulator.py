import os
import json
import time
import random
import threading
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s | [SIMULATOR] %(message)s")

_script_dir = os.path.dirname(os.path.abspath(__file__))
_live_logs_dir = os.path.normpath(os.path.join(_script_dir, "..", "data", "live_logs"))
_log_file = os.path.join(_live_logs_dir, "system.log")
_data_dir = os.path.normpath(os.path.join(_script_dir, "..", "data"))

users = [f"USER_{i:03d}" for i in range(1, 21)]

def ensure_dir():
    os.makedirs(_live_logs_dir, exist_ok=True)
    if not os.path.exists(_log_file):
        open(_log_file, 'a').close()

def generate_normal_event(user):
    types = ['logon', 'device', 'email', 'file']
    evt_type = random.choices(types, weights=[10, 5, 40, 45])[0]
    
    now = datetime.now()
    event = {
        "timestamp": now.isoformat(),
        "user": user,
        "type": evt_type,
        "hour": now.hour
    }
    
    if evt_type == "device":
        event["action"] = random.choice(["connect", "disconnect"])
    elif evt_type == "email":
        event["external"] = random.choice([True, False, False, False]) # 25% external
    elif evt_type == "file":
        ext = random.choice([".docx", ".xlsx", ".pdf", ".exe", ".zip"])
        event["filename"] = f"doc_{random.randint(100,999)}{ext}"
        
    return event

def generate_anomaly(user):
    now = datetime.now()
    events = []
    # Spike in file downloads (exe/zip) + external emails + off-hour (simulate 3 AM)
    for _ in range(random.randint(30, 50)):
        events.append({
            "timestamp": now.isoformat(),
            "user": user,
            "type": "file",
            "hour": 3,
            "filename": f"sensitive_data_{random.randint(1,100)}.zip"
        })
    for _ in range(random.randint(10, 20)):
        events.append({
            "timestamp": now.isoformat(),
            "user": user,
            "type": "email",
            "hour": 3,
            "external": True
        })
    return events

def run_simulation(interval=2.0):
    ensure_dir()
    logging.info(f"Started writing to {_log_file}")
    
    while True:
        with open(_log_file, "a") as f:
            # Generate normal traffic
            if random.random() < 0.8:
                u = random.choice(users)
                evt = generate_normal_event(u)
                f.write(json.dumps(evt) + "\n")
                
            # Randomly inject anomaly (2% chance per tick)
            if random.random() < 0.02:
                u = random.choice(users)
                logging.warning(f"Injecting anomaly for {u}")
                evts = generate_anomaly(u)
                for evt in evts:
                    f.write(json.dumps(evt) + "\n")
                    
        time.sleep(interval)

if __name__ == "__main__":
    run_simulation(0.5)

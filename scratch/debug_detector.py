import os
import sys

_script_dir = os.path.dirname(os.path.abspath(__file__))
_project_dir = os.path.normpath(os.path.join(_script_dir, ".."))
sys.path.insert(0, os.path.join(_project_dir, "src"))

from online_detector import OnlineDetector
import json

detector = OnlineDetector()

log_file = os.path.join(_project_dir, "data", "r4.2", "live_logs", "system.log")

with open(log_file, 'r', encoding='utf-8') as f:
    lines = f.readlines()

print(f"Total lines: {len(lines)}")

for idx, line in enumerate(lines):
    line = line.strip()
    if not line:
        continue
    try:
        event = json.loads(line)
        user = event.get("user")
        if user == "USER_016":
            # Update state
            detector.update_state(event)
            state = detector.user_states[user]
            
            # Print state details
            print(f"\nLine {idx+1} | Event: {event['type']} | User: {user}")
            print(f"  Current State: {state}")
            
            # Evaluate manually to show variables
            vector = []
            for f_name in detector.feature_names:
                if f_name in detector.live_feature_names:
                    vector.append(state.get(f_name, 0))
                else:
                    base = detector.baselines.get(user, {}).get(f_name)
                    if not base:
                        base = detector.global_baselines.get(f_name, {"mean": 0})
                    vector.append(base["mean"])
            
            v_scaled = detector.scaler.transform([vector])
            prediction = detector.model.predict(v_scaled)[0]
            score = float(detector.model.decision_function(v_scaled)[0])
            
            # Deviation check
            deviation_count = 0
            dev_details = []
            for fname in detector.live_feature_names:
                val = state.get(fname, 0)
                base = detector.baselines.get(user, {}).get(fname)
                if not base:
                    base = detector.global_baselines.get(fname, {"mean": 0, "std": 1})
                mean = base["mean"]
                std = max(base["std"], 1.0)
                dev = abs(val - mean) / std
                if dev > 1.0:
                    deviation_count += 1
                    dev_details.append(f"{fname}(val={val:.1f}, mean={mean:.1f}, std={std:.1f}, dev={dev:.1f})")
            
            print(f"  Scaled Vector: {[round(float(v), 2) for v in v_scaled[0]]}")
            print(f"  Prediction: {prediction} | Score: {score:.4f}")
            print(f"  Deviation Count: {deviation_count} | Triggered details: {dev_details}")
            
            if prediction == -1 or deviation_count >= 2:
                print(f"  >>> ALERT TRIGGERED! <<<")
                # Stop here to see the first trigger
                break
    except Exception as e:
        print("Error:", e)
        break

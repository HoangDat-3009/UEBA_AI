import os
import sqlite3
import pandas as pd
import numpy as np
import logging
from datetime import datetime
from ueba_pipeline import UEBAPipeline

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | [OFFLINE] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

_script_dir = os.path.dirname(os.path.abspath(__file__))
_data_dir = os.path.normpath(os.path.join(_script_dir, "..", "data", "r4.2"))
_models_dir = os.path.normpath(os.path.join(_script_dir, "..", "models"))
_baseline_db_path = os.path.join(_data_dir, "baseline.db")
_alerts_db_path = os.path.join(_data_dir, "alerts.db")

def init_dbs():
    """Initialize SQLite databases for baselines and alerts."""
    # Baseline DB
    conn = sqlite3.connect(_baseline_db_path)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS baselines (
            user_id TEXT,
            feature_name TEXT,
            mean REAL,
            std REAL,
            min_val REAL,
            max_val REAL,
            p95 REAL,
            computed_at TIMESTAMP,
            PRIMARY KEY (user_id, feature_name)
        )
    ''')
    
    # Precompute global thresholds based on typical values across all users
    # useful when a user has no history or very little history
    c.execute('''
        CREATE TABLE IF NOT EXISTS global_baselines (
            feature_name TEXT PRIMARY KEY,
            mean REAL,
            std REAL,
            min_val REAL,
            max_val REAL,
            p95 REAL,
            computed_at TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS model_meta (
            key TEXT PRIMARY KEY, value TEXT, updated_at TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

    # Alerts DB
    conn = sqlite3.connect(_alerts_db_path)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP,
            user_id TEXT,
            severity TEXT,
            anomaly_score REAL,
            feature_deviations TEXT,
            description TEXT,
            acknowledged INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()


def run_offline_profiling():
    logger.info("Starting Offline Profiling...")
    
    init_dbs()
    
    pipeline = UEBAPipeline(data_dir=_data_dir, contamination=0.05)
    df_master = pipeline.build_master_profile()
    
    if df_master.empty or len(df_master) < 2:
        logger.error("Not enough data to profile.")
        return

    # Train model and get predictions
    df_master, scaled_features = pipeline.train_predict(df_master)
    
    # Export Models
    model_path = os.path.join(_models_dir, "ueba_model.joblib")
    scaler_path = os.path.join(_models_dir, "ueba_scaler.joblib")
    pipeline.export_model(model_path, scaler_path)
    
    feature_cols = [
        c for c in df_master.columns
        if c not in ("user", "anomaly_label", "anomaly_score", "PC1", "PC2", "label_text")
    ]
    
    # Build Baseline Statistics
    # For a real system, we'd have time-series log data to compute mean/std properly.
    # Here, we only have one aggregate row per user. We will store it as 'mean' with std=0 for simplicity,
    # OR we can compute the global mean and std for these features, and store user-specific as well.
    
    conn = sqlite3.connect(_baseline_db_path)
    c = conn.cursor()
    
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Global baselines
    for f in feature_cols:
        vals = df_master[f].values
        g_mean = float(np.mean(vals))
        g_std = float(np.std(vals))
        g_min = float(np.min(vals))
        g_max = float(np.max(vals))
        g_p95 = float(np.percentile(vals, 95))
        c.execute('''
            INSERT OR REPLACE INTO global_baselines (feature_name, mean, std, min_val, max_val, p95, computed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (f, g_mean, g_std, g_min, g_max, g_p95, now))

    # User-specific baselines
    # In batch, we aggregated all history into one number. Let's use that as mean, std=global_std.
    # In a real app, we'd roll up over 1-hour windows to calculate mean/std of windows.
    for _, row in df_master.iterrows():
        uid = row["user"]
        for f in feature_cols:
            val = float(row[f])
            # For this demo, let's just use val as mean, and global std as std to allow some wiggle room
            # so the detector won't alert on exact same behavior.
            # We'll calculate g_std from global table query
            c.execute('SELECT std FROM global_baselines WHERE feature_name=?', (f,))
            g_std = c.fetchone()[0]
            
            # std shouldn't be 0. Avoid division by zero later.
            std_val = max(g_std, 1.0)

            c.execute('''
                INSERT OR REPLACE INTO baselines (user_id, feature_name, mean, std, min_val, max_val, p95, computed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (uid, f, val, std_val, val, val, val, now))

    c.execute('INSERT OR REPLACE INTO model_meta (key, value, updated_at) VALUES (?, ?, ?)',
              ('last_profiled', now, now))
    
    conn.commit()
    conn.close()
    
    logger.info(f"Offline Profiling completed. Baselines saved for {len(df_master)} users.")

if __name__ == "__main__":
    run_offline_profiling()

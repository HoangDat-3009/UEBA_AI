import sqlite3
c = sqlite3.connect('data/r4.2/baseline.db')
print(c.execute("SELECT * FROM global_baselines WHERE feature_name IN ('exe_zip_downloads', 'total_file_access')").fetchall())

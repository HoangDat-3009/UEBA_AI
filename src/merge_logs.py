import os
import json
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s | [MERGE] %(message)s")
logger = logging.getLogger(__name__)

_script_dir = os.path.dirname(os.path.abspath(__file__))
_data_dir = os.path.normpath(os.path.join(_script_dir, "..", "data"))
_live_logs_dir = os.path.join(_data_dir, "live_logs")
_log_file = os.path.join(_live_logs_dir, "system.log")

def merge_system_log():
    if not os.path.exists(_log_file):
        return
        
    with open(_log_file, "r") as f:
        lines = f.readlines()
        
    if not lines:
        return
        
    logger.info(f"Merging {len(lines)} realtime logs into batch CSVs...")
    
    with open(os.path.join(_data_dir, "logon.csv"), "a") as logon_f, \
         open(os.path.join(_data_dir, "device.csv"), "a") as device_f, \
         open(os.path.join(_data_dir, "email.csv"), "a") as email_f, \
         open(os.path.join(_data_dir, "file.csv"), "a") as file_f:
         
        for line in lines:
            if not line.strip(): continue
            try:
                evt = json.loads(line)
            except:
                continue
                
            user = evt.get("user", "")
            # Convert USER_001 to USR0001 to match CSV format
            if user.startswith("USER_"):
                num = user.split("_")[1]
                user = f"USR{int(num):04d}"
                
            ts = evt.get("timestamp", "")
            ts = ts.replace("T", " ")[:19]
            
            t = evt.get("type", "")
            
            if t == "logon":
                logon_f.write(f"\n,{ts},{user},SIM-PC,Logon")
            elif t == "device":
                act = evt.get("action", "connect")
                device_f.write(f"\n,{ts},{user},SIM-PC,{act}")
            elif t == "email":
                # email.csv headers: id,date,user,to,attachments,size
                ext = evt.get("external", False)
                domain = "external@domain.com" if ext else "internal@company.com"
                attach = "attachment.zip" if ext else ""
                email_f.write(f"\n,{ts},{user},{domain},{attach},1024")
            elif t == "file":
                # file.csv headers: id,date,user,pc,filename,activity
                fname = evt.get("filename", "")
                file_f.write(f"\n,{ts},{user},SIM-PC,{fname},Access")
                
    # Truncate system.log so we don't process them again
    with open(_log_file, "w") as f:
        pass
    logger.info("Merged successfully. Truncated system.log")

if __name__ == "__main__":
    merge_system_log()

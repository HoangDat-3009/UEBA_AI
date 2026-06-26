"""Check what Windows log tools are available."""
import subprocess, sys

# Check pywin32
try:
    import win32evtlog
    print("[OK] win32evtlog (pywin32) available")
except ImportError:
    print("[NO] win32evtlog (pywin32) NOT available")

# Check wmi
try:
    import wmi
    print("[OK] wmi available")
except ImportError:
    print("[NO] wmi NOT available")

# Check subprocess wevtutil
r = subprocess.run(["wevtutil", "el"], capture_output=True, text=True, timeout=5)
logs = [l.strip() for l in r.stdout.splitlines() if l.strip()]
print(f"\n[OK] wevtutil: {len(logs)} event log channels available")
print("Top channels:", logs[:15])

# Query system events (logon-related: 7001=User Logon, 7002=User Logoff)
print("\n--- System Event IDs 7001/7002 (User Logon/Logoff) ---")
r = subprocess.run(
    ["wevtutil", "qe", "System", "/q:*[System[(EventID=7001 or EventID=7002)]]", 
     "/c:3", "/f:text", "/rd:true"],
    capture_output=True, text=True, timeout=10
)
print(r.stdout[:2000] if r.stdout else "No events found")

# Check PowerShell-based USB/Storage events
print("\n--- USB/PnP Events (Kernel-PnP) ---")
r = subprocess.run(
    ["wevtutil", "qe", "Microsoft-Windows-Kernel-PnP/Configuration",
     "/c:3", "/f:text", "/rd:true"],
    capture_output=True, text=True, timeout=10
)
print(r.stdout[:1500] if r.stdout else "No events / log not enabled")
if r.stderr:
    print("ERR:", r.stderr[:500])

# Check for Sysmon
print("\n--- Sysmon Operational ---")
r = subprocess.run(
    ["wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational",
     "/c:1", "/f:text", "/rd:true"],
    capture_output=True, text=True, timeout=5
)
print(r.stdout[:500] if r.stdout else "Not available")
if r.stderr:
    print("ERR:", r.stderr[:200])

# Check PowerShell script execution logs
print("\n--- PowerShell/Operational ---")
r = subprocess.run(
    ["wevtutil", "qe", "Microsoft-Windows-PowerShell/Operational",
     "/c:3", "/f:text", "/rd:true"],
    capture_output=True, text=True, timeout=5
)
print(r.stdout[:1500] if r.stdout else "Not available")
if r.stderr:
    print("ERR:", r.stderr[:200])

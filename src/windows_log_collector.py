# File: src/windows_log_collector.py
# ===========================================================================
# Windows Event Log Collector — Replaces log_simulator.py
# ===========================================================================
# Reads REAL Windows Event Logs from multiple channels using `wevtutil`
# (built-in Windows tool, no extra packages required) and converts them
# into the UEBA JSON format that online_detector.py already consumes.
#
# Channels monitored:
#   - System:           Logon/Logoff (7001/7002), Services, Drivers
#   - Application:      Application events
#   - PowerShell/Op:    Script execution events
#   - Kernel-PnP/Conf:  USB/Device plug events
# ===========================================================================

import os
import sys
import json
import time
import logging
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | [COLLECTOR] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

_script_dir = os.path.dirname(os.path.abspath(__file__))
_data_dir = os.path.normpath(os.path.join(_script_dir, "..", "data", "r4.2"))
_live_logs_dir = os.path.join(_data_dir, "live_logs")
_default_log_file = os.path.join(_live_logs_dir, "system.log")

# XML namespace used by Windows Event Log
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# ---------------------------------------------------------------------------
# Channel definitions with XPath filters
# ---------------------------------------------------------------------------
# Each channel has a list of Event IDs we care about for UEBA analysis.
CHANNELS = {
    "System": {
        "description": "Logon/Logoff, Services, Drivers, Kernel events",
        "xpath": (
            "*[System[("
            "EventID=7001 or EventID=7002 or "   # Winlogon logon/logoff
            "EventID=10000 or EventID=10002 or "  # Driver install/update (USB)
            "EventID=16 or "                       # Kernel-General hive/file access
            "EventID=7045"                         # New service installed
            ")]]"
        ),
    },
    "Microsoft-Windows-Kernel-PnP/Configuration": {
        "description": "USB/Device connect/disconnect",
        "xpath": "*[System[(EventID=410 or EventID=430)]]",
    },
    "Microsoft-Windows-PowerShell/Operational": {
        "description": "PowerShell script execution",
        "xpath": (
            "*[System[("
            "EventID=40961 or EventID=40962 or "  # Console startup/ready
            "EventID=4104"                         # Script block execution
            ")]]"
        ),
    },
    "Application": {
        "description": "Application errors and warnings",
        "xpath": "*[System[(Level=1 or Level=2 or Level=3)]]",  # Critical, Error, Warning only
    },
}

# ---------------------------------------------------------------------------
# SID-to-username cache (avoid repeated lookups)
# ---------------------------------------------------------------------------
_sid_cache = {}


def _resolve_sid(sid: str) -> str:
    """Convert a Windows SID to a username.

    Uses a simple heuristic: the last part of a domain SID (RID) combined
    with a `wmic` lookup for the current machine. Falls back to the raw SID.
    """
    if not sid or sid in ("S-1-5-18", "S-1-5-19", "S-1-5-20"):
        # Well-known system accounts
        return {
            "S-1-5-18": "SYSTEM",
            "S-1-5-19": "LOCAL_SERVICE",
            "S-1-5-20": "NETWORK_SERVICE",
        }.get(sid, sid)

    if sid in _sid_cache:
        return _sid_cache[sid]

    # Try to resolve via wmic (fast, local-only)
    try:
        result = subprocess.run(
            ["wmic", "useraccount", "where", f"SID='{sid}'", "get", "Name"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            name = line.strip()
            if name and name.lower() != "name":
                _sid_cache[sid] = name
                return name
    except Exception:
        pass

    # Fallback: extract the last SID component as a pseudo-username
    parts = sid.rsplit("-", 1)
    if len(parts) == 2:
        fallback = f"USER_{parts[1]}"
        _sid_cache[sid] = fallback
        return fallback

    _sid_cache[sid] = sid
    return sid


# ---------------------------------------------------------------------------
# Main Collector Class
# ---------------------------------------------------------------------------

class WindowsLogCollector:
    """Collect real Windows Event Logs and output UEBA-compatible JSON.

    This class replaces the simulated log_simulator.py. It polls Windows
    Event Log channels using `wevtutil` (built-in) and writes structured
    JSON lines to the same `system.log` file that online_detector.py reads.
    """

    def __init__(self, output_path: str = None, poll_interval: float = 3.0):
        self.output_path = output_path or _default_log_file
        self.poll_interval = poll_interval
        self.running = False
        self.total_events = 0
        self.start_time = None

        # Per-channel bookmark: last event timestamp (ISO 8601 UTC)
        self._bookmarks: dict[str, str] = {}

        # Ensure output directory exists
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def run(self):
        """Main polling loop. Call from a thread or directly."""
        self.running = True
        self.start_time = datetime.now()

        # Initialize bookmarks to "now" so we only get NEW events going forward
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.0000000Z")
        for channel in CHANNELS:
            self._bookmarks[channel] = now_utc

        logger.info("=" * 60)
        logger.info("Windows Event Log Collector started")
        logger.info("Output: %s", self.output_path)
        logger.info("Poll interval: %.1fs", self.poll_interval)
        logger.info("Channels: %s", ", ".join(CHANNELS.keys()))
        logger.info("=" * 60)

        # Also do one initial historical scan (last 5 minutes) to have some data
        self._initial_scan()

        while self.running:
            try:
                self._poll_all_channels()
            except Exception as e:
                logger.error("Poll error: %s", e)
            time.sleep(self.poll_interval)

    def stop(self):
        """Stop the polling loop."""
        self.running = False
        logger.info("Collector stopped. Total events collected: %d", self.total_events)

    def get_status(self) -> dict:
        """Return current collector status for API."""
        uptime = None
        if self.start_time:
            uptime = str(datetime.now() - self.start_time).split(".")[0]
        return {
            "running": self.running,
            "total_events": self.total_events,
            "uptime": uptime,
            "channels": list(CHANNELS.keys()),
            "poll_interval": self.poll_interval,
            "output_path": self.output_path,
        }

    # -------------------------------------------------------------------
    # Internal: Polling
    # -------------------------------------------------------------------

    def _initial_scan(self):
        """Scan events from the last 5 minutes for initial data."""
        five_min_ago = (
            datetime.now(timezone.utc) - timedelta(minutes=5)
        ).strftime("%Y-%m-%dT%H:%M:%S.0000000Z")

        logger.info("Initial scan: collecting events from last 5 minutes...")
        total = 0

        for channel, config in CHANNELS.items():
            try:
                events = self._query_channel(channel, config["xpath"], five_min_ago)
                if events:
                    ueba_events = self._convert_events(events, channel)
                    self._write_events(ueba_events)
                    total += len(ueba_events)
            except Exception as e:
                logger.warning("Initial scan failed for %s: %s", channel, e)

        logger.info("Initial scan complete: %d events collected", total)

    def _poll_all_channels(self):
        """Poll all channels for new events since last bookmark."""
        for channel, config in CHANNELS.items():
            try:
                since = self._bookmarks.get(channel)
                events = self._query_channel(channel, config["xpath"], since)
                if not events:
                    continue

                ueba_events = self._convert_events(events, channel)
                if ueba_events:
                    self._write_events(ueba_events)

                # Update bookmark to the latest event time
                latest_time = max(e.get("_raw_time", "") for e in events)
                if latest_time:
                    self._bookmarks[channel] = latest_time

            except Exception as e:
                logger.debug("Channel %s poll error: %s", channel, e)

    def _query_channel(
        self, channel: str, xpath: str, since_time: str
    ) -> list[dict]:
        """Query a Windows Event Log channel using wevtutil.

        Returns a list of parsed event dicts from the XML output.
        """
        # Build time-based XPath filter
        time_filter = f"*[System[TimeCreated[@SystemTime>'{since_time}']]]"

        # Combine with channel-specific filter
        # wevtutil requires a single XPath, so we combine with 'and'
        combined_xpath = (
            f"*[System[TimeCreated[@SystemTime>'{since_time}']]] and {xpath}"
        )

        # Actually, wevtutil /q requires a proper XPath.
        # The simplest approach: query with time filter, then filter results.
        # We query recent events and filter by our event IDs in Python.

        try:
            result = subprocess.run(
                [
                    "wevtutil", "qe", channel,
                    f"/q:{xpath}",
                    "/c:100",       # Max 100 events per poll
                    "/f:xml",
                    "/rd:true",     # Reverse chronological
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except subprocess.TimeoutExpired:
            logger.warning("Timeout querying channel: %s", channel)
            return []
        except FileNotFoundError:
            logger.error("wevtutil not found. This module requires Windows.")
            return []

        if result.returncode != 0 or not result.stdout.strip():
            return []

        # Parse XML events
        events = self._parse_xml(result.stdout, since_time)
        return events

    # -------------------------------------------------------------------
    # Internal: XML Parsing
    # -------------------------------------------------------------------

    def _parse_xml(self, xml_text: str, since_time: str) -> list[dict]:
        """Parse wevtutil XML output into structured event dicts.

        wevtutil may return multiple <Event> elements concatenated
        (not wrapped in a root element), so we wrap them first.
        """
        # wevtutil outputs one <Event> per line, all concatenated
        xml_text = xml_text.strip()
        if not xml_text:
            return []

        # Wrap in root element for valid XML
        wrapped = f"<Events>{xml_text}</Events>"

        try:
            root = ET.fromstring(wrapped)
        except ET.ParseError as e:
            logger.debug("XML parse error: %s", e)
            return []

        events = []
        for event_elem in root.findall(f"{_NS}Event"):
            parsed = self._parse_single_event(event_elem)
            if parsed and parsed.get("_raw_time", "") > since_time:
                events.append(parsed)

        return events

    def _parse_single_event(self, event_elem) -> dict | None:
        """Extract key fields from a single <Event> XML element."""
        sys_elem = event_elem.find(f"{_NS}System")
        if sys_elem is None:
            return None

        # Event ID
        eid_elem = sys_elem.find(f"{_NS}EventID")
        event_id = int(eid_elem.text) if eid_elem is not None and eid_elem.text else 0

        # Timestamp
        tc_elem = sys_elem.find(f"{_NS}TimeCreated")
        raw_time = tc_elem.get("SystemTime", "") if tc_elem is not None else ""

        # Provider
        prov_elem = sys_elem.find(f"{_NS}Provider")
        provider = prov_elem.get("Name", "") if prov_elem is not None else ""

        # Channel
        ch_elem = sys_elem.find(f"{_NS}Channel")
        channel = ch_elem.text if ch_elem is not None else ""

        # Computer
        comp_elem = sys_elem.find(f"{_NS}Computer")
        computer = comp_elem.text if comp_elem is not None else ""

        # User SID
        sec_elem = sys_elem.find(f"{_NS}Security")
        user_sid = sec_elem.get("UserID", "") if sec_elem is not None else ""

        # Level
        lvl_elem = sys_elem.find(f"{_NS}Level")
        level = int(lvl_elem.text) if lvl_elem is not None and lvl_elem.text else 4

        # EventData — collect all <Data> elements
        event_data = {}
        ed_elem = event_elem.find(f"{_NS}EventData")
        if ed_elem is not None:
            for data_elem in ed_elem.findall(f"{_NS}Data"):
                name = data_elem.get("Name", "")
                value = data_elem.text or ""
                if name:
                    event_data[name] = value
                elif value:
                    # Unnamed data elements — store with index
                    idx = len([k for k in event_data if k.startswith("_data")])
                    event_data[f"_data{idx}"] = value

        return {
            "event_id": event_id,
            "_raw_time": raw_time,
            "provider": provider,
            "channel": channel,
            "computer": computer,
            "user_sid": user_sid,
            "level": level,
            "event_data": event_data,
        }

    # -------------------------------------------------------------------
    # Internal: Event Mapping → UEBA Format
    # -------------------------------------------------------------------

    def _convert_events(self, raw_events: list[dict], channel: str) -> list[dict]:
        """Convert parsed Windows events to UEBA JSON format."""
        ueba_events = []
        for raw in raw_events:
            mapped = self._map_to_ueba(raw)
            if mapped:
                ueba_events.append(mapped)
        return ueba_events

    def _map_to_ueba(self, raw: dict) -> dict | None:
        """Map a single Windows Event to UEBA JSON format.

        Returns a dict compatible with the existing online_detector.py format:
        {
            "timestamp": ISO string,
            "user": username,
            "type": "logon" | "device" | "file" | "email",
            "hour": int,
            ...extra fields...
        }
        """
        eid = raw["event_id"]
        raw_time = raw["_raw_time"]
        user_sid = raw["user_sid"]
        event_data = raw.get("event_data", {})

        # Parse timestamp
        try:
            # wevtutil format: "2026-06-25T01:34:18.1540596Z"
            ts_str = raw_time.replace("Z", "+00:00")
            # Truncate nanoseconds to microseconds for fromisoformat
            if "." in ts_str:
                parts = ts_str.split(".")
                frac = parts[1].split("+")[0].split("-")[0]
                tz_part = "+" + parts[1].split("+")[1] if "+" in parts[1] else ""
                if len(frac) > 6:
                    frac = frac[:6]
                ts_str = f"{parts[0]}.{frac}{tz_part}"
            dt = datetime.fromisoformat(ts_str)
            # Convert to local time
            dt_local = dt.astimezone()
        except Exception:
            dt_local = datetime.now()

        hour = dt_local.hour
        timestamp = dt_local.strftime("%Y-%m-%dT%H:%M:%S")

        # Resolve user
        # For logon events (7001/7002), the actual user SID is in EventData
        if eid in (7001, 7002):
            actual_sid = event_data.get("UserSid", user_sid)
            user = _resolve_sid(actual_sid)
        else:
            user = _resolve_sid(user_sid)

        # Map SYSTEM-level events to the active desktop user since USB plugs
        # and service installs are initiated by the desktop user but logged as SYSTEM.
        if user in ("SYSTEM", "LOCAL_SERVICE", "NETWORK_SERVICE", ""):
            try:
                import os
                user = os.getlogin()
            except Exception:
                user = "admin" # Fallback

        # --- Map by Event ID ---

        # Logon/Logoff (Winlogon)
        if eid == 7001:
            return {
                "timestamp": timestamp,
                "user": user,
                "type": "logon",
                "hour": hour,
                "source": "winlogon",
                "event_id": eid,
            }

        if eid == 7002:
            # Logoff — we still count it as a logon event for activity tracking
            return {
                "timestamp": timestamp,
                "user": user,
                "type": "logon",
                "hour": hour,
                "source": "winlogon_logoff",
                "event_id": eid,
            }

        # USB/Device connected (Kernel-PnP)
        if eid in (410, 430):
            device_id = event_data.get("DeviceInstanceId", "")
            # Check if it's a USB/Storage device
            is_usb = any(
                kw in device_id.upper()
                for kw in ("USB", "STORAGE", "USBSTOR", "WPD", "DISK")
            )
            if is_usb:
                return {
                    "timestamp": timestamp,
                    "user": user,
                    "type": "device",
                    "action": "connect",
                    "hour": hour,
                    "device_id": device_id[:80],
                    "source": "kernel_pnp",
                    "event_id": eid,
                }
            return None

        # Driver install/update (often USB-related)
        if eid in (10000, 10002):
            return {
                "timestamp": timestamp,
                "user": user,
                "type": "device",
                "action": "connect",
                "hour": hour,
                "source": "driver_framework",
                "event_id": eid,
            }

        # File/Registry access (Kernel-General hive events)
        if eid == 16:
            return {
                "timestamp": timestamp,
                "user": user,
                "type": "file",
                "hour": hour,
                "filename": "registry_hive",
                "source": "kernel_general",
                "event_id": eid,
            }

        # New service installed (potential persistence mechanism)
        if eid == 7045:
            service_name = event_data.get("ServiceName", "unknown_service")
            return {
                "timestamp": timestamp,
                "user": user,
                "type": "file",
                "hour": hour,
                "filename": f"{service_name}.exe",
                "source": "service_install",
                "event_id": eid,
            }

        # PowerShell execution
        if eid in (40961, 40962, 4104):
            return {
                "timestamp": timestamp,
                "user": user,
                "type": "file",
                "hour": hour,
                "filename": "powershell_activity",
                "process_name": "powershell.exe",
                "source": "powershell",
                "event_id": eid,
            }

        # Application errors/warnings (Level 1=Critical, 2=Error, 3=Warning)
        if raw.get("level", 4) <= 3:
            provider = raw.get("provider", "unknown")
            return {
                "timestamp": timestamp,
                "user": user,
                "type": "file",
                "hour": hour,
                "filename": f"app_event_{provider}",
                "source": "application",
                "event_id": eid,
            }

        return None

    # -------------------------------------------------------------------
    # Internal: Write to log file
    # -------------------------------------------------------------------

    def _write_events(self, events: list[dict]):
        """Append UEBA JSON events to the output log file."""
        if not events:
            return

        try:
            with open(self.output_path, "a", encoding="utf-8") as f:
                for event in events:
                    f.write(json.dumps(event, ensure_ascii=False) + "\n")
            self.total_events += len(events)

            # Log summary (not every single event)
            event_types = {}
            for e in events:
                t = e.get("type", "unknown")
                event_types[t] = event_types.get(t, 0) + 1
            type_str = ", ".join(f"{k}={v}" for k, v in event_types.items())
            logger.info(
                "Wrote %d events (%s) | Total: %d",
                len(events), type_str, self.total_events,
            )
        except OSError as e:
            logger.error("Failed to write events: %s", e)


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

def run_collector(poll_interval: float = 3.0):
    """Run the collector as a standalone process."""
    collector = WindowsLogCollector(poll_interval=poll_interval)
    try:
        collector.run()
    except KeyboardInterrupt:
        collector.stop()
        print("\nCollector stopped by user.")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  [UEBA] Windows Event Log Collector")
    print("  [MODE] Real-time log collection from Windows")
    print("=" * 60 + "\n")
    run_collector(poll_interval=3.0)

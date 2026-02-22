import os
import time
import json
import requests
from datetime import datetime
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ==============================
# LOAD CONFIG
# ==============================
with open("config.json", "r") as f:
    config = json.load(f)

API_BASE = config["api_base"]
TOKEN = config["token"]
USER_EMAIL = config["email"]

# ==============================
# SETTINGS
# ==============================
RENAME_THRESHOLD = 15
TIME_WINDOW = 10  # seconds

rename_events = deque()

# ==============================
# LOCAL LOGGING
# ==============================

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "monitor.log")

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

def write_local_log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {message}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry)

# ==============================
# BACKEND ALERT
# ==============================

def send_alert(event_type, details):
    payload = {
        "token": TOKEN,
        "event_type": event_type,
        "details": details,
        "timestamp": datetime.now().isoformat()
    }

    try:
        requests.post(
            f"{API_BASE}/api/detector/log",
            json=payload,
            timeout=5
        )
    except:
        pass

# ==============================
# MONITOR CLASS
# ==============================

class FolderMonitor(FileSystemEventHandler):

    def on_moved(self, event):
        now = time.time()
        rename_events.append(now)

        write_local_log(f"File renamed: {event.src_path}")

        while rename_events and now - rename_events[0] > TIME_WINDOW:
            rename_events.popleft()

        if len(rename_events) >= RENAME_THRESHOLD:
            message = "Mass file rename detected"
            write_local_log(message)

            send_alert(
                event_type="mass_rename",
                details={
                    "directory": MONITOR_PATH,
                    "count": len(rename_events)
                }
            )

            rename_events.clear()

# ==============================
# MAIN
# ==============================

def start_monitor(path):
    observer = Observer()
    observer.schedule(FolderMonitor(), path, recursive=True)
    observer.start()

    print("===================================")
    print("PRD-SYS FolderGuard Running")
    print("Monitoring:", path)
    print("Logs stored in:", LOG_FILE)
    print("===================================")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()

import requests

def send_log_file():
    log_path = os.path.join("logs", "monitor.log")

    if not os.path.exists(log_path):
        return

    try:
        with open(log_path, "rb") as f:
            files = {"file": ("monitor.log", f)}
            data = {"token": TOKEN}

            requests.post(
                f"{API_BASE}/api/detector/log",
                json={
                    "token": TOKEN,
                    "event_type": "mass_rename",
                    "details": {
                        "directory": monitored_path,
                        "count": len(rename_events)
                    },
                    "timestamp": datetime.now().isoformat()
                }
            )
    except Exception as e:
        print("Log upload failed:", e)

if __name__ == "__main__":
    user_input = input("Enter directory to monitor: ").strip()

    if not os.path.exists(user_input):
        print("Invalid directory.")
    else:
        MONITOR_PATH = user_input
        start_monitor(MONITOR_PATH)
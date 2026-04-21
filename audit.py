import json
import os
import tempfile
import threading
import time
from pathlib import Path
from flask import current_app, request, has_request_context

#This file contains utility functions for managing the audit trail of user activities in the application. 
#It defines functions to get the path to the audit file, load and save audit data, log events with 
#relevant details, and retrieve recent audit entries. The audit trail captures important information
#such as the event type, user ID, document ID, filename, event details, affected user ID (if applicable), 
#timestamp, and IP address. This allows for tracking user actions and monitoring system activity for 
#security and accountability purposes.

#The get_audit_file function constructs the file path for the audit trail JSON file based on the 
#application's configured data directory. The load_audit function attempts to read and parse the
#audit trail from the JSON file, returning an empty list if the file does not exist or cannot be read. 
#The save_audit function writes the provided audit data back to the JSON file with indentation for 
#readability.
AUDIT_LOCK = threading.Lock()


def get_audit_file():
    return Path(current_app.config["DATA_DIR"]) / "audit_trail.json"

#The log_event function is responsible for recording an event in the audit trail. It takes parameters
#such as the event type, user ID, document ID, filename, event details, and affected user ID. It loads
#the existing audit data, appends a new entry with the provided information along with the current
#timestamp and the IP address of the requester (if available), and then saves the updated audit data back
#to the file. This function is used throughout the application to log various user actions and system events.
def load_audit():
    try:
        with open(get_audit_file(), 'r', encoding='utf-8-sig') as f:
            return json.load(f)
    except:
        return []
    
#The save_audit function writes the audit data back to the JSON file. It writes to a temporary
#file first and then replaces the real audit file in one step so the app is less likely to leave
#behind a half-written audit trail if something interrupts the save.
def save_audit(data):
    audit_file = get_audit_file()
    audit_file.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=audit_file.parent,
        delete=False,
    ) as handle:
        json.dump(data, handle, indent=4)
        temp_name = handle.name

    # I replace the audit file in one step here so a partial write does not leave
    # the audit trail half-written if the app is interrupted mid-save.
    os.replace(temp_name, audit_file)

#The log_event function is responsible for recording an event in the audit trail. It takes parameters
#such as the event type, user ID, document ID, filename, event details, and affected user ID. It loads
#the existing audit data, appends a new entry with the provided information along with the current
#timestamp and the IP address of the requester (if available), and then saves the updated audit data back
#to the file. It also uses a lock so two requests do not overwrite each other's audit entry while they
#are both trying to update the audit trail at the same time.
def log_event(event, user_id, doc_id=None, filename=None, details=None, affected_user_id=None):
    # I use a lock around load -> append -> save so two requests do not both read
    # the same old audit list and accidentally overwrite each other's event.
    with AUDIT_LOCK:
        logs = load_audit()
        ip_address = request.remote_addr if has_request_context() else "unknown"
        logs.append({
            "event": event,
            "user_id": user_id,
            "doc_id": doc_id,
            "filename": filename,
            "details": details,
            "affected_user_id": affected_user_id,
            "timestamp": time.time(),
            "ip_address": ip_address
        })
        save_audit(logs)

#The get_recent_audit function retrieves the audit entries sorted by timestamp in descending order
#(most recent first). It accepts an optional limit parameter to specify how many recent entries to
#return. If no limit is provided, it returns all audit entries sorted by recency. This function is used
#to display recent user activities in the audit log view and for administrative monitoring purposes.
def get_recent_audit(limit=None):
    logs = sorted(load_audit(), key=lambda entry: entry.get("timestamp", 0), reverse=True)
    if limit is not None:
        return logs[:limit]
    return logs

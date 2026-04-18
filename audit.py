import json
import time
from pathlib import Path
from flask import current_app, request, has_request_context

def get_audit_file():
    return Path(current_app.config["DATA_DIR"]) / "audit_trail.json"

def load_audit():
    try:
        with open(get_audit_file(), 'r') as f:
            return json.load(f)
    except:
        return []
    
def save_audit(data):
    with open(get_audit_file(), 'w') as f:
        json.dump(data, f, indent=4)

def log_event(event, user_id, doc_id=None, filename=None):
    logs = load_audit()
    ip_address = request.remote_addr if has_request_context() else "unknown"
    logs.append({
        "event": event,
        "user_id": user_id,
        "doc_id": doc_id,
        "filename": filename,
        "timestamp": time.time(),
        "ip_address": ip_address
    })
    save_audit(logs)


def get_recent_audit(limit=None):
    logs = sorted(load_audit(), key=lambda entry: entry.get("timestamp", 0), reverse=True)
    if limit is not None:
        return logs[:limit]
    return logs

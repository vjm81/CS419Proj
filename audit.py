import json
import time
from pathlib import Path
from flask import current_app, request

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
    logs.append({
        "event": event,
        "user_id": user_id,
        "doc_id": doc_id,
        "filename": filename,
        "timestamp": time.time(),
        "ip_address": request.remote_addr
    })
    save_audit(logs)

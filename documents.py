import json
import uuid
import time
from pathlib import Path

from flask import current_app, has_request_context, request
from werkzeug.utils import secure_filename

from audit import log_event
from encryption import EncryptedFileStorage

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DATA_FILE = BASE_DIR / "data" / "documents.json"
DEFAULT_SHARES_FILE = BASE_DIR / "data" / "shares.json"
DEFAULT_FILES_DIR = BASE_DIR / "data" / "encrypted"
DEFAULT_KEY_FILE = BASE_DIR / "secret.key"


def get_documents_file():
    try:
        # I use the app config path here so tests and the real app both read the same documents file.
        return Path(current_app.config["DATA_DIR"]) / "documents.json"
    except RuntimeError:
        return DEFAULT_DATA_FILE


def get_shares_file():
    try:
        return Path(current_app.config["DATA_DIR"]) / "shares.json"
    except RuntimeError:
        return DEFAULT_SHARES_FILE


def get_files_dir():
    try:
        # This keeps encrypted uploads inside the app's configured encrypted folder.
        files_dir = Path(current_app.config["ENCRYPTED_DIR"])
    except RuntimeError:
        files_dir = DEFAULT_FILES_DIR
    files_dir.mkdir(parents=True, exist_ok=True)
    return files_dir


def get_encrypted_storage():
    try:
        key_file = Path(current_app.config["ENCRYPTION_KEY_FILE"])
    except RuntimeError:
        key_file = DEFAULT_KEY_FILE
    return EncryptedFileStorage(key_file)


def get_upload_policy():
    try:
        return {
            "allowed_extensions": set(current_app.config["ALLOWED_UPLOAD_EXTENSIONS"]),
            "allowed_mime_types": set(current_app.config["ALLOWED_UPLOAD_MIME_TYPES"]),
            "extension_mime_map": {
                extension: set(mime_types)
                for extension, mime_types in current_app.config["EXTENSION_MIME_MAP"].items()
            },
        }
    except RuntimeError:
        return {
            "allowed_extensions": {"txt", "pdf", "doc", "docx", "csv", "png", "jpg", "jpeg"},
            "allowed_mime_types": {
                "text/plain",
                "application/pdf",
                "application/msword",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "text/csv",
                "image/png",
                "image/jpeg",
            },
            "extension_mime_map": {
                "txt": {"text/plain"},
                "pdf": {"application/pdf"},
                "doc": {"application/msword"},
                "docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
                "csv": {"text/csv"},
                "png": {"image/png"},
                "jpg": {"image/jpeg"},
                "jpeg": {"image/jpeg"},
            },
        }

def load_documents():
    data_file = get_documents_file()
    try:
        with open(data_file, 'r', encoding='utf-8') as f:
            documents = json.load(f)
            # I normalize old list-based data to an empty dict because the rest of this file stores docs by id.
            if isinstance(documents, list):
                return {}
            return documents
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    
def save_documents(documents):
    data_file = get_documents_file()
    with open(data_file, 'w', encoding='utf-8') as f:
        json.dump(documents, f, indent=4)


def load_share_index():
    shares_file = get_shares_file()
    try:
        with open(shares_file, 'r', encoding='utf-8') as f:
            shares = json.load(f)
            return shares if isinstance(shares, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_share_index(shares):
    shares_file = get_shares_file()
    with open(shares_file, 'w', encoding='utf-8') as f:
        json.dump(shares, f, indent=4)

def create_document(file, owner_id, document_name=None):
    documents = load_documents()
    doc_id = str(uuid.uuid4())
    original_filename, stored_filename = save_encrypted_upload(file)
    now = time.time()
    display_name = (document_name or "").strip() or original_filename
    documents[doc_id] = {
        "id": doc_id,
        "display_name": display_name,
        "filename": original_filename,
        "stored_filename": stored_filename,
        "owner_id": owner_id,
        "shared_with": [],
        "created_at": now,
        "updated_at": now,
        "version": 1,
        "version_history": [],
        "is_deleted": False,
    }

    log_event("FILE_UPLOAD", owner_id, doc_id, display_name)
    save_documents(documents)
    return doc_id

def get_document(doc_id):
    documents = load_documents()
    return documents.get(doc_id)


def get_all_documents(include_deleted: bool = False):
    documents = list(load_documents().values())
    if include_deleted:
        return documents
    return [doc for doc in documents if not doc.get("is_deleted")]


def get_user_document_role(doc, user_id):
    if doc["owner_id"] == user_id:
        return "owner"

    for entry in doc["shared_with"]:
        if entry["user_id"] == user_id:
            return entry["role"]

    return None


def can_view_document(doc, user_id):
    return get_user_document_role(doc, user_id) in {"owner", "editor", "viewer"}


def can_edit_document(doc, user_id):
    return get_user_document_role(doc, user_id) in {"owner", "editor"}


def can_share_document(doc, user_id):
    return get_user_document_role(doc, user_id) == "owner"


def can_user_access(doc, user_id):
    return can_view_document(doc, user_id)


def sync_share_index(documents):
    shares = []
    for doc in documents.values():
        if doc.get("is_deleted"):
            continue
        for entry in doc.get("shared_with", []):
            shares.append(
                {
                    "document_id": doc["id"],
                    "owner_id": doc["owner_id"],
                    "user_id": entry["user_id"],
                    "role": entry["role"],
                    "filename": doc["display_name"],
                    "updated_at": doc["updated_at"],
                }
            )
    save_share_index(shares)


def share_document(doc_id, owner_id, target_user_id, role):
    if role not in {"viewer", "editor"}:
        raise ValueError("Invalid share role.")

    documents = load_documents()
    if doc_id not in documents:
        raise ValueError("Document not found.")

    doc = documents[doc_id]
    if not can_share_document(doc, owner_id):
        raise PermissionError("You do not have permission to share this document.")
    if target_user_id == owner_id:
        raise ValueError("You already own this document.")

    for entry in doc['shared_with']:
        if entry['user_id'] == target_user_id:
            entry['role'] = role
            doc['updated_at'] = time.time()
            sync_share_index(documents)
            save_documents(documents)
            log_event("FILE_SHARED", target_user_id, doc_id, doc["filename"])
            return doc
    doc['shared_with'].append({
        "user_id": target_user_id,
        "role": role
    })

    doc['updated_at'] = time.time()
    sync_share_index(documents)
    save_documents(documents)
    log_event("FILE_SHARED", target_user_id, doc_id, doc["filename"])
    return doc


def remove_share(doc_id, owner_id, target_user_id):
    documents = load_documents()
    if doc_id not in documents:
        raise ValueError("Document not found.")

    doc = documents[doc_id]
    if not can_share_document(doc, owner_id):
        raise PermissionError("You do not have permission to manage sharing for this document.")

    original_len = len(doc.get("shared_with", []))
    doc["shared_with"] = [
        entry for entry in doc.get("shared_with", [])
        if entry["user_id"] != target_user_id
    ]
    if len(doc["shared_with"]) == original_len:
        raise ValueError("That user does not currently have access to this document.")

    doc["updated_at"] = time.time()
    save_documents(documents)
    sync_share_index(documents)
    log_event("FILE_UNSHARED", target_user_id, doc_id, doc["filename"])
    return doc


def delete_document(doc_id, actor_id, allow_override: bool = False):
    documents = load_documents()
    doc = documents.get(doc_id)
    if not doc or doc.get("is_deleted"):
        raise ValueError("Document not found.")

    if not allow_override and doc["owner_id"] != actor_id:
        raise PermissionError("You do not have permission to delete this document.")

    doc["is_deleted"] = True
    doc["updated_at"] = time.time()
    save_documents(documents)
    sync_share_index(documents)
    log_event("FILE_DELETED", actor_id, doc_id, doc.get("display_name", doc["filename"]))
    return doc


def remove_user_from_all_shares(target_user_id):
    documents = load_documents()
    changed = False
    for doc in documents.values():
        original_len = len(doc.get("shared_with", []))
        doc["shared_with"] = [
            entry for entry in doc.get("shared_with", [])
            if entry["user_id"] != target_user_id
        ]
        if len(doc["shared_with"]) != original_len:
            doc["updated_at"] = time.time()
            changed = True

    if changed:
        save_documents(documents)
        sync_share_index(documents)

def get_user_documents(user_id):
    documents = load_documents()
    user_docs = []
    for doc in documents.values():
        if doc['is_deleted']:
            continue
        # A user should see their own files plus files that were explicitly shared with them.
        if can_view_document(doc, user_id):
            user_docs.append(doc)

    return user_docs


def get_owned_documents(user_id):
    return [doc for doc in load_documents().values() if not doc["is_deleted"] and doc["owner_id"] == user_id]


def get_documents_shared_with_user(user_id):
    shared_docs = []
    for doc in load_documents().values():
        if doc["is_deleted"]:
            continue
        role = get_user_document_role(doc, user_id)
        if role in {"viewer", "editor"}:
            shared_docs.append(doc)
    return shared_docs

def get_file_path(doc):
    return str(get_files_dir() / doc['stored_filename'])


def get_decrypted_file_bytes(doc):
    encrypted_storage = get_encrypted_storage()
    return encrypted_storage.decrypt_from_file(get_file_path(doc))


def save_encrypted_upload(file):
    files_dir = get_files_dir()
    encrypted_storage = get_encrypted_storage()

    # I clean the original filename first so weird path characters do not get written to disk.
    original_filename = secure_filename(file.filename or "")
    if not original_filename:
        raise ValueError("Invalid filename.")

    validate_uploaded_file(file, original_filename)

    # The stored filename gets a UUID prefix so two users can upload files with the same visible name safely.
    stored_filename = f"{uuid.uuid4()}_{original_filename}"
    filepath = files_dir / stored_filename

    # To meet the data-at-rest requirement, I encrypt the uploaded bytes before writing them to disk.
    encrypted_storage.encrypt_to_file(filepath, file.read())
    return original_filename, stored_filename


def validate_uploaded_file(file, original_filename):
    policy = get_upload_policy()
    extension = original_filename.rsplit(".", 1)[-1].lower() if "." in original_filename else ""
    content_type = (getattr(file, "content_type", "") or "").split(";", 1)[0].strip().lower()

    if extension not in policy["allowed_extensions"]:
        log_input_validation_failure(original_filename, "disallowed_extension", content_type)
        raise ValueError("This file type is not allowed.")

    if content_type not in policy["allowed_mime_types"]:
        log_input_validation_failure(original_filename, "disallowed_mime_type", content_type)
        raise ValueError("This upload MIME type is not allowed.")

    expected_mime_types = policy["extension_mime_map"].get(extension, set())
    if expected_mime_types and content_type not in expected_mime_types:
        log_input_validation_failure(original_filename, "mime_extension_mismatch", content_type)
        raise ValueError("The file extension does not match the detected upload type.")


def log_input_validation_failure(filename, reason, content_type):
    log_event("INPUT_VALIDATION_FAILED", None, filename=filename)
    try:
        current_app.logger.warning(
            json.dumps(
                {
                    "event_type": "INPUT_VALIDATION_FAILED",
                    "user_id": None,
                    "ip_address": request.remote_addr if has_request_context() else "unknown",
                    "user_agent": request.headers.get("User-Agent") if has_request_context() else "unknown",
                    "details": {
                        "filename": filename,
                        "reason": reason,
                        "content_type": content_type,
                    },
                    "severity": "WARNING",
                }
            )
        )
    except RuntimeError:
        pass


def update_document(doc_id, user_id, file):
    documents = load_documents()
    doc = documents.get(doc_id)
    if not doc or doc.get("is_deleted"):
        raise ValueError("Document not found.")
    if not can_edit_document(doc, user_id):
        raise PermissionError("You do not have permission to update this document.")

    original_filename, stored_filename = save_encrypted_upload(file)
    now = time.time()

    # I keep metadata for older versions so we still have a history even after the latest file replaces the current one.
    doc.setdefault("version_history", []).append(
        {
            "version": doc["version"],
            "display_name": doc["display_name"],
            "filename": doc["filename"],
            "stored_filename": doc["stored_filename"],
            "updated_at": doc["updated_at"],
        }
    )
    doc["filename"] = original_filename
    doc["stored_filename"] = stored_filename
    doc["version"] += 1
    doc["updated_at"] = now

    save_documents(documents)
    sync_share_index(documents)
    log_event("FILE_UPDATED", user_id, doc_id, original_filename)
    return doc


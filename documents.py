import os
import json
import uuid
import time
from pathlib import Path

from flask import current_app
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DATA_FILE = BASE_DIR / "data" / "documents.json"
DEFAULT_FILES_DIR = BASE_DIR / "files"


def get_documents_file():
    try:
        # I use the app config path here so tests and the real app both read the same documents file.
        return Path(current_app.config["DATA_DIR"]) / "documents.json"
    except RuntimeError:
        return DEFAULT_DATA_FILE


def get_files_dir():
    try:
        # This keeps uploaded files inside the app's configured upload folder instead of a random hardcoded path.
        files_dir = Path(current_app.config["UPLOAD_DIR"])
    except RuntimeError:
        files_dir = DEFAULT_FILES_DIR
    files_dir.mkdir(parents=True, exist_ok=True)
    return files_dir

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

def create_document(file, owner_id):
    documents = load_documents()
    files_dir = get_files_dir()
    doc_id = str(uuid.uuid4())
    # I clean the original filename first so weird path characters do not get written to disk.
    original_filename = secure_filename(file.filename or "")
    if not original_filename:
        raise ValueError("Invalid filename.")

    # The stored filename gets a UUID prefix so two users can upload files with the same visible name safely.
    stored_filename = f"{uuid.uuid4()}_{original_filename}"

    filepath = files_dir / stored_filename

    # Right now uploads still save in plain form. The next encryption step will swap this
    # for the helper in encryption.py so the file bytes are encrypted before being written.
    file.save(filepath)
    documents[doc_id] = {
        "id": doc_id,
        "filename": original_filename,
        "stored_filename": stored_filename,
        "owner_id": owner_id,
        "shared_with": [],
        "created_at": time.time(),
        "updated_at": time.time(),
        "version": 1,
        "is_deleted": False
    }
    save_documents(documents)
    return doc_id

def get_document(doc_id):
    documents = load_documents()
    return documents.get(doc_id)
    
def can_user_access(doc, user_id):
    if doc['owner_id'] == user_id:
        return True
        
    for entry in doc['shared_with']:
        if entry['user_id'] == user_id:
            return True
            
    return False
    
def share_document(doc_id, target_user_id, role):
    documents = load_documents()
    if doc_id not in documents:
        return False
        
    doc = documents[doc_id]
    for entry in doc['shared_with']:
        if entry['user_id'] == target_user_id:
            entry['role'] = role
            save_documents(documents)
            return True
    doc['shared_with'].append({
        "user_id": target_user_id,
        "role": role
    })

    doc['updated_at'] = time.time()
    save_documents(documents)
    return True

def get_user_documents(user_id):
    documents = load_documents()
    user_docs = []
    for doc in documents.values():
        if doc['is_deleted']:
            continue
        # A user should see their own files plus files that were explicitly shared with them.
        if doc['owner_id'] == user_id or can_user_access(doc, user_id):
            user_docs.append(doc)

    return user_docs

def get_file_path(doc):
    # This currently returns the on-disk upload path. Once encryption is wired in,
    # downloads should read the encrypted file and decrypt it before sending it back.
    return str(get_files_dir() / doc['stored_filename'])

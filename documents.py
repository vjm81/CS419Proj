import os
import json
import uuid
import time

DATA_FILE = 'data/documents.json'
FILES_DIR = 'files/'

os.makedirs(FILES_DIR, exist_ok=True)

def load_documents():
    try:
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    except:
        return []
    
def save_documents(documents):
    with open(DATA_FILE, 'w') as f:
        json.dump(documents, f, indent=4)

def create_document(file, owner_id):
    documents = load_documents()
    doc_id = str(uuid.uuid4())
    stored_filename = f"{uuid.uuid4()}.enc"

    filepath = os.path.join(FILES_DIR, stored_filename)

    file.save(filepath)
    documents[doc_id] = {
        "id": doc_id,
        "filename": file.filename,
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
        if doc['owner_id'] == user_id or can_user_access(doc, user_id):
            user_docs.append(doc)

    return user_docs

def get_file_path(doc):
    return os.path.join(FILES_DIR, doc['stored_filename'])
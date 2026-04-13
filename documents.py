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

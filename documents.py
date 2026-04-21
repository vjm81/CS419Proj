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

#This documents module manages the core functionality related to document storage, retrieval, sharing, 
#and versioning. It defines functions for loading and saving document metadata, handling file uploads 
#with encryption, and enforcing access controls based on user roles. The module interacts with the 
#file system to store encrypted files and uses JSON files to maintain the document index and sharing
#information. It also includes logging for important events like uploads, shares, updates, and deletions 
#to support auditing and monitoring of document-related activities. Overall, this module encapsulates 
#the main logic for managing documents in the application while ensuring security and proper access 
#controls are in place.

#The get_documents_file, get_shares_file, and get_files_dir functions determine the file paths for 
#storing document metadata, sharing information, and uploaded files. They attempt to read these paths
#from the Flask app configuration, allowing for flexibility in different environments, but fall back 
#to default locations if the app context is not available (such as during testing). The get_encrypted_
#storage function initializes an instance of the EncryptedFileStorage class using the configured
#encryption key file, while the get_upload_policy function retrieves the allowed file extensions 
#and MIME types for uploads from the app configuration, providing defaults if not set. These functions 
#centralize the configuration and setup for document storage and upload handling, making it easier 
#to manage and maintain the underlying file paths and policies used throughout the document 
#management logic.
def get_documents_file():
    try:
        # I use the app config path here so tests and the real app both read the same documents file.
        return Path(current_app.config["DATA_DIR"]) / "documents.json"
    except RuntimeError:
        return DEFAULT_DATA_FILE

#see above comment
def get_shares_file():
    try:
        return Path(current_app.config["DATA_DIR"]) / "shares.json"
    except RuntimeError:
        return DEFAULT_SHARES_FILE

#see above comment
def get_files_dir():
    try:
        # This keeps encrypted uploads inside the app's configured encrypted folder.
        files_dir = Path(current_app.config["ENCRYPTED_DIR"])
    except RuntimeError:
        files_dir = DEFAULT_FILES_DIR
    files_dir.mkdir(parents=True, exist_ok=True)
    return files_dir

#see above comment
def get_encrypted_storage():
    try:
        key_file = Path(current_app.config["ENCRYPTION_KEY_FILE"])
    except RuntimeError:
        key_file = DEFAULT_KEY_FILE
    return EncryptedFileStorage(key_file)

#see above comment
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

#The load_documents function reads the document metadata from a JSON file and returns it as a dictionary. 
#If the file does not exist or contains invalid JSON, it returns an empty dictionary. 
#The save_documents function takes a dictionary of documents and writes it to the JSON file, 
#ensuring that the data is persisted. These functions abstract away the file handling for 
#document metadata, allowing the rest of the application to interact with documents as Python 
#dictionaries without worrying about the underlying file storage mechanics. They also handle 
#potential issues with missing or corrupted files gracefully, ensuring that the application can 
#continue to function even if there are problems with the document metadata file.
def load_documents():
    data_file = get_documents_file()
    try:
        with open(data_file, 'r', encoding='utf-8-sig') as f:
            documents = json.load(f)
            # I normalize old list-based data to an empty dict because the rest of this file stores docs by id.
            if isinstance(documents, list):
                return {}
            return documents
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

#see above
def save_documents(documents):
    data_file = get_documents_file()
    with open(data_file, 'w', encoding='utf-8') as f:
        json.dump(documents, f, indent=4)

#The load_share_index and save_share_index functions manage the sharing information for documents.
#The load_share_index function reads the sharing data from a JSON file and returns it as a list of
#shares, while the save_share_index function takes a list of shares and writes it to the JSON file.
#This sharing information is used to quickly determine which documents are shared with which users
#without having to scan through all document metadata, improving the efficiency of access control 
#checks and sharing management. Like the document loading and saving functions, these also handle 
#potential issues with missing or corrupted files gracefully, ensuring that the application can 
#continue to function even if there are problems with the sharing metadata file.
def load_share_index():
    shares_file = get_shares_file()
    try:
        with open(shares_file, 'r', encoding='utf-8-sig') as f:
            shares = json.load(f)
            return shares if isinstance(shares, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []

#see above
def save_share_index(shares):
    shares_file = get_shares_file()
    with open(shares_file, 'w', encoding='utf-8') as f:
        json.dump(shares, f, indent=4)

#The create_document function handles the creation of a new document when a user uploads a file. 
#It generates a unique document ID, saves the uploaded file using encrypted storage, and creates a 
#metadata entry for the document that includes information about the owner, sharing settings, 
#versioning, and timestamps. It also logs the upload event for auditing purposes. 
#This function encapsulates the entire process of taking an uploaded file, securely storing it, 
#and creating the necessary metadata to manage it within the application.
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

#The get_document function retrieves the metadata for a specific document by its ID. 
#It loads all documents and returns the one that matches the given ID, or None if it does 
#not exist. This function is used throughout the application to access document information 
#when performing operations like viewing, editing, sharing, or deleting documents.
def get_document(doc_id):
    documents = load_documents()
    return documents.get(doc_id)

#The get_all_documents function returns a list of all document metadata entries. It has an optional
#include_deleted parameter that, when set to True, includes documents that have been marked as deleted.
#By default, it only returns documents that are not marked as deleted. This function is useful for
#administrative views or operations that need to access the full list of documents regardless of their
#deletion status, while the default behavior supports typical user-facing views that should only show
#active documents.
def get_all_documents(include_deleted: bool = False):
    documents = list(load_documents().values())
    if include_deleted:
        return documents
    return [doc for doc in documents if not doc.get("is_deleted")]

#The get_user_document_role function checks the role of a user with respect to a specific document.
#It first checks if the user is the owner of the document, and if not, it looks through the shared_with
#list to see if the user has been granted access and what their role is (viewer or editor).
#If the user has no access, it returns None. This function is central to enforcing access
#controls throughout the application, as it allows other functions to determine what actions a user is
#allowed to perform on a document based on their role.
def get_user_document_role(doc, user_id):
    if doc["owner_id"] == user_id:
        return "owner"

    for entry in doc["shared_with"]:
        if entry["user_id"] == user_id:
            return entry["role"]

    return None

#The can_view_document, can_edit_document, and can_share_document functions are helper functions that
#determine whether a user has the necessary role to perform certain actions on a document.
def can_view_document(doc, user_id):
    return get_user_document_role(doc, user_id) in {"owner", "editor", "viewer"}

#The can_edit_document function checks if the user has either "owner" or "editor" role for the document,
#which would allow them to make changes to the document. This is used to enforce edit permissions in the
#application, ensuring that only authorized users can modify the document's content or metadata.
def can_edit_document(doc, user_id):
    return get_user_document_role(doc, user_id) in {"owner", "editor"}

#The can_share_document function checks if the user has the "owner" role for the document, which is
#required to manage sharing settings. Only the owner of a document should have the ability to share it
#with others or change sharing permissions, so this function is used to enforce that restriction in the
#application.
def can_share_document(doc, user_id):
    return get_user_document_role(doc, user_id) == "owner"

#The can_user_access function is a simple wrapper around can_view_document that checks if a user has any
#level of access to a document (owner, editor, or viewer). This can be used in contexts where we just need
#to know if the user can access the document at all, without needing to differentiate between view and edit
#permissions.
def can_user_access(doc, user_id):
    return can_view_document(doc, user_id)

#The sync_share_index function rebuilds the share index based on the current document metadata. It iterates
#through all documents and their sharing settings to create a list of share entries that include the document
#ID, owner ID, shared user ID, role, filename, and last updated timestamp. This share index is then saved to
#a separate JSON file for quick access when determining which documents are shared with which users, improving
#the efficiency of access control checks and sharing management throughout the application.
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

#The share_document function manages the sharing of a document with another user. It checks if the document 
#exists and if the owner has permission to share it. It then either updates the sharing role for an 
#existing shared user or adds a new entry to the shared_with list. After making changes, it updates 
#the document's metadata, syncs the share index, saves the documents, and logs the sharing event for
#auditing purposes. This function encapsulates all the logic related to sharing a document, including 
#permission checks, metadata updates, and event logging.
def share_document(doc_id, owner_id, target_user_id, role, target_label=None):
    if role not in {"viewer", "editor"}:
        raise ValueError("Invalid share role.")

    target_label = target_label or target_user_id

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
            previous_role = entry["role"]
            entry['role'] = role
            doc['updated_at'] = time.time()
            sync_share_index(documents)
            save_documents(documents)
            log_event(
                "FILE_SHARE_ROLE_UPDATED",
                owner_id,
                doc_id,
                doc.get("display_name", doc["filename"]),
                details=f"Changed {target_label} from {previous_role} to {role}",
                affected_user_id=target_user_id,
            )
            return doc
    doc['shared_with'].append({
        "user_id": target_user_id,
        "role": role
    })

    doc['updated_at'] = time.time()
    sync_share_index(documents)
    save_documents(documents)
    log_event(
        "FILE_SHARED",
        owner_id,
        doc_id,
        doc.get("display_name", doc["filename"]),
        details=f"Granted {role} access to {target_label}",
        affected_user_id=target_user_id,
    )
    return doc

#The remove_share function handles the removal of a user's access to a document. It checks if the 
#document exists and if the owner has permission to manage sharing for it. It then removes the 
#specified user from the shared_with list and updates the document's metadata. After making changes, 
#it syncs the share index, saves the documents, and logs the unsharing event for auditing purposes. 
#This function ensures that only authorized users can manage sharing settings and that all changes 
#are properly recorded and reflected in the application's data storage. It also provides feedback 
#if the user being removed did not have access in the first place, helping to prevent 
#confusion when managing shares.
def remove_share(doc_id, owner_id, target_user_id, target_label=None):
    documents = load_documents()
    if doc_id not in documents:
        raise ValueError("Document not found.")

    target_label = target_label or target_user_id

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
    log_event(
        "FILE_UNSHARED",
        owner_id,
        doc_id,
        doc.get("display_name", doc["filename"]),
        details=f"Removed access for {target_label}",
        affected_user_id=target_user_id,
    )
    return doc

#The delete_document function marks a document as deleted by setting the is_deleted flag in its metadata.
#It checks if the document exists and if the user has permission to delete it (either the owner or an override).
#After marking the document as deleted, it updates the metadata, syncs the share index, saves the documents,
#and logs the deletion event for auditing purposes. This function does not permanently remove the document or its
#file from storage, allowing for potential recovery or auditing of deleted documents, while ensuring that
#deleted documents are not visible or accessible to regular users in the application.
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

#The remove_user_from_all_shares function is a utility function that removes a specified user from the 
#shared_with list of all documents. This is useful in scenarios such as user account deletion, 
#where you want to ensure that the user no longer has access to any documents they were previously 
#shared on. The function iterates through all documents, checks if the user is in the shared_with list,
#and if so, removes them and updates the document's metadata. After processing all documents, it saves 
#the changes and syncs the share index to reflect the updated sharing information across the application.
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

#The get_user_documents function retrieves a list of documents that a specific user has access to. 
#It loads all documents and filters them based on whether they are deleted and whether the user has 
#permission to view them. This function is used to populate the user's document list in the application, 
#showing them all the documents they own or that have been shared with them, while excluding any documents
#that have been marked as deleted. It ensures that users only see documents they are authorized to access,
#maintaining proper access controls in the user interface.
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

#The get_owned_documents function retrieves a list of documents that are owned by a specific user. 
#It loads all documents and filters them based on the owner_id. It only returns documents that are not 
#marked as deleted and where the owner_id matches the given user_id.
def get_owned_documents(user_id):
    return [doc for doc in load_documents().values() if not doc["is_deleted"] and doc["owner_id"] == user_id]

#The get_documents_shared_with_user function retrieves a list of documents that have been shared with a 
#specific user. It loads all documents and checks if the user has a viewer or editor role for each 
#document, while also excluding any documents that are marked as deleted. This function is used to 
#show users the documents that they have access to through sharing, separate from the documents they own, 
#providing a clear view of their shared document collaborations within the application. 
#It ensures that users can easily identify which documents they can access through sharing, 
#while maintaining proper access controls and excluding any documents that are no longer active.
def get_documents_shared_with_user(user_id):
    shared_docs = []
    for doc in load_documents().values():
        if doc["is_deleted"]:
            continue
        role = get_user_document_role(doc, user_id)
        if role in {"viewer", "editor"}:
            shared_docs.append(doc)
    return shared_docs

#The get_file_path function constructs the file path for a given document based on its stored filename.
#It uses the get_files_dir function to determine the base directory for file storage and appends
#the stored filename from the document metadata. This function is used to locate the encrypted file on disk
#when performing operations like decryption for downloads or updates, ensuring that the application can
#consistently find the correct file associated with a document's metadata.
def get_file_path(doc):
    return str(get_files_dir() / doc['stored_filename'])

#The get_decrypted_file_bytes function retrieves the encrypted file associated with a document, 
#decrypts it, and returns the original file bytes. It uses the get_file_path function to locate the 
#encrypted file on disk and the get_encrypted_storage function to access the encryption utilities for
#decryption.
def get_decrypted_file_bytes(doc):
    encrypted_storage = get_encrypted_storage()
    return encrypted_storage.decrypt_from_file(get_file_path(doc))

#The save_encrypted_upload function handles the process of saving an uploaded file in an encrypted format.
#It first validates the uploaded file against the defined upload policy, then generates a unique stored
#filename by prefixing the original filename with a UUID. It uses the EncryptedFileStorage instance to
#encrypt the file bytes and save them to disk. The function returns both the original filename and
#the stored filename for use in document metadata. This function ensures that all uploaded files are
#securely stored in an encrypted format, meeting the data-at-rest requirement, while also maintaining
#the necessary information to manage the files within the application. It also includes validation to
#enforce file type restrictions and prevent potentially harmful uploads, contributing to the overall
#security of the application.
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

#The validate_uploaded_file function checks if the uploaded file meets the defined upload policy, 
#including allowed file extensions and MIME types. It extracts the file extension and content type 
#from the uploaded file and compares them against the allowed lists from the upload policy. 
#If the file does not meet the requirements, it logs the validation failure and raises a 
#ValueError to prevent the upload from proceeding.
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

#The log_input_validation_failure function logs details about failed input validation attempts for
#file uploads. It records the filename, reason for failure, and content type in the application logs 
#with a warning level, and also logs an event for auditing purposes. This function helps to provide 
#visibility into potentially malicious upload attempts or user errors, allowing administrators to 
#monitor and respond to issues related to file uploads while maintaining a record of validation 
#failures for security auditing.
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

#The update_document function handles the process of updating an existing document with a new uploaded 
#file. It checks if the document exists and if the user has permission to edit it. It then saves the 
#new uploaded file in encrypted storage, updates the document's metadata with the new filename and versioning
#information, and logs the update event for auditing purposes. This function allows users to replace the
#content of an existing document while maintaining a history of previous versions and ensuring that all
#changes are properly recorded and reflected in the application's data storage. It also enforces access
#controls to ensure that only authorized users can perform updates on the document.
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
    log_event("FILE_UPDATED", user_id, doc_id, doc["display_name"])
    return doc


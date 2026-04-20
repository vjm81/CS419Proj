from io import BytesIO

from werkzeug.datastructures import FileStorage

from app import create_app
from config import Config
from documents import create_document, get_decrypted_file_bytes, get_document, get_file_path

#This file contains tests for the document management functionality of the application, specifically 
#focusing on the encryption and decryption of uploaded files. The test verifies that when a document is
#created by uploading a file, the file is stored in an encrypted format, and that the original content 
#can be correctly retrieved by decrypting the stored file. It simulates a file upload using a BytesIO 
#stream, creates a document with that file, and then checks that the stored file does not contain the 
#original plaintext content while confirming that the decrypted bytes match the original input. 
#This ensures that the encryption mechanism is working as intended while preserving data integrity for
#retrieval.


#This test verifies that when a document is created by uploading a file, the file is stored in an 
#encrypted format. It simulates a file upload using a BytesIO stream, creates a document with that 
#file, and then checks that the stored file does not contain the original plaintext content. 
#This ensures that the encryption mechanism is working as intended and that sensitive information
#is not stored in plaintext on the server.
def build_test_app(tmp_path):
    class TestConfig(Config):
        SECRET_KEY = "test-secret"
        TESTING = True
        DATA_DIR = tmp_path / "data"
        LOG_DIR = tmp_path / "logs"
        UPLOAD_DIR = DATA_DIR / "uploads"
        ENCRYPTED_DIR = DATA_DIR / "encrypted"
        ENCRYPTION_KEY_FILE = tmp_path / "secret.key"
        SESSION_TIMEOUT = 1800
        SESSION_COOKIE_SECURE = False

    return create_app(TestConfig)

#This test verifies that when a document is created by uploading a file, the file is stored in an 
#encrypted format, and that the original content can be correctly retrieved by decrypting the stored
#file. It simulates a file upload using a BytesIO stream, creates a document with that file, and then 
#checks that the stored file does not contain the original plaintext content while confirming that the 
#decrypted bytes match the original input. This ensures that the encryption mechanism is working as 
#intended while preserving data integrity for retrieval.
def test_create_document_encrypts_file_and_preserves_decryption(tmp_path):
    app = build_test_app(tmp_path)

    with app.app_context():
        uploaded_file = FileStorage(
            stream=BytesIO(b"top secret notes"),
            filename="notes.txt",
            content_type="text/plain",
        )

        doc_id = create_document(uploaded_file, "user-123")
        doc = get_document(doc_id)

        assert doc is not None
        stored_bytes = open(get_file_path(doc), "rb").read()
        assert b"top secret notes" not in stored_bytes
        assert get_decrypted_file_bytes(doc) == b"top secret notes"

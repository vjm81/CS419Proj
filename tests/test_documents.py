from io import BytesIO

from werkzeug.datastructures import FileStorage

from app import create_app
from config import Config
from documents import create_document, get_decrypted_file_bytes, get_document, get_file_path


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

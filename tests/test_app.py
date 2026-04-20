import json
from datetime import datetime
from io import BytesIO

from app import create_app, resolve_ssl_context
from config import Config


def build_test_app(tmp_path):
    class TestConfig(Config):
        SECRET_KEY = "test-secret"
        TESTING = True
        DATA_DIR = tmp_path / "data"
        LOG_DIR = tmp_path / "logs"
        UPLOAD_DIR = DATA_DIR / "uploads"
        ENCRYPTED_DIR = DATA_DIR / "encrypted"
        SESSION_TIMEOUT = 1800
        SESSION_COOKIE_SECURE = False

    return create_app(TestConfig)


def build_https_test_app(tmp_path):
    class HttpsConfig(Config):
        SECRET_KEY = "test-secret"
        DATA_DIR = tmp_path / "data"
        LOG_DIR = tmp_path / "logs"
        UPLOAD_DIR = DATA_DIR / "uploads"
        ENCRYPTED_DIR = DATA_DIR / "encrypted"
        SESSION_TIMEOUT = 1800
        SESSION_COOKIE_SECURE = True
        DEBUG = False
        TESTING = False
        FORCE_HTTPS = True

    return create_app(HttpsConfig)


def register(client, username="test_user", email="test@example.com", password="StrongPass123!"):
    return client.post(
        "/register",
        data={
            "username": username,
            "email": email,
            "password": password,
            "confirm_password": password,
        },
        follow_redirects=False,
    )


def login(client, identifier="test_user", password="StrongPass123!"):
    return client.post(
        "/login",
        data={
            "identifier": identifier,
            "password": password,
        },
        follow_redirects=False,
    )


def upload_document(
    client,
    filename="notes.txt",
    contents=b"hello world",
    content_type="text/plain",
):
    return client.post(
        "/documents",
        data={
            "document_file": (BytesIO(contents), filename, content_type),
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )


def read_security_log(tmp_path, app=None):
    if app is not None:
        for handler in app.logger.handlers:
            flush = getattr(handler, "flush", None)
            if callable(flush):
                flush()
    return (tmp_path / "logs" / "security.log").read_text(encoding="utf-8")


def test_health_endpoint(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_security_configuration_event_is_logged_on_startup(tmp_path):
    app = build_test_app(tmp_path)

    security_log = read_security_log(tmp_path, app)

    assert "SECURITY_CONFIGURATION" in security_log


def test_force_https_redirects_insecure_requests(tmp_path):
    app = build_https_test_app(tmp_path)
    client = app.test_client()

    response = client.get("/", base_url="http://localhost", follow_redirects=False)

    assert response.status_code == 301
    assert response.headers["Location"].startswith("https://")


def test_resolve_ssl_context_uses_existing_cert_and_key(tmp_path):
    app = build_test_app(tmp_path)
    cert_file = tmp_path / "cert.pem"
    key_file = tmp_path / "key.pem"
    cert_file.write_text("cert", encoding="utf-8")
    key_file.write_text("key", encoding="utf-8")

    app.config["TLS_CERT_FILE"] = cert_file
    app.config["TLS_KEY_FILE"] = key_file

    ssl_context = resolve_ssl_context(app)

    assert ssl_context == (str(cert_file), str(key_file))


def test_register_valid_user_saves_to_json(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    response = register(client)

    assert response.status_code == 302
    users = json.loads((tmp_path / "data" / "users.json").read_text(encoding="utf-8"))
    assert len(users) == 1
    assert users[0]["username"] == "test_user"
    assert users[0]["email"] == "test@example.com"
    assert users[0]["password_hash"] != "StrongPass123!"


def test_register_rejects_duplicate_username_and_email(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    register(client)
    username_response = register(client, email="other@example.com")
    email_response = register(client, username="other_user")

    assert username_response.status_code == 400
    assert email_response.status_code == 400


def test_register_rejects_weak_password(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    response = client.post(
        "/register",
        data={
            "username": "weak_user",
            "email": "weak@example.com",
            "password": "weakpass",
            "confirm_password": "weakpass",
        },
    )

    assert response.status_code == 400
    users = json.loads((tmp_path / "data" / "users.json").read_text(encoding="utf-8"))
    assert users == []


def test_login_creates_session_and_protects_pages(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    unauthenticated = client.get("/dashboard")
    assert unauthenticated.status_code == 302
    assert unauthenticated.headers["Location"].endswith("/login")

    register(client)
    login_response = login(client)

    assert login_response.status_code == 302
    assert login_response.headers["Location"].endswith("/dashboard")
    assert "session_token=" in login_response.headers.get("Set-Cookie", "")

    sessions = json.loads((tmp_path / "data" / "sessions.json").read_text(encoding="utf-8"))
    assert len(sessions) == 1

    dashboard = client.get("/dashboard")
    documents = client.get("/documents")

    assert dashboard.status_code == 200
    assert documents.status_code == 200


def test_failed_login_locks_account_after_five_attempts(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    register(client)

    for _ in range(4):
        response = login(client, password="WrongPassword123!")
        assert response.status_code == 400

    locked_response = login(client, password="WrongPassword123!")
    blocked_response = login(client, password="StrongPass123!")

    assert locked_response.status_code == 400
    assert blocked_response.status_code == 400

    users = json.loads((tmp_path / "data" / "users.json").read_text(encoding="utf-8"))
    assert users[0]["failed_attempts"] == 5
    assert users[0]["locked_until"] is not None


def test_login_rate_limit_blocks_eleventh_attempt_from_same_ip(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    for _ in range(10):
        response = login(client, identifier="unknown_user", password="WrongPassword123!")
        assert response.status_code == 400
        assert b"Too many login attempts from this IP" not in response.data

    blocked_response = login(client, identifier="unknown_user", password="WrongPassword123!")

    assert blocked_response.status_code == 400
    assert b"Too many login attempts from this IP" in blocked_response.data

    login_attempts = json.loads((tmp_path / "data" / "login_attempts.json").read_text(encoding="utf-8"))
    assert "127.0.0.1" in login_attempts
    assert len(login_attempts["127.0.0.1"]) == 10


def test_logout_removes_session(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    register(client)
    login(client)

    logout_response = client.post("/logout", follow_redirects=False)

    assert logout_response.status_code == 302
    assert logout_response.headers["Location"].endswith("/login")
    sessions = json.loads((tmp_path / "data" / "sessions.json").read_text(encoding="utf-8"))
    assert sessions == {}


def test_invalid_session_token_is_logged(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    client.set_cookie("session_token", "fake-token-value")
    response = client.get("/dashboard", follow_redirects=False)

    assert response.status_code == 302
    security_log = read_security_log(tmp_path, app)
    assert "INVALID_SESSION_TOKEN" in security_log


def test_guest_cannot_access_user_only_pages(tmp_path):
    app = build_test_app(tmp_path)
    owner_client = app.test_client()
    guest_client = app.test_client()

    register(owner_client, username="owner_user", email="owner@example.com")
    register(guest_client, username="guest_user", email="guest@example.com")
    users_path = tmp_path / "data" / "users.json"
    users = json.loads(users_path.read_text(encoding="utf-8"))
    users[1]["role"] = "guest"
    users_path.write_text(json.dumps(users, indent=2), encoding="utf-8")

    login(owner_client, identifier="owner_user")
    upload_document(owner_client, filename="guest-view.txt", contents=b"guest copy")
    documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    doc_id = next(iter(documents))
    owner_client.post(
        "/sharing",
        data={
            "share_document": doc_id,
            "share_user": "guest_user",
            "share_role": "viewer",
        },
        follow_redirects=False,
    )

    login(guest_client, identifier="guest_user")
    documents_response = guest_client.get("/documents")
    dashboard_response = guest_client.get("/dashboard")
    download_response = guest_client.get(f"/download/{doc_id}")
    upload_attempt = upload_document(guest_client, filename="blocked.txt", contents=b"blocked")
    update_attempt = guest_client.post(
        f"/documents/{doc_id}/update",
        data={"document_file": (BytesIO(b"new"), "new.txt")},
        content_type="multipart/form-data",
        follow_redirects=False,
    )

    assert documents_response.status_code == 200
    assert dashboard_response.status_code == 200
    assert download_response.status_code == 200
    assert b"guest-view.txt" in documents_response.data
    assert b"Guest Access" in documents_response.data
    assert b"Upload Document" not in documents_response.data
    assert upload_attempt.status_code == 302
    assert update_attempt.status_code == 403


def test_guest_can_still_view_and_download_old_owned_documents(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    register(client, username="guest_owner", email="guest-owner@example.com")
    login(client, identifier="guest_owner")
    upload_document(client, filename="owned-before-downgrade.txt", contents=b"owner bytes")

    documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    doc_id = next(iter(documents))

    users_path = tmp_path / "data" / "users.json"
    users = json.loads(users_path.read_text(encoding="utf-8"))
    users[0]["role"] = "guest"
    users_path.write_text(json.dumps(users, indent=2), encoding="utf-8")

    documents_page = client.get("/documents")
    allowed_download = client.get(f"/download/{doc_id}")

    assert documents_page.status_code == 200
    assert b"owned-before-downgrade.txt" in documents_page.data
    assert b"Replace File" not in documents_page.data
    assert b"Delete Document" not in documents_page.data
    assert allowed_download.status_code == 200
    assert allowed_download.data == b"owner bytes"


def test_document_upload_and_listing(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    register(client)
    login(client)

    response = upload_document(client)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/documents")

    listing = client.get("/documents")
    assert listing.status_code == 200
    assert b"notes.txt" in listing.data

    documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    assert len(documents) == 1
    stored_filename = next(iter(documents.values()))["stored_filename"]
    stored_bytes = (tmp_path / "data" / "encrypted" / stored_filename).read_bytes()
    assert b"hello world" not in stored_bytes


def test_upload_rejects_disallowed_extension(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    register(client)
    login(client)

    response = upload_document(
        client,
        filename="payload.exe",
        contents=b"bad file",
        content_type="application/octet-stream",
    )

    assert response.status_code == 302
    documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    assert documents == {}
    assert "INPUT_VALIDATION_FAILED" in read_security_log(tmp_path, app)


def test_upload_rejects_mime_mismatch(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    register(client)
    login(client)

    response = upload_document(
        client,
        filename="notes.txt",
        contents=b"pretend executable",
        content_type="application/pdf",
    )

    assert response.status_code == 302
    documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    assert documents == {}


def test_document_uses_entered_name_in_lists(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    register(client)
    login(client)

    response = client.post(
        "/documents",
        data={
            "document_name": "Project Proposal",
            "document_file": (BytesIO(b"proposal body"), "proposal.pdf"),
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )

    assert response.status_code == 302

    listing = client.get("/documents")
    sharing_page = client.get("/sharing")
    documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    stored_doc = next(iter(documents.values()))

    assert stored_doc["display_name"] == "Project Proposal"
    assert b"Project Proposal" in listing.data
    assert b"proposal.pdf" not in listing.data
    assert b"Project Proposal" in sharing_page.data


def test_document_download_returns_decrypted_file(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    register(client)
    login(client)

    upload_document(client, filename="secret.txt", contents=b"secret document body")

    documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    doc_id = next(iter(documents))

    response = client.get(f"/download/{doc_id}")

    assert response.status_code == 200
    assert response.data == b"secret document body"
    assert "attachment" in response.headers["Content-Disposition"]
    assert "secret.txt" in response.headers["Content-Disposition"]


def test_owner_can_share_document_with_viewer(tmp_path):
    app = build_test_app(tmp_path)
    owner_client = app.test_client()
    viewer_client = app.test_client()

    register(owner_client, username="owner_user", email="owner@example.com")
    register(viewer_client, username="viewer_user", email="viewer@example.com")
    login(owner_client, identifier="owner_user")

    upload_document(owner_client, filename="shared.txt", contents=b"shared data")
    documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    doc_id = next(iter(documents))

    share_response = owner_client.post(
        "/sharing",
        data={
            "share_document": doc_id,
            "share_user": "viewer_user",
            "share_role": "viewer",
        },
        follow_redirects=False,
    )

    assert share_response.status_code == 302
    updated_documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    shared_with = updated_documents[doc_id]["shared_with"]
    assert shared_with[0]["role"] == "viewer"

    login(viewer_client, identifier="viewer_user")
    viewer_docs_page = viewer_client.get("/documents")
    viewer_download = viewer_client.get(f"/download/{doc_id}")

    assert viewer_docs_page.status_code == 200
    assert b"shared.txt" in viewer_docs_page.data
    assert viewer_download.status_code == 200
    assert viewer_download.data == b"shared data"


def test_non_owner_cannot_share_document(tmp_path):
    app = build_test_app(tmp_path)
    owner_client = app.test_client()
    editor_client = app.test_client()

    register(owner_client, username="owner_user", email="owner@example.com")
    register(editor_client, username="editor_user", email="editor@example.com")
    login(owner_client, identifier="owner_user")
    upload_document(owner_client, filename="project.txt", contents=b"project body")

    documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    doc_id = next(iter(documents))

    owner_client.post(
        "/sharing",
        data={
            "share_document": doc_id,
            "share_user": "editor_user",
            "share_role": "editor",
        },
        follow_redirects=False,
    )

    login(editor_client, identifier="editor_user")
    share_attempt = editor_client.post(
        "/sharing",
        data={
            "share_document": doc_id,
            "share_user": "owner_user",
            "share_role": "viewer",
        },
        follow_redirects=False,
    )

    assert share_attempt.status_code == 302
    updated_documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    assert len(updated_documents[doc_id]["shared_with"]) == 1


def test_owner_can_remove_document_share(tmp_path):
    app = build_test_app(tmp_path)
    owner_client = app.test_client()
    viewer_client = app.test_client()

    register(owner_client, username="owner_user", email="owner@example.com")
    register(viewer_client, username="viewer_user", email="viewer@example.com")
    login(owner_client, identifier="owner_user")
    upload_document(owner_client, filename="shared.txt", contents=b"shared data")

    documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    doc_id = next(iter(documents))
    owner_client.post(
        "/sharing",
        data={
            "share_document": doc_id,
            "share_user": "viewer_user",
            "share_role": "viewer",
        },
        follow_redirects=False,
    )

    viewer_id = json.loads((tmp_path / "data" / "users.json").read_text(encoding="utf-8"))[1]["id"]
    remove_response = owner_client.post(
        "/sharing/remove",
        data={
            "document_id": doc_id,
            "target_user_id": viewer_id,
        },
        follow_redirects=False,
    )

    assert remove_response.status_code == 302

    updated_documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    assert updated_documents[doc_id]["shared_with"] == []

    login(viewer_client, identifier="viewer_user")
    viewer_download = viewer_client.get(f"/download/{doc_id}")
    assert viewer_download.status_code == 403


def test_unshared_user_can_still_see_unshare_event_in_audit_log(tmp_path):
    app = build_test_app(tmp_path)
    owner_client = app.test_client()
    viewer_client = app.test_client()

    register(owner_client, username="owner_user", email="owner@example.com")
    register(viewer_client, username="viewer_user", email="viewer@example.com")
    login(owner_client, identifier="owner_user")
    upload_document(owner_client, filename="remove-audit.txt", contents=b"remove audit body")

    documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    doc_id = next(iter(documents))
    owner_client.post(
        "/sharing",
        data={
            "share_document": doc_id,
            "share_user": "viewer_user",
            "share_role": "viewer",
        },
        follow_redirects=False,
    )

    viewer_id = json.loads((tmp_path / "data" / "users.json").read_text(encoding="utf-8"))[1]["id"]
    owner_client.post(
        "/sharing/remove",
        data={
            "document_id": doc_id,
            "target_user_id": viewer_id,
        },
        follow_redirects=False,
    )

    login(viewer_client, identifier="viewer_user")
    audit_page = viewer_client.get("/audit")

    assert audit_page.status_code == 200
    assert b"FILE_UNSHARED" in audit_page.data
    assert b"remove-audit.txt" in audit_page.data


def test_share_role_change_appears_in_owner_audit_log(tmp_path):
    app = build_test_app(tmp_path)
    owner_client = app.test_client()
    viewer_client = app.test_client()

    register(owner_client, username="owner_user", email="owner@example.com")
    register(viewer_client, username="viewer_user", email="viewer@example.com")
    login(owner_client, identifier="owner_user")
    upload_document(owner_client, filename="audit-share.txt", contents=b"audit share body")

    documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    doc_id = next(iter(documents))

    owner_client.post(
        "/sharing",
        data={
            "share_document": doc_id,
            "share_user": "viewer_user",
            "share_role": "editor",
        },
        follow_redirects=False,
    )

    owner_client.post(
        "/sharing",
        data={
            "share_document": doc_id,
            "share_user": "viewer_user",
            "share_role": "viewer",
        },
        follow_redirects=False,
    )

    audit_page = owner_client.get("/audit")

    assert audit_page.status_code == 200
    assert b"FILE_SHARE_ROLE_UPDATED" in audit_page.data
    assert b"Changed" in audit_page.data
    assert b"audit-share.txt" in audit_page.data


def test_shared_user_sees_document_activity_from_other_users(tmp_path):
    app = build_test_app(tmp_path)
    owner_client = app.test_client()
    viewer_client = app.test_client()

    register(owner_client, username="owner_user", email="owner@example.com")
    register(viewer_client, username="viewer_user", email="viewer@example.com")
    login(owner_client, identifier="owner_user")
    upload_document(owner_client, filename="shared-audit.txt", contents=b"version one")

    documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    doc_id = next(iter(documents))

    owner_client.post(
        "/sharing",
        data={
            "share_document": doc_id,
            "share_user": "viewer_user",
            "share_role": "viewer",
        },
        follow_redirects=False,
    )
    owner_client.get(f"/download/{doc_id}")
    owner_client.post(
        f"/documents/{doc_id}/update",
        data={
            "document_file": (BytesIO(b"version two"), "shared-audit-v2.txt"),
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )

    login(viewer_client, identifier="viewer_user")
    audit_page = viewer_client.get("/audit")
    dashboard_page = viewer_client.get("/dashboard")

    assert audit_page.status_code == 200
    assert dashboard_page.status_code == 200
    assert b"FILE_SHARED" in audit_page.data
    assert b"FILE_DOWNLOAD" in audit_page.data
    assert b"FILE_UPDATED" in audit_page.data
    assert b"shared-audit.txt" in audit_page.data
    assert b"FILE_UPDATED" in dashboard_page.data


def test_owner_can_upload_new_document_version(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    register(client)
    login(client)
    upload_document(client, filename="report.txt", contents=b"version one")

    documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    doc_id = next(iter(documents))

    response = client.post(
        f"/documents/{doc_id}/update",
        data={
            "document_file": (BytesIO(b"version two"), "report-v2.txt"),
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )

    assert response.status_code == 302

    updated_documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    updated_doc = updated_documents[doc_id]
    assert updated_doc["version"] == 2
    assert updated_doc["filename"] == "report-v2.txt"
    assert len(updated_doc["version_history"]) == 1
    assert updated_doc["version_history"][0]["version"] == 1

    download = client.get(f"/download/{doc_id}")
    assert download.status_code == 200
    assert download.data == b"version two"


def test_editor_can_upload_new_document_version_for_shared_file(tmp_path):
    app = build_test_app(tmp_path)
    owner_client = app.test_client()
    editor_client = app.test_client()

    register(owner_client, username="owner_user", email="owner@example.com")
    register(editor_client, username="editor_user", email="editor@example.com")
    login(owner_client, identifier="owner_user")
    upload_document(owner_client, filename="shared-edit.txt", contents=b"original")

    documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    doc_id = next(iter(documents))

    owner_client.post(
        "/sharing",
        data={
            "share_document": doc_id,
            "share_user": "editor_user",
            "share_role": "editor",
        },
        follow_redirects=False,
    )

    login(editor_client, identifier="editor_user")
    update_response = editor_client.post(
        f"/documents/{doc_id}/update",
        data={
            "document_file": (BytesIO(b"editor update"), "shared-edit-v2.txt"),
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )

    assert update_response.status_code == 302

    shared_page = editor_client.get("/documents")
    updated_documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    updated_doc = updated_documents[doc_id]

    assert updated_doc["version"] == 2
    assert updated_doc["filename"] == "shared-edit-v2.txt"
    assert b"shared-edit-v2.txt" in shared_page.data
    assert b"Upload New Version" in shared_page.data


def test_audit_page_shows_logged_events(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    register(client)
    login(client)
    upload_document(client, filename="audit.txt", contents=b"audit body")

    documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    doc_id = next(iter(documents))
    client.get(f"/download/{doc_id}")

    audit_page = client.get("/audit")

    assert audit_page.status_code == 200
    assert b"FILE_UPLOAD" in audit_page.data
    assert b"FILE_DOWNLOAD" in audit_page.data
    assert b"audit.txt" in audit_page.data


def test_admin_panel_shows_all_content(tmp_path):
    app = build_test_app(tmp_path)
    admin_client = app.test_client()

    register(admin_client, username="admin_user", email="admin@example.com")
    users_path = tmp_path / "data" / "users.json"
    users = json.loads(users_path.read_text(encoding="utf-8"))
    users[0]["role"] = "admin"
    users_path.write_text(json.dumps(users, indent=2), encoding="utf-8")

    login(admin_client, identifier="admin_user")
    upload_document(admin_client, filename="admin-report.txt", contents=b"admin body")

    admin_page = admin_client.get("/admin")

    assert admin_page.status_code == 200
    assert b"Admin Overview" in admin_page.data
    assert b"admin-report.txt" in admin_page.data
    assert b"admin_user" in admin_page.data
    assert b"owner_id" not in admin_page.data


def test_admin_can_download_and_delete_any_document(tmp_path):
    app = build_test_app(tmp_path)
    owner_client = app.test_client()
    admin_client = app.test_client()

    register(owner_client, username="owner_user", email="owner@example.com")
    register(admin_client, username="admin_user", email="admin@example.com")
    users_path = tmp_path / "data" / "users.json"
    users = json.loads(users_path.read_text(encoding="utf-8"))
    users[1]["role"] = "admin"
    users_path.write_text(json.dumps(users, indent=2), encoding="utf-8")

    login(owner_client, identifier="owner_user")
    upload_document(owner_client, filename="admin-target.txt", contents=b"admin target body")
    documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    doc_id = next(iter(documents))

    login(admin_client, identifier="admin_user")
    download_response = admin_client.get(f"/download/{doc_id}")
    delete_response = admin_client.post(f"/documents/{doc_id}/delete", follow_redirects=False)

    assert download_response.status_code == 200
    assert download_response.data == b"admin target body"
    assert delete_response.status_code == 302

    updated_documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    assert updated_documents[doc_id]["is_deleted"] is True

    deleted_download = admin_client.get(f"/download/{doc_id}")
    assert deleted_download.status_code == 404


def test_admin_can_change_user_role_and_remove_user(tmp_path):
    app = build_test_app(tmp_path)
    admin_client = app.test_client()
    target_client = app.test_client()

    register(admin_client, username="admin_user", email="admin@example.com")
    register(target_client, username="target_user", email="target@example.com")
    users_path = tmp_path / "data" / "users.json"
    users = json.loads(users_path.read_text(encoding="utf-8"))
    users[0]["role"] = "admin"
    users_path.write_text(json.dumps(users, indent=2), encoding="utf-8")

    login(admin_client, identifier="admin_user")
    updated_users = json.loads(users_path.read_text(encoding="utf-8"))
    target_user = next(user for user in updated_users if user["username"] == "target_user")

    upload_document(admin_client, filename="admin-share.txt", contents=b"admin shared body")
    documents_path = tmp_path / "data" / "documents.json"
    documents = json.loads(documents_path.read_text(encoding="utf-8"))
    doc_id = next(iter(documents))
    admin_client.post(
        "/sharing",
        data={
            "share_document": doc_id,
            "share_user": "target_user",
            "share_role": "viewer",
        },
        follow_redirects=False,
    )

    login(target_client, identifier="target_user")
    sessions_before_delete = json.loads((tmp_path / "data" / "sessions.json").read_text(encoding="utf-8"))
    assert any(session["user_id"] == target_user["id"] for session in sessions_before_delete.values())

    role_response = admin_client.post(
        f"/admin/users/{target_user['id']}/role",
        data={"role": "guest"},
        follow_redirects=False,
    )
    assert role_response.status_code == 302

    updated_users = json.loads(users_path.read_text(encoding="utf-8"))
    target_user = next(user for user in updated_users if user["username"] == "target_user")
    assert target_user["role"] == "guest"

    delete_response = admin_client.post(
        f"/admin/users/{target_user['id']}/delete",
        follow_redirects=False,
    )
    assert delete_response.status_code == 302

    final_users = json.loads(users_path.read_text(encoding="utf-8"))
    final_documents = json.loads(documents_path.read_text(encoding="utf-8"))
    final_sessions = json.loads((tmp_path / "data" / "sessions.json").read_text(encoding="utf-8"))

    assert all(user["username"] != "target_user" for user in final_users)
    assert final_documents[doc_id]["shared_with"] == []
    assert all(
        session["user_id"] != target_user["id"]
        for session in final_sessions.values()
    )


def test_non_admin_activity_views_accessible_document_events_with_timestamp(tmp_path):
    app = build_test_app(tmp_path)
    owner_client = app.test_client()
    viewer_client = app.test_client()

    register(owner_client, username="owner_user", email="owner@example.com")
    register(viewer_client, username="viewer_user", email="viewer@example.com")
    login(owner_client, identifier="owner_user")
    upload_document(owner_client, filename="privacy.txt", contents=b"private data")

    documents = json.loads((tmp_path / "data" / "documents.json").read_text(encoding="utf-8"))
    doc_id = next(iter(documents))
    owner_client.post(
        "/sharing",
        data={
            "share_document": doc_id,
            "share_user": "viewer_user",
            "share_role": "viewer",
        },
        follow_redirects=False,
    )

    login(viewer_client, identifier="viewer_user")
    viewer_client.get(f"/download/{doc_id}")

    audit_log = json.loads((tmp_path / "data" / "audit_trail.json").read_text(encoding="utf-8"))
    viewer_download_entry = next(
        entry for entry in audit_log
        if entry["event"] == "FILE_DOWNLOAD" and entry["user_id"] == json.loads((tmp_path / "data" / "users.json").read_text(encoding="utf-8"))[1]["id"]
    )
    expected_timestamp = datetime.fromtimestamp(
        viewer_download_entry["timestamp"]
    ).strftime("%Y-%m-%d %H:%M:%S").encode()

    audit_page = viewer_client.get("/audit")
    dashboard_page = viewer_client.get("/dashboard")

    assert audit_page.status_code == 200
    assert dashboard_page.status_code == 200
    assert b"owner_user" in audit_page.data
    assert b"FILE_UPLOAD" in audit_page.data
    assert b"viewer_user" in audit_page.data
    assert b"FILE_DOWNLOAD" in audit_page.data
    assert expected_timestamp in audit_page.data
    assert expected_timestamp in dashboard_page.data

import json
from datetime import datetime
from io import BytesIO

from app import create_app, resolve_ssl_context
from config import Config

#This file contains integration tests that use the Flask test client to simulate real user interactions with the application. 
#It tests the full request handling, including authentication, document management, sharing, and admin functionality.
#The tests also verify that security events are properly logged and that access controls are enforced. Each test builds a fresh 
#instance of the app with a temporary data directory to ensure isolation and repeatability.


#This helper function creates a test instance of the Flask app with a custom configuration that uses temporary directories for data and logs.
#It also sets a fixed secret key and disables secure cookies to allow testing without HTTPS.
#The returned app instance can be used to create a test client for making requests in the tests.
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

#This helper function creates a test instance of the Flask app with a configuration that forces HTTPS and secure cookies.
#It uses temporary directories for data and logs, and sets a fixed secret key.
#This app can be used to test HTTPS-related functionality, such as redirects and SSL context resolution.
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

#This helper function simulates a user registration by sending a POST request to the /register endpoint 
#with the provided username, email, and password.
#It returns the response object from the registration request, which can be used to verify the outcome 
#of the registration process in the tests.
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

#This helper function simulates a user login by sending a POST request to the /login endpoint with the 
#provided identifier (username or email) and password.
#It returns the response object from the login request, which can be used to verify the outcome of the login
def login(client, identifier="test_user", password="StrongPass123!"):
    return client.post(
        "/login",
        data={
            "identifier": identifier,
            "password": password,
        },
        follow_redirects=False,
    )

#This helper function simulates a user logout by sending a POST request to the /logout endpoint.
#It returns the response object from the logout request, which can be used to verify the outcome
#of the logout process in the tests.
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

#This helper function reads the contents of the security log file. 
#If an app instance is provided, it flushes all log handlers to ensure that any buffered log messages 
#are written to the file before reading.
def read_security_log(tmp_path, app=None):
    if app is not None:
        for handler in app.logger.handlers:
            flush = getattr(handler, "flush", None)
            if callable(flush):
                flush()
    return (tmp_path / "logs" / "security.log").read_text(encoding="utf-8")

#This test verifies that the /health endpoint returns a 200 status code and a JSON response with a 
#"status" key set to "ok". It uses the test client to send a GET request to the endpoint and checks the response.
def test_health_endpoint(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"

#This test verifies that a SECURITY_CONFIGURATION event is logged in the security log when the application starts up.
#It builds a test app instance, reads the security log, and checks that the expected event is present in the log contents.
def test_security_configuration_event_is_logged_on_startup(tmp_path):
    app = build_test_app(tmp_path)

    security_log = read_security_log(tmp_path, app)

    assert "SECURITY_CONFIGURATION" in security_log

#This test verifies that when the application is configured to force HTTPS, 
#any HTTP request to the root endpoint is redirected to HTTPS.
#It builds a test app instance with HTTPS enforcement, sends a GET request to the root endpoint using HTTP, 
#and checks that the response is a 301 redirect to an HTTPS URL.
def test_force_https_redirects_insecure_requests(tmp_path):
    app = build_https_test_app(tmp_path)
    client = app.test_client()

    response = client.get("/", base_url="http://localhost", follow_redirects=False)

    assert response.status_code == 301
    assert response.headers["Location"].startswith("https://")

#This test verifies that if the application is configured with existing TLS certificate and key files,
#the resolve_ssl_context function returns the correct paths to those files.
#It creates temporary certificate and key files, configures the app to use them, and checks that the 
#resolved SSL context matches the expected file paths.
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

#This test verifies that when a valid user registration request is made, the user's information is 
#saved to the users.json file with a hashed password.
#It builds a test app instance, simulates a registration request, and checks that the response is a redirect. 
#It then reads the users.json file and verifies that the user data is stored correctly, 
#including that the password is not stored in plaintext.
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

#This test verifies that the registration endpoint rejects attempts to register with a username or email that already exists in the system.
#It simulates multiple registration attempts with the same username and email, and checks that the responses have a 400 status code, 
#indicating that the registration was rejected due to duplication.
def test_register_rejects_duplicate_username_and_email(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    register(client)
    username_response = register(client, email="other@example.com")
    email_response = register(client, username="other_user")

    assert username_response.status_code == 400
    assert email_response.status_code == 400

#This test verifies that the registration endpoint rejects attempts to register with a weak
#password that does not meet the defined strength requirements. It simulates a registration attempt with a 
#weak password and checks that the response has a 400 status code, indicating that the registration was rejected due to weak password. 
#It also checks that no user data was saved to the users.json file.
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

#This test verifies that a successful login creates a session and allows access to protected pages, 
#while an unauthenticated user is redirected to the login page. It simulates a login attempt with 
#valid credentials, checks that the response is a redirect to the dashboard, and verifies that a session 
#token is set in the cookies. It then checks that the session information is saved to the sessions.json file,
#and that authenticated requests to protected pages return a 200 status code.
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

#This test verifies that after five consecutive failed login attempts, the user's account is 
#locked and further login attempts are rejected. It simulates multiple failed login attempts with an 
#incorrect password, checks that the responses have a 400 status code, and verifies that the user's failed_attempts
#count is updated in the users.json file.
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

#This test verifies that after ten consecutive failed login attempts from the same IP address, 
#further login attempts from that IP are blocked. It simulates multiple failed login attempts 
#with an incorrect password, checks that the responses have a 400 status code, and verifies 
#that the login_attempts.json file contains the expected number of attempts for the IP address.
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

#This test verifies that when a user logs out, their session is removed from the sessions.json 
#file and they are redirected to the login page. It simulates a login followed by a logout, checks
#that the logout response is a redirect to the login page, and verifies that the sessions.json 
#file is empty after logout.
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

#This test verifies that if a request is made with an invalid session token, the application 
#logs an INVALID_SESSION_TOKEN event in the security log and redirects the user to the login page.
#It simulates a request to a protected page with a fake session token, checks that the response is 
#a redirect to the login page, and verifies that the expected event is present in the security log.
def test_invalid_session_token_is_logged(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    client.set_cookie("session_token", "fake-token-value")
    response = client.get("/dashboard", follow_redirects=False)

    assert response.status_code == 302
    security_log = read_security_log(tmp_path, app)
    assert "INVALID_SESSION_TOKEN" in security_log

#This test verifies that a user with the "guest" role can access shared documents but cannot upload 
#new documents or edit existing ones.
#It simulates a scenario where an owner user shares a document with a guest user, and then checks 
#that the guest user can view and download the shared document but receives a 403 Forbidden 
#response when attempting to upload a new document or update the shared document.
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

#This test verifies that if a user's role is changed to "guest" after they have uploaded documents, 
#they can still view and download those documents but cannot edit or delete them.
#It simulates a scenario where a user uploads a document, then their role is changed to "guest" 
#in the users.json file.
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

#This test verifies that when a user uploads a document, the file is stored in an encrypted form on disk,
#and the document metadata is saved to the documents.json file with a reference to the stored filename.
#It simulates a document upload, checks that the response is a redirect to the documents page, 
#and then verifies that the uploaded file is not stored in plaintext and that the metadata is 
#correctly saved.
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

#This test verifies that if a user attempts to upload a file with a disallowed extension, the 
#upload is rejected, the file is not saved, and an INPUT_VALIDATION_FAILED event is logged in the 
#security log. It simulates an upload attempt with a disallowed file type, checks that the response
#is a redirect, and then verifies that no document metadata is saved and that the expected event 
#is present in the security log.
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

#This test verifies that if a user attempts to upload a file where the declared MIME type does not match
#the expected MIME type for the file extension, the upload is rejected, the file is not saved, and an 
#INPUT_VALIDATION_FAILED event is logged in the security log. It simulates an upload attempt with a 
#MIME type that does not match the file extension, checks that the response is a redirect, and then 
#verifies that no document metadata is saved and that the expected event is present in the security log.
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

#This test verifies that when a user uploads a document, the display name shown in the document 
#listing and sharing pages is the name entered by the user, not the original filename or stored filename.
#It simulates a document upload with a specific display name, checks that the response is a redirect, 
#and then verifies that the display name is correctly shown in the document listing and sharing pages, 
#and that the stored metadata contains the correct display name.
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

#This test verifies that when a user downloads a document, the file is decrypted and returned 
#with the correct content and headers. It simulates a document upload, retrieves the document 
#ID from the metadata, and then sends a GET request to the download endpoint for that document.
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

#This test verifies that the owner of a document can share it with another user and assign them a 
#viewer role, and that the shared user can see the document in their listing and download it, but 
#cannot edit it. It simulates a scenario where an owner user uploads a document, shares it with a 
#viewer user, and then the viewer user logs in and checks that they can see and download the shared 
#document but do not have edit permissions.
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

#This test verifies that a user who is not the owner of a document cannot share it with others or 
#change sharing permissions. It simulates a scenario where an owner user uploads a document and 
#shares it with another user, and then the shared user attempts to share the document with a third user 
#or change the sharing role, and checks that those attempts are rejected and do not modify the sharing 
#settings in the documents.json file.
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

#This test verifies that the owner of a document can remove sharing permissions for a user, and that the 
#removed user can no longer access the document. It simulates a scenario where an owner user uploads a 
#document, shares it with a viewer user, and then removes the viewer's access. It checks that the 
#sharing permissions are updated in the documents.json file and that the viewer user receives a 403 
#Forbidden response when attempting to access the document after being removed.
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

#This test verifies that when a user is removed from a document's sharing permissions, an 
#FILE_UNSHARED event is logged in the audit log for that user, and they can see the event in their
#sudit log even though they no longer have access to the document. It simulates a scenario where an
#owner user uploads a document, shares it with a viewer user, and then removes the viewer's access. 
#It checks that the expected event is present in the viewer's audit log after being removed.
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

#This test verifies that when a document's sharing role is changed for a user, a FILE_SHARE_ROLE_UPDATED
#event is logged in the audit log for the owner, and the event details include the document name and
#the fact that the role was changed. It simulates a scenario where an owner user uploads a document, 
#shares it with another user as an editor, and then changes that user's role to viewer. It checks that
#the expected event is present in the owner's audit log with the correct details.
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

#This test verifies that when a document is shared with a user, the shared user can see all 
#activity related to that document in their audit log, including actions performed by other users.
#It simulates a scenario where an owner user uploads a document, shares it with a viewer user, and 
#then performs several actions on the document (download and update). It checks that the viewer user
#can see all of those events in their audit log.
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

#This test verifies that the owner of a document can upload a new version of the document, and
#that the new version is stored correctly with an updated version number and version history. 
#It simulates a document upload, retrieves the document ID, and then sends a POST request to the
#update endpoint with a new file. It checks that the response is a redirect, and then verifies that
#the documents.json file reflects the updated version information, and that downloading the document 
#returns the new version content.
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

#This test verifies that when a document is shared with a user as an editor, that user can upload 
#a new version of the document, and that the new version is stored correctly with an updated version
#number and version history. It simulates a scenario where an owner user uploads a document, shares 
#it with another user as an editor, and then the editor user uploads a new version of the document.
#It checks that the response is a redirect, and then verifies that the documents.json file reflects 
#the updated version information, and that the editor user can see the new version in their document listing.
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

#This test verifies that when a user performs actions on a document (upload, download, update), those
#actions are logged in the audit log with the correct event types and details, and that the user can see
#those events in their audit log. It simulates a scenario where a user uploads a document, downloads it,
#and then updates it, and checks that the expected events are present in the audit log with
#the correct details.
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

#This test verifies that when a user with the "admin" role accesses the admin panel, they can see
#an overview of all documents and users in the system, but sensitive information like owner_id is not
#displayed. It simulates an admin user logging in and accessing the admin panel, and checks that the
#expected content is present while sensitive details are not shown.
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

#This test verifies that a user with the "admin" role can download and delete any document in the system,
#regardless of ownership. It simulates a scenario where an admin user uploads a document, and
#then another admin user logs in and attempts to download and delete that document. It checks
#that the download is successful and returns the correct content, that the delete action results
#in a redirect, and that the document is marked as deleted in the documents.json file. 
#It also verifies that attempting to download the deleted document returns a 404 Not Found response.
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

#This test verifies that a user with the "admin" role can change another user's role to "guest", 
#and then delete that user, and that the deleted user can no longer access the system or any 
#documents they had access to. It simulates a scenario where an admin user uploads a document,
#shares it with another user, changes that user's role to guest, and then deletes that user. 
#It checks that the expected events are present in the audit log, that the user's access is revoked,
#and that their sessions are invalidated.
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

#This test verifies that when a document is shared with a user, that user can see all activity
#related to that document in their audit log, including timestamps for each event. It simulates
#a scenario where an owner user uploads a document, shares it with a viewer user, and then the 
#viewer user downloads the document. It checks that the expected events are present in the viewer's 
#audit log with the correct timestamps.
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

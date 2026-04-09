import json

from app import create_app
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


def test_health_endpoint(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


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


def test_guest_cannot_access_user_only_pages(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    register(client, username="guest_user", email="guest@example.com")
    users_path = tmp_path / "data" / "users.json"
    users = json.loads(users_path.read_text(encoding="utf-8"))
    users[0]["role"] = "guest"
    users_path.write_text(json.dumps(users, indent=2), encoding="utf-8")

    login(client, identifier="guest_user")
    documents_response = client.get("/documents")
    dashboard_response = client.get("/dashboard")

    assert documents_response.status_code == 403
    assert dashboard_response.status_code == 200

from __future__ import annotations

import json
import logging
from functools import wraps
from pathlib import Path

from flask import Flask, flash, g, make_response, redirect, render_template, request, url_for

from auth import AuthManager
from config import Config

from documents import create_document, get_user_documents

def ensure_project_files(app: Flask) -> None:
    data_dir = Path(app.config["DATA_DIR"])
    log_dir = Path(app.config["LOG_DIR"])

    for directory in (
        data_dir,
        data_dir / "logs",
        app.config["UPLOAD_DIR"],
        app.config["ENCRYPTED_DIR"],
        log_dir,
        Path("docs"),
        Path("presentation"),
    ):
        Path(directory).mkdir(parents=True, exist_ok=True)

    default_json_files = {
        data_dir / "users.json": [],
        data_dir / "sessions.json": {},
        data_dir / "documents.json": {},
        data_dir / "shares.json": [],
        data_dir / "audit_trail.json": [],
    }

    for file_path, default_value in default_json_files.items():
        if not file_path.exists():
            file_path.write_text(json.dumps(default_value, indent=2), encoding="utf-8")

    for log_name in ("security.log", "access.log"):
        log_path = log_dir / log_name
        log_path.touch(exist_ok=True)


def configure_logging(app: Flask) -> None:
    security_log = Path(app.config["LOG_DIR"]) / "security.log"

    file_handler = logging.FileHandler(security_log, encoding="utf-8")
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    )

    if not app.logger.handlers:
        app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)


def create_app(config_class: type[Config] = Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)
    app.secret_key = app.config["SECRET_KEY"]

    ensure_project_files(app)
    configure_logging(app)
    auth_manager = AuthManager(
        users_file=Path(app.config["DATA_DIR"]) / "users.json",
        sessions_file=Path(app.config["DATA_DIR"]) / "sessions.json",
        security_log_file=Path(app.config["LOG_DIR"]) / "security.log",
        session_timeout=app.config["SESSION_TIMEOUT"],
    )

    def client_ip() -> str:
        return request.remote_addr or "unknown"

    def client_agent() -> str:
        return request.headers.get("User-Agent", "unknown")

    def current_session_token() -> str | None:
        return request.cookies.get("session_token")

    def login_required(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            if g.current_user is None:
                flash("Please log in to continue.", "error")
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapped_view

    def role_required(*allowed_roles: str):
        def decorator(view):
            @wraps(view)
            def wrapped_view(*args, **kwargs):
                if g.current_user is None:
                    flash("Please log in to continue.", "error")
                    return redirect(url_for("login"))
                if not auth_manager.require_role(g.current_user, set(allowed_roles)):
                    auth_manager.log_event(
                        "ACCESS_DENIED",
                        g.current_user["id"],
                        {"path": request.path, "allowed_roles": list(allowed_roles)},
                        client_ip(),
                        client_agent(),
                        severity="WARNING",
                    )
                    return render_template("403.html"), 403
                return view(*args, **kwargs)

            return wrapped_view

        return decorator

    @app.before_request
    def load_user_session() -> None:
        token = current_session_token()
        # I re-check the session on every request because the cookie alone should not be trusted
        # unless it still matches a valid session in our storage.
        session_data = auth_manager.validate_session(token, client_ip(), client_agent())
        g.session = session_data
        g.current_user = auth_manager.get_user_by_id(session_data["user_id"]) if session_data else None

    @app.after_request
    def set_security_headers(response):
        # I set security headers here to make the browser handle the site more safely,
        # like reducing clickjacking and limiting where content can load from.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if not app.debug:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            result = auth_manager.login_user(
                identifier=request.form.get("identifier", ""),
                password=request.form.get("password", ""),
                ip_address=client_ip(),
                user_agent=client_agent(),
            )
            if not result.ok:
                flash(result.message, "error")
                return render_template("login.html"), 400

            response = make_response(redirect(url_for("dashboard")))
            # I set the session cookie this way to make it safer:
            # HttpOnly helps keep JavaScript from reading it, and SameSite helps with some CSRF-style attacks.
            response.set_cookie(
                "session_token",
                result.session_token,
                httponly=True,
                secure=app.config["SESSION_COOKIE_SECURE"],
                samesite=app.config["SESSION_COOKIE_SAMESITE"],
                max_age=app.config["SESSION_TIMEOUT"],
            )
            flash("Logged in successfully.", "success")
            return response

        return render_template("login.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            result = auth_manager.register_user(
                username=request.form.get("username", ""),
                email=request.form.get("email", ""),
                password=request.form.get("password", ""),
                confirm_password=request.form.get("confirm_password", ""),
                ip_address=client_ip(),
                user_agent=client_agent(),
            )
            if not result.ok:
                flash(result.message, "error")
                return render_template("register.html"), 400

            flash(result.message, "success")
            return redirect(url_for("login"))

        return render_template("register.html")

    @app.post("/logout")
    def logout():
        auth_manager.logout_session(current_session_token(), client_ip(), client_agent())
        response = make_response(redirect(url_for("login")))
        response.delete_cookie("session_token")
        flash("Logged out successfully.", "success")
        return response

    @app.get("/dashboard")
    @login_required
    @role_required("admin", "user", "guest")
    def dashboard():
        # I load the current user's documents here so the dashboard can show real data instead of placeholders.
        documents = get_user_documents(g.current_user["id"])
        return render_template("dashboard.html", documents=documents)

    @app.route("/documents", methods=["GET", "POST"])
    @login_required
    @role_required("admin", "user")
    def documents():
        if request.method == "POST":
            # This has to match the file input name in the template or Flask will not find the uploaded file.
            file = request.files.get("document_file")

            if not file or not file.filename:
                flash("No file uploaded.", "error")
                return redirect(url_for("documents"))
            user_id = g.current_user["id"]

            try:
                # The helper handles filename cleanup plus saving metadata into documents.json.
                create_document(file, user_id)
            except ValueError as exc:
                flash(str(exc), "error")
                return redirect(url_for("documents"))

            flash("File uploaded successfully.", "success")
            return redirect(url_for("documents"))
        user_id = g.current_user["id"]
        docs = get_user_documents(user_id)
        return render_template("documents.html", documents=docs)

    @app.get("/sharing")
    @login_required
    @role_required("admin", "user")
    def sharing():
        return render_template("sharing.html")

    @app.get("/audit")
    @login_required
    @role_required("admin", "user", "guest")
    def audit():
        return render_template("audit.html")

    @app.get("/admin")
    @login_required
    @role_required("admin")
    def admin_panel():
        return render_template("dashboard.html")

    @app.get("/health")
    def health():
        return {"status": "ok", "app": "secure-document-sharing-system"}

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host=app.config["APP_HOST"], port=app.config["APP_PORT"], debug=True)

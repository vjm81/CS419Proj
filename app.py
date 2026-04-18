from __future__ import annotations

from datetime import datetime
from io import BytesIO
import json
import logging
from functools import wraps
from pathlib import Path

from flask import Flask, flash, g, make_response, redirect, render_template, request, send_file, url_for

from auth import AuthManager
from config import Config
from audit import get_recent_audit, log_event

from documents import (
    can_edit_document,
    can_user_access,
    create_document,
    get_documents_shared_with_user,
    get_decrypted_file_bytes,
    get_document,
    get_owned_documents,
    get_user_documents,
    get_user_document_role,
    load_documents,
    remove_share,
    share_document,
    update_document,
)

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

    def get_all_users():
        return auth_manager.load_users()

    def find_user_by_username(username: str):
        return auth_manager.find_user_by_username(username)

    def summarize_documents_for_user(user_id: str):
        owned = get_owned_documents(user_id)
        shared = get_documents_shared_with_user(user_id)
        editable_shared = [doc for doc in shared if can_edit_document(doc, user_id)]
        return owned, shared, editable_shared

    def enrich_audit_entries(entries):
        users_by_id = {user["id"]: user["username"] for user in get_all_users()}
        return [
            {
                **entry,
                "username": users_by_id.get(entry.get("user_id"), entry.get("user_id") or "unknown"),
                "formatted_timestamp": datetime.fromtimestamp(
                    entry.get("timestamp", 0)
                ).strftime("%Y-%m-%d %H:%M:%S"),
            }
            for entry in entries
        ]

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

    @app.get("/download/<doc_id>")
    @login_required
    def download(doc_id):
        doc = get_document(doc_id)

        if not doc:
            return "Document not found", 404

        if not can_user_access(doc, g.current_user["id"]):
            log_event("ACCESS_DENIED", g.current_user["id"], doc_id) #{"doc_id": doc_id}, client_ip(), client_agent(), severity="WARNING"
            return "Forbidden", 403
        
        log_event("FILE_DOWNLOAD", g.current_user["id"], doc_id, doc["filename"])

        return send_file(
            BytesIO(get_decrypted_file_bytes(doc)),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=doc["filename"],
        )

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
        user_id = g.current_user["id"]
        owned_docs, shared_docs, editable_shared_docs = summarize_documents_for_user(user_id)
        recent_events = enrich_audit_entries(
            [
                entry
                for entry in get_recent_audit()
                if g.current_user["role"] == "admin" or entry.get("user_id") == user_id
            ][:5]
        )
        return render_template(
            "dashboard.html",
            documents=owned_docs,
            shared_documents=shared_docs,
            editable_shared_documents=editable_shared_docs,
            recent_events=recent_events,
            get_user_document_role=get_user_document_role,
        )

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
        docs, shared_docs, editable_shared_docs = summarize_documents_for_user(user_id)
        return render_template(
            "documents.html",
            documents=docs,
            shared_documents=shared_docs,
            editable_shared_documents=editable_shared_docs,
            get_user_document_role=get_user_document_role,
        )

    @app.post("/documents/<doc_id>/update")
    @login_required
    @role_required("admin", "user")
    def update_existing_document(doc_id):
        file = request.files.get("document_file")
        if not file or not file.filename:
            flash("Please choose a file to upload as the new version.", "error")
            return redirect(url_for("documents"))

        try:
            updated_doc = update_document(doc_id, g.current_user["id"], file)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("documents"))
        except PermissionError as exc:
            flash(str(exc), "error")
            return redirect(url_for("documents"))

        flash(
            f"Uploaded version {updated_doc['version']} for {updated_doc['filename']}.",
            "success",
        )
        return redirect(url_for("documents"))

    @app.route("/sharing", methods=["GET", "POST"])
    @login_required
    @role_required("admin", "user")
    def sharing():
        if request.method == "POST":
            doc_id = request.form.get("share_document", "")
            target_username = request.form.get("share_user", "").strip()
            role = request.form.get("share_role", "")

            if not doc_id or not target_username or not role:
                flash("Please fill out all sharing fields.", "error")
                return redirect(url_for("sharing"))

            target_user = find_user_by_username(target_username)
            if not target_user:
                flash("Target user not found.", "error")
                return redirect(url_for("sharing"))

            try:
                share_document(doc_id, g.current_user["id"], target_user["id"], role)
            except ValueError as exc:
                flash(str(exc), "error")
                return redirect(url_for("sharing"))
            except PermissionError as exc:
                flash(str(exc), "error")
                return redirect(url_for("sharing"))

            flash(f"Shared document with {target_username} as {role}.", "success")
            return redirect(url_for("sharing"))

        owned_documents = get_owned_documents(g.current_user["id"])
        current_shares = []
        for doc in owned_documents:
            for entry in doc["shared_with"]:
                shared_user = auth_manager.get_user_by_id(entry["user_id"])
                current_shares.append(
                    {
                        "document_id": doc["id"],
                        "filename": doc["filename"],
                        "target_username": shared_user["username"] if shared_user else entry["user_id"],
                        "target_user_id": entry["user_id"],
                        "role": entry["role"],
                        "version": doc["version"],
                    }
                )
        return render_template(
            "sharing.html",
            owned_documents=owned_documents,
            current_shares=current_shares,
            all_users=[user for user in get_all_users() if user["id"] != g.current_user["id"]],
        )

    @app.post("/sharing/remove")
    @login_required
    @role_required("admin", "user")
    def remove_document_share():
        doc_id = request.form.get("document_id", "")
        target_user_id = request.form.get("target_user_id", "")
        try:
            remove_share(doc_id, g.current_user["id"], target_user_id)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("sharing"))
        except PermissionError as exc:
            flash(str(exc), "error")
            return redirect(url_for("sharing"))

        flash("Removed document access successfully.", "success")
        return redirect(url_for("sharing"))

    @app.get("/audit")
    @login_required
    @role_required("admin", "user", "guest")
    def audit():
        audit_entries = enrich_audit_entries(get_recent_audit())
        user_id = g.current_user["id"]
        if g.current_user["role"] != "admin":
            audit_entries = [
                entry for entry in audit_entries
                if entry.get("user_id") == user_id
            ]

        audit_summary = {
            "total_events": len(audit_entries),
            "downloads": sum(1 for entry in audit_entries if entry["event"] == "FILE_DOWNLOAD"),
            "shares": sum(1 for entry in audit_entries if entry["event"] in {"FILE_SHARED", "FILE_UNSHARED"}),
            "updates": sum(1 for entry in audit_entries if entry["event"] == "FILE_UPDATED"),
        }
        return render_template("audit.html", audit_entries=audit_entries, audit_summary=audit_summary)

    @app.get("/admin")
    @login_required
    @role_required("admin")
    def admin_panel():
        all_users = get_all_users()
        all_documents = list(load_documents().values())
        audit_entries = enrich_audit_entries(get_recent_audit(limit=10))
        admin_summary = {
            "total_users": len(all_users),
            "total_documents": len(all_documents),
            "active_shares": sum(len(doc.get("shared_with", [])) for doc in all_documents),
        }
        return render_template(
            "admin.html",
            all_users=all_users,
            all_documents=all_documents,
            audit_entries=audit_entries,
            admin_summary=admin_summary,
            get_user_document_role=get_user_document_role,
        )

    @app.get("/health")
    def health():
        return {"status": "ok", "app": "secure-document-sharing-system"}

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host=app.config["APP_HOST"], port=app.config["APP_PORT"], debug=True)

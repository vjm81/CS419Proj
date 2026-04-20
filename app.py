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
    delete_document,
    get_documents_shared_with_user,
    get_decrypted_file_bytes,
    get_document,
    get_all_documents,
    get_owned_documents,
    get_user_documents,
    get_user_document_role,
    load_documents,
    remove_share,
    remove_user_from_all_shares,
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
        data_dir / "login_attempts.json": {},
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

    existing_file_handler = any(
        isinstance(handler, logging.FileHandler)
        and Path(getattr(handler, "baseFilename", "")) == security_log
        for handler in app.logger.handlers
    )
    if not existing_file_handler:
        app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)


def resolve_ssl_context(app: Flask):
    cert_file = Path(app.config["TLS_CERT_FILE"])
    key_file = Path(app.config["TLS_KEY_FILE"])
    if cert_file.exists() and key_file.exists():
        return (str(cert_file), str(key_file))
    return None


def create_app(config_class: type[Config] = Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)
    app.secret_key = app.config["SECRET_KEY"]

    ensure_project_files(app)
    configure_logging(app)
    auth_manager = AuthManager(
        users_file=Path(app.config["DATA_DIR"]) / "users.json",
        sessions_file=Path(app.config["DATA_DIR"]) / "sessions.json",
        login_attempts_file=Path(app.config["DATA_DIR"]) / "login_attempts.json",
        security_log_file=Path(app.config["LOG_DIR"]) / "security.log",
        session_timeout=app.config["SESSION_TIMEOUT"],
    )
    auth_manager.log_event(
        "SECURITY_CONFIGURATION",
        None,
        {
            "force_https": app.config.get("FORCE_HTTPS", False),
            "session_cookie_secure": app.config["SESSION_COOKIE_SECURE"],
            "tls_configured": bool(resolve_ssl_context(app)),
        },
        "system",
        "startup",
    )

    def get_all_users():
        return auth_manager.load_users()

    def find_user_by_username(username: str):
        return auth_manager.find_user_by_username(username)

    def summarize_documents_for_user(user_id: str):
        owned = get_owned_documents(user_id)
        shared = get_documents_shared_with_user(user_id)
        editable_shared = []
        if not g.current_user or g.current_user["role"] != "guest":
            editable_shared = [doc for doc in shared if can_edit_document(doc, user_id)]
        return owned, shared, editable_shared

    def get_visible_audit_entries_for_user(user_id: str):
        audit_entries = enrich_audit_entries(get_recent_audit())
        if g.current_user["role"] == "admin":
            return audit_entries

        owned_docs, shared_docs, _ = summarize_documents_for_user(user_id)
        visible_doc_ids = {doc["id"] for doc in owned_docs + shared_docs}
        return [
            entry
            for entry in audit_entries
            if entry.get("user_id") == user_id or entry.get("doc_id") in visible_doc_ids
        ]

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

    def effective_document_role(doc, user):
        if not user:
            return None

        role = get_user_document_role(doc, user["id"])
        if user.get("role") == "guest" and role == "editor":
            # Guests stay read-only at the system level, so even if document metadata says
            # editor we present it like viewer access in the UI.
            return "viewer"
        return role

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

    @app.before_request
    def require_https():
        if (
            app.config.get("FORCE_HTTPS")
            and not request.is_secure
            and not app.debug
            and not app.testing
        ):
            secure_url = request.url.replace("http://", "https://", 1)
            return redirect(secure_url, code=301)

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

        if not doc or doc.get("is_deleted"):
            return "Document not found", 404

        if g.current_user["role"] != "admin" and not can_user_access(doc, g.current_user["id"]):
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
        recent_events = get_visible_audit_entries_for_user(user_id)[:5]
        return render_template(
            "dashboard.html",
            documents=owned_docs,
            shared_documents=shared_docs,
            editable_shared_documents=editable_shared_docs,
            recent_events=recent_events,
            get_user_document_role=get_user_document_role,
            effective_document_role=effective_document_role,
        )

    @app.route("/documents", methods=["GET", "POST"])
    @login_required
    @role_required("admin", "user", "guest")
    def documents():
        if request.method == "POST":
            if g.current_user["role"] == "guest":
                flash("Guest accounts can only view and download shared documents.", "error")
                return redirect(url_for("documents"))
            # This has to match the file input name in the template or Flask will not find the uploaded file.
            file = request.files.get("document_file")

            if not file or not file.filename:
                flash("No file uploaded.", "error")
                return redirect(url_for("documents"))
            user_id = g.current_user["id"]

            try:
                # The helper handles filename cleanup plus saving metadata into documents.json.
                create_document(
                    file,
                    user_id,
                    document_name=request.form.get("document_name", ""),
                )
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
            effective_document_role=effective_document_role,
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

    @app.post("/documents/<doc_id>/delete")
    @login_required
    @role_required("admin", "user")
    def delete_existing_document(doc_id):
        allow_override = g.current_user["role"] == "admin"
        try:
            deleted_doc = delete_document(doc_id, g.current_user["id"], allow_override=allow_override)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("documents"))
        except PermissionError as exc:
            flash(str(exc), "error")
            return redirect(url_for("documents"))

        flash(f"Deleted {deleted_doc['display_name']}.", "success")
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
                share_document(
                    doc_id,
                    g.current_user["id"],
                    target_user["id"],
                    role,
                    target_label=target_user["username"],
                )
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
                        "filename": doc["display_name"],
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
        user_id = g.current_user["id"]
        audit_entries = get_visible_audit_entries_for_user(user_id)

        audit_summary = {
            "total_events": len(audit_entries),
            "downloads": sum(1 for entry in audit_entries if entry["event"] == "FILE_DOWNLOAD"),
            "shares": sum(
                1
                for entry in audit_entries
                if entry["event"] in {"FILE_SHARED", "FILE_UNSHARED", "FILE_SHARE_ROLE_UPDATED"}
            ),
            "updates": sum(1 for entry in audit_entries if entry["event"] == "FILE_UPDATED"),
        }
        return render_template("audit.html", audit_entries=audit_entries, audit_summary=audit_summary)

    @app.get("/admin")
    @login_required
    @role_required("admin")
    def admin_panel():
        all_users = get_all_users()
        all_documents = get_all_documents(include_deleted=True)
        audit_entries = enrich_audit_entries(get_recent_audit(limit=10))
        admin_summary = {
            "total_users": len(all_users),
            "total_documents": len([doc for doc in all_documents if not doc.get("is_deleted")]),
            "deleted_documents": len([doc for doc in all_documents if doc.get("is_deleted")]),
            "active_shares": sum(len(doc.get("shared_with", [])) for doc in all_documents if not doc.get("is_deleted")),
        }
        return render_template(
            "admin.html",
            all_users=all_users,
            all_documents=all_documents,
            audit_entries=audit_entries,
            admin_summary=admin_summary,
            get_user_document_role=get_user_document_role,
            user_lookup={user["id"]: user["username"] for user in all_users},
        )

    @app.post("/admin/users/<user_id>/role")
    @login_required
    @role_required("admin")
    def update_system_role(user_id):
        if g.current_user["id"] == user_id:
            flash("Admins cannot change their own role from this page.", "error")
            return redirect(url_for("admin_panel"))

        new_role = request.form.get("role", "")
        try:
            updated_user = auth_manager.update_user_role(user_id, new_role)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("admin_panel"))

        log_event("USER_ROLE_UPDATED", g.current_user["id"], filename=f"{updated_user['username']} -> {new_role}")
        flash(f"Updated {updated_user['username']} to role {new_role}.", "success")
        return redirect(url_for("admin_panel"))

    @app.post("/admin/users/<user_id>/delete")
    @login_required
    @role_required("admin")
    def delete_user_account(user_id):
        if g.current_user["id"] == user_id:
            flash("Admins cannot delete their own account from this page.", "error")
            return redirect(url_for("admin_panel"))

        try:
            removed_user = auth_manager.remove_user(user_id)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("admin_panel"))

        remove_user_from_all_shares(user_id)
        log_event("USER_REMOVED", g.current_user["id"], filename=removed_user["username"])
        flash(f"Removed user {removed_user['username']}.", "success")
        return redirect(url_for("admin_panel"))

    @app.get("/health")
    def health():
        return {"status": "ok", "app": "secure-document-sharing-system"}

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host=app.config["APP_HOST"],
        port=app.config["APP_PORT"],
        debug=app.config.get("DEBUG", False),
        ssl_context=resolve_ssl_context(app),
    )

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

#This file contains the main Flask application factory and route definitions for the secure document 
#sharing system. It sets up the application configuration, initializes necessary directories and files,
#configures logging, and defines routes for user authentication, document management, sharing, and audit 
#viewing. The application uses an AuthManager class to handle user authentication and session management, 
#and includes decorators to enforce login and role-based access control on protected routes. The routes 
#handle actions like uploading documents (with encryption), downloading (with decryption), 
#sharing documents with specific roles, and viewing audit logs of user activity. Security best 
#practices are applied in handling file uploads, managing sessions, and setting HTTP security headers.


#This function ensures that all necessary directories and files for the application to run are created 
#if they do not already exist. It creates the data directory, log directory, upload and encrypted 
#subdirectories, and initializes default JSON files for users, sessions, login attempts, documents, 
#shares, and audit trail.
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

#This function configures logging for the Flask application, specifically setting up a file handler 
#for security-related logs. It creates a FileHandler that writes to a security.log file in the 
#configured log directory, with a specific log format. The function checks if a handler for that log 
#file already exists to avoid adding duplicate handlers, and sets the logging level to INFO.
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

#This function checks if TLS certificate and key files are configured and exist, and if so, returns 
#a tuple of their paths to be used as the SSL context for the Flask application. If either file is 
#missing, it returns None, indicating that the application should run without SSL. This allows the
#application to support both secure (HTTPS) and non-secure (HTTP) modes based on configuration and
#available files.
def resolve_ssl_context(app: Flask):
    cert_file = Path(app.config["TLS_CERT_FILE"])
    key_file = Path(app.config["TLS_KEY_FILE"])
    if cert_file.exists() and key_file.exists():
        return (str(cert_file), str(key_file))
    return None

#This function is the main application factory for the Flask app. It takes an optional configuration 
#class, and sets up the Flask application with that configuration. It ensures necessary files and 
#directories are created. It initializes an AuthManager for handling authentication and session 
#management, and defines helper functions for user and document management. It also defines route
#handlers for various endpoints like downloading documents, user authentication 
#(login, register, logout), dashboard, document management (upload, update, delete), 
#sharing management, audit viewing, and admin panel.
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
    #This is a helper function to retrieve all users from the authentication manager, 
    #which can be used in various parts of the application to display user information or
    #perform user-related operations.
    def get_all_users():
        return auth_manager.load_users()
    
    #This is a helper function to find a user by their username using the authentication manager,
    #which can be used in routes that need to look up users based on their username, such as when sharing
    #documents with other users.
    def find_user_by_username(username: str):
        return auth_manager.find_user_by_username(username)
    
    #This is a helper function to retrieve all documents that a specific user has access to, 
    #including both documents they own and documents shared with them. It can be used in
    #routes that need to display a user's documents or check access permissions.
    def summarize_documents_for_user(user_id: str):
        owned = get_owned_documents(user_id)
        shared = get_documents_shared_with_user(user_id)
        editable_shared = []
        if not g.current_user or g.current_user["role"] != "guest":
            editable_shared = [doc for doc in shared if can_edit_document(doc, user_id)]
        return owned, shared, editable_shared
    
    #This is a helper function to retrieve all documents in the system, 
    #including deleted ones, which can be used in the admin panel to provide an
    #overview of all documents and their statuses.
    def get_visible_audit_entries_for_user(user_id: str):
        audit_entries = enrich_audit_entries(get_recent_audit())
        if g.current_user["role"] == "admin":
            return audit_entries

        owned_docs, shared_docs, _ = summarize_documents_for_user(user_id)
        visible_doc_ids = {doc["id"] for doc in owned_docs + shared_docs}
        return [
            entry
            for entry in audit_entries
            if entry.get("user_id") == user_id
            or entry.get("affected_user_id") == user_id
            or entry.get("doc_id") in visible_doc_ids
        ]
    
    #This is a helper function to enrich audit log entries with additional information
    #such as usernames and formatted timestamps, which can be used to make the audit log more
    #readable and informative in the UI.
    def enrich_audit_entries(entries):
        users_by_id = {user["id"]: user["username"] for user in get_all_users()}
        return [
            {
                **entry,
                "username": users_by_id.get(entry.get("user_id"), entry.get("user_id") or "unknown"),
                "affected_username": (
                    users_by_id.get(
                        entry.get("affected_user_id"),
                        entry.get("affected_user_id") or "unknown",
                    )
                    if entry.get("affected_user_id")
                    else None
                ),
                "formatted_timestamp": datetime.fromtimestamp(
                    entry.get("timestamp", 0)
                ).strftime("%Y-%m-%d %H:%M:%S"),
            }
            for entry in entries
        ]
    
    #This is a helper function to determine the effective role a user has for a specific document, 
    #taking into account both the user's system role and their document-specific role. 
    #For example, if a user has a "guest" system role but is assigned an "editor" role for a
    #document, this function will  return "viewer" to reflect that guests should not have 
    #editing capabilities even if the document metadata says otherwise.
    def effective_document_role(doc, user):
        if not user:
            return None

        role = get_user_document_role(doc, user["id"])
        if user.get("role") == "guest" and role == "editor":
            # Guests stay read-only at the system level, so even if document metadata says
            # editor we present it like viewer access in the UI.
            return "viewer"
        return role
    
    #This is a helper function to retrieve the client's IP address from the request, 
    #which can be used for logging and security purposes, such as in the audit log or 
    #when validating sessions.
    def client_ip() -> str:
        return request.remote_addr or "unknown"

    #This is a helper function to retrieve the client's user agent string from the request headers,
    #which can be used for logging and security purposes, such as in the audit log or when validating
    #sessions.
    def client_agent() -> str:
        return request.headers.get("User-Agent", "unknown")
    
    #This is a helper function to retrieve the current session token from the request cookies,
    #which can be used for validating the user's session and retrieving session data.
    def current_session_token() -> str | None:
        return request.cookies.get("session_token")


    #This is a helper function to retrieve the CSRF token tied to the current session.
    #I use this in templates so every logged-in form can include the same token the server
    #expects when it validates state-changing POST requests.
    def current_csrf_token() -> str:
        if g.get("session"):
            return g.session.get("csrf_token", "")
        return ""

    #This is a decorator function to enforce that a user must be logged in to access certain routes.
    def login_required(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            if g.current_user is None:
                flash("Please log in to continue.", "error")
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapped_view

    #This is a decorator function to enforce that a user must have one of the specified roles to 
    #access certain routes.
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

    #This function is registered to run before each request, and it loads the user's session based on 
    # the session token cookie. It validates the session token against the stored sessions, checks the 
    #client's IP and user agent for additional security, and sets the current user information in the 
    #Flask global context (g) for use in route handlers.
    @app.before_request
    def load_user_session() -> None:
        token = current_session_token()
        # I re-check the session on every request because the cookie alone should not be trusted
        # unless it still matches a valid session in our storage.
        is_static_request = request.endpoint == "static" or request.path == "/favicon.ico"
        validator = auth_manager.get_session if is_static_request else auth_manager.validate_session
        session_data = validator(token, client_ip(), client_agent())
        g.session = session_data
        g.current_user = auth_manager.get_user_by_id(session_data["user_id"]) if session_data else None

    #This function is registered to run before each request, and it enforces HTTPS by redirecting any
    #non-secure requests to the secure version of the URL if the application is configured to force HTTPS.
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

    @app.before_request
    def protect_authenticated_post_requests():
        # I validate the CSRF token here before logged-in POST requests are allowed to continue.
        # This helps stop another site from using the browser's cookie automatically to trigger
        # actions like share, delete, update, or logout behind the user's back.
        if request.method != "POST":
            return None
        if request.endpoint in {"static", "login", "register"}:
            return None
        if g.get("current_user") is None:
            return None

        submitted_token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        expected_token = current_csrf_token()
        if not expected_token or submitted_token != expected_token:
            auth_manager.log_event(
                "CSRF_VALIDATION_FAILED",
                g.current_user["id"],
                {"path": request.path},
                client_ip(),
                client_agent(),
                severity="WARNING",
            )
            return render_template("403.html"), 403

        return None

    @app.context_processor
    def inject_template_helpers():
        # This makes the CSRF token available in every template so forms can include it
        # without each route having to pass it in manually.
        return {
            "csrf_token": current_csrf_token(),
        }

    #This function is registered to run after each request, and it sets various HTTP security 
    #headers on the response to help protect against common web vulnerabilities such as XSS, 
    #clickjacking, and content sniffing.
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

    #This route handler allows a logged-in user to download a document by its ID. 
    #It checks if the document exists and is not deleted, verifies that the user has access 
    #to the document, logs the download event, and then sends the decrypted file as a response 
    #with appropriate headers for downloading.
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

    #The following route handlers and functions are defined for user authentication 
    #(login, register, logout), dashboard, document management (upload, update, delete), 
    #sharing management, audit viewing, and admin panel, with appropriate access controls 
    #and logging for security and audit purposes.
    @app.get("/")
    def index():
        return render_template("index.html")

    #see above for login route handler with detailed comments
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
    #see above for login route handler with detailed comments
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
    #see above for login route handler with detailed comments
    @app.post("/logout")
    def logout():
        auth_manager.logout_session(current_session_token(), client_ip(), client_agent())
        response = make_response(redirect(url_for("login")))
        response.delete_cookie("session_token")
        flash("Logged out successfully.", "success")
        return response
    #see above for login route handler with detailed comments
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

    #This function is registered to run before each request, and it enforces HTTPS by redirecting any
    #non-secure requests to the secure version of the URL if the application is configured to force HTTPS.
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

    #This route handler allows a logged-in user with the appropriate role to upload a new version of an existing document.
    #It checks if the document exists, verifies that the user has edit access to the document
    #and that a file is uploaded, then it updates the document with the new file and logs the update event.
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

    #This route handler allows a logged-in user with the appropriate role to delete an existing document.
    #It checks if the document exists, verifies that the user has access to delete the document
    #(either they are the owner or they are an admin), then it deletes the document and logs the 
    #deletion event.
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

    #This route handler allows a logged-in user with the appropriate role to share a document with 
    #another user by specifying the target user's username and the role to assign. It checks that all 
    #required fields are provided, verifies that the target user exists, and then shares the document 
    #with the target user while logging the sharing event. It also handles errors such as missing fields,
    #non-existent target users, and permission issues.
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

    #This route handler allows a logged-in user with the appropriate role to remove sharing 
    #access for a specific user on a document.
    @app.post("/sharing/remove")
    @login_required
    @role_required("admin", "user")
    def remove_document_share():
        doc_id = request.form.get("document_id", "")
        target_user_id = request.form.get("target_user_id", "")
        target_user = auth_manager.get_user_by_id(target_user_id)
        try:
            remove_share(
                doc_id,
                g.current_user["id"],
                target_user_id,
                target_label=target_user["username"] if target_user else target_user_id,
            )
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("sharing"))
        except PermissionError as exc:
            flash(str(exc), "error")
            return redirect(url_for("sharing"))

        flash("Removed document access successfully.", "success")
        return redirect(url_for("sharing"))

    #This route handler allows a logged-in user with the appropriate role to view the audit log 
    #of user activity. It retrieves the audit entries that are visible to the user based on their
    #access to documents and their user role, summarizes the audit data for display, and renders 
    #the audit log template with this information.
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

    #This route handler allows a logged-in user with the "admin" role to access the admin panel, 
    #which provides an overview of all users, documents, and recent audit events. It retrieves all
    #users and documents (including deleted ones), enriches recent audit entries with additional 
    #information, summarizes key metrics for the admin dashboard, and renders the admin panel 
    #template with this data.
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

    #This route handler allows a logged-in user with the "admin" role to update the system role of 
    #another user.
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

    #This route handler allows a logged-in user with the "admin" role to delete another user's account. 
    #It checks that the admin is not trying to delete their own account, then it removes the user 
    #from the authentication manager, removes their access from all shared documents, logs the user
    #removal event, and redirects back to the admin panel.
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

    #This route handler provides a simple health check endpoint that returns a JSON response
    #indicating that the application is running and healthy. This can be used for monitoring
    #and load balancer health checks.
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

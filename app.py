from __future__ import annotations

import json
import logging
from pathlib import Path

from flask import Flask, render_template

from config import Config


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
        data_dir / "documents.json": [],
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

    ensure_project_files(app)
    configure_logging(app)

    @app.after_request
    def set_security_headers(response):
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

    @app.get("/login")
    def login():
        return render_template("login.html")

    @app.get("/register")
    def register():
        return render_template("register.html")

    @app.get("/dashboard")
    def dashboard():
        return render_template("dashboard.html")

    @app.get("/documents")
    def documents():
        return render_template("documents.html")

    @app.get("/sharing")
    def sharing():
        return render_template("sharing.html")

    @app.get("/audit")
    def audit():
        return render_template("audit.html")

    @app.get("/health")
    def health():
        return {"status": "ok", "app": "secure-document-sharing-system"}

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host=app.config["APP_HOST"], port=app.config["APP_PORT"], debug=True)

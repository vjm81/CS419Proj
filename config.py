from __future__ import annotations

import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-secret-change-me")
    APP_HOST = os.getenv("APP_HOST", "127.0.0.1")
    APP_PORT = int(os.getenv("APP_PORT", "5000"))
    SESSION_TIMEOUT = int(os.getenv("SESSION_TIMEOUT", "1800"))
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", str(16 * 1024 * 1024)))
    ENCRYPTION_KEY_FILE = Path(os.getenv("ENCRYPTION_KEY_FILE", BASE_DIR / "secret.key"))

    DATA_DIR = Path(os.getenv("DATA_DIR", BASE_DIR / "data"))
    LOG_DIR = Path(os.getenv("LOG_DIR", BASE_DIR / "logs"))
    UPLOAD_DIR = DATA_DIR / "uploads"
    ENCRYPTED_DIR = DATA_DIR / "encrypted"

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_COOKIE_SECURE = False
    PERMANENT_SESSION_LIFETIME = SESSION_TIMEOUT


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True

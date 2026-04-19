from __future__ import annotations

import json
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import bcrypt


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PASSWORD_SPECIALS = set("!@#$%^&*")


@dataclass
class AuthResult:
    ok: bool
    message: str
    user: dict[str, Any] | None = None
    session_token: str | None = None


class AuthManager:
    def __init__(
        self,
        users_file: Path,
        sessions_file: Path,
        login_attempts_file: Path,
        security_log_file: Path,
        session_timeout: int = 1800,
        lockout_threshold: int = 5,
        lockout_seconds: int = 900,
        rate_limit_max_attempts: int = 10,
        rate_limit_window_seconds: int = 60,
    ) -> None:
        self.users_file = Path(users_file)
        self.sessions_file = Path(sessions_file)
        self.login_attempts_file = Path(login_attempts_file)
        self.security_log_file = Path(security_log_file)
        self.session_timeout = session_timeout
        self.lockout_threshold = lockout_threshold
        self.lockout_seconds = lockout_seconds
        self.rate_limit_max_attempts = rate_limit_max_attempts
        self.rate_limit_window_seconds = rate_limit_window_seconds

    def load_users(self) -> list[dict[str, Any]]:
        return self._read_json(self.users_file, [])

    def save_users(self, users: list[dict[str, Any]]) -> None:
        self._write_json(self.users_file, users)

    def load_sessions(self) -> dict[str, dict[str, Any]]:
        return self._read_json(self.sessions_file, {})

    def save_sessions(self, sessions: dict[str, dict[str, Any]]) -> None:
        self._write_json(self.sessions_file, sessions)

    def load_login_attempts(self) -> dict[str, list[float]]:
        attempts = self._read_json(self.login_attempts_file, {})
        return attempts if isinstance(attempts, dict) else {}

    def save_login_attempts(self, attempts: dict[str, list[float]]) -> None:
        self._write_json(self.login_attempts_file, attempts)

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        confirm_password: str,
        ip_address: str,
        user_agent: str,
        role: str = "user",
    ) -> AuthResult:
        username = username.strip()
        email = email.strip().lower()

        validation_error = self.validate_registration_input(
            username=username,
            email=email,
            password=password,
            confirm_password=confirm_password,
        )
        if validation_error:
            self.log_event(
                "REGISTER_FAILED",
                None,
                {"username": username, "reason": validation_error},
                ip_address,
                user_agent,
                severity="WARNING",
            )
            return AuthResult(False, validation_error)

        users = self.load_users()
        if self.find_user_by_username(username, users):
            return AuthResult(False, "Username already exists.")
        if self.find_user_by_email(email, users):
            return AuthResult(False, "Email already exists.")

        now = time.time()
        # To follow the password security rules, I hash the password with bcrypt
        # instead of storing the real password in the JSON file.
        password_hash = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt(rounds=12),
        ).decode("utf-8")
        user = {
            "id": secrets.token_hex(8),
            "username": username,
            "email": email,
            "password_hash": password_hash,
            "role": role,
            "created_at": now,
            "failed_attempts": 0,
            "locked_until": None,
        }
        users.append(user)
        self.save_users(users)
        self.log_event(
            "REGISTER_SUCCESS",
            user["id"],
            {"username": username},
            ip_address,
            user_agent,
        )
        return AuthResult(True, "Registration successful. You can now log in.", user=user)

    def login_user(
        self,
        identifier: str,
        password: str,
        ip_address: str,
        user_agent: str,
    ) -> AuthResult:
        identifier = identifier.strip()
        if self.is_rate_limited(ip_address):
            self.log_event(
                "LOGIN_RATE_LIMITED",
                None,
                {"identifier": identifier, "reason": "Too many attempts from IP"},
                ip_address,
                user_agent,
                severity="WARNING",
            )
            return AuthResult(False, "Too many login attempts from this IP. Please wait a minute and try again.")

        self.record_login_attempt(ip_address)
        users = self.load_users()
        user = self.find_user_by_identifier(identifier, users)

        if not user:
            self.log_event(
                "LOGIN_FAILED",
                None,
                {"identifier": identifier, "reason": "Unknown account"},
                ip_address,
                user_agent,
                severity="WARNING",
            )
            return AuthResult(False, "Invalid username/email or password.")

        if self.is_locked(user):
            remaining = int(max(0, user["locked_until"] - time.time()))
            self.log_event(
                "LOGIN_BLOCKED_LOCKOUT",
                user["id"],
                {"identifier": identifier, "seconds_remaining": remaining},
                ip_address,
                user_agent,
                severity="WARNING",
            )
            return AuthResult(False, "Account is locked. Try again later.")

        # During login, I compare the typed password with the stored bcrypt hash.
        # This way the app can verify the password without ever storing it in plain text.
        if not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
            return self._record_failed_login(user, users, identifier, ip_address, user_agent)

        user["failed_attempts"] = 0
        user["locked_until"] = None
        self._upsert_user(users, user)
        self.save_users(users)

        token = self.create_session(user["id"], ip_address, user_agent)
        self.log_event(
            "LOGIN_SUCCESS",
            user["id"],
            {"identifier": identifier},
            ip_address,
            user_agent,
        )
        return AuthResult(True, "Login successful.", user=user, session_token=token)

    def logout_session(self, token: str | None, ip_address: str, user_agent: str) -> None:
        if not token:
            return
        sessions = self.load_sessions()
        session = sessions.pop(token, None)
        self.save_sessions(sessions)
        if session:
            self.log_event(
                "SESSION_DESTROYED",
                session["user_id"],
                {"reason": "logout"},
                ip_address,
                user_agent,
            )

    def create_session(self, user_id: str, ip_address: str, user_agent: str) -> str:
        # To make sessions harder to guess, I use a long random token instead of something predictable.
        token = secrets.token_urlsafe(32)
        sessions = self.load_sessions()
        sessions[token] = {
            "token": token,
            "user_id": user_id,
            "created_at": time.time(),
            "last_activity": time.time(),
            "ip_address": ip_address,
            "user_agent": user_agent,
        }
        self.save_sessions(sessions)
        self.log_event(
            "SESSION_CREATED",
            user_id,
            {"token_prefix": token[:10]},
            ip_address,
            user_agent,
        )
        return token

    def validate_session(self, token: str | None, ip_address: str, user_agent: str) -> dict[str, Any] | None:
        if not token:
            return None

        sessions = self.load_sessions()
        session = sessions.get(token)
        if not session:
            self.log_event(
                "INVALID_SESSION_TOKEN",
                None,
                {"reason": "unknown_token", "token_prefix": token[:10]},
                ip_address,
                user_agent,
                severity="WARNING",
            )
            return None

        # I expire inactive sessions here so a session does not stay valid forever
        # if someone walks away from their computer or a cookie gets exposed.
        if time.time() - session["last_activity"] > self.session_timeout:
            sessions.pop(token, None)
            self.save_sessions(sessions)
            self.log_event(
                "SESSION_EXPIRED",
                session["user_id"],
                {"reason": "timeout"},
                ip_address,
                user_agent,
            )
            return None

        session["last_activity"] = time.time()
        sessions[token] = session
        self.save_sessions(sessions)
        return session

    def get_user_by_id(self, user_id: str | None) -> dict[str, Any] | None:
        if not user_id:
            return None
        for user in self.load_users():
            if user["id"] == user_id:
                return user
        return None

    def update_user_role(self, user_id: str, role: str) -> dict[str, Any]:
        if role not in {"admin", "user", "guest"}:
            raise ValueError("Invalid user role.")

        users = self.load_users()
        for user in users:
            if user["id"] == user_id:
                user["role"] = role
                self.save_users(users)
                return user
        raise ValueError("User not found.")

    def remove_user(self, user_id: str) -> dict[str, Any]:
        users = self.load_users()
        removed_user = None
        remaining_users = []
        for user in users:
            if user["id"] == user_id:
                removed_user = user
            else:
                remaining_users.append(user)

        if removed_user is None:
            raise ValueError("User not found.")

        self.save_users(remaining_users)

        sessions = self.load_sessions()
        active_tokens = [
            token for token, session in sessions.items()
            if session["user_id"] == user_id
        ]
        for token in active_tokens:
            sessions.pop(token, None)
        self.save_sessions(sessions)
        return removed_user

    def validate_registration_input(
        self,
        username: str,
        email: str,
        password: str,
        confirm_password: str,
    ) -> str | None:
        # I validate the registration fields here so the app only accepts usernames,
        # emails, and passwords that match the project security rules.
        if not USERNAME_PATTERN.match(username):
            return "Username must be 3-20 characters and use only letters, numbers, and underscores."
        if not EMAIL_PATTERN.match(email):
            return "Email must be in a valid format."
        if password != confirm_password:
            return "Password confirmation does not match."
        if len(password) < 12:
            return "Password must be at least 12 characters long."
        if not any(char.isupper() for char in password):
            return "Password must include at least one uppercase letter."
        if not any(char.islower() for char in password):
            return "Password must include at least one lowercase letter."
        if not any(char.isdigit() for char in password):
            return "Password must include at least one number."
        if not any(char in PASSWORD_SPECIALS for char in password):
            return "Password must include at least one special character: !@#$%^&*"
        return None

    def require_role(self, user: dict[str, Any] | None, allowed_roles: set[str]) -> bool:
        if not user:
            return False
        # For access control, I only allow the request if the user's role is in the allowed list.
        # Anything not explicitly allowed gets denied by default.
        return user.get("role") in allowed_roles

    def is_rate_limited(self, ip_address: str) -> bool:
        attempts = self.load_login_attempts()
        recent_attempts = self._recent_attempts_for_ip(attempts, ip_address)
        attempts[ip_address] = recent_attempts
        self.save_login_attempts(attempts)
        return len(recent_attempts) >= self.rate_limit_max_attempts

    def record_login_attempt(self, ip_address: str) -> None:
        attempts = self.load_login_attempts()
        recent_attempts = self._recent_attempts_for_ip(attempts, ip_address)
        recent_attempts.append(time.time())
        attempts[ip_address] = recent_attempts
        self.save_login_attempts(attempts)

    def log_event(
        self,
        event_type: str,
        user_id: str | None,
        details: dict[str, Any],
        ip_address: str,
        user_agent: str,
        severity: str = "INFO",
    ) -> None:
        entry = {
            "timestamp": time.time(),
            "event_type": event_type,
            "user_id": user_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "details": details,
            "severity": severity,
        }
        # I log security events in JSON format so it is easier to review failed logins,
        # lockouts, and other suspicious activity later.
        with self.security_log_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")

    def find_user_by_identifier(
        self, identifier: str, users: list[dict[str, Any]] | None = None
    ) -> dict[str, Any] | None:
        users = users if users is not None else self.load_users()
        normalized = identifier.lower()
        for user in users:
            if user["username"] == identifier or user["email"] == normalized:
                return user
        return None

    def find_user_by_username(
        self, username: str, users: list[dict[str, Any]] | None = None
    ) -> dict[str, Any] | None:
        users = users if users is not None else self.load_users()
        for user in users:
            if user["username"].lower() == username.lower():
                return user
        return None

    def find_user_by_email(
        self, email: str, users: list[dict[str, Any]] | None = None
    ) -> dict[str, Any] | None:
        users = users if users is not None else self.load_users()
        for user in users:
            if user["email"].lower() == email.lower():
                return user
        return None

    def is_locked(self, user: dict[str, Any]) -> bool:
        locked_until = user.get("locked_until")
        return bool(locked_until and locked_until > time.time())

    def _record_failed_login(
        self,
        user: dict[str, Any],
        users: list[dict[str, Any]],
        identifier: str,
        ip_address: str,
        user_agent: str,
    ) -> AuthResult:
        # I count failed logins here so repeated bad password attempts eventually lock the account
        # and make brute-force guessing harder.
        user["failed_attempts"] = int(user.get("failed_attempts", 0)) + 1
        message = "Invalid username/email or password."
        severity = "WARNING"

        if user["failed_attempts"] >= self.lockout_threshold:
            user["locked_until"] = time.time() + self.lockout_seconds
            message = "Account locked after too many failed attempts. Try again later."
            severity = "ERROR"
            self.log_event(
                "ACCOUNT_LOCKED",
                user["id"],
                {"identifier": identifier, "failed_attempts": user["failed_attempts"]},
                ip_address,
                user_agent,
                severity="ERROR",
            )

        self._upsert_user(users, user)
        self.save_users(users)
        self.log_event(
            "LOGIN_FAILED",
            user["id"],
            {"identifier": identifier, "failed_attempts": user["failed_attempts"]},
            ip_address,
            user_agent,
            severity=severity,
        )
        return AuthResult(False, message)

    def _upsert_user(self, users: list[dict[str, Any]], updated_user: dict[str, Any]) -> None:
        for index, user in enumerate(users):
            if user["id"] == updated_user["id"]:
                users[index] = updated_user
                return

    def _recent_attempts_for_ip(
        self,
        attempts: dict[str, list[float]],
        ip_address: str,
    ) -> list[float]:
        cutoff = time.time() - self.rate_limit_window_seconds
        return [
            timestamp
            for timestamp in attempts.get(ip_address, [])
            if isinstance(timestamp, (int, float)) and timestamp >= cutoff
        ]

    @staticmethod
    def _read_json(path: Path, default: Any) -> Any:
        if not path.exists():
            return default
        raw = path.read_text(encoding="utf-8").strip()
        if not raw:
            return default
        return json.loads(raw)

    @staticmethod
    def _write_json(path: Path, payload: Any) -> None:
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

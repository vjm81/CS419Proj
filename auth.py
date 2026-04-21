from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import bcrypt


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PASSWORD_SPECIALS = set("!@#$%^&*")

#This file contains the AuthManager class which handles user authentication, session management, 
#and security logging. It provides methods for registering users, logging in and out, validating 
#sessions, and enforcing role-based access control. The class uses JSON files to store user data, 
#session information, login attempts, and security logs. It implements features such as password 
#hashing with bcrypt, account lockout after repeated failed login attempts, rate limiting based 
#on IP address, and detailed event logging for security auditing purposes. 



#The AuthResult dataclass is used to standardize the results returned by authentication operations, 
#including success status, messages, user data, and session tokens when applicable.
@dataclass
class AuthResult:
    ok: bool
    message: str
    user: dict[str, Any] | None = None
    session_token: str | None = None

#The AuthManager class provides methods for user registration, login, logout, session management, and
#security event logging. It uses JSON files to store user information, active sessions, login attempts
#for rate limiting, and security logs. The class includes features such as password hashing with bcrypt,
#account lockout after repeated failed login attempts, and role-based access control for protected routes.
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

    #The load_users method reads the user data from the specified JSON file and returns 
    #it as a list of dictionaries.
    def load_users(self) -> list[dict[str, Any]]:
        return self._read_json(self.users_file, [])

    #The save_users method takes a list of user dictionaries and writes it to the specified JSON file,
    #overwriting any existing data.
    def save_users(self, users: list[dict[str, Any]]) -> None:
        self._write_json(self.users_file, users)

    #The load_sessions method reads the active session data from the specified 
    #JSON file and returns it as a dictionary mapping session tokens to session information.
    def load_sessions(self) -> dict[str, dict[str, Any]]:
        return self._read_json(self.sessions_file, {})

    #The save_sessions method takes a dictionary of active sessions and writes it to the 
    #specified JSON file, overwriting any existing session data.
    def save_sessions(self, sessions: dict[str, dict[str, Any]]) -> None:
        self._write_json(self.sessions_file, sessions)

    #The load_login_attempts method reads the login attempt data from the specified JSON file and 
    #returns it as a dictionary mapping IP addresses to lists of timestamps for recent login attempts.
    #This is used for implementing rate limiting based on the number of login attempts from a given 
    #IP address within a certain time window.
    def load_login_attempts(self) -> dict[str, list[float]]:
        attempts = self._read_json(self.login_attempts_file, {})
        return attempts if isinstance(attempts, dict) else {}

    #The save_login_attempts method takes a dictionary of login attempts 
    #(mapping IP addresses to lists of timestamps) and writes it to the specified JSON file, 
    #overwriting any existing data. This is used to track login attempts for rate limiting purposes.
    def save_login_attempts(self, attempts: dict[str, list[float]]) -> None:
        self._write_json(self.login_attempts_file, attempts)

    #The register_user method handles the registration of new users. It validates the 
    #input fields, checks for existing usernames and emails, hashes the password using bcrypt,
    #creates a new user record, saves it to the users file, and logs the registration event. 
    #It returns an AuthResult indicating the success or failure of the registration process 
    #along with an appropriate message and user data if successful.
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

    #The login_user method handles user login by validating the provided identifier 
    #(username or email) and password. It checks for rate limiting based on the IP address, 
    #verifies the password against the stored bcrypt hash, manages account lockout after repeated 
    #failed attempts, creates a session token upon successful login, and logs all relevant events. 
    #It returns an AuthResult indicating the success or failure of the login attempt along with an 
    #appropriate message, user data, and session token if successful.
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

    #The logout_session method invalidates a user's session token, effectively logging them out. 
    #It removes the session from the active sessions file and logs the session destruction event
    #along with the reason for logout.
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

    #The create_session method generates a new session token for a user upon successful login, 
    #stores the session information in the sessions file, and logs the session creation event. 
    #The session information includes the user ID, creation time, last activity time, IP address,
    #and user agent.
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
            "csrf_token": secrets.token_urlsafe(32),
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

    #The validate_session method checks if a given session token is valid and active. 
    #It verifies that the token exists, has not expired due to inactivity, and optionally 
    #updates the last activity timestamp to keep the session alive. It returns the session
    #information if valid or None if the session is invalid or expired.
    def validate_session(self, token: str | None, ip_address: str, user_agent: str) -> dict[str, Any] | None:
        return self._validate_session(token, ip_address, user_agent, touch_activity=True)

    #The get_session method is similar to validate_session but does not update the last activity timestamp.
    def get_session(self, token: str | None, ip_address: str, user_agent: str) -> dict[str, Any] | None:
        return self._validate_session(token, ip_address, user_agent, touch_activity=False)

    #The _validate_session method is an internal helper that performs the actual validation 
    #logic for session tokens.
    def _validate_session(
        self,
        token: str | None,
        ip_address: str,
        user_agent: str,
        touch_activity: bool,
    ) -> dict[str, Any] | None:
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

        if session.get("ip_address") != ip_address or session.get("user_agent") != user_agent:
            sessions.pop(token, None)
            self.save_sessions(sessions)
            self.log_event(
                "SESSION_BINDING_MISMATCH",
                session["user_id"],
                {
                    "expected_ip": session.get("ip_address"),
                    "actual_ip": ip_address,
                    "expected_user_agent": session.get("user_agent"),
                    "actual_user_agent": user_agent,
                },
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

        if touch_activity:
            session["last_activity"] = time.time()
            sessions[token] = session
            self.save_sessions(sessions)
        return session

    #The get_user_by_id method retrieves a user dictionary from the users file based on 
    #the provided user ID.
    def get_user_by_id(self, user_id: str | None) -> dict[str, Any] | None:
        if not user_id:
            return None
        for user in self.load_users():
            if user["id"] == user_id:
                return user
        return None

    #The update_user_role method allows an administrator to change a user's role. It 
    #checks that the new role is valid, updates the user's role in the users file, and
    #returns the updated user dictionary. If the user is not found or the role is invalid,
    #it raises a ValueError.
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

    #The remove_user method allows an administrator to delete a user's account.
    #It removes the user from the users file, invalidates any active sessions for that user, 
    #and returns the removed user dictionary.
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

    #The validate_registration_input method checks the validity of the registration input fields 
    #such as username, email, password, and password confirmation. It ensures that the username 
    #and email follow the specified patterns, that the password meets complexity requirements,
    #and that the password confirmation matches. It returns an error message if any validation
    #fails or None if all inputs are valid.
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

    #The require_role method checks if a given user has one of the allowed roles for accessing 
    #a protected route.
    def require_role(self, user: dict[str, Any] | None, allowed_roles: set[str]) -> bool:
        if not user:
            return False
        # For access control, I only allow the request if the user's role is in the allowed list.
        # Anything not explicitly allowed gets denied by default.
        return user.get("role") in allowed_roles

    #The is_rate_limited method checks if the number of recent login attempts from a given IP address
    #exceeds the configured threshold for rate limiting. It uses the login attempts data to determine
    #how many attempts have been made from that IP address within the defined time window and returns True
    #if the limit has been exceeded, or False otherwise. This helps to mitigate brute-force login attempts
    #by temporarily blocking further attempts from the same IP address after too many failed logins.
    def is_rate_limited(self, ip_address: str) -> bool:
        attempts = self.load_login_attempts()
        recent_attempts = self._recent_attempts_for_ip(attempts, ip_address)
        attempts[ip_address] = recent_attempts
        self.save_login_attempts(attempts)
        return len(recent_attempts) >= self.rate_limit_max_attempts

    #The record_login_attempt method records a login attempt for a given IP address by 
    #appending the current timestamp to the list of attempts for that IP in the login attempts data. 
    #This is used to track the number of login attempts from each IP address for implementing rate 
    #limiting and blocking excessive login attempts that may indicate a brute-force attack.
    def record_login_attempt(self, ip_address: str) -> None:
        attempts = self.load_login_attempts()
        recent_attempts = self._recent_attempts_for_ip(attempts, ip_address)
        recent_attempts.append(time.time())
        attempts[ip_address] = recent_attempts
        self.save_login_attempts(attempts)

    #The log_event function is responsible for recording an event in the audit trail. It takes parameters
    #such as the event type, user ID, document ID, filename, event details, and affected user ID. It loads
    #the existing audit data, appends a new entry with the provided information along with the current
    #timestamp and the IP address of the requester (if available), and then saves the updated audit data back
    #to the file. This function is used throughout the application to log various user actions and
    #system events. The logged information includes details such as the event type, user ID, document ID,
    #filename, event details, affected user ID (if applicable), timestamp, and IP address.
    #This allows for tracking user actions and monitoring system activity for security and accountability
    #purposes.
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

    #The find_user_by_identifier method searches for a user in the provided list of users 
    #(or loads them if not provided) by matching the given identifier against both the username 
    #and email fields. It returns the user dictionary if a match is found or None if no matching 
    #user exists. This allows for flexible login using either username or email as the identifier.
    def find_user_by_identifier(
        self, identifier: str, users: list[dict[str, Any]] | None = None
    ) -> dict[str, Any] | None:
        users = users if users is not None else self.load_users()
        normalized = identifier.lower()
        for user in users:
            if user["username"] == identifier or user["email"] == normalized:
                return user
        return None

    #The find_user_by_username method searches for a user in the provided list of users 
    #(or loads them if not provided) by matching the given username against the username 
    #field of each user. It returns the user dictionary if a match is found or None if no 
    #matching user exists. This is used to check for existing usernames during registration 
    #and for login when the identifier is a username.
    def find_user_by_username(
        self, username: str, users: list[dict[str, Any]] | None = None
    ) -> dict[str, Any] | None:
        users = users if users is not None else self.load_users()
        for user in users:
            if user["username"].lower() == username.lower():
                return user
        return None

    #The find_user_by_email method searches for a user in the provided list of users
    #(or loads them if not provided) by matching the given email against the email field of each user.
    #It returns the user dictionary if a match is found or None if no matching user exists
    #This is used to check for existing emails during registration and for login when the identifier 
    #is an email.
    def find_user_by_email(
        self, email: str, users: list[dict[str, Any]] | None = None
    ) -> dict[str, Any] | None:
        users = users if users is not None else self.load_users()
        for user in users:
            if user["email"].lower() == email.lower():
                return user
        return None

    #The is_locked method checks if a user's account is currently locked due to too many failed 
    #login attempts. It looks at the "locked_until" field of the user dictionary and compares
    #it to the current time.
    def is_locked(self, user: dict[str, Any]) -> bool:
        locked_until = user.get("locked_until")
        return bool(locked_until and locked_until > time.time())

    #The _record_failed_login method is called when a login attempt fails due to an incorrect password.
    #It increments the failed_attempts count for the user, checks if the account should be
    #locked based on the lockout threshold, updates the user record, saves it, and logs the failed login
    #event. If the account gets locked, it also logs an account lockout event.
    #This method helps to enforce account lockout policies after repeated failed login attempts,
    #making it harder for attackers to guess passwords through brute-force methods by temporarily
    #locking the account after a certain number of failed attempts and logging all relevant events
    #for security monitoring.
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

    #The _upsert_user method is an internal helper that updates an existing user record in the 
    #list of users or adds it if it does not already exist. It searches for a user with the 
    #same ID and replaces the record with the updated user data. This is used to save changes
    # to a user's failed login attempts, lockout status, role changes, and other updates to 
    #the user record in the users file.
    def _upsert_user(self, users: list[dict[str, Any]], updated_user: dict[str, Any]) -> None:
        for index, user in enumerate(users):
            if user["id"] == updated_user["id"]:
                users[index] = updated_user
                return

    #The _recent_attempts_for_ip method filters the list of login attempt timestamps for a 
    #given IP address to include only those that fall within the defined rate limit window. 
    #It calculates a cutoff time based on the current time minus the rate limit window duration 
    #and returns a list of timestamps that are greater than or equal to this cutoff. 
    #This is used to determine how many recent login attempts have been made from that
    #IP address for enforcing rate limiting.
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

    #The _read_json method is a static helper function that reads JSON data from a specified file path.
    #If the file does not exist or is empty, it returns a provided default value.
    # If the file contains invalid JSON, it creates a backup of the corrupted file with a ".corrupt" 
    #suffix and returns the default value. This method is used to safely read user data, session 
    #information, login attempts, and other JSON-based data while handling potential issues with 
    #file corruption or missing files gracefully.
    @staticmethod
    def _read_json(path: Path, default: Any) -> Any:
        if not path.exists():
            return default
        raw = path.read_text(encoding="utf-8-sig").strip()
        if not raw:
            return default
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            # Runtime JSON files can get corrupted if the app closes mid-write.
            # Falling back here keeps one bad state file from crashing the whole site.
            backup_path = path.with_suffix(path.suffix + ".corrupt")
            backup_path.write_text(raw, encoding="utf-8")
            return default

    #The _write_json method is a static helper function that writes JSON data to a specified file path.
    #It ensures that the parent directory exists, writes the JSON data to a temporary file, and then
    #atomically replaces the target file with the temporary file. This approach helps to prevent data
    #corruption by ensuring that the file is only replaced if the write operation completes successfully.
    @staticmethod
    def _write_json(path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            delete=False,
        ) as handle:
            json.dump(payload, handle, indent=2)
            temp_name = handle.name
        for _ in range(3):
            try:
                os.replace(temp_name, path)
                return
            except PermissionError:
                time.sleep(0.05)
        Path(temp_name).unlink(missing_ok=True)
        raise

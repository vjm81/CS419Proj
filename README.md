# Secure Document Sharing System

Secure Flask web application for the CS 419 Spring 2026 course project. The app supports authenticated document sharing with encryption, audit logging, version history, and admin controls using JSON file-based storage.

## Features

- User registration and login
- Password hashing with `bcrypt`
- Account lockout after 5 failed logins for 15 minutes
- IP login rate limiting: 10 attempts per minute
- Secure session tokens with timeout handling
- Encrypted file storage using `cryptography.fernet`
- Document upload, download, sharing, versioning, and soft deletion
- System roles: `admin`, `user`, `guest`
- Document roles: `owner`, `editor`, `viewer`
- Admin controls for viewing all content, deleting documents, changing user roles, and removing users
- Audit trail for document actions and security events
- Security headers and local HTTPS/TLS support
- Upload validation with extension and MIME allowlists

## Tech Stack

- Python 3.11+
- Flask
- JSON file-based persistence
- `bcrypt`
- `cryptography`
- `pytest`

## Project Structure

- `app.py` - Flask routes, security headers, HTTPS config, and page wiring
- `auth.py` - registration, login, sessions, lockout, and rate limiting
- `documents.py` - encrypted file handling, sharing, permissions, and versioning
- `audit.py` - audit trail storage
- `config.py` - app, upload, and TLS configuration
- `templates/` - HTML templates
- `static/` - CSS and JS assets
- `data/` - JSON storage files
- `logs/` - security logs
- `tests/` - automated tests
- `docs/` - design document and penetration testing report
- `presentation/` - project slides

## Data Files

- `data/users.json`
- `data/sessions.json`
- `data/login_attempts.json`
- `data/documents.json`
- `data/shares.json`
- `data/audit_trail.json`

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Run The App

Standard local run:

```powershell
python app.py
```

Default app URL:

- `http://127.0.0.1:5000` when no TLS certificate is present
- `https://127.0.0.1:5000` when `cert.pem` and `key.pem` exist

## HTTPS / TLS

The app supports local HTTPS using:

- `cert.pem`
- `key.pem`

These files are ignored by Git. The app automatically uses them when they exist.

Optional environment variables:

- `TLS_CERT_FILE`
- `TLS_KEY_FILE`
- `FORCE_HTTPS`

See [.env.example](C:/Users/Owner/Documents/codes/CS419Proj/.env.example) for sample values.

### HTTPS Setup

If you want to run the app over HTTPS locally, create a development certificate and key in the project root:

- `cert.pem`
- `key.pem`

The current project already supports loading those files automatically through [app.py](C:/Users/Owner/Documents/codes/CS419Proj/app.py).

### Generate Cert Files

Option 1: Use the existing local files if they are already present.

Option 2: Generate a self-signed certificate with Python and `cryptography`:

```powershell
python -c "from pathlib import Path; from datetime import datetime, timedelta, timezone; import ipaddress; from cryptography import x509; from cryptography.x509.oid import NameOID; from cryptography.hazmat.primitives import hashes, serialization; from cryptography.hazmat.primitives.asymmetric import rsa; base=Path('.'); key_path=base/'key.pem'; cert_path=base/'cert.pem'; key=rsa.generate_private_key(public_exponent=65537,key_size=2048); subject=issuer=x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME,'US'),x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,'New York'),x509.NameAttribute(NameOID.LOCALITY_NAME,'Local Development'),x509.NameAttribute(NameOID.ORGANIZATION_NAME,'CS419 Project'),x509.NameAttribute(NameOID.COMMON_NAME,'localhost')]); cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(minutes=5)).not_valid_after(datetime.now(timezone.utc)+timedelta(days=365)).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256())); key_path.write_bytes(key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())); cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))"
```

### Run Over HTTPS

Once `cert.pem` and `key.pem` exist, start the app normally:

```powershell
python app.py
```

Then open one of these in your browser:

- `https://127.0.0.1:5000`
- `https://localhost:5000`

Because this is a self-signed development certificate, your browser will likely show a warning page first. That is expected for local testing.

### Optional HTTPS Redirect Setting

To enable the app's redirect logic outside development-style runs, set this in your local `.env`:

```env
FORCE_HTTPS=1
```

Then restart the app.

## Testing

Run the automated test suite:

```powershell
python -m pytest -v
```

Current suite coverage includes:

- authentication and lockout behavior
- IP rate limiting
- session creation and invalid-token handling
- document upload and encrypted download
- upload validation
- sharing and versioning
- guest/admin permission checks
- HTTPS configuration behavior

## Demo Accounts

Accounts are created through the register page. To make an admin account quickly for local testing, update the user's `role` in `data/users.json` from `user` to `admin`.

## Notes

- Uploaded files are stored encrypted on disk.
- `guest` users can view and download shared documents and previously owned documents, but cannot upload, update, or delete content.
- Runtime JSON files in `data/` may change during local testing.

# Secure Document Sharing System

Starter repository for the CS 419 Spring 2026 secure web application project.

## Project Goal

Build a secure document sharing system with:

- user registration and authentication
- encrypted document storage
- document sharing with specific users
- access control with owner, editor, and viewer roles
- document versioning and an audit trail

## Tech Stack

- Python 3.11+
- Flask
- JSON file-based persistence
- `bcrypt`, `cryptography`, and `PyJWT` for security-related features

## Current Status

This repo currently includes the project structure and starter files only. The full security controls and business logic still need to be implemented.

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
flask --app app run --debug
```

## Planned Data Files

- `data/users.json`
- `data/sessions.json`
- `data/documents.json`
- `data/shares.json`
- `data/audit_trail.json`

## Deliverables Folder Map

- `docs/` for the security design document and penetration testing report
- `presentation/` for slides
- `tests/` for automated checks


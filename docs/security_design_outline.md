# Security Design Document Outline

# Section #1 - Architecture Overview

1. System Architecture Diagram
    - Presentation Layer
        * Flask routes and templates
        * Handles HTTP requests/responses
    - Application Layer
        * auth.py = authentication and session logic
        * documents.py = document handling and sharing
        * audit.py = logging and monitoring
    - Data Layer
        * JSON-based storage (users, sessions, documents, shares)
        * Encrypted file storage on disk

2. Data Flow Diagrams
    - Authentication Flow
        * User submits credentials
        * System validates input
        * Password checked using bcrypt
        * If valid -> session token generated
        * Session stored and returned to client
    - File Upload Flow
        * File uploaded by user
        * Filename sanitized
        * File validated (extension + MIME type)
        * File encrypted
        * Encrypted file stored on disk
        * Metadata saved in JSON

3. Component Descriptions
    - Authentication Manager (auth.py)
        * Handles:
            - Registration
            - Login/logout
            - Session validation
            - Rate limiting
            - Account lockout
        * Uses secure hashing and token-based sessions
    - Document Manager (documents.py)
        * Handles:
            - File uploads (encrypted)
            - Document metadata
            - Versioning
            - Sharing permissions
        * Enforces access control policies
    - Audit System (audit.py)
        * Logs:
            - Security events
            - File actions
            - User activity
        * Provides accountability and traceability
    - Configuration Module (config.py)
        * Centralizes
            - Security settings
            - File restrictions
            - Environment variables
        * Supports secure deployment practices

4. Technology Stack Justification
    - Backend Framework: Flask
        * Lightweight and modular
        * Easy integration with security libraries
        * Suitable for educational secure systems
    - Passwords Security: bcrypt
        * Industry-standard hashing algorithm
        * Built-in salting cost factor
    - File Handling: Werkzeug
        * Secure filename sanitization
        * Reliable request handling
    - Storage Choice (JSON)
        * Simple and transparent for development
        * Allows manual inspection for auditing
        * Tradeoff: not scalable (acknowledged limitation)

# Section #2 - Threat Model

1. Asset Identification
    - Critical assets include:
        * User credentials (password hashes)
        * Session tokens
        * Encrypted document files
        * Document metadata
        * Audit logs
        * Encryption key file

2. Threat Enumeration
    - Using STRIDE-style thinking:
        * Spoofing
            - Stolen session tokens
            - Credential guessing
        * Tampering
            - File modification
            - JSON data corruption
        * Repudiation
            - Users denying actions
        * Information Disclosure
            - Unauthorized document access
            - Data leaks
        * Denial of Service
            - Login flooding
            - File upload abuse
        * Elevation of Privilege
            - Unauthor-ized role escalation

3. Vunerability Assessment
    - Potential weaknesses:
        * JSON file storage (race conditions)
        * Lack of database-level constraints
        * Reliance on MIME type validation
        * No built-in CSRF protection
        * Session token reuse risk

4. Attack Scenarios
    - Scenario 1: Brute Force Attack
        * Attacker attempts repeated logins
        * Mitigated by:
            - Rate limiting
            - Account lockout
    - Scenario 2: Malicious File Upload
        * Attacker uploads disguised executable
        * Mitigated by:
            - Extension whitelist
            - MIME validation
    - Scenario 3: Unauthorized Document Access
        * User attempts to access another user's file
        * Mitigated by:
            - Role-based access control
    - Scenario 4: Sessions Hijacking
        * Attacker steals session token
        * Impact:
            - Full account access
5. Risk Prioritization
    Threat             Likelihood     Impact     Priority
    ----------------------------------------------------------
    Brute force login    High         Medium     High
    File upload attack   Medium       High       High
    Session hijacking    Medium       High       High
    Data corruption      Low          Medium     Medium
    Privilege escalation Low          High       Medium

# Section #3 - Security Controls

1. Password Security
    - Control Description:
        * Secure password storage
    - Implementation
        * bcrypt hashing with salt
    - Testing:
        * Attempt plaintext retrieval -> impossible
        * Verify login with correct/incorrect passwords
    - Limitations:
        * No password rotation policy
    - Mitigation:
        * Enforce periodic password changes

2. Rate Limiting
    - Control Description:
        * Limit login attempts per IP
    - Implementation
        * 10 attempts per minute per IP
    - Testing:
        * Simulate repeated login attempts
    - Limitations:
        * Can be bypassed with multiple IPs
    - Mitigation:
        * Add CAPTCHA or device fingerprinting

3. Account Lockout
    - Control Description:
        * Lock account after failed attempts
    - Implementation
        * Lock after 5 failures for 15 minutes
    - Testing:
        * Trigger lock condition
    - Limitations:
        * Could enable denial-of-service
    - Mitigation:
        * Add progressive delays instead

4. Encryption at Rest
    - Control Description:
        * Protect stored files
    - Implementation
        * Files encrypted before disk storage
    - Testing:
        * Verify stored files are unreadable
    - Limitations:
        * Key stored locally
    - Mitigation:
        * Use hardware security module (HSM)

5. Access Control
    - Control Description:
        * Restrict document access
    - Implementation
        * Owner/editor/viewer roles
    - Testing:
        * Attempt unauthorized actions
    - Limitations:
        * No hierarchical roles
    - Mitigation:
        * Add policy engine

6. Audit Logging
    - Control Description:
        * Track system activity
    - Implementation
        * JSON-based audit trail
    - Testing:
        * Trigger events and verify logs
    - Limitations:
        * No tamper protection
    - Mitigation:
        * Use append-only or signed logs


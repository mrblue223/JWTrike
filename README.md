# JWTrike: JWT/JWE Security and Stress Testing Framework

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-brightgreen)
![License](https://img.shields.io/badge/license-MIT-red)
![Security](https://img.shields.io/badge/focus-penetration%20testing-lightgrey)
![Environment](https://img.shields.io/badge/environment-remote%20ready-blueviolet)

JWTrike is a modular security suite designed for the end-to-end manipulation, auditing, and exploitation of JSON Web Tokens (JWT) and JSON Web Encryption (JWE). It provides a structured framework for security researchers to identify misconfigurations and assess the resilience of token-based authentication systems.

## Core Features

- Protocol Support: Support for HS, RS, ES, and PS algorithm families.
- Vulnerability Scanning: Automated detection of "none" algorithm support, weak HMAC secrets, and header injections.
- Cryptographic Auditing: High-speed dictionary and brute-force attacks to recover signing secrets.
- Exploit Generation: Specialized payload creation for Algorithm Confusion, KID SQL Injection, Path Traversal, and SSRF (JKU/X5U).
- Integration: Native Flask-based REST API and Model Context Protocol (MCP) server for AI-agent integration.

## Technical Architecture

The framework is built with a decoupled architecture to ensure extensibility:

- core/encoder.py: Handles token serialization and signing.
- core/decoder.py: Manages deserialization and signature verification logic.
- core/scanner.py: The heuristic engine for vulnerability identification.
- core/cracker.py: Optimized multi-threaded secret recovery module.
- core/mcp_server.py: Implementation of the Model Context Protocol for LLM interoperability.

## Installation

### Prerequisites
- Python 3.8 or higher
- Virtualenv (recommended)

### Setup
Clone the repository and execute the provided setup script:

```bash
git clone [https://github.com/mrblue223/JWTrike.git](https://github.com/mrblue223/JWTrike.git)
cd JWTrike
chmod +x setup.sh
./setup.sh
```
### Activate Environment

```bash
source jwt-env/bin/activate
```

## Usage Guide
JWTrike utilizies a sub-command structure for granular contro.

1. Token Operations
Encode a token with a specific claims:

```bash
python main.py encode --payload '{"user":"admin"}' --secret "supersecret" --alg HS256
```

Decode ans inspect a token:
```bash
python main.py decode <TOKEN> --secret "supersecret"
```

2. Security Assessments
Scan a live endpoint for JWT misconfigurations:

```bash
python main.py scan <TOKEN> --url [http://api.target.internal/protected](http://api.target.internal/protected)
```
Launch a dictionary attack againts an HMAC secret:

```bash
python main.py crack <TOKEN> --wordlist wordlists/common_secrets.txt
```

3. Payload Generation
Generate tokens for specific attack vectors:
```bash
# Test for Key ID (KID) SQL Injection
python main.py payload --attack kid_sql

# Test for Algorithm Confusion (RS256 to HS256)
python main.py payload --attack alg_confusion
```
4. Integration Modes
Start the REST API for remote automation:
```bash
python main.py server --port 3000
```
Start the MCP Server for AI-assisted auditing:
```bash
python main.py mcp
```

## Project Structure
        JWTrike/
        ├── main.py              # CLI Entry point
        ├── requirements.txt     # Dependency manifest
        ├── setup.sh             # Installation script
        ├── core/                # Logic engine
        │   ├── cracker.py
        │   ├── decoder.py
        │   ├── encoder.py
        │   ├── scanner.py
        │   ├── server.py
        │   └── mcp_server.py
        └── utils/               # Constants and helpers
            ├── constants.py
            └── helpers.py

## Disclaimer

This tool is intended for **authorized security testing and educational purposes only.** Unauthorized use of this tool against systems without prior written consent is illegal. The developers assume no liability for misuse or damage caused by this software.

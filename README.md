# JWTrike: JWT/JWE Security & Stress Testing Tool

JWTrike is a comprehensive Python-based security suite designed for the end-to-end manipulation, auditing, and exploitation of JSON Web Tokens (JWT) and JSON Web Encryption (JWE). It provides a modular framework for security researchers to identify misconfigurations and test the robustness of token-based authentication systems.
# 🚀 Features
- Token Management: Encode, decode, and verify JWT/JWE tokens with support for HS, RS, ES, and PS algorithm families.
- Security Auditing:
    - Automated Scanner: Detects none algorithm support, weak HMAC secrets, expired tokens, and header injections.
    - Secret Cracker: High-speed dictionary and brute-force attacks to recover signing secrets.
    - Attack Payload Generator: Creates specialized tokens for:
        - Algorithm Confusion (Asymmetric to Symmetric).
        - KID SQL Injection & Path Traversal.
        - JKU / X5U SSRF & Key Substitution.
        - XSS via cty header.
- Integration Ready:
    - REST API: Integrated Flask server for remote access and automation.
    - MCP Server: Model Context Protocol support for LLM/AI agent integration.

# 🛠️ Installation

    Clone the repository: git clone https://github.com/yourusername/JWTrike.git cd JWTrike

    Run the setup script: The setup.sh script automates the creation of a virtual environment and installs all necessary dependencies. chmod +x setup.sh ./setup.sh

    Activate the environment: source jwt-env/bin/activate

# 📖 Usage Guide

JWTrike uses a sub-command structure via main.py.
## 1. Basic Operations

Encode a token: python main.py encode --payload '{"user":"admin"}' --secret "supersecret" --alg HS256

Decode and verify: python main.py decode <TOKEN> --secret "supersecret"
## 2. Security Testing

Scan a token for vulnerabilities: python main.py scan <TOKEN> --url http://api.target.com/protected

Crack a weak HMAC secret: python main.py crack <TOKEN> --wordlist common_passwords.txt
## 3. Attack Payload Generation

Generate a list of malicious tokens to test server-side parsing:
Test for none algorithm vulnerability

python main.py payload --attack none
Test for KID header SQL injection

python main.py payload --attack kid_sql
## 4. Server Modes

Start the REST API: python main.py server --port 3000

Start the MCP Server (for AI agents): python main.py mcp
# 📂 Project Structure

    main.py: Main entry point and CLI handler.

    core/:

        encoder.py / decoder.py: Token processing logic.

        scanner.py: Vulnerability detection engine.

        payloads.py: Attack vector generation.

        server.py: Flask REST API implementation.

        mcp_server.py: Model Context Protocol implementation.

    utils/:

        helpers.py: Utility functions for Base64 and JSON handling.

        constants.py: Supported algorithms and vulnerability definitions.

# ⚠️ Disclaimer

This tool is intended for legal security testing and educational purposes only. Always obtain explicit permission before testing against any third-party systems. The authors are not responsible for any misuse or damage caused by this tool.

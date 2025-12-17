# core/scanner.py
import json
import base64
import requests
import jwt
from urllib.parse import urljoin

class JWTScanner:
    def __init__(self):
        self.vulnerabilities = []
    
    def scan(self, token, url=None):
        """Scan for JWT vulnerabilities"""
        
        self.vulnerabilities = []
        
        # Parse token
        parts = token.split('.')
        if len(parts) < 2:
            return []
        
        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '==').decode())
        except:
            return []
        
        # Check for various vulnerabilities
        self._check_none_algorithm(header, token)
        self._check_weak_secrets(token)
        self._check_kid_injection(header)
        self._check_jku_x5u(header)
        self._check_expired_token(token)
        
        if url:
            self._test_endpoint(token, url)
        
        return self.vulnerabilities
    
    def _check_none_algorithm(self, header, token):
        """Check for 'none' algorithm vulnerability"""
        
        if header.get('alg') == 'none':
            self.vulnerabilities.append({
                "name": "None Algorithm",
                "severity": "HIGH",
                "description": "Token uses 'none' algorithm - no signature verification",
                "remediation": "Reject tokens with 'none' algorithm"
            })
    
    def _check_weak_secrets(self, token):
        """Check for weak secrets"""
        
        weak_secrets = ['secret', 'password', '123456', 'admin', 'test', '']
        
        for secret in weak_secrets:
            try:
                jwt.decode(token, secret, algorithms=['HS256'])
                self.vulnerabilities.append({
                    "name": "Weak Secret",
                    "severity": "HIGH",
                    "description": f"Token uses weak secret: {secret}",
                    "remediation": "Use strong, random secrets"
                })
                break
            except:
                continue
    
    def _check_kid_injection(self, header):
        """Check for KID injection vulnerabilities"""
        
        if 'kid' in header:
            kid = header['kid']
            if any(x in str(kid).lower() for x in ['..', 'http://', 'https://', 'file://']):
                self.vulnerabilities.append({
                    "name": "KID Injection",
                    "severity": "HIGH",
                    "description": "KID header may be vulnerable to path traversal or SSRF",
                    "remediation": "Validate and sanitize KID values"
                })
    
    def _check_jku_x5u(self, header):
        """Check for JKU/X5U vulnerabilities"""
        
        for field in ['jku', 'x5u']:
            if field in header:
                self.vulnerabilities.append({
                    "name": f"{field.upper()} Header",
                    "severity": "MEDIUM",
                    "description": f"Token contains {field} header - may allow key substitution",
                    "remediation": "Whitelist trusted URLs or disable external key fetching"
                })
    
    def _check_expired_token(self, token):
        """Check if token is expired"""
        
        try:
            # Decode without verification to check expiration
            decoded = jwt.decode(token, options={"verify_signature": False})
            import time
            if 'exp' in decoded and decoded['exp'] < time.time():
                self.vulnerabilities.append({
                    "name": "Expired Token",
                    "severity": "LOW",
                    "description": "Token has expired",
                    "remediation": "Ensure tokens have appropriate expiration times"
                })
        except:
            pass
    
    def _test_endpoint(self, token, url):
        """Test token against endpoint"""
        
        headers = {"Authorization": f"Bearer {token}"}
        
        try:
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                self.vulnerabilities.append({
                    "name": "Token Accepted",
                    "severity": "INFO",
                    "description": f"Token was accepted by {url}",
                    "remediation": "None"
                })
        except Exception as e:
            pass
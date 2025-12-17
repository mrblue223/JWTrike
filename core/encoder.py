# core/encoder.py
import json
import jwt
import zlib
import base64
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization

class JWTEncoder:
    def __init__(self):
        self.supported_algorithms = [
            'HS256', 'HS384', 'HS512',
            'RS256', 'RS384', 'RS512',
            'ES256', 'ES384', 'ES512',
            'PS256', 'PS384', 'PS512',
            'none'
        ]
    
    def encode(self, payload, secret=None, key=None, algorithm="HS256", 
               custom_header=None, compress=False, jwe=False):
        """Encode JWT/JWE token"""
        
        # Parse payload
        if isinstance(payload, str):
            try:
                if payload.endswith('.json'):
                    with open(payload, 'r') as f:
                        payload_data = json.load(f)
                else:
                    payload_data = json.loads(payload)
            except:
                payload_data = {"data": payload}
        else:
            payload_data = payload
            
        # Add default claims if not present
        if 'iat' not in payload_data:
            payload_data['iat'] = int(datetime.now().timestamp())
        if 'exp' not in payload_data:
            payload_data['exp'] = int((datetime.now() + timedelta(hours=1)).timestamp())
            
        # Handle compression
        if compress:
            payload_str = json.dumps(payload_data)
            compressed = zlib.compress(payload_str.encode())
            payload_data = {"compressed": True, "data": base64.urlsafe_b64encode(compressed).decode()}
            
        # Prepare header
        header = {"alg": algorithm, "typ": "JWT"}
        if custom_header:
            if isinstance(custom_header, str):
                custom_header = json.loads(custom_header)
            header.update(custom_header)
            
        if compress:
            header["zip"] = "DEF"
            
        # Handle JWE
        if jwe:
            return self._encode_jwe(header, payload_data, secret, key)
            
        # Handle different algorithms
        if algorithm == "none":
            return self._encode_none(header, payload_data)
        elif algorithm.startswith("HS"):
            if not secret:
                raise ValueError("Secret required for HMAC algorithms")
            return jwt.encode(payload_data, secret, algorithm=algorithm, headers=header)
        elif algorithm.startswith(("RS", "ES", "PS")):
            if not key:
                raise ValueError("Key required for asymmetric algorithms")
            with open(key, 'rb') as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
            return jwt.encode(payload_data, private_key, algorithm=algorithm, headers=header)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def _encode_none(self, header, payload):
        """Encode token with 'none' algorithm"""
        header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
        payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
        return f"{header_encoded.decode()}.{payload_encoded.decode()}."
    
    def _encode_jwe(self, header, payload, secret=None, key=None):
        """Encode JWE token (simplified implementation)"""
        # This is a simplified JWE implementation
        # For production, use jwcrypto or python-jose
        import json
        from base64 import urlsafe_b64encode
        
        header['enc'] = 'A256GCM'
        header['alg'] = 'dir'
        
        # In real implementation, you would encrypt the payload
        # Here we just base64 encode for demonstration
        payload_str = json.dumps(payload)
        encrypted_key = urlsafe_b64encode(secret.encode() if secret else b'key').decode()
        iv = urlsafe_b64encode(b'initialvector').decode()
        ciphertext = urlsafe_b64encode(payload_str.encode()).decode()
        tag = urlsafe_b64encode(b'authtag').decode()
        
        return f"{urlsafe_b64encode(json.dumps(header).encode()).decode()}." \
               f"{encrypted_key}.{iv}.{ciphertext}.{tag}"
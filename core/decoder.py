# core/decoder.py
import json
import jwt
import zlib
import base64
from datetime import datetime

class JWTDecoder:
    def decode(self, token, secret=None, key=None, algorithm=None, 
               verify_iat=False, compress=False):
        """Decode JWT/JWE token"""
        
        # Check if it's JWE
        parts = token.split('.')
        if len(parts) == 5:
            return self._decode_jwe(token, secret, key)
        
        # Decode header
        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '==').decode())
        except:
            header = {"alg": "unknown"}
            
        # Handle 'none' algorithm
        if header.get('alg') == 'none':
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '==').decode())
            return {"header": header, "payload": payload, "signature": parts[2] if len(parts) > 2 else None}
        
        # Decode with verification
        try:
            if algorithm:
                options = {'verify_signature': True}
                if not verify_iat:
                    options['verify_iat'] = False
                
                if header['alg'].startswith('HS'):
                    payload = jwt.decode(token, secret, algorithms=[algorithm], options=options)
                else:
                    with open(key, 'rb') as f:
                        key_data = f.read()
                    payload = jwt.decode(token, key_data, algorithms=[algorithm], options=options)
            else:
                # Just decode without verification
                payload = jwt.decode(token, options={"verify_signature": False})
                
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid token: {str(e)}")
        
        # Handle compression
        if compress or ('zip' in header and header['zip'] == 'DEF'):
            if 'compressed' in payload and payload['compressed']:
                compressed_data = base64.urlsafe_b64decode(payload['data'])
                decompressed = zlib.decompress(compressed_data)
                payload = json.loads(decompressed.decode())
        
        return {"header": header, "payload": payload}
    
    def _decode_jwe(self, token, secret=None, key=None):
        """Decode JWE token (simplified)"""
        parts = token.split('.')
        header = json.loads(base64.urlsafe_b64decode(parts[0] + '==').decode())
        
        # In real implementation, you would decrypt the ciphertext
        # Here we just base64 decode for demonstration
        ciphertext = base64.urlsafe_b64decode(parts[3] + '==').decode()
        try:
            payload = json.loads(ciphertext)
        except:
            payload = {"data": ciphertext}
        
        return {
            "header": header,
            "encrypted_key": parts[1],
            "initialization_vector": parts[2],
            "ciphertext": parts[3],
            "authentication_tag": parts[4],
            "payload": payload
        }
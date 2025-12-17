# core/verifier.py
import jwt
from cryptography.hazmat.primitives import serialization

class JWTVerifier:
    def verify(self, token, secret=None, key=None, algorithm=None):
        """Verify JWT token"""
        
        try:
            if algorithm:
                if algorithm.startswith('HS'):
                    if not secret:
                        return {"valid": False, "error": "Secret required for HMAC algorithms"}
                    jwt.decode(token, secret, algorithms=[algorithm])
                elif algorithm.startswith(('RS', 'ES', 'PS')):
                    if not key:
                        return {"valid": False, "error": "Key required for asymmetric algorithms"}
                    with open(key, 'rb') as f:
                        key_data = f.read()
                    jwt.decode(token, key_data, algorithms=[algorithm])
                elif algorithm == 'none':
                    # Check if token has signature part
                    parts = token.split('.')
                    if len(parts) == 3 and parts[2]:
                        return {"valid": False, "error": "Token has signature but algorithm is 'none'"}
                    return {"valid": True, "error": None}
                else:
                    return {"valid": False, "error": f"Unsupported algorithm: {algorithm}"}
            else:
                # Try to auto-detect algorithm
                parts = token.split('.')
                if len(parts) != 3:
                    return {"valid": False, "error": "Invalid token format"}
                
                # Try with secret if provided
                if secret:
                    try:
                        decoded = jwt.decode(token, secret, algorithms=['HS256', 'HS384', 'HS512'])
                        return {"valid": True, "error": None}
                    except:
                        pass
                
                # Try with key if provided
                if key:
                    with open(key, 'rb') as f:
                        key_data = f.read()
                    try:
                        decoded = jwt.decode(token, key_data, algorithms=['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'])
                        return {"valid": True, "error": None}
                    except:
                        pass
                
                return {"valid": False, "error": "Token verification failed"}
                
        except jwt.ExpiredSignatureError:
            return {"valid": False, "error": "Token expired"}
        except jwt.InvalidSignatureError:
            return {"valid": False, "error": "Invalid signature"}
        except jwt.InvalidTokenError as e:
            return {"valid": False, "error": str(e)}
        except Exception as e:
            return {"valid": False, "error": str(e)}
        
        return {"valid": True, "error": None}
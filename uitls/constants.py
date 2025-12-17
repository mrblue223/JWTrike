# utils/constants.py
SUPPORTED_ALGORITHMS = {
    'HMAC': ['HS256', 'HS384', 'HS512'],
    'RSA': ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'],
    'ECDSA': ['ES256', 'ES384', 'ES512'],
    'NONE': ['none']
}

JWT_VULNERABILITIES = [
    'none_alg',
    'weak_secret',
    'kid_injection',
    'jku_misuse',
    'x5u_misuse',
    'alg_confusion',
    'expired_token'
]
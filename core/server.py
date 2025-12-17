# core/server.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import json

class JWTServer:
    def __init__(self):
        self.app = Flask(__name__)
        CORS(self.app)
        self._setup_routes()
    
    def _setup_routes(self):
        @self.app.route('/api/encode', methods=['POST'])
        def encode():
            from core.encoder import JWTEncoder
            data = request.json
            encoder = JWTEncoder()
            try:
                token = encoder.encode(
                    payload=data.get('payload', {}),
                    secret=data.get('secret'),
                    key=data.get('key'),
                    algorithm=data.get('algorithm', 'HS256'),
                    custom_header=data.get('header'),
                    compress=data.get('compress', False),
                    jwe=data.get('jwe', False)
                )
                return jsonify({"token": token})
            except Exception as e:
                return jsonify({"error": str(e)}), 400
        
        @self.app.route('/api/decode', methods=['POST'])
        def decode():
            from core.decoder import JWTDecoder
            data = request.json
            decoder = JWTDecoder()
            try:
                result = decoder.decode(
                    token=data['token'],
                    secret=data.get('secret'),
                    key=data.get('key'),
                    algorithm=data.get('algorithm'),
                    verify_iat=data.get('verify_iat', False),
                    compress=data.get('compress', False)
                )
                return jsonify(result)
            except Exception as e:
                return jsonify({"error": str(e)}), 400
        
        @self.app.route('/api/verify', methods=['POST'])
        def verify():
            from core.verifier import JWTVerifier
            data = request.json
            verifier = JWTVerifier()
            result = verifier.verify(
                token=data['token'],
                secret=data.get('secret'),
                key=data.get('key'),
                algorithm=data.get('algorithm')
            )
            return jsonify(result)
        
        @self.app.route('/api/scan', methods=['POST'])
        def scan():
            from core.scanner import JWTScanner
            data = request.json
            scanner = JWTScanner()
            vulnerabilities = scanner.scan(
                token=data['token'],
                url=data.get('url')
            )
            return jsonify({"vulnerabilities": vulnerabilities})
        
        @self.app.route('/api/payloads', methods=['GET'])
        def get_payloads():
            from core.payloads import JWTPayloadGenerator
            attack_type = request.args.get('type', 'none')
            generator = JWTPayloadGenerator()
            payloads = generator.generate_payloads(attack_type)
            return jsonify({"payloads": payloads})
    
    def run(self, host='localhost', port=3000):
        print(f"Starting JWT Server on http://{host}:{port}")
        self.app.run(host=host, port=port, debug=False)
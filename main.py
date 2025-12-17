#!/usr/bin/env python3
# main.py
import sys
import argparse
from colorama import init, Fore, Style

# Initialize colorama for Windows compatibility
init(autoreset=True)

def print_banner():
    banner = f"""
{Fore.CYAN}
    ██╗    ██╗████████╗
    ██║    ██║╚══██╔══╝
    ██║ █╗ ██║   ██║   
    ██║███╗██║   ██║   
    ╚███╔███╔╝   ██║   
     ╚══╝╚══╝    ╚═╝   
{Style.RESET_ALL}
{Fore.YELLOW}JWT Stress Testing Tool v1.0{Style.RESET_ALL}
{Fore.GREEN}Author: Security Tool{Style.RESET_ALL}
"""
    print(banner)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="JWT Stress Testing Tool")
    subparsers = parser.add_subparsers(dest="mode", help="Mode of operation")
    
    # Encode mode
    encode_parser = subparsers.add_parser("encode", help="JWT/JWE Encoder")
    encode_parser.add_argument("--payload", required=True, help="Payload JSON file or string")
    encode_parser.add_argument("--secret", help="Secret key")
    encode_parser.add_argument("--key", help="Private key file (for asymmetric algorithms)")
    encode_parser.add_argument("--alg", default="HS256", help="Algorithm (default: HS256)")
    encode_parser.add_argument("--header", help="Custom header JSON")
    encode_parser.add_argument("--compress", action="store_true", help="Use DEFLATE compression")
    encode_parser.add_argument("--jwe", action="store_true", help="Create JWE token")
    
    # Decode mode
    decode_parser = subparsers.add_parser("decode", help="JWT/JWE Decoder")
    decode_parser.add_argument("token", help="JWT token to decode")
    decode_parser.add_argument("--secret", help="Secret key for verification")
    decode_parser.add_argument("--key", help="Public/Private key file")
    decode_parser.add_argument("--alg", help="Algorithm to use")
    decode_parser.add_argument("--verify-iat", action="store_true", help="Verify issued at time")
    decode_parser.add_argument("--compress", action="store_true", help="Use DEFLATE compression")
    
    # Verify mode
    verify_parser = subparsers.add_parser("verify", help="JWT Verifier")
    verify_parser.add_argument("token", help="JWT token to verify")
    verify_parser.add_argument("--secret", help="Secret key")
    verify_parser.add_argument("--key", help="Public key file")
    verify_parser.add_argument("--alg", help="Algorithm")
    
    # Crack mode
    crack_parser = subparsers.add_parser("crack", help="Secret Cracker")
    crack_parser.add_argument("token", help="JWT token to crack")
    crack_parser.add_argument("--wordlist", required=True, help="Dictionary file")
    crack_parser.add_argument("--brute-force", action="store_true", help="Use brute force")
    crack_parser.add_argument("--min-length", type=int, default=1, help="Min length for brute force")
    crack_parser.add_argument("--max-length", type=int, default=8, help="Max length for brute force")
    crack_parser.add_argument("--charset", default="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", help="Character set")
    crack_parser.add_argument("--compress", action="store_true", help="Use DEFLATE compression")
    
    # Payload mode
    payload_parser = subparsers.add_parser("payload", help="JWT Attack Payload Generator")
    payload_parser.add_argument("--template", help="Base token to modify")
    payload_parser.add_argument("--attack", required=True, choices=['jku_x5u', 'alg_confusion', 'kid_sql', 'x5c', 'cty', 'none'], help="Attack type")
    payload_parser.add_argument("--output", help="Output file")
    
    # Scan mode
    scan_parser = subparsers.add_parser("scan", help="Vulnerability Scanner")
    scan_parser.add_argument("token", help="JWT token to scan")
    scan_parser.add_argument("--url", help="Target URL for testing")
    
    # Server mode
    server_parser = subparsers.add_parser("server", help="API Server")
    server_parser.add_argument("--host", default="localhost", help="Host to bind")
    server_parser.add_argument("--port", type=int, default=3000, help="Port to bind")
    
    # MCP mode
    mcp_parser = subparsers.add_parser("mcp", help="Model Context Protocol Server")
    
    args = parser.parse_args()
    
    if not args.mode:
        parser.print_help()
        sys.exit(1)
    
    try:
        if args.mode == "encode":
            from core.encoder import JWTEncoder
            encoder = JWTEncoder()
            token = encoder.encode(
                payload=args.payload,
                secret=args.secret,
                key=args.key,
                algorithm=args.alg,
                custom_header=args.header,
                compress=args.compress,
                jwe=args.jwe
            )
            print(f"\n{Fore.GREEN}Generated Token:{Style.RESET_ALL}")
            print(token)
            
        elif args.mode == "decode":
            from core.decoder import JWTDecoder
            decoder = JWTDecoder()
            result = decoder.decode(
                token=args.token,
                secret=args.secret,
                key=args.key,
                algorithm=args.alg,
                verify_iat=args.verify_iat,
                compress=args.compress
            )
            print(f"\n{Fore.GREEN}Decoded Token:{Style.RESET_ALL}")
            import json
            print(json.dumps(result, indent=2))
            
        elif args.mode == "verify":
            from core.verifier import JWTVerifier
            verifier = JWTVerifier()
            result = verifier.verify(
                token=args.token,
                secret=args.secret,
                key=args.key,
                algorithm=args.alg
            )
            if result["valid"]:
                print(f"{Fore.GREEN}✓ Token is valid{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}✗ Token is invalid: {result['error']}{Style.RESET_ALL}")
                
        elif args.mode == "crack":
            from core.cracker import JWTCracker
            cracker = JWTCracker()
            result = cracker.crack(
                token=args.token,
                wordlist=args.wordlist,
                brute_force=args.brute_force,
                min_length=args.min_length,
                max_length=args.max_length,
                charset=args.charset,
                compress=args.compress
            )
            if result["found"]:
                print(f"{Fore.GREEN}✓ Secret found: {result['secret']}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}✗ Secret not found{Style.RESET_ALL}")
                
        elif args.mode == "payload":
            from core.payloads import JWTPayloadGenerator
            generator = JWTPayloadGenerator()
            payloads = generator.generate_payloads(args.attack, args.template)
            print(f"{Fore.GREEN}Generated Payloads:{Style.RESET_ALL}")
            for i, p in enumerate(payloads, 1):
                print(f"\n{i}. {p}")
                
        elif args.mode == "scan":
            from core.scanner import JWTScanner
            scanner = JWTScanner()
            vulnerabilities = scanner.scan(args.token, args.url)
            print(f"{Fore.CYAN}Scan Results:{Style.RESET_ALL}")
            if vulnerabilities:
                for vuln in vulnerabilities:
                    color = Fore.RED if vuln['severity'] == 'HIGH' else Fore.YELLOW if vuln['severity'] == 'MEDIUM' else Fore.BLUE
                    print(f"{color}[{vuln['severity']}] {vuln['name']}: {vuln['description']}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}No vulnerabilities found{Style.RESET_ALL}")
                
        elif args.mode == "server":
            from core.server import JWTServer
            server = JWTServer()
            server.run(host=args.host, port=args.port)
            
        elif args.mode == "mcp":
            from core.mcp_server import MCPServer
            mcp_server = MCPServer()
            mcp_server.run()
            
    except ImportError as e:
        print(f"{Fore.RED}Import Error: {str(e)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Make sure all dependencies are installed: pip install -r requirements.txt{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    # Check Python version
    if sys.version_info[0] < 3:
        print(f"{Fore.RED}Error: Python 3 is required. Please run with python3.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Current Python version: {sys.version}{Style.RESET_ALL}")
        sys.exit(1)
    main()
#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║     NETSCALER NSC_BODY CREDENTIAL DECODER - STANDALONE TOOL                ║
║                                                                            ║
║  Usage: python3 decode_nsc_body.py <NSC_BODY_COOKIE>                       ║
║         echo "<cookie>" | python3 decode_nsc_body.py --stdin               ║
║                                                                            ║
║  Example:                                                                  ║
║    $ python3 decode_nsc_body.py YXBwbGljYXRpb24veC13d3ct...                ║
║    $ echo "YXBwbGlj..." | python3 decode_nsc_body.py --stdin        ║
╚══════════════════════════════════════════════════════════════════════════════╝

Quick decoder for NetScaler NSC_BODY cookie credential extraction.
Paste any NSC_BODY cookie value and get instant credential extraction.

"""

import base64
import sys

# ANSI COLORS
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
BOLD = '\033[1m'
DIM = '\033[2m'
RESET = '\033[0m'


def decode_nsc_body(cookie_value):
    """
    Decode NSC_BODY cookie and extract credentials.
    
    NSC_BODY Format:
    Base64("application/x-www-form-urlencoded&dusername=<USER>&passwd=<PASS>")
    """
    try:
        cookie = cookie_value.strip()
        decoded = base64.b64decode(cookie).decode('utf-8', errors='ignore')
        
        credentials = {}
        for param in decoded.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                credentials[key] = value
        
        return {
            'success': True,
            'raw_decoded': decoded,
            'username': credentials.get('dusername', credentials.get('username', 'N/A')),
            'password': credentials.get('passwd', credentials.get('password', 'N/A')),
            'error': None
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'username': None,
            'password': None,
            'raw_decoded': None
        }


def main():
    if len(sys.argv) < 2:
        banner = f"""
{CYAN}{BOLD}
    +==========================================================+
    |  NSC_BODY Cookie Credential Decoder                     |
    |  Extract credentials from NetScaler NSC_BODY cookies     |
    +==========================================================+
{RESET}

Usage:
  python3 decode_nsc_body.py <NSC_BODY_COOKIE>
  python3 decode_nsc_body.py --stdin
  echo "<cookie>" | python3 decode_nsc_body.py --stdin

Examples:
  python3 decode_nsc_body.py YXBwbGljYXRpb24veC13d3ct...
  echo "YXBwbGlj..." | python3 decode_nsc_body.py --stdin
        """
        print(banner)
        sys.exit(1)
    
    if sys.argv[1] == '--stdin':
        cookie = sys.stdin.read().strip()
    else:
        cookie = sys.argv[1]
    
    if not cookie:
        print(f"{RED}[X] No cookie provided{RESET}")
        sys.exit(1)
    
    result = decode_nsc_body(cookie)
    
    print(f"""
{DIM}{'=' * 60}{RESET}
{CYAN}NSC_BODY CREDENTIAL EXTRACTION{RESET}
{DIM}{'=' * 60}{RESET}

Input Cookie: {DIM}{cookie[:60]}...{RESET}
{DIM}{'-' * 60}{RESET}
""")
    
    if result['success']:
        box = f"""
{GREEN}[+]{RESET} Successfully decoded!

Decoded Content:
  Raw:    {result['raw_decoded']}
  
  +----------------------------------------------------------+
  |                                                          |
  |   Username:  {BOLD}{GREEN}{result['username']:<30}{RESET}  |
  |   Password:  {BOLD}{GREEN}{result['password']:<30}{RESET}  |
  |                                                          |
  +----------------------------------------------------------+

Security Impact:
  {YELLOW}WARNING: This cookie contains plaintext credentials!{RESET}
  WARNING: Base64 encoding provides NO security protection
  WARNING: Anyone can decode to obtain username and password
  WARNING: This represents a CRITICAL security vulnerability
"""
        print(box)
    else:
        print(f"{RED}[X] Decode failed: {result['error']}{RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
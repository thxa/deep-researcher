# Web Security Testing Methodology

## 1. OWASP Testing Guide v4 Mapping

### 1.1 OWASP Testing Guide Structure

The OWASP Testing Guide v4 provides a comprehensive framework for web application security testing, organized into 12 categories with 93 tests. Each test maps to specific OWASP Top 10 categories:

```
OWASP Testing Guide v4 Structure:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WSTG-INFO: Information Gathering
  WSTG-INFO-01: Conduct Search Engine Discovery
  WSTG-INFO-02: Fingerprint Web Server
  WSTG-INFO-03: Review Webserver Metafiles
  WSTG-INFO-04: Enumerate Applications on Webserver
  WSTG-INFO-05: Review Webpage Content
  WSTG-INFO-06: Review Webserver Technology
  WSTG-INFO-07: Identify User Agent Strings
  WSTG-INFO-08: Fingerprint Web Application Framework
  WSTG-INFO-09: Fingerprint Web Application
  WSTG-INFO-10: Identify Application Entry Points

WSTG-CONF: Configuration Management
  WSTG-CONF-01: Test Network Infrastructure Configuration
  WSTG-CONF-02: Test Application Platform Configuration
  WSTG-CONF-03: Review Old Backup and Unreferenced Files
  WSTG-CONF-04: Review Admin Interfaces
  WSTG-CONF-05: Test HTTP Methods
  WSTG-CONF-06: Test HTTP Strict Transport Security
  WSTG-CONF-07: Test RIA Policy Files
  WSTG-CONF-08: Test File Permission
  WSTG-CONF-09: Test for Subdomain Takeover

WSTG-IDNT: Identity Management
  WSTG-IDNT-01: Test Role Definitions
  WSTG-IDNT-02: Test User Registration Process
  WSTG-IDNT-03: Test Account Provisioning Process
  WSTG-IDNT-04: Test Account Enumeration
  WSTG-IDNT-05: Test for Weak or Unenforced Username Policy

WSTG-ATHN: Authentication Testing
  WSTG-ATHN-01: Test Credentials Transport
  WSTG-ATHN-02: Test Default Credentials
  WSTG-ATHN-03: Test Weak Lock Out Mechanism
  WSTG-ATHN-04: Test Weak Password Policy
  WSTG-ATHN-05: Test Weak Security Question
  WSTG-ATHN-06: Test Weak Password Change/Reset
  WSTG-ATHN-07: Test Weak Authentication in Alternative Channel

WSTG-ATHZ: Authorization Testing
  WSTG-ATHZ-01: Test Directory Traversal
  WSTG-ATHZ-02: Test Bypassing Authorization Schema
  WSTG-ATHZ-03: Test Privilege Escalation
  WSTG-ATHZ-04: Test Insecure Direct Object References

WSTG-SESS: Session Management
  WSTG-SESS-01: Test Session Management Schema
  WSTG-SESS-02: Test for Cookies Attributes
  WSTG-SESS-03: Test Session Timeout
  WSTG-SESS-04: Test Session Puzzling
  WSTG-SESS-05: Test for CSRF
  WSTG-SESS-06: Test for Logout Functionality
  WSTG-SESS-07: Test Session Cache
  WSTG-SESS-08: Test for Session Puzzling

WSTG-INPV: Input Validation Testing
  WSTG-INPV-01: Test for Reflected XSS
  WSTG-INPV-02: Test for Stored XSS
  WSTG-INPV-03: Test for HTTP Verb Tampering
  WSTG-INPV-04: Test for HTTP Parameter Pollution
  WSTG-INPV-05: Test for SQL Injection
  WSTG-INPV-06: Test for LDAP Injection
  WSTG-INPV-07: Test for ORM Injection
  WSTG-INPV-08: Test for XML Injection
  WSTG-INPV-09: Test for SSI Injection
  WSTG-INPV-10: Test for XPath Injection
  WSTG-INPV-11: Test for IMAP/SMTP Injection
  WSTG-INPV-12: Test for Code Injection
  WSTG-INPV-13: Test for Command Injection
  WSTG-INPV-14: Test for Buffer Overflow
  WSTG-INPV-15: Test for Incubated Vulnerability
  WSTG-INPV-16: Test for HTTP Splitting/Smuggling
  WSTG-INPV-17: Test for HTTP Incoming Requestss
  WSTG-INPV-18: Test for Host Header Injection
  WSTG-INPV-19: Test for SSRF
  WSTG-INPV-20: Test for Mass Assignment

WSTG-ERRH: Error Handling
  WSTG-ERRH-01: Test for Improper Error Handling
  WSTG-ERRH-02: Test for Stack Traces

WSTG-CRYP: Cryptography
  WSTG-CRYP-01: Test for Weak SSL/TLS Configuration
  WSTG-CRYP-02: Test for Weak Padding Oracle
  WSTG-CRYP-03: Test for Sensitive Information Sent via Unencrypted Channel
  WSTG-CRYP-04: Test for Weak Encryption

WSTG-BUSL: Business Logic
  WSTG-BUSL-01: Test Business Logic Data Validation
  WSTG-BUSL-02: Test Ability to Bypass Workflow
  WSTG-BUSL-03: Test Defensible Limits
  WSTG-BUSL-04: Test for Insufficient Anti-Automation
  WSTG-BUSL-05: Test for Lack of Integrity Check
  WSTG-BUSL-06: Test for Exploitation of Session Variables

WSTG-CLNT: Client-Side Testing
  WSTG-CLNT-01: Test for DOM-based XSS
  WSTG-CLNT-02: Test for JavaScript Execution
  WSTG-CLNT-03: Test for HTML Injection
  WSTG-CLNT-04: Test for CSS Injection
  WSTG-CLNT-05: Test for Client-side URL Redirect
  WSTG-CLNT-06: Test for Client-side Resource Manipulation
  WSTG-CLNT-07: Test Cross Origin Resource Sharing
  WSTG-CLNT-08: Test for Flash Policy Files
  WSTG-CLNT-09: Test for Clickjacking
  WSTG-CLNT-10: Test for WebSockets
  WSTG-CLNT-11: Test for Cross Site Flashing
  WSTG-CLNT-12: Test for PostMessage

WSTG-APIV: API Testing
  WSTG-APIV-01: Test for GraphQL
  WSTG-APIV-02: Test for REST API
  WSTG-APIV-03: Test for WebSockets
```

---

## 2. DAST vs SAST vs IAST

### 2.1 Testing Approach Comparison

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Testing Approaches                              │
├──────────────┬──────────────────┬──────────────────┬───────────────────┤
│              │   DAST           │   SAST           │   IAST            │
├──────────────┼──────────────────┼──────────────────┼───────────────────┤
│ When         │ Running app      │ Source code      │ Running + agent   │
│ Language     │ Black box        │ White box        │ Gray box          │
│ Access       │ URL only         │ Source code      │ Source + runtime  │
│ Findings     │ Exploitable      │ Potential        │ Confirmed         │
│ False +      │ Low              │ High             │ Medium            │
│ Speed        │ Minutes-hours    │ Hours-days        │ Minutes          │
│ Coverage     │ Entry points    │ All code paths    │ Executed paths    │
│ Requirements │ Deployed app     │ Source code      │ Instrumented app  │
│ Auth         │ Manual/session   │ N/A              │ Via agent        │
│ Examples     │ Burp, ZAP, Nuclei│ Semgrep, SonarQube│ Contrast, Seeker│
└──────────────┴──────────────────┴──────────────────┴───────────────────┘
```

### 2.2 DAST (Dynamic Application Security Testing)

```bash
# OWASP ZAP automated scan
# Start ZAP in daemon mode
zap-x.sh -daemon -port 8080 -config api.key=zap-api-key

# Spider the target
curl "http://localhost:8080/JSON/spider/action/scan/?zapapiformat=JSON&apikey=zap-api-key&url=https://target.com&maxChildren=&recurse=true"

# Active scan
curl "http://localhost:8080/JSON/ascan/action/scan/?zapapiformat=JSON&apikey=zap-api-key&url=https://target.com&recurse=true"

# Nuclei scan with templates
nuclei -u https://target.com -t cves/ -t vulnerabilities/ -t misconfiguration/ -severity critical,high

# Nikto web server scanner
nikto -h https://target.com -o nikto_results.html -Format htm

# ffuf for content discovery
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403 -fc 404

# Arjun for parameter discovery
arjun -u https://target.com/api/endpoint -m GET,POST -t 20

# SQLMap for automated SQL injection testing
sqlmap -u "https://target.com/api/users?id=1" --batch --dbs --level 5 --risk 3
sqlmap -u "https://target.com/api/users?id=1" --dump -D target_db -T users
```

### 2.3 SAST (Static Application Security Testing)

```bash
# Semgrep — multi-language pattern-based SAST
semgrep --config auto --json path/to/code/
semgrep --config p/owasp-top-ten --json path/to/code/
semgrep --config p/xss --config p/sql-injection --config p/command-injection path/to/code/

# SonarQube — enterprise SAST with quality gates
# Run via CI/CD pipeline:
sonar-scanner \
  -Dsonar.projectKey=target-app \
  -Dsonar.sources=src/ \
  -Dsonar.host.url=http://sonarqube:9000 \
  -Dsonar.login=sonar-token

# Bandit — Python-specific SAST
bandit -r src/ -f json -o bandit-results.json

# Brakeman — Ruby on Rails SAST
brakeman --path /path/to/rails/app --format json --output brakeman-results.json

# CodeQL — GitHub's semantic code analysis
codeql database create --language=python --source-root=src/ /tmp/codeql-db
codeql database analyze /tmp/codeql-db --format=sarif-latest --output=results.sarif

# Node.js specific: npm audit + Snyk
npm audit --json
snyk test --json --file=package.json
snyk code test path/to/code/
```

### 2.4 IAST (Interactive Application Security Testing)

```yaml
# Contrast IAST agent configuration (Java)
# Add JVM agent to application startup:
java -javaagent:contrast.jar \
  -Dcontrast.server.name=target-app \
  -Dcontrast.server.path=/api \
  -Dcontrast.app.name=target-app \
  -Dcontrast.app.version=1.0.0 \
  -jar target-app.jar

# IAST finds vulnerabilities through actual code execution:
# - Monitors data flow from source to sink
# - Confirms exploitability through runtime analysis
# - Low false positive rate (only reports reachable vulnerabilities)
# - Requires functional/integration testing to trigger code paths
# - Cannot find vulnerabilities in unexecuted code paths
```

---

## 3. Reconnaissance Methodology

### 3.1 Subdomain Enumeration

```bash
# Step 1: Passive subdomain enumeration (no direct interaction with target)
# Certificate Transparency logs
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# DNS enumeration via various tools
subfinder -d target.com -silent | sort -u > subdomains.txt

# Amass — comprehensive subdomain enumeration
amass enum -passive -d target.com -o amass_results.txt

# SecurityTrails
curl -s "https://api.securitytrails.com/v1/domain/target.com/subdomains" \
  -H "apikey: YOUR_API_KEY" | jq -r '.subdomains[]' | sort -u

# Step 2: Active subdomain enumeration (DNS resolution)
# Resolve all discovered subdomains
cat subdomains.txt | dnsx -r 1.1.1.1,8.8.8.8 -resp-only -silent | sort -u > resolved.txt

# Step 3: HTTP probing (identify web services)
cat resolved.txt | httpx -status-code -title -tech-detect -follow-redirects -silent > probed.txt

# Step 4: Content discovery on each subdomain
cat probed.txt | ffuf -H "Host: FUZZ.target.com" -u "https://FUZZ.target.com" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,301,302,403

# Step 5: Port scanning
nmap -sV -sC -p 80,443,8080,8443,3000,5000,9000,9090 -iL resolved.txt -oA nmap_results
```

### 3.2 Technology Fingerprinting

```bash
# Wappalyzer — identify technologies
# Browser extension or CLI
wappalyzer https://target.com

# WhatWeb — web technology fingerprinting
whatweb -v https://target.com

# BuiltWith — technology profiling
curl -s "https://builtwith.com/target.com" | grep -i "technology"

# HTTP Header analysis
curl -sI https://target.com
# Look for:
# X-Powered-By: Express        → Express.js
# X-AspNet-Version: 4.0.30319  → ASP.NET
# Server: nginx/1.18.0          → Nginx version
# X-Generator: Drupal 9         → Drupal CMS
# Set-Cookie: PHPSESSID         → PHP
# Set-Cookie: JSESSIONID        → Java/Tomcat

# Favicon hash analysis (identify frameworks by favicon)
python3 favfreak.py -f urls.txt -o favicon_hashes.txt

# Wappalyzer CLI
wappalyzer https://target.com | jq '.technologies[] | {name, version, categories}'

# JavaScript analysis (identify frameworks from JS files)
curl -s https://target.com/ | grep -oP 'src="[^"]*\.js"' | while read js; do
  curl -s "$js" | grep -oP '(?:react|angular|vue|jquery|backbone|ember|next|nuxt)[^a-z]'
done
```

### 3.3 Content Discovery

```bash
# Directory and file discovery
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,301,302,403 -fc 404 -t 50

# File discovery (common sensitive files)
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -mc 200,301,302 -fc 404 -t 50

# Specific sensitive file checks
for file in .env .git/config .git/HEAD .svn/entries .DS_Store web.config \
            wp-config.php configuration.php config.yml settings.py \
            package.json composer.json Gemfile requirements.txt \
            swagger-ui.html api-docs graphql graphiql \
            .well-known/security.txt robots.txt sitemap.xml \
            server-status debug trace.axd elmah.axd; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$file")
  if [ "$status" != "404" ] && [ "$status" != "0" ]; then
    echo "[+] $file → $status"
  fi
done

# API endpoint discovery
ffuf -u https://target.com/api/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200,201,401,403 -fc 404

# HTTP method enumeration
for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
  status=$(curl -s -o /dev/null -w "%{http_code}" -X $method "https://target.com/api/users")
  echo "$method → $status"
done

# Parameter fuzzing with Arjun
arjun -u https://target.com/api/endpoint -m GET,POST
```

---

## 4. Automated Scanning

### 4.1 Burp Suite Professional

```
Burp Suite Professional Workflow:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Proxy Setup:
   - Configure browser to proxy through 127.0.0.1:8080
   - Install Burp's CA certificate in browser
   - Enable intercept (or disable for passive crawling)

2. Spidering:
   - Target → Site map → Right-click → Spider this host
   - Configure spider settings: maximum depth, maximum links
   - Application-aware spidering: log in first, then spider authenticated areas

3. Active Scanning:
   - Select URLs in site map → Right-click → Active scan
   - Scanner issues: SQL injection, XSS, path traversal, SSRF, etc.
   - Review issues dashboard: confirmed, tentative, false positive

4. Manual Testing:
   - Intruder: automated payload delivery (sniper, battering ram, pitchfork, cluster bomb)
   - Repeater: manual request modification and testing
   - Comparer: compare two responses to find differences
   - Decoder: encode/decode data in various formats
   - Sequencer: analyze randomness of session tokens

5. Extensions:
   - Autorize: test for authorization bypasses
   - Cookie Decrypter: decode encrypted cookies
   - Param Miner: discover hidden parameters
   - HTTP Request Smuggler: detect CL.TE and TE.CL smuggling
   - JSON Beautifier: format JSON responses
   - WSDL Scanner: enumerate WSDL endpoints
   -Software Vulnerability Scanner: detect vulnerable client-side JS

6. Collaboration:
   - Burp Suite Enterprise: scheduled scans
   - Project file sharing: team collaboration
   - Scan data export: JSON, XML, HTML reports
```

### 4.2 OWASP ZAP

```bash
# ZAP automated scanning workflow
# Step 1: Start ZAP in daemon mode
zap-x.sh -daemon -port 8080 -config api.key=zap-api-key

# Step 2: Spider the target
curl "http://localhost:8080/JSON/spider/action/scan/?zapapiformat=JSON&apikey=zap-api-key&url=https://target.com&maxChildren=&recurse=true"

# Step 3: Active scan
curl "http://localhost:8080/JSON/ascan/action/scan/?zapapiformat=JSON&apikey=zap-api-key&url=https://target.com&recurse=true"

# Step 4: Get alerts
curl "http://localhost:8080/JSON/core/view/alerts/?zapapiformat=JSON&apikey=zap-api-key&baseurl=https://target.com" | jq '.alerts[] | {alert: .alert, risk: .risk, confidence: .confidence, url: .url, param: .param, evidence: .evidence}'

# Step 5: Generate report
curl "http://localhost:8080/OTHER/core/other/htmlreport/?apikey=zap-api-key" > zap-report.html
```

### 4.3 Nuclei

```bash
# Nuclei — template-based vulnerability scanner
# Scan with all templates
nuclei -u https://target.com -t /nuclei-templates/ -severity critical,high,medium

# Specific vulnerability categories
nuclei -u https://target.com -t /nuclei-templates/cves/ -severity critical
nuclei -u https://target.com -t /nuclei-templates/vulnerabilities/
nuclei -u https://target.com -t /nuclei-templates/misconfiguration/
nuclei -u https://target.com -t /nuclei-templates/exposures/
nuclei -u https://target.com -t /nuclei-templates/takeovers/

# Custom template for specific vulnerabilities
cat > custom-template.yaml << 'EOF'
id: custom-sqli

info:
  name: Custom SQL Injection Test
  severity: high
  description: Tests for SQL injection in the search parameter

http:
  - method: GET
    path:
      - "{{BaseURL}}/search?q=test"
      - "{{BaseURL}}/search?q=test'"
      - "{{BaseURL}}/search?q=test'+OR+1%3D1--"
    matchers-condition: or
    matchers:
      - type: status
        status:
          - 500
      - type: word
        words:
          - "SQL syntax"
          - "mysql_fetch"
          - "ORA-01756"
          - "Microsoft OLE DB"
EOF

nuclei -u https://target.com -t custom-template.yaml

# Scan multiple targets
cat targets.txt | nuclei -t /nuclei-templates/ -severity critical,high

# Output formats
nuclei -u https://target.com -t /nuclei-templates/ -json -o results.json
nuclei -u https://target.com -t /nuclei-templates/ -sarif -o results.sarif
nuclei -u https://target.com -t /nuclei-templates/ -markdown -o results.md
```

---

## 5. Manual Testing Techniques

### 5.1 Authentication Testing Checklist

```
Authentication Testing:
━━━━━━━━━━━━━━━━━━━━━━

□ Test for default credentials (admin/admin, root/root, etc.)
□ Test for weak password policy (minimum length, complexity, history)
□ Test for username enumeration (different responses for valid/invalid users)
□ Test account lockout mechanism (brute force resistance)
□ Test password reset flow (token predictability, expiration, secure delivery)
□ Test remember-me functionality (cookie security, token strength)
□ Test session management (session ID entropy, timeout, regeneration)
□ Test multi-factor authentication bypass (direct API access, OTP reuse, brute force)
□ Test OAuth/OIDC flows (redirect URI validation, PKCE, token leakage)
□ Test JWT security (algorithm confusion, none algorithm, weak secrets, jku/x5u)
□ Test SAML security (signature wrapping, assertion replay, comment injection)
□ Test credential stuffing resistance (rate limiting, CAPTCHA, IP blocking)
□ Test concurrent session handling (can same user login twice?)
□ Test password change functionality (old password required, notification)
□ Test account deletion (confirmation, data retention)
```

### 5.2 Authorization Testing Checklist

```
Authorization Testing:
━━━━━━━━━━━━━━━━━━━━━

□ Test vertical privilege escalation (user → admin)
□ Test horizontal privilege escalation (user A → user B's data)
□ Test IDOR across all object types (users, orders, documents, etc.)
□ Test forceful browsing (direct access to admin pages)
□ Test parameter tampering (role=admin, is_admin=true)
□ Test mass assignment (adding unexpected fields to requests)
□ Test API endpoint authorization (same endpoint, different roles)
□ Test CORS configuration (Access-Control-Allow-Origin, credentials)
□ Test file-based authorization (can user A download user B's file?)
□ Test feature-level authorization (can user access admin features?)
□ Test multi-tenancy authorization (can user access other tenant's data?)
□ Test time-based authorization (can user access data outside allowed hours?)
□ Test IP-based authorization (can user access from unauthorized IP?)
□ Test rate limiting per role (admin vs. user rate limits?)
```

### 5.3 Injection Testing Checklist

```
Injection Testing:
━━━━━━━━━━━━━━━━━━━

□ SQL injection (all input vectors: URL params, form fields, headers, cookies)
  □ Union-based
  □ Boolean-based blind
  □ Time-based blind
  □ Out-of-band
  □ Second-order
  □ Error-based

□ NoSQL injection (MongoDB, CouchDB, Redis)
  □ Operator injection ($ne, $gt, $regex, $where)
  □ Type confusion (string vs. object)
  □ JavaScript injection in $where

□ LDAP injection
  □ Authentication bypass
  □ Information disclosure
  □ Blind extraction

□ XPath injection
  □ Authentication bypass
  □ Blind extraction

□ OS command injection
  □ Command separators (;, |, &&, ||, \n)
  □ Filter bypass (encoding, alternative commands)
  □ Blind injection (DNS, HTTP, timing)

□ Server-side template injection
  □ Jinja2, Twig, Freemarker, ERB, Mako, Expression Language
  □ Detection methodology (mathematical expressions, string operations)
  □ RCE exploitation

□ LDAP injection
□ XML injection / XXE
□ Header injection (CRLF)
□ Expression Language injection
□ SSTI (Server-Side Template Injection)
□ SSI (Server-Side Includes)
```

---

## 6. API Security Testing Workflow

```bash
# Step 1: API Documentation Discovery
# Check for Swagger/OpenAPI documentation
for path in /swagger-ui.html /swagger-ui/ /api-docs /v2/api-docs /v3/api-docs /api/swagger /swagger.json /openapi.json /openapi.yaml /api/v1/docs /docs /redoc /graphql /graphiql; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$path")
  if [ "$status" = "200" ]; then
    echo "[+] Found: $path ($status)"
  fi
done

# Step 2: API Endpoint Enumeration
# Use API documentation or fuzzing
ffuf -u https://target.com/api/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,401,403,405 -fc 404

# Step 3: Authentication Testing
# Test with no authentication
curl -s https://target.com/api/v1/users | jq .

# Test with various auth methods
curl -s -H "Authorization: Bearer TOKEN" https://target.com/api/v1/users | jq .
curl -s -H "X-API-Key: APIKEY" https://target.com/api/v1/users | jq .
curl -s -H "Cookie: session=SESSION" https://target.com/api/v1/users | jq .

# Step 4: CRUD Testing (for each endpoint, test all HTTP methods)
for method in GET POST PUT PATCH DELETE OPTIONS; do
  for endpoint in /api/v1/users /api/v1/orders /api/v1/products /api/v1/admin; do
    status=$(curl -s -o /dev/null -w "%{http_code}" -X $method "https://target.com$endpoint" \
      -H "Authorization: Bearer $TOKEN")
    if [ "$status" != "404" ] && [ "$status" != "405" ]; then
      echo "[$method] $endpoint → $status"
    fi
  done
done

# Step 5: IDOR Testing
for id in 1 2 3 100 999 admin superadmin; do
  curl -s -H "Authorization: Bearer $TOKEN" "https://target.com/api/v1/users/$id" | jq .
done

# Step 6: Rate Limiting Testing
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST "https://target.com/api/v1/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong'$i'"}'
done

# Step 7: GraphQL-specific Testing
# Introspection query
curl -s -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name,fields{name}}}}"}' \
  https://target.com/graphql | jq .

# Query depth attack
curl -s -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"{user(id:1){posts{comments{author{posts{comments{author{name}}}}}}}}"}' \
  https://target.com/graphql

# Batch query attack
curl -s -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '[{"query":"{user(id:1){name}}"},{"query":"{user(id:2){name}}"},...]' \
  https://target.com/graphql
```

---

## 7. Source Code Review Methodology

### 7.1 Systematic Code Review Approach

```bash
# Step 1: Identify technology stack
find . -name "package.json" -o -name "requirements.txt" -o -name "pom.xml" \
       -o -name "Gemfile" -o -name "go.mod" -o -name "composer.json" | head -20

# Step 2: Search for security-relevant patterns (Semgrep)
semgrep --config p/owasp-top-ten .
semgrep --config p/sql-injection .
semgrep --config p/xss .
semgrep --config p/command-injection .
semgrep --config p/jwt .
semgrep --config p/crypto .

# Step 3: Manual code review patterns

# SQL injection patterns
rg -n "execute\(|raw\(|cursor\.|\.query\(|\.raw\(" --type py --type java --type php
rg -n "f\".*SELECT|f\".*INSERT|f\".*UPDATE|f\".*DELETE" --type py
rg -n "\$.*SELECT|\$.*INSERT|\$.*UPDATE|\$.*DELETE" --type php

# XSS patterns
rg -n "innerHTML|outerHTML|document\.write|v-html|dangerouslySetInnerHTML" --type js --type ts
rg -n "\|\s*safe\b|markSafe\|\s*markdown\(|\|\s*raw\b" --type py --type html

# Authentication patterns
rg -n "password|secret|token|api_key|apikey|credential" --type py --type js --type java -i
rg -n "jwt\.encode|jwt\.decode|JWT\.create|JWT\.require" --type py --type java

# Hardcoded secrets
rg -n "(password|secret|key|token|api_key|apikey)\s*=\s*['\"]" --type py --type js --type java -i
rg -n "AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|STRIP_SECRET|DATABASE_URL" -i

# Command injection patterns
rg -n "os\.system|subprocess\.call|subprocess\.run|exec\(|eval\(" --type py
rg -n "Runtime\.getRuntime\(\)|ProcessBuilder" --type java
rg -n "system\(|exec\(|passthru\(|shell_exec\(|popen\(" --type php

# File inclusion patterns
rg -n "include\(|require\(|include_once\(|require_once\(" --type php
rg -n "open\(|read\(|readlines\(|send_file" --type py

# SSRF patterns
rg -n "requests\.get\(|urlopen\(|fetch\(|http\.Get\(|axios\.get\(" --type py --type js --type go
rg -n "url.*=.*request\.(get|args|form|json)" --type py
```

### 7.2 Blind Testing Approach

When source code is not available, apply a systematic black-box methodology:

```python
# Blind testing workflow
class BlindWebTester:
    def __init__(self, target_url):
        self.target = target_url
        self.findings = []
    
    def test_all_endpoints(self):
        """Systematic endpoint testing."""
        endpoints = self.discover_endpoints()
        for endpoint in endpoints:
            self.test_authentication(endpoint)
            self.test_authorization(endpoint)
            self.test_input_validation(endpoint)
            self.test_injection(endpoint)
            self.test_error_handling(endpoint)
            self.test_rate_limiting(endpoint)
    
    def test_authentication(self, endpoint):
        """Test authentication mechanisms."""
        # Unauthenticated access
        resp = requests.get(endpoint)
        if resp.status_code == 200:
            self.findings.append({"type": "missing_auth", "endpoint": endpoint})
        
        # Invalid token
        resp = requests.get(endpoint, headers={"Authorization": "Bearer invalid"})
        if resp.status_code == 200:
            self.findings.append({"type": "token_validation", "endpoint": endpoint})
        
        # Expired token
        resp = requests.get(endpoint, headers={"Authorization": "Bearer expired_token"})
        if resp.status_code == 200:
            self.findings.append({"type": "expired_token_accepted", "endpoint": endpoint})
    
    def test_injection(self, endpoint):
        """Test for injection vulnerabilities."""
        params = self.discover_parameters(endpoint)
        for param in params:
            # SQL injection
            for payload in ["' OR 1=1--", "\" OR 1=1--", "1' OR '1'='1", "1; WAITFOR DELAY '0:0:5'--"]:
                resp = requests.get(endpoint, params={param: payload})
                if self.indicates_sqli(resp):
                    self.findings.append({"type": "sql_injection", "endpoint": endpoint, "param": param})
            
            # XSS
            for payload in ["<script>alert(1)</script>", '"><script>alert(1)</script>', "javascript:alert(1)"]:
                resp = requests.get(endpoint, params={param: payload})
                if payload in resp.text:
                    self.findings.append({"type": "xss", "endpoint": endpoint, "param": param})
            
            # SSRF
            for payload in ["http://127.0.0.1", "http://169.254.169.254", "http://localhost"]:
                resp = requests.get(endpoint, params={param: payload})
                if self.indicates_ssrf(resp):
                    self.findings.append({"type": "ssrf", "endpoint": endpoint, "param": param})
```

---

## Cross-Reference Guide

| Topic | Cross-Reference |
|-------|-----------------|
| OWASP Top 10 categories | `01b_owasp_top10_deep_dive.md` |
| Injection testing | `02a_injection_attacks.md` |
| Authentication testing | `02b_authentication_authorization.md` |
| SSRF testing | `03a_ssrf_csrflfi.md` |
| API testing | `03b_api_security.md` |
| Client-side testing | `04a_client_side_security.md` |
| WAF bypass methodology | `05b_waf_bypass_techniques.md` |
| Hardening | `06b_web_hardening_defense.md` |
| Future testing tools | `07_web_security_future.md` |

---

*Web security testing requires a systematic approach that combines automated scanning for breadth with manual testing for depth. DAST finds known vulnerabilities quickly, SAST finds code-level issues comprehensively, and IAST bridges the gap with runtime analysis. But no tool replaces the intuition and creativity of a skilled tester who understands the application's business logic and can chain vulnerabilities into impactful exploits.*

---

## References

1. OWASP Foundation. "OWASP Testing Guide v4." https://owasp.org/www-project-web-security-testing-guide/
2. OWASP Foundation. "OWASP Application Security Verification Standard (ASVS) 4.0." https://owasp.org/www-project-application-security-verification-standard/
3. PTES. "Penetration Testing Execution Standard." http://www.pentest-standard.org/
4. PortSwigger Ltd. "Burp Suite Professional." https://portswigger.net/burp/pro
5. ZAP. "OWASP Zed Attack Proxy." https://www.zaproxy.org/
6. Nuclei Project. "Nuclei: Fast and Customizable Vulnerability Scanner." https://github.com/projectdiscovery/nuclei
7. OWASP Foundation. "OWASP Dependency-Check." https://owasp.org/www-project-dependency-check/
8. OWASP Foundation. "OWASP ZAP API Testing." https://www.zaproxy.org/docs/docker/
9. Snyk. "Static Application Security Testing." https://snyk.io/learn/sast-static-application-security-testing/
10. OWASP Foundation. "DAST vs SAST vs IAST." https://owasp.org/www-community/Source_Code_Analysis_Tools
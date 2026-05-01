# Web Application Hardening: Defense in Depth

## 1. HTTP Security Headers

### 1.1 Content-Security-Policy (CSP)

CSP is the most powerful client-side security header, controlling which resources the browser may load and execute:

```http
# Comprehensive CSP for a modern web application
Content-Security-Policy: 
  default-src 'self';
  script-src 'self' 'nonce-{random}' https://cdn.example.com;
  style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
  img-src 'self' data: https:;
  font-src 'self' https://fonts.gstatic.com;
  connect-src 'self' https://api.example.com wss://ws.example.com;
  media-src 'self' https://cdn.example.com;
  object-src 'none';
  frame-src 'none';
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self' https://auth.example.com;
  manifest-src 'self';
  worker-src 'self';
  report-uri /csp-report;
  report-to csp-violation;
```

CSP directive security analysis:

| Directive | Recommended Value | Risk if Misconfigured |
|-----------|-------------------|----------------------|
| `default-src` | `'self'` | Overly permissive fallback if other directives are missing |
| `script-src` | `'self' 'nonce-{random}'` | `'unsafe-inline'` enables inline XSS; `'unsafe-eval'` enables eval() |
| `style-src` | `'self' 'unsafe-inline'` | `'unsafe-inline'` required for many frameworks; CSS exfiltration possible |
| `img-src` | `'self' data: https:` | `data:` enables embedded images; `*` enables tracking pixels |
| `connect-src` | `'self' https://api.example.com` | `*` allows data exfiltration via fetch/XHR |
| `object-src` | `'none'` | If not set, Flash/PDF vulnerabilities can execute |
| `frame-ancestors` | `'none'` | Replaces X-Frame-Options; prevents clickjacking |
| `base-uri` | `'self'` | If not set, `<base>` tag hijacking can redirect all relative URLs |
| `form-action` | `'self'` | If not set, forms can submit to any URL |
| `report-uri` | `/csp-report` | Must be same-origin for violation reports to work |

```python
# CSP implementation in Python (Flask)
from flask import Flask, make_response
import secrets

app = Flask(__name__)

@app.after_request
def set_csp(response):
    nonce = secrets.token_hex(16)  # Generate per-request nonce
    csp = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' https://cdn.example.com; "
        f"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        f"img-src 'self' data: https:; "
        f"font-src 'self' https://fonts.gstatic.com; "
        f"connect-src 'self' https://api.example.com wss://ws.example.com; "
        f"object-src 'none'; "
        f"frame-ancestors 'none'; "
        f"base-uri 'self'; "
        f"form-action 'self' https://auth.example.com; "
        f"report-uri /csp-report"
    )
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), payment=()'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    # Store nonce for use in templates
    response.set_cookie('csp-nonce', nonce, secure=True, httponly=True, samesite='strict')
    return response
```

```html
<!-- Using CSP nonce in templates -->
<script nonce="{{ csp_nonce }}">
    // This script is allowed by CSP because it has the correct nonce
    console.log('CSP-allowed script');
</script>

<!-- Scripts without the correct nonce will be blocked by CSP -->
<script>
    // BLOCKED: No nonce attribute
    console.log('This will be blocked');
</script>
```

### 1.2 HSTS (HTTP Strict Transport Security)

```http
# Basic HSTS
Strict-Transport-Security: max-age=31536000

# Recommended: Include subdomains and preload
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload

# HSTS lifecycle:
# 1. First visit: Browser sees HSTS header (no HTTPS yet guaranteed)
# 2. Subsequent visits: Browser forces HTTPS for max-age seconds
# 3. includeSubDomains: HTTPS required for all subdomains
# 4. preload: Submit to hstspreload.org → browsers force HTTPS without first visit
#    (Eliminates the initial HTTP request vulnerability)

# HSTS implementation considerations:
# - Must be served over HTTPS (HTTP responses with HSTS are ignored)
# - max-age should be at least 1 year (31536000 seconds), preferably 2 years
# - includeSubDomains requires HTTPS on ALL subdomains
# - preload submission is permanent (removal takes months)
# - Cannot be revoked easily (users must clear browser HSTS state)
```

### 1.3 X-Frame-Options and Frame-Ancestors

```http
# X-Frame-Options (legacy, still recommended for backward compatibility)
X-Frame-Options: DENY           # Never allow framing (most secure)
X-Frame-Options: SAMEORIGIN     # Allow framing from same origin only

# Content-Security-Policy frame-ancestors (modern replacement)
Content-Security-Policy: frame-ancestors 'none'           # Equivalent to DENY
Content-Security-Policy: frame-ancestors 'self'            # Equivalent to SAMEORIGIN
Content-Security-Policy: frame-ancestors 'self' https://trusted.com  # Specific origins

# Recommendation: Set both headers for maximum compatibility
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'
```

### 1.4 Permissions Policy

```http
# Permissions Policy (formerly Feature-Policy)
# Controls which browser APIs the page can use
Permissions-Policy: 
  camera=(),
  microphone=(),
  geolocation=(),
  payment=(),
  usb=(),
  magnetometer=(),
  gyroscope=(),
  accelerometer=(),
  fullscreen=(self),
  autoplay=(self)

# Allow specific origins:
Permissions-Policy: camera=https://trusted-video.example.com, microphone=https://trusted-audio.example.com

# Allow all origins:
Permissions-Policy: geolocation=*
```

---

## 2. Input Validation Strategy

### 2.1 Defense in Depth for Input Handling

```
Input Validation Layers:
━━━━━━━━━━━━━━━━━━━━━━━

Layer 1: Client-side validation (UX improvement, NOT security)
  - HTML5 form validation (required, pattern, min, max)
  - JavaScript validation (immediate feedback)
  - DOES NOT provide security (easily bypassed)

Layer 2: API gateway / WAF validation
  - Rate limiting
  - Request size limits
  - Pattern-based attack detection
  - Helps but doesn't replace application validation

Layer 3: Application-level validation (PRIMARY security)
  - Type checking (integer, string, date, etc.)
  - Range checking (min/max values)
  - Length checking (string min/max length)
  - Whitelist validation (regex patterns)
  - Business logic validation (domain rules)

Layer 4: Database-level constraints
  - Column types (INT, VARCHAR, DATE)
  - NOT NULL constraints
  - CHECK constraints
  - FOREIGN KEY constraints
  - UNIQUE constraints
```

```python
# Comprehensive input validation (Python/Pydantic)
from pydantic import BaseModel, EmailStr, constr, conint, field_validator
import re

class UserCreateRequest(BaseModel):
    """Validated user creation request."""
    username: constr(min_length=3, max_length=32, pattern=r'^[a-zA-Z0-9_-]+$')
    email: EmailStr
    password: constr(min_length=12, max_length=128)
    age: conint(ge=18, le=120)
    role: str = "user"  # Default role, not acceptible from client
    
    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v):
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'[0-9]', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        # Check against common passwords
        if v.lower() in COMMON_PASSWORDS:
            raise ValueError('Password is too common')
        return v
    
    @field_validator('role')
    @classmethod
    def validate_role(cls, v):
        # NEVER accept role from client input - use default or derive from auth context
        raise ValueError('Role cannot be set from client input')

class SearchRequest(BaseModel):
    """Validated search request."""
    query: constr(min_length=1, max_length=200, pattern=r'^[a-zA-Z0-9\s\-,.]+$')
    page: conint(ge=1, le=1000) = 1
    per_page: conint(ge=1, le=100) = 20
    sort_by: str = "relevance"  # Whitelist validated below
    
    @field_validator('sort_by')
    @classmethod
    def validate_sort_by(cls, v):
        allowed_sort = {"relevance", "date", "popularity", "price_asc", "price_desc"}
        if v not in allowed_sort:
            raise ValueError(f'sort_by must be one of: {", ".join(allowed_sort)}')
        return v
```

### 2.2 Output Encoding

Output encoding prevents injection by escaping special characters for the correct output context:

```python
# Context-specific output encoding
import html
import json
import re

def encode_for_html(data):
    """Encode data for HTML body, attribute, or element context."""
    return html.escape(str(data), quote=True)

def encode_for_html_attribute(data):
    """Encode data for HTML attribute context (more aggressive)."""
    data = html.escape(str(data), quote=True)
    # Also encode special characters that might break out of attributes
    return data

def encode_for_javascript(data):
    """Encode data for JavaScript string context."""
    return json.dumps(str(data))

def encode_for_css(data):
    """Encode data for CSS context (property values)."""
    return re.sub(r'[^a-zA-Z0-9-_]', r'\\\000026', str(data))

def encode_for_url(data):
    """Encode data for URL context (query parameters)."""
    import urllib.parse
    return urllib.parse.quote(str(data), safe='')

def encode_for_xml(data):
    """Encode data for XML context."""
    data = str(data)
    data = data.replace('&', '&amp;')
    data = data.replace('<', '&lt;')
    data = data.replace('>', '&gt;')
    data = data.replace('"', '&quot;')
    data = data.replace("'", '&apos;')
    return data

# Template engine auto-escaping (preferred approach)
# Jinja2 defaults to auto-escaping in .html files:
# {{ user_input }}  → HTML-escaped
# {{ user_input|safe }}  → NOT escaped ( developer explicitly marks as safe)
# {{ user_input|tojson }}  → JSON-encoded (for JavaScript context)

# Auto-encoding by context:
# HTML body:     <div>{{ user_input }}</div>           → &lt;script&gt;alert(1)&lt;/script&gt;
# HTML attr:     <div title="{{ user_input }}">         → &lt;script&gt;alert(1)&lt;/script&gt;
# JavaScript:   var data = {{ user_input|tojson }};     → "\u003Cscript\u003Ealert(1)\u003C/script\u003E"
# URL:          <a href="/search?q={{ user_input|urlencode }}"> → %3Cscript%3Ealert(1)%3C/script%3E
# CSS:           <div style="color: {{ user_input|css_encode }}"> → \3C script\3E
```

---

## 3. Parameterized Queries and ORM Security

### 3.1 Parameterized Queries

```python
# VULNERABLE: String formatting in SQL queries
def get_user_vulnerable(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    # Attack: username = "admin' OR '1'='1"
    # Query: SELECT * FROM users WHERE username = 'admin' OR '1'='1'
    return db.execute(query)

# SECURE: Parameterized queries
def get_user_secure(username):
    query = "SELECT * FROM users WHERE username = %s"
    return db.execute(query, (username,))
    # The database driver properly escapes the parameter
    # No SQL injection possible regardless of input

# Django ORM (automatically parameterized)
user = User.objects.filter(username=username)  # Safe
user = User.objects.raw("SELECT * FROM users WHERE username = %s", [username])  # Safe

# SQLAlchemy (parameterized)
from sqlalchemy import text
result = db.session.execute(text("SELECT * FROM users WHERE username = :username"), {"username": username})

# VULNERABLE: SQLAlchemy string formatting
result = db.session.execute(text(f"SELECT * FROM users WHERE username = '{username}'"))  # UNSAFE

# Java PreparedStatement (parameterized)
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
stmt.setString(1, username);  // Parameterized, safe

// VULNERABLE: Java string concatenation
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE username = '" + username + "'");  // UNSAFE
```

### 3.2 ORM Security Consider

```python
# Django ORM: Safe by default, but can be vulnerable with raw queries

# SAFE: ORM query
User.objects.filter(username=username)

# SAFE: Parameterized raw query
User.objects.raw("SELECT * FROM auth_user WHERE username = %s", [username])

# UNSAFE: Format string in raw query
User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{username}'")

# SAFE: ORM with extra() and parameters
User.objects.extra(where=["username = %s"], params=[username])

# UNSAFE: extra() with string interpolation
User.objects.extra(where=[f"username = '{username}'"])

# SAFE: Q objects for dynamic queries
from django.db.models import Q
filters = Q(username=username)
User.objects.filter(filters)

# SQLAlchemy ORM considerations

# SAFE: ORM query
session.query(User).filter(User.username == username)

# SAFE: Core with parameters
session.execute(text("SELECT * FROM users WHERE username = :username"), {"username": username})

# UNSAFE: String interpolation
session.execute(f"SELECT * FROM users WHERE username = '{username}'")

# IMPORTANT: ORM doesn't protect against mass assignment
# SAFE: Explicit field inclusion
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']  # Whitelist
        # NEVER use fields = '__all__' with models containing sensitive fields

# UNSAFE: Exclude approach (new sensitive fields are included by default)
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        exclude = ['password', 'is_superuser']  # If new sensitive field added, it's included by default
```

---

## 4. Secure Session Management

```python
# Flask secure session configuration
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')  # Must be cryptographically random
app.config['SESSION_COOKIE_SECURE'] = True     # HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True    # No JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'   # Cross-site protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Session timeout
app.config['SESSION_PERMANENT'] = False         # Not permanent by default

# Django secure session configuration
# settings.py
SESSION_ENGINE = 'django.contrib.sessions.backends.db'  # Database-backed sessions
SESSION_COOKIE_SECURE = True     # HTTPS only
SESSION_COOKIE_HTTPONLY = True    # No JavaScript access
SESSION_COOKIE_SAMESITE = 'Lax'  # Cross-site protection
SESSION_COOKIE_AGE = 3600        # 1 hour timeout
SESSION_SAVE_EVERY_REQUEST = True # Refresh session on each request

# Custom session management
import secrets
from datetime import datetime, timedelta

class SessionManager:
    def __init__(self, redis_client, session_timeout=3600):
        self.redis = redis_client
        self.timeout = session_timeout
    
    def create_session(self, user_id, additional_data=None):
        session_id = secrets.token_hex(32)  # 256-bit random session ID
        session_data = {
            'user_id': user_id,
            'created_at': datetime.utcnow().isoformat(),
            'ip_address': additional_data.get('ip_address'),
            'user_agent': additional_data.get('user_agent'),
        }
        self.redis.setex(
            f'session:{session_id}',
            self.timeout,
            json.dumps(session_data)
        )
        return session_id
    
    def validate_session(self, session_id, request_ip=None, request_ua=None):
        data = self.redis.get(f'session:{session_id}')
        if not data:
            return None
        session = json.loads(data)
        
        # Validate IP and User-Agent (optional, for session hijacking prevention)
        if request_ip and session.get('ip_address') != request_ip:
            # IP changed — could be legitimate (mobile network switch)
            # Log the event for anomaly detection
            pass
        
        if request_ua and session.get('user_agent') != request_ua:
            # User-Agent changed — more suspicious
            return None  # Invalidate session
        
        return session
    
    def destroy_session(self, session_id):
        self.redis.delete(f'session:{session_id}')
```

---

## 5. CORS Hardening

```python
# Flask CORS hardening
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)

# Option 1: Specific origin (most secure)
CORS(app, origins=['https://app.example.com'],
     methods=['GET', 'POST', 'PUT', 'DELETE'],
     allow_headers=['Content-Type', 'Authorization'],
     expose_headers=['X-Request-ID'],
     supports_credentials=True,
     max_age=86400)

# Option 2: Custom CORS per endpoint
@app.route('/api/data')
def get_data():
    origin = request.headers.get('Origin')
    allowed_origins = ['https://app.example.com', 'https://admin.example.com']
    
    if origin in allowed_origins:
        response = jsonify(data)
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.headers['Access-Control-Max-Age'] = '86400'
        response.headers['Vary'] = 'Origin'  # Critical: prevent caching issues
        return response
    
    return jsonify({'error': 'CORS not allowed'}), 403

# NEVER DO THIS: Reflect any origin with credentials
@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin')
    if origin:  # REFLECTS ANY ORIGIN WITH CREDENTIALS — VULNERABLE!
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response
```

---

## 6. Rate Limiting Implementation

```python
# Rate limiting with Redis and Flask
from flask import Flask, request, jsonify
import redis
import time

app = Flask(__name__)
redis_client = redis.Redis(host='localhost', port=6379, db=0)

class RateLimiter:
    def __init__(self, redis_client, key_prefix='rate_limit'):
        self.redis = redis_client
        self.prefix = key_prefix
    
    def check_rate_limit(self, identifier, limit=100, window=60):
        """Sliding window rate limiter.
        
        Args:
            identifier: Unique identifier (IP, user_id, API key)
            limit: Maximum requests per window
            window: Time window in seconds
        
        Returns:
            tuple: (allowed: bool, remaining: int, reset_time: int)
        """
        key = f'{self.prefix}:{identifier}'
        now = time.time()
        window_start = now - window
        
        # Remove old entries and add new one
        pipe = self.redis.pipeline()
        pipe.zremrangebyscore(key, 0, window_start)
        pipe.zadd(key, {str(now): now})
        pipe.zcard(key)
        pipe.expire(key, window)
        results = pipe.execute()
        
        current_count = results[2]
        remaining = max(0, limit - current_count)
        
        return current_count <= limit, remaining, int(now + window)
    
    def check_progressive_delay(self, identifier, base_delay=1, max_delay=3600):
        """Progressive delay for authentication attempts.
        
        Each failed attempt doubles the delay, up to max_delay seconds.
        """
        key = f'{self.prefix}:delay:{identifier}'
        attempts = self.redis.get(key)
        
        if attempts is None:
            self.redis.setex(key, max_delay, 1)
            return 0  # No delay on first attempt
        
        attempts = int(attempts)
        delay = min(base_delay * (2 ** attempts), max_delay)
        
        self.redis.incr(key)
        self.redis.expire(key, max_delay)
        
        return delay

# Rate limiting middleware
limiter = RateLimiter(redis_client)

@app.before_request
def rate_limit_check():
    # Get identifier (IP for anonymous, user_id for authenticated)
    if hasattr(request, 'user'):
        identifier = f'user:{request.user.id}'
    else:
        identifier = f'ip:{request.remote_addr}'
    
    # Different limits for different endpoints
    if request.path.startswith('/api/auth/login'):
        allowed, remaining, reset_time = limiter.check_rate_limit(
            identifier, limit=5, window=300)  # 5 per 5 minutes
    elif request.path.startswith('/api/'):
        allowed, remaining, reset_time = limiter.check_rate_limit(
            identifier, limit=100, window=60)  # 100 per minute
    else:
        allowed, remaining, reset_time = limiter.check_rate_limit(
            identifier, limit=300, window=60)  # 300 per minute
    
    if not allowed:
        response = jsonify({'error': 'Rate limit exceeded'})
        response.headers['X-RateLimit-Remaining'] = str(remaining)
        response.headers['X-RateLimit-Reset'] = str(reset_time)
        response.headers['Retry-After'] = str(reset_time - int(time.time()))
        return response, 429
    
    # Add rate limit headers to successful responses
    # (Implemented in after_request)
```

---

## 7. WAF Configuration Best Practices

```nginx
# ModSecurity core rules (nginx configuration)
# /etc/nginx/modsecurity/modsecurity.conf

SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off  # Don't inspect responses (performance)
SecRequestBodyLimit 13107200  # 12.5MB max request body
SecRequestBodyNoFilesLimit 131072  # 128KB max non-file body
SecRequestBodyInMemoryLimit 131072  # 128KB in-memory limit

# Rule exclusions for false positives
SecRuleRemoveById 942100  # Exclude specific rule if false positive

# Custom rules
# Block known malicious IPs
SecRule REMOTE_ADDR "@ipMatch 192.168.1.100,10.0.0.50" "id:1000,deny,status:403,msg:'Blocked IP'"

# Block requests with suspicious User-Agent
SecRule REQUEST_HEADERS:User-Agent "@contains curl" "id:1001,deny,status:403,msg:'Curl blocked'"

# Custom SQL injection rule (beyond CRS)
SecRule REQUEST_URI|REQUEST_BODY "@rx (?i:union\s+select\s+.*\s+from\s+.*)" "id:2000,deny,status:403,msg:'Custom SQLi rule'"

# Geo-blocking (block specific countries)
# SecRule GEO:COUNTRY_CODE "@streq CN RU" "id:3000,deny,status:403,msg:'Country blocked'"
```

```nginx
# Nginx security headers and rate limiting
server {
    listen 443 ssl http2;
    server_name example.com;
    
    # TLS configuration (Mozilla Modern profile)
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    
    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "0" always;  # Deprecated, use CSP instead
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;
    
    # General rate limiting
    limit_req zone=general burst=20 nodelay;
    
    location /api/auth/login {
        limit_req zone=auth burst=3 nodelay;
        # Progressive delay for failed auth (implemented in application)
        proxy_pass http://backend;
    }
    
    location /api/ {
        limit_req zone=api burst=50 nodelay;
        proxy_pass http://backend;
    }
    
    # Block suspicious paths
    location ~ /\.(git|svn|hg|env) {
        deny all;
        return 404;
    }
    
    # Block common attack paths
    location ~*(wp-admin|wp-login|phpmyadmin|phpmy|pma|admin|manager|console) {
        deny all;
        return 404;
    }
}
```

---

## 8. HTTPS Configuration

```nginx
# Mozilla SSL Configuration Generator - Modern profile
# https://ssl-config.mozilla.org/

server {
    listen 443 ssl http2;
    server_name example.com;
    
    # Certificate
    ssl_certificate /etc/ssl/certs/example.com.crt;
    ssl_certificate_key /etc/ssl/private/example.com.key;
    
    # Modern TLS configuration (TLS 1.3 only)
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/ssl/certs/example.com-chain.crt;
    resolver 1.1.1.1 8.8.8.8 valid=300s;
    resolver_timeout 5s;
    
    # Session settings
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    
    # Redirect HTTP to HTTPS
    error_page 497 301 =307 https://$host:$server_port$request_uri;
}

server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}
```

### 8.1 Testing TLS Configuration

```bash
# Comprehensive TLS testing with testssl.sh
testssl.sh --full --severity LOW --cdn example.com

# Key checks:
# - TLS 1.3 only (Modern), TLS 1.2+ (Intermediate)
# - No TLS 1.0, 1.1 (deprecated, insecure)
# - No RC4, DES, 3DES cipher suites
# - No SHA-1 certificates
# - No EXPORT cipher suites (FREAK attack)
# - Forward secrecy (ECDHE key exchange)
# - No heartbleed (CVE-2014-0160)
# - HSTS configured
# - Certificate transparency
# - OCSP stapling

# SSLyze for automated testing
python -m sslyze --regular example.com

# nmap SSL scan
nmap --script ssl-enum-ciphers -p 443 example.com

# openssl manual testing
openssl s_client -connect example.com:443 -tls1_3
openssl s_client -connect example.com:443 -tls1_2
openssl s_client -connect example.com:443 -tls1_1  # Should fail
openssl s_client -connect example.com:443 -tls1    # Should fail
```

---

## 9. Dependency Scanning and SAST Integration

### 9.1 Dependency Scanning

```bash
# npm audit (Node.js)
npm audit
npm audit --json > npm-audit.json
npm audit fix  # Auto-fix where possible

# Snyk (multi-language)
snyk test --severity-threshold=high
snyk monitor  # Continuous monitoring
snyk code test  # SAST testing

# Dependabot (GitHub)
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
    open-pull-requests-limit: 10
    
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "daily"
    
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"

# Python pip audit
pip audit --requirements requirements.txt

# OWASP Dependency-Check (Java)
dependency-check-maven --out . --scan target/
dependency-check --scan . --format JSON --out dependency-check-report.json
```

### 9.2 SAST Integration in CI/CD

```yaml
# GitHub Actions SAST integration
name: Security Scanning
on: [push, pull_request]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/owasp-top-ten
            p/xss
            p/sql-injection
            p/command-injection
            p/jwt
            p/crypto

  codeql:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: github/codeql-action/init@v2
        with:
          languages: python, javascript
      - uses: github/codeql-action/analyze@v2

  npm-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: npm ci
      - run: npm audit --audit-level=high

  pip-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: pip install pip-audit
      - run: pip-audit --requirements requirements.txt

  docker-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: docker build -t app:latest .
      - uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'app:latest'
          format: 'table'
          exit-code: '1'
          severity: 'CRITICAL,HIGH'
```

---

## 10. Secure Coding Checklist

```
Input Validation:
━━━━━━━━━━━━━━━
□ All inputs validated on server side (never trust client-side validation alone)
□ Whitelist validation used (not blacklist)
□ Input length limits enforced (string, numeric range)
□ Input type checking (integer, string, date, enum)
□ File upload validation (type, size, content, extension)
□ URL validation (scheme, host, path — no SSRF targets)
□ JSON/XML parsing with safe parsers (no entity expansion)
□ File path validation (no path traversal)

Output Encoding:
━━━━━━━━━━━━━━━
□ HTML context: HTML entity encoding
□ JavaScript context: JSON encoding
□ CSS context: CSS escaping
□ URL context: URL encoding
□ SQL context: parameterized queries (not encoding)
□ Shell context: escapeshellarg/escapeshellcmd
□ Headers: CRLF injection prevention

Authentication:
━━━━━━━━━━━━━━━
□ Password hashing with bcrypt/scrypt/Argon2id (never MD5/SHA1)
□ Password requirements: minimum 12 chars, complexity rules
□ Session IDs: cryptographically random, regenerated on login
□ Multi-factor authentication for sensitive operations
□ Account lockout with progressive delays (not hard lockout)
□ Secure password reset: time-limited tokens, single use
□ Login rate limiting per account and per IP

Authorization:
━━━━━━━━━━━━━━━
□ Every API endpoint enforces authorization
□ Object-level authorization (user can only access own resources)
□ Function-level authorization (role-based access control)
□ Whitelist approach: deny by default, allow explicitly
□ Mass assignment prevention (explicit field allowlists)
□ CORS: specific origins, not wildcard
□ CSRF tokens for state-changing operations

Session Management:
━━━━━━━━━━━━━━━━━
□ Secure cookies: HttpOnly, Secure, SameSite=Strict/Lax
□ Session ID in cookie, not URL
□ Regenerate session ID on privilege change (login, role change)
□ Session timeout (idle timeout and absolute timeout)
□ Logout invalidates session on both client and server
□ Concurrent session management (limit or detect)

Cryptography:
━━━━━━━━━━━━━━━
□ TLS 1.2+ required (no TLS 1.0, 1.1)
□ HSTS with includeSubDomains and preload
□ Passwords hashed with Argon2id (preferred) or bcrypt
□ Encryption: AES-256-GCM for data at rest
□ Key management: keys in HSM or KMS, not in code or config files
□ Random number generation: secrets module (Python), SecureRandom (Java), crypto.randomBytes (Node)
□ No custom cryptographic algorithms

Error Handling:
━━━━━━━━━━━━━━━
□ Generic error messages to users (no stack traces, no internal paths)
□ Detailed errors logged server-side only
□ Error handling for all expected and unexpected conditions
□ No sensitive data in error messages (no passwords, tokens, SQL queries)
□ Custom error pages (no default server error pages)
□ CORS error handling (no information leakage)

Logging and Monitoring:
━━━━━━━━━━━━━━━━━━━━━━
□ All authentication events logged (success and failure)
□ All authorization failures logged
□ Input validation failures logged
□ Security-relevant actions logged (password change, role change, data export)
□ Log injection prevention (sanitize log input, structured logging)
□ Centralized log aggregation (SIEM integration)
□ Real-time alerting for suspicious patterns
□ Log retention policy (minimum 90 days)
```

---

## Cross-Reference Guide

| Defense Technique | Threat Mitigated | Cross-Reference |
|-------------------|-----------------|-----------------|
| CSP, security headers | XSS, clickjacking | `04a_client_side_security.md` |
| Parameterized queries | SQL injection | `02a_injection_attacks.md` |
| Input validation | All injection | `02a_injection_attacks.md` |
| Session hardening | Session hijacking, fixation | `02b_authentication_authorization.md` |
| CORS hardening | CORS attacks | `01a_web_architecture_attack_surface.md` |
| Rate limiting | Brute force, DoS | `01b_owasp_top10_deep_dive.md` |
| TLS hardening | Cryptographic failures | `01b_owasp_top10_deep_dive.md` |
| Dependency scanning | Vulnerable components | `01b_owasp_top10_deep_dive.md` |
| WAF configuration | Various web attacks | `05b_waf_bypass_techniques.md` |
| Testing methodology | All vulnerabilities | `06a_web_security_testing.md` |

---

*Web application hardening requires defense in depth: no single measure is sufficient. Security headers protect the client, input validation protects the server, parameterized queries protect the database, and monitoring provides detection when defenses fail. Implement all layers comprehensively, test regularly, and keep dependencies updated.*

---

## References

1. OWASP Foundation. "Security Headers Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
2. OWASP Foundation. "Content Security Policy Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
3. Mozilla Observatory. "Security Headers Scanner." https://observatory.mozilla.org/
4. SecurityHeaders.com. "HTTP Security Headers Test." https://securityheaders.com/
5. OWASP Foundation. "Input Validation Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
6. OWASP Foundation. "Session Management Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
7. RFC 6797. "HTTP Strict Transport Security (HSTS)." IETF, 2012. https://www.rfc-editor.org/rfc/rfc6797
8. CWE-20. "Improper Input Validation." MITRE. https://cwe.mitre.org/data/definitions/20.html
9. OWASP Foundation. "OWASP Proactive Controls." https://owasp.org/www-project-proactive-controls/
10. NIST. "SP 800-53 Rev. 5: Security and Privacy Controls." https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
11. Let's Encrypt. "Free TLS Certificates." https://letsencrypt.org/
12. OWASP Foundation. "TLS Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html
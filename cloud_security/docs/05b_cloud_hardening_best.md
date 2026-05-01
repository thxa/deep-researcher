# Cloud Hardening Best Practices

## CIS Benchmarks, Network Segmentation, Encryption, and Compliance Frameworks

---

## Table of Contents

1. [CIS Benchmarks for Cloud Providers](#1-cis-benchmarks-for-cloud-providers)
2. [Kubernetes CIS Benchmark](#2-kubernetes-cis-benchmark)
3. [Pod Security Standards Enforcement](#3-pod-security-standards-enforcement)
4. [Network Segmentation](#4-network-segmentation)
5. [Encryption at Rest and in Transit](#5-encryption-at-rest-and-in-transit)
6. [Key Management](#6-key-management)
7. [SLSA Framework for Supply Chain](#7-slsa-framework-for-supply-chain)
8. [Cloud Security Posture Management](#8-cloud-security-posture-management)
9. [Compliance Frameworks](#9-compliance-frameworks)

---

## 1. CIS Benchmarks for Cloud Providers

### 1.1 AWS CIS Benchmark Summary

| Section | Controls | Critical Recommendations |
|---|---|---|
| **IAM** | 12 | No root access keys, MFA for all users, password policy |
| **Logging** | 8 | CloudTrail enabled in all regions, log validation |
| **Monitoring** | 15 | GuardDuty enabled, CloudWatch alarms for critical events |
| **Networking** | 10 | No 0.0.0.0/0 ingress, VPC flow logs, default SG restricted |
| **EC2** | 6 | IMDSv2 required, no public AMIs, EBS encryption |
| **S3** | 4 | No public buckets, versioning enabled, encryption required |
| **KMS** | 3 | Key rotation enabled, key policy restricted |

```bash
# AWS CIS Benchmark implementation with AWS CLI

# 1.1 - Maintain current contact details
aws account put-contact-information --contact-information 'address=...;email=security@company.com;phone=+1-555-0100'

# 1.3 - Ensure MFA is enabled for all IAM users with console password
for user in $(aws iam list-users --query 'Users[].UserName' --output text); do
  mfa_devices=$(aws iam list-mfa-devices --user-name $user --query 'MFADevices[]' --output text)
  if [ -z "$mfa_devices" ]; then
    echo "[!] No MFA device for user: $user"
  fi
done

# 1.6 - Ensure hardware MFA is enabled for root account
aws iam enable-mfa-device --user-name root \
  --serial-number arn:aws:iam::123456789012:mfa/root \
  --authentication-code1 123456 \
  --authentication-code2 789012

# 1.14 - Ensure hardware MFA is enabled for root (ensure no access keys)
aws iam delete-access-key --access-key-id AKIA... --user-name root

# 2.1 - Ensure CloudTrail is enabled in all regions
aws cloudtrail create-trail \
  --name multi-region-trail \
  --s3-bucket-name cloudtrail-logs \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --kms-key-id arn:aws:kms:us-east-1:123456789012:key/abc123

# 3.1 - Ensure GuardDuty is enabled
aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES

# 5.1 - Ensure no security groups allow ingress from 0.0.0.0/0 to SSH
for sg in $(aws ec2 describe-security-groups \
  --filters Name=group-name,Values=default \
  --query 'SecurityGroups[].GroupId' --output text); do
  aws ec2 revoke-security-group-ingress \
    --group-id $sg \
    --protocol tcp \
    --port 22 \
    --cidr 0.0.0.0/0 2>/dev/null || true
done
```

### 1.2 Azure CIS Benchmark Summary

| Section | Controls | Critical Recommendations |
|---|---|---|
| **Identity** | 15 | MFA for all users, no guest users, conditional access |
| **Storage** | 6 | Secure transfer required, encryption, no public access |
| **Networking** | 7 | No public endpoints, NSG rules, DDoS protection |
| **Compute** | 8 | Disk encryption, endpoint protection, OS hardening |
| **Logging** | 5 | Activity log enabled, diagnostic settings, retention |
| **App Service** | 4 | TLS 1.2+, client certificates, managed identity |

### 1.3 GCP CIS Benchmark Summary

| Section | Controls | Critical Recommendations |
|---|---|---|
| **IAM** | 14 | No SA key usage, org policies, MFA |
| **Logging** | 6 | Audit logging enabled, retention, data access |
| **Networking** | 8 | No public IPs, firewall rules, VPC flow logs |
| **Compute** | 6 | Shielded VMs, disk encryption, OS login |
| **Storage** | 4 | Bucket encryption, uniform access, no public |
| **KMS** | 3 | Key rotation, CMEK, restricted access |

---

## 2. Kubernetes CIS Benchmark

### 2.1 Key K8s CIS Controls

```yaml
# CIS Kubernetes Benchmark - Key Controls

# 1. Control Plane Node Configuration
# 1.1 API Server
# --anonymous-auth=false
# --authorization-mode=Node,RBAC
# --enable-admission-plugins=NodeRestriction,PodSecurity,LimitRanger,ServiceAccount
# --audit-log-path=/var/log/kubernetes/audit.log
# --audit-log-maxage=30
# --encryption-provider-config=/etc/kubernetes/encryption-config.yaml
# --etcd-certfile and --etcd-keyfile
# -- tls-cert-file and --tls-private-key-file

# 1.2 etcd
# --client-cert-auth=true
# --peer-client-cert-auth=true
# --peer-auto-tls=false

# 1.3 Controller Manager
# --terminated-pod-gc-threshold=100
# --use-service-account-credentials=true

# 1.4 Scheduler
# --profiling=false

# 2. Worker Node Configuration
# 2.1 Kubelet
# --anonymous-auth=false
# --authorization-mode=Webhook
# --read-only-port=0
# --streaming-connection-idle-timeout=5m
# --protect-kernel-defaults=true
# --make-iptables-util-chains=true
# --event-qps=50
```

```bash
# Kubescape / kube-bench: Automated CIS benchmark scanner

# Install kube-bench
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml

# Run the benchmark
kubectl get jobs -n kube-bench
kubectl logs job/kube-bench -n kube-bench

# Key remediations:
# 1. Disable anonymous authentication
# /etc/kubernetes/manifests/kube-apiserver.yaml
# Add: --anonymous-auth=false

# 2. Enable RBAC
# /etc/kubernetes/manifests/kube-apiserver.yaml
# Add: --authorization-mode=Node,RBAC

# 3. Enable audit logging
# /etc/kubernetes/manifests/kube-apiserver.yaml
# Add: --audit-log-path=/var/log/kubernetes/audit.log

# 4. Encrypt secrets at rest
# Create encryption config:
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-encoded-32-byte-key>
      - identity: {}
```

---

## 3. Pod Security Standards Enforcement

### 3.1 Pod Security Admission Configuration

```yaml
# Enforce Pod Security Standards at the namespace level

# Production: Restricted policy (most secure)
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.27
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: v1.27
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: v1.27
---
# Staging: Baseline policy (moderate security)
apiVersion: v1
kind: Namespace
metadata:
  name: staging
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/enforce-version: v1.27
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: v1.27
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: v1.27
---
# Development: Privileged policy (least secure, for dev workloads)
apiVersion: v1
kind: Namespace
metadata:
  name: development
  labels:
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/audit: baseline
    pod-security.kubernetes.io/warn: baseline
---
# System namespaces: Privileged (required for system components)
apiVersion: v1
kind: Namespace
metadata:
  name: kube-system
  labels:
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/audit: privileged
    pod-security.kubernetes.io/warn: privileged
```

### 3.2 Restricted Pod Security Policy Template

```yaml
# Complete restricted pod security policy
apiVersion: v1
kind: Pod
metadata:
  name: restricted-pod-template
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
    supplementalGroups: [1000]
  containers:
  - name: app
    image: gcr.io/distroless/static:nonroot@sha256:abc123
    imagePullPolicy: Always
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    resources:
      limits:
        memory: "512Mi"
        cpu: "1"
      requests:
        memory: "256Mi"
        cpu: "500m"
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: cache
      mountPath: /var/cache
  volumes:
  - name: tmp
    emptyDir:
      medium: Memory
      sizeLimit: "128Mi"
  - name: cache
    emptyDir:
      medium: Memory
      sizeLimit: "256Mi"
  automountServiceAccountToken: false
  hostNetwork: false
  hostPID: false
  hostIPC: false
```

---

## 4. Network Segmentation

### 4.1 AWS Security Groups and NACLs

```terraform
# Tiered security group architecture

# Web tier security group
resource "aws_security_group" "web" {
  name        = "web-tier"
  description = "Security group for web tier"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Only HTTPS from internet
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    security_groups = [aws_security_group.app.id]  # Only to app tier
  }

  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["10.0.0.0/8"]  # DNS only to internal
  }

  tags = { Name = "web-tier" }
}

# Application tier security group
resource "aws_security_group" "app" {
  name        = "app-tier"
  description = "Security group for application tier"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 8443
    to_port         = 8443
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]  # Only from web tier
  }

  egress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.database.id]  # Only to DB tier
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # HTTPS to external APIs
  }

  tags = { Name = "app-tier" }
}

# Database tier security group
resource "aws_security_group" "database" {
  name        = "database-tier"
  description = "Security group for database tier"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]  # Only from app tier
  }

  # No egress rules - database should not initiate connections
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # Required for DNS, patching, etc.
  }

  tags = { Name = "database-tier" }
}
```

### 4.2 Azure NSGs and VNet Service Endpoints

```hcl
# Azure Network Security Group (NSG) for tiered architecture
resource "azurerm_network_security_group" "web" {
  name                = "web-tier-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  # Allow HTTPS from internet
  security_rule {
    name                       = "allow-https-inbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "Internet"
    destination_address_prefix = "10.0.1.0/24"
  }

  # Deny all other inbound
  security_rule {
    name                       = "deny-all-inbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# VNet Service Endpoints (restrict Azure service access to VNet only)
resource "azurerm_subnet_service_endpoint_storage_policy" "main" {
  name                = "allow-storage-from-vnet"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  definition {
    name = "storage-endpoint-policy"
    service_resources = [
      azurerm_storage_account.main.id
    ]
  }
}
```

### 4.3 GCP VPC Service Controls

```hcl
# GCP VPC Service Controls (data exfiltration prevention)
resource "google_access_context_manager_service_perimeter" "main" {
  name         = "accessPolicies/${google_access_context_manager_policy.main.name}/servicePerimeters/restricted"
  parent       = "accessPolicies/${google_access_context_manager_policy.main.name}"
  title        = "restricted-perimeter"
  description  = "Restrict data exfiltration from VPC"

  status {
    restricted_services = [
      "storage.googleapis.com",
      "bigquery.googleapis.com",
      "cloudkms.googleapis.com",
    ]

    resources = [
      "projects/${var.project_id}",
    ]

    ingress_policies {
      ingress_from {
        identity_type = "ANY_IDENTITY"
        sources {
          access_level = "accessPolicies/${google_access_context_manager_policy.main.name}/accessLevels/corporate"
        }
      }
      ingress_to {
        resources = ["*"]
        operations {
          service_operations {
            service = "storage.googleapis.com"
          }
        }
      }
    }
  }
}

# VPC firewall rules
resource "google_compute_firewall" "deny_metadata" {
  name    = "deny-metadata-access"
  network = google_compute_network.main.name

  deny {
    protocol = "tcp"
    ports    = ["80", "443"]
  }

  destination_ranges = ["169.254.169.254/32"]
  source_ranges      = ["10.0.0.0/8"]
  priority           = 100

  description = "Deny access to GCP metadata service from internal networks"
}
```

---

## 5. Encryption at Rest and in Transit

### 5.1 Encryption Architecture

```
+------------------------------------------------------------------+
|                    Encryption Stack                                |
|                                                                    |
|  Application Layer                                                |
|  ┌─────────────────────────────────────────────────────────────┐  |
*  │  Application-Level Encryption (Envelope Encryption)          │  |
│  │  - Data encrypted with DEK (Data Encryption Key)            │  |
│  │  - DEK encrypted with KEK (Key Encryption Key)              │  |
│  │  - KEK stored in KMS                                         │  |
│  └─────────────────────────────────────────────────────────────┘  |
*                                                                    |
|  Storage Layer                                                    |
|  ┌─────────────────────────────────────────────────────────────┐  |
*  │  Storage-Level Encryption                                     │  |
│  │  - S3 SSE-S3 (Amazon-managed keys)                           │  |
│  │  - S3 SSE-KMS (Customer-managed keys via KMS)               │  |
│  │  - EBS Encryption (KMS-backed)                              │  |
│  │  - RDS Encryption (KMS-backed)                               │  |
│  └─────────────────────────────────────────────────────────────┘  |
*                                                                    |
|  Network Layer                                                    |
|  ┌─────────────────────────────────────────────────────────────┐  |
*  │  Transport Layer Encryption (TLS 1.2/1.3)                    │  |
│  │  - TLS termination at load balancer                         │  |
│  │  - mTLS between services (service mesh)                     │  |
│  │  - VPC endpoint encryption                                  │  |
│  └─────────────────────────────────────────────────────────────┘  |
*                                                                    |
|  Key Management Layer                                              |
|  ┌─────────────────────────────────────────────────────────────┐  |
*  │  KMS (Key Management Service)                                 │  |
│  │  - Key rotation (annual)                                     │  |
│  │  - Key policies (least privilege)                            │  |
│  │  - Key deletion protection                                    │  |
│  │  - Audit logging (CloudTrail)                                 │  |
│  └─────────────────────────────────────────────────────────────┘  |
+------------------------------------------------------------------+
```

### 5.2 Envelope Encryption Deep Dive

```
+------------------------------------------------------------------+
|                    Envelope Encryption Flow                         |
|                                                                    |
|  1. Application needs to encrypt data                              |
|     ┌──────────┐                                                  |
|     │ App      │──→ "Encrypt this data" ──→ KMS                  |
|     └──────────┘                                                  |
|                                                                    |
|  2. KMS generates Data Encryption Key (DEK)                       |
|     ┌──────────┐                                                  |
|     │ KMS      │──→ DEK (plaintext) ──→ Application              |
|     │          │──→ DEK (encrypted with KEK) ──→ Storage          |
*  └──────────┘                                                  |
|                                                                    |
|  3. Application encrypts data with DEK                            |
|     ┌──────────┐                                                  |
|     │ App      │──→ Encrypted data ──→ Storage                    |
|     │          │──→ Encrypted DEK ──→ Storage (alongside data)    |
|     └──────────┘                                                  |
|                                                                    |
|  4. Decryption: Application sends encrypted DEK to KMS            |
|     ┌──────────┐                                                  |
|     │ App      │──→ Encrypted DEK ──→ KMS                        |
|     │          │←── Plaintext DEK ──← KMS (decrypted with KEK)    |
*  └──────────┘                                                  |
|                                                                    |
|  5. Application decrypts data with DEK                            |
|     ┌──────────┐                                                  |
*  │ App      │──→ DEK decrypts data ──→ Plaintext                 |
*  └──────────┘                                                  |
|                                                                    |
|  Benefits:                                                         |
|  - KMS only sees the DEK, never the data                          |
|  - KEK can be rotated without re-encrypting data                  |
|  - DEK iscached in memory (performance)                            |
|  - KEK policy controls who can decrypt                            |
+------------------------------------------------------------------+
```

---

## 6. Key Management

### 6.1 AWS KMS Best Practices

```terraform
# AWS KMS key with least-privilege policy
resource "aws_kms_key" "application" {
  description             = "Application data encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true  # Annual key rotation

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM Key Administration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/KeyAdmin"
        }
        Action = [
          "kms:Create*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:List*",
          "kms:Put*",
          "kms:Update*",
          "kms:Revoke*",
          "kms:Disable*",
          "kms:Delete*",
          "kms:Tag*",
          "kms:Untag*",
          "kms:ScheduleKeyDeletion",
          "kms:RotateKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow Application Encrypt/Decrypt"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/ApplicationRole"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:EncryptionContext:application" = "myapp"
            "kms:EncryptionContext:environment" = "production"
          }
        }
      },
      {
        Sid    = "Allow Audit Logging"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/SecurityAudit"
        }
        Action = [
          "kms:Describe*",
          "kms:Get*",
          "kms:List*"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "application" {
  name          = "alias/application-production"
  target_key_id = aws_kms_key.application.key_id
}
```

### 6.2 HashiCorp Vault Integration

```hcl
# Vault KMS integration for cloud key management

# Enable AWS KMS secrets engine
resource "vault_mount" "aws" {
  path = "aws"
  type = "aws"
}

# Configure AWS KMS access
resource "vault_aws_secret_backend_role" "kms" {
  backend = vault_mount.aws.path
  name    = "kms-role"

  credential_type = "assumed_role"
  role_arns       = [aws_iam_role.vault_kms.arn]
}

# Dynamic secret: generates short-lived AWS credentials
resource "vault_generic_secret" "kms_config" {
  path = "aws/config/root"
  data_json = jsonencode({
    access_key = var.aws_access_key
    secret_key = var.aws_secret_key
    region     = var.aws_region
  })
}

# Transit engine for application-level encryption
resource "vault_mount" "transit" {
  path = "transit"
  type = "transit"
}

resource "vault_transit_secret_backend_key" "application" {
  backend    = vault_mount.transit.path
  name       = "application-key"
  type       = "aes256-gcm96"
  deletion_allowed = false
  exportable = false
}

# Application encryption using Vault Transit
# POST /v1/transit/encrypt/application-key
# { "plaintext": "dGhpcyBpcyBhIHRlc3Q=" }
#
# Response:
# { "ciphertext": "vault:v1:abcdefghij..." }
#
# Application decryption:
# POST /v1/transit/decrypt/application-key
# { "ciphertext": "vault:v1:abcdefghij..." }
#
# Response:
# { "plaintext": "dGhpcyBpcyBhIHRlc3Q=" }
```

---

## 7. SLSA Framework for Supply Chain

### 7.1 SLSA Levels

| Level | Description | Requirements |
|---|---|---|
| **SLSA 1** | Documentation | Build process documented, build provenance exists |
| **SLSA 2** | Hosted Build | Build on hosted platform, signed provenance |
| **SLSA 3** | Hardened Build | Build platform hardened, non-falsifiable provenance |
| **SLSA 4** | Reproducible | Hermetic, reproducible builds, two-party provenance verification |

### 7.2 SLSA Implementation for Containers

```yaml
# GitHub Actions workflow with SLSA provenance generation
name: Build and Push Container Image

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write  # Required for SLSA provenance
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Build container image
        run: |
          docker build -t myregistry.io/myapp:${{ github.sha }} .
      
      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          image: myregistry.io/myapp:${{ github.sha }}
          format: spdx-json
          output-file: sbom.spdx.json
      
      - name: Scan image for vulnerabilities
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myregistry.io/myapp:${{ github.sha }}
          format: 'table'
          exit-code: '1'
          severity: 'CRITICAL,HIGH'
      
      - name: Sign container image
        uses: sigstore/cosign-installer@v3
        run: |
          cosign sign --key env://COSIGN_PRIVATE_KEY myregistry.io/myapp:${{ github.sha }}
        env:
          COSIGN_PRIVATE_KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}
      
      - name: Generate SLSA provenance
        uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v1.9.0
        with:
          image: myregistry.io/myapp
          digest: ${{ steps.build.outputs.digest }}
      
      - name: Push image and provenance
        run: |
          docker push myregistry.io/myapp:${{ github.sha }}
          cosign attach sbom --sbom sbom.spdx.json myregistry.io/myapp:${{ github.sha }}
```

---

## 8. Cloud Security Posture Management

### 8.1 CSPM Architecture

```
+------------------------------------------------------------------+
|                    CSPM Architecture                               |
|                                                                    |
|  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              |
|  │ AWS         │  │ Azure       │  │ GCP         │              |
|  │ Config      │  │ Policy      │  │ Security     │              |
*  │ SecurityHub │  │ Defender    │  │ Command Ctr  │              |
*  │ GuardDuty   │  │ Sentinel    │  │ SCC          │              |
*  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              |
*         │                │                │                      |
*         v                v                v                      |
*  ┌──────────────────────────────────────────────────────────┐   |
*  │                    CSPM Platform                         │   |
*  │  - Configuration assessment                              │   |
*  │  - Compliance mapping (CIS, SOC 2, FedRAMP)             │   |
*  │  - Drift detection                                        │   |
*  │  - Remediation automation                                │   |
*  │  - Risk prioritization                                    │   |
*  └──────────────────────────────────────────────────────────┘   |
*         │                │                │                      |
*         v                v                v                      |
*  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              |
*  │ Dashboards  │  │ Alerts      │  │ Reports     │              |
*  │ Risk Scores │  │ Tickets     │  │ Compliance  │              |
*  └─────────────┘  └─────────────┘  └─────────────┘              |
+------------------------------------------------------------------+
```

### 8.2 Custom CSPM Checks

```python
# Custom CSPM checks for cloud security posture

class CSPMChecker:
    def __init__(self, session):
        self.session = session
        self.ec2 = session.client('ec2')
        self.iam = session.client('iam')
        self.s3 = session.client('s3')
        self.kms = session.client('kms')
        self.findings = []

    def check_security_groups(self):
        """Check for overly permissive security groups"""
        sgs = self.ec2.describe_security_groups()
        for sg in sgs['SecurityGroups']:
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    if ip_range['CidrIp'] == '0.0.0.0/0':
                        if rule['FromPort'] in [22, 3389, 23, 21]:
                            self.findings.append({
                                'severity': 'CRITICAL',
                                'resource': sg['GroupId'],
                                'check': 'Security Group - Public SSH/RDP',
                                'detail': f"SG {sg['GroupId']} allows {rule['FromPort']} from 0.0.0.0/0"
                            })
        return self.findings

    def check_s3_public_access(self):
        """Check for publicly accessible S3 buckets"""
        buckets = self.s3.list_buckets()
        for bucket in buckets['Buckets']:
            try:
                acl = self.s3.get_bucket_acl(Bucket=bucket['Name'])
                for grant in acl['Grants']:
                    if 'AllUsers' in grant.get('Grantee', {}).get('URI', ''):
                        self.findings.append({
                            'severity': 'CRITICAL',
                            'resource': bucket['Name'],
                            'check': 'S3 Public Access',
                            'detail': f"Bucket {bucket['Name']} has public access"
                        })
            except Exception:
                pass
        return self.findings

    def check_iam_mfa(self):
        """Check for IAM users without MFA"""
        users = self.iam.list_users()
        for user in users['Users']:
            mfa_devices = self.iam.list_mfa_devices(UserName=user['UserName'])
            if not mfa_devices['MFADevices']:
                self.findings.append({
                    'severity': 'HIGH',
                    'resource': user['UserName'],
                    'check': 'IAM MFA',
                    'detail': f"User {user['UserName']} has no MFA device"
                })
        return self.findings

    def check_kms_rotation(self):
        """Check for KMS keys without rotation"""
        keys = self.kms.list_keys()
        for key in keys['Keys']:
            key_info = self.kms.describe_key(KeyId=key['KeyId'])
            if key_info['KeyMetadata']['KeyState'] == 'Enabled':
                rotation = self.kms.get_key_rotation_status(KeyId=key['KeyId'])
                if not rotation['KeyRotationEnabled']:
                    self.findings.append({
                        'severity': 'MEDIUM',
                        'resource': key['KeyId'],
                        'check': 'KMS Rotation',
                        'detail': f"Key {key['KeyId']} does not have rotation enabled"
                    })
        return self.findings
```

---

## 9. Compliance Frameworks

### 9.1 Compliance Matrix

| Control | SOC 2 | FedRAMP | ISO 27001 | AWS CIS | Azure CIS | GCP CIS |
|---|---|---|---|---|---|---|
| **MFA** | CC6.1 | AC-2 | A.9.4.2 | 1.10 | 1.1 | 1.2 |
| **Encryption at rest** | CC6.7 | SC-28 | A.10.1.1 | 2.1 | 4.1 | 4.1 |
| **Encryption in transit** | CC6.7 | SC-8 | A.10.1.1 | 2.1 | 4.1 | 4.1 |
| **Access control** | CC6.1 | AC-3 | A.9.2.1 | 1.1 | 1.1 | 1.1 |
| **Audit logging** | CC7.2 | AU-2 | A.12.4.1 | 2.1 | 5.1 | 2.1 |
| **Incident response** | CC7.3 | IR-4 | A.16.1.1 | 2.1 | 5.1 | 2.1 |
| **Change management** | CC8.1 | CM-3 | A.12.1.2 | N/A | N/A | N/A |
| **Vulnerability management** | CC7.1 | RA-5 | A.12.6.1 | N/A | N/A | N/A |
| **Network segmentation** | CC6.6 | SC-7 | A.13.1.1 | 5.1 | 6.1 | 3.1 |
| **Key management** | CC6.7 | SC-12 | A.10.1.2 | 2.8 | 8.1 | 7.1 |

### 9.2 SOC 2 Type II Cloud Controls

```markdown
# SOC 2 Type II Cloud Control Mapping

## Trust Service Criteria: Security (CC6)

### CC6.1 - Logical and Physical Access Controls
- MFA enabled for all IAM users (AWS CIS 1.10, Azure CIS 1.1)
- Service account keys rotated every 90 days
- SSH key-based access to EC2 instances
- Just-in-time (JIT) access for privileged operations
- Conditional access policies enforce device compliance

### CC6.6 - Network Segmentation
- VPC with public and private subnets
- Security groups enforce micro-segmentation
- Network ACLs provide defense in depth
- VPC endpoints for AWS services (no internet traversal)
- WAF protects public-facing applications

### CC6.7 - Encryption
- All S3 buckets use SSE-KMS encryption
- EBS volumes encrypted at rest
- RDS instances encrypted at rest
- TLS 1.2 minimum for all API endpoints
- KMS keys rotated annually
- Customer-managed keys (CMK) for sensitive data

### CC6.8 - System Communications
- VPC Flow Logs enabled in all VPCs
- CloudTrail enabled in all regions with log validation
- DNS query logging enabled
- S3 access logging for sensitive buckets
- CloudWatch Logs for application logging

## Trust Service Criteria: Availability (CC7)

### CC7.2 - Monitoring and Alerting
- CloudWatch alarms for critical thresholds
- GuardDuty enabled for threat detection
- Security Hub for posture management
- PagerDuty integration for critical alerts
- SLO monitoring dashboards

### CC7.3 - Incident Response
- Incident response runbooks for cloud-specific scenarios
- Automated remediation for common findings
- Quarterly incident response exercises
- Post-incident reviews documented
- Communication templates for stakeholder notification
```

**Cross-reference**: Cloud hardening connects to IAM (`01b_identity_access_management.md`) for least-privilege configurations, to container security (`02a_container_security.md`) for pod hardening, and to IaC security (`03b_infrastructure_as_code_security.md`) for policy-as-code enforcement. The compliance frameworks map to the detection controls in `05a_cloud_detection_monitoring.md`.

---

*Next: [06 — Cloud Case Studies and Future](06_cloud_case_studies_future.md)*

---

## References

1. CIS. "CIS Benchmarks: AWS, Azure, GCP, Kubernetes." *Center for Internet Security*. 2024. https://www.cisecurity.org/cis-benchmarks/
2. NSA/CISA. "Kubernetes Hardening Guide." *National Security Agency*. 2022. https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/1/CTR_KUBERNETES_HARDENING_GUIDANCE.PDF
3. NIST. "SP 800-190: Application Container Security Guide." *National Institute of Standards and Technology*. 2024. https://csrc.nist.gov/pubs/sp/800-190/final
4. NIST. "SP 800-53: Security and Privacy Controls." *National Institute of Standards and Technology*. 2024. https://csrc.nist.gov/pubs/sp/800-53/r5
5. AWS. "KMS Documentation." *Amazon Web Services*. 2024. https://docs.aws.amazon.com/kms/
6. HashiCorp. "Vault Documentation." *HashiCorp*. 2024. https://developer.hashicorp.com/vault/docs
7. SLSA. "Supply Chain Levels for Software Artifacts." *SLSA Framework*. 2024. https://slsa.dev/spec/
8. ISO/IEC. "ISO 27001:2022 Information Security Management." *International Organization for Standardization*. 2022. https://www.iso.org/standard/27001
9. AICPA. "SOC 2 Trust Services Criteria." *American Institute of Certified Public Accountants*. 2024. https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-sup-2640-soc2-reporting
10. FedRAMP. "Federal Risk and Authorization Management Program." *FedRAMP*. 2024. https://www.fedramp.gov/
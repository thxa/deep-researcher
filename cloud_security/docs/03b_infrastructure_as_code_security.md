# Infrastructure as Code Security

## Terraform, CloudFormation, Pulumi — State, Policy, and Supply Chain Risks

---

## Table of Contents

1. [IaC Security Fundamentals](#1-iac-security-fundamentals)
2. [Terraform Security Deep Dive](#2-terraform-security-deep-dive)
3. [State File Secrets Exposure](#3-state-file-secrets-exposure)
4. [CloudFormation Security](#4-cloudformation-security)
5. [Pulumi Security](#5-pulumi-security)
6. [Drift Detection and Runtime Security](#6-drift-detection-and-runtime-security)
7. [Supply Chain in Terraform Providers](#7-supply-chain-in-terraform-providers)
8. [OIDC Trust Configuration Errors](#8-oidc-trust-configuration-errors)
9. [Secrets Management in IaC](#9-secrets-management-in-iac)
10. [Policy-as-Code](#10-policy-as-code)
11. [Terraform Plan Security Review](#11-terraform-plan-security-review)

---

## 1. IaC Security Fundamentals

### 1.1 The IaC Security Model

Infrastructure as Code (IaC) treats infrastructure definitions as software artifacts — subject to version control, review, testing, and security analysis. This shift introduces both new risks and new security controls.

```
+------------------------------------------------------------------+
|                    IaC Security Pipeline                          |
|                                                                    |
|  Developer → Git Commit → CI/CD Pipeline → Deployment             |
|       │           │            │               │                    |
|       v           v            v               v                    |
*  ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌──────────┐               |
|  │ Code    │ │ Review  │ │ Policy   │ │ Runtime  │               |
|  │ Secrets │ │ Process │ │ Check    │ │ Drift    │               |
|  │ Scan    │ │ (PR)    │ │ (OPA/Sen)│ │ Detect   │               |
|  └─────────┘ └─────────┘ └──────────┘ └──────────┘               |
|       │           │            │               │                    |
|       v           v            v               v                    |
|  ┌─────────────────────────────────────────────────────────┐      |
|  │                  IaC Risk Categories                      │      |
|  │                                                           │      |
|  │ 1. Secrets in code/state files                            │      |
|  │ 2. Misconfigured resources (overly permissive)            │      |
|  │ 3. Supply chain (malicious providers/modules)             │      |
|  │ 4. Drift from IaC to runtime configuration                │      |
|  │ 5. Identity/trust misconfigurations (OIDC, SAML)          │      |
|  │ 6. Privilege escalation via IaC execution role             │      |
|  └─────────────────────────────────────────────────────────┘      |
+------------------------------------------------------------------+
```

### 1.2 IaC Risk Matrix

| Risk | Terraform | CloudFormation | Pulumi |
|---|---|---|---|
| **Secrets in state** | Critical | Critical | High |
| **Secrets in code** | High | High | High |
| **Provider supply chain** | Critical | N/A (AWS-only) | High |
| **Module supply chain** | High | High (nested stacks) | Medium |
| **State file integrity** | Critical | N/A (managed) | Medium |
| **Plan-time vs runtime drift** | High | Medium | Medium |
| **OIDC trust misconfiguration** | Critical | High | High |
| **Privilege escalation** | High | High | High |

---

## 2. Terraform Security Deep Dive

### 2.1 Terraform Architecture and Security Boundaries

```
+------------------------------------------------------------------+
|                    Terraform Security Boundaries                   |
|                                                                    |
|  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐          |
|  │ .tf files    │     │ State file  │     │ Provider    │          |
*  │ (declarative)│────→│ (tfstate)  │────→│ binaries    │          |
*  └─────────────┘     └──────┬──────┘     └──────┬──────┘          |
|       │                      │                    │                  |
|       v                      v                    v                  |
|  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐          |
|  │ Secrets in  │     │ Secrets in  │     │ Cloud API   │          |
|  │ code        │     │ state      │     │ calls       │          |
|  └─────────────┘     └─────────────┘     └─────────────┘          |
|                              │                                    |
|                              v                                    |
|                       ┌─────────────┐                            |
|                       │ Cloud       │                            |
|                       │ Resources   │                            |
|                       │ (runtime)   │                            |
|                       └─────────────┘                            |
+------------------------------------------------------------------+
```

### 2.2 Terraform Configuration Security

```hcl
# VULNERABLE: Insecure Terraform configuration

resource "aws_s3_bucket" "data" {
  bucket = "my-insecure-bucket"
  acl    = "public-read"  # VULNERABILITY: Public access
  
  # No versioning
  # No encryption
  # No logging
  # No server-side encryption
}

resource "aws_security_group" "web" {
  name = "web-sg"
  
  ingress {
    from_port   = 0
    to_port     = 65535
    from_port   = 0
    to_port     = 0
    protocol    = "-1"  # VULNERABILITY: All traffic allowed
    cidr_blocks = ["0.0.0.0/0"]  # VULNERABILITY: From anywhere
  }
}

resource "aws_iam_role" "lambda" {
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

# VULNERABILITY: Inline policy with full permissions
resource "aws_iam_role_policy" "lambda_full" {
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action   = "*"  # VULNERABILITY: Full access
      Effect   = "Allow"
      Resource = "*"  # VULNERABILITY: All resources
    }]
  })
}

# VULNERABILITY: Hardcoded secret in Terraform code
resource "aws_db_instance" "database" {
  engine     = "mysql"
  username   = "admin"
  password   = "SuperSecret123!"  # NEVER DO THIS!
}
```

```hcl
# SECURE: Hardened Terraform configuration

resource "aws_s3_bucket" "data" {
  bucket = "my-secure-bucket-${random_id.bucket_suffix.hex}"
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "data" {
  bucket        = aws_s3_bucket.data.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "log/data-bucket/"
}

resource "aws_security_group" "web" {
  name = "web-sg"
  vpc_id = aws_vpc.main.id
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Internal only
  }
  
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/8"]
  }
}

# Secure IAM role with least privilege
data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "lambda" {
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy" "lambda_least" {
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetObject"
        ]
        Effect   = "Allow"
        Resource = "${aws_s3_bucket.data.arn}/data/*"
      },
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# Reference secret from Secrets Manager
resource "aws_db_instance" "database" {
  engine  = "mysql"
  username = "admin"
  password = aws_secretsmanager_secret_version.db_password.secret_string
}

resource "aws_secretsmanager_secret" "db_password" {
  name = "prod/database/password"
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id = aws_secretsmanager_secret.db_password.id
  secret_string = random_password.db_password.result
}

resource "random_password" "db_password" {
  length  = 32
  special = true
}
```

---

## 3. State File Secrets Exposure

### 3.1 The State File Problem

Terraform state files contain the complete resource graph, including sensitive values. This is by design — Terraform needs to track resource attributes to detect changes. However, this makes state files a high-value target.

```json
// tfstate file (simplified) — contains ALL resource attributes including secrets

{
  "version": 4,
  "resources": [
    {
      "type": "aws_db_instance",
      "instances": [{
        "attributes": {
          "username": "admin",
          "password": "SuperSecret123!",    // ← PLAINTEXT SECRET
          "endpoint": "db-instance.c1x2y3z4.us-east-1.rds.amazonaws.com"
        }
      }]
    },
    {
      "type": "aws_iam_access_key",
      "instances": [{
        "attributes": {
          "id": "AKIAIOSFODNN7EXAMPLE",      // ← ACCESS KEY ID
          "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  // ← SECRET KEY
        }
      }]
    },
    {
      "type": "aws_lambda_function",
      "instances": [{
        "attributes": {
          "environment": {
            "variables": {
              "DB_PASSWORD": "postgres://admin:password@db:5432/mydb",  // ← DB CREDENTIALS
              "API_KEY": "sk-live-xxxxxxxxxxxx"                          // ← API KEY
            }
          }
        }
      }]
    }
  ]
}
```

### 3.2 State File Attack Scenarios

```bash
# Attack 1: Compromised state file in S3 bucket
# If the S3 bucket containing tfstate is publicly accessible:
aws s3 ls s3://terraform-state-company-com/ --no-sign-request
aws s3 cp s3://terraform-state-company-com/production/terraform.tfstate /tmp/tfstate --no-sign-request

# Parse secrets from state file:
cat /tmp/tfstate | jq -r '.resources[] | select(.type == "aws_db_instance") | .instances[].attributes.password'
cat /tmp/tfstate | jq -r '.resources[] | select(.type == "aws_iam_access_key") | .instances[].attributes.secret'

# Attack 2: State file in version control
# If tfstate is committed to Git:
git log --all --full-history -- '*.tfstate' '*.tfstate.backup'
git show abc123:terraform.tfstate | jq -r '.resources[].instances[].attributes.password // empty'

# Attack 3: State file manipulation
# If an attacker modifies the state file, they can:
# 1. Remove security controls (e.g., delete a security group rule)
# 2. Change resource configurations (e.g., modify an IAM policy)
# 3. Introduce drift that masks malicious changes

# Download state
terraform state pull > current_state.json

# Modify state (remove encryption configuration)
jq '.resources[] |= if .type == "aws_s3_bucket_server_side_encryption_configuration" then .instances = [] else . end' current_state.json > modified_state.json

# Push modified state
terraform state push modified_state.json

# Attack 4: State file locking denial of service
# If state locking is enabled (it should be), an attacker can:
# 1. Acquire a lock and never release it
# 2. Block all Terraform operations
# 3. Force manual state lock removal (which bypasses safety checks)
```

### 3.3 State File Security Best Practices

```hcl
# Secure state backend configuration
terraform {
  backend "s3" {
    bucket         = "terraform-state-secure-prod"
    key            = "production/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true  # SSE-S3 encryption
    kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/abc123"  # SSE-KMS
    
    dynamodb_table = "terraform-state-lock"  # State locking
    acl            = "private"
    
    # Role assumption for state access
    role_arn = "arn:aws:iam::123456789012:role/TerraformStateAccess"
  }
}

# S3 bucket for state (with maximum security)
resource "aws_s3_bucket" "terraform_state" {
  bucket = "terraform-state-secure-prod"
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  versioning_configuration {
    status = "Enabled"  # Versioning for state recovery
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.terraform_state.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_policy" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnforceTLSTransit"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.terraform_state.arn,
          "${aws_s3_bucket.terraform_state.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "RestrictToTerraformRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:role/TerraformStateAccess"
        }
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.terraform_state.arn}/*"
      }
    ]
  })
}
```

---

## 4. CloudFormation Security

### 4.1 CloudFormation Security Model

```yaml
# VULNERABLE: Insecure CloudFormation template
AWSTemplateFormatVersion: '2010-09-09'
Description: Insecure infrastructure

Resources:
  InsecureBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-insecure-bucket
      # No encryption, no versioning, no access controls
      
  InsecureSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Allow all traffic
      SecurityGroupIngress:
        - IpProtocol: -1
          CidrIp: 0.0.0.0/0  # VULNERABILITY: All traffic from anywhere
          
  DatabaseWithHardcodedPassword:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: mysql
      MasterUsername: admin
      MasterUserPassword: SuperSecret123!  # VULNERABILITY: Hardcoded password
```

```yaml
# SECURE: Hardened CloudFormation template
AWSTemplateFormatVersion: '2010-09-09'
Description: Secure infrastructure

Parameters:
  DBPassword:
    Type: String
    NoEcho: true  # Prevents password from appearing in console/API
    Description: Database master password
    
Resources:
  SecureBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: aws:kms
              KMSMasterKeyID: !Ref EncryptionKey
      VersioningConfiguration:
        Status: Enabled
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      
  SecureBucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref SecureBucket
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: EnforceTLSTransit
            Effect: Deny
            Principal: '*'
            Action: s3:*
            Resource:
              - !Sub 'arn:aws:s3:::${SecureBucket}'
              - !Sub 'arn:aws:s3:::${SecureBucket}/*'
            Condition:
              Bool:
                aws:SecureTransport: false
                
  # Reference password from Secrets Manager
  DatabaseSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      SecretString: !Ref DBPassword
      
  SecureDatabase:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: mysql
      MasterUsername: admin
      MasterUserPassword: !Ref DBPassword  # NoEcho parameter
      StorageEncryption: true
      KmsKeyId: !Ref EncryptionKey
```

### 4.2 CloudFormation Nested Stack Injection

```yaml
# CloudFormation nested stacks can be a supply chain vector
# If a nested stack URL points to an external S3 bucket,
# an attacker who compromises that bucket can inject malicious resources

AWSTemplateFormatVersion: '2010-09-09'
Resources:
  # DANGEROUS: Reference to external template
  ExternalNestedStack:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: https://external-bucket.s3.amazonaws.com/nested-stack.yaml
      # If external-bucket is compromised, the attacker can:
      # 1. Modify the template to create IAM roles with admin access
      # 2. Add resources that exfiltrate data
      # 3. Create backdoor resources
      
  # SECURE: Reference to internal template with version pinning
  SecureNestedStack:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: !Sub 'https://s3.amazonaws.com/${InternalBucket}/nested-stack-v1.2.3.yaml'
      # Use versioned templates, verify S3 bucket ownership
```

---

## 5. Pulumi Security

### 5.1 Pulumi-Specific Security Concerns

Pulumi differs from Terraform and CloudFormation in that it uses general-purpose programming languages (Python, TypeScript, Go) instead of DSLs. This introduces unique security considerations:

```python
# Pulumi (Python) — Security concerns specific to general-purpose languages

import pulumi
import pulumi_aws as aws

# RISK 1: Dynamic secret computation in code
# Unlike Terraform's `random_password`, Pulumi can compute secrets in code
# If the computation is visible in logs or stack outputs, it's a risk
import hashlib
import secrets

password = secrets.token_urlsafe(32)
# This is computed locally and stored in state — but is it marked as secret?
pulumi_db_password = pulumi.Output.secret(password)  # Correct: marked as secret

# RISK 2: Dependency confusion (Pulumi uses pip/npm)
# Pulumi programs have the same dependency confusion risk as any Python/Node project
# An attacker can publish a malicious pulumi-aws-evil package that gets installed
# instead of pulumi-aws if not properly pinned

# RISK 3: Program logic can be complex (why is this bad?)
# Complex logic makes security review harder
def create_vpc(name, cidr):
    vpc = aws.ec2.Vpc(f"{name}-vpc", cidr_block=cidr)
    # Security: What if cidr is "0.0.0.0/0"? 
    # Unlike Terraform where this is clearly visible, Pulumi's
    # programmatic logic can hide security issues
    
    subnet = aws.ec2.Subnet(f"{name}-subnet", vpc_id=vpc.id, cidr_block="0.0.0.0/0")
    # This is obviously wrong, but in more complex code, it's easy to miss
    
    return vpc, subnet

# SECURE: Pulumi with Stack Reference isolation and policy packs
vpc = aws.ec2.Vpc("secure-vpc",
    cidr_block="10.0.0.0/16",
    enable_dns_hostnames=True,
    enable_dns_support=True,
    tags={"Name": "secure-vpc", "Environment": pulumi.get_stack()}
)

# Pulumi Policy Pack (enforcement at the organization level)
# policies.py:
from pulumi_policy import PolicyPack, ResourceValidationPolicy, ReportViolation

def validate_no_public_ingress(args):
    if args.resource_type == "aws:ec2/securityGroupRule":
        if args.props.get("cidr_blocks") and "0.0.0.0/0" in args.props["cidr_blocks"]:
            if args.props.get("type") == "ingress":
                args.report_violation("Security group allows public ingress")

PolicyPack(
    name="secure-infra",
    enforcement_level="mandatory",  # Block on violation, not just warn
    policies=[
        ResourceValidationPolicy(
            name="no-public-ingress",
            description="No security group allows public ingress",
            validate=validate_no_public_ingress,
        ),
    ],
)
```

---

## 6. Drift Detection and Runtime Security

### 6.1 IaC Drift

```
+------------------------------------------------------------------+
|                    IaC Drift Problem                              |
|                                                                    |
|  IaC Definition (Desired State)          Runtime (Actual State)    |
|  ┌───────────────────────┐             ┌───────────────────────┐ |
|  │ Security Group:        │             │ Security Group:        │ |
|  │   Ingress: 443 from   │             │   Ingress: 443 from   │ |
*  │            10.0.0.0/8 │      ≠      │            10.0.0.0/8 │ |
|  │                        │             │   Ingress: 22 from    │ |
|  │                        │             │            0.0.0.0/0 │ |
|  │                        │             │            (DRIFT!)   │ |
*  └───────────────────────┘             └───────────────────────┘ |
|                                                                    |
|  Drift sources:                                                    |
|  1. Manual console changes                                         |
|  2. API changes outside IaC                                        |
|  3. Compromised credentials making changes                        |
|  4. Auto-scaling or cloud-init modifications                      |
|  5. Security incidents (attacker modifying resources)              |
+------------------------------------------------------------------+
```

### 6.2 Drift Detection Implementation

```bash
# Terraform drift detection
terraform plan -detailed-exitcode

# Exit codes:
# 0 - No changes (in sync)
# 1 - Error
# 2 - Changes detected (drift or IaC changes)

# Automated drift detection script
#!/bin/bash
cd /path/to/terraform/environments/production
terraform init -backend-config="key=production/terraform.tfstate"
terraform plan -detailed-exitcode -out=drift-check.tfplan

EXIT_CODE=$?

if [ $EXIT_CODE -eq 2 ]; then
    echo "DRIFT DETECTED! Resources have changed outside Terraform."
    terraform show -json drift-check.tfplan | jq '.resource_changes[] | select(.change.actions != ["no-op"]) | {type: .type, name: .name, actions: .change.actions}'
    
    # Send alert
    aws sns publish --topic-arn $ALERT_TOPIC --message "Infrastructure drift detected in production environment"
elif [ $EXIT_CODE -eq 0 ]; then
    echo "No drift detected. Infrastructure is in sync."
elif [ $EXIT_CODE -eq 1 ]; then
    echo "Error running terraform plan. Check configuration."
fi
```

```python
# CloudFormation drift detection
import boto3

client = boto3.client('cloudformation')

def check_drift(stack_name):
    # Start drift detection
    response = client.detect_stack_drift(StackName=stack_name)
    detection_id = response['StackDriftDetectionId']
    
    # Wait for completion
    waiter = client.get_waiter('stack_drift_detection_complete')
    waiter.wait(StackName=stack_name, StackDriftDetectionId=detection_id)
    
    # Get results
    response = client.describe_stack_resource_drifts(StackName=stack_name)
    
    drifted_resources = [
        r for r in response['StackResourceDrifts']
        if r['StackResourceDriftStatus'] == 'MODIFIED'
    ]
    
    if drifted_resources:
        print(f"DRIFT DETECTED in {stack_name}:")
        for resource in drifted_resources:
            print(f"  {resource['LogicalResourceId']} ({resource['ResourceType']})")
            for diff in resource['PropertyDifferences']:
                print(f"    {diff['PropertyPath']}: {diff['ActualValue']} (expected: {diff['ExpectedValue']})")
    
    return drifted_resources
```

---

## 7. Supply Chain in Terraform Providers

### 7.1 Provider Supply Chain Risks

```
+------------------------------------------------------------------+
|                    Terraform Provider Supply Chain                 |
|                                                                    |
|  ┌───────────────┐                                                |
|  │ Terraform     │    Downloads    ┌───────────────┐              |
|  │ Registry      │──────→──────────│ Provider      │              |
|  │ (registry.io) │                 │ Binary        │              |
*  └───────────────┘                 └───────┬───────┘              |
|                                            │                      |
|                                     Executes as                  |
|                                     host process                 |
|                                            │                      |
*                                            v                      |
|                                    ┌───────────────┐              |
|                                    │ Cloud API      │              |
|                                    │ (AWS/Azure/GCP)│              |
|                                    └───────────────┘              |
|                                                                    |
|  Attack Vectors:                                                   |
|  1. Malicious provider on Terraform Registry                      |
|  2. Compromised developer account pushing fake version             |
|  3. Typosquatting (hashicorp/aws vs hash1corp/aws)                |
|  4. Brandjacking (using similar names/icons)                      |
|  5. Compromised CI pipeline injecting malicious binary             |
|  6. Provider binary signed but not verified                        |
|  7. Provider uses third-party libraries with vulnerabilities       |
+------------------------------------------------------------------+
```

### 7.2 Provider Verification

```hcl
# Terraform provider verification (0.13+)
# The .terraform.lock.hcl file pins provider hashes

# .terraform.lock.hcl
provider "registry.terraform.io/hashicorp/aws" {
  version     = "5.31.0"
  constraints = ">= 5.31.0"
  hashes = [
    "h1:0EsALgCOqGOhGJ/OqqKpMH7GZ1IKBRpF4Fd5gY5R12A=",  # SHA256 hash of the provider binary
    "zh:0e7f491d5c67f6d2c67a5e6b7b6852c2e9b8be0083e5e5d7c88e8a8b7c6d5e4f3",
    # zh: = zip hash (hash of the provider distribution zip)
  ]
}

# To verify providers:
terraform providers lock
terraform providers mirror /path/to/mirror

# To manually verify provider integrity:
sha256sum ~/.terraform/providers/registry.terraform.io/hashicorp/aws/5.31.0/linux_amd64/terraform-provider-aws_v5.31.0_x5
```

### 7.3 Module Supply Chain

```hcl
# VULNERABLE: Using untrusted Terraform modules
module "vpc" {
  source  = "github.com/unknown-org/terraform-aws-vpc"  # Untrusted source!
  version = "1.0.0"
}

# SECURE: Using verified modules with hash verification
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.31.0"
    }
  }
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.5.0"  # Pin to specific version
  
  # Verify module source
  # Use private registry with signed modules
  # Avoid GitHub source URLs — prefer registry with checksum verification
}

# Secure module sourcing patterns:
# 1. Private Terraform registry (requires authentication)
module "vpc" {
  source  = "app.terraform.io/my-org/vpc/aws"
  version = "1.0.0"
}

# 2. Git source with tag pinning (more secure than branch)
module "vpc" {
  source  = "git::https://github.com/my-org/terraform-aws-vpc.git?ref=v1.0.0"
}

# 3. Local source (for internal modules)
module "vpc" {
  source = "./modules/vpc"
}
```

---

## 8. OIDC Trust Configuration Errors

### 8.1 OIDC in IaC Pipelines

```yaml
# GitHub Actions OIDC trust for Terraform
# This replaces long-lived AWS access keys with short-lived OIDC tokens

# .github/workflows/terraform.yml
name: Terraform Deployment
on:
  push:
    branches: [main]

jobs:
  terraform:
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # Required for OIDC
      contents: read
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActions-Terraform
          aws-region: us-east-1
          # No access key needed! OIDC token from GitHub is used
```

### 8.2 Common OIDC Trust Misconfigurations

```json
// VULNERABLE: Overly permissive OIDC trust policy for GitHub Actions
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
      }
      // MISSING: Subject condition!
      // This allows ANY GitHub repository to assume this role
    }
  }]
}

// SECURE: Properly scoped OIDC trust policy
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
      },
      "StringLike": {
        "token.actions.githubusercontent.com:sub": "repo:my-org/my-terraform-repo:ref:refs/heads/main"
      },
      "StringEquals": {
        "token.actions.githubusercontent.com:repository_owner": "my-org"
      }
    }
  }]
}
```

```hcl
# Terraform configuration for secure OIDC trust
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab5fb691e1f1d659a525f5746c7b0"]  # GitHub's thumbprint

  # Verify the OIDC provider's signing key
  # This prevents token forgery
}

resource "aws_iam_role" "github_actions_terraform" {
  name = "GitHubActions-Terraform"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.github.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:my-org/my-terraform-repo:ref:refs/heads/main"
        }
      }
    }]
  })
}

# Least-privilege policy for the OIDC role
resource "aws_iam_role_policy" "github_actions_terraform" {
  role = aws_iam_role.github_actions_terraform.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.terraform_state.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem"
        ]
        Resource = aws_dynamodb_table.terraform_lock.arn
      }
    ]
  })
}
```

---

## 9. Secrets Management in IaC

### 9.1 Secrets Management Architecture

```
+------------------------------------------------------------------+
|                    Secrets Management in IaC                       |
|                                                                    |
|  Option 1: Plain Text (NEVER DO THIS)                             |
|  resource "aws_db_instance" "db" {                                |
|    password = "SuperSecret123!"   ← Visible in code, state, Git  |
|  }                                                                 |
|                                                                    |
|  Option 2: Terraform Variables (Better, but still in state)       |
|  variable "db_password" {}                                        |
|  resource "aws_db_instance" "db" {                               |
|    password = var.db_password     ← Not in code, but IN STATE     |
|  }                                                                 |
|                                                                    |
|  Option 3: Secrets Manager (Best for AWS)                         |
|  data "aws_secretsmanager_secret" "db_password" {}                |
|  data "aws_secretsmanager_secret_version" "db_password" {}        |
|  resource "aws_db_instance" "db" {                                |
|    password = data.aws_secretsmanager_secret_version.db_password   |
|  }                                                                 |
|  ← Still in state! Mark with `sensitive = true`                  |
|                                                                    |
|  Option 4: External Secret Store (Best overall)                   |
|  Vault generic secret → Terraform data source → Resource          |
|  ← Secret fetched at runtime, NOT stored in state                 |
+------------------------------------------------------------------+
```

### 9.2 HashiCorp Vault Integration

```hcl
# Terraform + Vault integration for secrets
provider "vault" {
  address = "https://vault.company.com:8200"
  token   = var.vault_token  # Set via environment variable, never in code
}

# Read secret from Vault (NOT stored in state)
data "vault_generic_secret" "db_credentials" {
  path = "secret/data/production/database"
}

resource "aws_db_instance" "database" {
  engine   = "mysql"
  username = data.vault_generic_secret.db_credentials.data["username"]
  password = data.vault_generic_secret.db_credentials.data["password"]
  
  # Mark as sensitive to prevent output in logs
  lifecycle {
    ignore_changes = [password]  # Don't track password changes in state
  }
}

# Alternative: AWS Secrets Manager with dynamic refresh
resource "aws_db_instance" "database" {
  engine   = "mysql"
  username = "admin"
  password = aws_secretsmanager_secret_version.db_password.secret_string
  
  # Auto-rotate password via Secrets Manager
  lifecycle {
    ignore_changes = [password]
  }
}

resource "aws_secretsmanager_secret" "db_password" {
  name                    = "prod/database/password"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id = aws_secretsmanager_secret.db_password.id
  secret_string = jsonencode({
    username = "admin"
    password = random_password.db_password.result
    engine   = "mysql"
    host     = aws_db_instance.database.address
    port     = 3306
    dbname   = "mydb"
  })
}

resource "aws_secretsmanager_secret_rotation" "db_password" {
  secret_id          = aws_secretsmanager_secret.db_password.id
  rotation_lambda_arn = aws_lambda_function.password_rotation.arn
  
  rotation_rules {
    automatically_after_days = 30
  }
}
```

---

## 10. Policy-as-Code

### 10.1 Open Policy Agent (OPA) / Rego

```rego
# OPA Policy: Prevent public S3 buckets
package terraform.security

# Deny public ACL on S3 buckets
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    resource.change.after.acl == "public-read"
    msg := sprintf("S3 bucket '%s' has public-read ACL", [resource.name])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    resource.change.after.acl == "public-read-write"
    msg := sprintf("S3 bucket '%s' has public-read-write ACL", [resource.name])
}

# Deny security groups allowing ingress from 0.0.0.0/0 on any port except 80/443
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group_rule"
    resource.change.after.type == "ingress"
    resource.change.after.cidr_blocks[_] == "0.0.0.0/0"
    port := resource.change.after.from_port
    not is_allowed_public_port(port)
    msg := sprintf("Security group rule allows public ingress on port %d", [port])
}

is_allowed_public_port(80) { true }
is_allowed_public_port(443) { true }
is_allowed_public_port(port) { false }

# Deny IAM policies with full privileges
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_role_policy"
    policy := json_decode(resource.change.after.policy)
    statement := policy.Statement[_]
    statement.Effect == "Allow"
    statement.Action[_] == "*"
    statement.Resource[_] == "*"
    msg := sprintf("IAM policy for '%s' grants full privileges (*:*)", [resource.name])
}

# Require encryption at rest for all storage resources
deny[msg] {
    resource := input.resource_changes[_]
    is_storage_resource(resource.type)
    not has_encryption(resource)
    msg := sprintf("Storage resource '%s' of type '%s' does not have encryption at rest", [resource.name, resource.type])
}

is_storage_resource("aws_s3_bucket") { true }
is_storage_resource("aws_ebs_volume") { true }
is_storage_resource("aws_rds_cluster") { true }

has_encryption(resource) {
    resource.type == "aws_s3_bucket"
    resource.change.after.server_side_encryption_configuration != null
}

has_encryption(resource) {
    resource.type == "aws_ebs_volume"
    resource.change.after.encrypted == true
}
```

### 10.2 Checkov

```bash
# Checkov: Static analysis for IaC security

# Scan Terraform files
checkov -d /path/to/terraform --framework terraform

# Scan specific checks
checkov -d /path/to/terraform --check CKV_AWS_18,CKV_AWS_19,CKV_AWS_20

# Key Checkov checks for AWS:
# CKV_AWS_18: Ensure S3 bucket has access logging
# CKV_AWS_19: Ensure S3 bucket has versioning
# CKV_AWS_20: Ensure S3 bucket is not publicly accessible
# CKV_AWS_23: Ensure S3 bucket encryption at rest
# CKV_AWS_24: Ensure no security groups allow ingress from 0.0.0.0/0 to SSH
# CKV_AWS_33: Ensure KMS key rotation is enabled
# CKV_AWS_46: Ensure no IAM policies allow *:* permissions
# CKV_AWS_52: Ensure S3 bucket has MFA delete enabled
# CKV_AWS_53: Ensure S3 bucket has public access block
# CKV_AWS_57: Ensure S3 bucket policy requires encryption in transit

# Custom check (Python):
# checkov/custom_checks/s3_no_public_acl.py
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

class S3NoPublicACL(BaseResourceCheck):
    def __init__(self):
        name = "Ensure S3 bucket does not have public ACL"
        id = "CKV_CUSTOM_001"
        supported_resources = ["aws_s3_bucket_acl"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        acl = conf.get("acl", [None])[0]
        if acl in ["public-read", "public-read-write", "public-read-delivered"]:
            return CheckResult.FAILED
        return CheckResult.PASSED
```

### 10.3 Terraform Sentinel

```python
# Sentinel policy for Terraform Cloud/Enterprise

# Require encryption for all S3 buckets
import "tfplan/v2" as tfplan

S3_buckets = filter tfplan.resource_changes as _ {
    _.type is "aws_s3_bucket" and
    _.mode is "managed" and
    _.change.actions is not ["delete"]
}

encryption_required = rule {
    all S3_buckets as _ {
        _.change.after.server_side_encryption_configuration is not null or
        _.change.after.new_ is null  # bucket is being deleted
    }
}

# Deny IAM policies with *:*
all_resources = filter tfplan.resource_changes as _ {
    _.mode is "managed" and _.change.actions is not ["delete"]
}

no_wildcard_iam = rule {
    all all_resources as _ {
        not _.change.after.policy matches "*Action*:\s*\*\s*" or
        not _.change.after.policy matches "*Resource*:\s*\*\s*"
    }
}

# Main rule
main = rule {
    encryption_required and no_wildcard_iam
}
```

---

## 11. Terraform Plan Security Review

### 11.1 Plan Review Process

```bash
# Step 1: Generate a detailed plan
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Step 2: Review the plan for security changes
# Focus on:
# - IAM policy changes (new policies, modified policies)
# - Security group changes (ingress rules, egress rules)
# - Encryption changes (enabled/disabled)
# - Public access changes (S3, storage accounts)
# - Network changes (VPC, subnets, routing)

# Step 3: Extract security-relevant changes
jq '.resource_changes[] | select(.type | test("aws_iam|aws_security_group|aws_s3_bucket|aws_kms_key|aws_vpc|aws_route|aws_db_instance")) | {type: .type, name: .name, actions: .change.actions}' tfplan.json

# Step 4: Review specific changes in detail
# IAM policy changes:
jq '.resource_changes[] | select(.type == "aws_iam_role_policy") | .change.after.policy' tfplan.json | jq '.'

# Security group changes:
jq '.resource_changes[] | select(.type | startswith("aws_security_group")) | .change.after.ingress' tfplan.json

# S3 bucket changes:
jq '.resource_changes[] | select(.type == "aws_s3_bucket") | {name: .name, acl: .change.after.acl, versioning: .change.after.versioning}' tfplan.json

# Step 5: Run policy-as-code against the plan
checkov -f tfplan.json --framework terraform_plan
```

### 11.2 Automated Plan Review Pipeline

```yaml
# GitHub Actions: Automated Terraform plan review
name: Terraform Security Review
on:
  pull_request:
    paths: ['terraform/**']

jobs:
  security-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
      
      - name: Terraform Init
        run: terraform init
        working-directory: terraform
      
      - name: Terraform Plan
        run: terraform plan -out=tfplan
        working-directory: terraform
      
      - name: Terraform Show (JSON)
        run: terraform show -json tfplan > tfplan.json
        working-directory: terraform
      
      - name: Checkov security scan
        uses: bridgecrewio/checkov-action@master
        with:
          directory: terraform
          framework: terraform
          output_format: cli,sarif
          output_file_path: console,results.sarif
          soft_fail: false
      
      - name: tfsec security scan
        uses: aquasecurity/tfsec-action@v1.0.0
        with:
          soft_fail: false
      
      - name: OPA policy check
        run: |
          opa eval --data policies/ --input tfplan.json "data.terraform.security.deny"
          if [ $? -ne 0 ]; then
            echo "Policy violations detected!"
            exit 1
          fi
        working-directory: terraform
      
      - name: Plan summary
        run: |
          echo "=== Security-relevant changes ==="
          jq '.resource_changes[] | select(.type | test("iam|security_group|s3_bucket|kms|vpc")) | .name' tfplan.json
          echo ""
          echo "=== Potential risk changes ==="
          jq '.resource_changes[] | select(.change.actions | index("create") or index("update")) | select(.type | test(" iam|security_group")) | .change.after' tfplan.json
        working-directory: terraform
```

**Cross-reference**: IaC security is deeply connected to cloud IAM (see `01b_identity_access_management.md` for IAM policy patterns), cloud architecture (see `01a_cloud_architecture_security.md` for trust boundary definitions), and supply chain security (see `supply_chain_security/docs/` for broader supply chain attack patterns). The OIDC trust misconfigurations described here are the same class of vulnerability as the OIDC federation attacks in `01b_identity_access_management.md`.

---

*Next: [04a — Cloud Exploitation Techniques](04a_cloud_exploitation_techniques.md)*

---

## References

1. HashiCorp. "Terraform Security Best Practices." *HashiCorp Developer*. 2024. https://developer.hashicorp.com/terraform/tutorials/security
2. Amazon. "CloudFormation Security." *Amazon Web Services*. 2024. https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/security-best-practices.html
3. Pulumi. "Pulumi Security." *Pulumi Documentation*. 2024. https://www.pulumi.com/docs/security/
4. Open Policy Agent. "OPA Rego Policy Reference." *Open Policy Agent*. 2024. https://www.openpolicyagent.org/docs/latest/policy-reference/
5. Bridgecrew. "Checkov Documentation." *Bridgecrew by Prisma Cloud*. 2024. https://www.checkov.io/
6. HashiCorp. "Sentinel Policy-as-Code." *HashiCorp Developer*. 2024. https://developer.hashicorp.com/sentinel
7. SLSA. "Supply Chain Levels for Software Artifacts." *SLSA Framework*. 2024. https://slsa.dev/spec/
8. CIS. "CIS Benchmarks: AWS, Azure, GCP, Kubernetes." *Center for Internet Security*. 2024. https://www.cisecurity.org/cis-benchmarks/
9. AWS. "OIDC Identity Providers for GitHub Actions." *Amazon Web Services*. 2024. https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html
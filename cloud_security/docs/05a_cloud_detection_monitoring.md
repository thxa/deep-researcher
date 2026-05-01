# Cloud Detection and Monitoring

## CloudTrail, GuardDuty, Falco, eBPF, and MITRE ATT&CK Cloud Matrix

---

## Table of Contents

1. [Cloud Detection Architecture](#1-cloud-detection-architecture)
2. [AWS CloudTrail and GuardDuty](#2-aws-cloudtrail-and-guardduty)
3. [Azure Monitor and Sentinel](#3-azure-monitor-and-sentinel)
4. [GCP Cloud Audit Logs](#4-gcp-cloud-audit-logs)
5. [Detection Engineering for Cloud-Native Attacks](#5-detection-engineering-for-cloud-native-attacks)
6. [SIEM Integration Challenges](#6-siem-integration-challenges)
7. [MITRE ATT&CK Cloud Matrix Mapping](#7-mitre-attck-cloud-matrix-mapping)
8. [Falco for Runtime Container Detection](#8-falco-for-runtime-container-detection)
9. [eBPF-Based Security Monitoring](#9-ebpf-based-security-monitoring)

---

## 1. Cloud Detection Architecture

### 1.1 Detection Stack

```
+------------------------------------------------------------------+
|                    Cloud Detection Architecture                    |
|                                                                    |
|  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              |
|  │ Data Sources │  │ Collection  │  │ Analysis    │              |
*  │              │  │ Layer       │  │ Layer       │              |
|  │ CloudTrail   │  │ Kinesis/Fn  │  │ GuardDuty   │              |
|  │ VPC Flow    │──→│ Event Hub  │──→│ ML Models  │              |
|  │ DNS Logs    │  │ Pub/Sub     │  │ Rule Engine │              |
|  │ S3 Access   │  │ IoT Core   │  │ Correlation │              |
|  └─────────────┘  └─────────────┘  └──────┬──────┘              |
|                                            │                      |
|                                            v                      |
|  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              |
|  │ Response    │  │ Visibility  │  │ Storage     │              |
|  │ Layer       │  │ Layer       │  │ Layer       │              |
|  │ Lambda/Step │  │ Dashboards  │  │ S3/Blob/    │              |
|  │ Functions    │  │ Alerts      │  │ GCS/BigQuery│              |
|  │ SSM/RunCmd │  │ Reports     │  │ Hot/Warm/   │              |
|  └─────────────┘  └─────────────┘  │ Cold tiers  │              |
|                                     └─────────────┘              |
+------------------------------------------------------------------+
```

### 1.2 Cloud Service Log Comparison

| Log Type | AWS | Azure | GCP | Retention | Key Use Cases |
|---|---|---|---|---|---|
| **API Audit** | CloudTrail | Activity Log | Cloud Audit Logs | 90 days default | IAM changes, resource mutations |
| **Data Access** | S3 Access Logs | Storage Analytics | Data Access Logs | Variable | S3/Blob read access tracking |
| **Network** | VPC Flow Logs | NSG Flow Logs | VPC Flow Logs | Variable | Network intrusion detection |
| **DNS** | Route53 Resolver | Azure DNS | Cloud DNS | 30 days | Data exfiltration, C2 detection |
| **Console** | CloudTrail Events | Sign-in Logs | Audit Logs | 90 days | Unauthorized access attempts |
| **Config** | AWS Config | Azure Policy | Security Command Center | Variable | Configuration drift detection |

---

## 2. AWS CloudTrail and GuardDuty

### 2.1 CloudTrail Configuration

```terraform
# Secure CloudTrail configuration
resource "aws_cloudtrail" "main" {
  name                          = "organization-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail.arn
  is_organization_trail          = true

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::${aws_s3_bucket.data.arn}/*"]
    }

    data_resource {
      type   = "AWS::Lambda::Function"
      values = ["arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:*"]
    }
  }
}

# S3 bucket for CloudTrail logs (secure configuration)
resource "aws_s3_bucket" "cloudtrail" {
  bucket = "cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cloudtrail.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}
```

### 2.2 GuardDuty Configuration

```bash
# Enable GuardDuty in all regions
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws guardduty create-detector \
    --region $region \
    --enable \
    --data-sources '{"S3Logs":{"Enable":true},"Kubernetes":{"AuditLogs":{"Enable":true}}}' \
    --finding-publishing-frequency FIFTEEN_MINUTES
done

# GuardDuty finding types for cloud attacks:
# UnauthorizedAccess:IAMUser/InstanceCredentialCompromise
#   - EC2 instance credentials used from external IP
# Persistence:IAMUser/RolePersistence
#   - IAM role created with overly permissive trust policy
# PrivilegeEscalation:IAMUser/AdministrativeAction
#   - Administrative action by unusual user
# CredentialAccess:IAMUser/AnomalousBehavior
#   - Unusual API call pattern for credentials
# Exfiltration:IAMUser/AnomalousBehavior
#   - Unusual data access pattern
# Impact:S3/MaliciousIPCaller
#   - S3 API from known malicious IP
```

### 2.3 Key CloudTrail Events for Detection

```json
// CloudTrail event patterns for detecting cloud attacks

// 1. IAM privilege escalation
{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": [
      "CreateAccessKey",
      "CreateLoginProfile",
      "AttachUserPolicy",
      "AttachRolePolicy",
      "PutUserPolicy",
      "PutRolePolicy",
      "AddUserToGroup"
    ]
  }
}

// 2. AssumeRole from unusual source
{
  "source": ["aws.sts"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"],
    "userIdentity": {
      "accountId": ["!{your-account-id}"]
    }
  }
}

// 3. S3 bucket policy changes
{
  "source": ["aws.s3"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["PutBucketPolicy", "DeleteBucketPolicy", "PutBucketAcl"]
  }
}

// 4. Security group changes allowing public access
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress"],
    "requestParameters": {
      "cidrIpv6": ["::/0"],
      "fromPort": [0, 22, 3389, 443, 80]
    }
  }
}

// 5. CloudTrail logging disabled
{
  "source": ["aws.cloudtrail"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["StopLogging", "DeleteTrail", "UpdateTrail"]
  }
}

// 6. IMDSv1 usage (should be IMDSv2)
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["RunInstances", "ModifyInstanceMetadataOptions"],
    "requestParameters": {
      "metadataOptions": {
        "httpTokens": ["optional"]
      }
    }
  }
}
```

---

## 3. Azure Monitor and Sentinel

### 3.1 Azure Sentinel Detection Rules

```kql
// KQL Detection Rule: Unusual IAM activity
// Detect mass IAM changes that may indicate privilege escalation

let timeframe = 1h;
let threshold = 10;
AzureActivity
| where TimeGenerated > ago(timeframe)
| where OperationNameValue in (
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/roleAssignments/delete",
    "Microsoft.Authorization/roleDefinitions/write",
    "Microsoft.Authorization/roleDefinitions/delete"
)
| summarize RoleChangeCount = count() by Caller, bin(TimeGenerated, 5m)
| where RoleChangeCount > threshold
| join kind=inner (
    AzureActivity
    | where TimeGenerated > ago(timeframe)
    | where OperationNameValue in (
        "Microsoft.Authorization/roleAssignments/write",
        "Microsoft.Authorization/roleAssignments/delete"
    )
    | project Caller, TimeGenerated, OperationNameValue, ResourceGroup, Properties
) on Caller
| project TimeGenerated, Caller, RoleChangeCount, OperationNameValue, ResourceGroup, Properties

// KQL Detection Rule: IMDS token usage from outside Azure
// Detects tokens issued via IMDS being used from non-Azure IPs

let azureIPs = dynamic(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == 0
| where IPAddress !in (azureIPs)
| where AppDisplayName contains "Azure"
| where AuthenticationDetails contains "Managed Identity"
| project TimeGenerated, UserDisplayName, UserPrincipalName, IPAddress, AppDisplayName, AuthenticationDetails

// KQL Detection Rule: Storage account key retrieval
// Detects storage account key list operations which may indicate data exfiltration prep

AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue == "Microsoft.Storage/storageAccounts/listKeys/action"
| summarize KeyRetrieveCount = count() by Caller, bin(TimeGenerated, 1h)
| where KeyRetrieveCount > 5
| project TimeGenerated, Caller, KeyRetrieveCount

// KQL Detection Rule: Cross-tenant access
// Detects access from external tenants

SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| where ResourceTenantId != HomeTenantId
| summarize ForeignAccessCount = count() by UserPrincipalName, ResourceTenantId, HomeTenantId, IPAddress
| project TimeGenerated, UserPrincipalName, ResourceTenantId, HomeTenantId, IPAddress, ForeignAccessCount
```

### 3.2 Microsoft Defender for Cloud

```bash
# Enable Microsoft Defender for Cloud
az security pricing create --name VirtualMachines --tier Standard
az security pricing create --name StorageAccounts --tier Standard
az security pricing create --name SqlServers --tier Standard
az security pricing create --name AppServices --tier Standard
az security pricing create --name KeyVaults --tier Standard
az security pricing create --name KubernetesService --tier Standard
az security pricing create --name Containers --tier Standard
az security pricing create --name Dns --tier Standard
az security pricing create --name Arm --tier Standard

# Key Defender for Cloud alerts:
# - VM_ImpossibleTravel: Sign-in from impossible location
# - VM_SuspiciousProcess: Suspicious process execution
# - Storage_AnomalousAccess: Anomalous storage access pattern
# - KeyVault_AnomalousAccess: Anomalous key vault access
# - AKS_SuspiciousDeployment: Suspicious AKS deployment
# - ARM_SuspiciousDeployment: Suspicious ARM deployment
```

---

## 4. GCP Cloud Audit Logs

### 4.1 GCP Audit Log Configuration

```bash
# Enable Data Access audit logs for all services
# These are OFF by default and must be explicitly enabled

# Enable for all services
gcloud projects get-iam-policy ${PROJECT_ID} --format=json > policy.json

# Update policy to enable data access logging for all services
cat policy.json | jq '.auditConfigs = [
  {
    "service": "allServices",
    "auditLogConfigs": [
      {"logType": "ADMIN_READ"},
      {"logType": "DATA_READ"},
      {"logType": "DATA_WRITE"}
    ]
  }
]' > updated-policy.json

gcloud projects set-iam-policy ${PROJECT_ID} updated-policy.json

# Key GCP audit log events for security detection:
# 1. IAM policy changes
gcloud logging read 'logName="projects/${PROJECT_ID}/logs/cloudaudit.googleapis.com%2Factivity" 
  AND protoPayload.methodName="SetIamPolicy"' --limit=100

# 2. Service account key creation (potential exfiltration)
gcloud logging read 'logName="projects/${PROJECT_ID}/logs/cloudaudit.googleapis.com%2Factivity" 
  AND protoPayload.methodName="CreateServiceAccountKey"' --limit=100

# 3. Storage bucket access (exfiltration indicator)
gcloud logging read 'logName="projects/${PROJECT_ID}/logs/cloudaudit.googleapis.com%2Fdata_access" 
  AND protoPayload.methodName="storage.objects.get"
  AND protoPayload.authenticationInfo.principalEmail!="expected-user@company.com"' --limit=100

# 4. Compute instance metadata changes (IMDS attack indicator)
gcloud logging read 'logName="projects/${PROJECT_ID}/logs/cloudaudit.googleapis.com%2Factivity" 
  AND protoPayload.methodName="compute.instances.setMetadata"' --limit=100
```

---

## 5. Detection Engineering for Cloud-Native Attacks

### 5.1 Detection Rule Taxonomy

| Attack Stage | Detection Type | AWS | Azure | GCP |
|---|---|---|---|---|
| **Initial Access** | Anomaly | Console login from new IP | Sign-in from new IP | Login from new IP |
| **Execution** | Signature | Lambda invocation from unusual source | Function execution from unusual IP | Cloud Function invocation |
| **Persistence** | Signature | IAM role creation, Lambda layer update | App registration creation | Service account key creation |
| **Privilege Escalation** | Signature + Anomaly | AssumeRole from unusual source | Role assignment elevation | IAM policy change |
| **Defense Evasion** | Signature | CloudTrail logging disabled | Diagnostic setting deletion | Audit log configuration change |
| **Credential Access** | Anomaly | IMDS access from unusual source | Managed identity token request | Service account key usage |
| **Discovery** | Anomaly | Unusual API call patterns | Unusual ARM template deployment | Unusual resource enumeration |
| **Lateral Movement** | Anomaly | Cross-account role assumption | Cross-tenant access | Project-to-project access |
| **Exfiltration** | Anomaly | Large S3 download, unusual regions | Storage account download | Storage object download |
| **Impact** | Signature | Resource deletion, ransomware | Resource group deletion | Project resource deletion |

### 5.2 Sigma Rules for Cloud Detection

```yaml
# Sigma Rule: AWS IAM Access Key Creation from Unusual Source
title: AWS IAM Access Key Created From Unusual Source
id: 3e8a4f12-8a3e-4a1b-9c3d-5e6f7a8b9c0d
status: experimental
description: Detects creation of IAM access keys from unusual sources that may indicate credential theft
author: Security Research Team
date: 2024/01/15
references:
    - https://attack.mitre.org/techniques/T1078/
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: iam.amazonaws.com
        eventName: CreateAccessKey
    filter_automation:
        userIdentity.arn|endswith:
            - 'automation-role'
            - 'terraform-role'
            - 'cicd-role'
    filter_expected_ips:
        sourceIpAddress|cidr:
            - '10.0.0.0/8'
            - '172.16.0.0/12'
            - '192.168.0.0/16'
    condition: selection and not filter_automation and not filter_expected_ips
level: medium
tags:
    - attack.credential_access
    - attack.t1078
    - attack.t1550

---
# Sigma Rule: AWS S3 Data Exfiltration
title: AWS S3 Large Data Exfiltration
id: 5f9a0e23-7b4c-4d5e-9a6f-1b2c3d4e5f6a
status: experimental
description: Detects large-scale S3 data exfiltration
author: Security Research Team
date: 2024/01/15
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: s3.amazonaws.com
        eventName|contains:
            - GetObject
            - CopyObject
    condition: selection | count() by userIdentity.arn > 1000
    timeframe: 1h
level: high
tags:
    - attack.exfiltration
    - attack.t1567
```

---

## 6. SIEM Integration Challenges

### 6.1 Cloud Logging Architecture

```
+------------------------------------------------------------------+
|                    Cloud → SIEM Integration                         |
|                                                                    |
|  AWS                    Azure                     GCP                |
|  ┌──────────┐          ┌──────────┐          ┌──────────┐         |
|  │CloudTrail│          │Activity  │          │Audit Logs│         |
*  │  Logs    │          │Log +     │          │+ Data    │         |
|  │ + VPC    │          │Sentinel  │          │Access    │         |
|  │ Flow    │          │Alerts    │          │Logs      │         |
*  └────┬─────┘          └────┬─────┘          └────┬─────┘         |
|       │                     │                     │                |
|       v                     v                     v                |
|  ┌──────────┐          ┌──────────┐          ┌──────────┐         |
|  │Kinesis   │          │Event Hub │          │Pub/Sub   │         |
|  │Firehose  │          │          │          │          │         |
|  └────┬─────┘          └────┬─────┘          └────┬─────┘         |
|       │                     │                     │                |
|       └─────────────────────┼─────────────────────┘                |
|                             │                                      |
|                             v                                      |
|                    ┌──────────────────┐                            |
|                    │   SIEM Platform  │                            |
|                    │  (Splunk/QRadar/ │                            |
|                    │   Sentinel/ELK)  │                            |
*                    └──────┬───────────┘                            |
|                           │                                        |
|                           v                                        |
|                    ┌──────────────────┐                            |
|                    │   Detection Rules │                            |
|                    │   Correlation     │                            |
|                    │   Automation      │                            |
|                    └──────────────────┘                            |
+------------------------------------------------------------------+
```

### 6.2 Key Integration Challenges

| Challenge | Description | Mitigation |
|---|---|---|
| **Log volume** | Cloud logs generate massive data volumes | Selective logging, tiered storage |
| **Log format** | Each provider uses different formats | Normalize with ECS/OCSF |
| **Latency** | Cloud log delivery can be delayed | Use real-time alerts for critical events |
| **Cost** | Ingestion and storage costs grow with volume | Optimize retention, hot/warm/cold tiers |
| **Multi-account** | Logs distributed across accounts | Centralized logging, organization trail |
| **Context loss** | Cloud events lack host-level context | Correlate with endpoint and network logs |

---

## 7. MITRE ATT&CK Cloud Matrix Mapping

### 7.1 Cloud-Specific ATT&CK Techniques

| Tactic | Technique | Cloud Implementation | Detection |
|---|---|---|---|
| **Initial Access** | T1078 Valid Accounts | Compromised IAM credentials | CloudTrail login anomalies |
| **Initial Access** | T1190 Exploit Public-Facing App | SSRF to metadata service | WAF rules, GuardDuty |
| **Execution** | T1059 Command Scripting | Lambda/Functions execution | CloudTrail function invocation |
| **Execution** | T1204 User Execution | Phishing for cloud credentials | Sign-in log anomalies |
| **Persistence** | T1133 External Remote Services | VPN, Bastion host persistence | Unusual VPN connections |
| **Persistence** | T1098 Account Manipulation | Backdoor IAM roles | IAM policy change alerts |
| **Persistence** | T1546 Event Triggered Execution | Lambda layers, EventBridge rules | Lambda version change alerts |
| **Privilege Escalation** | T1548 Abuse Elevation Mechanism | IAM privilege escalation paths | CloudTrail IAM escalation alerts |
| **Privilege Escalation** | T1078 Valid Accounts | AssumeRole escalation | Unusual role assumption |
| **Defense Evasion** | T1562 Impair Defenses | Disable CloudTrail/GuardDuty | CloudTrail/GuardDuty modification events |
| **Credential Access** | T1550 Use Alternate Auth Material | SAML token forgery, OIDC replay | Token age anomaly detection |
| **Credential Access** | T1552 Unsecured Credentials | Secrets in code, S3, env vars | Secret scanning tools |
| **Discovery** | T1087 Account Discovery | IAM enumeration | Unusual IAM API call pattern |
| **Discovery** | T1083 File Discovery | S3 bucket enumeration | S3 list operations anomaly |
| **Lateral Movement** | T1534 Internal Spearphishing | Cross-account role assumption | Cross-account activity |
| **Exfiltration** | T1567 Exfiltration Over Web | S3 download, transfer services | Large data transfer detection |
| **Impact** | T1485 Data Destruction | S3 object deletion | S3 delete event monitoring |

---

## 8. Falco for Runtime Container Detection

### 8.1 Falco Architecture

```
+------------------------------------------------------------------+
|                    Falco Runtime Security                          |
|                                                                    |
|  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              |
|  │ Kernel Module│  │ eBPF Probe  │  │ Userspace   │              |
*  │ (syscall)   │  │ (kernel 5+) │  │ Events      │              |
*  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              |
*         │                │                │                      |
*         v                v                v                      |
*  ┌─────────────────────────────────────────────────────────┐      |
*  │                    Falco Engine                           │      |
*  │  - Syscall event stream                                  │      |
*  │  - Rule matching engine                                  │      |
*  │  - Output formatting                                     │      |
*  └─────────────────────────┬───────────────────────────────┘      |
*                            │                                      |
*                            v                                      |
*  ┌─────────────────────────────────────────────────────────┐      |
*  │                    Outputs                                 │      |
*  │  stdout, file, syslog, webhook, CloudWatch, etc.         │      |
*  └─────────────────────────────────────────────────────────┘      |
+------------------------------------------------------------------+
```

### 8.2 Key Falco Rules for Container Security

```yaml
# Falco rules for container runtime security

# Detect privileged container creation
- rule: Launch Privileged Container
  desc: Detect the creation of a privileged container
  condition: >
    container and container.image.repository != "" and
    container.image.repository not in (known_privileged_images) and
    (container.privileged = true or
     container.capabilities in (SYS_ADMIN, SYS_PTRACE, NET_ADMIN))
  output: >
    Privileged container started
    (user=%user.name container=%container.name image=%container.image.repository:%container.image.tag)
  priority: CRITICAL
  tags: [container, privilege]

# Detect container escape via hostPath mount
- rule: Container with HostPath Mount
  desc: Detect containers mounted with host paths
  condition: >
    container and container.image.repository != "" and
    (evt.arg.type = "hostPath" and
     evt.arg.path in ("/", "/etc", "/var/run/docker.sock", "/etc/kubernetes", "/proc", "/sys"))
  output: >
    Container started with sensitive hostPath mount
    (user=%user.name container=%container.name mount=%evt.arg.path)
  priority: CRITICAL
  tags: [container, privilege]

# Detect shell spawned in a container
- rule: Terminal Shell in Container
  desc: A shell was spawned inside a container
  condition: >
    spawned_process and container and
    proc.name in (bash, sh, zsh, fish) and
    container.image.repository not in (known_shell_images)
  output: >
    Shell spawned in container
    (user=%user.name container=%container.name shell=%proc.name parent=%proc.pname)
  priority: NOTICE
  tags: [container, shell]

# Detect outbound connection to metadata service
- rule: Contact Cloud Metadata Service
  desc: Detect outbound connection to cloud metadata service
  condition: >
    outbound and evt.arg.ip in (169.254.169.254) and
    container.id != "" and
    not proc.name in (cloud_metadata_allowed_procs)
  output: >
    Cloud metadata service contacted from container
    (user=%user.name container=%container.name proc=%proc.name ip=%evt.arg.ip)
  priority: CRITICAL
  tags: [cloud, ssrf]

# Detect container running as root
- rule: Container Running as Root
  desc: Detect container running as root user
  condition: >
    container and container.image.repository != "" and
    container.user.uid = 0 and
    container.image.repository not in (known_root_images)
  output: >
    Container running as root
    (user=%user.name container=%container.name image=%container.image.repository)
  priority: WARNING
  tags: [container, privilege]

# Detect read of sensitive files
- rule: Read Sensitive File in Container
  desc: Detect read of sensitive files from inside a container
  condition: >
    container and open_read and
    fd.name in (sensitive_files) and
    container.image.repository not in (known_sensitive_readers)
  output: >
    Sensitive file read in container
    (user=%user.name container=%container.name file=%fd.name)
  priority: WARNING
  tags: [container, data_leak]

# Detect Kubernetes API server access from container
- rule: K8s API Server Contact from Container
  desc: Detect container contacting Kubernetes API server
  condition: >
    outbound and container and
    (evt.arg.ip startswith "10.0.0.1" or
     evt.arg.ip startswith "172.16.0.1" or
     fd.sip.name endswith "kubernetes.default.svc.cluster.local") and
    not proc.name in (kube_proxy_procs)
  output: >
    Container contacting Kubernetes API server
    (user=%user.name container=%container.name proc=%proc.name ip=%evt.arg.ip)
  priority: NOTICE
  tags: [k8s, lateral_movement]
```

---

## 9. eBPF-Based Security Monitoring

### 9.1 eBPF Architecture for Security

```
+------------------------------------------------------------------+
|                    eBPF Security Architecture                      |
|                                                                    |
|  User Space                     Kernel Space                       |
|  ┌──────────────┐              ┌───────────────────────────┐      |
|  │ Tetragon /   │     Maps    │  eBPF Programs            │      |
|  │ Falco (eBPF) │◄───────────►│  - Process execution       │      |
*  │ / BPFTrace   │              │  - System call tracing     │      |
*  └──────────────┘              │  - Network filtering      │      |
*       │                         │  - File access monitoring  │      |
*       v                         │  - Capability checks       │      |
*  ┌──────────────┐              └───────────────────────────┘      |
*  │ Security     │                    │                              |
*  │ Policy Engine│◄───────────────────┘                              |
*  │ (Real-time   │              Kernel Events                        |
*  │  enforcement)│                                                    |
*  └──────────────┘                                                   |
+------------------------------------------------------------------+
```

### 9.2 Tetragon Configuration

```yaml
# Tetragon (Cilium eBPF security monitor) configuration

# TracingPolicy: Monitor process execution in containers
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: process-exec-monitor
spec:
  kprobes:
  - call: "sys_execve"
    syscall: true
    args:
    - index: 0
      type: "string"
    selectors:
    - matchNamespaces:
      - namespace: "mnt"
        values:
        - "/var/run/containerd"
        - "/run/containerd"
    labels:
    - "security"

# TracingPolicy: Monitor capability usage
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: capability-monitor
spec:
  kprobes:
  - call: "cap_capable"
    args:
    - index: 0
      type: "cred"
    - index: 1
      type: "int"
    - index: 2
      type: "int"
    - index: 3
      type: "int"
    selectors:
    - matchCapabilities:
      - CAP_SYS_ADMIN
      - CAP_SYS_PTRACE
      - CAP_NET_ADMIN
      - CAP_SYS_MODULE

# TracingPolicy: Monitor network connections from containers
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: network-monitor
spec:
  kprobes:
  - call: "tcp_connect"
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchNamespaces:
      - namespace: "mnt"
        values:
        - "/var/run/containerd"

# Monitoring eBPF events with Tetragon CLI:
# tetra getevents -o json | jq 'select(.process_kexec | .cap != 0)'
```

### 9.3 eBPF vs Traditional Monitoring

| Feature | eBPF (Tetragon) | Kernel Module (Falco) | Audit Logs |
|---|---|---|---|
| **Performance** | Minimal overhead (<1%) | Low overhead (2-5%) | No local overhead |
| **Coverage** | All syscalls, network, file | Syscalls only | API-level only |
| **Latency** | Real-time (<1ms) | Low latency (~1ms) | High latency (>1s) |
| **Visibility** | Full kernel | Syscall filter | API call only |
| **Container-aware** | Yes (namespace-aware) | Yes (container-aware) | No |
| **Risk** | eBPF verifier limits risk | Kernel module risk | No risk |
| **Kernel version** | 4.10+ (5.3+ recommended) | Any (module support) | Any |
| **Use case** | Runtime security, network policy | Container runtime security | Cloud audit, compliance |

**Cross-reference**: Cloud detection connects to the cloud architecture and IAM tracks (`01a_cloud_architecture_security.md` and `01b_identity_access_management.md`) for understanding the events being monitored. Container runtime detection (Falco, Tetragon) connects to the container security track (`02a_container_security.md`). The MITRE ATT&CK mapping provides the framework for organizing detections across all attack surfaces.

---

*Next: [05b — Cloud Hardening Best Practices](05b_cloud_hardening_best.md)*

---

## References

1. AWS. "CloudTrail Documentation." *Amazon Web Services*. 2024. https://docs.aws.amazon.com/awscloudtrail/latest/userguide/
2. AWS. "GuardDuty Documentation." *Amazon Web Services*. 2024. https://docs.aws.amazon.com/guardduty/latest/ug/
3. Microsoft. "Azure Sentinel Documentation." *Microsoft Learn*. 2024. https://learn.microsoft.com/en-us/azure/sentinel/
4. Google Cloud. "Cloud Audit Logs." *Google Cloud*. 2024. https://cloud.google.com/logging/docs/audit/
5. Falco. "Falco Documentation." *The Falco Project*. 2024. https://falco.org/docs/
6. Isovalent. "Tetragon Documentation." *Isovalent/Cilium*. 2024. https://tetragon.cilium.io/
7. MITRE. "ATT&CK Cloud Matrix." *MITRE Corporation*. 2024. https://attack.mitre.org/matrices/enterprise/cloud/
8. Aqua Security. "Container Threat Report." *Aqua Security*. 2023. https://www.aquasec.com/resources/container-threat-report/
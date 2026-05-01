# Cloud & Container Security — Quick Reference

---

## AWS CLI Security Commands

### IAM Enumeration
```bash
aws iam list-users
aws iam list-roles --query 'Roles[].RoleName'
aws iam list-policies --scope Local
aws iam list-attached-user-policies --user-name <USER>
aws iam list-attached-role-policies --role-name <ROLE>
aws iam list-user-policies --user-name <USER>
aws iam list-role-policies --role-name <ROLE>
aws iam get-policy-version --policy-arn <ARN> --version-id v1
aws iam get-policy --policy-arn <ARN>
aws iam list-access-keys --user-name <USER>
aws iam get-account-summary
aws iam get-authorization-details
aws sts get-caller-identity
aws sts get-access-key-info --access-key-id <AKID>
aws iam decode-authorization-message --encoded-message <MSG>
```

### S3 & Storage
```bash
aws s3 ls                              # List buckets
aws s3 ls s3://<BUCKET> --recursive   # List objects
aws s3api get-bucket-policy --bucket <BUCKET>
aws s3api get-bucket-acl --bucket <BUCKET>
aws s3api get-object-acl --bucket <BUCKET> --key <KEY>
aws s3api get-bucket-versioning --bucket <BUCKET>
aws s3api list-object-versions --bucket <BUCKET>
aws s3api get-bucket-encryption --bucket <BUCKET>
aws s3api get-public-access-block --bucket <BUCKET>
aws ecr describe-repositories
aws ecr list-images --repository-name <REPO>
aws ecr get-login-password --region <REGION>
```

### EC2 & Network
```bash
aws ec2 describe-instances --query 'Reservations[].Instances[].{ID:InstanceId,IP:PrivateIpAddress,State:State.Name}'
aws ec2 describe-security-groups --query 'SecurityGroups[].{ID:GroupId,Name:GroupName}'
aws ec2 describe-network-interfaces
aws ec2 describe-vpcs
aws ec2 describe-subnets
aws ec2 describe-route-tables
aws ec2 describe-nat-gateways
aws ec2 describe-vpn-connections
aws ec2 get-console-output --instance-id <IID>
aws ec2 describe-instance-attribute --instance-id <IID> --attribute userData
aws ec2 describe-instance-attribute --instance-id <IID> --attribute iamInstanceProfile
aws ec2 describe-iam-instance-profile-associations
aws ec2 describe-images --owners self amazon
aws ec2 describe-snapshots --owner-ids self
aws ec2 describe-volumes
aws ec2 describe-key-pairs
```

### Lambda & Serverless
```bash
aws lambda list-functions
aws lambda get-function --function-name <FN>
aws lambda get-policy --function-name <FN>
aws lambda list-layer-versions --layer-name <LAYER>
aws lambda get-layer-version-policy --layer-name <LAYER> --version-number <V>
aws lambda get-function-url-config --function-name <FN>
```

### Secrets & KMS
```bash
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id <ARN>
aws secretsmanager describe-secret --secret-id <ARN>
aws kms list-keys
aws kms describe-key --key-id <KID>
aws kms get-key-policy --key-id <KID>
aws kms list-key-policies --key-id <KID>
aws ssm get-parameters-by-path --path / --recursive --with-decryption
aws ssm get-parameter --name <NAME> --with-decryption
```

---

## Azure CLI Security Commands

```bash
az login
az account list --output table
az account set --subscription <SUB_ID>

# IAM
az ad user list --query '[].{Name:displayName,UPN:userPrincipalName}'
az ad group list
az ad app list
az ad sp list --show-mine
az role assignment list --assignee <PRINCIPAL>
az role definition list --query '[].{Name:roleName,Actions:actions}'
az role definition list --custom true
az policy assignment list

# Resources
az vm list --output table
az vm show --resource-group <RG> --name <VM>
az vm run-command invoke --resource-group <RG> --name <VM> --command-id RunShellScript --scripts 'id; whoami'
az storage account list --output table
az storage blob list --container-name <CONTAINER> --account-name <ACCT>
az keyvault list
az keyvault secret list --vault-name <KV>
az keyvault secret show --vault-name <KV> --name <SECRET>

# Networking
az network nsg list
az network nsg show --resource-group <RG> --name <NSG>
az network vnet list
az network vnet subnet list --resource-group <RG> --vnet-name <VNET>
```

---

## GCP CLI Security Commands

```bash
gcloud auth login
gcloud config set project <PROJECT>

# IAM
gcloud iam service-accounts list
gcloud iam service-accounts get-iam-policy <SA@PROJECT.iam.gserviceaccount.com>
gcloud iam roles list --filter='name:projects/<PROJECT>'
gcloud projects get-iam-policy <PROJECT>
gcloud iam policies analyze-iam-policy --resource=<RESOURCE>

# Compute
gcloud compute instances list
gcloud compute instances describe <INSTANCE>
gcloud compute firewall-rules list
gcloud compute networks list
gcloud compute subnets list

# Storage
gcloud storage buckets list
gcloud storage ls gs://<BUCKET>
gcloud storage cat gs://<BUCKET>/<OBJECT>
gsutil iam get gs://<BUCKET>

# Secrets
gcloud secrets list
gcloud secrets describe <SECRET>
gcloud secrets versions access latest --secret=<SECRET>
```

---

## kubectl Security Commands

### Reconnaissance
```bash
kubectl auth can-i --list                          # Check all permissions for current user
kubectl auth can-i --list --as=system:anonymous    # Check anonymous access
kubectl auth can-i create pods                     # Check specific permission
kubectl auth can-i escalate --as=system:anonymous  # Check RBAC escalation
kubectl auth can-i '*' '*'                         # Check wildcard (admin)
kubectl get pods --all-namespaces
kubectl get pods -n <NS> -o wide
kubectl get pods <POD> -o yaml                     # Check for privileged, hostPID, hostNetwork
kubectl get secrets --all-namespaces
kubectl get configmaps --all-namespaces
kubectl get serviceaccounts --all-namespaces
kubectl get roles --all-namespaces -o wide
kubectl get clusterroles -o wide
kubectl get networkpolicies --all-namespaces
kubectl get podsecuritypolicies                    # Deprecated in 1.21+
kubectl get validatingwebhookconfigurations
kubectl get mutatingwebhookconfigurations
kubectl get serviceaccounts <SA> -n <NS> -o jsonpath='{.secrets[*].name}'
```

### Execution & Extraction
```bash
kubectl exec -it <POD> -- /bin/sh
kubectl exec <POD> -- cat /etc/shadow                # If privileged
kubectl exec <POD> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
kubectl exec <POD> -- env                            # Check env vars for secrets
kubectl exec <POD> -- mount | grep -i secret
kubectl cp <NAMESPACE>/<POD>:<PATH> ./localfile
kubectl get secret <SECRET> -n <NS> -o jsonpath='{.data}'
kubectl get secret <SECRET> -n <NS> -o json | jq -r '.data | to_entries[] | .key + ": " + (.value | @base64d)'
kubectl auth can-i create pods -n <NS> --as=<SA>    # Test SA permissions
kubectl run attacker --image=alpine --rm -it --restart=Never -- sh
```

### RBAC Enumeration
```bash
kubectl describe role <ROLE> -n <NS>
kubectl describe clusterrole <CR>
kubectl get rolebindings --all-namespaces
kubectl get clusterrolebindings
kubectl get rolebinding <RB> -n <NS> -o yaml
kubectl get clusterrolebinding <CRB> -o yaml
kubectl auth can-i delete pods --as=system:anonymous
kubectl auth can-i create pods --as=system:serviceaccount:<NS>:<SA>
kubectl auth can-i use podsecuritypolicy --as=system:anonymous
```

---

## Docker Security Commands

### Inspection
```bash
docker inspect <CONTAINER> --format '{{.HostConfig.Privileged}}'
docker inspect <CONTAINER> --format '{{.HostConfig.CapAdd}}'
docker inspect <CONTAINER> --format '{{.HostConfig.SecurityOpt}}'
docker inspect <CONTAINER> --format '{{.HostConfig.PidMode}}'
docker inspect <CONTAINER> --format '{{.HostConfig.NetworkMode}}'
docker inspect <CONTAINER> --format '{{.HostConfig.Binds}}'
docker inspect <CONTAINER> --format '{{json .Config.Env}}'
docker inspect <CONTAINER> --format '{{.HostConfig.Runtime}}'
docker inspect <CONTAINER> --format '{{json .Mounts}}'
```

### Hardening
```bash
docker run --read-only --tmpfs /tmp --tmpfs /run alpine sh
docker run --cap-drop ALL --cap-add NET_BIND_SERVICE alpine sh
docker run --security-opt no-new-privileges --security-opt seccomp=seccomp-profile.json alpine sh
docker run --security-opt apparmor=docker-default alpine sh
docker run --pids-limit 50 --memory 256m --cpus 1 alpine sh
docker run --user 1000:1000 alpine sh
docker run --network none alpine sh
```

### Scanning
```bash
docker scout cves <IMAGE>
docker scout sbom <IMAGE>
trivy image <IMAGE>
grype <IMAGE>
syft <IMAGE>                          # SBOM generation
dockle <IMAGE>                        # CIS benchmark checks
docker bench security                 # CIS Docker Benchmark (run container)
```

---

## Terraform Security Scanning

```bash
# tfsec (static analysis)
tfsec .

# Checkov (policy scanner)
checkov -d . --framework terraform
checkov -d . --check CKV_AWS_*,CKV_GCP_*

# terrascan (OPA policies)
terrascan scan -t aws -d .

# tfsec with SARIF output
tfsec . --format sarif > findings.sarif

# terraform plan scanning
terraform plan -out=tfplan && terraform show -json tfplan | tfsec -

# Infracost (cost + security)
infracost breakdown --path .

# tflint (linting)
tflint --init && tflint

# Custom OPA/Rego policies
opa eval --data policy/ --input tfplan.json "data.terraform.deny"

# drift detection
terraform plan -detailed-exitcode && echo "Drift detected"
```

---

## Cloud Metadata SSRF Payloads

### AWS IMDSv1 (Instance Metadata Service v1)
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE-NAME>
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document
```

### AWS IMDSv2 (requires token header)
```
# Step 1: Get token
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
# Step 2: Use token
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### Azure Instance Metadata
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```
*Note: Requires `Metadata: true` header*

### GCP Instance Metadata
```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys
http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env
```
*Note: Requires `Metadata-Flavor: Google` header*

### Alternative SSRF Bypass Patterns
```
http://0xa9fea9fe/              # Hex IP for 169.254.169.254
http://0x7f000001/              # Hex IP for 127.0.0.1
http://2852039166/               # Decimal IP for 169.254.169.254
http://169.254.169.254.nip.io/  # DNS rebinding
http://[::ffff:a9fea9fe]/       # IPv6-mapped IPv4
http://metadata.google.internal/ # GCP alternative name
```

---

## IAM Privilege Escalation Paths

### AWS (Top Paths)

| Path | Starting Permission | Escalation Method |
|------|---------------------|-------------------|
| `iam:CreateAccessKey` | Create keys for any user | Create access key for admin user |
| `iam:CreateLoginProfile` | Create console login | Set password for existing user |
| `iam:UpdateLoginProfile` | Change passwords | Reset admin password |
| `iam:AttachUserPolicy` | Attach managed policy | Attach `AdministratorAccess` to self |
| `iam:PutUserPolicy` | Create inline policy | Create inline admin policy on self |
| `iam:AttachRolePolicy` | Attach role policy | Attach admin policy to assumable role |
| `iam:PassRole` + `lambda:CreateFunction` | Pass role + create Lambda | Create Lambda with admin role, invoke it |
| `iam:PassRole` + `ec2:RunInstances` | Pass role + launch EC2 | Launch EC2 with admin role, SSH in |
| `iam:PassRole` + `cloudformation:CreateStack` | Pass role + CFN | Create stack with admin role |
| `sts:AssumeRole` | Assume role chain | Assume role with higher privileges |
| `lambda:UpdateFunctionCode` | Modify Lambda code | Modify existing Lambda with powerful role |
| `ec2:ModifyInstanceAttribute` | Change instance attributes | Assign new IAM role to running EC2 |
| `ssm:StartSession` | Start SSM session | Session to privileged instance |
| `secretsmanager:GetSecretValue` | Read secrets | Extract credentials from secrets |
| `ssm:GetParameters` | Read SSM params | Extract credentials from parameter store |
| `cloudformation:UpdateStack` | Update stack | Modify stack to exfil resources |
| `glue:CreateDevEndpoint` | Create Glue endpoint | Create endpoint with admin role |
| `codebuild:StartBuild` | Start code build | Run build with privileged role |

### Azure (Top Paths)

| Path | Starting Permission | Escalation Method |
|------|---------------------|-------------------|
| `Microsoft.Authorization/roleAssignments/write` | Assign roles | Assign Owner/Contributor to self |
| `Microsoft.Authorization/elevateAccess` | PIM elevate | Elevate to User Access Administrator |
| `Microsoft.Compute/virtualMachines/runCommand/action` | Run VM command | Execute commands on any VM |
| `Microsoft.Compute/virtualMachines/write` | Update VM | Modify VM to add admin account |
| `Microsoft.Web/sites/config/list/action` | List app settings | Extract connection strings/credentials |
| `Microsoft.KeyVault/vaults/secrets/read` | Read Key Vault | Exfiltrate secrets |
| `Microsoft.Storage/storageAccounts/listKeys/action` | List storage keys | Access all storage data |
| `Microsoft.Automation/runbooks/run` | Run automation | Execute arbitrary scripts |
| `Microsoft.Logic/workflows/run/action` | Run logic app | Trigger workflow with elevated access |
| App Registration + `Application.ReadWrite.All` | Register + write apps | Create app with admin consent |

### GCP (Top Paths)

| Path | Starting Permission | Escalation Method |
|------|---------------------|-------------------|
| `iam.serviceAccounts.actAs` | Act as SA | Use privileged SA for API calls |
| `iam.serviceAccountKeys.create` | Create SA keys | Create key for privileged SA |
| `compute.instances.create` with SA | Create instance | Launch VM with privileged SA attached |
| `cloudfunctions.functions.create` | Create function | Deploy function with privileged SA |
| `cloudfunctions.functions.update` | Update function | Inject code into function with admin SA |
| `run.services.create` | Create Cloud Run | Deploy service with admin SA |
| `container.clusters.create` | Create GKE cluster | Create cluster with admin SA |
| `storage.objects.get` on bucket with SA key | Read SA key | Download service account JSON key |
| `secretmanager.versions.access` | Access Secret Manager | Retrieve SA keys/credentials |
| `cloudbuild.builds.create` | Create build | Run build spec with elevated SA |

---

## Kubernetes Pod Escape Techniques

| Technique | Prerequisites | Method | Severity |
|-----------|--------------|--------|----------|
| **Privileged container + mount** | `privileged: true` | `nsenter --target 1 --mount --uts --ipc --net --pid` | Critical |
| **Host PID namespace** | `hostPID: true` | Access `/proc/1/root` for host filesystem | High |
| **Host network namespace** | `hostNetwork: true` | Sniff traffic, access localhost services | Medium |
| **Docker socket mount** | `/var/run/docker.sock` mounted | `docker run -v /:/host alpine` via API | Critical |
| **kubeconfig in container** | Kubeconfig file accessible | Use kubectl with cluster-admin credentials | Critical |
| **SA token mount** | Default SA with excessive RBAC | `cat /var/run/secrets/kubernetes.io/serviceaccount/token` | High |
| **Cloud metadata** | Network to 169.254.169.254 | Steal cloud IAM credentials via SSRF | Critical |
| **hostPath volume mount** | `hostPath: /` mounted | Full host filesystem read/write | Critical |
| **cgroup release_agent** | `privileged: true` or `SYS_ADMIN` | Mount cgroup, set release_agent to host binary | Critical |
| **Cap SYS_ADMIN + mount** | `SYS_ADMIN` capability | `mount /dev/sda1 /mnt` then chroot | Critical |
| **Cap SYS_PTRACE** | `SYS_PTRACE` + host PID | Inject shellcode into host process | High |
| **node/proxy permission** | `nodes/proxy` RBAC | `kubectl exec` via kubelet to any pod on any node | High |
| **etcd direct access** | Network + credentials to etcd | Read/write cluster state, inject secrets | Critical |
| **kubeadm config** | Access to `/etc/kubernetes/admin.conf` | Full cluster admin access | Critical |
| **Created pod with hostPath** | `pods/create` RBAC permission | Create privileged pod to escape | High |

---

## Container Escape Checklist

```
[ ] Check if container is privileged (cat /proc/1/status | grep Cap)
[ ] Check capabilities (capsh --print or cat /proc/1/status | grep Cap)
[ ] Check for Docker socket (/var/run/docker.sock)
[ ] Check for kubeconfig files (/etc/kubernetes/, ~/.kube/config)
[ ] Check mounted volumes (mount, cat /proc/mounts)
[ ] Check for host PID namespace (ls /proc | wc -l > 100?)
[ ] Check for host network namespace (ip link, check for host interfaces)
[ ] Check for cloud metadata access (curl -m 1 169.254.169.254)
[ ] Check for seccomp profile (cat /proc/1/status | grep Seccomp)
[ ] Check for AppArmor/SELinux (cat /proc/1/attr/current)
[ ] Check kernel version for known exploits (uname -r)
[ ] Check for sensitive environment variables (env | grep -i 'pass\|key\|secret\|token')
[ ] Check for service account tokens (ls /var/run/secrets/)
[ ] Check for writable paths on host mounts (find / -writable -type f 2>/dev/null)
[ ] Check for nested containers (docker ps, crictl ps)
[ ] Check for kubelet access (curl -sk https://<NODE_IP>:10250/pods)
[ ] Check for etcd access (curl -sk https://<NODE_IP>:2379)
[ ] Check for cloud CLI tools (aws, az, gcloud)
[ ] Check for network pivot potential (ip route, iptables -L)
[ ] Check for sensitive files (/etc/shadow, ~/.ssh/, /root/.aws/)
```

---

## Cloud Security Misconfiguration Checklist

### IAM
```
[ ] No root/admin access keys
[ ] MFA enforced on all users
[ ] No policies with Action: * Resource: *
[ ] IAM roles use least privilege
[ ] Service accounts use Workload Identity (GCP) / IRSA (AWS) / Managed Identity (Azure)
[ ] Unused credentials rotated within 90 days
[ ] No cross-account trust with Principal: *
[ ] No inline policies (managed policies only)
[ ] Password policy enforcement (complexity, rotation)
[ ] Access keys rotated periodically
```

### Networking
```
[ ] Security groups / NSGs follow least privilege (no 0.0.0.0/0 on sensitive ports)
[ ] VPC flow logs enabled
[ ] No publicly accessible storage (S3, Blob, GS)
[ ] Network segmentation between tiers
[ ] No security groups allowing all outbound to 0.0.0.0/0
[ ] Private endpoints / VPC endpoints for data services
[ ] DDoS protection configured (AWS Shield, Azure DDoS)
[ ] DNS logging enabled
[ ] WAF deployed on internet-facing services
```

### Compute & Containers
```
[ ] No privileged containers in production
[ ] Container images scanned before deployment
[ ] Images use specific tags (not :latest)
[ ] Read-only root filesystem where possible
[ ] Resource limits set (CPU, memory, PID)
[ ] Seccomp/AppArmor profiles applied
[ ] No container running as root
[ ] Docker Content Trust / image signing enabled
[ ] Kubernetes network policies enforced
[ ] Kubernetes Pod Security Standards enforced (baseline minimum)
```

### Storage & Data
```
[ ] Encryption at rest enabled
[ ] Encryption in transit enforced (TLS 1.2+)
[ ] Versioning enabled on all buckets
[ ] Block public access enabled (S3)
[ ] Key rotation enabled for CMKs
[ ] Secrets not in environment variables
[ ] Secrets rotated regularly
[ ] Audit logging enabled (CloudTrail, Azure Activity Log, GCP Audit Logs)
[ ] Log integrity validation configured
[ ] Backup and recovery tested
```

### Kubernetes
```
[ ] RBAC follows least privilege (no cluster-admin for services)
[ ] Pod Security Standards (PSS) enforced via admission controller
[ ] Network policies for all namespaces
[ ] etcd encrypted at rest
[ ] KMS encryption for Kubernetes Secrets
[ ] Kubelet anonymous auth disabled
[ ] API server audit logging enabled
[ ] Secret Store CSI driver for external secrets
[ ] Image admission webhook (Sigverification)
[ ] Resource quotas and limit ranges set
```

---

## Key CVE Quick-Reference Table

| CVE | Component | Type | Impact | CVSS |
|-----|-----------|------|--------|------|
| CVE-2019-5736 | runc | Container escape via /proc/self/exe overwrite | Host root from inside container | 9.8 |
| CVE-2020-15257 | containerd | Container escape via abstract namespace | Host root via shim API | 9.8 |
| CVE-2022-0185 | Linux kernel | Heap overflow in filesystem context | Container escape | 7.8 |
| CVE-2022-0492 | Linux kernel | Cgroup BPF bypass | Container escape / LPE | 7.0 |
| CVE-2021-25742 | Kubernetes | Ingress-NGINX path traversal | Arbitrary file read from ingress controller | 8.2 |
| CVE-2022-3162 | Kubernetes | kube-apiserver unauthorized | Cluster compromise | 8.2 |
| CVE-2022-3294 | Kubernetes | kubelet path traversal | Arbitrary file read on node | 8.0 |
| CVE-2023-2727 | Kubernetes | kube-apiserver validate check bypass | Privilege escalation | 8.2 |
| CVE-2021-41103 | Moby (Docker) | Default directory permissions | Local escalation | 7.8 |
| CVE-2022-24769 | Moby (Docker) | Default inheritable capabilities | Container escape via cap | 9.8 |
| CVE-2020-8554 | Kubernetes | Man-in-the-middle via CVE-2020-8554 | Network traffic interception | 5.6 |
| CVE-2020-8558 | Kubernetes | kubelet localhost endpoint exposure | Unauthenticated read | 8.2 |
| CVE-2020-8562 | Kubernetes | kube-apiserver aggregated API disclosure | Data exposure | 6.5 |
| CVE-2024-1086 | Linux kernel | nf_tables double-free | Container escape / LPE (99.4% success) | 7.8 |
| CVE-2024-21626 | runc | Container escape via leaked FD | Host root access | 8.8 |
| CVE-2021-44716 | Go stdlib | HTTP/2 denial of service | Pod crash / DoS | 7.5 |
| CVE-2023-44487 | HTTP/2 | Rapid Reset attack | DDoS (affects cloud LBs) | 7.5 |
| CVE-2021-45046 | Log4j | Log4Shell RCE (bypass) | Remote code execution | 10.0 |
| CVE-2021-44228 | Log4j | Log4Shell RCE | Remote code execution | 10.0 |
| CVE-2023-46604 | Apache ActiveMQ | Deserialization RCE | Remote code execution | 10.0 |
| CVE-2023-4911 | glibc | buffer overflow in ld.so | Local privilege escalation | 7.8 |

---

## Falco Rule Examples

### Detect Privileged Container
```yaml
- rule: Launch Privileged Container
  desc: Detect container started with privileged flag
  condition: >
    container and
    evt.type = container_create and
    container.image.repository != "" and
    container.privileged = true and
    not container.image.repository in (falco_privileged_images)
  output: >
    Privileged container started
    (user=%user.name command=%proc.cmdline container=%container.name
     image=%container.image.repository:%container.image.tag)
  priority: CRITICAL
  tags: [container, privileged]
```

### Detect Container Escape via /proc
```yaml
- rule: Container Escape via /proc
  desc: Detect /proc/self/exe overwrite attempt (CVE-2019-5736 pattern)
  condition: >
    open_write and
    fd.type = file and
    fd.name = /proc/self/exe and
    container.id != host
  output: >
    Possible container escape via /proc/self/exe
    (user=%user.name command=%proc.cmdline container=%container.id)
  priority: EMERGENCY
  tags: [container, escape, cve-2019-5736]
```

### Detect cgroup Release Agent
```yaml
- rule: Container Escape via cgroup
  desc: Detect cgroup release_agent modification for container escape
  condition: >
    open_write and
    fd.type = file and
    fd.name startswith /sys/fs/cgroup/ and
    fd.name contains release_agent and
    container.id != host
  output: >
    Possible container escape via cgroup release_agent
    (user=%user.name command=%proc.cmdline container=%container.id)
  priority: CRITICAL
  tags: [container, escape, cgroup]
```

### Detect Cloud Metadata Access
```yaml
- rule: Contact Cloud Instance Metadata
  desc: Detect attempts to contact cloud metadata service
  condition: >
    (fd.sip = "169.254.169.254" or fd.sip = "fd00:ec2::254") and
    fd.sport != 0 and
    container.id != host and
    not proc.name in (awscli, azurecli, gcloud)
  output: >
    Container contacting cloud instance metadata
    (user=%user.name container=%container.id image=%container.image.repository
     connection=%fd.name)
  priority: WARNING
  tags: [cloud, ssrf, credential_theft]
```

### Detect K8s API Server Access from Unexpected Source
```yaml
- rule: Unexpected K8s API Server Access
  desc: Detect process in container contacting K8s API from unexpected binary
  condition: >
    (fd.sport = 6443 or fd.dport = 6443) and
    container and
    not proc.name in (kube-proxy, kubelet, kubectl, kube-controller)
  output: >
    Unexpected process contacting K8s API server
    (user=%user.name command=%proc.cmdline container=%container.name)
  priority: WARNING
  tags: [kubernetes, api_server]
```

### Detect Sensitive Mount in Container
```yaml
- rule: Sensitive Mount in Container
  desc: Detect container with sensitive host path mounted
  condition: >
    container and
    evt.type = container_create and
    (container.mounts[*] contains "/var/run/docker.sock" or
     container.mounts[*] contains "/etc/kubernetes" or
     container.mounts[*] contains "/root/.aws" or
     container.mounts[*] contains "/proc" or
     container.mounts[*] contains "/sys")
  output: >
    Container with sensitive host mount created
    (user=%user.name container=%container.name mounts=%container.mounts)
  priority: CRITICAL
  tags: [container, sensitive_mount]
```

### Detect Privilege Escalation via kubectl
```yaml
- rule: K8s Privilege Escalation
  desc: Detect creation of privileged pods or pods with host access
  condition: >
    ka.target.resource = pods and
    ka.verb = create and
    (ka.req.pod.spec.privileged = true or
     ka.req.pod.spec.hostPID = true or
     ka.req.pod.spec.hostNetwork = true or
     ka.req.pod.spec.hostIPC = true or
     ka.req.pod.spec.containers[*].securityContext.privileged = true)
  output: >
    Privileged pod created
    (user=%ka.auth.username pod=%ka.req.pod.name ns=%ka.target.namespace)
  priority: CRITICAL
  tags: [kubernetes, privilege_escalation]
```

---

## AWS IAM Policy Evaluation Logic (Quick Reference)

```
┌─────────────────────────────────┐
│  Explicit Deny in any policy?   │
│  (IAM, SCP, Permissions Boundary)│
└──────────────┬──────────────────┘
               │
         Yes ──┤──► DENY (final, override all)
               │ No
               ▼
┌─────────────────────────────────┐
│  Allow in any policy?           │
│  (Identity-based + Resource-based)│
└──────────────┬──────────────────┘
               │
         Yes ──┤──► Evaluate SCP (AWS Organizations)
               │      │
               │  SCP  ┤──► Allow SCP? ──► No ──► DENY
               │      │                    │
               │      │                   Yes
               │      │                    ▼
               │  Evaluate Permissions Boundary
               │      │
               │      ├──► Deny in boundary? ──► DENY
               │      │
               │      └──► Allow in boundary? ──► ALLOW
               │
         No ──┘──► IMPLICIT DENY
```

---

## Kubernetes RBAC → Privilege Escalation Quick Map

```
 ┌──────────────────────┐
 │  pods/exec           │────► Shell in any pod → cloud metadata / SA tokens
 └──────────────────────┘
 ┌──────────────────────┐
 │  pods/create         │────► Create privileged pod → host escape
 └──────────────────────┘
 ┌──────────────────────┐
 │  secrets/get,list    │────► Extract all secrets → credentials
 └──────────────────────┘
 ┌──────────────────────┐
 │  nodes/proxy         │────► Kubelet API access → exec on any pod
 └──────────────────────┘
 ┌──────────────────────┐
 │  podsecuritypolicies │────► Create privileged pods
 │  /use (create)       │
 └──────────────────────┘
 ┌──────────────────────┐
 │  escalate verb       │────► Grant permissions beyond current scope
 └──────────────────────┘
 ┌──────────────────────┘
 │  serviceaccounts/    │────► Create SA → bind to cluster-admin
 │  create + tokens/    │
 │  create              │
 └──────────────────────┘
 ┌──────────────────────┐
 │  configmaps/create   │────► Store malicious data → app reads it
 └──────────────────────┘
┌──────────────────────┐
  │  certificatesigning │────► Create CSR → approve → TLS boot to node
  │  requests/*         │
  └──────────────────────┘
```

---

## References

1. AWS. "AWS CLI Command Reference." *Amazon Web Services*. 2024. https://docs.aws.amazon.com/cli/latest/reference/
2. AWS. "IAM Policy Evaluation Logic." *Amazon Web Services*. 2024. https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
3. Microsoft. "Azure CLI Reference." *Microsoft Learn*. 2024. https://learn.microsoft.com/en-us/cli/azure/
4. Google Cloud. "gcloud CLI Reference." *Google Cloud*. 2024. https://cloud.google.com/sdk/gcloud/reference
5. Kubernetes. "kubectl Reference." *Kubernetes*. 2024. https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands
6. Kubernetes. "RBAC API Reference." *Kubernetes*. 2024. https://kubernetes.io/docs/reference/access-authn-authz/rbac/
7. Falco. "Falco CLI Reference." *The Falco Project*. 2024. https://falco.org/docs/getting-started/falco-cli/
8. Open Policy Agent. "OPA CLI Reference." *Open Policy Agent*. 2024. https://www.openpolicyagent.org/docs/latest/cli/
9. HashiCorp. "Terraform CLI Reference." *HashiCorp Developer*. 2024. https://developer.hashicorp.com/terraform/cli
10. CIS. "CIS Benchmarks: AWS, Azure, GCP, Kubernetes." *Center for Internet Security*. 2024. https://www.cisecurity.org/cis-benchmarks/
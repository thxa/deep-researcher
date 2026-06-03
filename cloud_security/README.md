# Cloud & Container Security

## Deep Research Track

A comprehensive, technically deep exploration of cloud and container security — from IaaS/PaaS/SaaS trust boundaries and multi-tenant hypervisor attacks to Kubernetes exploitation, serverless attack surfaces, and the future of cloud-native security.

### Track Structure

| Document | Topic | Key Focus |
|---|---|---|
| [01a](docs/01a_cloud_architecture_security.md) | Cloud Architecture Security | IaaS/PaaS/SaaS models, shared responsibility, multi-tenant isolation, hypervisor CVEs (VENOM, CVE-2017-17558, CVE-2019-5736), metadata service attacks, IMDSv1 vs IMDSv2, AWS/Azure/GCP trust boundaries |
| [01b](docs/01b_identity_access_management.md) | Identity & Access Management | AWS IAM policies/roles/STS, Azure AD/Entra conditional access, GCP IAM/workload identity, privilege escalation paths, OIDC federation attacks, SAML vulnerabilities (Golden SAML), IAM enumeration |
| [02a](docs/02a_container_security.md) | Container Security | Linux namespaces/cgroups/seccomp/AppArmor, Docker security, container runtimes, rootless containers, image security, CVE-2019-5736 (runc), CVE-2022-0492 (cgroups), CVE-2022-0847 (DirtyPipe) |
| [02b](docs/02b_kubernetes_security.md) | Kubernetes Security | Pod security standards, network policies, RBAC, service account risks, kubelet/API server/etcd security, pod-to-node escapes, CVE-2018-1002105, CVE-2022-3172, kubectl auth can-i enumeration |
| [03a](docs/03a_serverless_security.md) | Serverless Security | Lambda/Functions attack surface, event injection, persistence patterns, cold start timing attacks, dependency confusion, IAM overprivilege, VPC configuration, API Gateway attacks |
| [03b](docs/03b_infrastructure_as_code_security.md) | IaC Security | Terraform/CloudFormation/Pulumi security, state file secrets, drift detection, supply chain in providers, OIDC trust errors, policy-as-code (OPA/Sentinel/Checkov), terraform plan security review |
| [04a](docs/04a_cloud_exploitation_techniques.md) | Cloud Exploitation | SSRF-to-metadata, IMDSv1 role assumption, 175+ IAM escalation paths, cross-account trust exploitation, S3 enumeration/exfiltration, Azure AD consent attacks, GCP SA key exposure, cloud persistence mechanisms |
| [04b](docs/04b_kubernetes_exploitation.md) | Kubernetes Exploitation | Pod breakout (privileged/hostPath/docker.sock), RBAC escalation, etcd access, kubelet API exploitation, API server SSRF, admission controller bypass, image supply chain, sidecar injection, real-world case studies |
| [05a](docs/05a_cloud_detection_monitoring.md) | Detection & Monitoring | CloudTrail/GuardDuty/Sentinel/Cloud Audit Logs, detection engineering for cloud attacks, SIEM integration, MITRE ATT&CK cloud mapping, Falco, eBPF monitoring (Tetragon) |
| [05b](docs/05b_cloud_hardening_best.md) | Hardening Best Practices | CIS Benchmarks (AWS/Azure/GCP/K8s), Pod Security Standards, network segmentation, encryption at rest/transit, KMS/Vault key management, SLSA framework, CSPM, compliance (SOC 2, FedRAMP, ISO 27001) |
| [06](docs/06_cloud_case_studies_future.md) | Case Studies & Future | Capital One (SSRF→IAM), SolarWinds (Golden SAML), TeamTNT (cryptojacking), Azure AD cross-tenant. Future: eBPF-native security, confidential computing (SEV/TDX), zero-trust, AI-powered security, Wasm sandboxes, service mesh, platform engineering |

### Cross-Track References

- **Linux Kernel** (`../linux_kernel/docs/`): Namespace/cgroup primitives, kernel CVEs (DirtyPipe, Dirty COW), slab allocator exploitation
- **Zero Day** (`../zero_day/docs/`): Exploit development methodology for hypervisor and container runtime vulnerabilities
- **OSEE** (`../OSEE/docs/`): Offensive security engineering for cloud environments
- **Web Security** (`../web_security/docs/`): SSRF exploitation techniques foundational to cloud metadata attacks
- **Supply Chain** (`../supply_chain_security/docs/`): Container image supply chain, Terraform provider security, dependency confusion

### Reading Order

Recommended reading order for different backgrounds:

**Cloud Security Engineers**: 01a → 01b → 02a → 02b → 05b → 05a → 06
**Penetration Testers**: 04a → 04b → 01b → 02a → 02b → 03a → 06
**DevSecOps Engineers**: 03b → 05b → 02a → 02b → 07 → 05a → 06
**Security Architects**: 01a → 01b → 02a → 02b → 05b → 06 → 03a → 03b

---

## References

1. AWS. "Shared Responsibility Model." *Amazon Web Services*. 2024. https://aws.amazon.com/compliance/shared-responsibility-model/
2. NIST. "SP 800-190: Application Container Security Guide." *National Institute of Standards and Technology*. 2024. https://csrc.nist.gov/publications/detail/sp/800-190/final
3. MITRE. "ATT&CK Cloud Matrix." *MITRE Corporation*. 2024. https://attack.mitre.org/matrices/enterprise/cloud/
4. CIS. "CIS Benchmarks: AWS, Azure, GCP, Kubernetes." *Center for Internet Security*. 2024. https://www.cisecurity.org/cis-benchmarks/
5. NIST. "SP 800-204: Security Strategies for Microservices-based Application Systems." *National Institute of Standards and Technology*. 2021. https://csrc.nist.gov/publications/detail/sp/800-204/final
6. NSA/CISA. "Kubernetes Hardening Guide." *National Security Agency*. 2022. https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF
7. OWASP. "Cloud Security Resources." *Open Worldwide Application Security Project*. 2024. https://owasp.org/www-project-top-ten/
8. Aqua Security. "Container Threat Report." *Aqua Security*. 2023. https://info.aquasec.com/cloud-native-threat-report

---

## Recent Developments (2025–2026)

*Independently verified against primary sources (NVD / vendor advisories / papers) during the 2026-06 accuracy audit. Each CVE was confirmed to exist with the stated characterization.*

### Vulnerabilities (CVEs)

- **IngressNightmare: Unauthenticated RCE in Kubernetes ingress-nginx (CVE-2025-1974)** *(2025-03)* — In March 2025 the Wiz Research team disclosed five vulnerabilities in the Kubernetes ingress-nginx controller (CVE-2025-1974, CVE-2025-1097, CVE-2025-1098, CVE-2025-24513, CVE-2025-24514), collectively 'IngressNightmare'. CVE-2025-1974 (CVSS 9.8) lets any workload on the pod network inject NGINX config via the Validating Admission Controller for unauthenticated RCE and cluster-wide secret theft, affecting roughly 43% of cloud environments. Fixed in ingress-nginx v1.12.1 and v1.11.5. [[source]](https://kubernetes.io/blog/2025/03/24/ingress-nginx-cve-2025-1974/)
- **runc Container Escape Trio (CVE-2025-31133, CVE-2025-52565, CVE-2025-52881)** *(2025-11)* — On November 5, 2025 the OCI runc maintainers disclosed three vulnerabilities allowing full container breakout in Docker and Kubernetes, all abusing race conditions to redirect bind-mounts onto sensitive procfs files. CVE-2025-31133 replaces /dev/null with a symlink to mask-mount attacker paths; CVE-2025-52565 abuses /dev/console mounts; CVE-2025-52881 redirects writes to files like /proc/sys/kernel/core_pattern. Patched in runc 1.2.8, 1.3.3, and 1.4.0-rc.3. [[source]](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- **Cisco ISE Cloud Static Credential Vulnerability (CVE-2025-20286)** *(2025-06)* — Published June 4, 2025, this CVSS 9.9 flaw means cloud deployments of Cisco Identity Services Engine generate identical static credentials per release and platform, so all instances of a given version share the same secrets. An unauthenticated remote attacker who extracts credentials from one cloud ISE deployment can reuse them to access others on AWS (ISE 3.1-3.4), Azure, and OCI (3.2-3.4) when the Primary Administration Node is cloud-hosted. [[source]](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-aws-static-cred-FPMjUcm7)
- **Kubernetes NodeRestriction Privilege Escalation (CVE-2025-5187)** *(2025)* — A 2025 Kubernetes vulnerability in the NodeRestriction admission controller lets a user with node-level (kubelet) credentials delete their corresponding node object by patching themselves with an OwnerReference to a non-existent cluster-scoped resource, triggering garbage-collection deletion. This bypasses the intended authorization model that NodeRestriction is supposed to enforce, enabling cluster disruption from a compromised node. [[source]](https://www.cve.org/CVERecord?id=CVE-2025-5187)

### Incidents & In-the-Wild Exploitation

- **Shai-Hulud: Self-Replicating npm Worm Harvesting Cloud Credentials** *(2025-09)* — Beginning in September 2025, the Shai-Hulud worm became the first self-propagating npm supply-chain malware, spreading by stealing a compromised maintainer's npm token, injecting malicious post-install code into their other packages, and republishing them. It harvested AWS, GCP, and Azure credentials plus GitHub PATs, prompting a CISA alert; a more aggressive 'Shai-Hulud 2.0' wave in November 2025 exposed hundreds of AWS, GCP, and Azure credentials across thousands of repos. [[source]](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)
- **S1ngularity / Nx Supply Chain Breach Escalated to AWS Admin by UNC6426** *(2025-08)* — On August 26, 2025 attackers exploited a vulnerable GitHub Actions workflow in the Nx repository to steal an npm publishing token and publish malicious Nx package versions whose post-install script scanned developer machines for secrets, SSH keys, and cloud credentials, exposing over 2,000 distinct secrets. Mandiant later reported that threat actor UNC6426 used GitHub tokens stolen in this breach to obtain AWS administrator access in under 72 hours, illustrating CI/CD-to-cloud escalation chains. [[source]](https://thehackernews.com/2026/03/unc6426-exploits-nx-npm-supply-chain.html)

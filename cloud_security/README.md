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
6. NSA/CISA. "Kubernetes Hardening Guide." *National Security Agency*. 2022. https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/1/CTR_KUBERNETES_HARDENING_GUIDANCE.PDF
7. OWASP. "Cloud Security Resources." *Open Worldwide Application Security Project*. 2024. https://owasp.org/www-project-top-ten/
8. Aqua Security. "Container Threat Report." *Aqua Security*. 2023. https://www.aquasec.com/resources/container-threat-report/
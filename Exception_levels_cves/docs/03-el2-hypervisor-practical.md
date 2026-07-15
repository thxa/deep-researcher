# EL2 Hypervisor Vulnerabilities on ARM64: Practical Real-World Impact

**Researcher B perspective** — focuses on what is actually deployed, what has been publicly exploited, and what the incidents mean for defenders.

---

## 1. Summary

EL2 hypervisors on ARM64 are now a mainstream isolation layer: they sit underneath cloud VM fleets (AWS Graviton on the Nitro System, Azure Cobalt VMs, Google Axion VMs), they protect modern Android kernels through Samsung RKP, and they form the trusted computing base of Google's pKVM/Android Virtualization Framework. This report documents publicly known bugs, real-world compromise examples, and the gap between mobile hypervisor exploitation (where CVEs and Pwn2Own demonstrations are common) and cloud ARM64 hypervisors (where public VM-escape incidents have not been documented, but the underlying KVM/ARM64 CVE class is the same one that powers those platforms).

---

## 2. ARM64 Cloud Hypervisors: AWS, Azure, and Google Cloud

All three major hyperscalers now ship custom ARM64 server silicon and rely on a hypervisor for multi-tenant isolation.

| Provider | ARM64 offering | Public description of isolation layer |
|----------|----------------|----------------------------------------|
| **AWS** | AWS Graviton (Graviton2/3/4/5) instances | The **AWS Nitro System**, including the **Nitro Hypervisor**, is the underlying platform for all modern EC2 instances. AWS describes it as a deliberately minimized, firmware-like hypervisor designed for strong resource isolation and bare-metal performance. The whitepaper also notes that Nitro mitigates side-channel risks and eliminates operator/administrator access to the host. |
| **Microsoft Azure** | Azure Cobalt 100/200 VMs | Azure Cobalt 200 is described as an Arm-based VM family built on Microsoft's custom Cobalt 200 SoC. Microsoft's public isolation documentation states that Azure runs customer VMs on shared physical infrastructure, isolated by the hypervisor and by tenant-level identity boundaries. |
| **Google Cloud** | Axion-based N4A VMs | Google Cloud Compute Engine lists Axion-based N4A VMs as generally available. Google Cloud also offers **Confidential VMs** and other isolation technologies, but it does not publish the exact hypervisor name for Axion in the same way AWS publishes Nitro. |

### Key practical points

- **AWS Graviton** instances are explicitly built on the Nitro System, which is AWS's production hypervisor stack. The Nitro whitepaper emphasizes that the Nitro Hypervisor is minimized, that administrative access is removed by design, and that side-channel mitigations are part of the security model.
- **Azure Cobalt** is a first-party ARM64 VM family. Azure's isolation documentation acknowledges that multitenancy introduces the risk of sharing physical servers with potentially malicious tenants and states that the hypervisor is the primary isolation mechanism.
- **Google Axion** is a commercial ARM64 offering, but Google Cloud's public documentation does not detail the hypervisor implementation for N4A VMs. The risk assessment is therefore based on the general Compute Engine isolation model and the common ARM64/KVM bug class rather than a vendor-disclosed hypervisor CVE.
- **No public, confirmed multi-tenant VM escape on an ARM64 cloud hypervisor has been documented.** However, the same Linux kernel KVM/ARM64 CVEs that affect on-premise KVM on ARM64 are conceptually relevant to any cloud provider whose stack is built on or near KVM/ARM64 virtualization.

### Sources

- AWS Graviton product page: https://aws.amazon.com/ec2/graviton/
- AWS Nitro System security whitepaper: https://docs.aws.amazon.com/whitepapers/latest/security-design-of-aws-nitro-system/security-design-of-aws-nitro-system.html
- Azure Cobalt 200 announcement: https://azure.microsoft.com/en-us/blog/new-azure-cobalt-200-vms-deliver-50-performance-improvement-fully-optimized-for-modern-agentic-ai-workloads/
- Azure isolation documentation: https://learn.microsoft.com/en-us/azure/security/fundamentals/isolation-choices
- Google Cloud Compute Engine (Axion N4A VMs mentioned): https://cloud.google.com/compute

---

## 3. pKVM and Android 13+ Deployment

### What pKVM is

Google's **protected KVM (pKVM)** is the hypervisor for the **Android Virtualization Framework (AVF)**. According to AOSP documentation:

- AVF is supported **only on ARM64** devices.
- pKVM is a **KVM-based hypervisor at EL2** that isolates the host Android kernel and protected virtual machines (pVMs) into mutually distrusted environments.
- pKVM tracks the ownership of every physical page and removes donated pages from the host's Stage-2 mapping, so even a compromised host kernel cannot read pVM memory.
- AOSP describes the EL2 portion as roughly **10,000 lines of code**, compared with ~20 million lines in the Linux kernel, which is the formal-safety justification for using it as a confidentiality/integrity TCB.

### Deployment reality

pKVM ships on ARM64 GKI devices. It is the virtualization backend for:

- **Microdroid** (the pVM guest OS),
- **Confidential computing use cases** on Pixel and partner devices,
- **DRM, biometric, and key-management workloads** that need isolation from the host kernel.

While Google does not publish a device-by-device rollout list, AVF is a production feature of modern Android releases and is ARM64-only.

### A real pKVM vulnerability: CVE-2025-22413

In March 2025, Google published an Android Security Bulletin entry for **CVE-2025-22413**, a vulnerability in pKVM's `hyp-main.c`.

- **NVD description:** "In multiple functions of hyp-main.c, there is a possible privilege escalation due to a logic error in the code. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation."
- **Android bulletin:** listed under the Kernel section, subcomponent **KVM**, severity **High**, type **ID** (information disclosure).
- **Fix:** Two AOSP commits by Fuad Tabba (October 2024) with the title *"ANDROID: KVM: arm64: Don't run a protected VCPU if it isn't runnable"*. The patch adds a `is_vcpu_runnable()` check before running a protected VCPU and moves the pending-state reset so that a protected VCPU can only run in a runnable PSCI state.

#### Why this matters in practice

- The bug is in the EL2 hypervisor code itself, not the host kernel.
- A logic error in pKVM's VCPU scheduling could let a guest or host-controlled VCPU execute in an invalid state, which is exactly the type of primitive that can leak guest state or corrupt hypervisor context.
- It demonstrates that pKVM's smaller TCB does not make it bug-free; hypervisor logic errors still escape into production releases and are patched through the monthly Android security process.

### Other KVM/ARM64 and pKVM bugs in the same class

The NVD entries below show the recurring bug classes in the ARM64 hypervisor path:

- **CVE-2024-26598** (2024, CVSS 7.8): Use-after-free in the KVM/ARM64 GICv3 ITS LPI translation cache.
- **CVE-2024-26691** (2024): pKVM circular locking dependency in `pkvm_create_hyp_vm()` — a deadlock/DoS vector in the hypervisor creation path.
- **CVE-2021-47450** (2021): pKVM host Stage-2 PGD refcount bug in protected mode that can corrupt page tables.
- **CVE-2024-50114** (2024): Use-after-free when tearing down a redistributor on failed vCPU creation.

These are not all VM escapes, but they are the kinds of memory-safety and logic errors that exploitation research typically chains to escape a guest.

### Sources

- Android Virtualization Framework overview (AVF, pKVM): https://source.android.com/docs/core/virtualization
- pKVM security model: https://source.android.com/docs/core/virtualization/security
- Android Security Bulletin—March 2025 (CVE-2025-22413): https://source.android.com/docs/security/bulletin/2025-03-01
- NVD CVE-2025-22413: https://nvd.nist.gov/vuln/detail/CVE-2025-22413
- AOSP fix commit #1: https://android.googlesource.com/kernel/common/+/1a3366f0d3d9b94a8c025d9863edc3b427435c4c
- AOSP fix commit #2: https://android.googlesource.com/kernel/common/+/add3d68602a0c48ed2d5659f0cf26d869776ab35
- NVD CVE-2024-26598: https://nvd.nist.gov/vuln/detail/CVE-2024-26598
- NVD CVE-2024-26691: https://nvd.nist.gov/vuln/detail/CVE-2024-26691
- NVD CVE-2021-47450: https://nvd.nist.gov/vuln/detail/CVE-2021-47450
- NVD CVE-2024-50114: https://nvd.nist.gov/vuln/detail/CVE-2024-50114

---

## 4. VM Escape Research and Incidents on ARM64

### What "VM escape" means in this context

A VM escape is a compromise where code running inside a guest VM breaks out to the hypervisor (EL2) or to another guest/tenant. On ARM64, public examples are concentrated in the **mobile hypervisor** space (Samsung RKP) and in **Linux KVM/ARM64 research CVEs**, rather than in documented cloud incidents.

### Direct hypervisor control-flow bugs

- **CVE-2018-18021** (Linux kernel < 4.18.12, ARM64): `arch/arm64/kvm/guest.c` mishandled the `KVM_SET_ON_REG` ioctl. NVD states that an attacker who can create VMs can **arbitrarily redirect the hypervisor flow of control with full register control** and cause a hypervisor panic via an illegal exception return. CVSS 7.1 (High). This is a direct hypervisor control-flow attack from a guest VM.
- **CVE-2024-26598** (ARM64 KVM): UAF in the GICv3 ITS translation cache. While the published fix is in the kernel, the bug is in the virtual interrupt controller code that runs in the hypervisor context and can be reached from a guest VM. CVSS 7.8 (High).

### Cloud incident status

No public, vendor-acknowledged multi-tenant VM escape has been reported on AWS Graviton, Azure Cobalt, or Google Axion. The absence of public incidents is not the same as absence of risk: the CVEs above show that the ARM64 KVM codebase continues to produce guest-reachable hypervisor bugs, and those bugs are the raw material for future escape chains.

### Sources

- NVD CVE-2018-18021: https://nvd.nist.gov/vuln/detail/CVE-2018-18021
- NVD CVE-2024-26598: https://nvd.nist.gov/vuln/detail/CVE-2024-26598

---

## 5. Pwn2Own and Competitions Targeting ARM Hypervisors

### Pwn2Own does not currently run a dedicated ARM64 hypervisor category

Pwn2Own's public targets are dominated by browsers, enterprise applications, mobile phones, and (in some years) x86 hypervisors such as VMware, VirtualBox, Hyper-V, and Parallels. The Wikipedia summary of the contest notes that mobile phones were added in 2009, car targets in 2019, and industrial control systems in 2019, but it does not list a dedicated ARM64 hypervisor track.

### The closest real-world ARM hypervisor target: Samsung phones

Samsung Galaxy devices use Samsung Knox, which includes **RKP**, an EL2 hypervisor. These devices are repeatedly attacked at Pwn2Own:

- **Pwn2Own Toronto 2022**: The Samsung Galaxy S22, running the latest Android 13 with all updates, was successfully hacked four times during the contest. On day three, researchers from Pentest Limited exploited it in **55 seconds** via an improper input validation bug, earning $25,000. The STAR Labs team and a researcher known as Chim also demonstrated zero-day exploits against the Galaxy S22 on day one.

Because the S22's security stack includes RKP at EL2, successful full-system compromise at Pwn2Own implicitly demonstrates that the device's layered defenses — including the hypervisor-backed integrity protections — can be bypassed by a sufficiently valuable chain. The public write-ups do not usually claim "RKP bypass" as the headline, but the exploit outcome (arbitrary code execution on a fully patched flagship) is the practical proof that the hypervisor-backed security model is not invincible.

### Sources

- Pwn2Own Wikipedia (contest categories and history): https://en.wikipedia.org/wiki/Pwn2Own
- BleepingComputer, "Samsung Galaxy S22 hacked in 55 seconds on Pwn2Own Day 3" (9 Dec 2022): https://www.bleepingcomputer.com/news/security/samsung-galaxy-s22-hacked-in-55-seconds-on-pwn2own-day-3/

---

## 6. Multi-Tenant Isolation Failures

### What the cloud providers say

- **AWS Nitro System whitepaper**: describes the Nitro Hypervisor as a deliberately minimized hypervisor that provides strong resource isolation, eliminates administrative access, and includes mitigations against side-channel issues.
- **Azure isolation documentation**: acknowledges that multitenancy is the source of cloud cost savings but also introduces the risk that a customer's VM runs on the same physical server as a potentially malicious tenant. Azure states that the hypervisor is the primary isolation boundary between VMs.

### Documented failures

No public, vendor-acknowledged VM escape or multi-tenant isolation failure on an ARM64 cloud hypervisor was found in this research. The risks that have been publicly demonstrated are:

1. **Guest-reachable hypervisor bugs** in Linux KVM/ARM64 (e.g., CVE-2018-18021, CVE-2024-26598). These are the primitives that could be used to escape a guest, but they have not been publicly chained into a cloud VM escape.
2. **Side-channel leakage** across tenants. The Nitro whitepaper explicitly addresses this class, but no specific ARM64 cloud side-channel CVE or incident was identified in this review.

### Sources

- AWS Nitro System security whitepaper: https://docs.aws.amazon.com/whitepapers/latest/security-design-of-aws-nitro-system/security-design-of-aws-nitro-system.html
- Azure isolation documentation: https://learn.microsoft.com/en-us/azure/security/fundamentals/isolation-choices

---

## 7. Samsung RKP Vulnerabilities and Bypasses

### What RKP is

Samsung's **Real-time Kernel Protection (RKP)** is a security monitor that runs at **EL2 using ARM virtualization extensions**. According to Samsung's Knox documentation, RKP:

- Enforces read-only / execute-only permissions on kernel code and critical data via Stage-2 page tables.
- Prevents user-space processes from directly mapping kernel data regions.
- Monitors credential data structures (via KDP) to prevent privilege escalation.

RKP is therefore a hypervisor-level protection layer. The following CVEs show that it has been directly attacked and bypassed in the wild.

### Publicly documented RKP/CVEs

| CVE | Year | Device / SoC | Impact | Notes |
|-----|------|--------------|--------|-------|
| **CVE-2019-19273** | 2019 | Samsung Android 8/9, Exynos 8895 | **Arbitrary memory write** in RKP (CVSS 7.8) | CENSUS published an exploit (`samsung-hypervisor-rkp-arbitrary-zero-write`). |
| **CVE-2019-20553** | 2019 | Android 9, SM6150/SM8150/Exynos 7885/9610/9820 | **Arbitrary memory read and write** in RKP | Samsung SVE-2019-15143. |
| **CVE-2019-20556** | 2019 | Android 9, same chipsets | RKP memory corruption allows attacker to control the effective address in EL2 | Samsung SVE-2019-15221. |
| **CVE-2019-20601** | 2019 | Android 7/8/9, Exynos 7570/7580/7870/7880/8890 | RKP memory corruption causes **arbitrary write to protected memory** | Samsung SVE-2019-13921-2. |
| **CVE-2020-13829** | 2020 | Android 9/10 | Attackers can **disable the SEAndroid protection mechanism** via RKP | Samsung SVE-2019-15998 (CVSS 7.5). |
| **CVE-2020-25053** | 2020 | Android 10, Exynos 9830 | **RKP allows arbitrary code execution** | Samsung SVE-2020-17435 (CVSS 9.8). |
| **CVE-2021-25338** | 2021 | Android 10/11, Exynos 9830 | Improper memory access control allows a compromised kernel to write part of the **RKP EL2 memory region** | Samsung SVE-2021-XXXX; CVSS 5.2 (NIST). |
| **CVE-2017-18696** | 2017 | Android 6/7, Exynos 7420/8890/MSM8996 | RKP memory corruption | Samsung SVE-2016-7897. |

### Practical impact

- **Starting from a compromised kernel**, an attacker can target RKP's EL2 memory to turn off SELinux/SEAndroid, escalate privileges, or execute arbitrary code in the hypervisor.
- **CVE-2020-25053** has a **CVSS 9.8** score and is described as allowing arbitrary code execution in RKP — a full hypervisor compromise from the Android runtime.
- These CVEs are the mobile equivalent of a cloud VM escape: the attacker is already inside the "rich OS" kernel and then breaks into the hypervisor to disable the next layer of protection.
- Samsung Galaxy devices are also recurring Pwn2Own targets, which confirms that the market value of bypassing Samsung's layered security (including RKP) is high enough to justify repeated zero-day research.

### Sources

- Samsung Knox RKP blog: https://www.samsungknox.com/en/blog/real-time-kernel-protection-rkp
- NVD CVE-2019-19273: https://nvd.nist.gov/vuln/detail/CVE-2019-19273
- NVD CVE-2019-20553: https://nvd.nist.gov/vuln/detail/CVE-2019-20553
- NVD CVE-2019-20556: https://nvd.nist.gov/vuln/detail/CVE-2019-20556
- NVD CVE-2019-20601: https://nvd.nist.gov/vuln/detail/CVE-2019-20601
- NVD CVE-2020-13829: https://nvd.nist.gov/vuln/detail/CVE-2020-13829
- NVD CVE-2020-25053: https://nvd.nist.gov/vuln/detail/CVE-2020-25053
- NVD CVE-2021-25338: https://nvd.nist.gov/vuln/detail/CVE-2021-25338
- NVD CVE-2017-18696: https://nvd.nist.gov/vuln/detail/CVE-2017-18696
- Samsung Mobile Security Update portal: https://security.samsungmobile.com/securityUpdate.smsb

---

## 8. Conclusions for Defenders

1. **Mobile ARM64 hypervisors are already a mature attack target.** Samsung RKP has a long public CVE trail, and pKVM has started accumulating CVEs (e.g., CVE-2025-22413). The mobile ecosystem is where ARM64 hypervisor bugs are currently most visible.
2. **Cloud ARM64 hypervisors have not yet had a public VM escape incident**, but they share the same KVM/ARM64 codebase and are not immune to the same primitives (CVE-2018-18021, CVE-2024-26598).
3. **Pwn2Own does not currently isolate ARM64 hypervisors as a category**, but the mobile category repeatedly attacks Samsung devices whose security model depends on RKP. Those results are the closest public proxy for "ARM hypervisor bypass at a competition."
4. **Multi-tenant isolation is a documented design goal, not a guarantee.** AWS and Azure publicly describe the hypervisor as the isolation boundary, and both vendors explicitly account for side-channel risks. No ARM64-specific multi-tenant escape has been disclosed, but the risk is acknowledged by the architecture.
5. **For Android/pKVM deployments**, the practical takeaway is that the smaller EL2 TCB reduces exposure but does not eliminate it. Monthly Android security bulletins remain the primary remediation channel.

---

## 9. Sources

- AWS Graviton: https://aws.amazon.com/ec2/graviton/
- AWS Nitro System security whitepaper: https://docs.aws.amazon.com/whitepapers/latest/security-design-of-aws-nitro-system/security-design-of-aws-nitro-system.html
- Azure Cobalt 200: https://azure.microsoft.com/en-us/blog/new-azure-cobalt-200-vms-deliver-50-performance-improvement-fully-optimized-for-modern-agentic-ai-workloads/
- Azure isolation: https://learn.microsoft.com/en-us/azure/security/fundamentals/isolation-choices
- Google Cloud Compute Engine (Axion N4A): https://cloud.google.com/compute
- Android Virtualization Framework / pKVM overview: https://source.android.com/docs/core/virtualization
- pKVM security model: https://source.android.com/docs/core/virtualization/security
- Android Security Bulletin March 2025: https://source.android.com/docs/security/bulletin/2025-03-01
- NVD CVE-2025-22413: https://nvd.nist.gov/vuln/detail/CVE-2025-22413
- AOSP fix 1 (CVE-2025-22413): https://android.googlesource.com/kernel/common/+/1a3366f0d3d9b94a8c025d9863edc3b427435c4c
- AOSP fix 2 (CVE-2025-22413): https://android.googlesource.com/kernel/common/+/add3d68602a0c48ed2d5659f0cf26d869776ab35
- NVD CVE-2018-18021: https://nvd.nist.gov/vuln/detail/CVE-2018-18021
- NVD CVE-2024-26598: https://nvd.nist.gov/vuln/detail/CVE-2024-26598
- NVD CVE-2024-26691: https://nvd.nist.gov/vuln/detail/CVE-2024-26691
- NVD CVE-2021-47450: https://nvd.nist.gov/vuln/detail/CVE-2021-47450
- NVD CVE-2024-50114: https://nvd.nist.gov/vuln/detail/CVE-2024-50114
- Pwn2Own Wikipedia: https://en.wikipedia.org/wiki/Pwn2Own
- BleepingComputer, Galaxy S22 Pwn2Own 2022: https://www.bleepingcomputer.com/news/security/samsung-galaxy-s22-hacked-in-55-seconds-on-pwn2own-day-3/
- Samsung Knox RKP: https://www.samsungknox.com/en/blog/real-time-kernel-protection-rkp
- NVD CVE-2019-19273: https://nvd.nist.gov/vuln/detail/CVE-2019-19273
- NVD CVE-2020-25053: https://nvd.nist.gov/vuln/detail/CVE-2020-25053
- NVD CVE-2021-25338: https://nvd.nist.gov/vuln/detail/CVE-2021-25338
- NVD CVE-2020-13829: https://nvd.nist.gov/vuln/detail/CVE-2020-13829
- Samsung Mobile Security Update: https://security.samsungmobile.com/securityUpdate.smsb

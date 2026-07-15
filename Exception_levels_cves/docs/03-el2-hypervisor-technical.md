# EL2 Hypervisor Vulnerabilities on ARM64: Technical Architecture & Attack Surface

This report focuses on the ARM64 hypervisor layer (EL2), its virtualization extensions, the main implementations that run there, and the vulnerabilities that have allowed VM escape or host compromise. The emphasis is on technical depth: how Stage-2 translation, the HVC/SMC interfaces, and device emulation create attacker-facing state, and how real CVEs have abused that state.

---

## 1. ARM64 Virtualization Extensions: VHE, VTTBR, VMID, and Stage-2 Translation

### 1.1 Exception Levels and the Role of EL2

ARM64 defines four standard Exception Levels (EL0–EL3). EL2 is the hypervisor level. On a system with virtualization, the host kernel runs at EL1, userspace at EL0, and the hypervisor at EL2. EL2 has its own MMU, its own system registers, and—crucially—controls the Stage-2 translation that is applied to EL0/EL1 memory accesses.

A key distinction is **non-VHE** versus **VHE** mode:

- **Non-VHE (traditional):** EL2 has its own separate translation regime. The host kernel must context-switch state when entering/exiting the hypervisor, which adds complexity and limits the code that can run at EL2.
- **VHE (Virtualization Host Extensions):** When `HCR_EL2.E2H` is set, EL2 can use the EL1 translation regime. This lets Linux itself run at EL2 with the same page tables and MMU semantics as EL1, making KVM/ARM much simpler and faster. The kernel can be booted at EL1 and then promoted to EL2 via `HVC_FINALISE_EL2` if VHE is supported and the EL2 MMU is off.

Relevant kernel documentation: the internal kernel/HYP ABI notes that `HVC_FINALISE_EL2` attempts to upgrade the kernel from EL1 to EL2 by enabling VHE mode.

### 1.2 Stage-2 Translation Tables and VTTBR

While EL1/EL0 have their own Stage-1 page tables (managed by the guest or host kernel), the hypervisor at EL2 owns the **Stage-2** page tables. These translate the **Intermediate Physical Address (IPA)** produced by Stage-1 into the actual **Physical Address (PA)** seen by memory.

- **VTTBR_EL2** holds the base address of the Stage-2 translation tables.
- **VTCR_EL2** configures the Stage-2 translation regime (granule size, start level, etc.).
- Each Stage-2 walk uses the **VMID** (Virtual Machine ID) stored in `VTTBR_EL2.VMID` to tag TLB entries and avoid coherency problems between different guests or between host and guest translation regimes.

Because the hypervisor controls Stage-2, it can:

- Unmap pages from a guest so the guest cannot access them.
- Trap guest accesses to specific IPAs and emulate them in the hypervisor (MMIO).
- Share pages between host and guest by mapping the same PA in both Stage-2 regimes.

A malicious or buggy hypervisor, or a guest that can corrupt the hypervisor's Stage-2 state, can therefore remap memory arbitrarily, bypassing isolation.

### 1.3 VMID and TLB Management

VMID is a 16-bit (or smaller, implementation-defined) tag. TLB entries for Stage-2 translations are tagged by VMID, so switching VMs requires only a VMID change rather than a full TLB invalidate. This is efficient but creates subtle correctness requirements: if the hypervisor invalidates a Stage-2 TLB entry (TLBI) on one CPU while another CPU is performing a store to the affected page, hardware errata can cause the store to complete after the invalidation, bypassing new protections. This is exactly the class of issue seen in Xen XSA-493 (CVE-2025-10263), discussed below.

---

## 2. Hypervisor Implementations

### 2.1 KVM/ARM64 (Upstream Linux)

KVM/ARM64 runs the hypervisor code as part of the Linux kernel at EL2. With VHE, most of the hypervisor logic runs using the same kernel image, with the EL2-specific entry/exit path in `arch/arm64/kvm/hyp/`. KVM/ARM64 supports both host-managed VMs and, in the protected-KVM variant, isolated pVMs.

KVM/ARM64 exposes hypercalls to guests using the **Arm SMC Calling Convention** (DEN0028/C). The hypercall interface is defined in `arch/arm64/include/asm/kvm_hypevents.h` and documented in the kernel's hypercall page. Function IDs include `ARM_SMCCC_VENDOR_HYP_KVM_FEATURES_FUNC_ID` (discovery), `ARM_SMCCC_VENDOR_HYP_KVM_PTP_FUNC_ID` (para-virtualized time), and pKVM-specific functions such as `ARM_SMCCC_KVM_FUNC_MEM_SHARE` and `ARM_SMCCC_KVM_FUNC_MMIO_GUARD`.

### 2.2 pKVM (Protected KVM on Android)

Google's **Protected KVM (pKVM)** is a minimal hypervisor built on top of KVM/ARM64. It is the basis for the Android Virtualization Framework (AVF). pKVM's stated goal is to reduce the trusted computing base: instead of trusting the entire Android kernel (~25 MLOC), a pVM trusts only the hypervisor and the pVM firmware.

According to the upstream Linux documentation, booting with `kvm-arm.mode=protected` enables pKVM. During boot, pKVM installs a Stage-2 identity map for the host and uses it to isolate the hypervisor at EL2 from the rest of the host at EL1/EL0. Protected VMs are created with the `KVM_VM_TYPE_ARM_PROTECTED` machine type.

pKVM's isolation mechanisms are documented as follows:

- **CPU memory isolation:** Metadata pages (page-table pages, `struct kvm_vcpu` pages) are donated from the host to the hypervisor and unmapped from the host's Stage-2 identity map. Regular anonymous pages are pinned and unmapped when they are mapped into a protected guest. This means the host cannot access pVM memory that has not been explicitly shared back.
- **CPU state isolation:** Listed as **unimplemented** in the upstream documentation.
- **DMA isolation using an IOMMU:** Listed as **unimplemented** in the upstream documentation.
- **FF-A and PSCI proxy:** Calls from the host are proxied to prevent the host from sharing pVM or hypervisor memory with TrustZone as part of a confused-deputy attack.
- **pVM firmware (pvmfw):** Listed as **unimplemented** in the upstream documentation.

These "unimplemented" items are important limitations: they represent concrete future attack surface, and bugs in the proxy layers or in the way the host manages memory before donation can break isolation.

pKVM memory is governed by ownership states: pages can be host-owned, shared with the guest, donated to the hypervisor/guest, or hypervisor-owned. The transition logic is the core of the attack surface; a logic error in a transition can let a guest or a compromised host access memory it should not.

### 2.3 Xen on ARM

Xen is a Type-1 hypervisor that runs directly on hardware at EL2. On ARM, Xen maintains a **P2M (Physical-to-Machine)** mapping for each guest, which is the equivalent of Stage-2 page tables. Xen also uses PV (paravirtualized) devices, event channels, and grant tables for inter-domain and guest-to-host communication. These mechanisms create a large, historically error-prone interface between untrusted guests and Xen/dom0.

### 2.4 Proprietary Hypervisors

- **Samsung RKP (Real-time Kernel Protection):** Runs at EL2 on Samsung devices. It is not a general-purpose hypervisor but a security monitor that enforces read-only kernel `.text`/`.rodata`, KDP (read-only `cred`/SELinux structures), and other integrity policies. It has been bypassed in the past by abusing HVCs that changed Stage-2 permissions without validating that the target IPA was not EL2 memory.
- **Apple / Qualcomm / MediaTek hypervisors:** Various vendor EL2 stacks exist for secure boot, debug, and TEE coordination. These are typically closed-source and audit targets for TrustZone/EL3 researchers.

---

## 3. Attack Surfaces

### 3.1 HVC (Hypervisor Call) Interface

The HVC instruction is the primary control-plane boundary between EL1 and EL2. A guest or a host kernel issues HVCs to request services from the hypervisor: PSCI power management, KVM-specific hypercalls, pKVM memory management, etc. Every HVC handler must validate:

- The caller's privilege (host vs. guest).
- The validity of the page/IPA being operated on.
- The legality of the requested state transition (e.g., cannot donate an already-donated page).
- That no double-mapping is introduced.

Because the HVC interface is intentionally small, bugs in individual handlers tend to have high impact: a single missing check can allow the host to corrupt hypervisor memory or the guest to corrupt the host's Stage-2 tables.

### 3.2 SMC Forwarding and TrustZone Proxying

SMCs are normally handled by the Secure Monitor at EL3. Hypervisors often intercept and proxy SMCs to enforce policy (e.g., pKVM's FF-A/PSCI proxy). The proxy must ensure that the host cannot use the secure world as a confused deputy to access pVM or hypervisor memory. If the proxy fails to sanitize arguments, a compromised host can exfiltrate protected data via the secure world.

### 3.3 Virtio Device Emulation and Shared Memory

Guest VMs communicate with the host via virtio over shared memory. The hypervisor must ensure that shared pages are mapped in both the guest and host Stage-2 regimes while non-shared pages remain inaccessible. Virtio queue descriptors, indirect descriptors, and buffer chains are complex to parse; errors in bounds checking can lead to out-of-bounds reads/writes in the VMM or host kernel.

### 3.4 MMIO Trap Handling

When a guest accesses an MMIO region, the Stage-2 mapping is marked as invalid, causing a trap to EL2. The hypervisor (or the host, in some designs) emulates the access. MMIO emulation is a classic source of bugs: incorrect handling of unaligned access, multi-byte access, or device state can lead to memory corruption, information leaks, or denial of service.

### 3.5 Stage-2 Page Table Management

The Stage-2 page tables themselves are the highest-value target. If an attacker can corrupt a Stage-2 descriptor, they can remap any IPA to any PA. This is a direct path from a guest or host bug to a hypervisor or cross-VM compromise. Protection mechanisms such as pKVM's page-state tracker and hypervisor-owned page tables are designed to prevent this, but any bug in the tracker or in the allocator that backs the tables can subvert it.

---

## 4. Vulnerabilities Enabling VM Escape or Host Compromise

The common patterns for EL2 compromise are:

1. **Corrupt Stage-2 page tables:** A guest or host gains write access to the hypervisor's page-table pages and rewrites an IPA→PA mapping.
2. **Confuse page ownership state:** In pKVM, tricking the hypervisor into thinking a guest-owned page is host-owned (or vice versa) breaks isolation.
3. **Exploit HVC/SMC handler logic errors:** Missing validation in a hypervisor call allows a caller to read/write hypervisor memory, unmap protected pages, or change CPU state.
4. **Exploit hardware errata in TLB/TLBI behavior:** Even correct software can be bypassed by micro-architectural ordering issues, as shown by Xen XSA-493.
5. **Abuse PV/virtio/grant-table paths:** A guest supplies malicious descriptors that cause the host/hypervisor to read/write out of bounds or use freed memory.

---

## 5. pKVM Security Model and Limitations

pKVM's security model is built on a small, formally targeted hypervisor. The upstream documentation explicitly describes what is currently isolated and what is not:

- **Isolated:** CPU memory (anonymous guest pages and metadata) is protected by Stage-2 unmapping. The host cannot read or write pVM memory unless the pVM explicitly shares it back via `ARM_SMCCC_KVM_FUNC_MEM_SHARE` or `ARM_SMCCC_KVM_FUNC_MMIO_GUARD`.
- **Not yet isolated:** CPU state (vCPU register state), DMA, and pVM firmware are listed as unimplemented. This means devices with DMA access and certain vCPU operations are not fully protected by the upstream model at the time of the documentation snapshot.
- **Proxy layer:** FF-A and PSCI calls are proxied to prevent confused-deputy attacks against TrustZone. The correctness of these proxies is critical.
- **Host deprivileging:** The host kernel runs under Stage-2. It cannot modify its own page tables directly; it must request changes via HVC, which the hypervisor can reject if they violate the memory-ownership model.

Limitations:

- Memslots cannot be moved or deleted once a pVM starts running.
- Read-only memslots and dirty logging are not supported.
- File-backed pages generally cannot be mapped into a pVM.
- Donated pages are accounted against `RLIMIT_MLOCK` and remain locked until the pVM is destroyed.
- If host code accesses pVM memory that was not shared back, the hypervisor either kills the context or forcibly reclaims the pages (zeroing them). This prevents silent leakage but can still be used as a DoS primitive.

These restrictions are not just user-visible inconveniences; they are also the boundary conditions that any EL2 exploit must violate. Bugs in the enforcement of these boundaries (e.g., the CVE-2025-22413 logic error in `hyp-main.c`) are exactly the vulnerabilities that let a caller escape the model.

---

## 6. Notable CVEs in ARM Hypervisors

### 6.1 pKVM / KVM/ARM64

#### CVE-2025-22413 — pKVM hyp-main.c logic error

- **Component:** `arch/arm64/kvm/hyp/nvhe/hyp-main.c` (pKVM protected-VCPU path)
- **Type:** Logic error / privilege escalation
- **Impact:** Local information disclosure; possible privilege escalation from host/guest context to hypervisor. The Android Security Bulletin (March 2025) classifies it as Information Disclosure (ID) in the KVM subcomponent.
- **Root cause:** Multiple functions in `hyp-main.c` failed to check whether a protected vCPU was in a runnable PSCI state before running it. The fix, committed to `android/kernel/common` as `ANDROID: KVM: arm64: Don't run a protected VCPU if it isn't in a runnable PSCI state`, adds the missing state check. Running a non-runnable protected vCPU allowed the hypervisor to operate on stale or inconsistent vCPU state, which could leak information or be abused to corrupt hypervisor state.
- **Affected:** Android devices with pKVM/protected-KVM enabled.
- **Sources:**
  - NVD entry: https://nvd.nist.gov/vuln/detail/CVE-2025-22413
  - Android Security Bulletin March 2025: https://source.android.com/docs/security/bulletin/2025-03-01
  - Fix commit: https://android.googlesource.com/kernel/common/+/1a3366f0d3d9b94a8c025d9863edc3b427435c4c

### 6.2 Xen on ARM

#### CVE-2025-10263 / XSA-493 — Arm TLBI ordering erratum

- **Component:** Xen ARM Stage-2 / TLB invalidation
- **Type:** Hardware erratum / privilege escalation
- **Impact:** A malicious guest can write to memory after Xen has modified Stage-2 to forbid writes, potentially escalating to hypervisor privilege.
- **Root cause:** On certain Arm CPUs (Cortex-X1/X2/X3/X4/X925, Cortex-A76/A77/A78/A710, Neoverse V1/V2/V3/N1/N2, C1-Ultra/Premium), a broadcast TLBI on one PE may complete before a store on another PE is globally observed. A guest can use this ordering window to write memory that has just been unmapped/protected.
- **Affected:** Xen on Arm, multi-core configurations only; x86 not affected.
- **Sources:**
  - Xen XSA-493: https://xenbits.xen.org/xsa/advisory-493.html

#### CVE-2022-33747 / XSA-409 — Unbounded memory consumption for 2nd-level page tables

- **Component:** Xen ARM P2M (Stage-2) page-table allocator
- **Type:** Denial of service
- **Impact:** A malicious guest can exhaust Xen's global memory pool by manipulating its own P2M mappings, preventing new guests from being created or other operations requiring Xen memory allocation.
- **Root cause:** Removing large P2M mappings required allocations from the global memory pool to split them into smaller mappings. A guest could repeatedly trigger these allocations.
- **Fix:** Introduced a dedicated P2M page pool and `XEN_DOMCTL_shadow_op` for Arm to bound the memory consumed by P2M operations.
- **Sources:**
  - Xen XSA-409: https://xenbits.xen.org/xsa/advisory-409.html

#### CVE-2022-33744 / XSA-406 — Arm guests can cause Dom0 DoS via PV devices

- **Component:** Xen ARM dom0 foreign-mapping rbtree
- **Type:** Denial of service / data-structure corruption
- **Impact:** A guest performing parallel I/O on PV devices can corrupt the rbtree that dom0 uses to track foreign mappings, crashing dom0 or preventing further mappings.
- **Root cause:** The rbtree was updated without always holding the associated lock, creating a race window.
- **Affected:** Arm 32-bit and 64-bit only; x86 not affected. Dom0 Linux 3.13–5.18 vulnerable.
- **Sources:**
  - Xen XSA-406: https://xenbits.xen.org/xsa/advisory-406.html

#### CVE-2022-23033 / XSA-393 — guest_physmap_remove_page fails to remove p2m mappings

- **Component:** Xen ARM P2M (Stage-2) management
- **Type:** Use-after-free / privilege escalation
- **Impact:** A guest could retain access to memory pages after returning them to Xen, leading to information leaks, host DoS, or privilege escalation.
- **Root cause:** P2M removal functions did not clear the pagetable entry if the valid bit was not set. A guest could use set/way cache maintenance to create a valid entry without the valid bit, then call `XENMEM_decrease_reservation` to "return" the page while keeping the mapping.
- **Affected:** Xen 4.12 and newer on Arm; x86 not affected.
- **Sources:**
  - Xen XSA-393: https://xenbits.xen.org/xsa/advisory-393.html

#### CVE-2023-34320 / XSA-436 — Arm guests can trigger a deadlock on Cortex-A77

- **Component:** Xen ARM scheduler / CPU hotplug
- **Type:** Denial of service
- **Impact:** A guest can trigger a deadlock that hangs the system.
- **Affected:** Xen on Arm with Cortex-A77; x86 not affected.
- **Sources:**
  - Xen XSA list: https://xenbits.xen.org/xsa/

#### CVE-2021-28693 / XSA-372 — Xen ARM boot modules not scrubbed

- **Component:** Xen ARM boot module handling
- **Type:** Information disclosure
- **Impact:** Sensitive boot modules left in memory after boot could be read by guests.
- **Affected:** Xen on Arm.
- **Sources:**
  - Xen XSA list: https://xenbits.xen.org/xsa/

### 6.3 Proprietary / Vendor Hypervisors

#### Samsung RKP historical bypasses

- **Attack:** Samsung RKP's `rkp_s2_page_change_permission` HVC did not validate that the target IPA was not EL2 memory, allowing an attacker at EL1 to make RKP code pages writable with a single HVC. This was demonstrated by Impalabs (2021).
- **Impact:** Full bypass of RKP's Stage-2 protections, including read-only `.text`, `.rodata`, and KDP pages.
- **Sources:**
  - Impalabs RKP compendium: https://blog.impalabs.com/2101_samsung-rkp-compendium.html
  - Project Zero "Lifting the Visor": https://projectzero.google/2017/02/lifting-hyper-visor-bypassing-samsungs.html

---

## 7. Sources

- Android Security Bulletins (monthly): https://source.android.com/docs/security/bulletin
- Android Virtualization Framework (AVF) overview: https://source.android.com/docs/core/virtualization
- Linux Kernel — Protected KVM (pKVM): https://docs.kernel.org/virt/kvm/arm/pkvm.html
- Linux Kernel — KVM/arm64-specific hypercalls exposed to guests: https://docs.kernel.org/virt/kvm/arm/hypercalls.html
- Linux Kernel — Internal ABI between the kernel and HYP: https://docs.kernel.org/virt/kvm/arm/hyp-abi.html
- NVD — CVE-2025-22413: https://nvd.nist.gov/vuln/detail/CVE-2025-22413
- Android kernel/common fix for CVE-2025-22413: https://android.googlesource.com/kernel/common/+/1a3366f0d3d9b94a8c025d9863edc3b427435c4c
- Xen Security Advisories: https://xenbits.xen.org/xsa/
- Xen XSA-493 (CVE-2025-10263): https://xenbits.xen.org/xsa/advisory-493.html
- Xen XSA-409 (CVE-2022-33747): https://xenbits.xen.org/xsa/advisory-409.html
- Xen XSA-406 (CVE-2022-33744): https://xenbits.xen.org/xsa/advisory-406.html
- Xen XSA-393 (CVE-2022-23033): https://xenbits.xen.org/xsa/advisory-393.html
- Samsung RKP research by Impalabs: https://blog.impalabs.com/2101_samsung-rkp-compendium.html
- Project Zero "Lifting the Visor": https://projectzero.google/2017/02/lifting-hyper-visor-bypassing-samsungs.html
- ARM SMC Calling Convention (DEN0028/C): https://developer.arm.com/docs/den0028/c (referenced by kernel hypercall documentation)

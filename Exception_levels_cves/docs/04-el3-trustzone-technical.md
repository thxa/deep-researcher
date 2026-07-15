# EL3 Secure Monitor & TrustZone Vulnerabilities on ARM64: Technical Architecture & Attack Surface

**Researcher A (Technical Depth)**  
**Scope:** ARM TrustZone architecture, ARM Trusted Firmware (TF-A), TEE implementations (OP-TEE, QSEE/QTEE, TEEGRIS, Kinibi, iTrustee), SMC interface attack surface, secure boot chain, and representative CVEs.  
**Date:** 2026-07-15

---

## 1. ARM TrustZone Architecture: Secure/Normal World Split

ARM TrustZone partitions the system into two worlds: **Secure** and **Non-secure** (Normal). On ARMv8-A, the split is enforced by the **SCR_EL3.NS** bit and the architectural notion of a "Secure state" versus a "Non-secure state." The Secure Monitor at **EL3** is the only software component that can switch between these two states.

### 1.1 Exception Levels and TrustZone

| EL | Normal World | Secure World | Typical Role |
|----|--------------|--------------|--------------|
| EL0 | Apps | Trusted Applications (TAs) | User-space code |
| EL1 | Android/Linux kernel | TEE kernel (Secure OS) | OS kernel |
| EL2 | Hypervisor | — | Virtualization (normal world only) |
| EL3 | **Secure Monitor** | **Secure Monitor** | Firmware, world switching, PSCI, boot |

Key points:

- The **Secure Monitor** runs at EL3 in the secure world. It is entered via the `SMC` instruction (from non-secure EL1/EL2) or via interrupts/secure exceptions. It is responsible for saving the non-secure CPU context, switching the NS bit, and dispatching to the appropriate secure-world handler (TEE, PSCI, SDEI, etc.).
- **Secure EL1** runs the TEE operating system (e.g., OP-TEE core, Qualcomm QTEE, Samsung TEEGRIS, Trustonic Kinibi).
- **Secure EL0** runs Trusted Applications (TAs), isolated from each other by the TEE kernel.
- **EL2** is not part of the secure world. A hypervisor at EL2 can trap SMC calls from EL1/EL0 and either forward them to EL3 or handle them itself. This is the primary architectural control point for normal-world SMC mediation.

### 1.2 Memory and Interrupt Partitioning

TrustZone isolation is not purely a CPU-state concept; it relies on bus-level hardware firewalls:

- **TZASC (TrustZone Address Space Controller)** partitions DRAM into secure and non-secure regions. A non-secure master that attempts to read secure memory will get an abort (or a returned zero, depending on configuration), but a secure master can usually access both regions.
- **TZMA (TrustZone Memory Adapter)** provides finer-grained on-chip memory protection.
- **GIC (Generic Interrupt Controller)** supports secure and non-secure interrupt groups, and the secure world can configure routing rules so that normal-world interrupts can be delivered to the secure monitor and then forwarded.

The practical implication is that a compromise of the secure-world kernel or the EL3 monitor effectively gives an attacker full control over both memory and interrupts, even if the normal-world hypervisor and kernel are intact.

### 1.3 State Transition: `SMC` and `ERET`

The canonical transition from the normal world to the secure world is the `SMC` (Secure Monitor Call) instruction:

1. Normal-world EL1/EL2 executes `SMC #0`.
2. The CPU takes an exception to EL3, sets `SCR_EL3.NS = 0` (or preserves it depending on the handler), and vectors into the EL3 Secure Monitor.
3. The monitor saves the non-secure context (general-purpose registers, banked system registers, etc.) to a per-CPU context structure on the EL3 stack.
4. The monitor dispatches based on the SMC function ID in `x0` (SMC64) or `w0` (SMC32), using the calling convention described in DEN0028/C (SMC Calling Convention).
5. On return, the monitor restores the saved context and executes `ERET`, which returns to the lower EL and flips the NS bit back to non-secure.

The integrity of the saved/restored context is security-critical: bugs in the monitor context switch can leak register state between SMC clients (see TFV-8 / CVE-2018-19440 below) or corrupt the return address.

---

## 2. SMC Calling Convention (DEN0028/C)

The ARM **SMC Calling Convention** defines how the normal world requests services from the secure world and how results are returned. It is the de facto boundary between untrusted and trusted code on ARM devices.

### 2.1 Function Identifier Encoding

SMC function IDs are 32-bit integers encoded as follows:

```
[31]      = Fast/Standard call (1 = fast, 0 = standard)
[30]      = SMC32/SMC64 (1 = 64-bit, 0 = 32-bit)
[29:24]   = Service call range (OEM, Trusted OS, Trusted Application, etc.)
[23:16]   = Must be zero for SMC32
[15:0]    = Function number within the service
```

Standard ranges include:

- `0x00000000–0x3FFFFFFF`: Reserved / SMCCC standard functions (e.g., PSCI, SMCCC version discovery, architectural calls).
- `0x40000000–0x7FFFFFFF`: Trusted OS calls (e.g., OP-TEE).
- `0x80000000–0xBFFFFFFF`: Trusted Application calls.
- `0xC0000000–0xFFFFFFFF`: Trusted firmware / platform-specific calls.

### 2.2 Argument and Return Registers

Up to six 64-bit arguments are passed in `x0`–`x5` (SMC64) or `w0`–`w5` (SMC32). Return values are placed in `x0`–`x3` for SMC64 or `w0`–`w3` for SMC32. The calling convention is not a secure interface by itself: it is the responsibility of the EL3 monitor and the TEE to validate arguments, check client permissions, and sanitize return registers.

### 2.3 Standard vs. Fast Calls

- **Standard calls** can be preempted by non-secure interrupts and are used for long-running operations (e.g., crypto, secure storage).
- **Fast calls** are atomic, cannot be interrupted, and are meant for quick state queries or power-management transitions (PSCI).

Because standard calls can be interrupted, the monitor must correctly handle re-entrant state: a non-secure interrupt during a standard SMC can itself issue another SMC, and the monitor must preserve the original call's context.

---

## 3. ARM Trusted Firmware (ATF / TF-A)

**ARM Trusted Firmware-A (TF-A)** is the reference open-source implementation of secure-world software for ARMv7-A and ARMv8-A. It provides the Secure Monitor at EL3 and the boot firmware that loads the TEE and normal-world bootloader.

### 3.1 Boot Stage Model

TF-A is organized into **Boot Levels (BL)**:

| Stage | EL | Role | Trust assumption |
|-------|----|------|------------------|
| BL1 | EL3 | Boot ROM / Trusted Boot Firmware | Immutable ROM or authenticated early code |
| BL2 | EL3/EL1S | Trusted Boot Firmware, loads images | Authenticated by BL1 |
| BL31 | EL3 | EL3 Runtime Software / Secure Monitor | Loaded and authenticated by BL2 |
| BL32 | Secure EL1 | Trusted Execution Environment (TEE) | Loaded and authenticated by BL2, dispatched by BL31 |
| BL33 | Non-secure EL1 | Normal-world bootloader (e.g., U-Boot, UEFI, Android bootloader) | Loaded and authenticated by BL2 |

BL31 is the runtime Secure Monitor. It implements the SMC dispatcher, PSCI (power state coordination), SDEI (Software Delegated Exception Interface), TBBR-CLIENT trusted boot, and, when used, the SMC proxy to the TEE.

### 3.2 TF-A Components Relevant to Security

- **SMC Dispatcher:** Routes incoming SMCs to the appropriate service (PSCI, SDEI, TEE, etc.). A missing or malformed handler is a common vulnerability class.
- **Context Management:** Saves and restores non-secure and secure CPU context. Vulnerabilities here (e.g., TFV-8) can leak values between SMC clients or corrupt the return path.
- **Authentication Framework:** Parses X.509 certificates to authenticate BL images. Vulnerabilities in the certificate parser (e.g., TFV-10) can cause out-of-bounds reads or bypass authentication in custom chain-of-trust configurations.
- **Firmware Update (FWU) SMC Interface:** Available briefly after cold boot to allow normal-world firmware update code to load a recovery image. Integer overflows in this path (e.g., TFV-1) allow unexpectedly large copies into secure memory.
- **Xlat (Translation) Library:** Used by TF-A for its own MMU mappings. A CPU erratum related to TLB invalidation sequencing affects this library (TFV-17 / CVE-2025-10263).

### 3.3 TF-A Security Advisories

The TF-A project maintains a public security-advisory index covering 17 tracked issues to date. Selected advisories are discussed in Section 7.

---

## 4. TEE Implementations

A Trusted Execution Environment (TEE) is a secure-world OS that hosts Trusted Applications (TAs). The following are the dominant implementations in mobile and embedded ARM devices.

### 4.1 OP-TEE

OP-TEE is the open-source TEE reference implementation maintained by Linaro and now part of the TrustedFirmware.org project. It runs at Secure EL1 and exposes a GlobalPlatform TEE Client API to the normal world via a Linux kernel driver (`drivers/tee/optee/`).

Architecture notes:

- **SMC dispatch:** OP-TEE receives SMCs forwarded by BL31. The standard message format is `optee_msg_arg`, which carries command type, session ID, and parameter list.
- **Shared memory:** Normal-world clients can register shared memory buffers with the TEE. OP-TEE uses memory objects (`mobj`) to track physical backing and secure/non-secure attributes. Flaws in mobj handling have led to UAF/OOB reads (e.g., CVE-2022-46152).
- **ASLR and stack canaries:** OP-TEE supports ASLR for both the TEE core and user-mode TAs, and compiler-instrumented stack canaries.
- **Pseudo-TAs:** Privileged TAs that run in the TEE core context (e.g., `tee-supplicant` support, secure storage). They are high-value targets because they execute with kernel privileges.

### 4.2 Qualcomm QSEE / QTEE

**QSEE (Qualcomm Secure Execution Environment)** is Qualcomm's proprietary TEE. It runs at Secure EL1 and is loaded by the Qualcomm boot chain (often as a signed ELF or mbn image). QSEE trustlets (TAs) are signed by Qualcomm or OEMs and are loaded via the QSEECOM driver in the normal-world kernel.

Key attack surface:

- **QSEECOM driver (`drivers/misc/qseecom.c`):** The normal-world kernel driver is the gatekeeper. It marshals requests to QSEE and validates offsets/lengths. Vulnerabilities here (e.g., CVE-2014-4322, CVE-2016-3931) allow the normal world to corrupt QSEE memory or escalate privileges.
- **QSEE trustlets:** Applications such as Widevine, fingerprint, and DRM run as QSEE trustlets. They parse normal-world-supplied input and are frequent targets for buffer overflows and information leaks (e.g., CVE-2015-6639, CVE-2018-11976).
- **SMC dispatch:** Qualcomm's EL3 monitor (sometimes based on an old ATF fork or a custom monitor) dispatches SMCs to QSEE. Missing access checks on SMCs intended only for the TEE can allow the normal world to reach privileged functions (CVE-2017-18141).

Qualcomm has been transitioning QSEE to **QTEE** in newer chipsets, but the trustlet model and the QSEECOM-style interface remain conceptually similar.

### 4.3 Samsung TEEGRIS

**TEEGRIS** is Samsung's proprietary TEE, deployed on Exynos-based Samsung devices from roughly the Galaxy S8 onward. It replaced Trustonic Kinibi on the Exynos product line and runs at Secure EL1.

TEEGRIS architecture notes:

- **Trustlets:** TEEGRIS hosts trustlets for DRM (Widevine), HDCP, fingerprint (SEC_FR), payment (Esecomm), and Samsung-specific services (BIOSUB, EXT_FR).
- **Normal-world interface:** The Android kernel exposes a `/dev/tee` or vendor-specific driver that forwards TA commands. The input is parsed by the TEE kernel, which then dispatches to the target trustlet.
- **Historical bug classes:** A large cluster of Samsung security bulletins (SVE-2019-148xx, SVE-2019-152xx) disclosed in 2019–2020 covered buffer overflows, out-of-bounds writes, and type confusion in trustlets such as HDCP, BIOSUB, SEC_FR, WVDRM, EXT_FR, and Esecomm. These are cataloged as CVE-2019-20545, CVE-2019-20560, CVE-2019-20562, CVE-2019-20563, CVE-2019-20571, CVE-2019-20583, CVE-2019-20584, and CVE-2020-10837.

### 4.4 Trustonic Kinibi

Trustonic's **Kinibi** (formerly t-base / <t-base) is a commercial TEE licensed to multiple OEMs, including Samsung on some older Exynos devices and MediaTek platforms. It runs at Secure EL1 and provides a GlobalPlatform-compatible API.

Kinibi has seen vulnerabilities in its memory-mapping logic. For example, CVE-2020-13831 affected Samsung Exynos 7570 devices by allowing arbitrary memory mapping through the Trustonic Kinibi component, which could compromise the isolation between TAs and normal-world memory.

### 4.5 Huawei iTrustee

**iTrustee** is Huawei's proprietary TEE, used on Kirin-based Huawei devices. It runs at Secure EL1 and provides a vendor-specific TA ecosystem. iTrustee is closed-source and has been less publicly documented than OP-TEE or QSEE, but its attack surface follows the same pattern: SMC dispatch, shared memory parsing, trustlet input validation, and secure-boot chain verification.

### 4.6 Comparison Matrix

| TEE | Vendor | Open Source | Typical Chipsets | Notable CVE Clusters |
|-----|--------|-------------|------------------|----------------------|
| OP-TEE | Linaro / TrustedFirmware | Yes | NXP i.MX, STM32MP, Rockchip, MediaTek reference | CVE-2019-101029x, CVE-2021-44149, CVE-2022-46152 |
| QSEE / QTEE | Qualcomm | No | Snapdragon | CVE-2014-4322, CVE-2015-6639, CVE-2016-3931, CVE-2017-18141, CVE-2018-11976 |
| TEEGRIS | Samsung | No | Samsung Exynos | CVE-2019-20545, CVE-2019-20560–20563, CVE-2019-20571, CVE-2019-20583, CVE-2019-20584, CVE-2020-10837 |
| Kinibi | Trustonic | No | Samsung/MediaTek/others | CVE-2020-13831 |
| iTrustee | Huawei | No | Kirin | (less public CVE data) |

---

## 5. SMC Interface Attack Surface and Fuzzing

The SMC interface is the primary attack surface from the normal world into the secure world. Unlike a driver, an SMC is a direct CPU-level exception into the highest-privilege firmware. The following subsections describe the main vulnerability classes and the research tools used to find them.

### 5.1 Vulnerability Classes in SMC Handling

| Class | Mechanism | Example |
|-------|-----------|---------|
| **Missing argument validation** | SMC handler trusts caller-supplied length, offset, or ID without range checks. | TFV-1 (FWU image copy), TFV-11 (SDEI interrupt ID) |
| **Integer overflow** | Arithmetic on SMC arguments overflows and bypasses bounds checks. | TFV-1 (image size / block size) |
| **Information leakage** | Monitor or TEE fails to sanitize return registers or shared memory. | TFV-8 (x0–x3 leakage), CVE-2018-11976 (ECDSA key leak) |
| **Confused deputy** | SMC intended for TEE is reachable from normal world; normal world tricks TEE into privileged operations. | CVE-2017-18141 |
| **Memory corruption in trustlets** | TA parses untrusted input from shared memory; stack/heap overflows, OOB writes, type confusion. | TEEGRIS CVE-2019-205xx, OP-TEE CVE-2019-101029x |
| **Race conditions / TLB/translation issues** | Sequences of SMCs are not atomic; translation invalidation or page ownership changes create TOCTOU. | TFV-17 (TLBI+DSB race), CVE-2022-46152 (mobj cleanup) |
| **Secure-boot parser bugs** | Boot-certificate or image parser is reachable pre-authentication. | TFV-10 (X.509 extensions) |

### 5.2 SMC Fuzzing and Research Methodologies

Because SMCs are a low-level binary interface, fuzzing them requires either a device, an emulator, or a firmware rehosting setup. Publicly referenced approaches include:

- **Rehosting and emulation:** Running TF-A / OP-TEE in QEMU or FVP (Fixed Virtual Platform) and mutating SMC arguments. The OP-TEE project itself provides QEMU and FVP build targets for testing.
- **Coverage-guided fuzzing:** Mutating the SMC argument registers and any associated shared-memory buffers while monitoring code coverage in the TEE binary. Tools like AFL, libFuzzer, or custom harnesses are used; the challenge is bridging the host fuzzer to the target TEE context.
- **Kernel-driven fuzzing:** A normal-world kernel module issues arbitrary SMCs and records panics, crashes, or abnormal return values. This is the practical approach on real devices but requires a rooted or test-device kernel.
- **Static and symbolic analysis:** Reversing trustlets and the SMC dispatcher to identify missing validation, memcpy targets, and trustlet entry points. Tools include Ghidra, IDA Pro, and angr.
- **Confused-deputy analysis:** Mapping which SMC function IDs are reachable from each normal-world client and checking whether any service assumes it is called only from the TEE or from a trusted kernel thread.

Notable research outputs:

- **F-Secure Foundry advisories** (e.g., FSC-HWSEC-VR2021-0001 and 0002) demonstrated OP-TEE TrustZone bypasses on NXP i.MX by abusing insecure Central Security Unit (CSU) register configurations in the OP-TEE CSU driver. These were assigned CVE-2021-36133 and CVE-2021-44149.
- **TF-A security advisories TFV-10 and TFV-11** were found by external researchers and Arm engineers using code review and targeted fuzzing of the certificate parser and SDEI SMC paths, respectively.

### 5.3 Shared Memory as a Secondary Attack Surface

Most TEE services operate on buffers shared between the normal world and the secure world. Even if the SMC dispatcher is correct, the TEE must:

- Verify that the physical pages backing the shared memory are non-secure (or secure, depending on expected direction).
- Validate the size of each parameter.
- Ensure the buffer remains mapped and accessible for the duration of the operation (preventing DMA-based revocation or UAF).
- Sanitize any metadata embedded in the shared memory (e.g., number of parameters, offsets, types).

Failures in these checks are common: CVE-2022-46152 in OP-TEE arose because `cleanup_shm_refs()` did not validate `num_params`, allowing a normal-world attacker to craft an SMC that caused out-of-bounds reading and fake-object freeing in the TEE core.

---

## 6. Secure Boot Chain and Its Relationship to EL3

The secure boot chain is the root of trust that determines which code is allowed to run at EL3, Secure EL1, and Non-secure EL1. If the boot chain is subverted, the attacker controls the Secure Monitor and can defeat higher-level security controls.

### 6.1 Chain of Trust (CoT)

TF-A implements the TBBR-CLIENT (Trusted Board Boot Requirements) model:

1. **Root of Trust Public Key (ROTPK)** is stored in immutable ROM or one-time-programmable fuses.
2. **BL1** verifies the signature of **BL2** using the ROTPK.
3. **BL2** verifies the signatures of **BL31**, **BL32** (TEE), and **BL33** (normal-world bootloader) using a chain of certificates.
4. Each image may be accompanied by a non-volatile counter certificate to enforce anti-rollback.
5. Only after all images are authenticated does control pass to BL31/BL32/BL33.

### 6.2 Key Attack Points

- **Certificate parser bugs:** If the X.509 or authentication parser can be made to read out-of-bounds or skip validation, an attacker may load a malicious BL image. TFV-10 (CVE-2022-47630) is an out-of-bounds read in the TF-A certificate parser; it is not exploitable pre-authentication in upstream TF-A but can be in custom chain-of-trust configurations.
- **Firmware update (FWU) path:** The FWU SMC interface allows untrusted normal-world code to copy a recovery image into secure memory before BL31 starts. Integer overflows here (TFV-1 / CVE-2016-10319) can cause oversized copies.
- **Anti-rollback bypass:** Tampering with the non-volatile counter or the certificate that encodes it can allow an attacker to downgrade to a vulnerable firmware version.
- **Hardcoded keys:** If the secure boot or applet encryption key is hardcoded, an attacker can sign malicious images. CVE-2020-12789 affected Microchip Atmel ATSAMA5 products because the Secure Monitor used a hardcoded key to encrypt and authenticate secure applets.
- **Bootloader unlock / debug:** CVE-2013-3051 showed that the Motorola TrustZone kernel on MSM8960 did not verify the association between a physical-address argument and a memory region, allowing crafted SMC operations to unlock the bootloader.

### 6.3 EL3 as the Trust Anchor

EL3 is the highest architectural privilege level. A compromise at EL3 bypasses:

- Hypervisor isolation at EL2 (the EL3 monitor can modify Stage-2 page tables or disable the MMU).
- OS kernel isolation at EL1 (the monitor can read/write any kernel memory).
- Userspace isolation at EL0.
- TrustZone memory partitioning (the monitor can reconfigure TZASC or access secure memory directly).

Therefore, EL3 vulnerabilities are typically the highest-impact class on ARM systems. Even read-only information leaks from EL3 (e.g., TFV-8) can be dangerous when combined with other primitives.

---

## 7. Notable CVEs by Implementation

### 7.1 ARM Trusted Firmware (ATF/TF-A) CVEs

| CVE | Advisory | Title | Root Cause | Impact |
|-----|----------|-------|------------|--------|
| **CVE-2016-10319** | TFV-1 | Malformed Firmware Update SMC can copy unexpectedly large data into secure memory | Integer overflow in `bl1_fwu_image_copy()` and `bl1_plat_mem_check()`; `block_size` / `image_size` SMC arguments unchecked | Oversized copy into secure memory; potential code execution if combined with another bug |
| **CVE-2018-19440** | TFV-8 | `x0`–`x3` not saved on SMC entry leaks return values between SMC clients | `restore_gp_registers()` restores stale x0–x3 from a previous SMC request | Information disclosure between normal-world SMC clients when EL2 does not trap/sanitize SMCs |
| **CVE-2022-47630** | TFV-10 | Incorrect validation of X.509 certificate extensions causes out-of-bounds read | `get_ext()` and `auth_nvctr()` in `mbedtls_x509_parser.c` lack proper bounds checks | OOB read in certificate parser; exploitable pre-authentication only in custom CoT configurations |
| **CVE-2023-49100** | TFV-11 | Malformed SDEI SMC causes out-of-bounds memory read / EL3 panic | `sdei_interrupt_bind()` does not validate the interrupt ID before indexing GIC structures | Secure-world panic (DoS); potential OOB read / memory corruption depending on GIC version |
| **CVE-2024-5660** | TFV-12 | Hardware Page Aggregation (HPA) may translate memory incorrectly when virtualization is used | CPU microarchitectural behavior with HPA enabled on Cortex-X/A7x/Neoverse cores | Compromised guest may attack host via HPA; information disclosure |
| **CVE-2025-10263** | TFV-17 | `TLBI+DSB` may complete too early | CPU erratum: a store crossing a page boundary may not be globally observed before a subsequent TLBI+DSB sequence completes | Page-table / memory-management data corruption; potential privilege escalation |

Sources: [TF-A Security Advisories Index](https://trustedfirmware-a.readthedocs.io/en/latest/security_advisories/index.html); individual advisory pages TFV-1, TFV-8, TFV-10, TFV-11, TFV-12, TFV-17.

### 7.2 Qualcomm QSEE / QTEE CVEs

| CVE | Description | Root Cause | Impact |
|-----|-------------|------------|--------|
| **CVE-2014-4322** | QSEECOM driver does not validate offset/length/base values in an ioctl | Missing validation in `drivers/misc/qseecom.c` | Memory corruption / privilege escalation from crafted app |
| **CVE-2015-6639** | Widevine QSEE TrustZone app privilege escalation | Vulnerability in `PRDiagVerifyProvisioning` / QSEECOM access | Arbitrary code in TrustZone context |
| **CVE-2015-6647** | Widevine QSEE TrustZone app privilege escalation | Related to CVE-2015-6639; insufficient trustlet input validation | Arbitrary code in TrustZone context |
| **CVE-2016-2431** | Qualcomm TrustZone component privilege escalation | Trustlet vulnerability in Qualcomm TZ stack | Privilege escalation via crafted app on Nexus 5/6/7/One |
| **CVE-2016-2432** | Qualcomm TrustZone component privilege escalation | Trustlet vulnerability in Qualcomm TZ stack | Privilege escalation on Nexus 6/One |
| **CVE-2016-3931** | QSEECOM driver privilege escalation | Missing validation in `drivers/misc/qseecom.c` (Android bug 29157595) | Privilege escalation via crafted app |
| **CVE-2016-5349** | HLOS did not provide sufficient memory address info to QSEE secure apps | Page alignment issue in normal-world → secure-world memory descriptors | Potential access-control bypass in QSEE |
| **CVE-2017-18141** | Non-secure world can issue SMC to access privileged functions meant only for the TEE | Missing access checks on SMC dispatch after a third-party TEE is loaded | Privilege escalation across Snapdragon chipsets |
| **CVE-2018-11976** | ECDSA signature code leaks private keys from secure world to non-secure world | Information leak in QSEE ECDSA implementation | Private key disclosure (CVSS 5.5 / 4.9) |

Sources: NVD entries for the listed CVEs; [Qualcomm Security Bulletins](https://www.qualcomm.com/company/product-security/bulletins); [Android Security Bulletins](http://source.android.com/security/bulletin/).

### 7.3 Samsung TEEGRIS and Trustonic Kinibi CVEs

| CVE | Affected Trustlet / Component | Description | Samsung ID |
|-----|-------------------------------|-------------|------------|
| **CVE-2019-20545** | HDCP Trustlet | Buffer overflow affects secure TEEGRIS memory | SVE-2019-15283 |
| **CVE-2019-20560** | BIOSUB Trustlet | Out-of-bounds write | SVE-2019-15261 |
| **CVE-2019-20562** | BIOSUB Trustlet | Buffer overflow | SVE-2019-15264 |
| **CVE-2019-20563** | SEC_FR Trustlet | Out-of-bounds write | SVE-2019-15272 |
| **CVE-2019-20571** | WVDRM Trustlet | Type confusion leading to arbitrary code execution | SVE-2019-14885 |
| **CVE-2019-20583** | EXT_FR Trustlet | Type confusion leading to arbitrary code execution | SVE-2019-14847 |
| **CVE-2019-20584** | HDCP Trustlet | Type confusion leading to arbitrary code execution | SVE-2019-14850 |
| **CVE-2020-10837** | Esecomm Trustlet | Stack overflow and arbitrary code execution | SVE-2019-15984 |
| **CVE-2020-13831** | Trustonic Kinibi | Arbitrary memory mapping | SVE-2019-16665 |

All of these CVEs are rated Critical (CVSS 9.8–10.0) and were fixed in Samsung Security Maintenance Releases (SMR) between 2019 and 2020. The underlying bug classes are classic memory-safety issues in trustlet parsers: buffer overflows, out-of-bounds writes, and type confusion.

Sources: NVD entries for the listed CVEs; [Samsung Mobile Security Updates](https://security.samsungmobile.com/securityUpdate.smsb).

### 7.4 OP-TEE CVEs

| CVE | Description | Root Cause | Fixed Version |
|-----|-------------|------------|---------------|
| **CVE-2019-1010296** | Buffer overflow; code execution in TEE core context | Integer overflow / OOB write in `optee_os` | 3.4.0+ |
| **CVE-2019-1010297** | Buffer overflow; code execution in TEE core context | Integer overflow / OOB write in `optee_os` | 3.4.0+ |
| **CVE-2019-1010298** | Buffer overflow; code execution in TEE core context | OOB write in `optee_os` | 3.4.0+ |
| **CVE-2021-36133** | TrustZone bypass on NXP i.MX; non-secure world can read/write secure memory | OP-TEE CSU driver lacks security access configuration for several i.MX models | 3.15.0+ |
| **CVE-2021-44149** | TrustZone bypass on NXP i.MX6UL; CSU driver lacks wakeup register security config | OP-TEE CSU driver misconfiguration at wakeup | 3.15.0+ |
| **CVE-2022-46152** | Improper validation of array index in `cleanup_shm_refs()` | `num_params` not validated; limited to 127 only in `get_cmd_buffer()` | 3.19.0+ |

The OP-TEE CSU driver issues are notable because they are configuration bugs, not memory-corruption bugs: the secure-world driver failed to program the NXP Central Security Unit (CSU) correctly, so a DMA-capable peripheral in the non-secure world could access secure-world memory.

Sources: NVD entries for the listed CVEs; [OP-TEE Security Advisories](https://github.com/OP-TEE/optee_os/security/advisories); [F-Secure Foundry OP-TEE Advisory](https://github.com/f-secure-foundry/advisories/blob/master/Security_Advisory-Ref_FSC-HWSEC-VR2021-0001-OP-TEE_TrustZone_bypass.txt).

### 7.5 Other TrustZone / Secure Monitor CVEs

| CVE | Component | Description | Root Cause |
|-----|-----------|-------------|------------|
| **CVE-2013-3051** | Motorola TrustZone kernel (MSM8960) | Bootloader unlock via crafted SMC 0x9 and 0x2 operations | Missing association check between physical-address argument and memory region |
| **CVE-2016-0825** | Widevine Trusted Application | Secure-storage information leak from TrustZone | Normal-world kernel can access sensitive TZ secure-storage info |
| **CVE-2020-12789** | Microchip Atmel ATSAMA5 Secure Monitor | Hardcoded key to encrypt and authenticate secure applets | CWE-798: Use of Hard-coded Credentials |

---

## 8. Mitigations and Defensive Recommendations

1. **Validate every SMC argument.** Length, offset, index, interrupt ID, and buffer type must be checked against architectural limits and platform-specific capability before use. Integer overflow must be considered in all arithmetic on attacker-controlled values.
2. **Sanitize return registers.** The EL3 monitor should clear or restore x0–x3 so that stale values from one SMC client are not leaked to another (the fix for TFV-8).
3. **Minimize the EL3 attack surface.** Disable unused SMC services (e.g., SDEI, FWU) and remove debug/hidden SMCs from production builds.
4. **Harden the secure-boot chain.** Use authenticated X.509 chains, enforce anti-rollback counters, and audit certificate parsers for out-of-bounds reads and logic bugs.
5. **Isolate TAs from each other and from the TEE core.** Stack canaries, ASLR, and strict shared-memory validation reduce the impact of trustlet memory-corruption bugs.
6. **Trap SMCs at EL2.** A hypervisor or kernel security module should trap and audit SMCs from userspace and untrusted kernel modules to prevent confused-deputy attacks.
7. **Apply CPU errata workarounds.** TLBI/DSB sequencing issues (TFV-17) and HPA behavior (TFV-12) require firmware-level workarounds; ensure these are enabled for affected cores.
8. **Fuzz and rehost TEE/SMC interfaces.** Use QEMU/FVP, coverage-guided fuzzers, and kernel-driven SMC fuzzers to find validation gaps before production.

---

## 9. Sources

1. ARM Developer, *TrustZone technology* documentation: https://developer.arm.com/documentation/102418/0300/TrustZone-technology?lang=en
2. ARM Developer, *SMC Calling Convention* (DEN0028/C): https://developer.arm.com/documentation/100935/0100/SMC-Calling-Convention?lang=en
3. Trusted Firmware-A Documentation: https://trustedfirmware-a.readthedocs.io/en/latest/
4. Trusted Firmware-A Security Advisories index: https://trustedfirmware-a.readthedocs.io/en/latest/security_advisories/index.html
5. OP-TEE Documentation, *Architecture*: https://optee.readthedocs.io/en/latest/architecture/index.html
6. National Vulnerability Database (NVD): https://nvd.nist.gov/
7. NVD API query results for TrustZone, TEE, TEEGRIS, OP-TEE, QSEE, and secure monitor keywords (queried via `services.nvd.nist.gov/rest/json/cves/2.0`).
8. Qualcomm Product Security Bulletins: https://www.qualcomm.com/company/product-security/bulletins
9. Samsung Mobile Security Updates: https://security.samsungmobile.com/securityUpdate.smsb
10. Android Security Bulletins: https://source.android.com/security/bulletin
11. F-Secure Foundry OP-TEE TrustZone bypass advisory (CVE-2021-36133 / CVE-2021-44149): https://github.com/f-secure-foundry/advisories/blob/master/Security_Advisory-Ref_FSC-HWSEC-VR2021-0001-OP-TEE_TrustZone_bypass.txt
12. OP-TEE GitHub Security Advisories (CVE-2022-46152): https://github.com/OP-TEE/optee_os/security/advisories/GHSA-65w8-6mrg-52g7

---

*Note: Web search services were unavailable due to network/rate-limit failures during the research window. CVE and technical details were therefore verified via direct NVD API/web fetches and the authoritative project documentation listed above. CVE summaries, dates, and CVSS scores are taken from NVD records as of 2026-07-15.*

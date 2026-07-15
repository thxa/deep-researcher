# EL3 Secure Monitor & TrustZone Vulnerabilities on ARM64: Practical Impact & Real-World Cases

**Researcher B (Practical & Real-World)**  
**Scope:** Real-world TrustZone compromises, Qualcomm QSEE / Samsung TEEGRIS / OP-TEE vulnerability histories, impact on payments/biometrics/DRM, and the research tools used to find these bugs.  
**Date:** 2026-07-15

---

## 1. Why TrustZone Compromise Is a System-Wide Catastrophe

ARM TrustZone splits a device into a **Normal World** (Android/Linux, EL1/EL0) and a **Secure World** (the TEE, S-EL1/S-EL0).  The **EL3 Secure Monitor** is the only software component that can switch between the two worlds.  Because the secure world is designed to protect the most sensitive assets on the device, a compromise at EL3 or inside the TEE does not merely grant “root” on Android—it grants **full control over everything the normal world trusts**.

The Project Zero research on QSEE and Trustonic Kinibi summarized the practical reality: the TEE is where devices store **KeyMaster keys (full-disk encryption), DRM content keys (Widevine), and biometric identifiers**.  If an attacker gains code execution in the TEE, these assets can be extracted or manipulated directly, and the normal-world operating system can be backdoored by patching its kernel from the secure side [[Project Zero 2017]](https://projectzero.google/2017/07/trust-issues-exploiting-trustzone-tees.html).

Key takeaways from real-world research:

- A TEE compromise is equivalent to **full device ownership**.
- OS-level mitigations (SELinux, kernel hardening, application sandboxing) become irrelevant once the secure world is lost.
- Attackers can achieve **undetectable persistence** by modifying the EL3 monitor or a trusted application rather than touching the normal-world filesystem.

---

## 2. Qualcomm QSEE: A History of Real-World TrustZone Failures

Qualcomm’s **QSEE (Secure Execution Environment)** is one of the two dominant proprietary TEEs in the Android ecosystem.  Its normal-world interface is the `qseecom` driver, and the security-critical code runs as **QSEE trustlets** (Trusted Applications) inside the secure world.

### 2.1 CVE-2015-6639 — Widevine Trustlet Privilege Escalation

The earliest public demonstration of a QSEE trustlet compromise is **CVE-2015-6639**, disclosed in the Android January 2016 security bulletin.  The NVD description states:

> “The Widevine QSEE TrustZone application in Android 5.x before 5.1.1 LMY49F and 6.0 before 2016-01-01 allows attackers to gain privileges via a crafted application that leverages QSEECOM access.” [[NVD CVE-2015-6639]](https://nvd.nist.gov/vuln/detail/CVE-2015-6639)

Project Zero showed that the exploit gave **arbitrary code execution inside the TEE** on the Nexus 6 and other devices, and that the same vulnerability was present in firmware from multiple manufacturers.  Crucially, the affected trustlets were **not revoked** in most firmware images, so even “patched” devices could be attacked by loading an old vulnerable trustlet from the filesystem [[Project Zero 2017]](https://projectzero.google/2017/07/trust-issues-exploiting-trustzone-tees.html).

### 2.2 CVE-2017-18141 — Normal World Reaching Privileged SMCs

**CVE-2017-18141** (published January 2019) is a confused-deputy-style bug in Qualcomm’s secure monitor:

> “When a 3rd party TEE has been loaded it is possible for the non-secure world to create a secure monitor call which will give it access to privileged functions meant to only be accessible from the TEE.” [[NVD CVE-2017-18141]](https://nvd.nist.gov/vuln/detail/CVE-2017-18141)

The impact is a local privilege escalation to secure-world capabilities, exactly the kind of failure that makes EL3 correctness critical.

### 2.3 CVE-2018-11976 — ECDSA Private Key Leak from Secure World

**CVE-2018-11976** is a concrete example of **key extraction** from the secure world:

> “ECDSA signature code leaks private keys from secure world to non-secure world in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Mobile, Snapdragon Wearables, Snapdragon Wired Infrastructure and Networking…” [[NVD CVE-2018-11976]](https://nvd.nist.gov/vuln/detail/CVE-2018-11976)

The affected chipsets span SD 820, 835, 845, 710, 670, 625, 636, and many others.  Private key material intended to be used only inside the TEE became readable by the normal world, directly breaking any service that relied on that key for authentication or DRM.

### 2.4 KeyMaster Key Extraction and Full-Disk Encryption Brute-Force

In a follow-up to the QSEE trustlet work, Gal Beniamini demonstrated that **Qualcomm’s KeyMaster implementation does not use a hardware-bound key for protecting Android FDE key blobs**.  Instead, the encryption/HMAC keys protecting the key blobs are derived from the **SHK (a hardware-fused key)** plus hard-coded strings, and the resulting keys are **directly available to TrustZone software**.

The practical consequences listed in the research are severe:

> “- The key derivation is not hardware bound. …  
> - OEMs can comply with law enforcement to break Full Disk Encryption. …  
> - Patching TrustZone vulnerabilities does not necessarily protect you from this issue. Even on patched devices, if an attacker can obtain the encrypted disk image … they can then ‘downgrade’ the device to a vulnerable version, extract the key by exploiting TrustZone, and use them to brute-force the encryption.  
> - Android FDE is only as strong as the TrustZone kernel or KeyMaster.” [[Bits, Please 2016]](http://bits-please.blogspot.com/2016/06/extracting-qualcomms-keymaster-keys.html)

This is a canonical real-world case of a **TrustZone failure undermining the entire device confidentiality model**: because the FDE key is ultimately protected by software inside the TEE, any TEE exploit or downgrade allows offline brute-force of the user’s PIN/password and decryption of the device.

### 2.5 Design-Level Failure: Trustlet Revocation Is Not Used

Project Zero analyzed **more than 45 firmware images** from Google, Samsung, LG, and Motorola.  In all but one firmware image, **every trustlet had version number 0**, meaning manufacturers were not using Qualcomm’s revocation mechanism even after known vulnerabilities were fixed.  Because the QSEECOM API receives the trustlet binary as a raw buffer, it has no filesystem-path context, so an attacker can simply place an old, vulnerable trustlet anywhere on the device and load it.  SELinux contexts with `qseecom` access include the media server, DRM server, KeyStore, volume daemon, and fingerprint daemon—providing many paths to trigger the attack [[Project Zero 2017]](https://projectzero.google/2017/07/trust-issues-exploiting-trustzone-tees.html).

---

## 3. Samsung TEEGRIS and Trustonic Kinibi: Proprietary TEEs in Practice

### 3.1 Trustonic Kinibi (pre-400) — No Rollback Prevention, No Exploit Mitigations

Samsung Exynos devices before the Galaxy S8 used **Trustonic Kinibi** (formerly `<t-base`).  Project Zero’s analysis showed that Kinibi trustlets had:

- **No ASLR** — trustlets are loaded at a fixed address (often `0x1000`), and the shared `mcLib` helper library is also at a fixed address (`0x7D01000`).
- **No stack cookies** — every stack buffer overflow is trivially exploitable.
- **No guard pages** between globals, heap, and stack, so overflows can cascade across regions.
- **No effective rollback prevention** — the “Service Version” field in the MobiCore Loadable Format was effectively unused, so old vulnerable trustlets could be loaded into newer firmware.

Project Zero demonstrated this by exploiting a **stack overflow in the OTP trustlet** on the Galaxy S7 Edge.  Because the trustlet was not revoked, the old version could be placed in `/data/app/mcRegistry` and loaded via the `mcDriverDaemon`, yielding arbitrary code execution in the TEE.  Samsung responded that rollback prevention was only added in **Kinibi 400 family and the Galaxy S8/S8+**; all earlier Exynos devices remained vulnerable [[Project Zero 2017]](https://projectzero.google/2017/07/trust-issues-exploiting-trustzone-tees.html).

### 3.2 Samsung TEEGRIS CVE Cluster (2019–2020)

Samsung’s later proprietary TEE, **TEEGRIS**, has also seen a stream of high-severity trustlet vulnerabilities.  Representative CVEs:

| CVE | Affected trustlet | Impact | Samsung ID / date |
|-----|-------------------|--------|-------------------|
| **CVE-2019-20545** | HDCP Trustlet | Buffer overflow in secure TEEGRIS memory; CVSS v3 9.8 | SVE-2019-15283, Nov 2019 [[NVD]](https://nvd.nist.gov/vuln/detail/CVE-2019-20545) |
| **CVE-2020-10837** | Esecomm Trustlet | Stack overflow and arbitrary code execution | SVE-2019-15984, Feb 2020 [[NVD]](https://nvd.nist.gov/vuln/detail/CVE-2020-10837) |

These trustlets handle HDCP (content protection) and embedded secure element / payment communication (`Esecomm`).  Code execution inside them gives an attacker access to the same cryptographic material that Samsung Knox and DRM systems rely on.

### 3.3 GlobalConfusion — Cross-TEE Type-Confusion 0-Days (2024)

A 2024 USENIX Security paper analyzed the **GlobalPlatform TEE Internal Core API** and found a design-level weakness: an optional type check for untrusted data is left to TA developers, and its omission leads to **type-confusion bugs that usually become arbitrary read/write primitives inside the TA**.  The researchers built **GPCheck**, a static binary analyzer, and ran it over **14,777 TAs** deployed on real-world TEEs including **QSEE, Kinibi, TEEGRIS, Trusty, OP-TEE, and BeanPod**.

Results:

- **9 known bugs** reconfirmed.
- **10 silently-fixed bugs** found.
- **14 critical 0-day vulnerabilities** discovered.
- **4 CVEs** assigned.
- Affected devices described as “currently in use by **billions of users**.”

The authors received a **$12,000 bug bounty** and responsibly disclosed the findings; ten of the 14 0-days were still in the disclosure process at publication time.  They also proposed a specification change to make the API fail-safe and demonstrated it on OP-TEE [[GlobalConfusion 2024]](https://www.usenix.org/system/files/usenixsecurity24-busch-globalconfusion.pdf).

This is a strong example of how a **single API design weakness propagates across multiple proprietary and open-source TEEs**, creating real-world exploitable bugs at scale.

---

## 4. OP-TEE: Security Track Record of the Open-Source TEE

OP-TEE is the dominant open-source TrustZone TEE, maintained by TrustedFirmware.org and used on NXP, STM, Rockchip, MediaTek reference, and other platforms.  Being open source has not made it immune to bugs.

### 4.1 CVE-2025-46733 — fTPM PCR Reset via Malicious tee-supplicant

**CVE-2025-46733** shows how a compromised **normal-world `tee-supplicant`** can attack the secure world:

> “In version 4.5.0, using a specially crafted tee-supplicant binary running in REE userspace, an attacker can trigger a panic in a TA that uses the libutee Secure Storage API. … A critical example of this is the optee_ftpm TA. It uses the kept alive memory to hold PCR values, which crucially must be non-resettable. An attacker who can trigger a panic in the fTPM TA can reset the PCRs, and then extend them with whatever they choose, falsifying boot measurements, accessing sealed data, and potentially more.” [[NVD CVE-2025-46733]](https://nvd.nist.gov/vuln/detail/CVE-2025-46733)

This is a **secure-boot / attestation bypass**: the fTPM is supposed to prove that the boot chain was not tampered with, but a normal-world attacker can force the TA to restart with a clean memory state and forge the measurements.

### 4.2 CVE-2026-45614 — ECDH Private Key Recovery

**CVE-2026-45614** is an invalid-curve attack:

> “Prior to version 4.11.0, on many of the ECDH shared secret paths, the public key isn't verified to be a point on the correct curve. By passing approximately 30–40 crafted public keys to OP-TEE, the private key can be reconstructed by a normal world attacker.” [[NVD CVE-2026-45614]](https://nvd.nist.gov/vuln/detail/CVE-2026-45614)

The attacker uses the Chinese Remainder Theorem to recover the full private key after collecting `d % r` leaks from crafted public keys.  This directly breaks any protocol that uses OP-TEE’s ECDH output as a shared secret.

### 4.3 CVE-2026-40290 — Use-After-Free in FF-A Shared Memory

**CVE-2026-40290** is a UAF in the FF-A shared-memory teardown path when OP-TEE is configured as an SPMC (`CFG_SECURE_PARTITION=y`):

> “Starting in version 3.16.0 and prior to 4.11.0, a user-after-free race condition exists in the shared memory teardown logic of FF-A within OP-TEE SPMC/SP flows. … The function `sp_mem_remove()` … fails to acquire the global `sp_mem_lock` before performing the `free()` operations.” [[NVD CVE-2026-40290]](https://nvd.nist.gov/vuln/detail/CVE-2026-40290)

CVSS v3: **7.8 HIGH** (local privilege escalation / information disclosure / denial of service).

### 4.4 CVE-2026-45702 — Type Confusion in FFA_MEM_SHARE

**CVE-2026-45702** is a type-confusion bug in OP-TEE’s handling of `FFA_MEM_SHARE` requests when configured as an SPMC:

> “Starting in version 4.3.0 and prior to version 4.11.0, a type confusion vulnerability exists in OP-TEE OS when processing an FFA_MEM_SHARE request from the normal world.” [[NVD CVE-2026-45702]](https://nvd.nist.gov/vuln/detail/CVE-2026-45702)

These recent CVEs illustrate that OP-TEE, despite its open-source scrutiny, continues to have bugs in the **SMC/FF-A boundary** between the normal world and the secure world—exactly the surface that EL3/TEE research tools target.

---

## 5. Impact on Mobile Payments, Biometric Security, and DRM

The real-world impact of TrustZone/EL3 failures is not theoretical.  The TEE is the component that is supposed to protect the assets that matter most to users and service providers.

### 5.1 Mobile Payments

Payment systems use the TEE for:

- **Hardware-backed key generation** for payment tokens.
- **Secure display / trusted UI** for PIN entry (to defeat screen-loggers).
- **Embedded Secure Element (eSE)** or NFC controller emulation (HCE) key storage.

A TEE compromise lets an attacker extract the payment keys or fake the trusted UI, enabling fraudulent transactions.  The **Esecomm** trustlet vulnerabilities in Samsung TEEGRIS directly target the secure-element communication path [[NVD CVE-2020-10837]](https://nvd.nist.gov/vuln/detail/CVE-2020-10837).

### 5.2 Biometric Security

Fingerprint and face templates are processed inside the TEE.  If the TEE is compromised:

- **Templates can be stolen**; unlike passwords, biometric data cannot be changed.
- **Liveness checks can be bypassed** by altering the trusted sensor driver or the matching logic.
- **Normal-world lockscreens can be silently unlocked** by manipulating the TEE’s response to the fingerprint daemon.

Project Zero explicitly listed the fingerprint daemon as one of the SELinux contexts with QSEECOM access, giving it a direct path to the TEE attack surface [[Project Zero 2017]](https://projectzero.google/2017/07/trust-issues-exploiting-trustzone-tees.html).

### 5.3 DRM (Widevine / HDCP)

DRM relies on the TEE to keep content decryption keys hidden.  Compromises have repeatedly shown that these keys leak:

- **CVE-2015-6639** directly targeted the **Widevine QSEE trustlet**.
- **CVE-2018-11976** leaked ECDSA private keys from the secure world.
- **CVE-2019-20545** overflowed the **HDCP trustlet** in Samsung TEEGRIS.

Once decryption keys are extracted, content can be decrypted outside the device, defeating the entire DRM chain.  The practical result is that TrustZone vulnerabilities are a direct route to **Widevine L1 → L3 downgrade** or wholesale content piracy.

### 5.4 Full-Disk Encryption / Secure Boot

The Bits, Please research showed that **Android FDE is only as strong as the TrustZone kernel or KeyMaster**.  If the TEE can be exploited (or downgraded to a vulnerable TEE image), the FDE key can be extracted and the user’s data decrypted offline.

Similarly, OP-TEE’s **fTPM TA** is used for measured boot and sealing secrets.  CVE-2025-46733 allows an attacker to reset PCRs and forge boot measurements, which breaks the secure-boot assumption and can unlock **BitLocker / dm-crypt / sealed credentials** that depend on the fTPM [[NVD CVE-2025-46733]](https://nvd.nist.gov/vuln/detail/CVE-2025-46733).

---

## 6. Research Tools That Uncover These Bugs

Because TrustZone software is closed-source and runs in a privileged hardware partition, specialized tooling is required to analyze it at scale.

### 6.1 PARTEMU — Emulation-Based Dynamic Analysis

**PARTEMU** (USENIX Security 2020) is an emulator built on QEMU/PANDA that can run four major real-world TZOSes: **Qualcomm QSEE, Trustonic Kinibi, Samsung TEEGRIS, and Linaro OP-TEE**.  It integrates AFL for feedback-driven fuzzing and was used to perform:

- A large-scale study of **194 unique TAs** from **12 different Android smartphone vendors** and a leading IoT vendor.
- Discovery of **previously unknown vulnerabilities in 48 TAs**, several exploitable.
- Dynamic testing of the **QSEE TZOS itself**, finding crashes in code paths that would not normally be exercised on a real device.

PARTEMU demonstrated that **emulation-based dynamic analysis of real-world TrustZone software is both feasible and effective** [[PARTEMU 2020]](https://www.usenix.org/system/files/sec20summer_harrison_prepub.pdf).

### 6.2 TEEzz — Black-Box Fuzzing on COTS Android Devices

**TEEzz** is a black-box fuzzer from HexHive/EPFL for **Trusted Applications running on COTS Android mobile devices**.  Unlike emulation-based approaches, TEEzz operates directly on production hardware by identifying client applications, generating driver code, and mutating TA inputs.  The tool is designed to find bugs in the same trustlet attack surface exploited by CVE-2015-6639, CVE-2019-20545, and CVE-2020-10837 [[TEEzz GitHub]](https://github.com/HexHive/teezz-fuzzer).

### 6.3 EL3XIR — Fuzzing COTS Secure Monitors at EL3

**EL3XIR** (USENIX Security 2024) targets the **EL3 Secure Monitor** itself, not just TAs or the TEE OS.  Rehosting and fuzzing proprietary secure-monitor firmware is difficult because SMCs depend on peripheral state and complex input formats.  EL3XIR solved those challenges and found:

- **34 bugs** total.
- **17 classified as security-critical**.
- **14 vendor-confirmed bugs**.
- **6 CVEs assigned**.

This is the first large-scale public demonstration that the **EL3 layer**—the highest-privilege firmware on ARM devices—is also exploitable in practice, with real CVEs assigned [[EL3XIR 2024]](https://www.usenix.org/system/files/usenixsecurity24-lindenmeier.pdf).

### 6.4 GPCheck — Static Analysis for GlobalPlatform API Type Confusion

**GPCheck**, introduced in the **GlobalConfusion** research, is a static binary analyzer that looks for the **fail-open type check** in GlobalPlatform TEE Internal Core API implementations.  It was used to analyze **14,777 TAs** and discovered **14 critical 0-day vulnerabilities** across multiple TEEs, including TEEGRIS.  The tool is a strong complement to fuzzers because it finds design-level bugs without needing a live device or emulator [[GlobalConfusion 2024]](https://www.usenix.org/system/files/usenixsecurity24-busch-globalconfusion.pdf).

---

## 7. Consequences of EL3 Compromise

The EL3 Secure Monitor is the highest-privilege CPU level on ARM devices.  It is responsible for:

- World switching between Normal and Secure worlds.
- SMC dispatch and argument routing.
- PSCI (power management) and SDEI (software-delegated exceptions).
- Saving and restoring CPU context across security boundaries.
- Configuring TrustZone memory and interrupt routing (in conjunction with TZASC/TZMA and the GIC).

If the EL3 monitor is compromised, the attacker can:

1. **Intercept every SMC** between the normal world and the TEE.
2. **Forge or suppress secure-world responses** to the normal world.
3. **Map, read, or modify any physical memory** by abusing the monitor’s privileged view.
4. **Subvert the boot chain** (e.g., PSCI, FWU SMCs) to load attacker-controlled firmware.
5. **Install persistent bootkit/backdoor** that survives OS reinstallation and is invisible to normal-world antivirus/EDR.

The EL3XIR results prove that this layer is not merely a theoretical target: **17 security-critical bugs** were found in real COTS secure monitors, and **6 CVEs** were assigned.  In short, an EL3 compromise is **full, undetectable, persistent device ownership**.

---

## 8. Mitigations and Practical Takeaways

Real-world TrustZone research suggests the following priorities for vendors and defenders:

1. **Use rollback prevention.**  Qualcomm’s `SW_ID`/`APP_ID` eFuse and RPMB-based revocation mechanisms exist, but manufacturers largely do not use them.  Enabling them and incrementing trustlet version counters after every security-relevant fix is essential.
2. **Harden the TEE attack surface.**  Apply modern exploit mitigations (ASLR, stack cookies, guard pages, heap isolation) inside the TEE, not just in the normal world.  Project Zero showed that Kinibi had none of these and that QSEE’s ASLR was limited to roughly 9 bits of entropy.
3. **Restrict normal-world access to TEE/EL3 interfaces.**  The QSEECOM and `mcDriverDaemon` interfaces are exposed to many privileged SELinux contexts; minimizing the number of processes that can issue SMCs or load trustlets reduces the attack surface.
4. **Fuzz and statically analyze TAs and the monitor.**  Tools like PARTEMU, TEEzz, EL3XIR, and GPCheck have proven that TEE bugs are abundant and exploitable.  They should be part of the vendor security lifecycle.
5. **Do not assume the TEE is uncompromisable.**  Mobile payments, biometrics, DRM, and FDE should be designed with the assumption that a TEE/EL3 compromise is possible, and should include additional independent checks where feasible.

---

## Sources

- Project Zero, “Trust Issues: Exploiting TrustZone TEEs,” July 2017.  https://projectzero.google/2017/07/trust-issues-exploiting-trustzone-tees.html
- NVD, CVE-2015-6639.  https://nvd.nist.gov/vuln/detail/CVE-2015-6639
- NVD, CVE-2017-18141.  https://nvd.nist.gov/vuln/detail/CVE-2017-18141
- NVD, CVE-2018-11976.  https://nvd.nist.gov/vuln/detail/CVE-2018-11976
- Bits, Please!, “Extracting Qualcomm’s KeyMaster Keys — Breaking Android Full Disk Encryption,” June 2016.  http://bits-please.blogspot.com/2016/06/extracting-qualcomms-keymaster-keys.html
- NVD, CVE-2019-20545.  https://nvd.nist.gov/vuln/detail/CVE-2019-20545
- NVD, CVE-2020-10837.  https://nvd.nist.gov/vuln/detail/CVE-2020-10837
- Busch, Mao, Payer, “GlobalConfusion: TrustZone Trusted Application 0-Days by Design,” USENIX Security 2024.  https://www.usenix.org/system/files/usenixsecurity24-busch-globalconfusion.pdf
- NVD, CVE-2025-46733.  https://nvd.nist.gov/vuln/detail/CVE-2025-46733
- NVD, CVE-2026-45614.  https://nvd.nist.gov/vuln/detail/CVE-2026-45614
- NVD, CVE-2026-40290.  https://nvd.nist.gov/vuln/detail/CVE-2026-40290
- NVD, CVE-2026-45702.  https://nvd.nist.gov/vuln/detail/CVE-2026-45702
- Harrison, Vijayakumar, Padhye, Sen, Grace, “PARTEMU: Enabling Dynamic Analysis of Real-World TrustZone Software Using Emulation,” USENIX Security 2020.  https://www.usenix.org/system/files/sec20summer_harrison_prepub.pdf
- HexHive, “TEEzz: Fuzzing Trusted Applications on COTS Android Devices,” GitHub repository.  https://github.com/HexHive/teezz-fuzzer
- Lindenmeier, Payer, Busch, “EL3XIR: Fuzzing COTS Secure Monitors,” USENIX Security 2024.  https://www.usenix.org/system/files/usenixsecurity24-lindenmeier.pdf

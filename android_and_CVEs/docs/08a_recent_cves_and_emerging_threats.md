# Recent Android CVEs and Emerging Threats (2023-2026)

## Table of Contents

1. [Overview](#1-overview)
2. [Critical CVEs from 2023](#2-critical-cves-from-2023)
3. [Critical CVEs from 2024](#3-critical-cves-from-2024)
4. [Critical CVEs from 2025-2026](#4-critical-cves-from-2025-2026)
5. [Actively Exploited Vulnerabilities (2023-2026)](#5-actively-exploited-vulnerabilities-2023-2026)
6. [ARM Mali GPU Vulnerabilities](#6-arm-mali-gpu-vulnerabilities)
7. [Qualcomm Recent CVEs](#7-qualcomm-recent-cves)
8. [Samsung Recent CVEs](#8-samsung-recent-cves)
9. [Android 14 and 15 Security Features](#9-android-14-and-15-security-features)
10. [Emerging Threat Categories](#10-emerging-threat-categories)
11. [Future of Android Security](#11-future-of-android-security)
12. [References](#12-references)

---

## 1. Overview

The Android threat landscape between 2023 and 2026 has been characterized by an escalation in sophistication of both vulnerabilities discovered and exploits deployed in the wild. Several key trends define this period:

- **GPU driver attacks** became a dominant exploitation vector, with ARM Mali and Qualcomm Adreno GPU kernel drivers being targeted by commercial spyware vendors and state-sponsored actors.
- **Zero-click exploit chains** grew in complexity, exemplified by Project Zero's demonstration of a full 0-click chain against the Pixel 9 using audio decoder and kernel driver vulnerabilities.
- **Memory safety vulnerabilities** continued their structural decline in AOSP code (from 76% to under 24% of all Android vulnerabilities) due to Google's Rust adoption strategy, but remained prevalent in vendor-specific components and third-party drivers.
- **Commercial spyware** operations (NSO Group, Intellexa, and newer vendors) continued to drive demand for Android zero-days, with CISA's Known Exploited Vulnerabilities catalog listing dozens of Android-related entries during this period.

---

## 2. Critical CVEs from 2023

The year 2023 saw a significant number of critical Android vulnerabilities, many of which were actively exploited before patches were available.

### 2.1 Android Framework and System CVEs

| CVE ID | Component | Severity | Type | Description |
|--------|-----------|----------|------|-------------|
| CVE-2023-21036 | Markup (aCropalypse) | High | Information Disclosure | The Pixel Markup screenshot editing tool failed to truncate PNG files when cropped, leaking original image content. Affected all Pixel screenshots ever edited with Markup. |
| CVE-2023-21273 | System (Bluetooth) | Critical | RCE | Remote code execution via Bluetooth without user interaction. Affected Android 11-13. |
| CVE-2023-21282 | Media Framework | Critical | RCE | Remote code execution when processing specially crafted media files. |
| CVE-2023-21246 | Framework | High | EoP | Elevation of privilege in the activity manager allowing bypass of background activity launch restrictions. |
| CVE-2023-21281 | System | Critical | RCE | Bluetooth vulnerability allowing remote code execution without additional privileges. |
| CVE-2023-35674 | Framework | High | EoP | Elevation of privilege in the Android Framework, confirmed exploited in the wild. |
| CVE-2023-35679 | System | Critical | RCE | Remote code execution in System component with no additional execution privileges needed. |

### 2.2 Kernel and Driver CVEs

| CVE ID | Component | Severity | Type | Description |
|--------|-----------|----------|------|-------------|
| CVE-2023-0266 | Linux Kernel (ALSA) | High | EoP | Use-after-free in the ALSA PCM subsystem's sound timer, exploited by commercial spyware vendors. |
| CVE-2023-26083 | Arm Mali GPU | Medium | Info Leak | Memory leak in the Mali GPU driver allowing kernel memory disclosure, a prerequisite for further exploitation. |
| CVE-2023-4211 | Arm Mali GPU | High | UAF | Use-after-free in Mali GPU driver's improper GPU memory processing operations. Confirmed exploited in the wild. |
| CVE-2023-33200 | Arm Mali GPU | High | UAF | Use-after-free in the Mali GPU kernel driver when processing GPU operations. |
| CVE-2023-33106 | Qualcomm Adreno GPU | High | Memory Corruption | Memory corruption in Graphics component when processing user requests to submit commands. |
| CVE-2023-33107 | Qualcomm Adreno GPU | High | Integer Overflow | Integer overflow leading to memory corruption in Adreno GPU driver. |
| CVE-2023-48409 | Pixel Mali customization | High | Integer Overflow | Integer overflow in Pixel's custom `gpu_pixel_handle_buffer_liveness_update_ioctl` function. |
| CVE-2023-48421 | Pixel Mali customization | High | Integer Overflow | Second integer overflow in Pixel's custom Mali driver code. |

---

## 3. Critical CVEs from 2024

The year 2024 continued the pattern of critical vulnerabilities in core Android components, third-party drivers, and vendor-specific code.

### 3.1 Android Framework and System CVEs

| CVE ID | Component | Severity | Type | Description |
|--------|-----------|----------|------|-------------|
| CVE-2024-0031 | System (Bluetooth) | Critical | RCE | Remote code execution in Bluetooth subsystem. Affected Android 11-14. |
| CVE-2024-0014 | System | Critical | EoP | Elevation of privilege in the System component requiring no additional execution privileges. |
| CVE-2024-23717 | Framework | High | EoP | Elevation of privilege enabling bypass of permission-based restrictions. |
| CVE-2024-29748 | Pixel Firmware | High | EoP | Vulnerability in Pixel device firmware exploited to prevent forensic wiping of seized devices. |
| CVE-2024-29745 | Pixel Bootloader | High | Info Leak | Information disclosure in Pixel bootloader, exploited in the wild by forensic companies. |
| CVE-2024-32896 | Pixel Firmware | High | EoP | Elevation of privilege in Pixel firmware; confirmed actively exploited. Google later patched this across wider Android in September 2024. |
| CVE-2024-36971 | Linux Kernel | High | EoP | Use-after-free in Linux kernel's network route management. Actively exploited in targeted attacks. |

### 3.2 Third-Party Component CVEs

| CVE ID | Component | Severity | Type | Description |
|--------|-----------|----------|------|-------------|
| CVE-2024-43047 | Qualcomm DSP (FASTRPC) | High | UAF | Use-after-free in Qualcomm's DSP service FASTRPC driver. Reported by Google Project Zero and Amnesty International. Confirmed exploited in spyware attacks. |
| CVE-2024-33066 | Qualcomm WLAN | Critical (9.8) | Memory Corruption | Improper input validation in WLAN Resource Manager leading to memory corruption. |
| CVE-2024-0153 | Arm Mali GPU Firmware | High | Buffer Overflow | Out-of-bounds write during GPU firmware instruction handling, discovered during Google-Arm collaborative research. |
| CVE-2024-23704 | MediaTek | High | EoP | Elevation of privilege in MediaTek chipset components. |

---

## 4. Critical CVEs from 2025-2026

The period from 2025 into early 2026 saw continued escalation in the severity and sophistication of Android-related vulnerabilities.

### 4.1 The Pixel 9 Zero-Click Chain (January 2026)

Google Project Zero disclosed a full 0-click exploit chain targeting the Pixel 9, demonstrating the evolving risk from AI-powered mobile features:

| CVE ID | Component | Severity | Type | Description |
|--------|-----------|----------|------|-------------|
| CVE-2025-54957 | Dolby Unified Decoder | Critical | Memory Corruption | Vulnerability in the Dolby audio decoder, reachable zero-click through Google Messages audio transcription. Affects most Android devices. Discovered by Project Zero's Natalie Silvanovich and Ivan Fratric. |
| CVE-2025-36934 | Pixel BigWave driver | High | UAF/EoP | Vulnerability in the `/dev/bigwave` AV1 hardware accelerator driver, accessible from the sandboxed `mediacodec` SELinux context. Enables kernel arbitrary read/write and full sandbox escape. |
| CVE-2025-49415 | Samsung Monkey's Audio | High | Memory Corruption | Vulnerability in Samsung's Monkey's Audio codec decoder, reachable zero-click through audio transcription features. |

### 4.2 Samsung DNG Exploit Chain (2024-2025)

Between July 2024 and February 2025, an in-the-wild exploit chain targeting Samsung devices was discovered through suspicious DNG image files uploaded to VirusTotal:

- The exploit targeted the **Quram library**, a Samsung-specific image parsing library.
- It was used to deploy commercial-grade spyware ("Landfall") as documented by Palo Alto Unit 42.
- The vulnerability was fixed in Samsung's April 2025 security update.
- Google Threat Intelligence Group provided the technical analysis, noting this as a rare publicly documented "one-shot" image-based exploit on Android.

### 4.3 Linux Kernel and Driver CVEs

| CVE ID | Component | Severity | Type | Description |
|--------|-----------|----------|------|-------------|
| CVE-2025-38236 | Linux Kernel (UNIX sockets) | High | UAF | Use-after-free in `MSG_OOB` handling for stream-oriented UNIX domain sockets (Linux >= 6.9). Discovered by Project Zero's Jann Horn. Was reachable from the Chrome renderer sandbox. |
| CVE-2025-31235 | macOS/iOS CoreAudio | High | Double-Free | Double-free in `coreaudiod`, also relevant for cross-platform audio attack surface research. |
| CVE-2026-3909 | Google Skia | High | OOB Write | Out-of-bounds write in Skia graphics library affecting Chrome, ChromeOS, Android, and Flutter. Added to CISA KEV catalog March 2026. |

### 4.4 Other Notable 2025-2026 CVEs

| CVE ID | Component | Severity | Type | Description |
|--------|-----------|----------|------|-------------|
| CVE-2025-27363 | FreeType | High | OOB Write | Out-of-bounds write in FreeType font rendering library. Affects Android and many other platforms. Added to CISA KEV. |
| CVE-2026-3910 | Chromium V8 | Critical | Memory Corruption | Improper restriction of operations within memory buffer bounds in V8 JavaScript engine. Affects Chrome on Android. CISA KEV March 2026. |
| CVE-2026-5281 | Google Dawn (WebGPU) | High | UAF | Use-after-free in Dawn/WebGPU allowing code execution from compromised renderer. CISA KEV April 2026. |

---

## 5. Actively Exploited Vulnerabilities (2023-2026)

The following table consolidates Android-ecosystem CVEs that were confirmed as **exploited in the wild** during 2023-2026, based on Google's security bulletins, CISA's Known Exploited Vulnerabilities catalog, and Google TAG/Amnesty International reports.

| CVE ID | Year | Component | Attributed Exploitation |
|--------|------|-----------|------------------------|
| CVE-2023-0266 | 2023 | Linux Kernel ALSA | Commercial spyware (linked to Samsung device exploitation chain) |
| CVE-2023-26083 | 2023 | Arm Mali GPU | Used as an info-leak primitive in multi-stage exploit chains |
| CVE-2023-4211 | 2023 | Arm Mali GPU | Confirmed targeted exploitation; Google TAG attribution |
| CVE-2023-33106 | 2023 | Qualcomm Adreno GPU | Limited, targeted exploitation per Qualcomm advisory |
| CVE-2023-33107 | 2023 | Qualcomm Adreno GPU | Limited, targeted exploitation per Qualcomm advisory |
| CVE-2023-33063 | 2023 | Qualcomm DSP | Limited, targeted exploitation per Qualcomm advisory |
| CVE-2023-35674 | 2023 | Android Framework | Confirmed exploited in the wild per Google bulletin |
| CVE-2024-29745 | 2024 | Pixel Bootloader | Exploited by forensic companies to extract device data |
| CVE-2024-29748 | 2024 | Pixel Firmware | Exploited to prevent device remote wiping during seizure |
| CVE-2024-32896 | 2024 | Pixel/Android Firmware | Actively exploited; originally Pixel-only, later broadened |
| CVE-2024-36971 | 2024 | Linux Kernel | Targeted exploitation in network route management UAF |
| CVE-2024-43047 | 2024 | Qualcomm DSP (FASTRPC) | Spyware targeting high-risk individuals (journalists, dissidents); reported by Google TAG and Amnesty International |
| CVE-2025-49415 | 2025 | Samsung Audio Codec | Zero-click spyware deployment targeting Samsung devices |
| CVE-2025-54957 | 2025 | Dolby Unified Decoder | Demonstrated by Project Zero as part of full 0-click chain |
| CVE-2026-3909 | 2026 | Google Skia | CISA KEV, affects Android via Chrome and system rendering |

### Key Observations on In-the-Wild Exploitation

1. **Commercial spyware dominance**: The majority of confirmed in-the-wild Android exploits during this period are attributed to commercial spyware vendors. Google TAG and Amnesty International's Security Lab have been the primary disclosers.
2. **GPU drivers as preferred targets**: GPU kernel drivers (both Arm Mali and Qualcomm Adreno) have become the most targeted component class for privilege escalation, replacing older attack surfaces like Binder or media frameworks.
3. **Zero-click via AI features**: The introduction of automatic audio transcription and image analysis features in messaging apps has expanded the zero-click attack surface, enabling exploitation without any user interaction.
4. **Forensic exploitation**: A distinct category of exploitation emerged targeting Pixel bootloader and firmware (CVE-2024-29745, CVE-2024-29748), used by law enforcement forensic tools rather than traditional spyware.

---

## 6. ARM Mali GPU Vulnerabilities

ARM Mali GPUs are the most widely deployed mobile GPUs in the Android ecosystem. Their kernel-mode driver (`kbase`) has been a persistent source of high-severity vulnerabilities due to the in-process HAL model used on Android, which allows untrusted app code to directly interact with the GPU kernel driver.

### 6.1 Key Mali GPU CVEs (2023-2025)

| CVE ID | Severity | Type | Details | Status |
|--------|----------|------|---------|--------|
| CVE-2023-4211 | High | Use-After-Free | Improper GPU memory processing operations allowing local non-privileged users to access freed memory. Confirmed exploited in the wild. | Patched Oct 2023 |
| CVE-2023-33200 | High | Use-After-Free | Improper handling of GPU operations leading to UAF in kernel space. | Patched Jul 2023 |
| CVE-2023-26083 | Medium | Information Leak | Mali driver leaks kernel memory addresses, used as an information disclosure primitive in exploit chains. | Patched Apr 2023 |
| CVE-2023-4295 | High | OOB Write | Out-of-bounds write in the Mali kernel driver. | Patched Oct 2023 |
| CVE-2023-48409 | High | Integer Overflow | Pixel-specific Mali customization: integer overflow in `gpu_pixel_handle_buffer_liveness_update_ioctl`. | Patched Dec 2023 |
| CVE-2023-48421 | High | Integer Overflow | Second Pixel-specific integer overflow in custom Mali driver code. | Patched Dec 2023 |
| CVE-2024-0153 | High | Buffer Overflow | GPU firmware out-of-bounds write during instruction handling, enabling code execution within GPU firmware. | Patched Jul 2024 |

### 6.2 Google-Arm Collaborative Security Research

In September 2024, Google and Arm published a joint report on their collaborative GPU security engagement:

- The **Android Red Team** worked directly with Arm's embedded product security experts to test the Mali `kbase` kernel driver.
- **Cloud-based fuzzing** using custom syzkaller configurations was deployed alongside on-device Pixel fuzzing to maximize coverage.
- **Firmware verification** combined fuzzing, formal verification, and manual analysis of the Mali GPU firmware, leading to the discovery of CVE-2024-0153.
- The engagement resulted in **nine new Security Test Suite (STS)** tests to help OEMs automatically verify they have applied Mali security patches.
- Google emphasized that "application -> kernel -> firmware -> kernel" is a known attack flow, where attackers use GPU firmware as a stepping stone from app context to kernel compromise.

### 6.3 Structural Challenges

The fundamental challenge with GPU driver security stems from the **in-process HAL model**: GPU user-space drivers execute within the app's process context, meaning any app can directly interact with the GPU kernel module's ioctl interface. This design prioritizes performance but creates a wide kernel attack surface accessible to all applications. Combined with the fact that GPU kernel modules are written in C (memory-unsafe), these drivers remain a high-value target.

---

## 7. Qualcomm Recent CVEs

Qualcomm's Snapdragon SoCs power a significant portion of Android devices. The DSP (Hexagon), WLAN, and GPU (Adreno) subsystems have been recurring sources of critical vulnerabilities.

### 7.1 Notable Qualcomm CVEs (2023-2025)

| CVE ID | Component | Severity | Type | Description |
|--------|-----------|----------|------|-------------|
| CVE-2023-33106 | Adreno GPU | High | Memory Corruption | Memory corruption when submitting GPU commands. Exploited in the wild. |
| CVE-2023-33107 | Adreno GPU | High | Integer Overflow | Integer overflow in GPU driver leading to memory corruption. Exploited in the wild. |
| CVE-2023-33063 | DSP Services | High | UAF | Use-after-free in DSP services. Exploited in the wild. |
| CVE-2024-43047 | DSP (FASTRPC) | High | UAF | Use-after-free in FASTRPC driver. Reported by Google Project Zero (Seth Jenkins), Conghui Wang, and Amnesty International. Confirmed exploited in spyware attacks targeting journalists and activists. |
| CVE-2024-33066 | WLAN Resource Manager | Critical (9.8) | Memory Corruption | Improper input validation in WLAN subsystem. Reported over a year before patching. |
| CVE-2024-21462 | Audio DSP | High | Buffer Overflow | Stack-based buffer overflow in audio DSP processing. |

### 7.2 The CVE-2024-43047 Case Study

This vulnerability deserves special attention as a representative example of the modern Android exploitation landscape:

- **Root Cause**: The DSP driver's FASTRPC interface exposed header buffers to the unsigned protection domain (user space). Users could inject invalid file descriptors that matched in-use FDs, triggering a use-after-free when the `put_args` cleanup path freed maps associated with those FDs.
- **Discovery**: Reported collaboratively by Google Project Zero's Seth Jenkins, researcher Conghui Wang, and Amnesty International Security Lab.
- **Exploitation**: Google TAG confirmed "limited, targeted exploitation," the standard language for commercial spyware campaigns targeting high-risk individuals.
- **Impact**: Affected **64+ Qualcomm chipsets** including Snapdragon 8 Gen 1/2/3, Snapdragon 888, and numerous older platforms.
- **Response**: Qualcomm released patches in October 2024, with a "strong recommendation" to OEMs for immediate deployment. However, as is typical in the Android ecosystem, patch deployment to end users was delayed across many OEMs.

---

## 8. Samsung Recent CVEs

As the largest Android device manufacturer, Samsung maintains both Knox security platform customizations and device-specific components that introduce unique attack surface.

### 8.1 Notable Samsung-Specific CVEs

| CVE ID | Component | Severity | Type | Description |
|--------|-----------|----------|------|-------------|
| CVE-2023-21492 | Samsung Kernel | High | Info Leak | Kernel pointer exposure in log files. Exploited by spyware vendors. CISA KEV listed. |
| CVE-2023-21433 | Galaxy Store | High | Improper Access Control | Galaxy Store app allowed local attackers to install arbitrary applications. |
| CVE-2023-21434 | Galaxy Store | High | Improper Input Validation | URL validation flaw in Galaxy Store enabling JavaScript execution. |
| CVE-2024-20803 | Samsung Contacts | High | OOB Write | Out-of-bounds write in Samsung Contacts app allowing code execution. |
| CVE-2024-20861 | Samsung SveService | High | UAF | Use-after-free in Samsung's SveService (Samsung Video Enhancement). |
| CVE-2025-49415 | Monkey's Audio Codec | High | Memory Corruption | Zero-click vulnerability in Samsung's Monkey's Audio codec, reachable through message audio transcription. |

### 8.2 The Quram Library / DNG Image Exploit (2024-2025)

One of the most significant Samsung-specific exploitation campaigns uncovered during this period involved DNG (Digital Negative) image files:

- **Discovery**: Six suspicious DNG image files were uploaded to VirusTotal between July 2024 and February 2025. Google Threat Intelligence Group investigated based on a lead from Meta.
- **Target**: The exploit targeted Samsung's **Quram library**, a proprietary image parsing library not present on other Android devices.
- **Exploitation**: The images exploited parsing vulnerabilities to achieve code execution on Samsung devices, deploying the "Landfall" commercial-grade spyware as documented by Palo Alto's Unit 42.
- **Significance**: This was one of the first publicly documented "one-shot" image-based exploit chains on Android, analogous to Apple's FORCEDENTRY exploit.
- **Fix**: Samsung patched the vulnerability in the April 2025 security update.

---

## 9. Android 14 and 15 Security Features

### 9.1 Android 14 Security Enhancements

Android 14 (released October 2023) introduced several security improvements:

| Feature | Description | Vulnerability Class Addressed |
|---------|-------------|-------------------------------|
| **Credential Manager** | Unified API for passkeys, passwords, and federated sign-in. Reduces phishing risk by supporting FIDO2 passkeys natively. | Credential theft, phishing |
| **Partial photo/video access** | Users can grant access to specific media items instead of entire libraries. | Privacy, over-permissioning |
| **Block installation of outdated apps** | Apps targeting very old SDK versions (< Android 6.0) cannot be installed, preventing abuse of pre-runtime-permission models. | Permission bypass |
| **Background activity restrictions** | Stronger restrictions on background app launches, closing privilege escalation vectors. | EoP via background activities |
| **Minimum targetSdkVersion 23** | All sideloaded apps must target at least API 23. | Abuse of legacy permission model |
| **READ_MEDIA_VISUAL_USER_SELECTED** | New permission for granular media access. | Privacy over-collection |
| **Improved IntentFilter handling** | Tightened restrictions on implicit intents to reduce intent hijacking. | Intent redirection attacks |

### 9.2 Android 15 Security Enhancements

Android 15 (released 2024) further hardened the platform:

| Feature | Description | Vulnerability Class Addressed |
|---------|-------------|-------------------------------|
| **Private Space** | Encrypted, separately authenticated container for sensitive apps, hidden from the main profile. | Physical access attacks |
| **Theft Detection Lock** | AI-powered detection of device theft (sudden motion patterns) triggering automatic lock. | Physical device theft |
| **Improved ADB protections** | USB debugging requires additional authentication when connecting to new hosts. | ADB-based local attacks |
| **Enhanced file integrity** | Stronger fs-verity usage for APK and system file verification. | Supply chain, code tampering |
| **Locked screen notification protection** | Sensitive notification content hidden on lock screen by default. | Shoulder surfing, info disclosure |
| **One-time permission improvements** | More granular one-time permissions for camera, microphone, and location. | Over-permissioning |
| **16KB page size support** | Kernel memory page size increase improving ASLR entropy and reducing heap metadata exploitation viability. | Memory corruption exploitation |
| **Hardware-backed attestation improvements** | Stronger key attestation for device integrity verification. | Device spoofing |

---

## 10. Emerging Threat Categories

### 10.1 AI-Powered Attacks on Android

The integration of AI features into mobile platforms has created both new attack surfaces and new attack methodologies:

- **Expanded zero-click surface through AI processing**: As demonstrated by the Pixel 9 zero-click chain, features like automatic audio transcription in Google Messages now decode incoming media *before* the user interacts with it. This means audio decoders (Dolby, Monkey's Audio, etc.) and image processors are now in the zero-click attack surface of billions of devices.
- **Adversarial ML attacks**: On-device ML models used for spam detection, image classification, and text prediction can be manipulated through adversarial inputs designed to bypass or corrupt model behavior.
- **AI-assisted vulnerability discovery**: Google Project Zero and other researchers have demonstrated that LLMs and AI-guided fuzzing can accelerate vulnerability discovery. Google's "Project Naptime" explored using AI to find vulnerabilities, potentially lowering the bar for offensive researchers as well.
- **Deepfake threats on Android**: Deepfake generation apps and real-time face/voice synthesis tools running on-device create risks for biometric authentication bypass, social engineering, and disinformation. Android's face unlock mechanisms may need to be hardened against synthesized video inputs.

### 10.2 5G-Related Attack Surfaces

The rollout of 5G introduces new attack vectors relevant to Android devices:

- **Baseband vulnerabilities**: 5G NR (New Radio) baseband processors handle complex protocol stacks. Vulnerabilities in Samsung Shannon, Qualcomm, and MediaTek basebands can be triggered over-the-air. Project Zero's research on Samsung's Shannon baseband has previously demonstrated remote code execution.
- **Network slicing attacks**: 5G network slicing, while designed for isolation, may introduce side-channel information leaks or cross-slice attacks if improperly implemented.
- **NPN (Non-Public Network) risks**: Enterprise 5G deployments may expose Android devices to rogue base station attacks at shorter ranges than traditional cell towers.
- **IMS/VoNR attack surface**: Voice-over-New-Radio and IP Multimedia Subsystem protocol handling in Android's telephony stack presents parsing complexity vulnerable to memory corruption.

### 10.3 Supply Chain and SDK Threats

- **Malicious SDKs**: Threat actors have increasingly embedded malicious functionality within popular advertising and analytics SDKs distributed through legitimate package repositories.
- **Pre-installed malware**: Devices from certain lower-cost manufacturers continue to ship with pre-installed applications containing backdoors or aggressive data exfiltration capabilities.
- **Build pipeline compromise**: Attacks targeting CI/CD infrastructure (as seen with the tj-actions and reviewdog GitHub Actions compromises in early 2025) pose risks to the Android app supply chain.

---

## 11. Future of Android Security

### 11.1 Memory Safety Roadmap and Rust Adoption

Google's data demonstrates a dramatic shift in Android's vulnerability composition:

| Year | Memory Safety Vulns (% of total) | Absolute Count (approx.) |
|------|----------------------------------|--------------------------|
| 2019 | 76% | 223 |
| 2020 | 70% | 194 |
| 2021 | 55% | 150 |
| 2022 | 40% | 107 |
| 2023 | 32% | ~85 |
| 2024 | 24% | ~36 (projected) |

The key insight from Google's research is that **vulnerabilities decay exponentially** -- they have a half-life. The vast majority of vulnerabilities reside in new or recently modified code. By focusing Rust adoption on *new* code while leaving existing C/C++ code to mature naturally (with targeted bug fixes), the overall vulnerability count drops exponentially without requiring rewrites.

**Current Rust adoption status in Android:**
- New AOSP code is increasingly written in Rust, with Rust's share of new commits growing steadily since 2019.
- Rust code in Android has a **rollback rate less than half** that of C++ code, indicating higher correctness.
- Google has invested $1,000,000 in the Rust Foundation and developed interoperability tools (Crubit, autocxx) for Rust-C++ integration.
- The interoperability-first approach means Rust components can be incrementally introduced without rewriting entire subsystems.

### 11.2 Kernel Hardening

Upcoming and ongoing kernel hardening efforts include:

- **16KB page size**: Android 15's support for 16KB kernel pages significantly increases ASLR entropy and makes heap exploitation more difficult by widening the gap between allocations.
- **CFI (Control-Flow Integrity)**: Clang CFI has been enabled for the Android kernel, preventing control-flow hijacking attacks that redirect function pointers.
- **kCFI (kernel CFI)**: A more hardware-efficient variant being deployed on ARMv8.5+ devices with BTI (Branch Target Identification) and PAC (Pointer Authentication Code) support.
- **Memory Tagging Extension (MTE)**: ARM's MTE provides hardware-assisted detection of use-after-free and buffer overflow bugs. Pixel 8+ devices support MTE, and Google has been progressively enabling it for more components.
- **GKI (Generic Kernel Image)**: The push toward a unified Generic Kernel Image reduces OEM kernel fragmentation, enabling faster security patch deployment and consistent hardening across devices.
- **KASLR improvements**: Project Zero research in late 2025 demonstrated that the Linux kernel's linear mapping placement could be inferred without any exploit primitive, motivating stronger KASLR implementations.

### 11.3 Broader Ecosystem Changes

- **Improved patching cadence**: Google's Security Test Suite (STS) helps OEMs verify patch completeness. The collaborative model with Arm (adding nine new STS tests for Mali GPU) is being extended to other vendors.
- **Sandboxing evolution**: The Pixel 9 zero-click chain highlighted that the `mediacodec` sandbox was insufficient because it allowed access to hardware drivers like BigWave. Google is working to restrict driver access from sandboxed contexts.
- **Chrome renderer sandbox tightening**: The discovery that `MSG_OOB` UNIX socket messages were available from Chrome renderers (CVE-2025-38236) led to blocking this feature in the renderer sandbox, exemplifying the ongoing effort to minimize accessible kernel surface.
- **Secure-by-design principles**: Google's approach aligns with CISA's "Secure by Design" initiative, moving from reactive patching and exploit mitigations toward structural elimination of vulnerability classes through safe languages and API design.

---

## 12. References

1. Google Security Blog, "Eliminating Memory Safety Vulnerabilities at the Source," September 2024.
2. Google Security Blog, "Google & Arm - Raising The Bar on GPU Security," September 2024.
3. Google Project Zero, "A 0-click exploit chain for the Pixel 9 (Parts 1-3)," January 2026.
4. Google Project Zero, "A look at an Android ITW DNG exploit," December 2025.
5. Google Project Zero, "Defeating KASLR by Doing Nothing at All," November 2025.
6. Google Project Zero, "From Chrome renderer code exec to kernel with MSG_OOB," August 2025.
7. CISA Known Exploited Vulnerabilities Catalog, accessed April 2026.
8. Qualcomm Security Bulletin, October 2024 (CVE-2024-43047).
9. BleepingComputer, "Qualcomm patches high-severity zero-day exploited in attacks," October 2024.
10. Palo Alto Unit 42, "Landfall: New Commercial-Grade Android Spyware," November 2025.
11. Android Security Bulletins 2023-2026, source.android.com.
12. Alexopoulos et al., "How Long Do Vulnerabilities Live in the Code?" USENIX Security 2022.

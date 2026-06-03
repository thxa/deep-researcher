# Android Architecture, Vulnerabilities, and CVEs

A comprehensive security research track covering Android's layered architecture, kernel and application vulnerability landscape, exploitation techniques, major historical CVEs, defense mechanisms, and the evolving threat landscape from 2015–2026. This corpus examines over 5,500 CVEs, real-world spyware campaigns, and Android's defense-in-depth strategy.

> **Difficulty:** 🟡 Intermediate | **Prerequisites:** Android basics, Linux kernel concepts, C/Java | **Estimated reading time:** ~8 hours (~71,000 words)

## Reading Order

| # | File | Topic |
|---|------|-------|
| 1 | [`01a_android_architecture_technical.md`](docs/01a_android_architecture_technical.md) | Detailed Android system architecture: kernel, HAL, Binder IPC, runtime layers |
| 2 | [`01b_android_architecture_security_perspective.md`](docs/01b_android_architecture_security_perspective.md) | Attack surface mapping by architectural layer and trust boundaries |
| 3 | [`02a_android_security_model.md`](docs/02a_android_security_model.md) | Security mechanisms: UID sandboxing, permissions, SELinux, verified boot, FBE |
| 4 | [`02b_android_defense_mechanisms.md`](docs/02b_android_defense_mechanisms.md) | Compiler mitigations (CFI, SCS, IntSan, MTE), kernel hardening, Rust adoption |
| 5 | [`03a_kernel_vulnerabilities.md`](docs/03a_kernel_vulnerabilities.md) | GPU driver, Binder, and vendor-specific kernel CVEs with CVSS scores |
| 6 | [`03b_kernel_exploitation_techniques.md`](docs/03b_kernel_exploitation_techniques.md) | Heap exploitation primitives, KASLR bypass, SELinux bypass, pipe buffer attacks |
| 7 | [`04a_application_vulnerabilities.md`](docs/04a_application_vulnerabilities.md) | Intent hijacking, WebView RCE, Content Provider injection, serialization bugs |
| 8 | [`04b_framework_vulnerabilities.md`](docs/04b_framework_vulnerabilities.md) | System server, Bluetooth, WiFi, NFC, telephony, and lock screen CVEs |
| 9 | [`05a_major_historical_cves.md`](docs/05a_major_historical_cves.md) | Deep-dives: Stagefright, Dirty COW, Bad Binder, Dirty Pipe, Janus, Broadpwn |
| 10 | [`05b_cve_statistics_and_trends.md`](docs/05b_cve_statistics_and_trends.md) | CVE volume trends, severity distribution, component breakdown, bug bounty economics |
| 11 | [`06a_exploitation_techniques.md`](docs/06a_exploitation_techniques.md) | Remote vectors (MMS, browser, WiFi/BT), rooting, physical attacks, side-channels |
| 12 | [`06b_real_world_exploitation.md`](docs/06b_real_world_exploitation.md) | Pegasus, Predator, Candiru, QuaDream campaigns, banking trojans, forensics |
| 13 | [`07a_patch_management.md`](docs/07a_patch_management.md) | Security bulletin pipeline, Treble, Mainline, GKI, OEM update tiers |
| 14 | [`07b_security_best_practices.md`](docs/07b_security_best_practices.md) | Hardening guidance: users, developers, enterprise; CIS/NIST frameworks |
| 15 | [`08a_recent_cves_and_emerging_threats.md`](docs/08a_recent_cves_and_emerging_threats.md) | 2023–2026 CVEs, Pixel 9 zero-click chain, Android 14/15 security features |
| 16 | [`08b_threat_landscape_and_future.md`](docs/08b_threat_landscape_and_future.md) | Threat actors, zero-day market pricing, AI-powered attacks, automotive Android |
| 17 | [`FINAL_REPORT_Android_Architecture_Vulnerabilities_and_CVEs.md`](FINAL_REPORT_Android_Architecture_Vulnerabilities_and_CVEs.md) | Synthesized summary of all 16 research documents |

## Related Tracks

- [Linux Kernel](../linux_kernel/) — Kernel internals and exploitation primitives
- [CVE-2023-20938 — Binder UAF](../CVE-2023-20938/) — Deep-dive into the Binder use-after-free
- [Zero-Day Exploit Development](../zero_day/) — Zero-day research methodology
- [Ring & Vulnerabilities](../ring_and_vulns/) — Ring-based privilege escalation and vulnerability classes

## Quick Reference

See [`CHEATSHEET.md`](CHEATSHEET.md) for ADB commands, key CVEs, mitigation configs, and attack surface checklists.

## References

1. Android Security Overview — https://source.android.com/security
2. Android Security Bulletins — https://source.android.com/security/bulletin
3. Android Security & Privacy 2024 Year in Review — https://security.googleblog.com/2025/02/android-security-privacy-2024-year-in.html
4. Google Project Zero Blog — https://googleprojectzero.blogspot.com/
5. CISA Known Exploited Vulnerabilities Catalog — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
6. NVD (National Vulnerability Database) — https://nvd.nist.gov/
7. Android Generic Kernel Image (GKI) — https://source.android.com/docs/core/architecture/kernel/generic-kernel-image
8. Android Security Rewards Program — https://bughunters.google.com/
9. Kaspersky Securelist: Mobile Threat Reports — https://securelist.com/
10. Citizen Lab, University of Toronto — https://citizenlab.ca/

---

## Recent Developments (2025–2026)

*Independently verified against primary sources (NVD / vendor advisories / papers) during the 2026-06 accuracy audit. Each CVE was confirmed to exist with the stated characterization.*

### Vulnerabilities (CVEs)

- **CVE-2025-48595 — Actively exploited Android Framework integer-overflow zero-day (June 2026)** *(2026-06)* — Google's June 2026 Android Security Bulletin patched 124 flaws including CVE-2025-48595, a high-severity (CVSS 8.4, CWE-190) integer overflow in the Android Framework enabling local privilege escalation with no user interaction on Android 14, 15, 16, and 16 QPR2. Google flagged it as under limited, targeted exploitation, and CISA added it to the Known Exploited Vulnerabilities catalog on June 2, 2026 with a June 5 federal remediation deadline. It is the fourth Android zero-day patched since December 2025, and is not yet documented in the track. [[source]](https://www.helpnetsecurity.com/2026/06/02/android-vulnerability-exploited-cve-2025-48595/)
- **CVE-2025-21479 / CVE-2025-21480 / CVE-2025-27038 — Qualcomm Adreno GPU zero-days exploited in the wild** *(2025-06)* — Qualcomm's June 2025 bulletin patched three Adreno GPU driver flaws reported by Google's Android Security team and TAG: CVE-2025-21479 and CVE-2025-21480 (both CVSS 8.6, incorrect-authorization issues causing GPU-microcode memory corruption) and CVE-2025-27038 (CVSS 7.5, use-after-free during Adreno rendering in Chrome). Google TAG indicated the trio was under limited, targeted exploitation, and CISA added all three to the KEV catalog on June 3, 2025. These specific Adreno 2025 CVEs are absent from the track, which only documents 2023-2024 Qualcomm GPU/DSP cases. [[source]](https://thehackernews.com/2025/06/qualcomm-fixes-3-zero-days-used-in.html)
- **December 2025 Android Security Bulletin — two actively exploited Framework zero-days** *(2025-12)* — Google's December 2025 update addressed 107 vulnerabilities including two Android Framework flaws under limited, targeted exploitation: CVE-2025-48633 (high-severity information disclosure) and CVE-2025-48572 (high-severity elevation of privilege), both affecting Android 13 through 16. These were patched in the 2025-12-01 and 2025-12-05 patch levels and are not currently captured in the track's recent-CVE coverage. [[source]](https://www.bleepingcomputer.com/news/security/google-fixes-two-android-zero-days-exploited-in-attacks-107-flaws/)

### Incidents & In-the-Wild Exploitation

- **LANDFALL spyware — CVE-2025-21042 zero-click DNG image exploit against Samsung Galaxy** *(2025-11)* — Palo Alto Unit 42 documented LANDFALL, commercial-grade Android spyware delivered through malformed DNG image files (filenames suggesting WhatsApp delivery) that exploited CVE-2025-21042, a zero-day in Samsung's libimagecodec.quram.so image-processing library, before Samsung's April 2025 patch. The campaign ran from July 2024 through early 2025, targeting Galaxy S22/S23/S24 and Z Fold4/Flip4 users in Iraq, Iran, Turkey, and Morocco, with capabilities including mic recording, location tracking, and SELinux policy manipulation for persistence. CISA added CVE-2025-21042 to its KEV catalog in November 2025; the track references the older Quram/Landfall thread but not this CVE ID or the November 2025 disclosure. [[source]](https://unit42.paloaltonetworks.com/landfall-is-new-commercial-grade-android-spyware/)

### Techniques

- **CVE-2025-0072 — Arm Mali GPU use-after-free that bypasses Memory Tagging Extension (MTE)** *(2025-05)* — GitHub Security Lab researcher Man Yue Mo disclosed CVE-2025-0072 (CVSS 7.8, CWE-416), a use-after-free in Arm Mali GPU drivers using the Command Stream Frontend (CSF) architecture (Valhall and 5th-Gen GPU drivers), affecting Pixel 7/8/9. The exploit reuses a kbase_queue rebound after its group terminates to overwrite GPU page-table pointers, and because freed page frames are mapped directly into user space via insert_pfn, accessing them from user space avoids kernel dereferences and therefore does not trigger MTE — defeating a key Pixel 8+ hardware mitigation. Arm fixed it in driver r54p0 (May 2, 2025) and Android's May 2025 update. [[source]](https://github.blog/security/vulnerability-research/bypassing-mte-with-cve-2025-0072/)

### Standards & Frameworks

- **Android 16 Advanced Protection Mode — one-switch hardening for high-risk users** *(2025-06)* — With Android 16 (2025) Google shipped Advanced Protection, a single device-level toggle that bundles high-risk-user defenses: automatic Memory Tagging Extension (MTE) for supported apps on Armv9 hardware, blocking sideloaded app installs and out-of-store updates, 72-hour inactivity reboot, Theft Detection Lock, and a later USB protection feature restricting locked-device USB ports to charging only. The track documents Android 14 and 15 features but not this Android 16 capability; the EFF analysis assesses its scope and trade-offs. [[source]](https://www.eff.org/deeplinks/2025/06/googles-advanced-protection-arrives-android-should-you-use-it)

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
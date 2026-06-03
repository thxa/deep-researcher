# macOS / XNU Security Architecture & Exploitation

A deep technical exploration of macOS security internals — from the XNU hybrid kernel (Mach, BSD, IOKit) through hardware-enforced mitigations on Apple Silicon — covering vulnerability classes, real-world exploit chains (FORCEDENTRY, Operation Triangulation), post-exploitation persistence, the macOS malware landscape, and the evolution of Apple's defense-in-depth model.

**Difficulty:** 🟡 Intermediate to Advanced  
**Estimated reading time:** ~4 hours  
**Prerequisites:** macOS fundamentals, understanding of Unix permissions and processes, basic exploitation concepts (heap UAF, stack overflows, privilege escalation)

---

## Reading Order

| # | Document | Topic |
|---|----------|-------|
| 1 | [`docs/01a_system_architecture_xnu.md`](docs/01a_system_architecture_xnu.md) | XNU hybrid kernel: Mach IPC, BSD syscalls, IOKit driver framework, zone allocator, boot chain |
| 2 | [`docs/01b_system_architecture_userland.md`](docs/01b_system_architecture_userland.md) | Userland architecture: launchd, XPC services, dyld shared cache, APFS, framework stack |
| 3 | [`docs/02a_security_architecture_sip_gatekeeper_tcc.md`](docs/02a_security_architecture_sip_gatekeeper_tcc.md) | System Integrity Protection, Gatekeeper, XProtect, TCC consent framework, secure boot |
| 4 | [`docs/02b_security_architecture_entitlements_sandbox.md`](docs/02b_security_architecture_entitlements_sandbox.md) | Entitlements (public & private), App Sandbox (Seatbelt/SBPL), MACF policy hooks, code signing |
| 5 | [`docs/03a_kernel_vulnerabilities_xnu_iokit.md`](docs/03a_kernel_vulnerabilities_xnu_iokit.md) | XNU attack surface: Mach traps, BSD syscalls, IOKit external methods, MIG vulnerabilities |
| 6 | [`docs/03b_kernel_vulnerabilities_race_logic.md`](docs/03b_kernel_vulnerabilities_race_logic.md) | Race conditions, TOCTOU, integer overflows, logic bugs, and remote network attack surface |
| 7 | [`docs/04a_userland_vulnerabilities_privesc.md`](docs/04a_userland_vulnerabilities_privesc.md) | Local privilege escalation, sudo vulnerabilities, SIP bypasses, TCC circumvention |
| 8 | [`docs/04b_userland_vulnerabilities_apps.md`](docs/04b_userland_vulnerabilities_apps.md) | Application attack surface: WebKit/JIT, Electron, XPC validation flaws, Objective-C runtime |
| 9 | [`docs/05a_exploitation_memory_corruption.md`](docs/05a_exploitation_memory_corruption.md) | Heap feng shui, magazine malloc, kalloc zone exploitation, stack canaries, ROP on macOS |
| 10 | [`docs/05b_exploitation_chains_advanced.md`](docs/05b_exploitation_chains_advanced.md) | Real exploit chains (FORCEDENTRY, Operation Triangulation, Ian Beer AWDL), PAC/KTRR bypass |
| 11 | [`docs/06a_post_exploitation_persistence.md`](docs/06a_post_exploitation_persistence.md) | Persistence mechanisms: LaunchAgents/Daemons, dylib hijacking, cron, Folder Actions, EFI |
| 12 | [`docs/06b_post_exploitation_evasion_lateral.md`](docs/06b_post_exploitation_evasion_lateral.md) | Defense evasion, credential harvesting (Keychain, SSH), lateral movement (SSH, ARD, MDM) |
| 13 | [`docs/07a_malware_landscape_families.md`](docs/07a_malware_landscape_families.md) | Malware families: Lazarus/AppleJeus, OceanLotus, Shlayer, XCSSET, Atomic Stealer, ransomware |
| 14 | [`docs/07b_malware_detection_trends.md`](docs/07b_malware_detection_trends.md) | Detection (XProtect, EDR, ES framework), forensic artifacts, emerging trends (ARM64 native, MaaS) |
| 15 | [`docs/08a_mitigations_hardware.md`](docs/08a_mitigations_hardware.md) | Hardware mitigations: PAC, KTRR, PPL, SEP, DART, W^X, ARM64e, Intel vs Apple Silicon comparison |
| 16 | [`docs/08b_mitigations_software_evolution.md`](docs/08b_mitigations_software_evolution.md) | Software mitigations: ASLR/KASLR, stack canaries, kCFI, zone isolation, SSV, Lockdown Mode, RSR |

---

## Related Tracks

- **[Chromium Architecture & Vulnerability](../Chromium_Architecture_and_Vulnerability/)** — Browser security overlaps with macOS WebKit/JIT exploitation
- **[Linux Kernel](../linux_kernel/)** — Kernel architecture comparison (Monolithic vs. hybrid XNU)
- **[Ring & Vulnerabilities](../ring_and_vulns/)** — Privilege levels and ring protection overlap with macOS kernel/user boundary
- **[Zero-Day Exploit Development](../zero_day/)** — Advanced exploit development techniques applicable to macOS targets

---

## References

- Apple Platform Security Guide: https://support.apple.com/guide/security/
- XNU Source Code: https://opensource.apple.com/
- Jonathan Levin, *macOS and iOS Internals* (Volumes I–III)
- *The Art of Mac Malware* by Patrick Wardle (No Starch Press, 2022)
- Ian Beer / Project Zero iOS/macOS Research: https://googleprojectzero.blogspot.com/
- Kaspersky Operation Triangulation Report: https://securelist.com/operation-triangulation/109842/
- Citizen Lab FORCEDENTRY Report: https://citizenlab.ca/
- NVD (National Vulnerability Database): https://nvd.nist.gov/
- Objective-See Mac Security Tools: https://objective-see.org/
- Apple Security Releases: https://support.apple.com/en-us/HT201222

---

## Recent Developments (2025–2026)

*Independently verified against primary sources (NVD / vendor advisories / papers) during the 2026-06 accuracy audit. Each CVE was confirmed to exist with the stated characterization.*

### Vulnerabilities (CVEs)

- **CVE-2025-31199 "Sploitlight" — Spotlight importer TCC bypass leaking Apple Intelligence caches** *(2025-07)* — Microsoft Threat Intelligence (Jonathan Bar Or, Alexia Wilson, Christine Fossaceca) disclosed a Spotlight-plugin TCC bypass that reads files in protected directories (Downloads, Pictures) and extracts Apple Intelligence caches containing precise geolocation, photo/video metadata, and face-recognition data. Apple fixed it in the macOS Sequoia security updates released March 31, 2025. It is significant because it is the first publicly documented TCC bypass shown to exfiltrate Apple Intelligence on-device data. [[source]](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- **CVE-2025-43530 — ScreenReader.framework / com.apple.scrod TCC bypass via TOCTOU** *(2025)* — Researcher Mickey Jin found that the privileged com.apple.scrod MIG service (VoiceOver) could be abused to execute arbitrary AppleScript and send AppleEvents to any process (e.g., Finder), fully bypassing TCC to access files, the microphone, and Apple Events without prompts. The root causes are over-reliance on code-signing checks plus a TOCTOU file-swap during verification, exploitable locally without admin rights. Apple patched it in macOS Tahoe 26.2, Sonoma 14.8.3, and Sequoia 15.7.3 by requiring the com.apple.private.accessibility.scrod entitlement from the client audit token. [[source]](https://securityonline.info/new-tcc-bypass-cve-2025-43530-exposes-macos-to-unchecked-automation/)
- **CVE-2025-24118 — XNU kernel race condition (read-only/credential handling) enabling privesc** *(2025-01)* — MIT CSAIL researcher Joseph Ravichandran (@0xjprx) reported a race condition in the XNU kernel (involving per-thread credential / read-only memory handling) that can corrupt kernel memory and cause arbitrary kernel writes, leading to local privilege escalation. Apple described it as 'an app may be able to cause unexpected system termination or write kernel memory' and fixed it (published January 27, 2025) in macOS Sequoia 15.3 and Sonoma 14.7.3; a proof-of-concept was released publicly. [[source]](https://nvd.nist.gov/vuln/detail/CVE-2025-24118)
- **CVE-2025-31219 — XNU vm_map race condition (ZDI) for kernel-level privilege escalation** *(2025-05)* — Trend Micro ZDI researchers Michael DePlante (@izobashi) and Lucas Leong (@wmliang) disclosed a race condition in the XNU kernel's vm_map virtual-memory allocation subsystem (CVSS 8.8) that lets a local low-privileged attacker escalate to kernel-mode execution. It was disclosed May 21, 2025 and fixed in macOS Sequoia 15.5, Sonoma 14.7.6, and Ventura 13.7.6. This is a notable recent example of memory-management TOCTOU bugs still being a productive XNU kernel attack surface on Apple Silicon. [[source]](https://cybersecuritynews.com/apple-xnu-kernel-vulnerability-let-attackers-escalate-privileges/)

### Incidents & In-the-Wild Exploitation

- **Atomic macOS Stealer (AMOS) adds an embedded backdoor for persistence** *(2025-07)* — Moonlock Lab (MacPaw) reported in July 2025 that the widely distributed Atomic macOS Stealer added an embedded backdoor for the first time, transforming it from a one-shot infostealer into a persistent C2-controlled implant. The backdoor survives reboots, beacons to its C2 roughly every 60 seconds, and can run arbitrary remote tasks (with potential for keylogging), marking only the second large-scale macOS backdoor deployment after North Korean operations. [[source]](https://www.infostealers.com/article/atomic-macos-stealer-now-includes-a-backdoor-for-persistent-access/)
- **XCSSET evolves with crypto clipper, Firefox theft, and LaunchDaemon persistence** *(2025-09)* — Microsoft Security documented new 2025 variants of the Xcode-project-infecting malware XCSSET that add a clipboard 'clipper' module (regex-matching crypto wallet addresses and swapping them for attacker-controlled ones), expand data theft to Firefox, use run-only compiled AppleScripts for stealth, and add a LaunchDaemon persistence mechanism. This shows continued active development of one of the few macOS supply-chain-style threats targeting developers. [[source]](https://www.microsoft.com/en-us/security/blog/2025/09/25/xcsset-evolves-again-analyzing-the-latest-updates-to-xcssets-inventory/)
- **North Korea–linked UNC1069 campaign deploys seven new macOS malware families** *(2026-02)* — Google Mandiant attributed a 2025–2026 campaign to UNC1069 that delivered seven previously undocumented macOS malware families (WAVESHAPER, HYPERCALL, HIDDENCALL, SILENCELIFT, DEEPBREATH, SUGARLOADER, CHROMEPUSH) written in C++, Go, and Swift. DEEPBREATH specifically bypasses TCC protections, and delivery used AI-generated/deepfake video and the ClickFix technique (fake Zoom meetings, Telegram social engineering) to trigger AppleScript execution and steal keychain, browser, and Telegram data. [[source]](https://www.bleepingcomputer.com/news/security/north-korean-hackers-use-new-macos-malware-in-crypto-theft-attacks/)

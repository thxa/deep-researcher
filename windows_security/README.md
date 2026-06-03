# Windows Security & Internals

> **Difficulty:** 🔴 Advanced | **Estimated reading time:** ~14 hours | **Prerequisites:** Windows internals, x86/x64 assembly, kernel debugging, Active Directory, C/C++

## Overview

This track covers the complete Windows security landscape — from NT kernel internals and pool corruption exploitation through Active Directory domain compromise to modern exploit mitigations and their bypasses. It is designed for advanced security researchers, exploit developers, and enterprise defenders who need deep technical understanding of how Windows security mechanisms work, how they fail, and how to harden them.

**What this track covers:**

- **Windows NT kernel architecture**: Object manager, executive subsystems, pool allocator, system call dispatch, and the Win32k graphics subsystem
- **Pool corruption exploitation**: Paged/non-paged pool overflow, use-after-free, double-free, and cross-object corruption techniques
- **Privilege escalation**: Token manipulation, potato attacks (SeImpersonatePrivilege), BYOVD, service misconfigurations, UAC bypasses
- **Active Directory attacks**: Kerberoasting, AS-REP roasting, delegation abuse, DCSync, Golden/Silver/Diamond tickets, ACL abuse
- **Windows malware & EDR evasion**: Process injection techniques, direct syscalls, ETW patching, unhooking, living-off-the-land
- **Modern mitigations & bypasses**: VBS/HVCI, kernel CET, kCFI, CFG, ACG/CIG — and the data-only attack patterns that bypass them
- **Hardening**: WDAC, Credential Guard, Secure Boot, tiered administration, BloodHound-based attack path elimination

**Prerequisites (assumed knowledge):**
- x86/x64 assembly and C programming
- Windows internals (`_EPROCESS`, `_ETHREAD`, `_TOKEN`, `_OBJECT_HEADER`)
- Kernel debugging with WinDbg
- Active Directory and Kerberos fundamentals
- Basic exploitation concepts (buffer overflow, UAF, ROP)

---

## Reading Order

| # | Document | Topic | Est. Time | Difficulty |
|---|----------|-------|-----------|------------|
| — | [FINAL REPORT](WINDOWS_SECURITY_FINAL_REPORT.md) | Comprehensive synthesis of the entire track | 90 min | 🔴 Advanced |
| — | [CHEATSHEET](CHEATSHEET.md) | Quick reference: WinDbg, structures, PowerShell, Mimikatz, BloodHound, CVEs | — | Reference |
| 01 | Windows NT Architecture & Intellect | Kernel architecture, executive subsystems, system call dispatch, Win32k | 60 min | 🟡 Intermediate |
| 02 | Windows Security Subsystem | Authentication (NTLM/Kerberos), access tokens, integrity levels, UAC | 50 min | 🟡 Intermediate |
| 03 | Kernel Object Manager & Pool Internals | `_OBJECT_HEADER`, `_POOL_HEADER`, pool allocator, object spray | 60 min | 🔴 Advanced |
| 04 | Pool Corruption Exploitation | Pool overflow, UAF, double-free, cross-object corruption, data-only attacks | 90 min | 🔴 Advanced |
| 05 | Win32k Attack Surface | GDI objects, window messages, `_SURFACE` corruption, CVE-2021-1732 deep-dive | 80 min | 🔴 Advanced |
| 06 | Privilege Escalation Techniques | Token theft, potato attacks, BYOVD, PrintNightmare, ALPC abuse | 70 min | 🟡 Intermediate |
| 07 | Active Directory Attacks | Kerberoasting, AS-REP roasting, delegation, DCSync, Golden/Silver tickets | 60 min | 🟡 Intermediate |
| 08 | Offensive Tooling & EDR Evasion | Mimikatz, BloodHound, Rubeus, process injection, direct syscalls, ETW bypass | 60 min | 🔴 Advanced |
| 09 | Modern Mitigations & Bypasses | VBS/HVCI, kCFI, CET, pool hardening — and data-only attack patterns | 70 min | 🔴 Advanced |
| 10 | Hardening & Defense | WDAC, Credential Guard, tiered admin, BloodHound defense, audit policy | 40 min | 🟢 Beginner |
| 11 | Landmark CVE Deep-Dives | CVE-2021-1732, CVE-2020-17087, PrintNightmare, BYOVD analysis | 80 min | 🔴 Advanced |

---

## Cross-References

| Related Track | Connection |
|---------------|------------|
| [**OSEE / EXP-401**](../OSEE/) | Hands-on Windows kernel exploitation — the practical lab for this track's theory |
| [**Linux Kernel**](../linux_kernel/) | Comparative kernel exploitation: pool vs. SLUB, WinDbg vs. GDB, `_EPROCESS.Token` vs. `commit_creds` |
| [**macOS**](../MacOS/) | Alternative desktop security model: Mach IPC vs. ALPC, SIP vs. VBS, AMFI vs. WDAC |
| [**CPU Rings**](../ring_and_vulns/) | Hardware-enforced privilege boundaries: Ring 3→0 escalation, Ring −1 (VBS/HVCI), Ring −2 (UEFI bootkits) |
| [**Zero-Day**](../zero_day/) | Vulnerability discovery methodology: fuzzing Windows IOCTLs, patch diffing, variant analysis |
| [**Chromium**](../Chromium_Architecture_and_Vulnerability/) | Browser sandbox escape → Win32k kernel chain (Chrome GPU → win32k → SYSTEM) |

---

## Learning Paths

### Path 1: Kernel Exploitation Track (OSEE Preparation)
Focus on kernel internals and exploitation for the OSEE/EXP-401 certification.

1. 01 → 03 → 04 → 05 → 09 → 11 → [OSEE track](../OSEE/)

### Path 2: Enterprise Attack Track (Red Team / AD Specialist)
Focus on Active Directory attacks, privilege escalation, and lateral movement.

1. 02 → 06 → 07 → 08 → 10

### Path 3: Defensive Track (Blue Team / Hardening)
Focus on understanding attack techniques to build better defenses.

1. 02 → 06 → 07 → 09 → 10

### Path 4: Malware Analysis Track (Reverse Engineering)
Focus on understanding Windows malware, process injection, and EDR evasion.

1. 01 → 03 → 08 → 09 → 05

### Path 5: Complete Track (Security Researcher)
Full deep-dive for researchers who want comprehensive understanding.

1. 01 → 02 → 03 → 04 → 05 → 06 → 07 → 08 → 09 → 10 → 11 → [OSEE track](../OSEE/)

## References

1. Russinovich, M. et al. "Windows Internals." 7th Ed. *Microsoft Press*. 2021.
2. Microsoft. "Windows Security Documentation." https://docs.microsoft.com/en-us/windows/security/. 2024.
3. MITRE. "ATT&CK: Windows Techniques." https://attack.mitre.org/techniques/enterprise/. 2024.
4. Microsoft Security Response Center (MSRC). https://msrc.microsoft.com/blog/. 2024.
5. j00ru (Jurczyk, M.). "Windows Kernel Research." https://j00ru.vexillium.org/. 2024.
6. Hacker, H. "HackSys Extreme Vulnerable Driver." https://github.com/hacksysteam/HackSysExtremeVulnerableDriver. 2024.
7. Corelan Team. "Exploit Writing Tutorials." https://www.corelan.be/. 2024.
8. Offensive Security. "EXP-401: Advanced Windows Exploitation." https://www.offsec.com/courses/exp-401/. 2024.

---

## Recent Developments (2025–2026)

*Independently verified against primary sources (NVD / vendor advisories / papers) during the 2026-06 accuracy audit. Each CVE was confirmed to exist with the stated characterization.*

### Vulnerabilities (CVEs)

- **CVE-2025-29824 — Windows CLFS use-after-free zero-day exploited in ransomware attacks** *(2025-04)* — A use-after-free flaw (CWE-416, CVSS 7.8) in the Windows Common Log File System (CLFS) kernel driver allowed local privilege escalation to SYSTEM. Microsoft observed in-the-wild post-compromise exploitation by the Storm-2460 group using the PipeMagic backdoor to deploy RansomEXX ransomware against targets in the US, Venezuela, Spain, and Saudi Arabia; Play ransomware was also linked to its abuse. Windows 11 24H2 was not affected by the observed exploitation; patched April 8, 2025. [[source]](https://nvd.nist.gov/vuln/detail/CVE-2025-29824)
- **CVE-2025-33073 — Reflective Kerberos/NTLM relay against the Windows SMB client (CISA KEV)** *(2025-06)* — RedTeam Pentesting disclosed a reflective relay flaw (CWE-284 improper access control, CVSS 8.8) in the Windows SMB client that bypasses prior NTLM-reflection mitigations. By coercing a host to authenticate (e.g., PrinterBug/EFSRPC) and relaying its own Kerberos/NTLM authentication back via SMB, an attacker gains NT AUTHORITY\SYSTEM on the target. Patched June 10, 2025, and later added to CISA's Known Exploited Vulnerabilities catalog; SMB signing mitigates it. [[source]](https://nvd.nist.gov/vuln/detail/CVE-2025-33073)
- **CVE-2025-49667 — Win32k ICOMP double-free kernel privilege escalation** *(2025-07)* — A double-free vulnerability (CWE-415, CVSS 7.8) in the Windows Win32k graphics driver's ICOMP composition component allows a local authenticated attacker to elevate to SYSTEM. Crafted graphical syscalls create objects with interdependencies whose improper state tracking during destruction frees the same kernel heap block twice. Published July 8, 2025, it continues the Win32k pool-corruption lineage already covered in the track (e.g., CVE-2021-1732). [[source]](https://nvd.nist.gov/vuln/detail/CVE-2025-49667)

### Techniques

- **CVE-2025-53779 ("BadSuccessor") — dMSA abuse for domain privilege escalation in Windows Server 2025** *(2025-08)* — Akamai researcher Yuval Gordon disclosed BadSuccessor, abusing the new delegated Managed Service Account (dMSA) feature in Windows Server 2025. By writing the msDS-ManagedAccountPrecededByLink and msDS-DelegatedMSAState attributes on an attacker-creatable dMSA, a low-privileged user with CreateChild rights on an OU can have the KDC issue them the privileges and Kerberos keys of any account, including Domain Admin. Microsoft assigned CVE-2025-53779 (Kerberos path traversal, CVSS 7.2) and patched it on August 12, 2025. [[source]](https://nvd.nist.gov/vuln/detail/CVE-2025-53779)
- **Embedded BYOVD goes mainstream as a ransomware EDR-killer technique (2024-2025)** *(2025)* — Bring-Your-Own-Vulnerable-Driver attacks became a standard pre-encryption step in ransomware operations during 2024-2025, with a single campaign using the TrueSight (RentDrv/Adlice) driver deploying over 2,500 signed driver variants to unregister kernel callbacks, disable ETW, and terminate EDR processes. The trend shifted from BYOVD as a separate staging step toward drivers embedded directly in payloads, shrinking the detection window. [[source]](https://www.vectra.ai/topics/edr-evasion)

### Tools

- **BloodHound Community Edition 8.0 released with OpenGraph** *(2025-07)* — SpecterOps released BloodHound Community Edition 8.0 on July 29, 2025, introducing OpenGraph, which extends attack-path mapping beyond Active Directory and Entra ID to arbitrary identity sources (initially GitHub, Snowflake, 1Password, and Microsoft SQL Server). It supports custom relationship modeling and Cypher querying across hybrid identity graphs, expanding both offensive attack-path discovery and defensive attack-path elimination. [[source]](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)

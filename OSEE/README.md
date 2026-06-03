# OSEE / EXP-401 — Offensive Security Exploitation Expert

> **Difficulty:** 🔴 Advanced (expert-level certification preparation)  
> **Estimated reading time:** ~14 hours  
> **Prerequisites:** Significant exploitation experience, Windows/Linux internals, x86/x64 assembly, debugger proficiency (WinDbg, x64dbg)

## Overview

This track is a comprehensive study guide and reference for the **OSEE (Offensive Security Exploitation Expert)** certification and its associated course **EXP-401 (Advanced Windows Exploitation)**. It covers the certification's history and industry context, the full EXP-401 curriculum, Windows kernel and driver exploitation, exploit mitigation bypasses, reverse engineering, exam strategy, and career impact.

If you're preparing for OSEE or want to understand the highest level of hands-on exploitation certification, this is your track.

## Reading order

| # | File | Topic |
|---|------|-------|
| 1 | [`01a_osee_overview_history.md`](docs/01a_osee_overview_history.md) | OSEE certification overview and history |
| 2 | [`01b_osee_industry_context.md`](docs/01b_osee_industry_context.md) | OSEE's place in the industry and certification hierarchy |
| 3 | [`02a_exp401_curriculum.md`](docs/02a_exp401_curriculum.md) | EXP-401 course curriculum breakdown |
| 4 | [`02b_exp401_technical_depth.md`](docs/02b_exp401_technical_depth.md) | EXP-401 technical depth and scope |
| 5 | [`03a_kernel_exploitation_techniques.md`](docs/03a_kernel_exploitation_techniques.md) | Windows kernel exploitation techniques |
| 6 | [`03b_driver_exploitation_attack_surfaces.md`](docs/03b_driver_exploitation_attack_surfaces.md) | Driver exploitation and attack surfaces |
| 7 | [`04a_exploit_mitigations_bypasses.md`](docs/04a_exploit_mitigations_bypasses.md) | Exploit mitigation bypasses (DEP, ASLR, CFG) |
| 8 | [`04b_advanced_mitigations_modern_bypass.md`](docs/04b_advanced_mitigations_modern_bypass.md) | Advanced mitigations and modern bypass techniques |
| 9 | [`05a_reverse_engineering_vuln_discovery.md`](docs/05a_reverse_engineering_vuln_discovery.md) | Reverse engineering and vulnerability discovery |
| 10 | [`06a_prerequisites_preparation.md`](docs/06a_prerequisites_preparation.md) | Prerequisites and preparation roadmap |
| 11 | [`06b_skillbuilding_roadmap.md`](docs/06b_skillbuilding_roadmap.md) | Skill-building roadmap and practice exercises |
| 12 | [`07a_exam_structure_strategies.md`](docs/07a_exam_structure_strategies.md) | OSEE exam structure and strategies |
| 13 | [`07b_exam_challenges_lessons_learned.md`](docs/07b_exam_challenges_lessons_learned.md) | Exam challenges walkthrough and lessons learned |
| 14 | [`08a_career_impact_industry_value.md`](docs/08a_career_impact_industry_value.md) | Career impact and industry value of OSEE |
| 15 | [`08b_exploitation_landscape_future.md`](docs/08b_exploitation_landscape_future.md) | The future of exploitation and the landscape ahead |

## Related tracks

- **Zero-day exploit development** → [`../zero_day/`](../zero_day/) — Complementary methodology for vulnerability discovery and exploit development
- **Linux kernel research** → [`../linux_kernel/`](../linux_kernel/) — Kernel exploitation foundations (Linux side)
- **Ring & vulnerabilities** → [`../ring_and_vulns/`](../ring_and_vulns/) — Privilege escalation from Ring 3 to Ring 0+ context
- **Chromium research** → [`../Chromium_Architecture_and_Vulnerability/`](../Chromium_Architecture_and_Vulnerability/) — Browser exploitation techniques

## References

- Offensive Security, "OSEE Certification," https://www.offsec.com/courses/
- Offensive Security, "EXP-401: Advanced Windows Exploitation," https://www.offsec.com/courses/exp-401/
- Mark Russinovich, David Solomon & Alex Ionescu, "Windows Internals," 7th Edition, Microsoft Press.
- Corelan Team, "Exploit Writing Tutorials," https://www.corelan.be/
- Morten Schenk, "Swimming In The (Kernel) Pool," 2021.
- Connor McGarr, Windows Kernel Exploitation Blog, https://connormcgarr.github.io/
- MITRE ATT&CK — Windows Techniques, https://attack.mitre.org/techniques/enterprise/
- Microsoft Security Response Center (MSRC) Blog, https://msrc.microsoft.com/blog/
- j00ru (Mateusz Jurczyk), Windows Kernel Research, https://j00ru.vexillium.org/

---

## Recent Developments (2025–2026)

*Independently verified against primary sources (NVD / vendor advisories / papers) during the 2026-06 accuracy audit. Each CVE was confirmed to exist with the stated characterization.*

### Vulnerabilities (CVEs)

- **CVE-2025-29824 — Windows CLFS driver use-after-free zero-day exploited for SYSTEM privilege escalation (Storm-2460 / PipeMagic ransomware)** *(2025-04)* — Microsoft patched an actively exploited use-after-free (CWE-416) elevation-of-privilege vulnerability in the Windows Common Log File System (CLFS) kernel driver on April 8, 2025. The exploit, deployed via PipeMagic malware and attributed to Storm-2460, leaked kernel addresses through NtQuerySystemInformation and used RtlSetAllBits to overwrite the process token with 0xFFFFFFFF for full privileges before deploying ransomware; Windows 11 24H2 was not affected because the needed information classes were restricted to SeDebugPrivilege. It was added to the CISA Known Exploited Vulnerabilities catalog on April 8, 2025. [[source]](https://www.microsoft.com/en-us/security/blog/2025/04/08/exploitation-of-clfs-zero-day-leads-to-ransomware-activity/)
- **CVE-2025-62215 — Windows kernel race-condition/double-free zero-day actively exploited (November 2025 Patch Tuesday)** *(2025-11)* — Microsoft's November 11, 2025 Patch Tuesday fixed CVE-2025-62215 (CVSS 7.0), an actively exploited local privilege escalation in the Windows Kernel caused by improper synchronization of a shared resource (CWE-362) leading to a double free (CWE-415). A local attacker forces multiple threads to touch the same kernel resource without synchronization, freeing the same block twice to corrupt the kernel heap and seize execution flow to escalate to SYSTEM. It affects all currently supported Windows editions including Windows 10 Extended Security Updates. [[source]](https://nvd.nist.gov/vuln/detail/CVE-2025-62215)
- **CVE-2025-32709 — AFD.sys (WinSock Ancillary Function Driver) use-after-free zero-day, CISA KEV** *(2025-05)* — CVE-2025-32709 is a use-after-free (CWE-416) elevation-of-privilege vulnerability in the Windows Ancillary Function Driver for WinSock (afd.sys), published May 13, 2025 with a CVSS 3.1 base score of 7.8 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H). An authorized local attacker can elevate privileges to SYSTEM; it was added to the CISA Known Exploited Vulnerabilities catalog with a remediation deadline of June 3, 2025, and is one of multiple afd.sys driver CVEs disclosed across 2025. [[source]](https://nvd.nist.gov/vuln/detail/CVE-2025-32709)

### Incidents & In-the-Wild Exploitation

- **Pwn2Own Berlin 2025: multiple fresh Windows 11 SYSTEM privilege-escalation zero-days demonstrated** *(2025-05)* — At Pwn2Own Berlin 2025 (mid-May 2025, organized by Trend Micro's Zero Day Initiative), researchers earned $1,078,750 disclosing 28 previously unknown vulnerabilities. Windows 11 SYSTEM escalations were demonstrated using a chained use-after-free plus integer overflow (Chen Le Qi, STAR Labs), an out-of-bounds write (Marcin Wiązowski), a type confusion, and race-condition bugs (e.g. Miloš Ivanović); a VirtualBox-escape-to-Windows-EoP chain earned $70,000. These represent the current state of practical Windows kernel/driver EoP techniques at the OSEE level. [[source]](https://www.securityweek.com/hackers-earn-over-1-million-at-pwn2own-berlin-2025/)

### Techniques

- **Synacktiv: analysis of the Windows kernel-mode shadow stack (Intel CET) mitigation with PoCs — SSTIC 2025** *(2025-06)* — At SSTIC 2025 (June 2025), Synacktiv researchers published static and dynamic analysis of Windows 11 24H2's kernel-mode hardware-enforced stack protection (Intel CET shadow stacks), reverse-engineering how Windows maintains kernel shadow-stack integrity on CET-capable hardware. The accompanying GitHub repository provides proof-of-concept driver/client code demonstrating return-address misalignment crashes, frame manipulation, disabling CET via CR4 modification, and writes to shadow-stack memory and PTEs. The work is directly relevant to OSEE's coverage of modern kernel mitigation bypasses, noting kernel shadow-stack protection is not enabled by default in 24H2. [[source]](https://github.com/synacktiv/windows_kernel_shadow_stack)

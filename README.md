# deep-researcher

Document-first security research repository covering browser, operating system, and exploit-development topics. The repo is organized as long-form Markdown reports and chaptered notes rather than as an application or library codebase.

## What this repository contains

- Chromium architecture and vulnerability research
- Linux kernel security research
- macOS/XNU architecture, exploitation, and mitigation research
- Android architecture, vulnerability landscape, and CVE research
- CPU protection rings — vulnerabilities and exploitation from userland to Ring −3
- Zero-day research and exploit development — fundamentals through advanced kernel exploitation
- A focused Android Binder CVE case study (`CVE-2023-20938`)
- OSEE / EXP-401 study and reference material

## What this repository is not

- Not a packaged application, service, or SDK
- Not a root-level lab environment with install/build/test workflows
- Not a ready-to-run exploit toolkit

Most directories are best approached as reading tracks.

## Start here

If you are new to the repo, start with one of these entry documents:

| Topic | Entry point |
| --- | --- |
| Chromium research | [`Chromium_Architecture_and_Vulnerability/Chromium_Architecture_and_Vulnerability_Report.md`](Chromium_Architecture_and_Vulnerability/Chromium_Architecture_and_Vulnerability_Report.md) |
| Android Binder CVE case study | [`CVE-2023-20938/CVE-2023-20938_FINAL_REPORT.md`](CVE-2023-20938/CVE-2023-20938_FINAL_REPORT.md) |
| Linux kernel research | [`linux_kernel/docs/FINAL_REPORT.md`](linux_kernel/docs/FINAL_REPORT.md) |
| macOS research | [`MacOS/docs/00_FINAL_REPORT_macOS_Architecture_Vulnerabilities_Exploits.md`](MacOS/docs/00_FINAL_REPORT_macOS_Architecture_Vulnerabilities_Exploits.md) |
| Android architecture & CVEs | [`android_and_CVEs/FINAL_REPORT_Android_Architecture_Vulnerabilities_and_CVEs.md`](android_and_CVEs/FINAL_REPORT_Android_Architecture_Vulnerabilities_and_CVEs.md) |
| CPU rings & vulnerabilities | [`ring_and_vulns/FULL_REPORT.md`](ring_and_vulns/FULL_REPORT.md) |
| Zero-day research & exploit development | [`zero_day/docs/00_MASTER_REPORT.md`](zero_day/docs/00_MASTER_REPORT.md) |
| OSEE / EXP-401 reference track | [`OSEE/docs/01a_osee_overview_history.md`](OSEE/docs/01a_osee_overview_history.md) |

## Repository structure

- `Chromium_Architecture_and_Vulnerability/` — Chromium internals, sandboxing, V8/Blink, exploit chains, and CVE case studies
- `CVE-2023-20938/` — deep dive into an Android Binder use-after-free privilege-escalation vulnerability
- `linux_kernel/` — large Linux kernel corpus covering architecture, vulnerability classes, exploitation, fuzzing, and defenses
- `MacOS/` — macOS/XNU security architecture, vulnerabilities, post-exploitation themes, malware, and mitigations
- `android_and_CVEs/` — Android system architecture, security model, kernel/application/framework vulnerability classes, CVE statistics and trends, and patch management
- `ring_and_vulns/` — CPU protection rings (Ring 3 → Ring 0 → Ring −1/−2/−3), vulnerabilities at each privilege level, cross-ring exploitation chains, and CVE references
- `zero_day/` — zero-day vulnerability research and exploit development curriculum: fundamentals, fuzzing, userspace/kernel exploitation, mitigation bypass, CTF strategy, and ethics/disclosure
- `OSEE/` — OSEE / EXP-401 study material focused on advanced exploitation and practitioner preparation

## How to navigate

1. Pick a topic directory.
2. Start with that directory's main report when one exists.
3. Continue into the numbered files under its `docs/` directory.
4. Treat numbered filenames as the intended reading order.

Note: structure is slightly uneven across tracks. Some topics expose a top-level report at the directory root, while others keep the main entry document inside `docs/`.

## Intended audience

This repository is most useful for:

- security researchers
- exploit developers and red teamers
- security engineers and defenders who need architecture-level context
- advanced learners studying operating-system, browser, and vulnerability research topics

Some sections assume familiarity with systems internals, debugging, exploit-development concepts, and security terminology.

## Usage expectations

You generally only need a Markdown-capable editor or viewer to use this repository. Expect substantial reading, cross-references, and report-style material rather than runnable code.

## Safety and responsible use

This repository contains dual-use security material, including discussion of vulnerabilities, exploitation techniques, persistence, evasion, and mitigation bypasses. Use it only for authorized research, education, and defensive/security-improvement purposes.

- Do not run commands or adapt techniques against systems you do not own or administer with permission.
- Prefer isolated lab environments for any hands-on experimentation.
- Independently verify technical details before operational use.

## Notes

- This repo is best understood as a living reference collection.
- Depth and document structure vary by topic.
- Some tracks are polished report sets; others are more handbook-like study material.
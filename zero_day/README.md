# Zero-Day Research & Exploit Development

A comprehensive zero-day vulnerability research and exploit development curriculum spanning from vulnerability taxonomy and fuzzing fundamentals through advanced kernel heap exploitation and CTF competition strategy. This track covers the full lifecycle — discovery, analysis, exploitation, and disclosure — with working pwntools exploits, GDB workflows, and real CVE walkthroughs drawn from landmark zero-days and top-tier CTF challenges.

| | |
|---|---|
| **Difficulty** | 🟡 Intermediate → 🔴 Advanced (progressive) |
| **Reading Time** | ~13 hours |
| **Prerequisites** | C, Python, x86 assembly, basic exploitation concepts (buffer overflows, shellcode), Linux CLI proficiency |

---

## Reading Order

| # | Document | Topic |
|---|----------|-------|
| 00 | [Master Report](docs/00_MASTER_REPORT.md) | Index, synthesis, and learning roadmap for the entire corpus |
| 01a | [Zero-Day Fundamentals & Taxonomy](docs/01a_zero_day_fundamentals_taxonomy.md) | 0-day/1-day/N-day classification, vulnerability class encyclopedia, 10+ landmark CVEs, threat landscape |
| 01b | [Zero-Day Ecosystem & Attack Surfaces](docs/01b_zero_day_ecosystem_attack_surfaces.md) | Zero-day economics, markets, attack surface mapping, patch diffing for 1-days, adversarial mindset |
| 02a | [Vuln Discovery: Fuzzing & Dynamic Analysis](docs/02a_vuln_discovery_fuzzing_dynamic.md) | AFL++, libFuzzer, syzkaller, coverage-guided fuzzing, crash triage, dynamic instrumentation |
| 02b | [Vuln Discovery: Code Audit & Reverse Engineering](docs/02b_vuln_discovery_audit_re.md) | Source auditing, Ghidra scripting, CodeQL/Semgrep, kernel code audit, patch diffing & variant analysis |
| 03a | [Userspace: Stack & Heap Exploitation](docs/03a_userspace_stack_heap.md) | Stack overflows, ROP/SROP/ret2csu, glibc heap internals, modern heap techniques (House of Apple/Botcake/Cat), FILE/FSOP |
| 03b | [Userspace: Advanced Techniques](docs/03b_userspace_advanced_techniques.md) | Format strings, integer bugs, type confusion, UAF, ret2dlresolve, one-gadgets, shellcraft, race conditions |
| 04a | [Kernel: Foundations & Slab Exploitation](docs/04a_kernel_slab_exploitation.md) | Linux kernel architecture, SLUB allocator internals, cross-cache attacks, msg_msg/pipe_buffer/tty spray, info leaks |
| 04b | [Kernel: Advanced LPE](docs/04b_kernel_advanced_lpe.md) | Kernel ROP, commit_creds/modprobe_path, SMEP/SMAP/KASLR/KPTI bypass, userfaultfd/FUSE, Dirty COW/Pipe, io_uring |
| 05 | [Mitigation Bypass Techniques](docs/05_mitigation_bypass_techniques.md) | NX→ROP, ASLR→info leak, canary→leak/bruteforce, PIE→disclosure, RELRO→GOT alternatives, seccomp escapes |
| 06 | [CTF Strategy & Mastery](docs/06_ctf_strategy_mastery.md) | Competition landscape, systematic pwn/kernel methodology, speed optimization, mental game, training regiment |
| 07 | [Tooling & Infrastructure](docs/07_tooling_infrastructure.md) | GDB/pwndbg mastery, pwntools reference, kernel debugging, QEMU scripts, checksec/one_gadget/patchelf, exploit templates |
| 08 | [Ethics, Disclosure & Legal](docs/08_ethics_disclosure_legal.md) | CVD process, CFAA/DMCA framework, bug bounty economics, zero-day market debate, career trajectories |

---

## Related Tracks

- [Linux Kernel](../linux_kernel/) — Deep kernel exploitation reference (subsystems, driver audit, kernel internals)
- [Ring & Vulnerabilities](../ring_and_vulns/) — Privilege ring architecture and hardware-enforced security boundaries
- [Chromium](../Chromium_Architecture_and_Vulnerability/) — Browser exploitation, V8, sandbox escapes
- [OSEE](../OSEE/) — Advanced exploitation certification preparation (CREST OSWE/OSEE level)
## References

- Project Zero Blog — Google. https://googleprojectzero.blogspot.com/
- "A Guide to Kernel Exploitation," Enno Rey, ERNW / DEF CON
- "Return-Oriented Programming: Systems, Languages, and Applications," Roemer et al., University of California, San Diego, 2012
- "Fuzzing: Brute Force Vulnerability Discovery," Sutton et al., McGraw-Hill, 2007
- Pwn College, Arizona State University. https://pwn.college/
- MITRE CWE — Common Weakness Enumeration. https://cwe.mitre.org/
- NVD — National Vulnerability Database. https://nvd.nist.gov/
- CVE records as cited throughout the corpus
- Various vulnerability research blog posts and conference proceedings (DEF CON, Black Hat, CCC)


---

## Recent Developments (2025–2026)

*Independently verified against primary sources (NVD / vendor advisories / papers) during the 2026-06 accuracy audit. Each CVE was confirmed to exist with the stated characterization.*

### Vulnerabilities (CVEs)

- **CVE-2025-38617: Race-within-a-race UAF in Linux packet sockets (kernelCTF)** *(2025)* — A use-after-free in the Linux kernel packet socket subsystem (net/packet/af_packet.c), caused by a race between packet_set_ring() and packet_notifier(), latent since Linux 2.6.12 (2005) and fixed in 6.16. Discovered and exploited by Quang Le (Calif) and submitted to Google's kernelCTF; reachable by an unprivileged local user with only CAP_NET_RAW (obtainable via user namespaces) for full LPE and container escape. The exploit demonstrates a generalizable heuristic: making a mutex holder sleep (here tpacket_snd() holding pg_vec_lock during wait_for_completion_interruptible_timeout()) to stretch a nanosecond race into a ~1-second deterministic window. [[source]](https://nvd.nist.gov/vuln/detail/CVE-2025-38617)
- **CVE-2025-10585: actively exploited V8 type-confusion zero-day in Chrome** *(2025-09)* — A type-confusion vulnerability in Chrome's V8 JavaScript/WebAssembly engine, discovered and reported by Google's Threat Analysis Group (TAG) on Sept 16, 2025, with an exploit confirmed in the wild. Google fixed it in Chrome 140.0.7339.185/.186; it was among multiple V8 type-confusion zero-days exploited in 2025, illustrating that browser renderer RCE remains the most active real-world zero-day target class. [[source]](https://thehackernews.com/2025/09/google-patches-chrome-zero-day-cve-2025.html)
- **CVE-2025-13223: another in-the-wild V8 type-confusion zero-day** *(2025-11)* — A V8 type-confusion flaw allowing heap corruption via a crafted HTML page, discovered by Clément Lecigne of Google's Threat Analysis Group and actively exploited in the wild. Google shipped the fix on Nov 18, 2025 in Chrome 142.0.7444.175/.176; a near-identical internally found variant (CVE-2025-13224) was patched alongside it, underscoring sustained variant-driven zero-day activity against V8 throughout 2025. [[source]](https://www.helpnetsecurity.com/2025/11/18/chrome-cve-2025-13223-exploited/)

### Techniques

- **kernel-hack-drill and a new approach to CVE-2024-50264 (Pwnie 2025, Best Privesc)** *(2025-09)* — Alexander Popov published (Sept 2, 2025) a detailed exploitation methodology for CVE-2024-50264, a race-condition UAF in Linux AF_VSOCK between connect() and a POSIX signal (introduced 2016, disclosed autumn 2024). The work introduces kernel-hack-drill (a drill module + userspace harness for prototyping primitives), a deferred-insertion msg_msg spray to corrupt linked-list pointers, novel pipe_buffer manipulation for arbitrary R/W, and use of 'immortal signal 33' to interrupt syscalls without killing the exploit. The technique won the Pwnie Award 2025 for Best Privilege Escalation. [[source]](https://a13xp0p0v.github.io/2025/09/02/kernel-hack-drill-and-CVE-2024-50264.html)

### Research

- **CROSS-X: generalized and stable cross-cache attacks (CCS 2025)** *(2025-10)* — Dongok Kim, Juhyun Song, and Insu Yun (KAIST) presented CROSS-X at ACM CCS 2025 (Taipei, Oct 13-17). Cross-cache attacks underpin modern kernel exploitation primitives (DirtyCred, Dirty Pagetable, SLUBStick) but historically lacked a reliable, standard methodology; CROSS-X introduces two robust new strategies plus an automated system to make cross-cache reclamation generalized and stable. The authors released a public implementation on GitHub (juhyun167/CROSS-X), directly advancing the slab-exploitation material in 04a/04b of this track. [[source]](https://doi.org/10.1145/3719027.3765152)

### Tools

- **Google Big Sleep AI agent pre-empts in-the-wild SQLite zero-day (CVE-2025-6965)** *(2025-07)* — On July 18, 2025 Google reported that its Big Sleep LLM-based vulnerability-research agent, combined with Google Threat Intelligence Group signals, found CVE-2025-6965 — a critical SQLite flaw known only to threat actors and imminently about to be exploited — and got it patched before exploitation. Google describes this as the first time an AI agent directly foiled an in-the-wild exploitation attempt, marking a shift in AI-assisted vulnerability discovery relevant to the fuzzing/discovery portions of this track. [[source]](https://cloud.google.com/blog/products/identity-security/cloud-ciso-perspectives-our-big-sleep-agent-makes-big-leap)

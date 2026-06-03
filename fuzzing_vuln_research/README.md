# Fuzzing & Vulnerability Research Methodology

A comprehensive deep-research track covering fuzzing techniques, vulnerability research methodology, and security tooling from fundamentals to the cutting edge.

## Track Structure

```
fuzzing_vuln_research/
├── README.md                              ← You are here
├── FUZZING_VULN_RESEARCH_FINAL_REPORT.md  ← Synthesis report (4000+ words)
├── CHEATSHEET.md                          ← Quick reference
└── docs/
    ├── 01_fuzzing_fundamentals.md          ← History, taxonomy, feedback, coverage, oracles
    ├── 02a_aflplusplus.md                 ← AFL++ deep dive
    ├── 02b_libfuzzer.md                   ← libFuzzer deep dive
    ├── 03_kernel_fuzzing.md               ← syzkaller, KCOV, KASAN, eBPF, Android
    ├── 04_protocol_format_fuzzing.md       ← TLS, SSH, HTTP/2, DNS, Wi-Fi, BT, formats
    ├── 05_browser_fuzzing.md              ← V8/fuzzilli, JSC, DOM, CSS, Wasm, GPU
    ├── 06_harnessing_optimization.md       ← Harness design, persistent mode, parallel fuzzing
    ├── 07_vulnerability_research.md        ← Crash→PoC, variant analysis, disclosure
    ├── 08_auditing_tools.md               ← CodeQL, Semgrep, BinDiff, patch analysis
    ├── 09_fuzzing_vuln_research_case_studies.md  ← OSS-Fuzz, DirtyPipe, V8, GPU drivers
    └── 10_fuzzing_future.md               ← AI fuzzing, concolic, hardware, FaaS
```

## Chapter Summaries

| Chapter | Topic | Key Content |
|---------|-------|-------------|
| 01 | Fuzzing Fundamentals | Miller 1989→modern; taxonomy; feedback mechanisms; coverage metrics; bug oracles |
| 02a | AFL++ Deep Dive | LTO mode; CmpLog; persistent mode; fork server; QEMU/Unicorn; custom mutators |
| 02b | libFuzzer Deep Dive | In-process model; FuzzedDataProvider; LPM; sanitizers; OSS-Fuzz; ClusterFuzz |
| 03 | Kernel Fuzzing | syzkaller architecture; KCOV; KASAN/KMSAN; netlink/io_uring/eBPF; Android |
| 04 | Protocol & Format Fuzzing | TLS, SSH, HTTP/2, DNS, Wi-Fi, Bluetooth; JPEG/PNG/PDF/ELF/ZIP; IPC; Peach |
| 05 | Browser Fuzzing | fuzzilli; V8/JSC/SpiderMonkey; DOMato/Dharma; CSS; Wasm; Mojo; GPU |
| 06 | Harnessing & Optimization | In-process vs out-of-process; persistent mode; corpus curation; parallel fuzzing |
| 07 | Vulnerability Research | Crash triage→PoC; CWE classification; timeline analysis; variant analysis; disclosure |
| 08 | Auditing Tools | CodeQL/Semgrep rules; BinDiff/Diaphora; git forensics; patch analysis; bug bounty |
| 09 | Case Studies | OSS-Fuzz (40K+ bugs); Dirty COW/Pipe; V8 CVE-2024-0519; Mali GPU; full workflow |
| 10 | Future | AI-augmented fuzzing; concolic revival; Intel PT; eBPF coverage; FaaS; ML fuzzing |

## Key CVEs Referenced

| CVE | Description | Discovery Method |
|-----|-------------|-----------------|
| CVE-2016-5195 | Dirty COW | Manual analysis |
| CVE-2019-2215 | Binder UAF (Pegasus) | syzkaller |
| CVE-2021-3490 | eBPF verifier bounds bypass | syzkaller |
| CVE-2022-0847 | DirtyPipe | Operational monitoring |
| CVE-2022-22706 | ARM Mali GPU OOB write | Fuzzing |
| CVE-2024-0519 | V8 Wasm SIMD OOB write | ClusterFuzz/fuzzilli |
| CVE-2024-1086 | nf_tables UAF | syzkaller |

## Tool Quick Reference

See [CHEATSHEET.md](CHEATSHEET.md) for:
- AFL++ one-liners and environment variables
- libFuzzer harness template and build commands
- syzkaller config template and kernel config
- CodeQL query examples
- Semgrep rule examples
- Crash triage commands
- Sanitizer compilation flags
- Fuzzing performance tips
- Bug classification decision tree

## Reading Order

**Beginner path:** 01 → 02a → 02b → 06 → 07 → CHEATSHEET
**Kernel focus:** 01 → 03 → 07 → 09
**Browser focus:** 01 → 02b → 05 → 09
**Bug bounty focus:** 01 → 06 → 07 → 08 → CHEATSHEET
**Research focus:** 01 → 07 → 08 → 09 → 10

## Prerequisites

- C/C++ programming proficiency
- Basic understanding of operating systems (processes, memory, syscalls)
- Familiarity with build systems (make, cmake)
- Comfortable with command-line tools (gcc, gdb, git)

## References

The track references 50+ CVEs, 30+ tools, and 20+ research papers. Key sources include:

[1] Miller, B.P., Fredriksen, L., & So, B. (1990). *An Empirical Study of the Reliability of UNIX Utilities*. Communications of the ACM, 33(12), 32–44. DOI: 10.1145/96279.96286

[2] Miller, B.P., Koski, D., Lee, C.P., Maganty, V., Murthy, R., Natarajan, A., & Steinfels, P. (1995). *Fuzz Revisited: A Re-examination of the Reliability of UNIX Utilities and Services*. University of Wisconsin CS Technical Report.

[3] Zalewski, M. (2013). *American Fuzzy Lop (AFL)*. https://lcamtuf.coredump.cx/afl/

[4] Fioraldi, A., Maier, D., Eißfeldt, H., & Heuse, M. (2020). *AFL++: Combining Incremental Steps of Fuzzing Research*. USENIX WOOT.

[5] Vyukov, D. (2015). *syzkaller: Kernel Fuzzer*. https://github.com/google/syzkaller

[6] Groß, S. (2019). *fuzzilli: Fuzzing for JavaScript JIT Compiler Bugs*. Google Project Zero. https://github.com/googleprojectzero/fuzzilli

[7] Serebryany, K. (2016). *Announcing OSS-Fuzz: Continuous Fuzzing for Open Source Software*. Google Security Blog. https://security.googleblog.com/2016/12/announcing-oss-fuzz-continuous-fuzzing.html

[8] Google. *ClusterFuzz*. https://github.com/google/clusterfuzz

[9] Böhme, M., Pham, V.T., & Roychoudhury, A. (2017). *Coverage-Based Greybox Fuzzing as Markov Chain*. IEEE S&P. DOI: 10.1109/SP.2017.41

[10] Klees, G., et al. (2018). *Evaluating Fuzz Testing*. ACM CCS. DOI: 10.1145/3243734.3243766

[11] Chen, P. & Chen, H. (2018). *Angora: Efficient Fuzzing by Principled Search*. IEEE S&P. DOI: 10.1109/SP.2018.00033

[12] Yun, I., et al. (2018). *QSYM: Practical Concolic Execution Tailored for Hybrid Fuzzing*. USENIX Security.

[13] Serebryany, K., Bruening, D., Potapenko, A., & Vyukov, D. (2012). *AddressSanitizer: A Fast Address Sanity Checker*. USENIX ATC.

[14] GitHub. *CodeQL Documentation*. https://codeql.github.com/docs/

[15] Return to Corporation. *Semgrep Documentation*. https://semgrep.dev/docs/


---

## Recent Developments (2025–2026)

*Independently verified against primary sources (NVD / vendor advisories / papers) during the 2026-06 accuracy audit. Each CVE was confirmed to exist with the stated characterization.*

### Vulnerabilities (CVEs)

- **CVE-2025-6965: SQLite memory corruption found by Google's Big Sleep AI agent before in-the-wild exploitation** *(2025-07)* — Google's Big Sleep AI agent (a collaboration of DeepMind and Project Zero) identified CVE-2025-6965, a numeric-truncation/memory-corruption flaw in SQLite versions before 3.50.2 in the aggregate-handling path, where an index can be truncated to a signed 16-bit value yielding out-of-bounds reads/writes. NVD rates it CVSS 9.8 (CWE-197), published July 15, 2025. Google states this is the first time an AI agent directly foiled an exploitation effort: combined with Threat Intelligence signals, the bug was known only to threat actors and imminently going to be used. [[source]](https://nvd.nist.gov/vuln/detail/CVE-2025-6965)

### Incidents & In-the-Wild Exploitation

- **DARPA AI Cyber Challenge (AIxCC) finals: Team Atlanta's ATLANTIS wins automated find-and-patch competition** *(2025-08)* — DARPA announced AIxCC final results at DEF CON 33 on August 8, 2025, with Team Atlanta (Georgia Tech, Samsung Research, KAIST, POSTECH) winning $4M for its ATLANTIS cyber reasoning system, ahead of Trail of Bits ($3M) and Theori ($1.5M). Across the finals the autonomous systems identified 86% of synthetic vulnerabilities and patched 68%, while also finding 18 real-world zero-days (6 C, 12 Java) at an average cost of about $152 per task. All seven finalist cyber reasoning systems are being released as open source. [[source]](https://www.darpa.mil/news/2025/aixcc-results)

### Research

- **KernelGPT (ASPLOS 2025): LLM-inferred Syzkaller specifications merged into upstream kernel fuzzer** *(2025)* — KernelGPT uses LLMs to automatically infer and refine Syzkaller (Syzlang) specifications from kernel source, with validation feedback to repair generated specs, extending syscall-description coverage that previously required manual effort. The project reports 24 new Linux kernel bugs (11 assigned CVEs, 12 fixes deployed) and states numerous KernelGPT-generated specifications have been merged into the official Syzkaller repository. Published at ASPLOS 2025. [[source]](https://github.com/ise-uiuc/KernelGPT)

### Tools

- **Buttercup: Trail of Bits' AIxCC cyber reasoning system released as open source** *(2025-08)* — Trail of Bits open-sourced Buttercup, the AI-driven find-and-patch system that won 2nd place ($3M) at AIxCC, on August 8, 2025. Buttercup combines conventional fuzzing and static analysis with LLMs (notably using only cheaper non-reasoning models) and in the final round found 28 vulnerabilities and applied 19 patches across 23 open-source repositories. Trail of Bits shipped a standalone laptop-runnable version tuned for per-project AI budgets. [[source]](https://blog.trailofbits.com/2025/08/08/buttercup-is-now-open-source/)

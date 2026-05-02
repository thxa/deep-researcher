# Reverse Engineering Track

A comprehensive, technically deep reference covering reverse engineering methodology, binary formats, static and dynamic analysis, malware/ransomware analysis, firmware RE, anti-tamper/obfuscation, binary exploitation from an RE perspective, protocol RE, tooling/workflow, and case studies/future directions.

## Documents

### Fundamentals & Methodology
| Document | Description |
|----------|-------------|
| [01a_re_fundamentals_methodology.md](docs/01a_re_fundamentals_methodology.md) | RE fundamentals: static vs dynamic analysis, methodology, legal considerations (DMCA 1201, EULAs, export controls), ethics, binary formats (ELF/PE/Mach-O), linking models, disassembly vs decompilation, address spaces |
| [01b_binary_formats_linking.md](docs/01b_binary_formats_linking.md) | Deep binary format analysis: ELF (headers, sections, symbols, PLT/GOT, relocations, DWARF), PE (DOS/COFF/Optional headers, IAT, resources, Authenticode), Mach-O (load commands, segments, code signing, FAT binaries), Android DEX/ART, format comparison |

### Analysis Techniques
| Document | Description |
|----------|-------------|
| [02a_static_analysis.md](docs/02a_static_analysis.md) | Static analysis: IDA Pro workflow, Ghidra (Decompiler, scripting, collaboration), radare2/rizin pipeline, Binary Ninja IL, pattern matching, FLIRT, cross-reference analysis, data flow, symbol recovery, string analysis, entropy analysis, YARA rules |
| [02b_dynamic_analysis.md](docs/02b_dynamic_analysis.md) | Dynamic analysis: GDB, WinDBG, x64dbg, LLDB, breakpoint types, watchpoints, trace-based analysis (strace/ltrace/Procmon), call tracing, coverage-guided analysis, API monitoring (API Monitor, Frida), hooking (inline/IAT/VEH), memory forensics, anti-debugging detection and bypass |

### Malware & Ransomware
| Document | Description |
|----------|-------------|
| [03a_malware_analysis.md](docs/03a_malware_analysis.md) | Malware analysis: triage (hashing, strings, imports, entropy), sandboxing (Cuckoo, CAPE, ANY.RUN), behavioral analysis, network indicators, packer identification/unpacking (UPX, Themida, VMProtect), anti-analysis (anti-VM, anti-debug, anti-disassembly), deobfuscation, sandbox evasion |
| [03b_ransomware_analysis.md](docs/03b_ransomware_analysis.md) | Ransomware analysis: crypto implementation (hybrid encryption, key generation weaknesses), file enumeration, VSS deletion, persistence, C2 communication, family analysis (WannaCry, NotPetya, REvil, Conti, LockBit), negotiator tools, decryption tool development |

### Embedded & Obfuscation
| Document | Description |
|----------|-------------|
| [04a_firmware_re.md](docs/04a_firmware_re.md) | Firmware RE: acquisition (UART, JTAG, SPI flash), extraction (binwalk, firmware-mod-kit), bootloader analysis (U-Boot, UEFI), embedded Linux, MIPS/ARM disassembly, cross-compilation, IoT firmware signature bypass, modification/re-flashing, binary diff |
| [04b_anti_tamper_obfuscation.md](docs/04b_anti_tamper_obfuscation.md) | Anti-tamper/obfuscation: control flow flattening, opaque predicates, junk code, string encryption, code virtualization (VMProtect, Themida), anti-debugging (IsDebuggerPresent, NtQueryInformationProcess, hardware BP detection), anti-dumping (PE header erasure), anti-disassembly, DRM/anti-cheat (Denuvo, EAC, BattlEye), deobfuscation (D-810, OLLVM) |

### Exploitation & Protocols
| Document | Description |
|----------|-------------|
| [05a_binary_exploitation_re.md](docs/05a_binary_exploitation_re.md) | Binary exploitation from RE perspective: vulnerable function patterns, buffer overflow identification, heap layout reconstruction, ROP gadget finding (ROPgadget, ropper), format string identification, integer overflow detection, UAF patterns, exploit development workflow (crash triage → root cause → primitive → exploitation) |
| [05b_protocol_re.md](docs/05b_protocol_re.md) | Protocol RE: methodology, binary protocol analysis, custom protocol identification, field mapping, protocol fuzzing, CAN bus RE for automotive, Bluetooth RE, game protocol RE, Wireshark dissection, Scapy protocol implementation, Frida protocol hooking, mitmproxy scripting |

### Tooling & Case Studies
| Document | Description |
|----------|-------------|
| [06_re_tooling_workflow.md](docs/06_re_tooling_workflow.md) | RE tooling: complete tool chain setup, IDA Pro/Ghidra/r2/Binary Ninja configuration and scripting, dynamic analysis toolkit, collaborative RE (Git-based), IDAPython/Java automation, LLM-assisted RE, Diaphora/BinDiff binary comparison, lab setup (VMs for each OS/arch) |
| [07_re_case_studies_future.md](docs/07_re_case_studies_future.md) | Case studies: Stuxnet (PLC code RE), FORCEDENTRY/Pegasus (iMessage PDF exploitation), SolarWinds SUNBURST, Equation Group, NotPetya rapid RE, Log4Shell, Pegasus indicators, UEFI LoJax. Future: AI-assisted decompilation, binary type recovery, ML-guided RE, formal verification, WebAssembly RE |

## Track Prerequisites

- Solid understanding of C/C++ and assembly (x86/x64, ARM)
- Familiarity with Linux command line and shell scripting
- Basic understanding of operating systems and networking
- Python programming for scripting and automation

## Related Tracks

- **[OSEE](../OSEE/)** — Offensive Security Exploitation Engineer certification
- **[Zero Day](../zero_day/)** — Zero-day vulnerability research
- **[Linux Kernel](../linux_kernel/)** — Kernel-level RE and exploitation
- **[MacOS](../MacOS/)** — Apple platform RE
- **[Windows Security](../windows_security/)** — Windows RE and security
- **[IoT Security](../iot_security/)** — IoT firmware and protocol analysis
- **[Fuzzing & Vuln Research](../fuzzing_vuln_research/)** — Fuzzing methodology

## References

1. Dennis Yurichev, "Reverse Engineering for Beginners," free online, https://yurichev.com/writings/RE_for_beginners-en.pdf
2. Michael Sikorski & Andrew Honig, "Practical Malware Analysis," No Starch Press, 2012.
3. Eldad Eilam, "Reversing: Secrets of Reverse Engineering," Wiley, 2005.
4. Chris Eagle, "The IDA Pro Book," No Starch Press, 2011.
5. Dennis Andriesse, "Practical Binary Analysis," No Starch Press, 2018.
6. IDA Pro documentation, https://hex-rays.com/ida-pro/
7. Ghidra documentation, https://ghidra-sre.org/
8. radare2 documentation, https://rada.re/n/
9. Phrack Magazine, various issues on binary analysis and exploitation, http://phrack.org/
10. SANS Institute, "Reverse Engineering Malware" (FOR610), https://www.sans.org/
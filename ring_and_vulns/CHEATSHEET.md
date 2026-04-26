# CPU Protection Rings — Quick Reference Cheatsheet

## Ring Architecture Quick Reference

| Ring | Mode | What Runs Here | Available Instructions | Key Restrictions |
|------|------|----------------|----------------------|------------------|
| 3 | CPL=3 | Apps, browsers, servers, containers | User-mode only (`syscall`, `int 0x80`) | No `cli`/`hlt`/`mov cr0`/`wrmsr`/`in`/`out` (unless IOPL), U/S=0 pages fault |
| 2 | CPL=2 | *(Unused in modern OSes)* | I/O port access if IOPL allows | Paging U/S bit treats as supervisor |
| 1 | CPL=1 | *(Unused in modern OSes)* | Call gate entry targets | Flat kernel model eliminates this ring |
| 0 | CPL=0 | Kernel, drivers, interrupt handlers | All instructions, all MSRs, CR0–CR4, I/O | SMAP/SMEP restrict user memory access |
| −1 | VMX Root | KVM, Xen, VMware, Hyper-V | All + VMX instructions (`vmcall`, `vmlaunch`) | Must manage VMCS/EPT for guests |
| −2 | SMM | UEFI firmware handlers, OEM code | All + `rsm`, unrestricted memory access | Invisible to OS; SMRAM protected by SMRR |
| −3 | Independent MCU | Intel ME (MINIX-3/ARC), AMD PSP (ARM Cortex-A5) | Own ISA, DMA, HECI, network stack | No host-CPU mechanism to inspect/halt |

## Key CVEs Per Ring Level

### Ring 3 → Ring 0 (Local Privilege Escalation)

| CVE | Bug | Technique | Affected |
|-----|-----|-----------|----------|
| CVE-2016-5195 | Dirty COW — COW race condition | `madvise(MADV_DONTNEED)` + write fault | Linux 2.6.22–4.8 |
| CVE-2022-0847 | Dirty Pipe — uninitialized `pipe_buffer.flags` | `splice()` + `write()` page cache corruption | Linux 5.8–5.16.11 |
| CVE-2021-4034 | PwnKit — pkexec `argc=0` envp confusion | `GCONV_PATH` library loading | polkit ≤0.120 |
| CVE-2021-3156 | Baron Samedit — sudo heap overflow | `set_cmnd()` overflow in `sudo` | sudo 1.8.2–1.8.31p2 |
| CVE-2019-18634 | sudo pwfeedback stack overflow | Stack buffer overflow | sudo <1.8.31 |
| CVE-2019-5736 | runc `/proc/self/exe` overwrite | Host binary replacement from container | runc ≤1.0-rc6 |

### Ring 0 — Kernel Bugs

| CVE | Bug | Technique | Affected |
|-----|-----|-----------|----------|
| CVE-2024-1086 | Netfilter `nft_verdict_init` UAF | Use-after-free in nf_tables | Linux 5.14–6.6 |
| CVE-2020-8835 | eBPF verifier OOB read/write | Bounds miscalculation in BPF | Linux 5.5–5.5.2 |
| CVE-2021-4154 | eBPF verifier OOB write | 32-bit bounds combining error | Linux 5.7–5.15.7 |
| CVE-2017-5123 | `waitid()` missing `access_ok()` | Arbitrary kernel write + SMEP bypass | Linux <4.14 |
| CVE-2017-7308 | signalfd UAF | `signalfd` + `copy_siginfo_to_user` race | Linux <4.11 |
| CVE-2016-0728 | Keyrings refcount overflow | `keyctl` refcount wrap → UAF | Linux <4.4 |
| CVE-2023-0386 | OverlayFS setuid copy-up | SUID preservation during copy-up | Linux <6.2 |

### Ring −1 — Hypervisor Escapes

| CVE | Bug | Technique | Hypervisor |
|-----|-----|-----------|------------|
| CVE-2015-3456 | VENOM — QEMU floppy heap overflow | Floppy controller `data_len` overflow → QEMU RCE | QEMU/KVM/Xen |
| CVE-2015-5161 | QEMU RTL8139 info leak | Network card descriptor leak → host memory disclosure | QEMU |
| CVE-2015-7504 | QEMU PCNET heap overflow | Network card emulation overflow → host RCE | QEMU |
| CVE-2019-6974 | KVM ioport race — `KVM_GET_DIRTY_LOG` | Race condition → host kernel corruption | KVM |
| CVE-2021-28476 | Hyper-V vmswitch RCE | Network packet handling → host RCE | Hyper-V |
| CVE-2020-3950 | VMware XHCI UAF | USB controller use-after-free → host RCE | VMware |
| CVE-2018-10938 | QEMU virtio-9p buffer overflow | 9pfs protocol overflow → host RCE | QEMU |

### Ring −2 — SMM

| CVE | Bug | Technique | Impact |
|-----|-----|-----------|--------|
| CVE-2017-5705 | Intel SMI buffer overflow | Overflow in SMI handler parameters | Ring 0 → Ring −2 |
| CVE-2017-5706 | Intel SMI callout | SMI handler dereferences pointer outside SMRAM | Ring 0 → Ring −2 |
| CVE-2017-5714 | Intel SMI TOCTOU | Time-of-check/time-of-use in SMI handler | Ring 0 → Ring −2 |
| CVE-2017-5713 | Intel unvalidated SMI parameters | Arbitrary SMI write primitive | Ring 0 → Ring −2 |
| CVE-2021-3816 | EDK II SMM variable UAF | Use-after-free in variable service | Ring 0 → Ring −2 |
| CVE-2022-0002 | Intel SMM LPE | Local privilege escalation to SMM | Ring 0 → Ring −2 |

### Ring −3 — Intel ME / AMD PSP

| CVE | Bug | Technique | Impact |
|-----|-----|-----------|--------|
| CVE-2017-5708 | Intel SPS privilege escalation | Firmware privilege escalation in SPS | Ring −2 → Ring −3 |
| CVE-2019-0090 | Intel CSME improper access control | OOB access in CSME → ME arbitrary code execution | Network → Ring −3 |
| CVE-2020-8758 | Intel CSME DAL buffer overflow | Buffer overflow in DAL → ME network RCE | Network → Ring −3 |
| CVE-2019-1549 | AMD PSP SEV key extraction | SEVered attack — DMA-based VM memory decryption | Ring −1 → Ring −3 |

## Intel ME / AMD PSP Attack Surfaces

| Surface | Description | Access Level |
|---------|-------------|-------------|
| **HECI interface** | Host↔ME communication via PCI MMIO | Ring 0 → ME (command validation) |
| **Network stack** | ME has own TCP/IP + MAC address | Remote (AMT/vPro enabled) |
| **JTAG debug** | Direct ME debug access on some platforms | Physical |
| **Firmware update** | SPI flash ME region (RSA-3072 signed) | Ring 0 → SPI flash write |
| **DAL (Dynamic App Loader)** | ME Java applet execution environment | Network/HECI |
| **AMT web server** | Intel Active Management Technology HTTP/S service | Remote (port 16992/16993) |
| **DMA engine** | ME DMA controller can read/write any host physical memory | Always on |
| **AMD PSP: SEV key management** | PSP manages SEV/SEV-ES/SEV-SNP encryption keys | Ring −1 (hypervisor) |
| **AMD PSP: fTPM** | Firmware TPM implementation in PSP | Ring 0 (TPM commands) |
| **AMD PSP: Boot firmware** | PSP validates initial boot (Platform Secure Boot) | Boot-time |

## SMM Exploitation Entry Points

| Vector | Mechanism | Prerequisites | Mitigation |
|--------|-----------|---------------|------------|
| **SMI callout** | SMI handler dereferences attacker-controlled pointer outside SMRAM | Ring 0 (write to SMI parameter buffer) | `SMM_CODE_CHK_EN`, pointer validation |
| **SMRAM cache poisoning** | Flush cache lines to load attacker data via cache line collision | Ring 0 (CLFLUSH + SMI timing) | SMRR, cache-as-hint mode |
| **TSEG bypass** | Circumvent SMRR via DMA, PCIe, or memory remap | Ring 0 + misconfigured IOMMU | IOMMU, SMRR lock |
| **Variable service attacks** | UEFI variable services (SMM_VARIABLE handler) UAF/OOB | Ring 0 (SetVariable syscall) | EDK II hardening, bounds checks |
| **SPI flash write** | Modify SMM handler code in SPI flash directly | Ring 0 (physical memory map write) | BIOS Guard, SPI write-protect |
| **Port 0xB2 trigger** | Software SMI via `outb(0xB2, command)` | Ring 0 (I/O port access) | Filter SMI commands, SMM lock |
| **PEI-phase callout** | Exploit SMM during PEI (pre-EFI initialization) | Boot-time (firmware modification) | Boot Guard, measured boot |

## Hypervisor Escape Techniques Summary

| Technique | Mechanism | Prerequisites | Example |
|-----------|-----------|---------------|---------|
| **Device emulation bug** | Overflow/UAF in QEMU device model | Code execution in VM | CVE-2015-3456 (VENOM) |
| **Virtio ring buffer** | Malicious descriptors in virtqueue | Ring 0 inside VM | CVE-2018-10938 |
| **MMIO abuse** | Malicious MMIO writes to emulated hardware | Ring 0 inside VM (can trigger from Ring 3 via `/dev/mem`) | CVE-2020-3950 |
| **Hypercall injection** | Malicious hypercall parameters | Ring 0 inside VM | CVE-2019-6974 |
| **Side channels** | L1TF, MDS, Foreshadow — speculative execution | Co-located VM | L1 Terminal Fault |
| **Hyperjacking** | Install malicious hypervisor underneath existing VMM | Ring 0 + physical access/PXE | Blue Pill, SubVirt |
| **Nested virt escape** | L2 guest escapes to L0 hypervisor | Nested virtualization enabled | Various (L1→L0) |
| **EPT/NPT manipulation** | Corrupt Extended Page Tables from host kernel | Ring 0 on host | KVM EPT bugs |

## Cross-Ring Escalation Paths

### Most Common Attack Chains

```
Ring 3 ──[CVE-2022-0847 / CVE-2021-4034]──→ Ring 0 ──[VM escape]──→ Ring −1 ──[SPI flash write]──→ Ring −2 ──[ME firmware mod]──→ Ring −3
```

| Chain | Threat Actor | Rings | Notable Example |
|-------|-------------|-------|-----------------|
| 3 → 0 → −2 | Sednit/APT28 | Phishing → LPE → UEFI bootkit | LoJax (2018) |
| 3 → 0 → −2 | Equation Group | Kernel rootkit → SPI flash VBR | GrayFish (2015) |
| 3 → 0 → −1 | Striped Fly | Supply chain → hypervisor implant | Custom hypervisor (2023) |
| 3 → 0 → Physical | Sandworm | MBR overwrite → industrial control | Stuxnet/BlackEnergy |
| 3 → 0 | Hafnium | Exchange RCE → kernel exploitation | CVE-2021-26855 chain |
| 0 → −2 | Various | Kernel driver → SMI handler exploit | LoJax stage 2 |

### Key Transition Mechanisms

| From → To | Mechanism | Instruction/Event |
|-----------|-----------|-------------------|
| Ring 3 → 0 | System call | `syscall` / `sysenter` |
| Ring 3 → 0 | Interrupt | `int 0x80` (legacy) |
| Ring 0 → 3 | Return | `sysret` / `iretq` |
| Ring 0 → −1 | VM Entry | `vmcall` (non-root → root) |
| Ring 0 → −2 | SMI | Port `0xB2` write or hardware SMI# |
| Ring −2 → 0 | RSM | `rsm` instruction |
| Ring * → −3 | HECI | Host → ME interface (PCI MMIO) |

## Key CPU Structures

| Structure | Ring | Purpose | Key Fields |
|-----------|------|---------|-----------|
| **MSRs** | 0/−1/−2 | Model-Specific Registers — CPU config | `IA32_LSTAR` (syscall entry), `IA32_STAR` (CS/SS), `IA32_EFER` (EFER), `IA32_SYSENTER_CS/EIP/ESP`, `IA32_KERNEL_GS_BASE`, `IA32_TSC_AUX` |
| **VMCS** | −1 | Virtual Machine Control Structure (Intel) | Guest/host RIP, RSP, CR0–CR4, EPTP, PIN/EXEC/EXIT controls, IO bitmaps |
| **VMCB** | −1 | Virtual Machine Control Block (AMD) | Guest/host state, intercept vectors, NPT, event injection |
| **EPT/NPT** | −1 | Extended/Nested Page Tables | Guest→host physical translation, permission bits, EPTVI |
| **SMRAM** | −2 | System Management RAM | Code at `SMBASE+0`, save state at `SMBASE+0xFE00`, stack at `SMBASE+0x10000` |
| **SMRR** | −2 | System Management Range Register | Base/mask of SMRAM region, locked by `IA32_SMRR_PHYSMASK.valid` |
| **SMM_SAVE_STATE** | −2 | CPU state save area inside SMRAM | SS, ESP, EFLAGS, CS, RIP, CR0–CR4, CR3, IDTR, GDTR, LDTR, TR |
| **IDT/GDT/LDT** | 0/3 | Descriptor tables | Gate descriptors (DPL), call gates, task gates, TSS |
| **TSS** | 0 | Task State Segment | `ss0:esp0`, `ss1:esp1`, `ss2:esp2`, IOPB, interrupt stacks |
| **Page Tables** | 0 | PML4/PDPT/PD/PT | U/S bit, NX bit, PAT, accessed/dirty bits |
| **HECI** | −3 | Host-Embedded Controller Interface | Message queue, ME command/response buffers |

## Ring-Specific Debugging Tools & Techniques

| Ring | Tools | Techniques |
|------|-------|------------|
| 3 | GDB, lldb, strace, ltrace, Valgrind, AddressSanitizer, Frida | User-mode tracing, syscall interception, memory error detection |
| 2/1 | `modify_ldt` audit, GDT/LDT dump tools | LDT/GDT structure inspection, call gate auditing (mostly historical) |
| 0 | KGDB, QEMU+GDB, crash, drgn, pahole, `perf record`, ftrace, bpftrace, eBPF | Kernel breakpoint debugging, live patching, kprobes, `/proc/kallsyms` leak analysis, KASAN/KFENCE |
| −1 | Xen debug keys, QEMU monitor, KVM tracing, Hyper-V debug, TPM attestation | VMCS integrity checks, EPT dump, virtio queue inspection, hypervisor log analysis |
| −2 | Chipsec, UEFI SCT, IBV firmware debug, SPI programmer, TPM event logs | SMI count monitoring (MSR `0x34`), SPI flash dump vs baseline, SMRAM integrity, TCG event log comparison |
| −3 | Intel MEI tools, `mei-amt-check`, JTAG/SPI flash programmer, power analysis | ME version audit, firmware hash verification, JTAG debug port monitoring, BMC log analysis |
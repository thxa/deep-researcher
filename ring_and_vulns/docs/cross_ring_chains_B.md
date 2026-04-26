# Defense-in-Depth Across CPU Rings: Comprehensive Defensive Strategy

> **Classification**: Technical Defensive Reference
> **Scope**: Ring 3 through Ring -3 — full privilege stack hardening
> **Audience**: Security engineers, platform architects, incident responders

---

## Table of Contents

1. [Comprehensive Defense Matrix](#1-comprehensive-defense-matrix)
2. [Ring-by-Ring Hardening](#2-ring-by-ring-harding)
3. [Monitoring and Detection Across Rings](#3-monitoring-and-detection-across-rings)
4. [Incident Response for Deep Exploits](#4-incident-response-for-deep-exploits)
5. [Architecture-Level Solutions](#5-architecture-level-solutions)
6. [Summary Table — Complete Ring-by-Ring Reference Card](#6-summary-table--complete-ring-by-ring-reference-card)

---

## 1. Comprehensive Defense Matrix

### Ring 3 — User Space

| Dimension | Details |
|-----------|---------|
| **Primary Threats** | Buffer overflows, ROP chains, privilege escalation (local → root), container escapes, sandbox escapes, supply chain (malicious userland binaries), format strings, use-after-free, integer overflows, XSS→RCE pivots |
| **Available Defenses** | ASLR, PIE, stack canaries, NX/DEP, RELRO, Fortify Source, seccomp-bpf, Linux capabilities, AppArmor/SELinux, cgroups/v2, user namespaces restrictions, ptrace_scope, Yama |
| **Configuration Guidance** | Enable full ASLR (`randomize_va_space=2`), compile with `-fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now`, drop capabilities (`capsh --drop=...`), set `kernel.yama.ptrace_scope=2`, use seccomp allow-lists, enforce SELinux `enforcing` or AppArmor `enforce` |
| **Detection Methods** | Auditd rules for `execve`/`ptrace`/`mprotect`, Falco anomalous syscall patterns, eBPF `execve` tracing, process ancestry monitoring, Auditd `syscall=59` filtering, filesystem integrity (AIDE/Tripwire) |
| **Incident Response** | Isolate container/host, capture process memory (`gcore`), collect audit logs, check for capability escalation (`capsh --print`), review seccomp violations, snapshot filesystem for forensics, kill malicious process tree |

### Ring 2 — I/O Privilege (Legacy / x86-specific)

| Dimension | Details |
|-----------|---------|
| **Primary Threats** | Direct hardware I/O port access, legacy device driver exploits, VGA/VBE attack surface, BIOS interrupt hooking from protected mode, DMA from misconfigured devices |
| **Available Defenses** | I/O Permission Bitmap (IOPL gating), TSS I/O port restrictions, VT-d / IOMMU for DMA isolation, kernel `iopl()` restrictions, `CONFIG_X86_IOPL_NONE=y`, strict `/dev/port` `/dev/mem` access controls |
| **Configuration Guidance** | Disable `CONFIG_X86_IOPL`, set `CONFIG_STRICT_DEVMEM=y` and `CONFIG_IO_STRICT_DEVMEM=y`, enable VT-d/IOMMU in firmware and kernel (`intel_iommu=on`), restrict `sys_iopl()` via seccomp, block `/dev/mem` access |
| **Detection Methods** | Audit I/O port access syscalls (`iopl`, `ioperm`), monitor `/dev/port` and `/dev/mem` opens, IOMMU fault logging (VT-d fault registers), dmesg filtering for DMA violations |
| **Incident Response** | Revoke I/O privileges, check IOMMU remapping tables for DMA tampering, audit kernel for malicious `iopl()` callers, inspect device firmware for implants leveraging Ring 2 access |

### Ring 1 — Kernel Services (Legacy)

| Dimension | Details |
|-----------|---------|
| **Primary Threats** | LDT/GDT manipulation for privilege escalation, call gate abuse, task register attacks (mostly historical on modern x86-64 where Ring 1 is unused) |
| **Available Defenses** | Flat kernel model (Ring 0 only on x86-64), `CONFIG_X86_64=y` eliminates separate Ring 1 usage, MMU-based isolation supersedes hardware ring gating, NX on GDT/LDT pages, microcode validation |
| **Configuration Guidance** | Run x86-64 exclusively (Ring 1 unused in long mode), disable `modify_ldt` where possible (`sysctl kernel.modify_ldt=0`), compile with `CONFIG_MODIFY_LDT_SYSCALL=n` |
| **Detection Methods** | Monitor `modify_ldt` syscalls, audit GDT/LDT structures in memory dumps, watch for unexpected segment selector values in kernel crash dumps |
| **Incident Response** | This ring is essentially deprecated on x86-64; focus on ensuring no LDT abuse path exists, check for `modify_ldt` exploitation artifacts |

### Ring 0 — Kernel / Supervisor

| Dimension | Details |
|-----------|---------|
| **Primary Threats** | LPE kernelsploits, loadable kernel module (LKM) rootkits, `/dev/mem` write exploits, netfilter/nftables UAF, io_uring bugs, BPF verifier escapes, driver exploits (GPU, USB, NIC), `/proc`/`/sys` tampering, kernel data structure corruption |
| **Available Defenses** | SMEP, SMAP, KASLR, KPTI, KASAN, KFENCE, RAP/CFI, Lockdown mode, kernel.config hardening, signed modules, `CONFIG_HARDENED_USERCOPY`, `CONFIG_RANDSTRUCT`, `CONFIG_SLUB_HARDENED`, `INIT_ON_ALLOC_DEFAULT_ON`, stackleak, `pagealloc=1` |
| **Configuration Guidance** | Enable `CONFIG_SECURITY_LOCKDOWN_LSM=y`, `CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y`, boot with `lockdown=confidentiality`, `config KASLR=y`, `CONFIG_PAGE_TABLE_ISOLATION=y`, `CONFIG_STRICT_KERNEL_RWX=y`, `CONFIG_DEBUG_RODATA=y`, `CONFIG_X86_SMAP=y`, `CONFIG_X86_SMEP=y`, sign LKMs with MOK, `sysctl kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1` |
| **Detection Methods** | eBPF monitoring (Tetragon, Falco), kmod loading audit, `/proc/kallsyms` baseline comparison, kernel integrity scanning (chkrootkit, rkhunter — limited), systemtap probes, kernel address leak detection, ftrace function graph monitoring |
| **Incident Response** | Capture `/proc/kallsyms` diff against known-good baseline, dump kernel memory, check for hidden modules (`lsmod` vs `/sys/module/`), look for inline hooks (compare kernel text against disk vmlinux), volatile memory forensics with Volatility, network artifact collection |

### Ring -1 — Hypervisor (Type 1 / VMM)

| Dimension | Details |
|-----------|---------|
| **Primary Threats** | VM escapes (VMBus, virtio, Xen PV), hypercall injection, nested virtualization exploits, MMU paravirtualization bugs, QEMU device emulation bugs (CVE-2015-5161/7504), hypervisor overlay attacks, side-channel (L1TF, MDS) |
| **Available Defenses** | Hypervisor isolation, sVirt (SELinux for VMs), KVM kernel address space isolation, Secure Encrypted Virtualization (SEV/SEV-ES/SEV-SNP), Intel TDX, VT-x EPT/NPT controls, IOMMU passthrough restrictions, cloud-hypervisor minimal VMM |
| **Configuration Guidance** | Enable SEV-SNP where hardware supports it, use `sVirt` with SELinux MCS labels per-VM, minimize QEMU device model (use `virtio` not emulated hardware), enable IOMMU (`intel_iommu=on`), disable nested virt unless required, apply hypervisor patches, use OVMF with Secure Boot |
| **Detection Methods** | Hypervisor introspection (Ether, XenAccess), VMCS/VMCB integrity checks, TPM-based attestation of guest launch state, VMI event monitoring, hypervisor audit logs (QEMU monitor, libvirt), IOMMU fault forwarding, side-channel anomaly detection |
| **Incident Response** | Live-migrate VM off compromised host, snapshot hypervisor state, inspect EPT/NPT tables for malicious remapping, audit QEMU process memory, check for nested hypervisor implants, collect libvirt/VMM logs, rebuild host from known-good image |

### Ring -2 — System Management Mode (SMM) / Firmware

| Dimension | Details |
|-----------|---------|
| **Primary Threats** | SMM rootkits (System Management Mode hijack), BIOS/UEFI bootkits, SPI flash implants, firmware supply chain implants, Boot Guard bypass, SMM code execution via SMI handlers, IPMI/BMC exploits, ThinkPwn, Intel CSME vulnerabilities |
| **Available Defenses** | Secure Boot, Measured Boot (TCG), BIOS Guard, SMM memory isolation (`SMM_FEATURES_CONTROL` lock), SPI flash write-protect, Hardware Root of Measure (TPM), Intel Boot Guard (OEM Key), UEFI capsule signing, `PRM` (Platform Runtime Mechanism), `chipsec` hardening |
| **Configuration Guidance** | Enable Secure Boot + Measured Boot, set BIOS/firmware passwords, enable `BIOS Guard`/`SPI Protection Range`, disable CSM/legacy boot, enable `DEF_SMM_FEATURE_CONTROL_LOCK`, lock SMI handlers, apply firmware security updates via UEFI capsule, run `chipsec` hardening checks |
| **Detection Methods** | TPM Measured Boot log (TCG Event Log) comparison, `chipsec` SPI flash dump vs baseline, SMI count monitoring (MSR `0x34`), SMM memory integrity checks, Boot Guard status verification via `chipsec`, ACPI table diff, NVRAM variable auditing |
| **Incident Response** | Dump SPI flash (hardware programmer + `chipsec`), compare against known-good firmware hash, analyze TCG Event Log for pre-OS tampering, check SMM handler integrity, check BIOS region for implants, reflashing from trusted source, physical TPM reset and re-attestation |

### Ring -3 — Management Engine / Hardware

| Dimension | Details |
|-----------|---------|
| **Primary Threats** | Intel ME/CSME exploits (SA-00086, SA-00118, SA-00213), AMD PSP vulnerabilities, hardware implants, side-channel attacks (Spectre, Meltdown, Foreshadow, Zombieload), CPU microcode manipulation, JTAG/Debug port access, supply chain implants (Bloomberg Supermicro-style), CPLD/FPGA bitstream tampering |
| **Available Defenses** | Intel ME patching/firmware updates, HAP bit (High Assurance Platform — ME disable), AMD PSP firmware updates, Intel PTT (firmware TPM in ME), BIOS Guard, physical security (chassis intrusion, tamper-evident seals), debug port disable (JTAG fusing), silicon root of trust, CPU microcode updates, hardware attestation |
| **Configuration Guidance** | Apply Intel ME firmware updates via OEM, set HAP bit where supported (HP/Dell enterprise systems), disable AMT/vPro if unused, update CPU microcode at boot (`intel-ucode`, `amd-ucode`), physically disable debug ports, enable TPM2.0, set chassis intrusion detection in BIOS, use measured launch for ME (if supported) |
| **Detection Methods** | Intel ME version/config audit (`mei-amt-check`), JTAG/debug port status polling, power analysis anomalies (ME consumption), TPM attestation failures, side-channel timing variance detection, hardware integrity verification (visual inspection, X-ray), CPUID/microcode revision checks, BMC audit logs |
| **Incident Response** | Reflash ME firmware from motherboard vendor, verify CPU microcode revision matches latest, physical inspection for implants, supply chain audit, replace hardware if implant is confirmed in ME, rotate all TPM-bound keys, incident containment requires hardware replacement in worst case |

---

## 2. Ring-by-Ring Hardening

### 2.1 Ring 3 — User Space Hardening

#### AppArmor / SELinux

```bash
# SELinux — enforce mode
sestatus
setenforce 1

# Make persistent
sed -i 's/SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config

# AppArmor — enforce all profiles
aa-enforce /etc/apparmor.d/*
aa-status
```

```bash
# AppArmor profile example — restrict a sensitive binary
#include <tunables/global>

/usr/bin/sensitive-app flags=(enforce) {
  # Deny network by default
  deny network,
  # Allow only specific file reads
  /etc/sensitive-app/{config,secrets} r,
  /var/log/sensitive-app/ w,
  /tmp/ rw,
  # Deny ptrace
  deny ptrace,
}
```

#### seccomp-bpf

```bash
# Docker seccomp profile — example denylist
# Drop dangerous syscalls for container workloads
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    { "names": ["execve", "fork", "ptrace", "mount", "keyctl"], "action": "SCMP_ACT_ALLOW" },
    { "names": ["process_vm_readv", "process_vm_writev"], "action": "SCMP_ACT_KILL" }
  ]
}
```

```c
// seccomp-bpf program (libseccomp)
// Strict allowlist — only permit read, write, exit, sigreturn
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
seccomp_load(ctx);
```

#### Linux Capabilities

```bash
# Drop all capabilities, add back only what's needed
capsh --drop=CAP_SYS_ADMIN --drop=CAP_NET_ADMIN \
      --drop=CAP_SYS_PTRACE --drop=CAP_SYS_MODULE \
      --drop=CAP_SYS_RAWIO --drop=CAP_DAC_OVERRIDE \
      -- -c "/usr/bin/app"

# Docker: minimal capabilities
docker run --cap-drop=ALL \
           --cap-add=CAP_NET_BIND_SERVICE \
           --cap-add=CAP_CHOWN \
           --security-opt=no-new-privileges \
           app:latest
```

#### Compiler Hardening

```bash
# Maximum hardening flags for GCC/Clang
CFLAGS="-fstack-protector-strong \
        -fPIE \
        -fstack-clash-protection \
        -fcf-protection=full \
        -D_FORTIFY_SOURCE=2 \
        -fno-delete-null-pointer-checks \
        -fno-allow-store-data-races"
LDFLAGS="-pie \
         -Wl,-z,relro \
         -Wl,-z,now \
         -Wl,-z,noexecstack \
         -Wl,-z,separate-code"

# Clang CFI (Control Flow Integrity)
CFLAGS+=" -fsanitize=cfi -flto"
```

#### ASLR and Kernel Hardening Sysctls

```bash
# /etc/sysctl.d/99-hardening.conf
kernel.randomize_va_space = 2           # Full ASLR
kernel.yama.ptrace_scope = 2           # Restrict ptrace
kernel.kptr_restrict = 2                # Hide kernel pointers
kernel.dmesg_restrict = 1               # Restrict dmesg
kernel.perf_event_paranoid = 3          # Restrict perf
kernel.kexec_load_disabled = 1          # Disable kexec
kernel.unprivileged_bpf_disabled = 1    # Disable unpriv BPF
vm.unprivileged_userfaultfd = 0         # Disable userfaultfd
fs.protected_regular = 1               # Restrict file creation
fs.protected_fifos = 2                  # Restrict FIFO writes
fs.protected_hardlinks = 1             # Restrict hardlinks
fs.protected_symlinks = 1              # Restrict symlinks
dev.tty.ldisc_autoload = 0             # No automatic line discipline loading
```

---

### 2.2 Ring 0 — Kernel Hardening

#### SMEP / SMAP

```
# CPU feature flags (check in /proc/cpuinfo)
smep    # Supervisor Mode Execution Prevention — prevents kernel from executing user-space pages
smap    # Supervisor Mode Access Prevention — prevents kernel from accessing user-space data
```

```bash
# Enforce via kernel command line (these are on by default on modern CPUs)
# /etc/default/grub
GRUB_CMDLINE_LINUX="nosmep=0 nosmap=0"
# NEVER add: nosmep nosmap (these disable the protections)
```

#### KASLR and KPTI

```bash
# /etc/default/grub
GRUB_CMDLINE_LINUX="kaslr nokaslr=0 pti=on"

# Kernel config
CONFIG_RANDOMIZE_BASE=y          # KASLR
CONFIG_PAGE_TABLE_ISOLATION=y    # KPTI (Meltdown mitigation)
```

#### CFI (Control Flow Integrity)

```bash
# Clang CFI for kernel (if compiled with Clang)
CONFIG_CFI_CLANG=y
CONFIG_CFI_PERMISSIVE=n          # Strict mode — panic on violation

# x86 CET (Control-flow Enforcement Technology) — hardware CFI
# IBT (Indirect Branch Tracking) — kernel CONFIG_X86_KERNEL_IBT=y
# SHSTK (Shadow Stack) — user-space CONFIG_X86_SHADOW_STACK=y
CONFIG_X86_KERNEL_IBT=y
CONFIG_X86_SHADOW_STACK=y
```

#### Lockdown Mode

```bash
# /etc/default/grub
GRUB_CMDLINE_LINUX="lockdown=confidentiality"

# Kernel config
CONFIG_SECURITY_LOCKDOWN_LSM=y
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y

# Lockdown levels (increasing restriction):
#   none          → No lockdown
#   integrity     → Cannot modify kernel code, no /dev/mem, no module loading
#   confidentiality → Above + no kernel pointer leak, no perf events to userspace
```

#### Kernel .config Hardening (KSPP Recommendations)

```ini
# KSPP (Kernel Self Protection Project) recommended configs
# --- Memory Protection ---
CONFIG_STRICT_KERNEL_RWX=y
CONFIG_STRICT_MODULE_RWX=y
CONFIG_HARDENED_USERCOPY=y
CONFIG_DEBUG_RODATA=y
CONFIG_RANDOMIZE_BASE=y
CONFIG_VMAP_STACK=y
CONFIG_THREAD_INFO_IN_TASK=y

# --- Heap Protection ---
CONFIG_SLUB_HARDENED=y
CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_SLAB_FREELIST_RANDOM=y
CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
CONFIG_INIT_ON_FREE_DEFAULT_ON=y

# --- Structure Layout Randomization ---
CONFIG_RANDSTRUCT=y
CONFIG_RANDSTRUCT_FULL=y

# --- Stack Protection ---
CONFIG_STACKPROTECTOR=y
CONFIG_STACKPROTECTOR_STRONG=y
CONFIG_STACKLEAK=y

# --- Misc ---
CONFIG_DEBUG_CREDENTIALS=y
CONFIG_DEBUG_NOTIFIERS=y
CONFIG_BUG_ON_DATA_CORRUPTION=y
CONFIG_PAGE_POISONING=y
CONFIG_DEBUG_WX=y
CONFIG_SCHED_STACK_END_CHECK=y

# --- Reduce Attack Surface ---
CONFIG_MODULES=n              # Disable loadable modules if possible
CONFIG_BPF_SYSCALL=y          # Keep for monitoring, but use unprivileged_bpf_disabled
CONFIG_IO_URING=n             # Disable if not needed (large attack surface)
CONFIG_COMPAT=n               # Disable compat syscalls (32-bit on 64-bit)
CONFIG_X86_X32=n              # Disable x32 ABI

# --- UBSAN for kernel ---
CONFIG_UBSAN=y
CONFIG_UBSAN_ALIGNMENT=y
CONFIG_UBSAN_BOUNDS=y

# --- KFENCE ---
CONFIG_KFENCE=y
CONFIG_KFENCE_SAMPLE_INTERVAL=100
```

```bash
# Validate running kernel config
cat /proc/config.gz | gunzip | grep -E "CONFIG_STRICT|CONFIG_HARDENED|CONFIG_RANDOMIZE|CONFIG_STACKPROTECTOR"
# Or: scripts/namespace.collisions (check KSPP compliance)
```

---

### 2.3 Ring -1 — Hypervisor Hardening

#### KVM/QEMU Hardening

```bash
# libvirt XML — harden VM definition
<domain type='kvm'>
  <features>
    <hyperv mode='custom'>
      <!-- Minimal hyper-V enlightenments only -->
    </hyperv>
  </features>
  <!-- Disable unused devices -->
  <devices>
    <!-- Use virtio, NOT emulated IDE/e1000 -->
    <disk type='file' device='disk'>
      <driver name='qemu' type='raw' cache='none' discard='unmap'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <interface type='bridge'>
      <model type='virtio'/>
    </interface>
    <!-- No USB, no floppy, no serial console unless needed -->
  </devices>
  <!-- QEMU command line hardening via <qemu:commandline> -->
  <qemu:commandline>
    <qemu:arg value='-object'/>
    <qemu:arg value='memory-backend-memfd,id=mem0,size=4096M,share=on,seal=on'/>
  </qemu:commandline>
</domain>
```

#### sVirt (SELinux for VMs)

```bash
# Verify sVirt is active
ps -eZ | grep svirt

# Each VM gets a unique MCS label: svirt_t:s0:c100,c200
# Prevents VM-to-VM cross-infection even if QEMU is compromised

# libvirt auto-assigns MCS labels per-VM
# Verify in /etc/libvirt/qemu.conf:
security_driver = "selinux"
```

#### AMD SEV / SEV-ES / SEV-SNP

```bash
# Check SEV support
cat /sys/firmware/kvm_sev/availability    # host
dmesg | grep -i sev

# Launch SEV-encrypted VM
# libvirt domain XML:
<launchSecurity>
  <type>sev</type>
  <cbitpos>47</cbitpos>
  <reducedPhysBits>1</reducedPhysBits>
  <policy>0x0003</policy>   <!-- SEV-ES enabled, no-debug -->
</launchSecurity>

# SEV-SNP adds: Cryptographic attestation, VMPL isolation, RMP (Reverse Map Table)
<launchSecurity>
  <type>sev-snp</type>
  <cbitpos>51</cbitpos>
  <reducedPhysBits>5</reducedPhysBits>
  <policy>0x30003</policy>
</launchSecurity>
```

#### Intel TDX

```bash
# Intel Trust Domain Extensions
# Provides hardware-isolated encrypted VMs (Trust Domains)
# Key properties:
#   - CPU-state encryption + integrity
#   - Memory encryption (MKTME-based)
#   - Secure EPT (SEPT)
#   - Remote attestation
# Kernel parameter: tdx=1
# Launch with: qemu -tdx ...
```

---

### 2.4 Ring -2 — Firmware / SMM Hardening

#### Secure Boot + Measured Boot

```bash
# Verify Secure Boot status
mokutil --sb-state
# Expected: SecureBoot enabled

# Check firmware Secure Boot
od -A x -t x1z /sys/firmware/efi/efivars/SecureBoot-*

# Enroll MOK (Machine Owner Key) for custom kernel
mokutil --import /path/to/MOK.der
# Reboot → MOK Manager → Enroll Key

# Measured Boot — each component hash extends TPM PCRs
# Check TCG Event Log:
cat /sys/kernel/security/tpm0/binary_bios_measurements
# Parse with:
tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements
```

#### SMM Hardening (chipsec)

```bash
# Install chipsec
pip3 install chipsec

# Check SMM protection
chipsec_main -m common.smm
chipsec_main -m common.smrr
chipsec_main -m common.bios_ts

# Check SPI flash protection
chipsec_main -m common.bios_wp
chipsec_main -m common.spi_lock

# Full platform Check
chipsec_main -m common.uefi.smm   # SMM protections
chipsec_main -m common.uefi.access  # Flash access controls
chipsec_main -m common.uefi.secboot  # Secure Boot status

# Expected output for hardened system:
# [*] SMRR is enabled and locked
# [*] BIOS Write Protect is enabled
# [*] SPI flash ranges are locked
# [*] SMM_FEATURES_CONTROL is locked
```

```bash
# Lock SMI handler configuration
# In firmware settings:
#   - Enable SMM Feature Control Lock
#   - Enable BIOS Guard (Intel)
#   - Set SPI flash write-protect ranges

# Verify from OS:
chipsec_main -m common.smm      # SMM code chk enable?
chipsec_main -m common.secboot   # Secure Boot enforced?
```

#### BIOS Guard and SPI Protection

```bash
# BIOS Guard: signed firmware update mechanism
# Prevents unauthorized SPI flash writes even from SMM
# Verified via:
chipsec_main -m common.bios_guard

# SPI Protection Ranges (PR0-PR4)
# Configure in BIOS setup — set write-protect range covering entire flash
chipsec_main -m common.spi_lock
# Should show:
# [*] SPI Flash Configuration is locked (FLOCKDN=1)
# [*] BIOS Range Protection is enabled
```

---

### 2.5 Ring -3 — Management Engine / Hardware Hardening

#### Intel ME Patching

```bash
# Check ME version
sudo apt install mei-amt-check || true
mei-amt-check

# Or use Intel CSME Detection Tool
# https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00086.html

# Apply ME firmware updates via:
#   - OEM firmware update packages (Dell Command Update, HP SPP, Lenovo System Update)
#   - Intel ME Update Tool (OEM-provided)

# Critical CVEs to patch:
#   SA-00086: Remote privilege escalation in ME (INTEL-SA-00086)
#   SA-00118: Buffer overflow in ME firmware (INTEL-SA-00118)
#   SA-00213: Privilege escalation in ME (INTEL-SA-00213)
```

#### HAP Bit (High Assurance Platform)

```bash
# HAP bit disables most ME functionality (leaves only BUP — Boot ROM)
# Usually toggled via BIOS on enterprise platforms (HP/Dell)

# Check if HAP is set:
# Method 1: chipsec
chipsec_main -m common.me

# Method 2: Read ME HAP register (platform-specific)
# On supported platforms, HAP bit at offset in ME PCI config space

# Alternative: me_cleaner (for unsupported platforms — RISKY)
# WARNING: me_cleaner can brick your system. Use only on supported platforms.
# python3 me_cleaner.py -S -t -O output_image.bin firmware_dump.bin
```

#### CPU Microcode Updates

```bash
# Check current microcode revision
cat /proc/cpuinfo | grep microcode

# Update microcode (early boot)
apt install intel-microcode    # Intel
apt install amducodefirm        # AMD

# Verify:
dmesg | grep microcode
# [    0.000000] microcode: updated early: 0x2e -> 0x38, date = 2024-XX-XX
```

#### Physical Security

```bash
# BIOS-level settings:
#   - Set firmware/BIOS password
#   - Disable boot from USB/CD unless needed
#   - Enable chassis intrusion detection
#   - Disable unused interfaces (serial, parallel)
#   - Set TPM2.0 to active

# Chassis intrusion:
# Most enterprise platforms support chassis intrusion switch
# Check: dmidecode -t 38 (or platform-specific)

# Disable JTAG/debug:
# Should be fused off in production silicon
# Verify via chipsec:
chipsec_main -m common.debug_enable
```

---

## 3. Monitoring and Detection Across Rings

### 3.1 eBPF-Based Kernel Monitoring

#### Tetragon

```yaml
# Tetragon — eBPF-based security observability and enforcement
# Install via Helm
helm install tetragon cilium/tetragon -n kube-system

# Example: monitor all execve calls
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: monitor-exec
spec:
  kprobes:
  - call: "__x64_sys_execve"
    syscall: true
    args:
    - index: 0
      type: "string"
    selectors:
    - matchNames:
      - namespace: "default"
```

```bash
# Tetragon CLI — monitor process executions
tetra getevents -o compact

# Example trace policy: block execution of /usr/bin/wget from certain contexts
# Tetragon can enforce in-kernel — no context switch to userspace
```

#### Falco

```yaml
# Falco — runtime security with eBPF driver
# /etc/falco/falco_rules.local.yaml

# Detect kernel module loading
- rule: Load Kernel Module
  desc: Detect kernel module loading
  condition: >
    evt.type = init_module or evt.type = finit_module
    and evt.arg.table = "kernel"
  output: >
    Kernel module loaded (table=%evt.arg.table name=%proc.name)
  priority: CRITICAL
  tags: [kernel, persistence]

# Detect unexpected privilege escalation
- rule: Unexpected Setuid Binary Execution
  desc: Detect execution of setuid binaries
  condition: >
    evt.type = execve and
    evt.arg.flags contains S_ISUID and
    not proc.name in (sudo, su, passwd, ping)
  output: >
    Suspicious setuid binary executed (name=%proc.name)
  priority: WARNING
  tags: [privilege_escalation]

# Detect /dev/mem access
- rule: Read Write /dev/mem
  desc: Detect /dev/mem access
  condition: >
    (evt.type = open or evt.type = openat) and
    evt.arg.flags contains O_RDWR and
    fd.name = /dev/mem
  output: >
    Process opened /dev/mem for read/write (name=%proc.name)
  priority: CRITICAL
  tags: [kernel, direct_hw_access]
```

#### Custom eBPF Monitoring

```c
// eBPF program: monitor kernel module loading
// Traces init_module and finit_module syscalls

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct event {
    u32 pid;
    u32 uid;
    char comm[64];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("kprobe/__x64_sys_finit_module")
int BPF_KPROBE(trace_module_load, int fd, const char *uargs, int flags) {
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### 3.2 TPM Measured Boot and Remote Attestation

```bash
# TPM2 Measured Boot — Extended Information
# PCR (Platform Configuration Register) allocation:
#   PCR0  — BIOS/UEFI firmware
#   PCR1  — BIOS configuration
#   PCR2  — Option ROMs
#   PCR3  — Boot loader configuration
#   PCR4  — Boot loader (GRUB)
#   PCR5  — Boot manager configuration
#   PCR6  — Kernel, initrd, kernel command line
#   PCR7  — Secure Boot policy (platform + authority certs)
#   PCR8  — GRUB command line + measured boot commands
#   PCR9  — Initrd hash
#   PCR10-15 — Available for application use

# Read all PCR values
tpm2_pcrread sha256

# Create a PCR quote (for remote attestation)
tpm2_quote -g sha256 \
  -l 0,1,2,3,4,5,6,7 \
  -q "nonce123" \
  -o quote.sig \
  -p quote.pcrs \
  -c /path/to/ek/certificate

# Remote attestation workflow:
# 1. Verifier sends nonce to attester
# 2. Attester uses TPM2_Quote to sign PCR values with Attestation Key
# 3. Verifier validates signature against known-good PCR values
# 4. If PCR values differ → tampering detected

# Keylime — Automated remote attestation
# Install:
pip3 install keylime

# Verifier configuration (keylime.conf):
[verifier]
ca_implementation = OpenSSL
enable_agent_attestation = True
requires_em = True     # Require encryption module (TPM)
```

### 3.3 Firmware Integrity Monitoring

```bash
# Method 1: chipsec SPI flash dump + hash comparison
# Dump current firmware:
chipsec_util spi dump firmware_current.bin

# Hash and compare:
sha256sum firmware_current.bin
# vs known-good firmware hash from vendor

# Method 2: UEFI variable auditing
chipsec_main -m common.uefi.access

# Method 3: Check BIOS region integrity
# Compare runtime firmware image against signed vendor image
# Some platforms store a signed copy in a protected SPI region (BIOS Guard)
chipsec_main -m common.bios_wp

# Method 4: Continuous firmware monitoring with FWUPD
fwupdmgr get-remotes
fwupdmgr refresh
fwupdmgr get-updates     # Check for firmware security updates

# Method 5: UEFI firmware parsing
# Use UEFIExtract to parse firmware images
UEFIExtract firmware_current.bin
# Look for unexpected DXE drivers, NVRAM variables, SMM modules
```

### 3.4 Hypervisor Introspection

```bash
# Xen —Inspect from Dom0 (privileged domain)
xl debug-keys h     # Dump hypervisor data
xl dmesg            # Hypervisor log
xl info             # Hypervisor configuration

# KVM — VM introspection via QEMU monitor
# Enable QMP (QEMU Machine Protocol) socket
virsh qemu-monitor-command <vm> --hmp "info tlb"     # TLB state
virsh qemu-monitor-command <vm> --hmp "info mtree"    # Memory map

# Libvirt — VMI (Virtual Machine Introspection)
# Use LibVMI for memory introspection of VMs from hypervisor
# git clone https://github.com/libvmi/libvmi.git
# Can read guest memory, walk page tables, find processes

# Cloud-specific monitoring
# AWS: Nitro hypervisor attestation via Nitro Enclaves
# Azure: vTPM-based attestation for CVMs (Confidential VMs)
# GCP: Shielded VMs with vTPM measured boot
```

### 3.5 SMI Count Monitoring

```bash
# SMI (System Management Interrupt) count indicates SMM activity
# Monitored via MSR 0x34 (IA32_SMI_COUNT)

# Read SMI count for each CPU:
for cpu in /dev/cpu/*/msr; do
    cpu_num=$(echo $cpu | cut -d/ -f4)
    count=$(rdmsr -p${cpu_num} 0x34 2>/dev/null)
    echo "CPU $cpu_num: SMI count = $count"
done

# Watch for unexpected SMI bursts (may indicate SMM rootkit activity)
# Normal desktop: ~50-200 SMIs/second (ACPI, timer, thermal)
# Rootkit activity: unusual spikes, especially during idle

# Enhanced monitoring with perf:
perf stat -e msr/smi/ -a sleep 10

# Kernel monitoring of SMI count:
# Add to /etc/sysctl.d/
dev.tty.ldisc_autoload = 0

# Script: alert on SMI anomalies
#!/bin/bash
BASELINE=$(rdmsr -p0 0x34)
sleep 60
CURRENT=$(rdmsr -p0 0x34)
DELTA=$((CURRENT - BASELINE))
if [ $DELTA -gt 60000 ]; then
    logger -p auth.alert "High SMI count: $DELTA SMIs in 60s"
fi
```

---

## 4. Incident Response for Deep Exploits

### 4.1 Detecting Ring -2/-3 Implants

#### Indicators of Compromise (IoCs)

```
Ring -2 (SMM/Firmware) IoCs:
  - SMI count anomalies (MSR 0x34)
  - TCG Event Log PCR mismatches (PCR0-PCR7)
  - Unexpected DXE drivers in firmware image
  - SMM memory region size changes
  - SMBIOS/IPMI manipulation
  - Secure Boot policy changes
  - SPI flash write attempts outside of firmware update windows
  - Unexpected NVRAM variables (especially in secure boot namespace)
  - Boot time anomalies (additional SMM handlers increase boot time)

Ring -3 (ME/Hardware) IoCs:
  - Intel ME firmware version mismatch with expected
  - Unexpected network listeners on ME port (16992/16993/623/664)
  - Unexplained network traffic from BMC/IPMI
  - ME power consumption anomalies
  - Side-channel timing anomalies (persistent across reboots)
  - TPM attestation failures without explanation
  - CPU microcode revision regression
  - Unexpected debug port activity (JTAG/ITP)
```

#### Detection Methodology

```bash
# Step 1: Check SMI count (Ring -2 indicator)
for cpu in /sys/devices/system/cpu/cpu*/topology/thread_siblings_list; do
    id=$(cat $cpu | cut -d, -f1)
    echo "CPU $id: SMI count = $(rdmsr -p${id} 0x34)"
done

# Step 2: Verify TPM Measured Boot (Ring -2 detection)
tpm2_pcrread sha256
# Compare against known-good baseline
# Any mismatch in PCR0-7 indicates firmware/boot tampering

# Step 3: Check Intel ME status (Ring -3)
# Use mei-amt-check or Intel CSME Detection Tool
mei-amt-check

# Step 4: Dump and analyze firmware (detailed below)
chipsec_util spi dump suspicious_firmware.bin
sha256sum suspicious_firmware.bin

# Step 5: Scan for unexpected listeners
ss -tlnp | grep -E '16992|16993|623|664'
# ME ports: 16992 (AMT SOAP), 16993 (AMT SOAP/TLS), 623 (RMCP/IPMI), 664 (AMT redirect)

# Step 6: Check microcode revision
grep microcode /proc/cpuinfo | sort -u

# Step 7: BMC/IPMI audit (server platforms)
ipmitool mc info
ipmitool lan print      # Check network configuration
ipmitool user list       # Check for unexpected users
ipmitool sel list        # System event log
```

### 4.2 Firmware Forensics Methodology

#### Step-by-Step Firmware Analysis

```bash
# Phase 1: Acquisition
# ----------

# Option A: Software-based acquisition (may be compromised if Ring -2 infiltrated)
chipsec_util spi dump firmware_image.bin

# Option B: Hardware programmer (RECOMMENDED for forensic integrity)
# Use CH341A SPI programmer + clip
#   flashrom -p ch341a_spi -r firmware_hardware.bin

# Verify acquisition integrity:
sha256sum firmware_image.bin

# Phase 2: Initial Triage
# ----------

# Extract firmware sections:
UEFIExtract firmware_image.bin

# Identify all UEFI modules:
find firmware_image.dump/ -name "*.efi" -o -name "*.dxes" | sort

# Check for known-bad hashes:
# UEFITool (UEFI firmware image parser): https://github.com/LongSoft/UEFITool
# Known-bad DXE/SMM driver database

# Phase 3: SMM Analysis (Ring -2 specific)
# ----------

# Find all SMM modules:
find firmware_image.dump/ -path "*Smm*" -name "*.efi"

# Disassemble SMM entry points:
# Use Ghidra with EFI loader

# Check SMM handler registration:
# SMM drivers register handlers via EFI_SMM_SW_DISPATCH2_PROTOCOL
# Look for: gEfiSmmSwDispatch2ProtocolGuid

# Phase 4: NVRAM Analysis
# ----------

# Extract NVRAM variables:
chipsec_util uefi var > nvram_dump.txt

# Check for:
#   - Unexpected Secure Boot keys (db, dbx, KEK, PK)
#   - Boot order modifications
#   - Driver health variables

# List Secure Boot keys:
chipsec_util uefi keys > sb_keys.txt

# Phase 5: Differential Analysis
# ----------

# Compare extracted firmware against vendor-provided firmware
# $ diff <(UEFIExtract vendor_firmware.bin -e) <(UEFIExtract firmware_image.bin -e)
# Look for:
#   - Modified DXE/SMM drivers
#   - Additional executable sections in PE/COFF
#   - Relocated SMM handlers (SMRR base changes)
#   - Unexpected boot script entries
```

### 4.3 SPI Flash Analysis

```bash
# SPI Flash regions (typical Intel):
#   Region 0: Descriptor (flash descriptor — contains region layout)
#   Region 1: BIOS (UEFI firmware)
#   Region 2: ME (Intel Management Engine firmware)
#   Region 3: GBE (Gigabit Ethernet firmware)
#   Region 4: PDR (Platform Data Region)

# Dump SPI flash regions:
chipsec_util spi list              # List regions
chipsec_util spi read descriptor  # Read flash descriptor
chipsec_util spi read bios bios_region.bin
chipsec_util spi read me me_region.bin

# Analyze flash descriptor for unusual region mappings:
chipsec_util spi info

# Check SPI flash write protection:
chipsec_main -m common.bios_wp

# Expected on hardened system:
#   BIOS Write Protect: enabled
#   BIOS Lock Enable: set
#   SPI Protected Ranges: configured

# Verify BIOS region integrity:
chipsec_main -m common.uefi.secboot
# Should show:
#   Secure Boot: enabled
#   PK: present
#   KEK: present
#   db: present (authorized signatures)
#   dbx: present (forbidden hashes)
```

### 4.4 Memory Dump Analysis for SMM Rootkits

```bash
# Phase 1: Acquire volatile memory
# ----------

# Option A: Linux /dev/mem (if lockdown allows)
dd if=/dev/mem of=memory_dump.bin bs=1M count=4096

# Option B: LiME (Linux Memory Extractor) — preferred
# insmod lime.ko "path=/mnt/memory_dump.lime format=lime"

# Option C: WinPmem (Windows)
# winpmem_mini_x64.exe memory_dump.raw

# Phase 2: SMM Memory Region Identification
# ----------

# SMM memory is at SMRR (System Management Range Register) base:
# CPU MSR 0xC82 (IA32_SMRR_PHYSBASE) and 0xC83 (IA32_SMRR_PHYSMASK)
# Read SMRR:
rdmsr 0xC82    # SMRR base (bits 12-31 = physical base, bit type field)
rdmsr 0xC83    # SMRR mask (valid bit, size specification)

# Phase 3: SMM Rootkit Signatures
# ----------

# Known SMM rootkit patterns (from research):
#   - ThinkPwn (RING -2): modifies SMI handler dispatch table
#   - bytecode_smrr: uses SMRR to hide SMM code from OS
#   - LightEater: DXE driver that escalates to SMM

# Search for indicators:
# 1. Unexpected SMI handlers in SMRAM
# 2. Modified EFI_SMM_SW_DISPATCH2_PROTOCOL entries
# 3. SMM code that touches OS memory without proper validation
# 4. Hooked SMI entry points
# 5. Shadow copies of SMM modules (backups for persistence)

# Phase 4: Volatility Framework Analysis
# ----------

# Volatility 3 — Linux memory forensics
vol -f memory_dump.lime linux.bash          # Bash history
vol -f memory_dump.lime linux.pslist        # Process list
vol -f memory_dump.lime linux.check_syscall  # Syscall table integrity
vol -f memory_dump.lime linux.elfs          # Loaded ELF binaries

# Check for kernel rootkits (Ring 0):
vol -f memory_dump.lime linux.check_modules # Hidden kernel modules
vol -f memory_dump.lime linux.check_idt     # IDT hooking

# For SMM analysis, use Volatility with custom SMM profile:
# This requires platform-specific SMM memory layout knowledge
# See: chipsec/modules/common/smm.py for SMRAM mapping
```

---

## 5. Architecture-Level Solutions

### 5.1 Control Flow Integrity (CFI) at Every Level

```
┌──────────────────────────────────────────────────────────────┐
│                    CFI ACROSS ALL RINGS                       │
├──────────┬───────────────────────────────────────────────────┤
│ Ring 3   │ Clang CFI (-fsanitize=cfi), CET IBT+SHSTK,       │
│          │ Shadow Stack, LLVM-type CFI, Pointer Auth (PAC)   │
├──────────┼───────────────────────────────────────────────────┤
│ Ring 0   │ Clang CFI for kernel (CONFIG_CFI_CLANG),          │
│          │ Intel CET-IBT (CONFIG_X86_KERNEL_IBT),             │
│          │ RAP (PaX/grsecurity), kCFI (GCC),                  │
│          │ Shadow Stack (CONFIG_X86_SHADOW_STACK)              │
├──────────┼───────────────────────────────────────────────────┤
│ Ring -1  │ Hypervisor CFI (KVM vmx/vmx exit path validation),│
│          │ VMCS integrity checks, SEV-SNP attestation          │
├──────────┼───────────────────────────────────────────────────┤
│ Ring -2  │ SMM CFI (SMM codechk), BIOS Guard signed updates, │
│          │ SmmCpuFeatureLib dispatch validation,              │
│          │ SMRAM memory isolation (SMRR + TSEG)                │
├──────────┼───────────────────────────────────────────────────┤
│ Ring -3  │ Intel ME firmware signing, Intel Boot Guard,       │
│          │ ACM (Authenticated Code Module) signature checks,  │
│          │ Hardware microcode signature verification          │
└──────────┴───────────────────────────────────────────────────┘
```

#### Ring 3 CFI (User Space)

```bash
# Clang CFI
clang -fsanitize=cfi -flto -fvisibility=hidden app.c

# Intel CET (Control-flow Enforcement Technology)
# IBT (Indirect Branch Tracking) — ENDBR at indirect branch targets
# SHSTK (Shadow Stack) — hardware-maintained return address stack
# Compile with:
gcc -fcf-protection=full app.c     # IBT + SHSTK
gcc -fcf-protection=check app.c    # SHSTK only
gcc -mharden-plt=all app.c         # Harden PLT entries (ARM)

# ARM Pointer Authentication (PAC)
# gcc -mbranch-protection=standard app.c
# Adds PAC instructions to function prologues/epilogues
```

#### Ring 0 CFI (Kernel)

```bash
# Clang-based kernel CFI
CONFIG_CFI_CLANG=y
CONFIG_CFI_PERMISSIVE=n          # Strict: panic on violation

# x86 IBT (Indirect Branch Tracking)
CONFIG_X86_KERNEL_IBT=y
# Inserts ENDBR64 at all valid indirect branch targets
# Prevents JOP/COP attacks via indirect branches

# Shadow Stack (CET SHSTK)
CONFIG_X86_SHADOW_STACK=y
# Hardware shadow stack for kernel return addresses

# GCC kCFI (kernel CFI) — alternative
# Available in kernel 6.1+, uses type hashes
CONFIG_KCFI=y

# x86 RAP (grsecurity/PaX) — commercial
# Type-based CFI with function prologue hashing
# Most comprehensive kernel CFI available
```

### 5.2 Memory Encryption

#### AMD SME/SEV/SEV-ES/SEV-SNP

```
┌──────────────────────────────────────────────────────────────┐
│              AMD MEMORY ENCRYPTION HIERARCHY                  │
├──────────┬───────────────────────────────────────────────────┤
│ SME      │ System Memory Encryption                          │
│          │ - Encrypts main memory with single key           │
│          │ - Transparent to OS/apps                          │
│          │ - Key managed by AMD-SP (Secure Processor)        │
│          │ - Enabled: mem_encrypt=on kernel parameter        │
├──────────┼───────────────────────────────────────────────────┤
│ SEV      │ Secure Encrypted Virtualization                   │
│          │ - Per-VM encryption keys                          │
│          │ - VM memory encrypted from hypervisor             │
│          │ - Hypervisor can still see memory (SEV-ES needed)  │
│          │ - 16 VM keys + 1 DMA key (EPYC)                  │
│          │ - Attack: hypervisor can modify VM memory         │
├──────────┼───────────────────────────────────────────────────┤
│ SEV-ES   │ SEV + Encrypt State                               │
│          │ - CPU register state encrypted on VMEXIT           │
│          │ - Hypervisor cannot see VM register state           │
│          │ - VMSA (VM Save Area) encrypted                    │
│          │ - Attack: replay-based attacks still possible      │
├──────────┼───────────────────────────────────┬───────────────┤
│ SEV-SNP  │ SEV + Secure Nested Paging        │ MITIGATIONS   │
│          │ - Cryptographic attestation of     │               │
│          │   guest launch state               │ + Replay      │
│          │ - Reverse Map Table (RMP) prevents │ + Data        │
│          │   hypervisor page-level attacks    │   corruption  │
│          │ - VMPL (VM Privilege Levels) for   │ + Replay      │
│          │   in-guest isolation               │   encryption  │
│          │ - Hardware-enforced integrity      │ + Corrupted   │
│          │   checks on guest memory           │   data        │
│          │ - VMPCK (VM Permission Check Key)  │ + RMP-based   │
│          │                                    │   mitigation  │
└──────────┴────────────────────────────────────┴───────────────┘
```

```bash
# Enable AMD SME on host
# /etc/default/grub
GRUB_CMDLINE_LINUX="mem_encrypt=on"

# For KVM with SEV guests:
# /etc/default/grub
GRUB_CMDLINE_LINUX="kvm_amd.sev=1"

# Verify SEV support:
cat /sys/firmware/kvm_sev/availability

# Launch SEV-SNP VM (libvirt XML):
<launchSecurity>
  <type>sev-snp</type>
  <cbitpos>51</cbitpos>
  <reducedPhysBits>5</reducedPhysBits>
  <policy>0x30003</policy>
</launchSecurity>
```

#### Intel TDX / MKTME

```
┌──────────────────────────────────────────────────────────────┐
│            Intel MEMORY ENCRYPTION HIERARCHY                  │
├──────────┬───────────────────────────────────────────────────┤
│ MKTME   │ Multi-Key Total Memory Encryption                 │
│         │ - Per-process or per-VM memory encryption keys    │
│         │ - Uses MKTME keys (up to 256 keys on Ice Lake+)  │
│         │ - Requires BIOS support + key allocation           │
│         │ - Transparent to applications                      │
├──────────┼───────────────────────────────────────────────────┤
│ TDX     │ Trust Domain Extensions                           │
│         │ - Fully encrypted VMs (Trust Domains)              │
│         │ - CPU state encrypted (like SEV-ES)                │
│         │ - Secure EPT (Extended Page Tables) isolation      │
│         │ - Remote attestation (TDX Quote generation)        │
│         │ - Protected by Intel TDX Module (Ring -1.5?)       │
│         │ - VM-to-VM isolation: cryptographic + hardware      │
│         │ - Attack surface: minimal TDX Module code path      │
├──────────┼───────────────────────────────────────────────────┤
│ SGX     │ Software Guard Extensions                          │
│         │ - Enclaves: isolated memory regions (EPC)          │
│         │ - Enclave memory encrypted + integrity-protected    │
│         │ - Remote attestation via IAS/DCAP                  │
│         │ - Not VM-level — application-level isolation        │
└──────────┴───────────────────────────────────────────────────┘
```

```bash
# Enable MKTME on host
# /etc/default/grub
GRUB_CMDLINE_LINUX="mktme_on=on"

# TDX guest launch (requires TDX-capable host):
# Use TDX-specific QEMU build
qemu-system-x86_64 \
  -accel kvm \
  -tdx \
  -m 4G \
  -smp 2 \
  -drive file=tdx-guest.qcow2,if=virtio \
  ...

# TDX attestation:
# Guest generates TDX Quote → Verifier checks against Intel TDX Signing Key
```

### 5.3 Confidential Computing Future

```
┌─────────────────────────────────────────────────────────────────┐
│             CONFIDENTIAL COMPUTING LANDSCAPE                     │
├────────────────────┬────────────────────────────────────────────┤
│ Technology         │ Status / Notes                              │
├────────────────────┼────────────────────────────────────────────┤
│ AMD SEV-SNP        │ GA — Production ready (EPYC Milan+, Genoa) │
│ Intel TDX          │ GA — Sapphire Rapids+ (4th Gen Xeon)       │
│ ARM CCA            │ GA — ARMv9.2 Realm Management Extensions  │
│ IBM SE             │ GA — Secure Execution on z16               │
│ Intel SGX          │ GA — Enclave-level, not VM-level          │
│ AWS Nitro Enclaves │ GA — AWS-specific enclave                  │
│ CCEL (Confidential │ Draft — Unified attestation event log      │
│   Computing Event  │ (TCG PC Client)                             │
│   Log)             │                                              │
├────────────────────┼────────────────────────────────────────────┤
│ RISC-V PMP         │ Emerging — Physical Memory Protection     │
│ CXL TEE            │ Future — CXL3 for TEE memory disaggregation│
│ GPU TEEs           │ Emerging — Intel TEE-GPU, NVIDIA CC        │
│ (NVIDIA CC,        │                                              │
│  Intel TDX-GPU)    │                                              │
│ FPGA TEE           │ Research — Programmable TEEs in FPGA       │
└────────────────────┴────────────────────────────────────────────┘

Key architectural principles for future CVM (Confidential Virtual Machine):
  1. Hardware-rooted trust: TPM/PSP/TDX Module as trust anchor
  2. Measured launch: Every component hash-chained to PCR
  3. Remote attestation: Verifiable proof of launch integrity
  4. Encrypted memory: Per-VM encryption keys (no hypervisor access)
  5. Encrypted state: Registers + memory + page tables all encrypted
  6. Minimal TCB: Smallest possible trusted computing base
  7. Side-channel resistance: Ongoing mitigation (Spectre-class)
```

### 5.4 Hardware Root of Trust

#### TPM 2.0 and Intel PTT

```bash
# TPM 2.0 — Hardware-based root of trust
# Check TPM presence:
ls /dev/tpm*             # /dev/tpm0, /dev/tpmrm0
cat /sys/class/tpm/tpm0/tpm_version_major  # TPM version

# Intel PTT (Platform Trust Technology) — firmware TPM in ME
# Integrated into Intel ME starting with Broadwell
# Provides TPM 2.0 functionality in firmware (no discrete TPM needed)

# TPM capabilities hierarchy:
#   1. Storage Root Key (SRK) — created on TPM initialization
#   2. Endorsement Key (EK) — burned at manufacturing (unique per TPM)
#   3. Attestation Identity Key (AIK) — derived from EK for attestation
#   4. Sealing keys — bind data to PCR values

# Create attestation key:
tpm2_createak -C 0x01 -c ak_ctx -G rsa -g sha256 -s rsassa

# Generate quote (for remote attestation):
tpm2_quote -C ak_ctx -l sha256:0,1,2,3,4,5,6,7 -q nonce123 -o quote.sig -p quote.pcrs

# Seal secret to PCR values (only unseal when system is in known state):
echo "my-secret" | tpm2_seal -C 0x01 -i secret_data.bin -c seal_ctx -L sha256:0,1,2,7

# Measured Boot with TPM:
# Each boot component extends a PCR:
#   PCR0 ← BIOS firmware hash
#   PCR1 ← BIOS configuration
#   PCR2 ← Option ROMs
#   PCR3 ← Boot configuration
#   PCR4 ← GRUB bootloader
#   PCR5 ← GRUB configuration
#   PCR6 ← Kernel + initrd
#   PCR7 ← Secure Boot policy
#   PCR8+ ← Application-defined (IMA, dm-verity, etc.)

# IMA (Integrity Measurement Architecture) extends PCRs:
# /etc/ima/ima-policy:
#   measure func=BPRM_CHECK
#   measure func=FILE_MMAP mask=MAY_EXEC
#   measure func=MODULE_CHECK
#   appraise func=BPRM_CHECK appraise_type=imasig
```

```
┌──────────────────────────────────────────────────────────────┐
│                HARDWARE ROOT OF TRUST CHAIN                   │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐     │
│  │  Ring -3: Intel ME/PSP → Boot Guard/Platform Secure │     │
│  │           Boot → ACM (Authenticated Code Module)    │     │
│  └──────────────┬──────────────────────────────────────┘     │
│                 │ Verifies                                   │
│  ┌──────────────▼──────────────────────────────────────┐     │
│  │  Ring -2: UEFI Firmware → Secure Boot (PK→KEK→db)   │     │
│  │           Measured Boot (PCR extends to TPM)         │     │
│  └──────────────┬──────────────────────────────────────┘     │
│                 │ Verifies                                   │
│  ┌──────────────▼──────────────────────────────────────┐     │
│  │  Ring 0: Kernel → IMA measurement → dm-verity       │     │
│  │           Kernel signature (if Secure Boot)          │     │
│  └──────────────┬──────────────────────────────────────┘     │
│                 │ Verifies                                   │
│  ┌──────────────▼──────────────────────────────────────┐     │
│  │  Ring 3: Applications → seccomp + AppArmor/SELinux   │     │
│  │           Container image signing (cosign)          │     │
│  └─────────────────────────────────────────────────────┘     │
│                                                               │
│  Each layer verifies the next → Complete trust chain          │
│  TPM provides measurement storage + remote attestation        │
└──────────────────────────────────────────────────────────────┘
```

---

## 6. Summary Table — Complete Ring-by-Ring Reference Card

| Ring | Name | Privilege Level | What Runs Here | Key Defenses | Notable CVEs | Key Exploitation Technique | Detection Method |
|------|------|----------------|----------------|-------------|-------------|---------------------------|-----------------|
| 3 | User Space | CPL=3 | Applications, containers, user daemons | ASLR, PIE, stack canaries, NX, RELRO, seccomp-bpf, AppArmor/SELinux, capabilities, `ptrace_scope`, Fortify Source, FORTIFY, `-fcf-protection` | CVE-2023-4911 (Looney Tunables), CVE-2021-4034 (PwnKit), CVE-2016-0728, CVE-2019-18634 | Buffer overflow → ROP chain → privilege escalation; `sudo`/`pkexec` LPE; dynamic linker abuse | Auditd, Falco, eBPF monitoring, seccomp violations, process ancestry |
| 2 | I/O Privilege | IOPL | Legacy hardware I/O (mostly unused on x86-64) | IOPB, VT-d/IOMMU, `STRICT_DEVMEM`, `ioport` restrictions | Rare; mostly historical | Direct port I/O abuse, DMA via misconfigured IOMMU, `/dev/mem` write → kernel corruption | IOMMU fault logs, `/dev/port` audit, `iopl` syscall monitoring |
| 1 | Kernel Services | CPL=1 (unused on x86-64) | Nothing (deprecated on x86-64) | Flat kernel model (Ring 0 only), LDT restrictions | CVE-2022-2588 (cls_route LDT), historical call gate attacks | `modify_ldt` abuse for local privilege escalation | `modify_ldt` syscall auditing, GDT/LDT integrity checks |
| 0 | Kernel | CPL=0 | Linux kernel, drivers, LSM, BPF verifier, io_uring | SMEP, SMAP, KASLR, KPTI, KASAN, KFENCE, CFI (IBT/kCFI/RAP), Lockdown, `RANDSTRUCT`, `SLUB_HARDENED`, stackleak, `STRICT_KERNEL_RWX`, signed modules | CVE-2022-2602 (io_uring), CVE-2023-0398 (nftables), CVE-2021-4059 (PMU), CVE-2021-22555 (netfilter), CVE-2023-32233 (nf_tables UAF) | LPE via UAF/double-free in kernel subsystems; BPF verifier escape; io_uring race conditions; netfilter UAF; `/dev/mem` write | eBPF (Tetragon/Falco), kallsyms baseline, module loading audit, kprobes, Volatility memory forensics |
| -1 | Hypervisor | VMX Root / -1 | KVM, Xen, Hyper-V, VMware hypervisor | sVirt/SELinux MCS, SEV/SEV-ES/SEV-SNP, TDX, IOMMU, VT-x EPT, minimal device model, nested virt disable | CVE-2015-5161 (QEMU heap overflow), CVE-2015-7504 (QEMU rat buffer overflow), CVE-2018-12382, CVE-2022-21123 (L1TF), CVE-2019-12258 (VMSA off-core) | VM escape via emulated device bugs; hypercall injection; VMBus/virtio race; L1TF/MDS side channels; QEMU device model exploitation | VMI (LibVMI), VMCS integrity, TPM attestation, IOMMU fault forwarding, QEMU process auditing |
| -2 | SMM / Firmware | SMM (-2) | UEFI/BIOS, SMI handlers, Option ROMs, BMC/IPMI | Secure Boot, Measured Boot, BIOS Guard, SPI flash write-protect, SMRR, `SMM_FEATURES_CONTROL` lock, SMM Code chk | CVE-2017-9683 (ThinkPwn), CVE-2018-12130 (RIDL), LightEater, LoJax, Vault 7 EFI, CVE-2019-11098 (SMM call-out) | SMI handler exploit → SMM code execution; SPI flash implant; UEFI bootkit (LoJax); BIOS Guard bypass; Option ROM shadowing | chipsec SPI dump vs baseline, TCG Event Log PCR comparison, SMI count monitoring, SMM handler integrity, NVRAM audit |
| -3 | ME / Hardware | ME/PSP (-3) | Intel ME/CSME, AMD PSP, BMC, CPU microcode, CPLD/FPGA | ME firmware signing, HAP bit, BIOS Guard, CPU microcode updates, JTAG fusing, chassis intrusion, TPM/PTT, silicon RoT | INTEL-SA-00086 (ME remote root), SA-00118 (ME buffer overflow), SA-00213 (ME LPE), AMD PSP (various), Spectre/Meltdown/L1TF/MDS class | ME network exploitation (AMT); firmware supply chain implant; JTAG debug access; side-channel (Spectre-class); CPLD bitstream modification | ME version audit, JTAG port status, TPM attestation failure, power analysis, CPUID/microcode revision check, hardware inspection |

---

## Appendix A: Quick-Reference Hardening Checklist

```markdown
## Ring 3 Hardening Checklist
- [ ] ASLR enabled (randomize_va_space=2)
- [ ] PIE + stack canary + RELRO + NX compiled
- [ ] seccomp-bpf allowlist for all services
- [ ] SELinux enforcing / AppArmor enforcing
- [ ] Capabilities dropped to minimum (capsh --drop=ALL + add back)
- [ ] ptrace_scope=2 (Yama LSM)
- [ ] no-new-privileges for container workloads
- [ ] Fortify Source=2 + stack-protector-strong

## Ring 0 Hardening Checklist
- [ ] SMEP + SMAP enabled (check /proc/cpuinfo)
- [ ] KASLR enabled (CONFIG_RANDOMIZE_BASE=y)
- [ ] KPTI enabled (CONFIG_PAGE_TABLE_ISOLATION=y)
- [ ] Lockdown mode = confidentiality
- [ ] kernel.dmesg_restrict=1
- [ ] kernel.kptr_restrict=2
- [ ] kernel.unprivileged_bpf_disabled=1
- [ ] Kernel .config per KSPP recommendations
- [ ] Signed kernel modules (MOK)
- [ ] CFI enabled (CONFIG_CFI_CLANG or CONFIG_X86_KERNEL_IBT)
- [ ] INIT_ON_ALLOC/INIT_ON_FREE enabled
- [ ] SLUB_HARDENED enabled

## Ring -1 Hardening Checklist
- [ ] sVirt SELinux MCS labels per-VM
- [ ] SEV-SNP or TDX enabled for sensitive VMs
- [ ] Minimal QEMU device model (virtio only)
- [ ] Nested virtualization disabled
- [ ] IOMMU enabled (VT-d/AMD-Vi)
- [ ] Hypervisor patches current
- [ ] Secure Boot for VMs (OVMF)

## Ring -2 Hardening Checklist
- [ ] Secure Boot enabled + Measured Boot
- [ ] BIOS Guard enabled
- [ ] SPI flash write-protect ranges set
- [ ] SMM_FEATURES_CONTROL locked
- [ ] CSM/legacy boot disabled
- [ ] chipsec hardening pass complete
- [ ] Firmware up to date

## Ring -3 Hardening Checklist
- [ ] Intel ME firmware patched (SA-00086, SA-00118, SA-00213)
- [ ] HAP bit set (or ME disabled) if supported
- [ ] AMT/vPro disabled if not used
- [ ] CPU microcode updated to latest
- [ ] JTAG/debug ports fused/disabled
- [ ] Chassis intrusion detection enabled
- [ ] TPM 2.0 active + measured boot configured
- [ ] BMC/IPMI hardened (unique passwords, network isolated)
```

---

## Appendix B: Cross-Ring Exploit Chain Detection

```
┌─────────────────────────────────────────────────────────────────┐
│         CROSS-RING EXPLOIT CHAIN DETECTION MODEL                │
│                                                                  │
│  Ring 3 → Ring 0 → Ring -1 → Ring -2                            │
│  ┌─────┐   ┌─────┐    ┌──────┐    ┌──────┐                     │
│  │ LPE │──▶│Root │───▶│ VM  │───▶│ SMM  │──▶ ...                │
│  │Bug  │   │kit  │    │Esc. │    │Root  │                       │
│  └─────┘   └─────┘    └──────┘    └──────┘                     │
│                                                                  │
│  Detection at each boundary:                                     │
│                                                                  │
│  R3→R0:  seccomp alert + auditd execve + Falco anomalous        │
│  R0→R-1: kernel module load + kallsyms change + KASLR leak      │
│  R-1→R-2: VM escape pattern + unexpected VMEXIT + vTPM failure  │
│  R-2→R-3: SMI count spike + PCR mismatch + SPI flash change    │
│                                                                  │
│  Correlation: time-series analysis across all ring monitors      │
│  SIEM integration: forward all events with ring-level tagging   │
│  Playbooks: ring-specific response + cross-ring escalation       │
└──────────────────────────────────────────────────────────────────┘
```

### Cross-Ring Correlation Rules

```yaml
# Falco correlation rule: Ring 3 → Ring 0 escalation
- rule: Privilege Escalation Chain Detected
  desc: Detect Ring 3 to Ring 0 escalation via kernel exploit
  condition: >
    (evt.type = execve and evt.arg.flags contains S_ISUID) and
    proc.pname in (sudo, su, pkexec) and
    not proc.name in (allowed_setuid_binaries)
  output: >
    Potential Ring 3→0 escalation: setuid binary executed
    (user=%user.name parent=%proc.pname command=%proc.name)
  priority: CRITICAL

# eBPF-based Ring boundary crossing detection
# Monitor: syscall → kernel → VMEXIT → SMI transitions
# Alert on rapid fire transitions indicating exploit chain
```

---

## Appendix C: Key References

| Resource | Description |
|----------|-------------|
| KSPP (Kernel Self Protection Project) | https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project |
| chipsec | https://github.com/chipsec/chipsec |
| lockdown LSM | https://www.kernel.org/doc/html/latest/security/index.html |
| AMD SEV SNP | https://developer.amd.com/sev/ |
| Intel TDX | https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html |
| Tetragon | https://github.com/cilium/tetragon |
| Falco | https://falco.org/ |
| Keylime (TPM Attestation) | https://keylime.dev/ |
| UEFI Forum Specs | https://uefi.org/specifications |
| NIST SP 800-193 (Platform Firmware Resiliency) | https://csrc.nist.gov/publications/detail/sp/800-193/final |
| INTEL-SA-00086 Detection Tool | https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00086.html |
| CVE-2021-4034 (PwnKit) | https://nvd.nist.gov/vuln/detail/CVE-2021-4034 |
| LoJax (UEFI Bootkit) | ESET Research, 2018 |
| ThinkPwn (SMM) | https://github.com/Cr4sh/ThinkPwn |
| Spectre/Meltdown | https://spectreattack.com/ |

---

*Document generated as a comprehensive defensive reference for security engineers. All techniques should be tested in controlled environments before production deployment. Ring -2 and -3 forensics require specialized hardware and should be performed by trained professionals.*
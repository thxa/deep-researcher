# Part 10b: Kernel Hardening & Defense Strategies — Operational Defense and Detection

## Table of Contents

1. [Detecting Kernel Exploitation Attempts](#1-detecting-kernel-exploitation-attempts)
2. [Kernel Exploit Detection Heuristics](#2-kernel-exploit-detection-heuristics)
3. [eBPF-Based Runtime Security Monitoring](#3-ebpf-based-runtime-security-monitoring)
4. [Integrity Verification](#4-integrity-verification)
5. [Kernel Vulnerability Management](#5-kernel-vulnerability-management)
6. [Operational Hardening: Sysctl Security Settings](#6-operational-hardening-sysctl-security-settings)
7. [Practical Sysctl Settings Reference](#7-practical-sysctl-settings-reference)
8. [Container Runtime Security and Kernel Isolation](#8-container-runtime-security-and-kernel-isolation)
9. [Exploit Prediction and Prioritization Frameworks](#9-exploit-prediction-and-prioritization-frameworks)
10. [Building a Kernel Security Program](#10-building-a-kernel-security-program)

---

## 1. Detecting Kernel Exploitation Attempts

Detecting kernel exploitation in progress is fundamentally different from detecting
userspace attacks. The kernel operates at the highest privilege level (ring 0 on x86),
and an attacker who achieves code execution in kernel context has, by definition,
already bypassed the primary trust boundary. Detection must therefore operate at
multiple layers: below the kernel (hypervisor/hardware), within the kernel itself
(audit subsystem, tracing, LSM hooks), and from userspace agents that observe
kernel-exposed telemetry.

### 1.1 Linux Audit Subsystem (`auditd`)

The Linux Audit Framework (auditd) is the kernel's native event-logging mechanism for
security-relevant operations. It hooks into the syscall entry/exit paths, filesystem
operations, and security-module decision points to produce structured log records.

**Key capabilities for exploit detection:**

```
# Monitor all execve calls (process execution)
-a always,exit -F arch=b64 -S execve -k exec_monitor

# Detect module loading (insmod, modprobe)
-a always,exit -F arch=b64 -S init_module -S finit_module -k module_load
-a always,exit -F arch=b64 -S delete_module -k module_unload

# Monitor privilege escalation via setuid/setgid
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k priv_escalation
-a always,exit -F arch=b64 -S setresuid -S setresgid -k priv_escalation

# Monitor mount operations (namespace escapes)
-a always,exit -F arch=b64 -S mount -S umount2 -k mount_ops

# Monitor ptrace (process injection, debugging)
-a always,exit -F arch=b64 -S ptrace -k ptrace_access

# Monitor namespace creation (unshare, clone with CLONE_NEW*)
-a always,exit -F arch=b64 -S unshare -k namespace_creation
-a always,exit -F arch=b64 -S clone -F a0&0x7e020000 -k namespace_clone

# Monitor access to sensitive kernel interfaces
-w /proc/kcore -p r -k proc_kcore_read
-w /dev/mem -p rw -k devmem_access
-w /dev/kmem -p rw -k devkmem_access
-w /proc/kallsyms -p r -k kallsyms_read

# Monitor modifications to critical files
-w /etc/sudoers -p wa -k sudoers_modification
-w /etc/passwd -p wa -k passwd_modification
-w /etc/shadow -p wa -k shadow_modification
-w /sbin/insmod -p x -k module_tools
-w /sbin/modprobe -p x -k module_tools
```

**Limitations:** auditd operates within the kernel and can be tampered with by an
attacker who has already gained kernel code execution. It also generates substantial
log volume, requiring careful tuning and robust log forwarding infrastructure.

### 1.2 Kernel Ring Buffer Monitoring (`dmesg`)

The kernel log (accessible via `dmesg` or `/dev/kmsg`) contains critical diagnostic
information that can reveal exploitation attempts:

- **KASAN (Kernel Address Sanitizer) reports:** Out-of-bounds access and use-after-free
  detections in instrumented kernels
- **UBSAN (Undefined Behavior Sanitizer) reports:** Integer overflows, shift
  out-of-range, and alignment violations
- **BUG/WARNING/OOPS messages:** Unexpected code paths triggered by exploitation
  attempts
- **Soft/Hard lockup reports:** May indicate kernel exploitation causing infinite loops
- **Page fault reports at unusual addresses:** Kernel null-pointer dereferences or
  controlled page faults
- **Audit messages:** SELinux/AppArmor denials that may indicate exploitation attempts
- **RCU stall warnings:** Can indicate exploitation disrupting normal scheduling

```bash
# Continuous monitoring of kernel log for security events
dmesg -w | grep -E '(BUG|WARNING|OOPS|KASAN|UBSAN|Call Trace|general protection fault|unable to handle|audit|segfault)'
```

### 1.3 `/proc` and `/sys` Filesystem Monitoring

Several `/proc` entries provide real-time kernel state information:

| Path | Security Relevance |
|------|-------------------|
| `/proc/modules` | Currently loaded kernel modules |
| `/proc/kallsyms` | Kernel symbol addresses (information disclosure) |
| `/proc/kcore` | Raw kernel memory in ELF format |
| `/proc/<pid>/maps` | Memory mappings per process |
| `/proc/<pid>/status` | Process credentials (UID/GID/capabilities) |
| `/proc/<pid>/ns/` | Namespace membership |
| `/proc/sys/kernel/tainted` | Kernel taint flags (modules, crashes, etc.) |
| `/sys/kernel/security/` | LSM state information |

**Taint flag monitoring** is particularly valuable. The kernel taint mask
(`/proc/sys/kernel/tainted`) is a bitmask that tracks events that compromise
kernel integrity:

| Bit | Meaning |
|-----|---------|
| 0 | Proprietary module loaded |
| 2 | Module force-loaded |
| 3 | SMP with non-SMP-safe module |
| 4 | Module force-unloaded |
| 6 | User-requested taint |
| 7 | Machine check exception |
| 9 | Kernel warning (WARN_ON) |
| 11 | Module from staging tree |
| 12 | Out-of-spec ACPI table |
| 13 | Module signature failure |
| 15 | Livepatch applied |
| 16 | Auxiliary taint (vendor) |

### 1.4 Perf and Ftrace for Anomaly Detection

The Linux kernel's built-in tracing infrastructure can be repurposed for security
monitoring:

```bash
# Trace all syscalls made by a specific process
perf trace -p <pid> -e 'syscalls:*'

# Monitor function calls related to credential changes
echo 'commit_creds' > /sys/kernel/debug/tracing/set_ftrace_filter
echo function > /sys/kernel/debug/tracing/current_tracer
echo 1 > /sys/kernel/debug/tracing/tracing_on
cat /sys/kernel/debug/tracing/trace_pipe

# Trace kernel module operations
perf trace -e 'module:*'

# Monitor mmap operations with executable permissions
perf trace -e 'mmap' --filter 'prot & 0x4'
```

**Kprobes** can be used to dynamically instrument specific kernel functions:

```bash
# Set a kprobe on commit_creds to detect privilege changes
echo 'p:kprobes/cred_change commit_creds uid=%di->uid.val' > \
    /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/events/kprobes/cred_change/enable
```

---

## 2. Kernel Exploit Detection Heuristics

Detection heuristics attempt to identify exploitation behavior rather than specific
exploits. These approaches generalize across vulnerability classes and can detect
zero-day exploitation.

### 2.1 Unusual Privilege Transitions

The most reliable indicator of successful kernel exploitation is an unauthorized
privilege escalation. In a normal system, the following transitions are well-defined
and rare:

**Credential changes to watch:**
- UID/GID transition from non-zero to 0 (root) without going through
  `setuid`/`su`/`sudo`
- Capability set expansion without a corresponding privileged binary execution
- Process gaining `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_NET_ADMIN`, or
  `CAP_SYS_MODULE` without authorization
- Credentials changing in a process that didn't exec a setuid binary

**Detection approach:**

```c
/*
 * Conceptual detection: hook commit_creds() and compare old vs new
 * credentials. Alert if:
 * 1. euid changes from non-zero to zero
 * 2. No setuid binary was execve'd in this syscall chain
 * 3. The calling process was not su/sudo/login
 */
```

At the eBPF/tracing layer, this can be expressed as:

```
# Tetragon TracingPolicy for credential change detection
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: detect-privilege-escalation
spec:
  kprobes:
  - call: "commit_creds"
    syscall: false
    args:
    - index: 0
      type: "cred"
    selectors:
    - matchActions:
      - action: Post
        rateLimit: "1m"
```

### 2.2 Suspicious Memory Access Patterns

Kernel exploits follow recognizable memory access patterns:

**Heap spray indicators:**
- Rapid allocation of many identically-sized objects through specific subsystems
  (msg_msg via `msgsnd`, pipe buffers, keyring structures)
- High-frequency `sendmsg`/`recvmsg` syscalls with specific buffer sizes matching
  kernel slab sizes (64, 128, 192, 256, 512, 1024 bytes)
- Many `add_key`/`keyctl` operations in rapid succession

**Stack pivot indicators:**
- RSP/ESP register value outside the normal kernel stack range for the current task
- Stack pointer pointing into user-mapped memory (should be caught by SMAP/SMEP)

**ROP/JOP chain indicators:**
- Instruction pointer at unusual function offsets (not function entries)
- Rapid sequence of returns without corresponding calls (detectable via LBR/Intel PT)

**User/kernel boundary violations:**
- Kernel code executing from user-mapped pages (SMEP violation)
- Kernel data access to user-mapped pages (SMAP violation)
- These are hardware-enforced on modern CPUs and generate immediate faults

### 2.3 Anomalous Syscall Patterns

Certain syscall sequences are strongly correlated with exploitation:

| Pattern | Potential Exploit |
|---------|------------------|
| `unshare(CLONE_NEWUSER)` followed by `mount` | User namespace escape attempt |
| Rapid `sendmsg`/`recvmsg` with `SCM_RIGHTS` | File descriptor table manipulation |
| `userfaultfd` + concurrent syscalls | Race condition exploitation (TOCTOU) |
| `io_uring_setup` + unusual `SQE` patterns | io_uring subsystem exploitation |
| `bpf(BPF_PROG_LOAD)` with unusual instructions | eBPF verifier bypass attempts |
| `ptrace(PTRACE_POKEDATA)` on pid 1 or kthread | Process injection into privileged processes |
| `mmap` with `MAP_FIXED` at low addresses | Null-pointer dereference exploitation |
| `prctl(PR_SET_NAME)` to known tool names | Exploitation tool evasion (process renaming) |

### 2.4 Kernel Object Integrity Checks

Runtime checks on kernel data structures can detect post-exploitation modifications:

- **Syscall table integrity:** Compare current syscall table entries against known-good
  values (rootkit detection)
- **IDT/GDT integrity:** Interrupt descriptor table modifications indicate deep
  kernel compromise
- **Function pointer validation:** Verify critical function pointers (e.g., in
  `file_operations`, `seq_operations`) point to legitimate kernel text
- **Credential structure validation:** Verify `task_struct->cred` pointers reference
  valid `cred` structures within expected slab caches
- **Module list consistency:** Compare `/proc/modules` with actual module list traversal
  to detect hidden modules

Tracee (by Aqua Security) implements several of these checks as built-in detection
events:
- `hooked_syscall` -- detects syscall table hooking
- `hooked_seq_ops` -- detects `/proc` file operations hooking
- `hidden_kernel_module` -- detects modules hidden from `/proc/modules`
- `proc_fops_hooking` -- detects proc filesystem function pointer tampering

---

## 3. eBPF-Based Runtime Security Monitoring

eBPF (extended Berkeley Packet Filter) has become the dominant technology for kernel
runtime security monitoring. By running sandboxed programs within the kernel, eBPF
tools achieve deep observability without requiring kernel module loading or source
modifications.

### 3.1 Cilium Tetragon

**Project:** [github.com/cilium/tetragon](https://github.com/cilium/tetragon)
**Maintainer:** Isovalent / Cilium community (CNCF)
**Architecture:** eBPF programs attached to kprobes, tracepoints, and LSM hooks

Tetragon is a runtime security enforcement and observability tool that performs
filtering, blocking, and event reaction directly in eBPF within the kernel, avoiding
expensive context switches to userspace.

**Key capabilities:**

- **Process execution monitoring:** Full process lifecycle tracking with parent/child
  relationships and command-line arguments
- **File integrity monitoring:** Detect reads/writes to sensitive files using kprobes on
  VFS functions
- **Network observability:** TCP/UDP connection tracking with process attribution
- **Capabilities monitoring:** Track capability checks and privilege operations
- **Runtime enforcement:** Kill processes or send signals in response to policy violations
  directly from the kernel (before syscall completion)
- **Kubernetes-aware:** Understands pods, namespaces, and workload identities

**Example TracingPolicy -- Detect kernel module loading:**

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: monitor-kernel-modules
spec:
  kprobes:
  - call: "do_init_module"
    syscall: false
    args:
    - index: 0
      type: "module"
    selectors:
    - matchActions:
      - action: Post
```

**Example TracingPolicy -- Detect writes to /etc/shadow:**

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: file-integrity-shadow
spec:
  kprobes:
  - call: "security_file_open"
    syscall: false
    args:
    - index: 0
      type: "file"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "/etc/shadow"
      matchActions:
      - action: Post
```

**Architectural advantage:** Tetragon hooks deep in the kernel where data structures
cannot be manipulated by userspace applications, avoiding common issues with syscall
tracing where data can be incorrectly read, maliciously altered by attackers, or
missing due to page faults and other user/kernel boundary issues (TOCTOU attacks).

### 3.2 Falco

**Project:** [github.com/falcosecurity/falco](https://github.com/falcosecurity/falco)
**Maintainer:** Falco community (CNCF Graduated project)
**Architecture:** Kernel driver (eBPF probe or kernel module) + userspace rules engine

Falco is a cloud-native runtime security tool that detects abnormal behavior and
potential threats by parsing Linux syscalls at runtime and asserting them against
a rules engine.

**Default driver:** Modern eBPF probe using CO-RE (Compile Once, Run Everywhere)
paradigm. Legacy options include a classic eBPF probe (deprecated) and a kernel
module.

**Built-in detection rules cover:**

- Privilege escalation using privileged containers
- Namespace changes using tools like `setns`
- Read/writes to well-known directories (`/etc`, `/usr/bin`, `/usr/sbin`)
- Unexpected network connections or socket mutations
- Shell execution within containers (`sh`, `bash`, `csh`, `zsh`)
- Kernel module loading/unloading
- Symlink creation and ownership/mode changes
- Mutations to coreutils, login binaries, and shadowutil executables

**Example Falco rule -- Detect container escape attempt:**

```yaml
- rule: Detect Container Escape via Privileged Operation
  desc: Detect attempts to escape container isolation
  condition: >
    evt.type in (setns, unshare) and
    container.id != host and
    not proc.name in (allowed_namespace_tools)
  output: >
    Namespace manipulation detected in container
    (user=%user.name command=%proc.cmdline container=%container.name
     image=%container.image.repository ns_type=%evt.arg.ns_type)
  priority: CRITICAL
  tags: [container, escape, mitre_privilege_escalation]
```

**Example Falco rule -- Detect kernel symbol address leak:**

```yaml
- rule: Read Kernel Symbols
  desc: Detect attempts to read kernel symbol addresses
  condition: >
    open_read and
    (fd.name = /proc/kallsyms or
     fd.name = /proc/kcore or
     fd.name = /boot/System.map*) and
    not proc.name in (expected_kernel_tools)
  output: >
    Sensitive kernel file read (user=%user.name command=%proc.cmdline
     file=%fd.name container=%container.name)
  priority: WARNING
  tags: [kernel, information_disclosure]
```

**Falco ecosystem:**
- **Falcosidekick:** Forwards Falco alerts to 60+ destinations (Slack, PagerDuty,
  Elasticsearch, AWS Security Hub, etc.)
- **Falcoctl:** CLI tool for managing rules and plugins
- **Plugin system:** Extends beyond syscalls to CloudTrail, Kubernetes audit logs,
  Okta events, and more

### 3.3 Tracee (Aqua Security)

**Project:** [github.com/aquasecurity/tracee](https://github.com/aquasecurity/tracee)
**Architecture:** eBPF-based with "everything is an event" design philosophy

Tracee provides both security observability and threat detection from a single tool.
It differs from alternatives by treating all data -- from raw syscalls to high-level
security detections -- as events in a unified pipeline.

**Event coverage:**
- 400+ system calls for comprehensive monitoring
- Network events including DNS, HTTP, and packet analysis
- 30+ built-in security detection signatures
- Container events with native Kubernetes integration

**Notable built-in security events (unique to Tracee):**

| Event | Description |
|-------|-------------|
| `syscall_table_hooking` | Detects modifications to the kernel syscall table |
| `hooked_seq_ops` | Detects hooking of `/proc` seq_operations structures |
| `hidden_kernel_module` | Detects modules absent from `/proc/modules` list |
| `proc_fops_hooking` | Detects proc filesystem function pointer tampering |
| `suspicious_syscall_source` | Detects syscalls from unexpected code regions |
| `stack_pivot` | Detects stack pointer manipulation (exploit technique) |
| `fileless_execution` | Detects execution from memory (memfd_create, etc.) |
| `proc_mem_code_injection` | Detects code injection via `/proc/<pid>/mem` |
| `ptrace_code_injection` | Detects code injection via ptrace |
| `dirty_pipe_splice` | Specifically detects CVE-2022-0847 exploitation |
| `ftrace_hook` | Detects ftrace-based function hooking |

**Forensic capabilities:**
- Network traffic capture for detailed post-incident analysis
- Binary collection for malware investigation
- Memory dumps for advanced forensics
- File artifact collection for compliance auditing

**Example Tracee policy:**

```yaml
apiVersion: tracee.aquasecurity.com/v1beta1
kind: Policy
metadata:
  name: kernel-security-policy
spec:
  scope:
  - global
  rules:
  - event: syscall_table_hooking
    filters: []
  - event: hidden_kernel_module
    filters: []
  - event: hooked_syscall
    filters: []
  - event: stack_pivot
    filters: []
  - event: fileless_execution
    filters: []
```

### 3.4 Comparison Matrix

| Feature | Tetragon | Falco | Tracee |
|---------|----------|-------|--------|
| **CNCF Status** | Incubating (via Cilium) | Graduated | N/A (Aqua) |
| **eBPF Driver** | CO-RE eBPF | CO-RE eBPF (default) | CO-RE eBPF |
| **Syscall Coverage** | Via TracingPolicy | ~400 syscalls | 400+ syscalls |
| **In-kernel Enforcement** | Yes (kill, signal) | No (alert-only) | No (alert-only) |
| **K8s Integration** | Native (Cilium) | Via plugins | Native |
| **Rootkit Detection** | Via custom policies | Limited | Built-in events |
| **Custom Policy Language** | TracingPolicy YAML | Falco rules (YAML) | Rego + YAML |
| **Forensic Artifacts** | No | No | Yes (pcap, binaries) |
| **Overhead** | Low (in-kernel filtering) | Moderate | Moderate |
| **Configuration Complexity** | Moderate (kprobe knowledge needed) | Low (pre-built rules) | Low-Moderate |

---

## 4. Integrity Verification

Integrity verification mechanisms ensure that the kernel, its modules, and the
root filesystem have not been tampered with. These form the foundation of a
"verified boot" or "measured boot" chain of trust.

### 4.1 Secure Boot (UEFI)

UEFI Secure Boot establishes a chain of trust from firmware to bootloader to kernel:

```
Firmware (ROM) --> Shim bootloader --> GRUB2 --> vmlinuz --> initramfs --> root
   |                   |                |          |
   PK/KEK            Signed by        Signed     Signed
   (Platform Key)    Microsoft or     by distro  modules
                     distro key       key        only
```

**Key database hierarchy:**
- **PK (Platform Key):** Top-level key, typically OEM-controlled. Authorizes KEK changes.
- **KEK (Key Exchange Key):** Authorizes changes to the db/dbx databases.
- **db (Signature Database):** Contains trusted certificates/hashes for bootloaders and
  kernels.
- **dbx (Forbidden Signature Database):** Contains revoked certificates/hashes.

**Verification on Linux:**

```bash
# Check if Secure Boot is enabled
mokutil --sb-state

# List enrolled keys
mokutil --list-enrolled

# Check if kernel is in lockdown mode (enforced by Secure Boot)
cat /sys/kernel/security/lockdown
# Output: [none] integrity confidentiality

# Verify Secure Boot state from kernel
dmesg | grep -i "secure boot"
```

**Kernel Lockdown Mode:** When Secure Boot is active, the kernel lockdown LSM
restricts operations that could compromise kernel integrity:

- **Integrity mode:** Blocks features that allow userspace to modify the running kernel
  (e.g., `/dev/mem`, `/dev/kmem`, `/dev/port`, kexec with unsigned images, writing
  to MSRs, direct PCI BAR access)
- **Confidentiality mode:** Additionally blocks features that allow extracting
  confidential kernel data (e.g., `/proc/kcore`, BPF read of kernel memory,
  perf access)

### 4.2 Kernel Module Signing

The kernel module signing facility cryptographically signs modules during installation
and verifies signatures upon loading. This prevents loading of unauthorized or
tampered modules.

**Configuration options:**

```
CONFIG_MODULE_SIG=y                    # Enable module signature verification
CONFIG_MODULE_SIG_FORCE=y              # Reject unsigned/invalid modules (restrictive)
CONFIG_MODULE_SIG_ALL=y                # Automatically sign all modules at build time
CONFIG_MODULE_SIG_SHA512=y             # Use SHA-512 for signing
CONFIG_MODULE_SIG_KEY="certs/signing_key.pem"  # Signing key location
CONFIG_SYSTEM_TRUSTED_KEYS="my_certs.pem"      # Additional trusted certificates
```

**Supported signing algorithms:** RSA (4096-bit recommended), NIST P-384 ECDSA,
and NIST FIPS-204 ML-DSA (post-quantum). Hash algorithms include SHA-2 and SHA-3
families (256, 384, 512 bit).

**Key management best practices:**
1. Generate keys on a dedicated, air-gapped signing machine
2. Destroy the private key after signing, or store in an HSM/PKCS#11 token
3. Use `CONFIG_MODULE_SIG_FORCE=y` in production to enforce signature verification
4. Use different keys per kernel configuration to prevent cross-loading
5. Enable `CONFIG_MODVERSIONS=y` to add ABI version checks in addition to signatures

**Manual signing:**

```bash
# Sign a module with a specific key
scripts/sign-file sha512 kernel-signkey.priv kernel-signkey.x509 module.ko

# Verify a module has a signature
hexdump -C module.ko | tail -3
# Look for: "~Module signature appended~."
```

**Runtime enforcement:**

```bash
# Disable all module loading after boot
echo 1 > /proc/sys/kernel/modules_disabled

# This is a one-way operation: once set to 1, modules can neither be loaded
# nor unloaded, and the toggle cannot be set back to 0
```

### 4.3 dm-verity

dm-verity is a Device-Mapper target that provides transparent integrity checking
of block devices using cryptographic digests. It is read-only and designed for
verified boot scenarios.

**How it works:**

dm-verity constructs a Merkle hash tree over the entire block device. Each leaf
node contains the cryptographic hash of one data block. Intermediate nodes contain
the hash of their children. The root hash is trusted (e.g., embedded in a signed
kernel command line or verified by the bootloader).

```
                        [ root hash ]          <- Trusted anchor
                       /    . . .    \
              [entry_0]                [entry_1]
             /  . . .  \               . . .    \
    [entry_0_0]  ...  [entry_0_127]   ...  [entry_1_127]
      / ... \           /   . . .  \           /        \
  blk_0 ... blk_127  blk_16256 ... blk_16383 ...     blk_32767
```

**On read:** Each data block's hash is computed and verified against the tree. If
verification fails up to the root, the I/O fails -- detecting any on-disk tampering.

**Setup example:**

```bash
# Create verity hash tree
veritysetup format /dev/sda1 /dev/sda2
# Output: Root hash: 4392712ba01368e...

# Activate verity device
veritysetup create vroot /dev/sda1 /dev/sda2 \
    4392712ba01368efdf14b05c76f9e4df0d53664630b5d48632ed17a137f39076

# Or via dmsetup directly
dmsetup create vroot --readonly --table \
    "0 2097152 verity 1 /dev/sda1 /dev/sda2 4096 4096 262144 1 sha256 \
    4392712ba01368efdf14b05c76f9e4df0d53664630b5d48632ed17a137f39076 \
    1234000000000000000000000000000000000000000000000000000000000000"
```

**Error handling options:**

| Option | Behavior |
|--------|----------|
| `ignore_corruption` | Log and continue (forensic mode) |
| `restart_on_corruption` | Reboot the system |
| `panic_on_corruption` | Kernel panic (for kexec/kdump capture) |

**Forward Error Correction (FEC):** dm-verity supports Reed-Solomon FEC to recover
from corruption without failing the I/O, while still verifying the recovered data
cryptographically.

**Root hash signature verification:** With `CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG`,
the root hash itself can be validated against a PKCS#7 signature using keys in the
kernel's built-in trusted keyring.

**Use cases:**
- Android Verified Boot (AVB) -- protects system, vendor, and boot partitions
- ChromeOS verified boot -- entire rootfs is dm-verity protected
- Container image integrity in read-only deployments
- IoT and embedded device firmware verification

### 4.4 IMA/EVM (Integrity Measurement Architecture / Extended Verification Module)

IMA provides a file-level integrity framework built into the kernel:

- **IMA-measurement:** Maintains a runtime measurement list (hash log) of files
  accessed, anchored to TPM PCR values
- **IMA-appraisal:** Verifies file integrity against stored reference hashes
  before allowing access (stored in `security.ima` extended attributes)
- **EVM:** Protects the integrity of file metadata (security extended attributes)
  using HMAC or digital signatures

```bash
# IMA policy example: measure and appraise all executables
echo "measure func=BPRM_CHECK" > /sys/kernel/security/ima/policy
echo "appraise func=BPRM_CHECK" >> /sys/kernel/security/ima/policy
echo "measure func=MODULE_CHECK" >> /sys/kernel/security/ima/policy
echo "appraise func=MODULE_CHECK" >> /sys/kernel/security/ima/policy

# View current measurement list
cat /sys/kernel/security/ima/ascii_runtime_measurements
```

### 4.5 Integrity Verification Chain Summary

```
Hardware Root of Trust (TPM / Secure Element)
    |
    v
UEFI Secure Boot (PK -> KEK -> db verifies Shim/GRUB)
    |
    v
Bootloader verifies kernel image (vmlinuz signature)
    |
    v
Kernel verifies modules (CONFIG_MODULE_SIG_FORCE)
    |
    v
dm-verity verifies root filesystem (Merkle hash tree)
    |
    v
IMA/EVM verifies individual files (per-file hashes/signatures)
    |
    v
Runtime: LSM policies (SELinux/AppArmor) enforce MAC
    |
    v
Runtime: eBPF monitoring (Tetragon/Falco/Tracee) detects anomalies
```

---

## 5. Kernel Vulnerability Management

### 5.1 Tracking Kernel CVEs

**Primary sources:**

| Source | URL | Coverage |
|--------|-----|----------|
| NVD (NIST) | nvd.nist.gov | All CVEs, CVSS scores |
| kernel.org security | kernel.org/pub/linux/kernel/ | Official advisories |
| CVE Details | cvedetails.com | Searchable database |
| Linux kernel CVE list | git.kernel.org (Documentation/process/CVE.rst) | Kernel-specific |
| Distro security trackers | (e.g., security-tracker.debian.org) | Distro-specific status |
| CISA KEV catalog | cisa.gov/known-exploited-vulnerabilities-catalog | Known exploited |

**Kernel-specific CVE tracking challenges:**
- The Linux kernel receives hundreds of CVEs annually
- Many CVEs affect code paths that are not compiled or reachable in a specific
  configuration
- Subsystem-level triage is essential: a CVE in the Bluetooth stack is irrelevant
  to a server with no Bluetooth hardware
- Backport status varies significantly across distribution kernels

**Recommended tracking workflow:**

```
1. Ingest CVE feeds (NVD API, distro advisories, CISA KEV)
        |
        v
2. Filter by kernel version and configuration
   - Parse CONFIG_ options from /boot/config-$(uname -r)
   - Compare against CVE-affected subsystems/functions
        |
        v
3. Assess exploitability
   - Check EPSS score (see Section 9)
   - Check if proof-of-concept exists
   - Check CISA KEV for known exploitation
   - Evaluate local attack surface (is the vulnerable interface exposed?)
        |
        v
4. Prioritize based on risk
   - CVSS Base Score + Temporal Score
   - EPSS probability
   - Asset criticality
   - Compensating controls in place
        |
        v
5. Remediate
   - Kernel update (reboot required)
   - Livepatch (no reboot)
   - Virtual patch (eBPF policy, sysctl)
   - Accept risk (with documentation)
```

### 5.2 Patching Strategies

#### 5.2.1 Traditional Kernel Updates

Full kernel updates require a system reboot, creating a window of vulnerability
between patch availability and application. Strategies to minimize this window:

- **Automated patching pipelines:** Use tools like `kexec` for fast reboots,
  reducing downtime from minutes to seconds
- **Rolling updates in clusters:** Cordon, drain, update, and re-enable nodes
  in Kubernetes or other orchestration platforms
- **Maintenance windows:** Scheduled, predictable update cadences (e.g., monthly
  kernel updates aligned with distro release cycles)

#### 5.2.2 Kernel Livepatching

Livepatching redirects function calls at runtime without requiring a reboot.
The Linux kernel's built-in livepatching facility (`CONFIG_LIVEPATCH`) uses ftrace
to redirect function execution to patched implementations.

**How it works:**
1. A livepatch module contains replacement function implementations
2. The module registers with the livepatch subsystem via `klp_enable_patch()`
3. The system enters a "transition state" where tasks converge to the patched state
4. Stack checking verifies it's safe to switch each task (no affected functions on stack)
5. When all tasks have transitioned, the patch is fully active

**Consistency model:** Livepatching uses a per-task consistency model combining:
- Stack trace checking of sleeping tasks (primary, most effective)
- Kernel exit switching (task switches when returning to userspace)
- Idle loop switching (for swapper/idle tasks)

**Monitoring livepatching:**

```bash
# Check livepatch status
cat /sys/kernel/livepatch/*/enabled
cat /sys/kernel/livepatch/*/transition

# Check per-task patch state
cat /proc/<pid>/patch_state
# -1 = no transition in progress
#  0 = unpatched
#  1 = patched

# Force transition (use with extreme caution)
echo 1 > /sys/kernel/livepatch/<patch>/force
```

**Commercial livepatch services:**
- **Canonical Livepatch Service** (Ubuntu)
- **Red Hat kpatch** (RHEL)
- **SUSE Live Patching**
- **Oracle Ksplice**
- **CloudLinux KernelCare**
- **TuxCare**

**Limitations:**
- Only functions with ftrace instrumentation can be patched (`-pg` compiler flag)
- Functions implementing ftrace itself cannot be patched
- Kretprobes using ftrace conflict with livepatched functions
- Complex patches requiring data structure changes may not be livepatchable
- Forced transitions can cause instability; they permanently disable module removal

#### 5.2.3 Virtual Patching

When a kernel update or livepatch is not immediately available, compensating controls
can reduce exposure:

```bash
# Example: Mitigate a user namespace vulnerability by disabling unprivileged namespaces
sysctl -w kernel.unprivileged_userns_clone=0

# Example: Mitigate io_uring vulnerabilities
sysctl -w kernel.io_uring_disabled=2

# Example: Block module loading to prevent LKM-based exploits
sysctl -w kernel.modules_disabled=1

# Example: Use seccomp to block vulnerable syscalls at the process level
# (Applied via container runtime or systemd service configuration)
```

---

## 6. Operational Hardening: Sysctl Security Settings

The `/proc/sys/` filesystem exposes hundreds of tunable kernel parameters. The
following sections document security-critical settings organized by defensive
objective.

### 6.1 Information Disclosure Prevention

These settings restrict what information the kernel exposes to unprivileged users,
making exploitation harder by denying attackers the address information they need.

```bash
# Restrict kernel pointer exposure in /proc and logs
# 0 = hash pointers (default), 1 = restrict to CAP_SYSLOG, 2 = always zeros
kernel.kptr_restrict = 2

# Restrict dmesg access to CAP_SYSLOG holders
kernel.dmesg_restrict = 1

# Restrict perf_event access
# -1 = allow all, 0 = disallow ftrace, 1 = disallow CPU events, 2 = disallow kernel profiling
kernel.perf_event_paranoid = 3  # (some distros support 3 = deny all unprivileged)

# Restrict access to kernel profiling
kernel.perf_event_paranoid = 2  # (standard kernels; 2 = deny kernel profiling)

# Disable kexec (prevents loading replacement kernels)
kernel.kexec_load_disabled = 1
```

### 6.2 Attack Surface Reduction

```bash
# Disable unprivileged user namespaces (major exploit vector)
# Available on Debian/Ubuntu kernels; upstream uses LSM controls
kernel.unprivileged_userns_clone = 0

# Disable unprivileged eBPF (prevents verifier bypass exploits)
kernel.unprivileged_bpf_disabled = 1

# Disable io_uring completely (significant attack surface)
# 0 = allow all, 1 = require group/CAP_SYS_ADMIN, 2 = disable completely
kernel.io_uring_disabled = 2

# Disable SysRq key combinations (prevents physical/console attacks)
kernel.sysrq = 0

# Disable module loading (one-way, set after boot)
# kernel.modules_disabled = 1

# Restrict core dumps (prevent credential/key leakage)
fs.suid_dumpable = 0

# Restrict BPF JIT to root
net.core.bpf_jit_harden = 2
```

### 6.3 Memory Protection

```bash
# Full ASLR: randomize mmap base, stack, VDSO, and heap
kernel.randomize_va_space = 2

# Restrict access to /dev/mem and /dev/kmem
# (Typically via CONFIG options rather than sysctl)

# Protected symlinks: prevent symlink attacks in world-writable directories
fs.protected_symlinks = 1

# Protected hardlinks: prevent hardlink attacks
fs.protected_hardlinks = 1

# Protected FIFOs: prevent FIFO attacks in world-writable sticky directories
fs.protected_fifos = 2

# Protected regular files: prevent regular file attacks in sticky directories
fs.protected_regular = 2
```

### 6.4 Network Hardening

```bash
# Disable IP forwarding (unless acting as router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Enable TCP SYN cookies (SYN flood protection)
net.ipv4.tcp_syncookies = 1

# Disable source routing (prevents IP spoofing attacks)
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Enable reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects (prevents MITM routing attacks)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0

# Don't send ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Ignore broadcast ICMP (Smurf attack prevention)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Enable bad error message protection
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Log martian packets (impossible source addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable TCP timestamps (fingerprinting prevention, trade-off with PAWS)
# net.ipv4.tcp_timestamps = 0  # Consider carefully; needed for PAWS
```

### 6.5 Process and Execution Hardening

```bash
# Restrict ptrace to parent processes only (Yama LSM)
# 0 = classic ptrace permissions
# 1 = restricted (parent only)
# 2 = admin-only attachment
# 3 = no ptrace at all
kernel.yama.ptrace_scope = 2

# Limit maximum number of PID values (defense-in-depth for PID exhaustion)
kernel.pid_max = 65536

# Panic on kernel oops (forces reboot rather than running compromised)
kernel.panic_on_oops = 1
kernel.panic = 10  # Reboot 10 seconds after panic

# Limit oops count before panic
kernel.oops_limit = 5
```

---

## 7. Practical Sysctl Settings Reference

### 7.1 Complete Hardened Configuration

The following is a comprehensive `/etc/sysctl.d/99-hardened.conf` suitable for
production servers. Each setting includes rationale and potential impact.

```bash
###############################################################################
# KERNEL HARDENING SYSCTL CONFIGURATION
# Apply with: sysctl --system
###############################################################################

#=============================================================================
# 1. INFORMATION DISCLOSURE PREVENTION
#=============================================================================

# kernel.kptr_restrict
# Controls exposure of kernel addresses via %pK format specifier
# 0 = hash pointers (default)
# 1 = hide from users without CAP_SYSLOG (check at read time)
# 2 = always hide regardless of privileges
# IMPACT: May break debugging tools; no impact on normal operations
kernel.kptr_restrict = 2

# kernel.dmesg_restrict
# Controls access to kernel log ring buffer via dmesg(8)
# 0 = unrestricted (default)
# 1 = require CAP_SYSLOG
# IMPACT: Unprivileged users cannot run dmesg; no impact on syslog/journald
kernel.dmesg_restrict = 1

# kernel.perf_event_paranoid
# Controls unprivileged access to perf_event_open()
# -1 = allow everything
#  0 = disallow ftrace function tracepoint
#  1 = disallow CPU event access
#  2 = disallow kernel profiling (recommended minimum)
# IMPACT: Unprivileged users cannot profile kernel; may affect developers
kernel.perf_event_paranoid = 2

# kernel.kexec_load_disabled
# Disables kexec_load/kexec_file_load syscalls
# 0 = enabled (default)
# 1 = disabled (one-way toggle)
# IMPACT: Cannot load kexec/kdump kernel after setting; set after kdump config
kernel.kexec_load_disabled = 1

#=============================================================================
# 2. ATTACK SURFACE REDUCTION
#=============================================================================

# kernel.unprivileged_bpf_disabled
# Controls unprivileged access to bpf() syscall
# 0 = unrestricted
# 1 = disabled for unprivileged (recommended)
# 2 = disabled, and cannot be re-enabled until reboot
# IMPACT: Normal applications unaffected; blocks BPF verifier exploit chain
kernel.unprivileged_bpf_disabled = 1

# kernel.io_uring_disabled
# Controls io_uring creation
# 0 = all processes can create (default)
# 1 = require io_uring_group or CAP_SYS_ADMIN
# 2 = completely disabled for all processes
# IMPACT: Applications using io_uring will fail; most servers don't need it
kernel.io_uring_disabled = 2

# kernel.sysrq
# Controls SysRq key functionality
# 0 = disabled, 1 = all enabled, bitmask for selective
# IMPACT: Cannot use SysRq for emergency operations; acceptable for remote servers
kernel.sysrq = 0

# fs.suid_dumpable
# Controls core dump creation for setuid processes
# 0 = no dumps (secure), 1 = debug dumps, 2 = suidsafe
# IMPACT: Cannot debug setuid crashes; prevents credential leakage
fs.suid_dumpable = 0

# net.core.bpf_jit_harden
# Hardens BPF JIT compiler output
# 0 = disabled, 1 = harden for unprivileged, 2 = harden for all
# IMPACT: Minor BPF performance reduction; prevents JIT spray attacks
net.core.bpf_jit_harden = 2

#=============================================================================
# 3. MEMORY PROTECTION
#=============================================================================

# kernel.randomize_va_space
# Controls Address Space Layout Randomization (ASLR)
# 0 = disabled, 1 = mmap/stack/VDSO, 2 = + heap (full ASLR)
# IMPACT: None for normal operations; essential defense against memory corruption
kernel.randomize_va_space = 2

# fs.protected_symlinks
# Prevents following symlinks in world-writable sticky directories
# unless owner matches the follower or directory owner
# IMPACT: May break poorly-written software that relies on symlink following in /tmp
fs.protected_symlinks = 1

# fs.protected_hardlinks
# Prevents creating hardlinks to files you don't own
# IMPACT: Prevents hardlink-based privilege escalation
fs.protected_hardlinks = 1

# fs.protected_fifos
# Restricts FIFO creation in world-writable sticky directories
# 0 = none, 1 = O_CREAT for FIFOs not owned by user, 2 = applies to group-writable
# IMPACT: Prevents FIFO-based race conditions in /tmp
fs.protected_fifos = 2

# fs.protected_regular
# Restricts regular file creation in world-writable sticky directories
# IMPACT: Similar to protected_fifos for regular files
fs.protected_regular = 2

#=============================================================================
# 4. NETWORK HARDENING
#=============================================================================

net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

#=============================================================================
# 5. PROCESS AND EXECUTION HARDENING
#=============================================================================

# kernel.yama.ptrace_scope
# 0 = classic (any process can PTRACE_ATTACH)
# 1 = restricted (only parent can PTRACE_ATTACH)
# 2 = admin-only (CAP_SYS_PTRACE required)
# 3 = no ptrace at all
# IMPACT: Debuggers (gdb, strace) require elevated privileges
kernel.yama.ptrace_scope = 2

# kernel.panic_on_oops
# Forces a kernel panic (and subsequent reboot) on oops
# IMPACT: System reboots on kernel oops instead of attempting to continue
kernel.panic_on_oops = 1
kernel.panic = 10
```

### 7.2 Kernel Boot Parameters for Security

Complement sysctl settings with kernel command-line parameters in GRUB configuration:

```bash
# /etc/default/grub
GRUB_CMDLINE_LINUX="
    # Disable legacy vsyscall interface (exploit target)
    vsyscall=none

    # Enable page allocator debugging (detect use-after-free)
    page_poison=1
    init_on_alloc=1
    init_on_free=1

    # Enable SLAB_FREELIST_HARDENED and randomization
    slab_nomerge
    slub_debug=FZP

    # Disable debugfs (reduces kernel attack surface)
    debugfs=off

    # Disable hibernation (prevents cold boot attacks on swap)
    nohibernate

    # Restrict module parameters (lockdown)
    module.sig_enforce=1

    # Disable legacy ptrace
    # (Use yama.ptrace_scope=2 sysctl instead for configurability)

    # Enable IOMMU for DMA attack protection
    intel_iommu=on
    amd_iommu=force_isolation

    # Mitigate CPU vulnerabilities
    mitigations=auto,nosmt

    # Lockdown the kernel
    lockdown=confidentiality

    # Quiet boot (reduce information leakage to console)
    quiet loglevel=0
"
```

---

## 8. Container Runtime Security and Kernel Isolation

Standard containers (Docker, containerd) share the host kernel, meaning a kernel
vulnerability in any container's syscall path can compromise the entire host. Several
technologies provide stronger isolation.

### 8.1 gVisor (Google)

**Project:** [github.com/google/gvisor](https://github.com/google/gvisor)
**Language:** Go (pure, no CGo, no unsafe imports in core packages)
**Architecture:** User-space kernel (Sentry) + file proxy (Gofer)

gVisor intercepts application syscalls and re-implements them in a user-space
kernel called the "Sentry." The application never directly interacts with the
host kernel's syscall interface.

**Security model:**

```
Application
    |
    | (Syscalls intercepted)
    v
Sentry (user-space kernel, implements ~300 syscalls)
    |
    | (Minimal host syscalls: ~60)
    v
Host Kernel (restricted by seccomp-bpf filter)
    |
    v
Gofer (separate process for filesystem access via connected socket)
```

**Key security principles:**
1. **No syscall passthrough:** Every application syscall has an independent
   implementation in the Sentry. The host is never exposed to application-crafted
   syscall arguments.
2. **Minimal host surface:** The Sentry itself uses only ~60 host syscalls, configured
   with a strict seccomp-bpf filter. No new sockets are opened (except with host
   networking), no files are opened directly (except with directfs).
3. **Written in Go:** Memory-safe language eliminates buffer overflows, use-after-free,
   and other memory corruption vulnerabilities in the kernel implementation itself.
4. **No external imports in core:** The Sentry carefully controls its dependency tree
   to maintain auditability.
5. **Continuous fuzzing:** The Sentry is continuously fuzzed to proactively identify
   bugs.

**Performance trade-offs:**
- Syscall overhead: Each syscall crosses user/kernel boundary twice (into Sentry, then
  possibly to host kernel)
- I/O performance: File I/O goes through Gofer process via socket; can be mitigated
  with directfs mode
- Network performance: Virtual network stack adds latency; can use host networking
  to bypass
- Best suited for: Untrusted workloads, multi-tenant platforms, serverless functions

**Comparison with VMs:** gVisor provides a comparable security boundary to VMs for
the System API attack vector, but using a different mechanism. VMs use hardware
virtualization to expose virtual hardware; gVisor uses syscall interception to expose
a virtual kernel. Neither approach fully mitigates hardware side channels.

### 8.2 Kata Containers

**Project:** [github.com/kata-containers/kata-containers](https://github.com/kata-containers/kata-containers)
**Architecture:** Lightweight VM per container (or pod)

Kata Containers runs each container inside a lightweight virtual machine, providing
hardware-virtualization-level isolation while maintaining the container workflow
experience (OCI-compatible runtime).

**Architecture:**

```
Container Workload
    |
    v
Guest Kernel (lightweight, minimal Linux)
    |
    v
VMM (QEMU/Cloud Hypervisor/Firecracker)
    |
    v
Host Kernel + KVM
```

**Supported VMMs:**
- **QEMU:** Full-featured, widest hardware support
- **Cloud Hypervisor:** Rust-based, reduced attack surface
- **Firecracker:** Minimal VMM, fastest startup (~125ms)

**Security properties:**
- Each container has its own kernel -- kernel vulnerabilities are contained
- Hardware virtualization boundary (VT-x/AMD-V) between workload and host
- Guest kernel can be stripped down and hardened specifically for container workloads
- Standard container interfaces (CRI, OCI) maintained

**Overhead:**
- Memory: ~40-60 MiB per VM (guest kernel + minimal userspace)
- Startup: 500ms-2s (QEMU), ~125ms (Firecracker)
- CPU: Near-native for computation, overhead on syscall-heavy workloads

### 8.3 Firecracker (AWS)

**Project:** [github.com/firecracker-microvm/firecracker](https://github.com/firecracker-microvm/firecracker)
**Language:** Rust
**Architecture:** Minimal VMM using Linux KVM

Firecracker is a purpose-built virtual machine monitor designed for serverless and
container workloads. It powers AWS Lambda and AWS Fargate.

**Security design:**
- **Minimal device model:** Only 5 emulated devices: virtio-net, virtio-block,
  virtio-vsock, serial console, and a minimal keyboard controller (for VM stop only)
- **No unnecessary functionality:** No USB, no GPU, no PCI passthrough, no display
- **Written in Rust:** Memory safety by default
- **Jailer companion:** Each Firecracker process is further isolated using cgroups,
  namespaces, seccomp-bpf, and chroot -- providing defense-in-depth
- **Rate limiters:** Built-in network and storage rate limiting per microVM

**Performance:**
- Boot time: <125ms to user space
- Memory overhead: <5 MiB per microVM
- Creation rate: Up to 150 microVMs per second per host
- Density: Thousands of microVMs per server

### 8.4 Security Comparison Matrix

| Property | Standard Container | gVisor | Kata Containers | Firecracker |
|----------|-------------------|--------|-----------------|-------------|
| **Isolation mechanism** | Namespaces + cgroups | Userspace kernel | Hardware VM | Hardware VM |
| **Kernel shared?** | Yes | No (Sentry) | No (guest kernel) | No (guest kernel) |
| **Kernel exploit impact** | Full host compromise | Sentry compromise | Guest-only | Guest-only |
| **Syscall surface** | Full (~300) | Re-implemented (~300) | Guest-only | Guest-only |
| **Host syscalls exposed** | ~300 | ~60 | ~20 (VMM) | ~20 (VMM) |
| **Memory overhead** | <1 MiB | ~15-50 MiB | ~40-60 MiB | <5 MiB |
| **Startup time** | <100ms | ~150ms | 500ms-2s | <125ms |
| **OCI compatible** | Yes | Yes (runsc) | Yes (kata-runtime) | Via containerd |
| **Side channel protection** | None | Minimal | Hardware isolation | Hardware isolation |
| **Best for** | Trusted workloads | Untrusted code | High-security | Serverless/FaaS |

### 8.5 Defense-in-Depth for Container Environments

Regardless of the runtime chosen, additional layers should be applied:

```
Layer 1: Runtime security (gVisor/Kata/Firecracker)
    |
Layer 2: Seccomp-BPF profiles (restrict syscalls)
    |
Layer 3: LSM policies (AppArmor/SELinux profiles)
    |
Layer 4: Namespace isolation (user, network, PID, mount)
    |
Layer 5: Capabilities dropping (drop all, add only needed)
    |
Layer 6: Read-only root filesystem
    |
Layer 7: Resource limits (cgroups v2)
    |
Layer 8: Network policies (Calico, Cilium)
    |
Layer 9: Runtime monitoring (Falco, Tetragon, Tracee)
    |
Layer 10: Image signing and verification (Cosign, Notary)
```

---

## 9. Exploit Prediction and Prioritization Frameworks

Not all vulnerabilities are created equal. With hundreds of kernel CVEs published
annually, organizations need data-driven methods to prioritize remediation effort
on the vulnerabilities most likely to be weaponized.

### 9.1 EPSS (Exploit Prediction Scoring System)

**Maintained by:** FIRST.org Special Interest Group
**Model:** Data-driven machine learning
**Output:** Probability (0-1) that a CVE will be exploited in the wild within 30 days

EPSS replaces subjective severity judgments with empirical signals from observed
exploitation activity. It publishes daily scores for every CVE and makes data freely
accessible via CSV and API.

**How EPSS works:**

The model incorporates multiple data sources:
- Vulnerability characteristics (CVSS vectors, CWE types)
- Exploit code availability (Exploit-DB, Metasploit, GitHub)
- Social media and dark web mentions
- Active exploitation observations (honeypots, threat intelligence feeds)
- Temporal features (days since publication, recent activity trends)

**Using EPSS for kernel CVE prioritization:**

```
Priority 1 (Critical):  EPSS > 0.5  AND  CVSS >= 7.0  AND  in CISA KEV
Priority 2 (High):      EPSS > 0.1  AND  CVSS >= 7.0
Priority 3 (Medium):    EPSS > 0.01 AND  CVSS >= 4.0
Priority 4 (Low):       EPSS <= 0.01 OR  CVSS < 4.0
```

**API access:**

```bash
# Get EPSS score for a specific CVE
curl -s "https://api.first.org/data/v1/epss?cve=CVE-2024-1086"

# Get scores for multiple CVEs
curl -s "https://api.first.org/data/v1/epss?cve=CVE-2024-1086,CVE-2023-32233"

# Get top 100 CVEs by EPSS score
curl -s "https://api.first.org/data/v1/epss?order=!epss&limit=100"
```

**Empirical evidence:** Studies have shown that EPSS significantly outperforms
CVSS alone in predicting actual exploitation. Many CVEs with CVSS 9.0+ are never
exploited, while some CVEs with moderate CVSS scores are actively weaponized.

### 9.2 CISA Known Exploited Vulnerabilities (KEV) Catalog

The CISA KEV catalog lists vulnerabilities that have confirmed exploitation in the
wild. For organizations subject to Binding Operational Directive 22-01, KEV
vulnerabilities have mandatory remediation deadlines.

**Kernel-relevant KEV entries** (examples):

| CVE | Description | Due Date |
|-----|-------------|----------|
| CVE-2024-1086 | Linux nf_tables use-after-free | Immediate |
| CVE-2023-32233 | Linux nf_tables use-after-free | Immediate |
| CVE-2022-0847 | Dirty Pipe (pipe buffer flag manipulation) | Immediate |
| CVE-2022-0185 | Linux VFS heap overflow via legacy_parse_param | Immediate |
| CVE-2021-4154 | Linux cgroup use-after-free | Immediate |
| CVE-2021-22555 | Netfilter setsockopt heap OOB write | Immediate |

### 9.3 Stakeholder-Specific Vulnerability Categorization (SSVC)

SSVC is a decision-tree framework developed by CERT/CC and CISA that maps
vulnerabilities to actions based on:

1. **Exploitation status:** None / PoC / Active
2. **Automatable:** Can the exploit be automated? (Yes/No)
3. **Technical impact:** Partial / Total
4. **Mission prevalence:** Minimal / Support / Essential

**Output actions:**
- **Track:** Monitor, no immediate action
- **Track*:** Closer monitoring, schedule patch
- **Attend:** Act within standard patch cycle
- **Act:** Immediate remediation required

### 9.4 Combined Prioritization Framework for Kernel CVEs

```
                          +-----------------------+
                          | New Kernel CVE        |
                          | published             |
                          +-----------+-----------+
                                      |
                          +-----------v-----------+
                          | Is CVE in CISA KEV?   |
                          +-----+----------+------+
                                |          |
                            YES |          | NO
                                |          |
                     +----------v--+  +----v------------------+
                     | ACT NOW     |  | Check EPSS score      |
                     | Patch <48h  |  +---------+-------------+
                     +-------------+            |
                                     +----------v-----------+
                                     | EPSS > 0.1?          |
                                     +-----+----------+-----+
                                           |          |
                                       YES |          | NO
                                           |          |
                                +----------v--+  +----v------------------+
                                | HIGH priority|  | Check local exposure |
                                | Patch <7d    |  | Is subsystem compiled|
                                +--------------+  | and reachable?       |
                                                  +-----+----------+----+
                                                        |          |
                                                    YES |          | NO
                                                        |          |
                                              +---------v---+  +---v-----------+
                                              | MEDIUM      |  | LOW / TRACK   |
                                              | Patch <30d  |  | Standard cycle|
                                              +-------------+  +---------------+
```

---

## 10. Building a Kernel Security Program

### 10.1 Organizational Framework

A kernel security program should be structured around five pillars:

```
                    KERNEL SECURITY PROGRAM
    +-----------+-----------+-----------+-----------+-----------+
    |           |           |           |           |           |
    | PREVENT   | DETECT    | RESPOND   | RECOVER   | GOVERN    |
    |           |           |           |           |           |
    +-----------+-----------+-----------+-----------+-----------+
    | Hardening | Monitoring| Incident  | Livepatching| Policy  |
    | Secure    | Alerting  | Response  | Fallback    | Metrics |
    | Config    | Forensics | Triage    | Recovery    | Training|
    | Patching  | Hunting   | Contain   | DR/BC       | Audit   |
    +-----------+-----------+-----------+-----------+-----------+
```

### 10.2 Prevention Layer

**Kernel configuration baseline:**

Establish a "golden" kernel configuration that:
1. Disables unnecessary subsystems (`CONFIG_*=n` for unused features)
2. Enables all hardening options:
   - `CONFIG_HARDENED_USERCOPY=y`
   - `CONFIG_FORTIFY_SOURCE=y`
   - `CONFIG_STACKPROTECTOR_STRONG=y`
   - `CONFIG_RANDOMIZE_BASE=y` (KASLR)
   - `CONFIG_RANDOMIZE_MEMORY=y`
   - `CONFIG_GCC_PLUGIN_RANDSTRUCT=y`
   - `CONFIG_GCC_PLUGIN_LATENT_ENTROPY=y`
   - `CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL=y` or `CONFIG_INIT_STACK_ALL_ZERO=y`
   - `CONFIG_SLAB_FREELIST_RANDOM=y`
   - `CONFIG_SLAB_FREELIST_HARDENED=y`
   - `CONFIG_SHUFFLE_PAGE_ALLOCATOR=y`
   - `CONFIG_PAGE_TABLE_ISOLATION=y` (KPTI)
   - `CONFIG_STATIC_USERMODEHELPER=y`
   - `CONFIG_SECURITY_LOCKDOWN_LSM=y`
   - `CONFIG_MODULE_SIG=y`
   - `CONFIG_MODULE_SIG_FORCE=y`
3. Applies sysctl hardening (Section 7)
4. Applies kernel boot parameters (Section 7.2)

**Automated compliance checking:**

```bash
#!/bin/bash
# Kernel hardening compliance check script (simplified)

KERNEL_CONFIG="/boot/config-$(uname -r)"
FAIL=0

check_config() {
    local option=$1
    local expected=$2
    if grep -q "^${option}=${expected}" "$KERNEL_CONFIG" 2>/dev/null; then
        echo "[PASS] ${option}=${expected}"
    else
        echo "[FAIL] ${option} not set to ${expected}"
        FAIL=$((FAIL + 1))
    fi
}

check_sysctl() {
    local key=$1
    local expected=$2
    local actual
    actual=$(sysctl -n "$key" 2>/dev/null)
    if [ "$actual" = "$expected" ]; then
        echo "[PASS] ${key}=${expected}"
    else
        echo "[FAIL] ${key}=${actual} (expected ${expected})"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== Kernel Configuration Checks ==="
check_config CONFIG_STACKPROTECTOR_STRONG y
check_config CONFIG_FORTIFY_SOURCE y
check_config CONFIG_HARDENED_USERCOPY y
check_config CONFIG_RANDOMIZE_BASE y
check_config CONFIG_PAGE_TABLE_ISOLATION y
check_config CONFIG_MODULE_SIG y
check_config CONFIG_MODULE_SIG_FORCE y
check_config CONFIG_SECURITY_LOCKDOWN_LSM y
check_config CONFIG_SLAB_FREELIST_HARDENED y
check_config CONFIG_SLAB_FREELIST_RANDOM y
check_config CONFIG_INIT_STACK_ALL_ZERO y

echo ""
echo "=== Sysctl Checks ==="
check_sysctl kernel.kptr_restrict 2
check_sysctl kernel.dmesg_restrict 1
check_sysctl kernel.unprivileged_bpf_disabled 1
check_sysctl kernel.randomize_va_space 2
check_sysctl kernel.yama.ptrace_scope 2
check_sysctl fs.protected_symlinks 1
check_sysctl fs.protected_hardlinks 1
check_sysctl net.ipv4.tcp_syncookies 1
check_sysctl net.ipv4.conf.all.rp_filter 1

echo ""
echo "=== Boot Parameter Checks ==="
CMDLINE=$(cat /proc/cmdline)
for param in "vsyscall=none" "init_on_alloc=1" "slab_nomerge"; do
    if echo "$CMDLINE" | grep -q "$param"; then
        echo "[PASS] Boot parameter: ${param}"
    else
        echo "[FAIL] Missing boot parameter: ${param}"
        FAIL=$((FAIL + 1))
    fi
done

echo ""
echo "=== Results ==="
if [ $FAIL -eq 0 ]; then
    echo "All checks passed."
else
    echo "${FAIL} check(s) failed."
    exit 1
fi
```

### 10.3 Detection Layer

**Tiered monitoring architecture:**

```
Tier 1: Always-On (low overhead, broad coverage)
  - auditd rules for critical syscalls (module load, credential change, mount)
  - Falco with default ruleset
  - Kernel log monitoring (KASAN/UBSAN/OOPS)

Tier 2: Targeted (moderate overhead, deep inspection)
  - Tetragon TracingPolicies for high-value assets
  - Custom Tracee policies for known attack patterns
  - IMA measurement of critical binaries

Tier 3: On-Demand (high overhead, investigation/hunting)
  - Full syscall tracing via perf/ftrace
  - Memory forensics via /proc/kcore or crash dumps
  - Intel PT / LBR analysis for control-flow hijacking
```

**Alert routing:**

```
Security Event
    |
    +---> SIEM (Elasticsearch, Splunk, Chronicle)
    |         |
    |         +---> Correlation rules
    |         +---> Anomaly detection
    |         +---> Threat hunting queries
    |
    +---> Incident response platform (PagerDuty, Jira)
    |
    +---> Automated response (Tetragon enforcement, network isolation)
```

### 10.4 Response Layer

**Kernel incident response playbook:**

```
1. DETECT
   - Alert from monitoring tool (Falco/Tetragon/Tracee/auditd)
   - Unusual system behavior (crashes, performance degradation)
   - External notification (CERT, vendor advisory)

2. TRIAGE
   - Classify: Is this exploitation, misconfiguration, or false positive?
   - Assess scope: Single host? Multiple hosts? Entire fleet?
   - Determine impact: Information disclosure? Privilege escalation? RCE?

3. CONTAIN
   - Network isolation of affected hosts
   - Disable vulnerable interfaces (sysctl, seccomp, module unload)
   - Enable enhanced monitoring on similar systems

4. INVESTIGATE
   - Capture volatile evidence:
     * /proc/kcore (kernel memory dump)
     * dmesg output
     * Module list (/proc/modules)
     * Open files and network connections
     * Process tree and credentials
   - Analyze audit logs and eBPF events
   - Check for indicators of compromise (rootkit artifacts, modified
     syscall tables, hidden modules)

5. REMEDIATE
   - Apply kernel patch (livepatch if available, full update + reboot otherwise)
   - Apply sysctl mitigations if patch unavailable
   - Deploy eBPF-based virtual patches
   - Update seccomp profiles to block exploit syscalls

6. RECOVER
   - Verify system integrity (IMA measurements, dm-verity, module signatures)
   - Restore from known-good state if integrity verification fails
   - Gradual return to production with enhanced monitoring

7. LESSONS LEARNED
   - Update detection rules based on observed attack patterns
   - Update hardening baseline if a misconfiguration contributed
   - Update patch prioritization if a known CVE was exploited
   - Document timeline and actions for future reference
```

### 10.5 Governance and Metrics

**Key metrics to track:**

| Metric | Target | Measurement |
|--------|--------|-------------|
| Mean Time to Patch (MTTP) | <7 days critical, <30 days high | CVE publish date to patch deployed |
| Hardening compliance | >95% | Automated checks vs. baseline |
| Kernel version currency | Within 1 minor version | Comparison to latest stable |
| Livepatch coverage | >80% of critical CVEs | Livepatched / total critical |
| Detection coverage | >90% of MITRE ATT&CK techniques | Tested techniques / total |
| False positive rate | <5% | False alerts / total alerts |
| Alert response time | <15 minutes P1, <4 hours P2 | Alert time to first response |
| Patching SLA compliance | >95% | Patched within SLA / total |

**Program maturity model:**

```
Level 1 - Ad Hoc
  - Kernel updates applied reactively
  - No hardening baseline
  - No runtime monitoring

Level 2 - Managed
  - Regular patching cadence established
  - Basic sysctl hardening applied
  - auditd configured with basic rules
  - CVE tracking via manual review

Level 3 - Defined
  - Documented hardening baseline (kernel config + sysctl + boot params)
  - eBPF monitoring deployed (Falco or equivalent)
  - Livepatching for critical CVEs
  - EPSS-based prioritization
  - Automated compliance checking

Level 4 - Quantitative
  - All metrics tracked and reported
  - Threat hunting program for kernel-level threats
  - Custom detection signatures for environment
  - Container runtime security (gVisor/Kata) for untrusted workloads
  - Automated response for specific attack patterns

Level 5 - Optimizing
  - Kernel configuration auto-generated from workload requirements
  - Continuous fuzzing of custom kernel modules
  - Red team exercises include kernel exploitation scenarios
  - Active contribution to upstream kernel security
  - Supply chain verification for all kernel artifacts
```

### 10.6 Staffing and Skills

A mature kernel security program requires the following competencies:

| Role | Responsibility |
|------|---------------|
| Kernel Security Engineer | Hardening baseline, kernel config, build pipeline |
| Vulnerability Analyst | CVE triage, EPSS monitoring, patch prioritization |
| Detection Engineer | eBPF policy development, audit rules, SIEM rules |
| Incident Responder | Kernel forensics, exploitation triage, containment |
| Infrastructure Engineer | Deployment of patches, livepatching, fleet management |
| Security Architect | Container isolation strategy, defense-in-depth design |

### 10.7 Tool Inventory Summary

| Category | Tools |
|----------|-------|
| **Runtime Monitoring** | Falco, Tetragon, Tracee, auditd, AIDE |
| **Integrity** | dm-verity, IMA/EVM, UEFI Secure Boot, module signing |
| **Livepatching** | kpatch (RHEL), Livepatch (Ubuntu), Ksplice (Oracle), KernelCare |
| **Vulnerability Intel** | EPSS API, CISA KEV, NVD API, distro security trackers |
| **Compliance** | OpenSCAP, Lynis, CIS Benchmarks, custom scripts |
| **Container Runtime** | gVisor (runsc), Kata Containers, Firecracker |
| **Forensics** | Volatility, crash (kdump), LiME, perf, ftrace |
| **Hardening Guides** | CIS Benchmarks, KSPP Recommended Settings, STIG |

---

## References

1. Linux Kernel Documentation - `/proc/sys/kernel/`. kernel.org
2. Linux Kernel Documentation - Kernel Module Signing Facility. kernel.org
3. Linux Kernel Documentation - dm-verity. kernel.org
4. Linux Kernel Documentation - Livepatch. kernel.org
5. Linux Kernel Documentation - Hardware Vulnerabilities. kernel.org
6. Linux Security Module Usage. kernel.org
7. Cilium Tetragon Documentation. tetragon.io
8. Falco Project Documentation. falco.org
9. Tracee Documentation. aquasecurity.github.io/tracee
10. gVisor Security Model. gvisor.dev
11. Kata Containers Architecture. github.com/kata-containers
12. Firecracker MicroVM. firecracker-microvm.github.io
13. FIRST EPSS - Exploit Prediction Scoring System. first.org/epss
14. Kernel Self Protection Project. kernsec.org
15. CISA Known Exploited Vulnerabilities Catalog. cisa.gov
16. SSVC - Stakeholder-Specific Vulnerability Categorization. CERT/CC
17. CIS Benchmarks for Linux. cisecurity.org

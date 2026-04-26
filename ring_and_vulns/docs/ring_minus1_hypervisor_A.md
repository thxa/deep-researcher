# Ring -1: Hypervisor / VMM — Privilege Below Ring 0

> *The root of trust shifted from the OS kernel to a thinner, more auditable layer — but that layer is still software, and software has bugs.*

---

## 1. What Is Ring -1?

Traditional x86 protection rings define privilege levels 0–3. Ring 0 is the most privileged (kernel mode), Ring 3 the least (user mode). Rings 1 and 2 exist in the architecture but are unused by modern operating systems.

**Ring -1** is an informal designation for the privilege level introduced by hardware virtualization extensions. When virtualization is active, the CPU enforces a new, **more-privileged mode** that sits *below* Ring 0. Code running in this mode — the hypervisor or Virtual Machine Monitor (VMM) — has **unrestricted access** to the physical hardware and can arbitrarily intercept, emulate, or modify any operation the guest OS attempts.

### 1.1 Intel VT-x (VMX)

Intel's Virtualization Extension for x86, introduced in 2005, adds a new CPU mode called **VMX operation**:

| Component | Description |
|---|---|
| **VMX root mode** | The mode in which the hypervisor/VMM executes. Has full hardware access and controls all guest execution. |
| **VMX non-root mode** | The mode in which guest OSes execute. Appears identical to normal Ring 0 from the guest's perspective, but many privileged operations are trapped and redirected to VMX root. |
| **VMCS** | Virtual Machine Control Structure — a per-VCPU data structure in memory that controls how VMX non-root mode behaves and what causes VM exits. |
| **VM entries** | Transitions from VMX root → VMX non-root (entering the guest). |
| **VM exits** | Transitions from VMX non-root → VMX root (exiting the guest back to the hypervisor). |

The key insight: code running at "Ring 0" inside a VM is actually running in VMX non-root mode. It *believes* it has full privilege, but the CPU transparently intercepts sensitive instructions and events, delivering them to the hypervisor for handling.

### 1.2 AMD-V (SVM — Secure Virtual Machine)

AMD's equivalent, introduced in 2006 as part of the AMD64 architecture:

| Component | Description |
|---|---|
| **Host mode** | Analogous to VMX root — the hypervisor runs here. |
| **Guest mode** | Analogous to VMX non-root — the guest OS runs here. |
| **VMCB** | Virtual Machine Control Block — AMD's equivalent of VMCS. Controls guest execution and exit conditions. |
| **VMRUN** | Instruction that enters guest mode (analogous to VMLAUNCH/VMRESUME). |
| **#VMEXIT** | The mechanism by which guest mode returns to host mode. |
| **NPT** | Nested Page Tables — AMD's equivalent of Intel's EPT. |

### 1.3 Why "Ring -1"?

The name is a convenience. It captures a critical property: the hypervisor has **strictly more privilege** than any Ring 0 kernel. Specifically:

```
  Ring -1 (Hypervisor / VMM)
      │
      │  Can intercept ANY privileged operation
      │
  Ring 0  (Guest Kernel — VMX non-root / Guest mode)
      │
  Ring 3  (Guest User — still Ring 3, but nested under VMX non-root)
```

- The hypervisor can read/write any physical memory, intercept I/O, intercept interrupts, intercept CR register modifications, and even lie to the guest about what hardware exists.
- The guest kernel has *no way* to detect it is virtualized if the hypervisor is carefully designed (though timing attacks and subtle hardware differences can leak information).
- This design means: **if an attacker compromises Ring -1, they compromise every guest on the system** — a catastrophic failure for multi-tenant cloud environments.

---

## 2. Hypervisor Architecture

### 2.1 Type 1 Hypervisors (Bare-Metal / Native)

The hypervisor runs directly on the hardware with no host OS underneath.

| Hypervisor | Description | Use Case |
|---|---|---|
| **VMware ESXi** | Proprietary, minimal kernel (~100 MB footprint). Monolithic VMM. | Enterprise data centers |
| **Microsoft Hyper-V** | Windows-based micro-kernel hypervisor. `HVLoader` boots first, then partitions. | Azure, Windows Server |
| **Xen** | Open-source. Dom0 (privileged management domain) + DomU (unprivileged guests). Paravirt and HVM modes. | AWS (historically), XenServer |
| **KVM (bare-metal)** | Linux kernel module that turns the kernel into a Type 1 hypervisor when loaded. QEMU provides device emulation. | Proxmox, Google Cloud, many clouds |
| **Proxmox VE** | Debian + KVM + QEMU + LXC. | SMB virtualization |

Architecture (Type 1):

```
  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
  │  Guest VM 1  │  │  Guest VM 2  │  │  Guest VM N  │
  │   (DomU)     │  │   (DomU)     │  │   (DomU)     │
  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
         │                 │                  │
  ═══════╪═════════════════╪══════════════════╪════════
         │        Hypervisor / VMM           │
  ═══════╪═════════════════╪══════════════════╪════════
         │                 │                  │
  ┌──────┴─────────────────┴──────────────────┴───────┐
  │                  Physical Hardware                  │
  └────────────────────────────────────────────────────┘
```

### 2.2 Type 2 Hypervisors (Hosted)

The hypervisor runs as an application on top of a conventional host OS.

| Hypervisor | Host OS | Description |
|---|---|---|
| **VirtualBox** | Windows/macOS/Linux | Oracle's open-source hosted hypervisor. |
| **VMware Workstation** | Windows/Linux | VMware's desktop hypervisor. |
| **QEMU/KVM** | Linux | QEMU provides device emulation; KVM provides hardware-accelerated CPU virtualization. |
| **Parallels Desktop** | macOS | Mac-focused virtualization. |

Architecture (Type 2):

```
  ┌──────────┐  ┌──────────┐
  │ Guest VM │  │ Guest VM │
  └─────┬────┘  └─────┬────┘
        │              │
  ┌─────┴──────────────┴──────┐
  │   Hypervisor Application  │  (VirtualBox, VMware, etc.)
  └───────────┬───────────────┘
              │
  ┌───────────┴───────────────┐
  │     Host Operating System │
  └───────────┬───────────────┘
              │
  ┌───────────┴───────────────┐
  │     Physical Hardware     │
  └───────────────────────────┘
```

**Type 1 vs Type 2 — security implications:**
- Type 1 has a smaller attack surface (no host OS) but a monolithic hypervisor.
- Type 2 inherits the host OS's attack surface; compromising the host OS grants full control over all guests.
- In practice, KVM blurs the line: the Linux kernel IS the VMM, making it a Type 1 with a large, well-audited codebase.

### 2.3 VMM (Virtual Machine Monitor) Responsibilities

The VMM must correctly emulate and virtualize the following for each guest:

| Responsibility | Details |
|---|---|
| **CPU virtualization** | Intercept privileged instructions (CPUID, `HLT`, `IN/OUT`, `WRMSR`, CR accesses). Present virtual CPUs (vCPUs). |
| **Memory virtualization** | Translate guest-physical → host-physical via EPT/NPT. Handle page faults, manage memory regions, enforce isolation. |
| **Device emulation** | Emulate NICs, disks, GPUs, serial ports, USB controllers, etc. QEMU's `hw/` directory contains millions of lines of device emulation code. |
| **Interrupt virtualization** | Inject virtual interrupts (IRQs) into guests via APIC virtualization. |
| **I/O virtualization** | Either emulate I/O devices (trap `IN`/`OUT` instructions) or pass through physical devices via VT-d/AMD-Vi (IOMMU). |
| **Timer virtualization** | Virtualize TSC, LAPIC timer, HPET. Time dilation effects are notoriously hard to get right. |
| **Scheduling** | Schedule vCPUs onto physical CPUs. Fairness and latency guarantees. |

---

## 3. VMX Operation in Depth

### 3.1 VMX Root vs VMX Non-Root

```
                 VMX Root Mode (Ring 0)
                 ┌─────────────────────────────────┐
                 │         Hypervisor / VMM         │
                 │                                 │
                 │  ● Full hardware access          │
                 │  ● Manages VMCS structures       │
                 │  ● Handles VM exits              │
                 │  ● Controls EPT                  │
                 └────────────┬────────────────────┘
                              │
                    VM Entry (VMLAUNCH / VMRESUME)
                              │
                              ▼
                 VMX Non-Root Mode (Ring 0)
                 ┌─────────────────────────────────┐
                 │          Guest OS Kernel         │
                 │                                 │
                 │  ● BELIEVES it has Ring 0       │
                 │  ● Privileged ops trap to VMM    │
                 │  ● Sees virtualized hardware     │
                 └────────────┬────────────────────┘
                              │
                    VM Exit (#EXIT reason)
                              │
                              ▼
                 Back to VMX Root Mode
```

Key VMX transitions:

| Transition | Instruction/Mechanism | Direction |
|---|---|---|
| VM Entry | `VMLAUNCH`, `VMRESUME` | Root → Non-root |
| VM Exit | Various (see below) | Non-root → Root |
| Initial entry | `VMLAUNCH` | Root → Non-root (first time) |
| Resume after exit | `VMRESUME` | Root → Non-root (subsequent) |

VM exits can be triggered by:

- **Unconditional**: `CPUID`, `INVD`, `XSETBV` (controlled by VMCS execution controls)
- **Conditional**: `IN`/`OUT` (based on I/O bitmap), `CR0`/`CR4` accesses (based on CR masking), MSR accesses (based on MSR bitmap)
- **Event-based**: EPT violations, APIC accesses, exceptions in the guest
- **External**: Host-initiated (preemption timer, IPI)

### 3.2 VMCS (Virtual Machine Control Structure)

The VMCS is a ~4 KB data structure in memory that controls every aspect of a vCPU's virtualized execution. It is pointed to by the `VMCS` pointer in the processor and manipulated via `VMREAD`/`VMWRITE`/`VMCLEAR`/`VMPTRLD` instructions.

**VMCS major sections:**

```
VMCS Structure (simplified)
├── Guest-state area
│   ├── Register state (RIP, RSP, RFLAGS, CR0/CR3/CR4, segment registers)
│   ├── MSR state (SYSENTER_CS/EIP/ESP, FS/GS base)
│   └── Debug state (DR7, IA32_DEBUGCTL)
│
├── Host-state area
│   ├── Register state (what the host will have on VM exit)
│   └── MSR state
│
├── VM-execution control fields
│   ├── Pin-based controls    (interrupt handling, NMI, preemption timer)
│   ├── Processor-based controls (CR loads/stores, MSR bitmaps, I/O bitmaps)
│   ├── Secondary controls     (EPT, VPID, RDTSCP, APIC virtualization)
│   └── Exception bitmap       (which exceptions cause VM exits)
│
├── VM-exit control fields
│   ├── Controls what state is saved/restored on exit
│   └── MSR store/load lists
│
├── VM-entry control fields
│   ├── Controls what state is loaded on entry
│   ├── MSR load list
│   └── Event injection (inject interrupts/exceptions into guest)
│
└── EPT / VPID fields
    ├── EPTP (EPT pointer — base of extended page tables)
    ├── VPID (Virtual Processor ID for TLB tagging)
    └── EPT controls
```

The VMCS is the **single most important data structure** in VMX operation. A corrupt VMCS can lead to:
- Guest state corruption
- Host state leakage
- VM entry failures (processor rejects entry)
- Privilege escalation (incorrect CR0/CR4 masking)

### 3.3 VM Entries and VM Exits in Detail

#### VM Entry Flow

```
VMM (VMX Root)                         Guest (VMX Non-Root)
     │                                        │
     │  1. Validate VMCS fields               │
     │  2. Load guest state from VMCS          │
     │  3. Load MSRs from MSR-load list       │
     │  4. Inject pending events              │
     │  5. VMLAUNCH / VMRESUME ──────────────►│
     │                                        │ Guest executes...
     │                                        │
     │◄─ VM Exit ─────────────────────────────│
     │  1. Save guest state to VMCS
     │  2. Load host state from VMCS
     │  3. Read VM-exit information
     │  4. Dispatch to exit handler
     │  5. Process and return
```

#### VM Exit Information

On every VM exit, the processor writes detailed information into the VMCS:

| Field | Description |
|---|---|
| Exit reason | Numeric code indicating why the exit occurred (e.g., 0x0A = CPUID, 0x1E = EPT violation) |
| Exit qualification | Additional detail about the exit (e.g., faulting address for EPT violations) |
| Guest-physical address | Physical address for EPT violations |
| Guest-linear address | Linear address for certain exits |
| Instruction length | Length of the instruction that caused the exit |
| Instruction info | Encoding details of the faulting instruction |

#### Common VM Exit Reasons (Intel)

```c
// Selected VMX exit reasons
#define EXIT_REASON_EXCEPTION_NMI      0x00
#define EXIT_REASON_EXTERNAL_INTERRUPT  0x01
#define EXIT_REASON_TRIPLE_FAULT        0x02
#define EXIT_REASON_CPUID               0x0A
#define EXIT_REASON_INVD                0x13
#define EXIT_REASON_VMCALL              0x12
#define EXIT_REASON_CR_ACCESS           0x1C
#define EXIT_REASON_IO_INSTRUCTION      0x1E
#define EXIT_REASON_MSR_READ            0x1F
#define EXIT_REASON_MSR_WRITE           0x20
#define EXIT_REASON_EPT_VIOLATION       0x30
#define EXIT_REASON_EPT_MISCONFIG       0x31
#define EXIT_REASON_XSAVES              0x3B
```

Every VM exit costs **~1000 CPU cycles** (~0.3–1.0 µs). Frequent exits destroy performance — this is why EPT (avoiding MMU shadow page tables) and APIC virtualization (avoiding interrupt delivery exits) are critical.

### 3.4 EPT (Extended Page Tables) / NPT (Nested Page Tables)

**The second-level address translation** that makes guest physical memory isolation possible.

#### Without EPT/NPT (Shadow Page Tables)

```
Guest Virtual Address
        │
        │  Guest page tables (walked by VMM in software)
        │
        ▼
Guest Physical Address
        │
        │  VMM maintains shadow page tables
        │  mapping Guest VA → Host PA directly
        │
        ▼
Host Physical Address
```

Problem: Every guest page table write causes a VM exit. Catastrophic performance.

#### With EPT/NPT (Hardware-Managed Two-Level Translation)

```
Guest Virtual Address (GVA)
        │
        │  Guest page tables (walked by hardware)
        │
        ▼
Guest Physical Address (GPA)
        │
        │  Extended Page Tables (EPT) / Nested Page Tables (NPT)
        │  Walked by hardware in parallel
        │
        ▼
Host Physical Address (HPA)
```

The CPU's MMU walks both page table levels in hardware. Guest page table modifications don't cause VM exits. EPT/NPT violations only occur when the GPA→HPA mapping is missing or has insufficient permissions.

#### EPT Entry Format (Intel, 64-bit)

```
  63  32 31              12 11 9 8 7 6 5 4 3 2 1 0
  ├─────┤┌───────────────┐├───┤│││││││││├───┤
  │ Phys │   Frame Addr   │ Rsvd│││││││││││││
  │ Addr │ (bits 51:12)  │     │││││││││││││
  │      │               │     │D││││││││││││
  │      │               │     │I││││││││││││
  │      │               │     │R││││││││││││
  └─────┘└───────────────┘     │S││││││││││││
                               │V││││││││││││
     Bits:                     │E││││││││││││
     0: Read access (R)       │ ││││││││││││
     1: Write access (W)      └─┴─┴─┴─┴─┴───┘
     2: Execute access (X)      │ │ │ │ │
     3: Memory type (bits 5:3)  │ │ │ │ └─ Execute-only for supervisor
     7: Ignore PAT              │ │ │ └─── Accessed
     8: Accessed flag           │ │ └──── Dirty
     9: Dirty flag              │ └───── Page size (2MB/1GB)
    10: Execute-only            └──── Suppress #VE
    11: Suppress #VE
```

Key EPT properties:
- **Separate R/W/X permissions** — enables fine-grained memory protection per physical page
- **EPT violations** — page faults at the EPT level, delivered to the hypervisor
- **EPT misconfiguration** — misconfigured entries that cause processor-detectable errors
- **VPID** — Virtual Processor ID tags TLB entries so TLB doesn't need flushing on VM entry/exit

---

## 4. Hypervisor Attack Surface and CVEs

### 4.1 Attack Surface Overview

The hypervisor attack surface is **broad and heterogeneous**:

```
                    Attack Vectors
                         │
         ┌───────────────┼───────────────┐
         │               │               │
    Device          CPU/vCPU          Memory
    Emulation       Management        Management
         │               │               │
  ┌──────┤          ┌────┤          ┌────┤
  │NIC   │          │VMX  │          │EPT  │
  │Disk  │          │SVM  │          │NPT  │
  │GPU   │          │VMCS │          │Balloon│
  │Serial│          │vCPU │          │vhost │
  │USB   │          │Sched│          │vsock │
  │Virtio│          │x2APIC│         │DM    │
  └──────┘          └────┘          └────┘
```

**Device emulation** is historically the **largest attack surface**. QEMU alone has ~6+ million lines of code, with hundreds of device models, many derived from hardware specifications that were never designed with adversarial guests in mind.

### 4.2 Notable CVEs

#### Table of Major Hypervisor CVEs

| # | CVE | Hypervisor | Type | Year | CVSS | Description |
|---|---|---|---|---|---|---|
| 1 | CVE-2015-3456 | QEMU | Device emulation | 2015 | 9.8 | **VENOM** — Heap buffer overflow in QEMU Floppy Disk Controller (FDC) emulator. Guest could overflow `FDC` command buffer → arbitrary code execution in QEMU process (host). |
| 2 | CVE-2015-5165 | QEMU/KVM | Device emulation | 2015 | 7.2 | Heap buffer overflow in QEMU RTL8139 NIC emulation. Guest → host escape. |
| 3 | CVE-2015-7504 | QEMU/KVM | Device emulation | 2015 | 7.5 | Heap buffer overflow in QEMU PCNET NIC emulation. |
| 4 | CVE-2016-9921 | QEMU | Device emulation | 2016 | 6.5 | Infinite loop in QEMU ColdFire Fast Ethernet Controller (mcf_fec). DoS via guest. |
| 5 | CVE-2019-6974 | KVM | vCPU | 2019 | 5.6 | Use-after-free in KVM `kvm_arch_vcpu_put()` on x86. Race condition on vCPU teardown. |
| 6 | CVE-2020-10758 | KVM | Memory (bitmap) | 2020 | 7.8 | Out-of-bounds read in KVM `kvm_ioapic_update_eoi()` — IOAPIC bitmap access. Guest could read hypervisor memory. |
| 7 | CVE-2021-28476 | Hyper-V | vCPU/signal | 2021 | 9.8 | Race condition in Hyper-V signal handling. Guest could corrupt hypervisor memory → VM escape. |
| 8 | CVE-2020-3950 | VMware ESXi | Auth/escape | 2020 | 9.8 | Use-after-free in VMware ESXi XHCI USB controller emulation. Authenticated VM escape. |
| 9 | CVE-2021-22054 | VMware ESXi | Auth | 2021 | 7.5 | Local privilege escalation in ESXi via authenticated user access to SFCB. |
| 10 | CVE-2022-26394 | Xen | vCPU | 2022 | 6.5 | Race condition in Xen IOREQ handling. Malicious guest could exploit race to cause DoS or privilege escalation. |
| 11 | CVE-2018-8897 | KVM/x86 | vCPU | 2018 | 7.8 | Debug exception (MOV SS/POP SS) privilege escalation in KVM. Incorrect handling of #DB exception after MOV SS in guest. |
| 12 | CVE-2022-31681 | VMware | Device emulation | 2022 | 7.8 | Out-of-bounds write in VMwareFloppy device emulation. Guest → host escape. |
| 13 | CVE-2023-33869 | Xen | Memory | 2023 | 7.8 | Xen memory mapping race — a guest could revoke access to a grant but retain the mapping, causing a use-after-free. |

### 4.3 Detailed CVE Analysis

#### CVE-2015-3456 — VENOM (Virtual Environment Neglected Operations Manipulation)

**The most famous VM escape CVE.**

```c
// Simplified vulnerability in hw/block/fdc.c
// The FDC command buffer had a fixed size but
// the controller accepted more data than it could hold.

#define FD_CMD_LEN  0x06  // Expected command length

static void fdctrl_handle_transfer(FDCtrl *fdctrl, int direction) {
    // The FDC's FIFO buffer is 512 bytes, but the
    // controller's data transfer size field is controlled
    // by the guest. Setting it > 512 causes heap overflow.
    int size = fdctrl->data_len;  // Guest-controlled!
    // ... buffer overflow when size > allocated buffer
}
```

**Impact**: Any user in the guest with access to the floppy device (even without root) could execute arbitrary code on the host as the QEMU process user. Affected QEMU, Xen (via QEMU-traditional), and any hypervisor using QEMU device emulation.

**Root cause**: The floppy controller emulator trusted the guest-supplied data length without bounds checking. This is a recurring pattern — device emulation code written for *cooperative* hardware (physical devices) is suddenly exposed to *adversarial* guests.

#### CVE-2021-28476 — Hyper-V vCPU Race

```c
// Simplified conceptual model
// Hyper-V signal event handling had a TOCTOU race:

// Thread 1 (vCPU):                  Thread 2 (Signal):
// hv_signal_event(event_ptr)        hv_process_signal()
//   if (event_ptr->state == IDLE)  // CHECK
//       event_ptr->state = ACTIVE   // USE
//       inject_interrupt()
//                                     event_ptr->state = IDLE
//                                     free(event_ptr)
//
// Result: use-after-free / double-free → hypervisor memory corruption
```

**Impact**: Guest could trigger a race condition in the vCPU signal path to corrupt hypervisor memory, enabling escape from the guest partition. CVSS 9.8.

#### CVE-2019-6974 — KVM Use-After-Free

Affecting `kvm_arch_vcpu_put()` in `arch/x86/kvm/x86.c`:

```c
// Simplified pattern
// When a vCPU is being torn down while still referenced:
void kvm_arch_vcpu_put(struct kvm_vcpu *vcpu) {
    // vcpu->arch could be freed concurrently if
    // vCPU teardown races with this function
    kvm_x86_ops->vcpu_put(vcpu);  // UAF if vcpu freed
}
```

**Root cause**: Insufficient reference counting / locking during vCPU lifecycle transitions. A carefully timed thread could cause `kvm_arch_vcpu_put` to dereference a freed `vcpu` structure.

---

## 5. Virtual Machine Escapes

### 5.1 How VM Escapes Work — Conceptual

A **VM escape** occurs when code running inside a guest VM breaks out of its isolation boundary and executes code in the hypervisor or host OS.

```
  ┌─────────────────────────────────────────────────┐
  │                Hypervisor / VMM                 │
  │                                                 │
  │   ┌─────────────┐   ┌──────────────┐           │
  │   │  Guest VM 1 │   │  Guest VM 2  │           │
  │   │  (Attacker) │   │  (Victim)    │           │
  │   └──────┬──────┘   └──────────────┘           │
  │          │                                      │
  │          │  VM Escape                           │
  │          ├──────────────────────►HOST            │
  │          │   (arbitrary code in VMM/host)       │
  │          │                                      │
  └─────────────────────────────────────────────────┘
```

**Escape categories:**

| Category | Mechanism | Typical Root Cause |
|---|---|---|
| **Device emulation bug** | Malicious input to emulated device → bug in emulation code → code execution in VMM | Buffer overflows, integer issues, logic errors in QEMU `hw/` |
| **vCPU state corruption** | Malicious guest manipulates vCPU state to corrupt VMM | Race conditions, missing validation in KVM/Hyper-V |
| **Memory mapping bug** | Incorrect EPT/guest-physical mapping → cross-VM memory access | Reference counting bugs, race conditions in Xen grant tables |
| **Shared resource exploit** | Abuse of virtio/vsock/shared memory interfaces | Insufficient sanitization, missing bounds checks |
| **Side channel** | Exploit timing/behavior differences to leak data from host or other VMs | EPT-based, cache-based, deduplication-based |

### 5.2 Network-Based Escapes

Hypervisors virtualize networking through software NICs (e1000, rtl8139, virtio-net) or SR-IOV passthrough.

**Attack vectors:**

```
  Guest VM (Attacker)
       │
       │ Crafted packets/frames
       ▼
  ┌─────────────┐
  │ vNIC Driver  │  (Guest: e1000, rtl8139, virtio-net)
  └──────┬──────┘
         │ MMIO / PIO writes
         ▼
  ┌─────────────┐
  │ NIC Emulator │  (QEMU: hw/net/e1000.c, hw/net/rtl8139.c)
  └──────┬──────┘
         │ Bug: overflow, UAF, logic error
         ▼
  ┌─────────────┐
  │ QEMU Process │  (Runs on host with elevated privileges)
  └─────────────┘
```

**Notable network-based escape cases:**

- **CVE-2015-5165** (RTL8139): Guest could transmit a specially crafted packet descriptor that triggers a heap overflow in the RTL8139 receive path. The `RTL8139` emulator's `rtl8139_cplus_transmit_one()` function failed to validate buffer sizes, enabling arbitrary write in QEMU process.
- **CVE-2015-7504** (PCNET): Similar class of bug — buffer overflow in the PCNET emulator's loopback test mode.

### 5.3 Device Emulation Bugs

QEMU contains dozens of device models, each thousands of lines long. The relationship between guest and device is inherently adversarial:

```c
// hw/display/vga.c — typical pattern
// Guest programs VGA registers via MMIO
static void vga_ioport_write(void *opaque, uint64_t addr, unsigned size, uint32_t val) {
    VGACommonState *s = opaque;

    switch (addr) {
    case VGA_CRT_IM:
        s->crt_index = val;  // Guest-controlled index
        break;
    case VGA_CRT_DA:
        // BUG: crt_index not validated!
        // If crt_index > ARRAY_SIZE(crt), out-of-bounds write
        s->crt[s->crt_index] = val;
        break;
    // ...
    }
}
```

**Categories of emulated devices commonly exploited:**

| Device | QEMU Source | Bug Pattern |
|---|---|---|
| Floppy controller (FDC) | `hw/block/fdc.c` | Heap overflow in data transfer (VENOM) |
| VGA | `hw/display/vga.c` | Integer overflow, OOB write |
| e1000 NIC | `hw/net/e1000.c` | Descriptor chain manipulation |
| rtl8139 NIC | `hw/net/rtl8139.c` | Offload processing (CVE-2015-5165) |
| virtio devices | `hw/virtio/*.c` | Descriptor table races |
| XHCI USB | `hw/usb/hcd-xhci.c` | Use-after-free (CVE-2020-3950) |
| Serial/UART | `hw/char/serial.c` | Buffer overflow in FIFO |
| IDE controller | `hw/ide/core.c` | DMA buffer overflow |
| NVMe | `hw/nvme/*.c` | SQ/CQ race conditions |

### 5.4 vCPU Exploitation

The vCPU — the virtual CPU exposed to the guest — is itself an attack surface. Bugs in KVM and other hypervisors' vCPU management can lead to host compromise.

**Key vCPU attack vectors:**

1. **Register state manipulation**: The guest can modify CR0, CR4, segment registers, and MSRs. If the hypervisor doesn't correctly validate these on VM exit, it can corrupt host state.

2. **Exception handling races**: The guest can trigger complex exception scenarios (e.g., breakpoints, double faults, NMIs) that race with vCPU state transitions.

```
  Guest vCPU                     KVM (Host Ring 0)
       │                              │
       │ MOV SS (suppresses #DB)      │
       │ INT3                         │
       │ ────── VM Exit ─────────────►│
       │                              │ Process #DB exception
       │                              │ BUG: MOV SS + #DB not handled
       │                              │ → Privilege escalation
       │                              │ (CVE-2018-8897)
```

3. **vCPU lifecycle races**: Creating, destroying, and migrating vCPUs involves complex locking. Races between `KVM_CREATE_VCPU`, `KVM_RUN`, and vCPU destruction can cause UAF.

```c
// Simplified pattern: vCPU lifecycle race
// Thread 1 (vCPU ioctls):          Thread 2 (teardown):
// KVM_RUN                          KVM_CREATE_VCPU
//   vcpu_load()                      kvm_arch_vcpu_create()
//   vcpu->arch.xxx = ...             ...
//   <- blocked in guest ->            kvm_arch_vcpu_destroy()
//                                      vcpu->arch freed!
//   <- VM exit ->
//   vcpu->arch.xxx  // UAF!
```

4. **APIC virtualization bugs**: The APIC (Advanced Programmable Interrupt Controller) has complex state that must be virtualized. Bugs in APIC emulation can allow guests to inject arbitrary interrupts or corrupt host APIC state.

### 5.5 Shared Memory / vsock Attacks

Mechanisms that share memory or communication channels between guest and host (or between guests) are natural attack surfaces:

#### Virtio Shared Memory

```
  ┌───────────────────┐        ┌───────────────────┐
  │     Guest VM      │        │     Host / VMM     │
  │                   │        │                    │
  │  ┌─────────────┐  │        │  ┌─────────────┐  │
  │  │ Virtio      │  │ MMIO   │  │ Virtio      │  │
  │  │ Frontend    │◄─┼────────┼─►│ Backend     │  │
  │  │ Driver      │  │        │  │ (vhost)     │  │
  │  └─────────────┘  │        │  └─────────────┘  │
  │                   │        │                    │
  │  Descriptor Table│◄───────┼──►Shared Memory    │
  │  (guest memory)  │  DMA   │  (mapped to host)  │
  └───────────────────┘        └───────────────────┘
```

**Virtio descriptor chain attacks:**

The guest populates a **descriptor table** — a ring buffer of `{addr, len, flags}` entries. The backend (vhost/vhost-user) processes these descriptors and accesses guest memory at the indicated addresses.

Attack patterns:
- **Descriptor chain loops**: Malicious guest creates circular descriptor chains → infinite loop in backend.
- **Out-of-bounds access**: Guest provides addresses/lengths that point outside the allocated region → backend reads/writes out of bounds.
- **TOCTOU in descriptor processing**: Guest modifies descriptor after backend validates it but before backend reads it → classic TOCTOU.

#### vsock (VM Socket)

vsock provides a socket interface between guest and host. It bypasses traditional networking:

- **CVE-2023-1859**: Use-after-free in `vsock_remove_bound()` when destroying a vsock socket. A malicious guest could trigger a race between socket close and packet processing.
- **CVE-2022-3625**: Out-of-bounds access in `virtio_transport_recv_pkt()` — guest could provide malformed `virtio_vsock_hdr` leading to heap corruption in the host kernel.

#### vhost-user

`vhost-user` moves virtio backends out of the hypervisor process into a separate userspace process, communicating over a UNIX domain socket. This reduces the hypervisor's attack surface but creates new ones:

- **Shared memory regions** (memory tables) can be poisoned by a malicious process.
- **Protocol race conditions** in `vhost-user` message handling.
- **DMABUF / zero-copy** paths increase the complexity of memory lifecycle management.

---

## 6. EPT / NPT Attacks

Extended Page Tables (Intel) and Nested Page Tables (AMD) are critical for memory isolation. Flaws in EPT/NPT management are among the most dangerous hypervisor bugs because they directly violate inter-VM memory isolation.

### 6.1 Double Page Mapping

**Concept**: A guest-physical page is mapped to **two different host-physical pages** (or vice versa) due to a bug in EPT management. This can happen when:

1. Memory ballooning changes guest physical layout.
2. Live migration copies pages to a new host.
3. Page deduplication (KSM) merges identical pages then one guest modifies its copy (copy-on-write).

```
  Guest-Physical Address 0x100000
         │
         │ EPT Entry 1 (stale)
         ├──────────────────► Host-Physical 0xAAAA000  ◄── Old mapping
         │
         │ EPT Entry 2 (current)
         └──────────────────► Host-Physical 0xBBBB000  ◄── New mapping
```

**Exploitation scenarios:**

- **Cross-VM data leakage**: If two VMs share a physical page that should have been unshared, one VM can read the other's data.
- **Cross-VM code injection**: If a guest can cause its EPT entry to point to another VM's physical page, it can write to that VM's memory.
- **Denial of service**: Stale mappings can cause host kernel panics if the pointed-to page has been freed.

**Real-world example**: Xen XSA-282 (CVE-2019-18421) — a bug in Xen's shadow paging could cause a guest-physical page to be mapped to the wrong machine page after a page type change.

### 6.2 EPT Invalidation Races

When the hypervisor modifies EPT entries (e.g., during memory ballooning, page fault handling, or live migration), it must ensure that all physical CPUs see the updated entries. This requires **EPT invalidation** (INVEPT instruction on Intel or INVLPGA on AMD).

```
  CPU 0 (vCPU 0)              CPU 1 (vCPU 1)
  ┌──────────────────┐        ┌──────────────────┐
  │ Read EPT entry    │        │                  │
  │ Page A → PA 0xAA │        │                  │
  │                  │        │                  │
  │ Access PA 0xAA   │        │                  │
  │                  │        │ VMM updates EPT  │
  │                  │        │ Page A → PA 0xBB │
  │                  │        │                  │
  │                  │        │ INVEPT (invalid.)│
  │                  │        │                  │
  │                  │        │ Access Page A    │
  │                  │        │ → reads PA 0xBB  │
  │                  │        │                  │
  │ Still using PA   │        │                  │
  │ 0xAA (stale TLB) │        │                  │
  └──────────────────┘        └──────────────────┘
```

**The race**: If CPU 0 has a stale TLB entry after the VMM updates EPT and calls INVEPT, CPU 0 may continue accessing the old physical page. This can lead to:

- **Data corruption**: Two CPUs see different data for the same guest-physical address.
- **Security violation**: One vCPU sees a page that the VMM has removed from the guest's EPT (e.g., a freed page now belonging to another VM).

**Mitigations:**
- IPI-based TLB shootdowns (send IPI to all vCPUs before considering EPT update complete)
- Using VPID to tag TLB entries per-vCPU and invalidate selectively
- On Intel, INVEPT with "global" context type ensures all processors invalidate

**Historical bugs:**
- Xen had several EPT invalidation races (XSA-281, XSA-290) where INVEPT was not issued on all necessary CPUs, allowing stale mappings.
- KVM had a race where `kvm_mmu_zap_all()` could leave stale entries in the EPT while vCPUs were still running.

### 6.3 Deduplication Side Channels

**Kernel Same-Page Merging (KSM)** and similar deduplication mechanisms (e.g., VMware's Content-Based Page Sharing) merge identical physical pages across VMs into a single copy-on-write page to save memory. This creates a powerful side channel.

#### Attack Mechanism

```
  VM A (Attacker)                              VM B (Victim)
  ┌─────────────────────────┐                  ┌─────────────────────────┐
  │                         │                  │                         │
  │  Page P_a: "secret"    │                  │  Page P_b: "secret"    │
  │                         │                  │                         │
  │  KSM merges P_a and P_b│──────────────────│  into shared page P_s  │
  │  (same content)         │                  │                         │
  │                         │                  │                         │
  │  Write to P_a           │                  │                         │
  │  → COW fault occurs    │   Timing leak!    │                         │
  │  → SLOWER than normal  │◄─────────────────│  KSM unmerges?          │
  │                         │                  │                         │
  └─────────────────────────┘                  └─────────────────────────┘
```

**Step-by-step:**

1. **Prepare**: Attacker fills a page with known content.
2. **Wait**: KSM scans and merges the attacker's page with a page in the victim VM that has the same content.
3. **Probe**: Attacker writes to its page. If KSM had merged it, a **copy-on-write fault** occurs, which takes measurably longer (~2-10 µs) than a normal write.
4. **Infer**: By observing which content patterns trigger COW faults, the attacker can determine the victim's page content one byte at a time.

**This is a cache timing side channel:**

```c
// Simplified timing measurement
uint8_t probe_byte = guess;

// Fill page with probe_byte
memset(probe_page, probe_byte, PAGE_SIZE);

// Wait for KSM to merge (typically 5-30 seconds)

// Time the write
t1 = rdtsc();
probe_page[0] = ~probe_byte;  // Trigger COW if merged
t2 = rdtsc();

if (t2 - t1 > THRESHOLD) {
    // COW fault occurred → KSM merged → guess was correct
    // The victim page contains the byte `probe_byte`
}
```

**Known implementations of this attack:**

| Name | Year | Platform | Target |
|---|---|---|---|
| **Xu et al.** | 2015 | KVM/KSM | Cross-VM memory deduplication |
| **CAB** (Content-Based Collision) | 2016 | VMware | Content-based page sharing |
| **Flush+Reload via KSM** | 2014 | KVM/KSM | RSA key recovery across VMs |
| **DUCA** | 2019 | Cross-platform | Differential utilization of deduplication |

**Mitigations:**

| Mitigation | Description | Trade-off |
|---|---|---|
| **Disable KSM** | `echo 0 > /sys/kernel/mm/ksm/run` | Eliminates memory savings |
| **Clepáticos** | Randomize page content before merging | Clear-text not stored, but complex |
| **Memory coloring** | Prevent cross-VM page merging | Reduces merging effectiveness |
| **Intra-VM merge only** | Only merge pages within the same VM | Retains some savings |
| **Adaptive merging** | Disable KSM under detected probe activity | Hard to detect reliably |
| **Hardware-based isolation (SEV)** | AMD SEV encrypts guest memory — KSM cannot compare encrypted ciphertext | Best isolation; hardware-dependent |

#### SEV/SEV-ES/SEV-SNP and EPT

AMD's SEV (Secure Encrypted Virtualization) adds memory encryption to guests, which fundamentally changes EPT attacks:

- **SEV**: Guest memory encrypted with a VM-specific key. KSM cannot merge because ciphertext differs. But EPT is still managed by the hypervisor — **EPT-based attacks still work** (remapping pages, mapping the same page twice).
- **SEV-ES**: Encrypts register state on VM exit, preventing register leaks. But EPT-based attacks and interrupt injection attacks remain.
- **SEV-SNP**: Adds **Reverse Map Table (RMAP)** and integrity checking. Prevents EPT remapping attacks — the guest can verify that a physical page belongs to it and hasn't been aliased. This specifically mitigates the double-mapping and invalidation race attacks described above.

```
  SEV Protection Hierarchy
  ┌──────────────────────────────┐
  │          SEV-SNP             │  Integrity + Encryption + Register Encryption
  │    ┌────────────────────┐    │
  │    │       SEV-ES        │    │  Register Encryption
  │    │  ┌────────────────┐ │    │
  │    │  │      SEV       │ │    │  Memory Encryption Only
  │    │  └────────────────┘ │    │
  │    └────────────────────┘    │
  └──────────────────────────────┘

  Mitigated by each level:
  ────────────────────────────────
  SEV:     KSM side channels (encryption key prevents content comparison)
  SEV-ES:  Register dump on VM exit (encrypted guest state in VMCB)
  SEV-SNP: EPT remapping, double mapping, aliasing (ATTACK_TABLE verification)
           - Hypervisor cannot map same page to two guests
           - Hypervisor cannot remap guest physical to different host physical
             without guest detecting
```

---

## Summary: The Full Ring -1 Attack Surface

```
                    RING -1 ATTACK SURFACE
                          │
        ┌─────────────────┼───────────────────┐
        │                 │                   │
    ┌───┴────┐     ┌──────┴──────┐     ┌─────┴──────┐
    │Device  │     │  vCPU/CPU   │     │  Memory   │
    │Emul.   │     │  Mgmt       │     │  Mgmt     │
    │        │     │             │     │           │
    │• NIC   │     │• VMCS/VMCB │     │• EPT/NPT  │
    │• Disk  │     │• VM Exit   │     │• KSM/DD   │
    │• USB   │     │• Register  │     │• Balloon  │
    │• VGA   │     │• APIC      │     │• vhost    │
    │• Serial│     │• Timers    │     │• vsock    │
    │• FDC   │     │• Exception │     │• Grant    │
    │• Virtio│     │• SIMD      │     │  tables   │
    └────────┘     └─────────────┘     └───────────┘
        │                 │                   │
     100+               20+                  15+
   CVEs/year          CVEs/year            CVEs/year

    Defensive Principles:
    ─────────────────────
    1. Minimize emulated device surface (use virtio + vhost)
    2. Sandbox device emulation (seccomp, separate processes)
    3. Enable EPT/NPT hardening (no writable-executable mappings)
    4. Disable KSM in multi-tenant environments
    5. Use SEV-SNP or TDX for confidential computing
    6. Apply hypervisor patches immediately
    7. Restrict VM-to-host communication (vsock, virtio)
    8. Audit VMCS/VMCB configurations carefully
```

---

## References

1. Intel. "Intel 64 and IA-32 Architectures Software Developer's Manual." Volume 3C: Chapter 24–33 — VMX (Virtual Machine Extensions).
2. AMD. "AMD64 Architecture Programmer's Manual Volume 2." Chapter 15 — Secure Virtual Machine (SVM).
3. Rutkowska, J. "Subverting Vista Kernel For Fun And Profit." Black Hat, 2006.
4. King, S.T., et al. "SubVirt: Implementing Malware with Virtual Machines." IEEE S&P, 2006.
5. Geffner, J. "VENOM: A Virtual Environment Not Operating as Meant." CrowdStrike, 2015.
6. Lipp, M., et al. "Meltdown: Reading Kernel Memory from User Space." USENIX Security, 2018.
7. Kocher, P., et al. "Spectre Attacks: Exploiting Speculative Execution." IEEE S&P, 2019.
8. Yarom, Y., Falkner, K. "Flush+Reload: A High Resolution, Low Noise, L3 Cache Side-Channel Attack." USENIX Security, 2014.
9. NIST. "National Vulnerability Database." CVE entries: CVE-2015-3456 (VENOM), CVE-2015-5165 (QEMU RTL8139), CVE-2019-6974 (KVM UAF), CVE-2021-28476 (Hyper-V race), CVE-2018-8897 (MOV SS debug exception).
10. AMD. "SEV-SNP: Strengthening VM Isolation with Integrity." AMD Developer Documentation, 2022.

---

*Report covering Ring -1 hypervisor architecture, VMX/SVM operation, VM escapes, device emulation vulnerabilities, vCPU attacks, EPT/NPT exploitation, and deduplication side channels.*
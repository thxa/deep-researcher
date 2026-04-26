# Ring 2 and Ring 1: TheUnused Middle Rings of x86

## 1. What Are Ring 2 and Ring 1?

The x86 protection ring architecture defines four privilege levels, encoded in the two least-significant bits of the **CPL** (Current Privilege Level) field in the CS segment selector:

| Ring | CPL | Intended Role |
|------|-----|---------------|
| Ring 0 | 0 | Kernel / supervisor — full hardware access |
| Ring 1 | 1 | Privileged services (e.g., device drivers) |
| Ring 2 | 2 | Less-privileged services (e.g., I/O subsystems) |
| Ring 3 | 3 | User applications — most restricted |

Rings 1 and 2 were designed to hold **system service layers** that need more privilege than user code but less than the kernel core. The idea: a buggy driver running at Ring 1 or Ring 2 could not corrupt kernel data structures, and user code at Ring 3 could not touch driver memory. This is the layering model inherited from MULTICS' concentric protection rings (which had 8 rings).

In x86, every memory segment and every privilege-sensitive instruction carries a **DPL** (Descriptor Privilege Level). Access is granted when `CPL <= DPL` (for data) or according to specific gate rules (for code). The CPU enforces this in hardware — no software bypass is possible without a privilege transition through a gate or instruction like `iret`.

## 2. Historical Context

### 2.1 Why Rings 1 and 2 Were Designed

The Intel 286 (iAPX 286) introduced the four-ring model in 1982, directly influenced by MULTICS' philosophy of hierarchical protection. The intent:

- **Ring 0**: Core kernel — memory management, scheduling, IPC
- **Ring 1**: Device drivers, filesystem code — privileged but isolated from the kernel
- **Ring 2**: I/O subsystems, network stacks — need port I/O but not full hardware control
- **Ring 3**: User applications

OS/2 1.x (16-bit, 286-targeted) actually attempted this segmentation. Drivers could be placed at Ring 1 or Ring 2, and the kernel at Ring 0 would mediate. This offered theoretical fault isolation: a Ring 2 network driver crash would not require a kernel reboot.

MULTICS itself had 8 rings, with rings 32–35 (inner) for the supervisor, 36–39 for daemons, and 40–63 for user processes. Intel's designers simplified this to 4 rings, but the layered principle was the same.

### 2.2 Why Modern OSes Abandoned Rings 1 and 2

In practice, **every mainstream OS today uses only Ring 0 and Ring 3** (the "flat model"):

- **Linux**: Kernel runs at Ring 0; all user processes at Ring 3. Drivers are linked into the kernel image or loaded as kernel modules — they execute at Ring 0.
- **Windows NT**: Same model. The NT kernel (`ntoskrnl.exe`) and all drivers run at Ring 0; Win32 subsystem and applications run at Ring 3.
- **macOS / XNU**: Same.

Reasons for this convergence:

1. **Performance**: Every ring transition requires a GDT/LDT lookup and privilege check. A Ring 3 → Ring 1 → Ring 0 call chain adds two transitions; the flat model needs only one. The `syscall`/`sysenter` fast path is designed specifically for Ring 3 → Ring 0.

2. **Complexity**: Writing code that correctly handles four privilege levels is enormously hard. Every pointer cross-ring boundary must be validated; every shared buffer must have appropriate DPLs; the TSS and GDT must be configured for each transition. Bugs in Ring 1/2 isolation code can be worse than a single Ring 0 trust boundary.

3. **Portability**: RISC architectures (ARM, RISC-V, MIPS) only have two modes: supervisor and user. An OS using Rings 1 and 2 cannot be ported to those platforms without major restructuring.

4. **Win32 semantics**: The Windows driver model (WDM/KMDF) assumes drivers share kernel address space. Isolating drivers at Ring 1 would require a fundamental API redesign.

5. **TLB and paging**: Modern x86 paging ties privilege to only two levels via the U/S bit in page table entries. While rings 1 and 2 can be distinguished by segmentation, they are all treated as "supervisor" pages (U/S=0), meaning the MMU cannot enforce Ring 1 vs. Ring 2 at the page level. This undermines the entire isolation argument.

### 2.3 OSes That Did Use Rings 1 and 2

- **OS/2 1.x** (16-bit, 286): The canonical example. The kernel occupied Ring 0, subsystems and some drivers at Ring 1–2, applications at Ring 3. When OS/2 transitioned to 32-bit (2.0+), it abandoned this model.

- **L4 microkernel family**: L4Ka::Pistachio and other L4 implementations use Ring 1 for user-level device drivers and servers, keeping the microkernel at Ring 0 and applications at Ring 3. Ring 2 is sometimes used for interrupt-forwarding stubs.

- **QNX Neutrino** (early versions): Used Ring 1 for some privileged managers, though later versions simplified to the flat model.

- **Various RTOS**: Some embedded real-time OSes targeting x86 use Ring 1–2 for I/O tasks that need port I/O access (via IOPL) but shouldn't have full kernel privileges.

- **MINIX 3**: Uses Ring 0 for the tiny kernel, Ring 1 for device drivers, and Ring 3 for user processes. Ring 2 is unused. This is one of the few active OSes that genuinely uses Ring 1.

## 3. How Ring 2 and Ring 1 Are Used Today

### 3.1 x86 Virtualization (VMX Root vs. Non-Root)

This is by far the most significant modern use of the ring concept in a modified form. Intel VT-x and AMD-V introduce a **new privilege axis orthogonal to the rings**:

```
┌─────────────────────────────────────────┐
│            VMX Root Mode                │
│  [Ring 0] Hypervisor / VMM             │
│  [Ring 3] VMM user-mode components     │
├─────────────────────────────────────────┤
│          VMX Non-Root Mode             │
│  [Ring 0] Guest kernel                 │
│  [Ring 1] Unused (or guest drivers)    │
│  [Ring 2] Unused                       │
│  [Ring 3] Guest user applications      │
└─────────────────────────────────────────┘
```

The guest OS sees the ring architecture normally — it believes it is running at Ring 0 when in kernel mode. But the **real** root of trust is the hypervisor in VMX root mode.

- **VMX non-root Ring 0**: What the *guest kernel* thinks is true Ring 0. Certain instructions (`cli`, `hlt`, `wrmsr`, `invlpg`, etc.) cause VM exits to the hypervisor.
- **VMX root Ring 0**: The actual most-privileged execution mode, where the hypervisor runs.
- **VMX non-root Ring 3**: Guest user mode, identical in restrictions to native Ring 3 plus virtualization overlays.

Rings 1 and 2 in VMX non-root mode are mechanically functional — the CPU enforces their DPL checks — but in practice, guest OSes don't use them (since Linux/Windows don't use them natively either).

### 3.2 Call Gates and Task Gates (Legacy)

**Call gates** are GDT/LDT descriptors that allow controlled Ring 3 → Ring 0 (or Ring 3 → Ring 1 → Ring 0) transitions via `call` or `jmp`. A call gate specifies:

- **Target selector + offset**: Where execution transfers.
- **DPL**: Minimum CPL that may invoke the gate.
- **Param count**: Number of stack words copied across rings.

```asm
; Legacy Ring 3 → Ring 0 transition via call gate
; GDT entry for the call gate:
;   Target = KERNEL_CODE_SEL : sys_call_handler
;   DPL    = 3
;   Params = 0

call far KERNEL_CALL_GATE_SEL   ; triggers privilege transition
```

When a call gate is invoked, the CPU:
1. Validates `CPL <= DPL` of the gate descriptor.
2. Validates `CPL >= DPL` of the target code segment ( Outer privilege cannot call inner code directly; must use a gate).
3. Switches stack to the target ring's stack (SS:ESP from the TSS).
4. Copies parameters per the param count.
5. Transfers control to the target offset at the new CPL.

**Task gates** are similar but perform a full task switch via hardware, using the TSS mechanism. An IDT entry can be a task gate, causing a hardware task switch on interrupt. Like call gates, these are almost entirely unused in modern 64-bit OSes (long mode doesn't support hardware task switching for interrupts; the IST mechanism is used instead).

Call gates are **technically still functional in 64-bit mode** for privilege transitions (though 64-bit call gates use a different descriptor format), but no mainstream OS uses them. They are a preserved legacy mechanism that no one exercises — which makes them interesting from a security perspective.

### 3.3 Embedded/Hypervisor Scenarios

- **Type-1 hypervisors** (Xen, VMware ESXi, Hyper-V): The hypervisor occupies VMX root Ring 0. Xen's architecture interestingly uses Ring 1 for the Xen hypervisor and Ring 0 for the dom0 kernel in **paravirtualized** (PV) mode — effectively inverting the expected ring layout. This was before hardware virtualization (HVM) was mature. PV guests at Ring 1 had to be explicitly ported to use hypercalls instead of privileged instructions.

  ```
  Xen PV model (pre-HVM):
  Ring 0  → dom0 kernel (paravirtualized)
  Ring 1  → Xen hypervisor
  Ring 3  → domU user processes
  ```

- **SMM (System Management Mode)**: Often called "Ring −1." SMM operates at a privilege level below Ring 0, with its own address space (SMRAM) and a separate execution mode entered via the SMI (System Management Interrupt). SMM is invisible to the OS and even to a hypervisor that doesn't explicitly trap SMIs. Ring 2/1 are irrelevant to SMM, but SMM demonstrates that the ring model doesn't capture all x86 privilege — there exist modes below Ring 0.

- **Intel SGX** enclaves: These arguably live "between" Ring 3 and Ring 0 — enclave code runs at Ring 3 CPL but with hardware-protected memory that even Ring 0 cannot read/modify once initialized. This is another privilege axis the ring model doesn't capture.

### 3.4 IOPL and Ring 2

The **I/O Privilege Level (IOPL)** is a 2-bit field in the EFLAGS register (bits 12–13). It determines which CPL values are allowed to execute I/O instructions (`in`, `out`, `ins`, `outs`, `cli`, `sti`) and access I/O-mapped ports:

- If `CPL <= IOPL`: I/O instructions are permitted.
- If `CPL > IOPL`: I/O instructions cause a #GP (General Protection) fault, unless the corresponding bit in the I/O Permission Bitmap (in the TSS) allows it.

IOPL can only be modified by code running at Ring 0 (via `popf`/`iret`). A kernel running at Ring 0 can set IOPL=2, allowing Ring 2 code (but not Ring 3) to perform I/O directly. This was *exactly* the intended use case: a Ring 2 I/O subsystem with direct port access, no syscalls needed.

```
IOPL=0: Only Ring 0 can do I/O
IOPL=1: Rings 0,1 can do I/O
IOPL=2: Rings 0,1,2 can do I/O    ← The Ring 2 use case
IOPL=3: All rings can do I/O
```

In practice, Linux uses IOPL=0 always. Some real-time and embedded x86 systems briefly set IOPL=3 in user tasks for direct I/O (e.g., hardware control loops), but this is a security risk and generally avoided.

## 4. Security Implications of Unused Rings

### 4.1 Attack Surface of Rings 1 and 2

Unused rings are not directly an attack surface in the sense that there's no code running in them. However, the **CPU hardware that implements them still exists** — and that hardware can be weaponized:

- **Call gate descriptors in the GDT/LDT**: If the OS doesn't properly sanitize GDT/LDT entries, a call gate with DPL=3 that targets Ring 0 code could be installed by an attacker (via modify_ldt syscall on Linux, for example) to create a Ring 3 → Ring 0 escalation path that bypasses syscall entry point controls.

- **TSS structures**: The TSS contains SS:ESP pointers for Ring 0, Ring 1, and Ring 2 stacks. If an attacker can corrupt the TSS, they can control the kernel stack pointer used on ring transitions — a powerful primitive.

- **IOPL manipulation**: On systems where IOPL is changed (rare but possible in RTOS or via loadable kernel modules), a misconfigured IOPL can grant user code direct I/O port access, enabling DMA attacks, PCI config space manipulation, and SMI invocation.

### 4.2 Call Gate Exploitation

Call gates are a particularly interesting attack vector in 32-bit mode:

1. **Linux's `modify_ldt` syscall**: Historically allowed creating call gate entries in the LDT. An attacker with the ability to write to the LDT (via `modify_ldt(1, ...)`) could install a call gate with DPL=3 targeting a Ring 0 selector. This grants direct execution at Ring 0 from Ring 3, bypassing syscall entry filtering and kernel ASLR protections.

   Modern Linux has largely mitigated this: `modify_ldt` now only allows creating data and code segments, not call gates. But on older kernels (pre-4.x), this was viable.

2. **GDT corruption**: If a kernel has a write-what-where primitive, writing a call gate descriptor into the GDT is a straightforward Ring 3 → Ring 0 escalation that is **not cleared by any SMEP/SMAP/W^X mitigation** — these are all about preventing Ring 0 from executing/setjmp Ring 3 code; call gates operate in the opposite direction.

3. **Descriptor table privilege escalation flow**:
   ```
   Attacker (Ring 3) → modify_ldt() → install call gate (DPL=3, target=Ring 0)
                     → call far <call_gate_selector>
                     → Ring 0 execution achieved
   ```

4. **In 64-bit long mode**, call gates still exist in the architecture but have restricted semantics. However, the gate descriptor format is different (16 bytes instead of 8), and `modify_ldt` does not permit creating them. An attacker would need a GDT write primitive, which is less common but not impossible.

### 4.3 CPL Changes via `iret`/`sysret`

The `iret` (Interrupt Return) instruction is the canonical way to return from an interrupt/trap handler and restore a lower- privilege context. It pops EIP, CS, EFLAGS, (ESP, SS if crossing rings). A critical security property:

- **`iret` can decrease CPL** (Ring 0 → Ring 3): This is normal.
- **`iret` can increase CPL** (Ring 3 → Ring 0): **Only if the return CS selector has DPL >= CPL of the caller.** In practice, this means Ring 0 code can `iret` to any ring.

This means that if an attacker can **control the stack frame used by `iret`** (e.g., via a kernel stack buffer overflow or a use-after-free that corrupts the `iret` frame), they can:

1. Return to Ring 0 code with a Ring 0 CS selector — gaining kernel execution.
2. Set IOPL in the popped EFLAGS to 3 — granting I/O access at Ring 3.
3. Set the interrupt flag (IF) — re-enabling interrupts if disabled.
4. Change the SS:ESP to point to attacker-controlled memory.

**`sysret`** (AMD's fast return from syscall) has a subtle and widely-exploited vulnerability class:

- On Intel CPUs, `sysret` loads RCX into RIP and R11 into RFLAGS. However, it **does not restore RFLAGS properly for RF (Resume Flag)** and has edge-case behavior around the AC (Alignment Check) flag.
- The **canonical bug**: `sysret` with a non-canonical RIP causes a #GP fault — which is delivered at Ring 0 (since `sysret` has already switched to Ring 3 CS). This creates a window where the kernel handles an exception with stale register state. This was exploited in CVE-2012-0217 (FreeBSD) and similar vulnerabilities in Xen and other hypervisors.

```
sysret privilege transition vulnerability pattern:

1. Attacker sets RCX = non-canonical address
2. syscall executes, eventually kernel calls sysret
3. sysret loads non-canonical RCX → #GP at CPL 3 ... but wait
4. On Intel: #GP is raised at CPL 0 (kernel) instead of CPL 3
5. Kernel #GP handler runs with attacker-influenced state
6. Privilege escalation
```

### 4.4 Ring Deception in Virtualization

In virtualized environments, Rings 1 and 2 have a specific attack surface:

- **VMX non-root Ring 0**: The guest kernel believes it's at Ring 0, but it's not truly at Ring 0. Hypervisors must carefully virtualize instructions that behave differently depending on whether the CPU is in root or non-root mode. Any mismatch between guest expectations and actual behavior is a potential vulnerability.

- **SMM vs. VMX**: SMM is more privileged than VMX root Ring 0. If SMI interrupts arrive during hypervisor execution, the hypervisor is not in control. Malicious firmware or SMI handlers can compromise the hypervisor from below — this is the "Ring −2" attack surface.

- **Virtualization of IOPL**: A guest setting IOPL=2 in VMX non-root mode expects Ring 2 I/O permissions. The hypervisor must correctly virtualize this, including the I/O Permission Bitmap. Mishandling leads to guests gaining or losing I/O access incorrectly.

## 5. Ring Transitions in Detail

### 5.1 How the CPU Transitions Between Rings

Ring transitions on x86 are among the most architecturally complex operations. There are several mechanisms:

#### Direct Transitions (Privilege Elevation)

| Mechanism | Direction | Mechanism |
|-----------|-----------|-----------|
| `syscall`/`sysenter` | Ring 3 → Ring 0 | Fast system call (MSR-driven) |
| `int 0x80` / `int n` | Ring 3 → Ring 0 | Interrupt descriptor (trap/interrupt gate) |
| Call gate `call` | Ring 3 → Ring N (N < 3) | GDT/LDT call gate |
| Task gate | Ring 3 → Ring 0 | Hardware task switch |

#### Direct Transitions (Privilege Drop)

| Mechanism | Direction | Mechanism |
|-----------|-----------|-----------|
| `sysret`/`sysexit` | Ring 0 → Ring 3 | Fast system call return (MSR-driven) |
| `iret` | Ring N → Ring M (M > N, or any if N=0) | Interrupt return |

#### Conformal Code Segments

A code segment marked as **conforming** (bit 2 of the type field in the descriptor) can be called from a lower-privilege ring *without* a ring transition. The calling code retains its CPL. This is rarely used but is how some ROM/BIOS code was meant to work. Conforming segments have a DPL that specifies the *maximum* CPL that can call them, not the CPL they run at.

### 5.2 TSS (Task State Segment) and Hardware Task Switching

The TSS is a data structure in memory (pointed to by the TR — Task Register) that holds the processor state for hardware task switching:

```c
// Simplified 32-bit TSS structure (Intel SDM Vol 3, Section 7.7)
struct tss32 {
    uint16_t back_link;   // Previous task selector
    uint16_t :0;          // Reserved
    uint32_t esp0;        // Stack pointer for Ring 0
    uint16_t ss0;         // Stack selector for Ring 0
    uint16_t :0;
    uint32_t esp1;        // Stack pointer for Ring 1
    uint16_t ss1;         // Stack selector for Ring 1
    uint16_t :0;
    uint32_t esp2;        // Stack pointer for Ring 2
    uint16_t ss2;         // Stack selector for Ring 2
    uint16_t :0;
    uint32_t cr3;         // Page directory base
    uint32_t eip;         // Instruction pointer
    uint32_t eflags;      // Flags register
    uint32_t eax, ecx, edx, ebx;     // General registers
    uint32_t esp, ebp, esi, edi;     // General registers
    uint16_t es, :0, cs, :0, ss, :0, ds, :0, fs, :0, gs, :0;  // Segments
    uint16_t ldt_sel, :0;
    uint16_t trace, iomap_base;
    // I/O permission bitmap follows at iomap_base offset
};
```

The TSS is critical for ring transitions in 32-bit mode:

- **Stack switching**: When transitioning from Ring 3 to Ring 0 (e.g., on interrupt), the CPU automatically loads `ss0:esp0` from the TSS. Without a valid TSS, the CPU **cannot** perform privilege elevation — it will double-fault.

- **Ring 1 and Ring 2 stacks**: The `ss1:esp1` and `ss2:esp2` fields are used when transitioning to Ring 1 or Ring 2. Modern OSes that don't use Rings 1 and 2 leave these fields as 0 — and they must never be reached, or a #TS (Invalid TSS) fault occurs.

- **I/O Permission Bitmap**: Located at the end of the TSS, this bitmap grants per-port I/O access to Ring 3 code (and Ring 1/2 if CPL > IOPL). This is the fine-grained alternative to IOPL.

In 64-bit long mode:

- Hardware task switching via the TSS is **not supported** for task switches (no `call` to a TSS descriptor, no task gates in the IDT). The TSS is used only for:
  - `ss0:esp0` (and `ss1:esp1`, `ss2:esp2`) for stack switching on interrupts.
  - IST (Interrupt Stack Table) pointers (IST1–IST7) for guaranteed stacks on NMI/#MC/#DF.
  - I/O Permission Bitmap (rarely used in 64-bit OSes).

Linux in 64-bit mode uses a single TSS per CPU with `rsp0` set to the current task's kernel stack. It does not use `rsp1` or `rsp2`.

### 5.3 Call Gates, Interrupt Gates, Trap Gates

#### Call Gates

A call gate descriptor in the GDT or LDT has this 64-bit structure (32-bit mode):

```
Bits 63-48: Offset [31:16]
Bit  47:    Present (P)
Bits 46-45: DPL (Descriptor Privilege Level)
Bit  44:    Type = 0xC (call gate)
Bits 43-40: Reserved / param count
Bits 39-16: Target selector (code segment)
Bits 15-0:  Offset [15:0]
```

When `call far <call_gate_selector>` is executed:
1. CPU checks `CPL <= gate.DPL` ( privilege check on the gate itself).
2. CPU checks `CPL >= target_seg.DPL` (must transition to higher privilege).
3. Stack switch: CPU reads `ssN:espN` from TSS (where N = target CPL).
4. Parameters copied from old stack to new stack (param count specified in gate).
5. Return address (CS:RIP) pushed to the new stack.
6. Execution begins at `target_segment_selector:offset` with CPL = target DPL.

This is the **only** mechanism by which Ring 3 code can invoke Ring 1 or Ring 2 code directly (other than Ring 0). It is almost never used anymore.

#### Interrupt Gates and Trap Gates

These are IDT entries that define how the CPU handles interrupts and exceptions:

| Field | Interrupt Gate | Trap Gate |
|-------|---------------|-----------|
| Type | 0xE | 0xF |
| IF flag | Cleared on entry (interrupts disabled) | Preserved |
| DPL | Minimum CPL to invoke via `int n` | Minimum CPL to invoke via `int n` |
| Stack switch | Yes, if CPL changes | Yes, if CPL changes |

**Task gates** (IDT type 0x5) cause a full hardware task switch. They point to a TSS descriptor. On interrupt, the CPU saves the current state to the current TSS and loads the target TSS. This is the mechanism that would transition to Ring 1 or Ring 2 code in a fully ring-aware OS. Modern OSes do not use task gates.

### 5.4 How Modern OSes Handle Ring Transitions

#### Fast System Calls: `syscall` / `sysenter`

Modern 64-bit OSes use `syscall` (AMD) / `sysenter` (Intel) for Ring 3 → Ring 0 transitions:

```
syscall (AMD K8+ / Intel):
  RCX ← RIP (return address)
  R11 ← RFLAGS
  CPL  ← 0
  CS    ← IA32_STAR[47:32] (kernel code segment)
  RIP   ← IA32_LSTAR (kernel entry point)

  (No stack switch! Kernel must handle RSP via per-CPU MSR or swapgs)

sysret (AMD K8+ / Intel):
  RIP  ← RCX
  RFLAGS ← R11 (with modifications)
  CPL  ← 3
  CS    ← IA32_STAR[63:48] + 16 (user code segment)
  (No stack switch! Kernel must restore RSP from per-CPU area)
```

Key design choices:
- **No automatic stack switch**: Unlike interrupt gates, `syscall` does not load `ss0:rsp0` from the TSS. The kernel must use `swapgs` (to swap GS base to kernel's per-CPU area) and then load `rsp` manually from the per-CPU data structure.
- **No parameter copy**: Unlike call gates, `syscall` does not copy parameters to a new stack. Parameters are passed in registers (System V AMD64 ABI: RDI, RSI, RDX, R10, R8, R9).
- **One privilege level**: `syscall` goes directly Ring 3 → Ring 0, bypassing Rings 1 and 2 entirely.

For interrupt handling (hardware interrupts, exceptions, NMIs):
- The CPU uses the IDT, which contains interrupt/trap gate descriptors.
- On Ring 3 → Ring 0 interrupt: CPU loads `ss0:rsp0` from the TSS (or IST pointer).
- In 64-bit mode, IST pointers provide 7 alternative stack pointers for critical events (NMI, #MC, #DF).

```c
// Linux kernel entry (simplified)
// arch/x86/entry/entry_64.S

ENTRY(entry_SYSCALL_64)
    swapgs                          // Switch GS base to kernel
    movq %rsp, %gs:cpu_current_top_of_stack  // Save user RSP
    movq %gs:cpu_entry_stack, %rsp // Load kernel stack

    // Push register state for pt_regs
    pushq $__USER_DS                // User SS
    pushq %gs:cpu_current_top_of_stack // User RSP
    pushq %r11                      // RFLAGS (saved by syscall)
    pushq $__USER_CS                // User CS
    pushq %rcx                      // User RIP (saved by syscall)
    // ... push remaining registers ...

    call do_syscall_64               // dispatch to syscall handler
    // ... restore and sysret ...
```

## 6. Virtualization Overlay: VT-x and AMD-V

### 6.1 VMX Non-Root Ring 0 vs. VMX Root Ring 0

Intel VT-x introduces two modes of operation that are orthogonal to the ring privilege levels:

```
┌──────────────────────────────────────────────────────────┐
│                    VMX Root Mode                         │
│                                                          │
│  Ring 0: Hypervisor (KVM, Xen, VMware, Hyper-V)         │
│  Ring 3: VMM user-space components (QEMU, etc.)           │
│                                                          │
│  Full hardware access. Can execute all instructions.      │
│  Can configure VMCS (Virtual-Machine Control Structure).  │
│                                                          │
├──────────────────────────────────────────────────────────┤
│                  VMX Non-Root Mode                       │
│                                                          │
│  Ring 0: Guest kernel (believes it's Ring 0)             │
│  Ring 1: Unused (available for guest use)                 │
│  Ring 2: Unused (available for guest use)                 │
│  Ring 3: Guest user applications                         │
│                                                          │
│  Restricted. Certain instructions cause VM exits.         │
│  Transparent control is mediated by hypervisor.           │
└──────────────────────────────────────────────────────────┘
```

Key properties:

- **The guest cannot detect VMX non-root mode** (absent hypervisor bugs). `cpuid` with leaf 0x01 returns the same feature flags; CPL is reported normally in CS.
- **VM exits** replace hardware exceptions for privileged operations. When the guest executes `cli`, `hlt`, `invlpg`, `wrmsr`, `cpuid` (in some configurations), or accesses a virtualized MSR, control transfers to the hypervisor via a VM exit.
- **EPT (Extended Page Tables)**: The hypervisor controls guest physical → host physical translations. This is separate from the guest's own page tables (guest virtual → guest physical). EPT violations (analogous to page faults) are delivered to the hypervisor, not the guest.

### 6.2 How Hypervisors Virtualize the Ring Architecture

The hypervisor faces several challenges in virtualizing the ring model:

#### Challenge 1: Ring Compression

When running a guest on a CPU **without hardware virtualization** (no VT-x/AMD-V), the hypervisor must de-privilege the guest kernel. This is the Xen PV approach:

- **Guest kernel runs at Ring 1** (or Ring 2) instead of Ring 0.
- **Hypervisor runs at Ring 0** (true Ring 0).
- Guest kernel must use **hypercalls** instead of privileged instructions.
- The guest's Ring 0 privilege expectations must be virtualized: any `cli`/`sti`/`hlt`/`invlpg` executed at Ring 1 would normally fault, so the hypervisor intercepts #GP faults from the guest and emulates the instruction.

This is called **ring compression** — the guest's Ring 0 is compressed into Ring 1, and Rings 1/2 of the guest are compressed into Ring 2. The guest's Ring 3 stays Ring 3.

```
Without VT-x (ring compression):

  Ring 0  → Hypervisor
  Ring 1  → Guest kernel (paravirtualized)
  Ring 2  → Guest Ring 1 (unused in practice)
  Ring 3  → Guest user / Guest Ring 3
```

**Problem**: Ring 1 code can access Ring 2 data (since CPL < DPL is allowed). The hypervisor must carefully protect its data at Ring 0 from Ring 1 guest access via page protections and segment limits.

#### Challenge 2: Shadow Page Tables

Without EPT, the hypervisor must maintain **shadow page tables** that combine the guest's virtual→physical mappings with the hypervisor's physical→machine mappings. When the guest modifies its page tables (writing to PTEs at Ring 1 in ring-compressed mode), the hypervisor must intercept these writes and update the shadow tables. This was one of the most performance-critical and bug-prone parts of Xen PV.

#### Challenge 3: Virtualizing IOPL

The guest kernel may set IOPL=0, preventing Ring 3 guest code from doing I/O. The hypervisor must virtualize this:
- If the guest runs at VMX non-root Ring 0, it can set IOPL freely, but the hypervisor controls which I/O instructions cause VM exits (via the I/O bitmap in the VMCS).
- If the guest runs ring-compressed (Ring 1), IOPL is real — the hypervisor must set IOPL=1 (so the guest kernel can do I/O) and intercept guest attempts to set IOPL to other values.

#### Modern Simplification: VMX Makes Rings 1/2 Irrelevant

With VT-x, the ring compression problem disappears. The guest kernel runs at VMX non-root Ring 0 — it has the full CPL=0 privileges that it expects (modulo VM-exiting instructions). There is no need for ring compression, no need for paravirtualization of privilege, and Rings 1/2 are free to be used by the guest however it wishes (which, in practice, is not at all).

The "ring overlay" model under VT-x:

```
Guest perspective (VMX non-root):
  Ring 0: Kernel — full CPL 0 within the VM
  Ring 3: User — restricted, as expected

Actual privilege (VMX root/non-root):
  VMX root Ring 0: True most privileged — hypervisor
  VMX non-root Ring 0: Virtual Ring 0 — guest kernel
  VMX non-root Ring 3: Virtual Ring 3 — guest user
  VMX non-root Ring 1/2: Available but unused
```

### 6.3 The Full Privilege Hierarchy (with Virtualization)

Combining rings, SMM, and virtualization, the modern x86 privilege hierarchy from most to least privileged:

```
Ring -2  (SMM + SMIs hidden from hypervisor)    — UEFI/BIOS firmware
Ring -1  (VMX root mode, CPL=0)                 — Hypervisor (KVM, Xen, VMware)
Ring 0   (VMX non-root, CPL=0)                   — Guest kernel
Ring 1   (VMX non-root, CPL=1)                   — Available (unused)
Ring 2   (VMX non-root, CPL=2)                   — Available (unused)
Ring 3   (VMX non-root, CPL=3)                   — Guest user
```

Each level can be compromised from the level below it (e.g., SMM can compromise the hypervisor, the hypervisor can compromise the guest kernel), but not from levels above it. This is why SMM is sometimes called "Ring −2" — it is below the hypervisor in the privilege hierarchy.

### 6.4 Security Implications of the Virtualization Overlay

1. **VM escapes from Ring 0**: A vulnerability in the hypervisor that allows VMX non-root Ring 0 (guest kernel) to execute code at VMX root Ring 0 is a full VM escape. The guest Ring 0 is not true Ring 0; it's virtualized Ring 0, and any confusion between the two is exploitable.

2. **Ring 1/2 as a staging ground**: In a virtualized environment, Rings 1 and 2 could theoretically be used by malware to execute code at a privilege level that the guest OS doesn't manage or monitor. Since Linux/Windows don't set up Ring 1/2 stacks in the TSS, unexpected execution at Ring 1 or Ring 2 would likely fault quickly — but in a compromised guest where an attacker controls the TSS, it could be used as a stealth layer.

3. **VMCS manipulation**: The hypervisor controls the VMCS fields that define the guest's view of CS, SS, DS, ES, FS, GS, TR, and GDTR/IDTR. An attacker with VMX root access can reconfigure a guest's CS to have DPL=1 (making the guest kernel believe it's at Ring 0 when it's actually at Ring 1 in the VMCS guest-state). This is a form of virtualization-based deception.

4. **EPT-based attacks**: A hypervisor bug in EPT handling could allow a VMX non-root Ring 0 guest to access VMX root memory — a far more direct attack than any Ring 1/2 manipulation.

---

## Summary

Rings 1 and 2 are a well-engineered feature of x86 that has been almost entirely abandoned by mainstream OSes in favor of the simpler Ring 0/Ring 3 binary model. Their security implications today are primarily:

1. **Call gate exploitation** in 32-bit mode (GDT/LDT manipulation to create Ring 3 → Ring 0 escalation paths).
2. **TSS corruption** (controlling Ring 0/1/2 stack pointers used during privilege transitions).
3. **IOPL misuse** (granting I/O privileges to Ring 3 code).
4. **iret/sysret frame manipulation** (controlling CPL on return from kernel mode).
5. **Ring compression attacks** in paravirtualized environments (Xen PV guests at Ring 1).
6. **VMX ring model confusion** (guest Ring 0 vs. true Ring 0 in hypervisors).

The rings exist in hardware, are checked by the CPU on every memory and I/O access, and their associated data structures (GDT, LDT, TSS, IDT) are maintained by every x86 OS — even those that nominally only use Rings 0 and 3. This gap between "architecturally present" and "practically used" is exactly where vulnerabilities live.

---

## References

1. Intel. "Intel 64 and IA-32 Architectures Software Developer's Manual." Volumes 2A/2B: Instruction Set Reference (SYSRET, IRET, CALL gates, IOPL).
2. Intel. "Intel 64 and IA-32 Architectures Software Developer's Manual." Volume 3A: Chapter 5 — Protection (privilege levels, call gates, task gates, IOPL).
3. AMD. "AMD64 Architecture Programmer's Manual Volume 2: System Programming." Sections on CPL, RPL, DPL, I/O permission bitmaps.
4. Rutkowska, J. "Understanding Intel's Item Over the Protection Rings Architecture." Invisible Things Lab, 2008.
5. Kallenberg, C., et al. "Defeating x86 Protection Rings via I/O Privilege Escalation." 2014.
6. Wojtczuk, R., Rutkowska, J. "Attacking Intel TXT via SINIT/Harti." 2011.
7. NIST. "National Vulnerability Database." CVE entries for CVE-2012-0217 (SYSRET privilege escalation).
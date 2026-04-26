# Ring Transitions and Ring 1/Ring 2 Attack Surfaces

> A deep-technical analysis of privilege boundary mechanics, descriptor-mediated transitions, and the exploitation landscape surrounding x86 protection rings 1 and 2.

---

## 1. Ring Transition Mechanisms in Detail

### 1.1 Software Interrupts (`int 0x80`)

The legacy Linux syscall path uses `int 0x80` to trap from Ring 3 into Ring 0. The mechanism is orchestrated entirely by the IDT descriptor for vector `0x80`:

```
; Ring 3 user code
mov  eax, __NR_write     ; syscall number
mov  ebx, 1              ; fd
mov  ecx, msg            ; buf
mov  edx, len             ; count
int  0x80                ; trap gate fires
```

The CPU performs the following sequence atomically:

1. **Privilege check**: The DPL of the IDT gate descriptor must satisfy `MAX(CPL, RPL) <= DPL`. For `int 0x80` the gate's DPL is 3, permitting Ring 3 callers.
2. **Stack switch**: The TSS provides the Ring 0 SS:ESP. The CPU pushes the user SS, ESP, EFLAGS, CS, and EIP onto the kernel stack.
3. **RFLAGS modification**: The IF flag is cleared only if the gate is an *interrupt gate* (type 0xE); *trap gates* (type 0xF) leave IF set. This is a crucial distinction for interrupt latency analysis.
4. **Transfer control**: CS:EIP is loaded from the gate descriptor, CPL becomes 0.

The `iret` instruction reverses the stack switch, popping EIP, CS, EFLAGS, ESP, and SS, restoring Ring 3 execution. Any inconsistency in the saved frame—e.g., a corrupt CS or SS pushed by the kernel—causes a #GP or worse.

**Key forensic artifact**: The exact stack frame layout at `0x80` entry permits kernel stack pivoting. Off-by-one errors in kernel stack frame construction are historically fertile ground because `iret` trusts whatever values sit on the stack.

### 1.2 `syscall`/`sysenter` and `sysret`/`sysexit`

Modern x86-64 uses `syscall` (AMD) or `sysenter` (Intel) as the privileged instruction path:

| Aspect | `syscall` | `sysenter` |
|--------|-----------|-------------|
| Defined by | `STAR`, `LSTAR`, `CSTAR` MSRs | `SYSENTER_CS`, `SYSENTER_EIP`, `SYSENTER_ESP` MSRs |
| Stack switch | Yes (SS:RSP from `STAR` hidden) | Yes (ESP from MSR) |
| RFLAGS mask | Stored in `RFLAGS`, masked per `FMASK` MSR | IF cleared, interrupts disabled |
| Return | `sysret` (also from MSR) | `sysexit` |

**`syscall` mechanics**:
```
; Entry: CPL=3
syscall
; CPU internally:
;   RCX = RIP of next instruction
;   R11 = RFLAGS
;   RFLAGS &= ~FMASK
;   CS  = STAR[47:32] | 0      ; e.g., 0x08 (KERNEL_CS)
;   SS  = STAR[47:32] | 8      ; e.g., 0x10 (KERNEL_DS) → set by architectural rule: SS = CS+8
;   RIP = LSTAR
;   CPL = 0
```

**`sysret` re-privilege vulnerability class**: On `sysret`, the CPU loads RCX into RIP and R11 into RFLAGS, then sets CS = `STAR[63:48] | 0` and SS = `STAR[63:48] | 8`. A critical subtlety: if the OS sets `RCX` to a non-canonical address before `sysret`, the CPU generates a #GP *after* CPL has reverted to 3. The #GP handler then runs in Ring 0 with a partially-restored user context—a classic privilege-escalation primitive exploited in CVE-2012-0217 (FreeBSD) and related Linux bugs.

### 1.3 Call Gates (Far Calls with Privilege Escalation)

Call gates are the *only* x86 mechanism that allows a Ring 3 program to directly call a Ring 1 or Ring 2 entry point. They live in the GDT or LDT:

```
; Call gate descriptor (8 bytes, 32-bit)
; Offset 0:
;   [31:16] = offset[15:0]
;   [15:0]  = segment selector (target code segment)
; Offset 4:
;   [31:16] = offset[31:16]
;   [15]    = P (present)
;   [14:13] = DPL
;   [12]    = 0 (system)
;   [11:8]  = type (0xC = call gate 32-bit)
;   [7:5]   = 0
;   [4:0]   = param count
```

A Ring 3 program invokes a call gate like so:

```nasm
; Assuming gate selector 0x28 (RPL=3) points to a call gate with DPL=3
call 0x0028:0x00000000    ; far call with gate selector
; CPU checks: MAX(CPL=3, RPL=3) <= DPL=3 → OK
; CPU reads gate → target selector (DPL=1) → stack switches to Ring 1 stack
; Pushes parameters (param count copied from gate)
; Pushes return CS:EIP
; Jumps to target offset
```

The stack switch and parameter copy are crucial. Parameters are *copied* from the caller's stack (at the old CPL) to the new stack (at the new CPL). The `param count` field specifies how many doublewords to copy. A **misconfigured param count** (e.g., larger than actual stack contents) can leak kernel/ring data, as the CPU copies whatever sits on the user stack even beyond meaningful data.

**Call gate attack surface**:
- Modify a call gate's target offset in the GDT/LDT → redirect execution to arbitrary Ring 1/2 addresses
- Set DPL=0 on a gate intended for Ring 3 → denies legitimate access (DoS)
- Set DPL=3 on a gate intended for Ring 0 → privilege escalation from Ring 3 into Ring 0
- Abuse param count to leak stack data across ring boundaries

### 1.4 Task Gates and Hardware Task Switching

Task gates in the IDT transfer control to a different TSS (Task State Segment) upon interrupt. The CPU performs an *atomic* hardware task switch:

```
; Task gate descriptor (IDT entry)
; Contains a TSS selector pointing to a Task State Segment descriptor
; On NMI/double-fault/etc:
;   1. CPU reads TSS selector from task gate
;   2. CPU saves current register state in *current* TSS
;   3. CPU loads new register state from *target* TSS
;   4. CPL becomes the target TSS's DPL
;   5. CR3 is switched (new page tables!)
;   6. I/O permission bitmap is switched
```

The **double-fault exception (#DF, vector 8)** is the most security-relevant task gate. When the CPU cannot handle a fault (e.g., an exception occurs while invoking a handler), it pushes through the task gate to a known-good TSS. This is the CPU's last resort for maintaining system integrity.

**Attack surface**: If an attacker can corrupt the TSS referenced by the #DF task gate *or* modify the task gate descriptor itself, they control the CPU state after a double fault—including CR3, EIP, CPL, and the I/O permission bitmap. This is a Ring 0 → Ring 0 persistence mechanism, but relies on Ring 1/2 concepts (TSS IOPB) for I/O access.

### 1.5 I/O Permission Bitmaps (IOPB)

The TSS contains an I/O Permission Bitmap starting at offset `TSS.io_bitmap`. Each bit corresponds to an I/O port (bit 0 = port 0x00, bit 1 = port 0x01, etc.). When CPL > IOPL:

```
; For IN/OUT instruction at CPL > IOPL:
;   port_index = port_number / 8
;   port_bit   = port_number % 8
;   if IOPB[port_index] & (1 << port_bit):
;       #GP(0) ← I/O denied
;   else:
;       I/O permitted
```

Critically, the IOPB is a **Ring 2 concept**: it only matters when `CPL > IOPL` (typically IOPL=0, so CPL=1,2,3 all check the bitmap). Ring 1 and Ring 2 code may execute privileged I/O instructions if the corresponding IOPB bits are clear, without needing Ring 0.

**IOPB attack patterns**:
- If the OS fails to terminate the IOPB with a 0xFF byte at the end, the CPU reads beyond the TSS boundary, leaking adjacent kernel memory as "permitted" I/O ports
- Off-by-one in IOPB length calculation grants access to unintended ports
- On Linux, `ioperm()` and `iopl()` syscalls modify the IOPB—any kernel bug that lets unprivileged code call these is direct Ring 3→(effective)Ring 2 I/O access

---

## 2. Attack Surfaces at Ring Boundaries

### 2.1 Exploiting Call Gates and Their Descriptors

The GDT and LDT reside in memory addressable only from Ring 0, but the LDT is uniquely dangerous because it is per-process. The `modify_ldt` syscall allows Ring 3 processes to create, modify, and delete LDT entries—including call gates:

```c
// Linux kernel: arch/x86/kernel/ldt.c (simplified)
static int write_ldt(struct mm_struct *mm, struct desc_struct *ldt,
                     int oldmode, struct user_desc *regs)
{
    // ... validation ...
    // The kernel DOES validate DPL and type:
    // - Call gates are ONLY allowed in compat (32-bit) mode
    // - DPL must be 3 (user-accessible) for call gates
    // ... but the target selector and offset are trusted ...
}
```

**Exploitation path**: A process can install a call gate in its LDT with a target CS selector pointing to a kernel code segment (DPL=0). When the process invokes the call gate via a far call:
- The CPU performs the privilege check against the *gate's* DPL (3) → passes
- Then loads the target CS (DPL=0) → CPU transitions to Ring 0
- This is the **intended** behavior if the gate is properly configured
- But if the kernel's LDT validation has bugs, the gate's target offset could point
  to a gadget, providing controlled Ring 0 execution

Historical bugs in Linux's `modify_ldt` (e.g., CVE-2015-5157 / "LDT flaw") allowed arbitrary write via call gates.

### 2.2 Double-Fault Scenarios and TSS Exploitation

The double-fault (#DF, vector 8) is architecturally defined to use a **task gate** to guarantee a valid stack and context. The attack surface:

1. **TSS corruption**: If an attacker can write to the TSS (e.g., via a kernel memory write primitive), they can corrupt:
   - `EIP` → redirect double-fault handler
   - `CR3` → switch page tables
   - `ESP` → pivot stack
   - `IOPB offset` → grant I/O access

2. **Nested exception UAF**: A race condition where exception A frees resources, exception B occurs during A's handler, and the #DF handler operates on freed data.

3. **Stack overflow → #DF**: In kernels with small kernel stacks (4K or 8K), a recursive kernel path can overflow, triggering #DF. If the #DF TSS has been corrupted, the resulting context is fully attacker-controlled.

```
; Vulnerable pattern: #DF handler TSS references unmapped memory
; CPU attempts task switch:
;   Reads TSS descriptor from GDT
;   Reads target TSS from memory
;   If TSS is in unmapped/paged-out memory → TRIPLE FAULT → RESET
;   If TSS is attacker-controlled → arbitrary ring 0 code execution
```

### 2.3 I/O Port Access from Ring 3 via IOPL

The `IOPL` field in EFLAGS[13:12] determines the minimum CPL needed to perform I/O instructions without checking the IOPB:

| IOPL | CPL that can do raw I/O | CPL that checks IOPB |
|------|------------------------|----------------------|
| 0    | 0 only                 | 1, 2, 3              |
| 1    | 0, 1                   | 2, 3                 |
| 2    | 0, 1, 2                | 3                    |
| 3    | 0, 1, 2, 3             | none                 |

The `iopl()` syscall on Linux sets IOPL=3 for the calling process. This effectively promotes the process to **Ring-equivalent 0 for I/O purposes**:

```c
// Privilege escalation via iopl:
iopl(3);  // Set IOPL=3
// Now ALL I/O ports are accessible without IOPB checks
// Direct hardware access:
outb(0x60, data);  // PS/2 keyboard controller
outb(0x3F8, data);  // Serial port
// Can also use CLI/STI (interrupt flag control)
asm volatile("cli");
```

**Attack pattern**: A kernel exploit that calls `iopl(3)` in a userspace process gives that process full I/O port access. Combined with PCI configuration space access (ports 0xCF8-0xCFF), this enables:
- Direct DMA programming → physical memory read/write
- PCI device configuration → bus mastering → arbitrary DMA
- Interrupt controller (8259A / IO-APIC) reprogramming → DoS or interrupt redirection

### 2.4 MSR (Model Specific Register) Abuse at Boundaries

MSRs are privileged registers accessed via `rdmsr`/`wrmsr` (CPL=0 only) or `sysenter`/`syscall` configuration. Key attack-relevant MSRs:

| MSR | Name | Security Relevance |
|-----|------|---------------------|
| `0xC0000080` | `EFER` | SCE bit enables/disables `syscall`; NXE enables NX |
| `0xC0000081` | `STAR` | `syscall` target CS/SS selectors |
| `0xC0000082` | `LSTAR` | `syscall` RIP entry point |
| `0xC0000083` | `CSTAR` | `syscall` compat RIP |
| `0xC0000084` | `FMASK` | RFLAGS mask on `syscall` |
| `0x00000174` | `SYSENTER_CS` | CS selector for `sysenter` |
| `0x00000175` | `SYSENTER_ESP` | ESP for `sysenter` |
| `0x00000176` | `SYSENTER_EIP` | EIP for `sysenter` |
| `0x0000001B` | `APIC_BASE` | APIC base address |
| `0x0000003B` | `UCODE_REV` | Microcode revision |

**Boundary MSR attacks**:
- **`LSTAR` overwrite**: Changing the `syscall` entry point redirects all syscalls to attacker-controlled Ring 0 code
- **`FMASK` manipulation**: Clearing the IF mask bit means `syscall` enters the kernel with interrupts enabled—a subtle race condition vector
- **`EFER.NXE` clear**: Disables NX bit → W^X bypass at hardware level
- **`SYSENTER_CS` = 0**: Forces `sysenter` to load a NULL selector → #GP → kernel panic or exploitable condition depending on handler

The `sysret` to Ring 3 path is particularly tricky because MSRs are not re-checked on return—only the `STAR` upper 16 bits determine the user CS/SS. An MSR write to `STAR` allows the attacker to make `sysret` return to Ring 0 instead of Ring 3.

---

## 3. Microkernel and Capability-based Security

### 3.1 How Microkernels Use Intermediate Rings Differently

#### L4 / seL4

L4 microkernels run exclusively in Ring 0 (or EL2 on ARM). All servers—filesystems, device drivers, network stacks—run in Ring 3. Rings 1 and 2 are **not used**. The L4 design explicitly rejects the ring hierarchy in favor of *capability-based isolation*:

```
; seL4 privilege model:
;   Kernel: Ring 0, ~15k LOC, formally verified
;   User servers: Ring 3, IPC-based communication
;   No Ring 1 or Ring 2 utilization
;
; Isolation is enforced by:
;   1. Capabilities (unforgeable tokens granting access rights)
;   2. IPC (inter-process communication via kernel-mediated message passing)
;   3. Address space isolation (per-process page tables)
```

The fundamental insight: Ring 1/2 privilege is a *monotonic subset* of Ring 0. A Ring 1 driver that can touch I/O ports can still corrupt the entire system. L4's answer is to remove intermediate privilege entirely and use capability-mediated IPC instead.

#### MINIX 3

MINIX 3 is the most prominent OS that *actually uses* Ring 1 for device drivers:

```
; MINIX 3 privilege rings:
;   Ring 0: Kernel, clock task
;   Ring 1: Device drivers (disk, network, audio)
;   Ring 2: Server processes (filesystem, process manager)
;   Ring 3: User processes
;
; IPC is always kernel-mediated:
;   send(dest, &msg)    → kernel copies message
;   receive(src, &msg)  → kernel copies message
;   sendrec(dest, &msg) → combined send+receive
```

In MINIX 3, a Ring 1 driver crash triggers automatic **restart** by the reincarnation server. The driver's address space is isolated, but I/O access (IOPB bits) is still granted. This is practical because:
- Ring 1 drivers have I/O port access (IOPB-granted) but cannot execute Ring 0 instructions
- Ring 1 cannot access the kernel's memory (page table isolation)
- Ring 1 cannot directly call Ring 0 code (must use IPC)

However, x86-64 long mode removes call gates and hardware task switching, making Ring 1/2 support architecturally impossible. MINIX 3's Ring 1 model works only in 32-bit protected mode.

### 3.2 Capability-based Addressing vs Ring-based Protection

Rings encode privilege as a *total order*: 0 > 1 > 2 > 3. This is fundamentally inadequate for real systems:

```
; Ring problem: "Which drivers can access which devices?"
;
; Ring model:
;   Driver A (disk) : Ring 1 → can access ALL I/O ports
;   Driver B (audio): Ring 1 → can access ALL I/O ports
;   Problem: Driver B can touch disk controller ports → violates least privilege
;
; Capability model:
;   Driver A: cap[I/O_port_0x1F0, READ|WRITE], cap[I/O_port_0x1F1, READ|WRITE], ...
;   Driver B: cap[I/O_port_0x220, READ|WRITE], ...
;   enforces EXACT access rights, not broad ring membership
```

**seL4 capability derivation**:
```
; Root CNode (capability space) at boot:
;   CNode[0] = Frame_Cap(paddr=0x00000, rwx)
;   CNode[1] = Frame_Cap(paddr=0x01000, r-- )
;   ...
;   CNode[N] = IOPort_Cap(base=0x1F0, size=8)
;   CNode[M] = Endpoint_Cap(dest=driver_A)
;
; Derivation: parent cap can create child caps with ≤ rights
; Mint: Frame_Cap(rwx) → Mint → Frame_Cap(rx)  (derive read+execute only)
```

Capabilities decompose the ring boundary into many fine-grained boundaries, each independently verifiable. The seL4 proof guarantees that no capability can grant rights not possessed by its parent—a property rings simply cannot express.

### 3.3 NUMA and Ring Isolation

NUMA systems introduce locality as a security-relevant axis. On a NUMA system:

```
; NUMA Node 0:
;   CPU 0-7    → local memory 0-64GB
;   CPU 8-15   → local memory 64-128GB
; NUMA Node 1:
;   CPU 16-23  → local memory 128-192GB
;   CPU 24-31  → local memory 192-256GB
;
; Ring isolation across NUMA nodes:
;   - Remote memory access has higher latency and goes through interconnect
;   - Interconnect (e.g., Intel UPI) is a shared resource → side-channel vector
;   - Page table updates to remote nodes require IPI → kernel entry → ring transition
;   - DMA transfers between nodes bypass CPU caches entirely
```

**NUMA-aware ring isolation challenges**:
- A Ring 1 driver on Node 0 accessing device memory on Node 1 creates a cross-node coherence traffic pattern observable via cache timing
- TLB shootdown IPIs broadcast to all nodes, creating a kernel-entry side channel that reveals which nodes have mappings for a given address space
- Intel's Sub-NUMA Clustering (SNC) creates "virtual NUMA nodes" within a socket, further fragmenting the ring boundary into a matrix of Node × Ring × Cache-domain

---

## 4. x86 Descriptor Tables and Privilege

### 4.1 GDT, LDT, IDT Entries and DPL Fields

The x86 protected-mode descriptor tables are the bedrock of ring enforcement:

#### GDT (Global Descriptor Table)

```
; GDT entry (8 bytes, 64-bit mode uses 16 bytes for code/data):
;
; Byte 0-1 (low):
;   [15:0]  = limit[15:0]
; Byte 2-3:
;   [23:0]  = base[15:0]
; Byte 4:
;   [31:24] = base[23:16]
; Byte 5:
;   [7]     = P (present)
;   [6:5]   = DPL (0-3) ← THE RING FIELD
;   [4]     = S (1=code/data, 0=system)
;   [3]     = type bit 3 (for code: 0=non-conforming, 1=conforming)
;   [2]     = type bit 2 (for code: 0=execute-only, 1=readable)
;   [1]     = type bit 1 (for data: 0=read-only, 1=writable)
;   [0]     = accessed
; Byte 6:
;   [3:0]   = limit[19:16]
;   [6]     = D/B (default operation size)
;   [5]     = L (64-bit code segment)
;   [4]     = reserved
;   [7]     = G (granularity: 0=byte, 1=4KB)
; Byte 7:
;   [31:24] = base[31:24]
```

**The DPL field is the ring assignment**. A code segment descriptor with DPL=1 creates a Ring 1 execution environment. The CPU loads this DPL into CPL when a far jump/call targets this segment.

**Conforming code segments** (type bit 3 set): These are a special case where the code segment can be entered from any CPL ≤ DPL, *without changing CPL*. Conforming segments are useful for shared library code that needs to run at the caller's privilege. They are also a security minefield—a conforming DPL=0 segment can be called from Ring 3 but executes at Ring 3's CPL, while a conforming DPL=3 segment can be entered from Ring 0 (reducing the caller's effective privilege to Ring 3 would require additional checks).

#### LDT (Local Descriptor Table)

Per-process descriptor table. Each process can have its own LDT with custom code/data/ gate descriptors. Selected by the LDT selector in the LDTR register:

```nasm
; Loading the LDT:
lldt  ax               ; ax = GDT selector pointing to LDT descriptor

; The LDT descriptor in the GDT:
;   DPL = 0 (only Ring 0 can load LDTs)
;   Type = LDT (0x2)
;   Base = physical address of LDT array
;   Limit = size of LDT - 1
```

The LDT is the **primary mechanism for Ring 1/2 exploitation** because:
- Ring 3 processes can read their own LDT via `modify_ldt()` or `syscall`
- The LDT can contain call gates, task gates, and code/data descriptors at arbitrary DPLs
- The kernel does not always validate LDT entries properly (historically)

#### IDT (Interrupt Descriptor Table)

```
; IDT gate descriptor (16 bytes in 64-bit mode):
; Offset 0:
;   [31:0]  = offset[31:0]
; Offset 4:
;   [31:16] = offset[63:32]
;   [15]    = P (present)
;   [14:13] = DPL (0-3) ← WHICH CPL CAN TRIGGER THIS VECTOR
;   [12]    = 0 (system)
;   [11:8]  = type (0xE=interrupt gate, 0xF=trap gate)
;   [7:0]   = IST (Interrupt Stack Table) index [x86-64 only]
; Offset 8:
;   [31:0]  = reserved
; Offset 12:
;   [31:0]  = offset[31:0] (high, upper 32 bits for 64-bit mode)
;   [15:0]  = target code segment selector
```

**IDT DPL determines which rings can trigger the interrupt**:
- DPL=0: Only Ring 0 can use `int N` for this vector (hardware exceptions typically)
- DPL=3: Rings 0-3 can use `int N` for this vector (the `int 0x80` Linux syscall vector)
- DPL=1: Only Rings 0 and 1 can use `int N` (hypothetical Ring 1 OS services)

Hardware interrupts (IRQs) are not subject to DPL checks—they always invoke the handler regardless of CPL. DPL only applies to software-triggered `int N` instructions.

### 4.2 How Segment Selectors Encode RPL and CPL

A segment selector (16-bit value loaded into segment registers) encodes:

```
; 16-bit segment selector:
;   [15:3] = Index into GDT/LDT (descriptor table entry number, NOT byte offset)
;   [2]    = TI (Table Indicator: 0=GDT, 1=LDT)
;   [1:0]  = RPL (Requested Privilege Level: 0-3)
;
; Example: 0x002B
;   Index = 5 (GDT entry 5)
;   TI    = 0 (GDT)
;   RPL   = 3 (Ring 3)
;
; Example: 0x0008
;   Index = 1 (GDT entry 1)
;   TI    = 0 (GDT)
;   RPL   = 0 (Ring 0)
```

**CPL (Current Privilege Level)**: This is always equal to the RPL of the *current CS selector*. When CS = 0x0008, CPL = 0. When CS = 0x002B, CPL = 3.

**The privilege check rule for data access**:
```
; To access a data segment with DPL=D and selector with RPL=R from CPL=C:
;   Access permitted if: MAX(C, R) <= D
;
; Example:
;   CPL=2, RPL=3, DPL=2  →  MAX(2,3)=3 > 2  → DENIED
;   CPL=1, RPL=0, DPL=1  →  MAX(1,0)=1 <= 1  → PERMITTED
;
; The RPL piggybacking attack:
;   A Ring 0 kernel creates a selector with RPL=0 pointing to user data
;   A Ring 3 process cannot create RPL=0 selectors (the CPU uses the provided RPL)
;   But if the kernel forgets to set RPL=3 before handing a selector to user space...
;   ...the user gets Ring 0 access to the descriptor
;   This is why Linux always ORs 0x03 into user-provided selectors
```

### 4.3 Privilege Check Rules: `MAX(CPL, RPL) <= DPL`

The single most important rule in ring security:

```
; Universal privilege check (for data segments and gates):
;   Permitted if MAX(CPL, RPL) <= DPL
;
; For control transfers (CALL/JMP to non-conforming code):
;   Permitted if DPL == CPL (same ring only, unless call gate used)
;
; For call gates:
;   1. MAX(CPL, RPL) <= gate_DPL  (can caller reach the gate?)
;   2. target_code_DPL <= CPL     (can caller reach the target ring?)
;   Note rule 2: target DPL must be ≤ CPL, meaning call gates can only
;   call SAME or MORE PRIVILEGED code (downward in ring number)
;
; For conforming code segments:
;   MAX(CPL, RPL) <= DPL           (same as data check)
;   CPL is NOT changed             (caller stays at current privilege)
```

**Common mistakes and attack vectors**:
1. **RPL not sanitized**: If the kernel copies a segment selector from user memory without forcing RPL=3, the user can forge RPL=0 selectors and bypass `MAX(CPL, RPL)` checks
2. **Gate DPL too permissive**: Setting a call gate's DPL to 3 when it targets Ring 0 code allows any process to invoke Ring 0 routines
3. **Conforming segment abuse**: A DPL=3 conforming code segment can be called from Ring 0 and will execute at Ring 0's CPL—potentially bypassing security checks in the calling code

---

## 5. Notable Historical CVEs Involving Ring 1/2 Concepts

### 5.1 Call Gate Exploits

#### CVE-2015-5157 — QEMU/AMD64 Call Gate Emulation

**Summary**: QEMU's x86 emulator did not properly validate call gate descriptors when emulating far calls from Ring 3. An attacker in a privileged VM (with access to LDT) could create a call gate with a target segment pointing to Ring 0 code and invoke it, achieving privilege escalation within the guest.

```
; Attack sequence:
; 1. Write call gate into LDT via modify_ldt():
;    Gate selector: 0x07 (LDT index 0, RPL=3, TI=1)
;    Gate DPL: 3 ( Ring 3 accessible)
;    Gate target CS: 0x08 (KERNEL_CS, DPL=0)
;    Gate target offset: address_of_gadget
; 2. Execute: CALL 0x0007:0x00000000
; 3. CPU transitions Ring 3 → Ring 0
; 4. Attacker executes Ring 0 gadget
```

This is the canonical call gate exploit pattern: LDT write → gate descriptor manipulation → far call → ring transition → Ring 0 code execution.

#### CVE-1999-0664 — Windows NT LDT Call Gate

A historical Windows NT vulnerability where malicious code could install a call gate in the LDT and use it to escalate from Ring 3 to Ring 0. Windows NT's `NtSetLdtEntries` had insufficient validation, allowing call gates targeting Ring 0 code segments.

### 5.2 I/O Privilege Escalation

#### CVE-2018-5333 — Linux `iopl()` and KASLR Bypass

The `iopl()` syscall sets IOPL to the requested level. On Linux, any process with `CAP_SYS_RAWIO` can call `iopl(3)`, gaining full I/O port access. CVE-2018-5333 involved a path where a leaked `iopl(3)` context (from a kernel thread) was inherited by a userspace process through improper kernel thread creation:

```c
// Vulnerable pattern: kernel thread inherits IOPL=3
kernel_thread(fn, arg, flags);
// If the parent kernel thread had IOPL=3,
// the child inherits IOPL=3 via copy_process()
// This means a Ring 3 process effectively runs at Ring 0 for I/O purposes
```

#### CVE-2020-10752 — Linux IOPB Out-of-Bounds Access

The I/O Permission Bitmap in the TSS must be properly terminated. If the bitmap's length field is larger than the TSS limit, the CPU reads beyond the TSS boundary, treating arbitrary memory as "permitted" I/O ports:

```
; Vulnerable TSS setup:
;   TSS limit = 0x67 (104 bytes, minimum for a 32-bit TSS)
;   IOPB offset = 0x66 (just before TSS end)
;   IOPB contains no 0xFF terminator within TSS bounds
;   CPU reads beyond TSS limit → treats adjacent kernel memory as IOPB
;   All ports appear accessible → Ring 3 I/O access without checks
```

Linux mitigated this by ensuring the IOPB is always terminated with 0xFF at `min(TSS limit, IOPB offset + 8192)`.

### 5.3 Virtual 8086 Mode (VM86) Attacks

VM86 mode runs Ring 3 code with Ring 0 I/O privileges (IOPL effectively ignored for VM86 tasks). This was designed for running DOS programs under Windows/Linux but creates a massive attack surface:

#### CVE-2009-1895 — Linux `vmsplice` / VM86 I/O Access

Under VM86, the `pushf`/`popf` instructions can modify the IF flag without privilege checks. Combined with memory corruption, an attacker could:
1. Enter VM86 mode via `vm86()` syscall
2. Execute `cli` (interrupts disabled) without CPL/IOPL checks
3. Modify VM86 platform data structures to redirect I/O
4. Access physical hardware directly

#### V8086 Monitor Privilege Confusion

The VM86 monitor (running in Ring 0) must emulate all privileged instructions for the VM86 task. A bug in the monitor's instruction parsing could:
- Fail to intercept `in`/`out` instructions → direct hardware access from VM86
- Incorrectly compute the VM86 client's address for simulated I/O → kernel memory reads/writes
- Misinterpret segment overrides in VM86 client code → TSS corruption

Linux removed VM86 support from x86-64 permanently, citing the uncontrollable attack surface.

### 5.4 Additional Ring-adjacent CVEs

| CVE | Year | Component | Ring Concept | Description |
|-----|------|-----------|--------------|-------------|
| CVE-2012-0217 | 2012 | FreeBSD | `sysret` | `sysret` with non-canonical RIP → #GP in Ring 0 → privilege escalation |
| CVE-2014-9090 | 2014 | Linux | `int 0x80` | `ptrace` + `int 0x80` interaction → ABI confusion → privilege escalation |
| CVE-2010-4258 | 2010 | Linux | TSS/`iopl` | `fork()` preserves parent IOPL → child gets elevated I/O access |
| CVE-2009-3234 | 2009 | Linux | LDT | `modify_ldt()` race condition → use-after-free in LDT management |
| CVE-2021-28389 | 2021 | Hyper-V | VM86/vmbus | VM86 escape via vmbus ring buffer confusion (hypervisor ring boundary) |

---

## 6. The Future: Will Rings 1 and 2 Ever Be Used Meaningfully Again?

### 6.1 CHERI Capability Hardware

CHERI (Capability Hardware Enhanced RISC Instructions) fundamentally replaces rings with *capabilities*—hardware-enforced, unforgeable pointers that encode access rights:

```
; CHERI capability (256-bit compressed, 128-bit in practice):
;   [127:64] = validity tag + permissions + object type + seal
;   [63:0]   = base + length (address range)
;   Combined: address + length + permissions + unforgeable tag
;
; How CHERI replaces rings:
;   Ring 0: capability with {LOAD, STORE, EXECUTE, SYSTEM} permissions
;   Ring 3: capability with {LOAD, STORE, EXECUTE} (no SYSTEM)
;   Fine-grained: per-object, per-field, per-function-pointer capabilities
;   No global ring: each capability is independently derived and bounded
```

CHERI renders Rings 1 and 2 irrelevant because:
- Every pointer is an unforgeable capability with precise permission subsets
- There is no "intermediate privilege level"—you have exactly the rights encoded in your capability
- The hardware enforces capability bounds at instruction level, not via coarse ring checks
- Compartmentalization (CHERI's term for process-like isolation) provides isolation *between* capabilities, not just between rings

**CHERI on x86**: The 2023 CHERIx86 proposal adds a 128-bit capability register file alongside x86's GPRs, keeping segment-descriptor-based protection for compatibility but deprecating Rings 1/2 entirely.

### 6.2 Intel CET and Shadow Stacks

Intel Control-flow Enforcement Technology (CET) introduces two mechanisms that are "ring-like" in their isolation properties but orthogonal to the ring model:

**Shadow Stack (SS)**:
```c
// CET Shadow Stack mechanism:
// On CALL:
//   SS:RSP -= 8
//   SS:[RSP] = RIP  (shadow copy of return address)
// On RET:
//   if SS:[RSP] != RSP return address → #CP (Control Protection exception)
//   SS:RSP += 8
//
// The shadow stack is in a NON-WRITABLE memory page (ring-protected)
// Ring 0 can create/destroy shadow stacks
// Ring 3 cannot modify shadow stack pages even with write access to data
```

The shadow stack is a **privileged data structure** that Ring 3 cannot modify. In architecture terms, this creates a new privilege dimension:
- Ring 3 + shadow stack read ≈ Ring 3 (normal)
- Ring 3 + shadow stack write ≈ Ring 3.5 (can corrupt return addresses → partial control)
- Ring 0 + shadow stack write = Ring 0 (full control)

CET doesn't revive Rings 1/2; it adds orthogonal privilege dimensions (control-flow vs data-flow), which is more expressive than rings but structurally different.

### 6.3 Confidential Computing Enclaves (SGX, TDX, SEV) as "Ring-like" Constructs

Intel SGX creates isolated *enclaves* that execute at CPL=3 but with hardware-protected memory (EPC):

```
; SGX Privilege Model:
;   Enclave code: CPL=3 (Ring 3!), but:
;     - Runs in "enclave mode" (EENTER/EEXIT transitions)
;     - Memory is encrypted (MEE) and integrity-protected
;     - CPU verifies enclave measurement (MRENCLAVE) on EENTER
;     - Enclave can access SECS/EPC pages that Ring 0 CANNOT access
;
; The effective privilege hierarchy:
;   Ring 0  < Ring 3 enclave < Ring 3 (outside enclave)
;   Ring 0 can set up enclave but CANNOT read enclave secrets
;   Ring 3 enclave can attest to remote parties
;   This inverts the traditional ring model!
```

**SGX as an "anti-ring"**: Rather than Ring 0 being the most privileged, SGX makes Ring 0 *less privileged* than enclave code for certain operations. The enclave can compute on secrets that Ring 0 cannot observe—a fundamentally different trust model.

**AMD SEV-SNP** takes this further:
```
; SEV-SNP Privilege:
;   Host (Ring 0):  Can run VM but CANNOT read guest memory (HW encrypted)
;   Guest (Ring 0): Can run normally, attests to remote parties
;   SNP adds:      Reverse map table prevents host from mapping same GPA twice
;                   Integrity tree prevents host from replaying old data
;
; Effective: Guest Ring 0 > Host Ring 0 (in terms of secret access)
```

**Will Rings 1 and 2 return?** No. The trajectory is clear:

1. **x86-64 long mode removed** call gates, task gates, and the TSS-based hardware task switching that made Rings 1/2 practical
2. **Virtualization (VT-x/AMD-V)** absorbs the "intermediate privilege" use case—VMX non-root mode is effectively a new Ring -1 for guest Ring 0
3. **Capabilities (CHERI)** provide finer-grained access control than ordinal rings
4. **Enclaves (SGX, TDX, SEV)** provide isolation *stronger* than rings with hardware memory encryption
5. **Microkernels (seL4)** demonstrate that Ring 3 + IPC is sufficient for all services previously assigned to Rings 1/2

The only remaining use of Rings 1/2 is in legacy 32-bit x86 systems and niche embedded designs. On modern x86-64 hardware, Rings 1 and 2 are architecturally vestigial—they can host code segments with DPL=1 or DPL=2 but gain no I/O access (IOPB checks still apply) and no syscall entry points (MSRs are Ring 0 only). They are protection ring deserts: elevated above Ring 3 in theory but impotent in practice.

---

## Appendix A: Descriptor Access Rules Quick Reference

```
; PRIVILEGE CHECK MATRIX
;
; Transfer type         | Rule                              | Effect
; ----------------------|-----------------------------------|-------------------
; Data access           | MAX(CPL,RPL) <= DPL              | Same or outer ring
; Call to non-conf code | DPL == CPL                        | Same ring only
; Call via call gate    | MAX(CPL,RPL) <= gate_DPL           | Gate check
;                       | target_DPL <= CPL                   | Target ring ≤ caller
; Call to conforming   | MAX(CPL,RPL) <= DPL              | Any ring ≤ DPL
; INT via IDT gate      | MAX(CPL,RPL) <= gate_DPL           | Gate check
; Hardware INT         | No DPL check                      | Always triggers
; I/O instruction      | CPL <= IOPL OR IOPB bit clear     | IOPL or bitmap
; MSR access           | CPL == 0                          | Ring 0 only
; CLI/STI              | CPL <= IOPL                       | IOPL check
```

## Appendix B: Ring Anatomy in 64-bit Long Mode

```
; x86-64 segmentation changes:
;   - CS.DPL determines CPL (segments bases are 0, limits are 4GB+)
;   - Call gates are REMOVED in 64-bit mode
;   - Task gates are REMOVED in 64-bit mode
;   - TSS still exists but only for IST (Interrupt Stack Table)
;   - IOPB still resides in TSS (offset at TSS.io_bitmap_base)
;   - LDT still exists but only for 32-bit compatibility segments
;   - syscall/sysret is the ONLY privilege transition mechanism
;
; What CAN exist in 64-bit mode:
;   Ring 0: Kernel code
;   Ring 3: User code
;   Ring 1/2: Theoretically possible via CS with DPL=1/2
;             but have NO special I/O or instruction privileges
;             and no standard entry mechanism
;
; Conclusion: Rings 1 and 2 are dead in x86-64.
;             Their attack surfaces survive only in 32-bit legacy mode
;             and virtualization edge cases.
```

---

*Document version: 2026-04-26 | Classification: Technical Research | Author: Security Research Team*
# EL0 → EL1 Privilege Escalation on ARM64: Technical Mechanisms and CVEs

This report examines how an unprivileged ARM64 userspace process (EL0) can escalate to kernel privilege (EL1) on Linux/Android systems. It covers the ARM64 exception-level boundary, common vulnerability classes that cross it, ARM-specific exploit constraints, kernel mitigations, and the technical details of the requested CVEs.

---

## 1. The ARM64 EL0/EL1 Boundary

### 1.1 Exception Levels and Privilege Model

ARM64 defines four exception levels: **EL0** (userspace), **EL1** (operating-system kernel), **EL2** (hypervisor), and **EL3** (secure monitor). Linux and Android run the kernel in **non-secure EL1** and applications in **EL0**. The boot protocol requires that the CPU enter the kernel at EL1 with interrupts masked (`PSTATE.DAIF`), the MMU off, and architected system registers initialized [kernel docs: Booting AArch64 Linux](https://docs.kernel.org/arch/arm64/booting.html).

Key system registers at the boundary:

- `VBAR_EL1` — Vector Base Address Register; points to the exception-vector table.
- `ELR_EL1` — Exception Link Register; holds the return address after an exception.
- `SPSR_EL1` — Saved Program Status Register; saved `PSTATE` on exception entry.
- `SP_EL0` / `SP_EL1` — the userspace and kernel stack pointers.
- `TTBR0_EL1` / `TTBR1_EL1` — page-table bases for userspace and kernel.
- `TCR_EL1`, `MAIR_EL1`, `SCTLR_EL1` — translation-control and memory-attribute registers.
- `FAR_EL1`, `ESR_EL1` — faulting address and exception-syndrome registers.

When the CPU is at EL0, the MMU uses `TTBR0_EL1` for the lower half of the address space (bit 55 == 0); at EL1, the kernel uses `TTBR1_EL1` for the upper half (bit 55 == 1) [Memory Layout on AArch64 Linux](https://docs.kernel.org/arch/arm64/memory.html).

### 1.2 Exception Vectors

The ARM64 vector table is a 2 KB aligned structure with 16 entries, selected by the originating exception level, the stack pointer used (`SP_EL0` vs `SP_EL1`), and whether the exception is synchronous, IRQ, FIQ, or SError [entry.S](https://raw.githubusercontent.com/torvalds/linux/master/arch/arm64/kernel/entry.S):

```c
SYM_CODE_START(vectors)
    kernel_ventry 1, t, 64, sync   // Synchronous EL1t
    kernel_ventry 1, t, 64, irq   // IRQ EL1t
    kernel_ventry 1, t, 64, fiq     // FIQ EL1t
    kernel_ventry 1, t, 64, error  // Error EL1t
    kernel_ventry 1, h, 64, sync   // Synchronous EL1h
    kernel_ventry 1, h, 64, irq   // IRQ EL1h
    kernel_ventry 1, h, 64, fiq   // FIQ EL1h
    kernel_ventry 1, h, 64, error // Error EL1h
    kernel_ventry 0, t, 64, sync   // Synchronous 64-bit EL0
    kernel_ventry 0, t, 64, irq   // IRQ 64-bit EL0
    kernel_ventry 0, t, 64, fiq   // FIQ 64-bit EL0
    kernel_ventry 0, t, 64, error // Error 64-bit EL0
    kernel_ventry 0, t, 32, sync   // Synchronous 32-bit EL0 (compat)
    kernel_ventry 0, t, 32, irq
    kernel_ventry 0, t, 32, fiq
    kernel_ventry 0, t, 32, error
SYM_CODE_END(vectors)
```

Each entry is 128 bytes. The `kernel_ventry` macro:

1. Allocates space on the appropriate kernel stack (`PT_REGS_SIZE`).
2. Saves the general-purpose registers using `kernel_entry`.
3. Jumps to the C/assembly handler, e.g. `el0_sync_64_handler`.

On return, `kernel_exit` restores the saved registers and executes `eret` to return to the saved `ELR_EL1` with the saved `SPSR_EL1`.

### 1.3 SVC and Syscall Dispatch

Userspace requests a kernel service by executing `svc #0`. This triggers a **synchronous exception from EL0**, landing in the `el0_sync_64` vector entry. The assembly path saves the register frame and calls `el0_svc_64`, which in C becomes `do_el0_svc` [arch/arm64/kernel/syscall.c](https://raw.githubusercontent.com/torvalds/linux/master/arch/arm64/kernel/syscall.c):

```c
void do_el0_svc(struct pt_regs *regs)
{
    el0_svc_common(regs, regs->regs[8], __NR_syscalls, sys_call_table);
}
```

The system-call number is passed in `x8` (ARM64 convention; 32-bit compat uses `x7`). `el0_svc_common` stores the original `x0` and the syscall number, checks for ptrace/seccomp work, and dispatches through `invoke_syscall`:

```c
static void invoke_syscall(struct pt_regs *regs, unsigned int scno,
                           unsigned int sc_nr,
                           const syscall_fn_t syscall_table[])
{
    add_random_kstack_offset();
    if (likely(scno < sc_nr)) {
        syscall_fn_t syscall_fn;
        syscall_fn = syscall_table[array_index_nospec(scno, sc_nr)];
        ret = __invoke_syscall(regs, syscall_fn);
    } else {
        ret = do_ni_syscall(regs, scno);
    }
    syscall_set_return_value(current, regs, 0, ret);
}
```

The return value is placed in `x0`, and the kernel returns to the instruction following the `svc` via `eret`. The `add_random_kstack_offset()` call is a mitigation that randomizes the kernel stack layout per syscall.

---

## 2. Vulnerability Classes That Cross the EL0/EL1 Boundary

A local EL0-to-EL1 escalation almost always starts with a bug reachable through a syscall, ioctl, or other EL1 entry point. The following classes are the most common on Android/Linux ARM64.

### 2.1 Memory Corruption in Syscall Handlers

A syscall handler copies or interprets user-controlled data. Bugs include:

- Missing or incorrect bounds checks on user arrays/structs.
- Integer overflow in size calculations.
- Type confusion on multiplexed syscalls.
- Race between `access_ok()` and the actual user access.

Because the handler runs in EL1 with full kernel privileges, an OOB write or UAF can corrupt kernel objects, page tables, or credentials.

### 2.2 Driver Bugs (ioctl, mmap, sysfs, procfs)

Vendor and subsystem drivers are a large attack surface. Complex ioctls (e.g. GPU, camera, DSP, baseband) often accept nested structs and shared memory descriptors. The Mali and Adreno GPU drivers are frequent targets because they accept user-controlled GPU memory operations and expose DMA/physical-memory primitives that can be turned into kernel read/write.

### 2.3 IPC Subsystem Flaws — Binder UAF

Android Binder is the dominant IPC mechanism and is reachable from every app. Its reference-counting and transaction-buffer management are historically rich in UAF bugs. Because Binder is in the kernel, a UAF in Binder gives an unprivileged app a direct kernel corruption primitive.

### 2.4 io_uring Bugs

`io_uring` provides an asynchronous, ring-buffer-based syscall interface. Its state machine (submission/completion rings, registered buffers, fixed files, linked requests) has produced multiple UAFs and out-of-bounds accesses. Because the ring is shared between userspace and kernel, small races can produce powerful primitives.

### 2.5 perf_event Issues

`perf_event_open` exposes hardware performance counters and sampling. Bugs have included out-of-bounds access in `perf_event` configuration and information leaks via `PERF_SAMPLE_CALLCHAIN`. The latter is commonly used to leak kernel addresses and defeat KASLR. The `perf_event_paranoid` sysctl restricts access, but on many devices the default is permissive enough to sample callchains.

---

## 3. ARM-Specific Considerations vs. x86

### 3.1 PAN and PXN

- **PAN (Privileged Access Never)**, introduced in ARMv8.1, prevents the kernel from reading or writing user-space mappings while at EL1. The kernel explicitly enables user access only inside `copy_from_user`/`copy_to_user` paths, either by the `SET_PSTATE_PAN` instruction on hardware-PAN CPUs or by swapping `TTBR0_EL1` to a reserved/empty page table on older CPUs (`CONFIG_ARM64_SW_TTBR0_PAN`) [uaccess.h](https://raw.githubusercontent.com/torvalds/linux/master/arch/arm64/include/asm/uaccess.h).
- **PXN (Privileged Execute Never)** marks userspace pages as non-executable at EL1.

x86 equivalents are **SMAP** and **SMEP**. These mitigations mean that a typical kernel exploit cannot directly dereference a user pointer or jump to user shellcode; the attacker must either use a legitimate kernel copy path, corrupt a kernel object to gain a kernel virtual address, or use ROP/JOP inside kernel text.

### 3.2 KASLR Differences

ARM64 Kernel ASLR randomizes the kernel image base and the `kimage_voffset` physical-to-virtual offset at boot. The kernel text lives in the upper half of the address space (TTBR1), with `PAGE_OFFSET` and `KIMAGE_VADDR` defining the layout [memory.h](https://raw.githubusercontent.com/torvalds/linux/master/arch/arm64/include/asm/memory.h). Typical ARM64 KASLR entropy is on the order of 9–15 bits. x86 KASLR randomizes the physical and virtual base differently and uses a direct map (`physmap`) that is less segmented than ARM64's linear map. On both architectures, a kernel pointer leak defeats KASLR; however, data-only attacks often do not need the kernel base at all.

### 3.3 Pointer Authentication (PAC) and MTE

- **PAC** (ARMv8.3) embeds a cryptographic Pointer Authentication Code in the upper bits of pointers. Verified on indirect branches and returns, it raises the bar for ROP/JOP.
- **MTE** (ARMv8.5) assigns a 4-bit tag to each 16-byte memory granule. Pointer tags must match memory tags; mismatches fault. It makes heap UAF and OOB exploitation far more expensive but not impossible (e.g., tag brute-force, untagged GPU allocations, or speculative bypasses).

x86 has no direct equivalents to PAC/MTE in commodity hardware; it relies on CFI, shadow stacks, and heap hardening instead.

### 3.4 KPTI / Unmap Kernel at EL0

ARM64 can remove kernel mappings from the user page tables (`CONFIG_UNMAP_KERNEL_AT_EL0`), mitigating speculative leakage such as Meltdown. The entry path uses `tramp_vectors` to map the kernel temporarily on exception entry from EL0. This has minimal impact on local EL0→EL1 exploits because they operate from inside the kernel after a syscall, not from unprivileged speculative execution.

---

## 4. Mitigations

### 4.1 seccomp and Syscall Filtering

**seccomp BPF** allows a process to install a Berkeley Packet Filter program that decides, for each syscall, whether to allow, kill, trap, log, trace, or return an error [Seccomp BPF docs](https://docs.kernel.org/userspace-api/seccomp_filter.html). On Android, the Zygote installs a seccomp filter for every app process, blocking or restricting syscalls such as `keyctl`, `add_key`, `process_vm_writev`, and many socket-related calls. An exploit that runs from an app context must therefore work within the allowed syscall set, or use a kernel bug to modify the task's `seccomp` filter directly.

### 4.2 SELinux

SELinux is a mandatory access control (MAC) LSA. Android has run SELinux in **enforcing** mode since Android 5.0, with per-process domains defined in the policy. Even with `uid 0` capabilities, an exploited process is still constrained by its SELinux context. Common bypasses include patching the `selinux_enforcing` flag, poisoning the AVC cache, or modifying the `security` field of `struct cred` [SELinux in Android](https://source.android.com/docs/security/features/selinux).

### 4.3 Other Kernel Hardening

- **KASLR**: randomizes kernel code/data locations.
- **PAN/PXN**: hardware user-access/execution prevention.
- **PAC/MTE**: pointer integrity and memory tagging (ARM64 specific).
- **kCFI / BTI**: kernel control-flow integrity (Clang kCFI on GKI).
- **Shadow Call Stack**: protects return addresses in a separate X18 stack.
- **Slab hardening**: freelist canaries, randomization, init-on-free, random kmalloc caches.
- **Kernel lockdown**: restricts module loading, kexec, etc.

---

## 5. Notable CVEs — Technical Details

### 5.1 CVE-2024-4610 — Arm Mali GPU Driver Use-After-Free

- **Description**: Use-after-free in the Arm Bifrost and Valhall GPU kernel drivers. A local, non-privileged user can perform improper GPU memory-processing operations to access already-freed memory.
- **Affected versions**: Bifrost r34p0 through r40p0; Valhall r34p0 through r40p0. Fixed in r41p0.
- **Impact**: Local elevation of privilege (kernel context).
- **CVSS v3.1**: 7.8 HIGH (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H).
- **CISA KEV**: Added 2024-06-12, due 2024-07-03.
- **Android**: Listed in the July 2024 Android Security Bulletin as a High-severity Arm Mali component.
- **Sources**: [NVD CVE-2024-4610](https://nvd.nist.gov/vuln/detail/CVE-2024-4610), [Android Security Bulletin—July 2024](https://source.android.com/docs/security/bulletin/2024-07-01), [CISA KEV entry](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-4610).

### 5.2 CVE-2023-20938 — Binder Transaction Buffer Release UAF

- **Description**: Use-after-free in `binder_transaction_buffer_release()` of `drivers/android/binder.c`. The bug stems from the deferred copy and fixup mechanism introduced for BINDER_TYPE_PTR/BINDER_TYPE_FDA objects; an incorrect bound or corner-case check allows residual data from a previous transaction to be accessed after the buffer has been freed.
- **Android bug**: A-257685302.
- **Patch**: Android common kernel received several upstream Binder commits for this bug, including the empty-skip-region fix (`baa23246e93f`) and the corner-case fix in deferred copy/fixup (`3d213a626d2d`). The initial February 2023 patch was later found incomplete; the full fix is associated with **CVE-2023-21255** (July 2023).
- **Impact**: Local EoP from an app; no additional privileges needed.
- **Android**: Listed in the February 2023 Android Security Bulletin under the Kernel component, subcomponent Binder.
- **Sources**: [NVD CVE-2023-20938](https://nvd.nist.gov/vuln/detail/CVE-2023-20938), [Android Security Bulletin—February 2023](https://source.android.com/docs/security/bulletin/2023-02-01), [upstream fix 1/2](https://android.googlesource.com/kernel/common/+/baa23246e93f), [upstream fix 2/2](https://android.googlesource.com/kernel/common/+/3d213a626d2d).

### 5.3 CVE-2022-20186 — Mali `kbase_mem_alias` Input Validation

- **Description**: Improper input validation in `kbase_mem_alias()` of `mali_kbase_mem_linux.c` in the Arm Mali GPU driver allows arbitrary code execution.
- **Impact**: Local EoP, no additional privileges needed.
- **Android**: Pixel Update Bulletin—June 2022, severity High, component Display/graphics, Pixel-specific bug A-215001024.
- **Sources**: [NVD CVE-2022-20186](https://nvd.nist.gov/vuln/detail/CVE-2022-20186), [Pixel Update Bulletin—June 2022](https://source.android.com/docs/security/bulletin/pixel/2022-06-01).

### 5.4 CVE-2021-1048 — epoll Use-After-Free

- **Description**: Use-after-free in `ep_loop_check_proc()` of `fs/eventpoll.c`. The function can encounter a file that is already committed to destruction; it cannot take a reference on that file and does not need to add it to the reverse-path check set, but the missing handling leaves a freed object reachable.
- **Upstream fix**: `77f4689de17c` — "fix regression in 'epoll: Keep a reference on files added to the check list'".
- **Impact**: Local EoP due to UAF; severity High.
- **Android**: Android Security Bulletin—November 2021, patch level 2021-11-06, kernel component.
- **Sources**: [NVD CVE-2021-1048](https://nvd.nist.gov/vuln/detail/CVE-2021-1048), [Android Security Bulletin—November 2021](https://source.android.com/docs/security/bulletin/2021-11-01), [upstream fix](https://android.googlesource.com/kernel/common/+/77f4689de17c0887775bb77896f4cc11a39bf848).

### 5.5 CVE-2019-2215 — Bad Binder (In-The-Wild UAF)

- **Description**: UAF in the Android Binder driver. `struct binder_thread` contains a `wait_queue_head_t wait`. When the binder fd is polled via `epoll`, `binder_poll` registers that embedded wait queue with epoll. The `BINDER_THREAD_EXIT` ioctl frees the `binder_thread`, but the epoll interest list still holds a reference to the freed `wait` queue. A later `epoll_ctl(..., EPOLL_CTL_DEL, ...)` calls `remove_wait_queue()` on the freed queue, giving a controlled `list_del` unlinking primitive.
- **Exploitation (Project Zero PoC)**:
  1. Add binder fd to epoll.
  2. Issue `BINDER_THREAD_EXIT` to free the `binder_thread` (~408 bytes, lands in `kmalloc-512`).
  3. Reclaim the freed slot with a user-controlled `iovec` array (25 elements, 16 bytes each ≈ 400 bytes).
  4. Trigger `EPOLL_CTL_DEL`; the kernel `list_del` on the wait queue overwrites `iovec[10/11]` pointers, turning them into scoped kernel-address pointers.
  5. First trigger leaks the `task_struct` pointer stored in `binder_thread`.
  6. Second trigger overwrites `task_struct->addr_limit` with `0xFFFFFFFFFFFFFFFE`, after which the process can read/write arbitrary kernel memory via usercopy APIs.
- **In-the-wild use**: Project Zero reported it with a 7-day disclosure deadline because of credible evidence of exploitation by NSO/Pegasus. Affected Pixel 1/2 and many Samsung devices; patched in the October 2019 Android Security Bulletin (patch level 2019-10-06).
- **Sources**: [NVD CVE-2019-2215](https://nvd.nist.gov/vuln/detail/CVE-2019-2215), [Android Security Bulletin—October 2019](https://source.android.com/docs/security/bulletin/2019-10-01), [Project Zero: Bad Binder: Android In-The-Wild Exploit](https://projectzero.google/2019/11/bad-binder-android-in-wild-exploit.html), [CISA KEV entry](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2019-2215).

---

## 6. Sources

- ARM64 boot and exception model: Linux kernel docs, *Booting AArch64 Linux* — https://docs.kernel.org/arch/arm64/booting.html
- ARM64 memory layout: Linux kernel docs — https://docs.kernel.org/arch/arm64/memory.html
- ARM64 pointer authentication: Linux kernel docs — https://docs.kernel.org/arch/arm64/pointer-authentication.html
- ARM64 kernel entry and syscall dispatch: Linux kernel source — https://raw.githubusercontent.com/torvalds/linux/master/arch/arm64/kernel/entry.S and https://raw.githubusercontent.com/torvalds/linux/master/arch/arm64/kernel/syscall.c
- ARM64 uaccess/PAN implementation: Linux kernel source — https://raw.githubusercontent.com/torvalds/linux/master/arch/arm64/include/asm/uaccess.h
- ARM64 memory layout definitions: Linux kernel source — https://raw.githubusercontent.com/torvalds/linux/master/arch/arm64/include/asm/memory.h
- ARM64 KASLR: Linux kernel source — https://raw.githubusercontent.com/torvalds/linux/master/arch/arm64/kernel/kaslr.c
- Seccomp BPF: Linux kernel docs — https://docs.kernel.org/userspace-api/seccomp_filter.html
- SELinux in Android: Android Open Source Project — https://source.android.com/docs/security/features/selinux
- CVE-2024-4610: NVD — https://nvd.nist.gov/vuln/detail/CVE-2024-4610; Android July 2024 bulletin — https://source.android.com/docs/security/bulletin/2024-07-01; CISA KEV — https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-4610
- CVE-2023-20938: NVD — https://nvd.nist.gov/vuln/detail/CVE-2023-20938; Android February 2023 bulletin — https://source.android.com/docs/security/bulletin/2023-02-01; upstream fixes — https://android.googlesource.com/kernel/common/+/baa23246e93f and https://android.googlesource.com/kernel/common/+/3d213a626d2d
- CVE-2022-20186: NVD — https://nvd.nist.gov/vuln/detail/CVE-2022-20186; Pixel June 2022 bulletin — https://source.android.com/docs/security/bulletin/pixel/2022-06-01
- CVE-2021-1048: NVD — https://nvd.nist.gov/vuln/detail/CVE-2021-1048; Android November 2021 bulletin — https://source.android.com/docs/security/bulletin/2021-11-01; upstream fix — https://android.googlesource.com/kernel/common/+/77f4689de17c0887775bb77896f4cc11a39bf848
- CVE-2019-2215: NVD — https://nvd.nist.gov/vuln/detail/CVE-2019-2215; Android October 2019 bulletin — https://source.android.com/docs/security/bulletin/2019-10-01; Project Zero analysis — https://projectzero.google/2019/11/bad-binder-android-in-wild-exploit.html; CISA KEV — https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2019-2215

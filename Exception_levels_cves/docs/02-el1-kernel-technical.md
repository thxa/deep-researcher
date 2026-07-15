# EL1 Kernel / OS Vulnerabilities on ARM64 — Technical Depth

> **Scope:** Architecture of ARM64 Linux/Android EL1 attack surfaces, memory-corruption vulnerability classes, escalation paths to higher exception levels and persistence, the Android Generic Kernel Image (GKI) model, and the ARM64-specific hardening mitigations that shape modern exploit development.

---

## 1. ARM64 EL1 Kernel Attack Surfaces

EL1 is the operating-system privilege level on ARM64. From an attacker’s perspective it is the highest software-defined layer reachable from an unprivileged app (EL0) before hitting the hypervisor (EL2) or secure monitor (EL3).

### 1.1 Syscall / Compat entry points
The `svc` instruction is the only architecturally-defined gate from EL0 to EL1. Because the kernel is a single address space, any syscall that copies, parses, or allocates attacker-controlled data is a potential memory-corruption trigger. The 32-bit compat layer (`CONFIG_COMPAT`) is especially interesting: it doubles the syscall table and frequently re-interprets 32-bit structures into 64-bit kernel structures, leading to **type confusion** and **sign-extension / truncation** bugs. The Linux kernel self-protection guide explicitly calls out compat, user namespaces, BPF creation and perf as entry points that would benefit from tighter restriction for unprivileged users.

### 1.2 Device drivers and subsystem ioctl interfaces
Drivers live in EL1 and parse complex, vendor-specific data from userspace. Common targets include:

* **USB gadget/host drivers** (e.g., `sound/usb`, `drivers/usb`) – firmware descriptors, altsettings, and configuration arrays are classic OOB targets.
* **GPU drivers** – ARM Mali (`midgard`, `bifrost`, `valhall`) and Qualcomm Adreno (`kgsl`) expose huge ioctl surfaces for memory allocation, JIT, command streams, and fence/timeline management. The attack surface is magnified by the fact that many operations are asynchronous and require explicit kernel-level memory management for GPU-visible pages.
* **Binder** – the Android IPC driver is a kernel attack surface unique to Android; recent bulletins list Binder vulnerabilities (e.g., CVE-2024-56556 in the April 2025 bulletin).
* **Network / Wi-Fi / Bluetooth** – driver firmware-loading interfaces and socket-level ioctls (e.g., `setsockopt`) are historically rich targets.
* **Media codecs and V4L2** – untrusted compressed data is parsed by kernel or HAL drivers; integer overflows during size/stride calculations are routine.

### 1.3 GPU drivers as a privileged attack surface
GPU drivers are particularly important because they bridge the boundary between an unprivileged app and physical memory / IOMMU / page tables. On Mali, operations such as `MEM_ALLOC`, `MEM_COMMIT`, `JIT_ALLOC`, `JIT_FREE`, and `KCPU_QUEUE` manipulate per-context memory regions, shrinker/eviction lists, and CPU/GPU page tables. On Qualcomm Adreno, the `kgsl` driver manages GPU memory, shared memory, command queues, and synchronization fences. The memory pools and fence/timeline objects in both families have repeatedly produced **use-after-free** and **race-condition** vulnerabilities.

### 1.4 HVC / SMC and TrustZone interfaces
`HVC` (Hypervisor Call) and `SMC` (Secure Monitor Call) are the architectural mechanisms used from EL1 to request services from EL2 or EL3/Secure world. While the kernel itself is not the final target of these calls, bugs in the kernel code that prepares SMC arguments, or in the kernel’s management of shared memory with the TEE / TrustZone, can become **EL1→EL2/EL3 escalation** primitives. Android’s security model explicitly relies on Trusty TEE as a secure OS running alongside the rich OS; a kernel compromise at EL1 can alter the data passed to or read from the TEE, undermining higher-privilege guarantees.

### 1.5 eBPF, perf, io_uring, and futex
These are modern, high-performance interfaces that are also high-density bug sources:

* **perf** (CVE-2023-6931) allows measuring and sampling kernel events; integer overflows in `perf_read_group()` can produce heap OOB writes.
* **eBPF** allows unprivileged or privileged users to run verified code inside the kernel; verifier bugs and helper argument bugs are a recurring class.
* **io_uring** exposes efficient async I/O with complex buffer-ring state; its rapid evolution has produced many CVEs.
* **futex** / rt-mutex code (recent field observations on Samsung and Pixel devices) can produce deterministic lock-inversion deadlocks that are exploitable as stack-displacement primitives.

---

## 2. Memory-Corruption Vulnerability Classes

The same classes seen in general Linux exploitation appear repeatedly on ARM64, but with ARM64-specific nuances: pointer sizes, the top-byte-ignore (TBI) behavior, the strong kernel/user memory separation via PAN/PXN, and the prevalence of vendor GPU drivers.

| Class | Typical ARM64 / Android Context | Representative Exploitation Path |
|---|---|---|
| **Use-After-Free (UAF)** | GPU memory regions, Binder objects, file/pipe buffers, futex waiters, perf events | Reclaim the freed slot with a controlled object (cross-cache) or corrupt heap metadata |
| **Out-of-Bounds (OOB) read/write** | USB descriptors, GPU JIT arrays, kernel arrays in `udmabuf`, `setsockopt` / `recvmsg` | Corrupt adjacent object (e.g., `pipe_buffer`, `msg_msg`) or leak kernel pointers |
| **Type Confusion** | Compat syscalls, eBPF map/helper types, ioctl unions | Redirect a function pointer or obtain a writable pointer to a read-only structure |
| **Race Conditions** | GPU fence/timeline close paths, rt-mutex chains, shrinker evictions | Win a UAF or double-free by interleaving two threads during a lock-drop window |
| **Integer Overflows** | Size calculations in GPU allocation, USB configuration parsing, `perf_read_group()` | Small allocation → large OOB write or wraparound index |
| **Double-Free** | GPU JIT free paths, `pipe_buffer` release chains | Same as UAF; reclaim with a different object to corrupt allocator state |
| **Uninitialized Memory / Info Leak** | GPU pool pages, kernel stack/heap copied to userspace, TLStream buffers | Bypass KASLR / stack canaries by leaking pointers or canary values |

### 2.1 UAF and cross-cache / Dirty Pagetable
On ARM64 Android, the standard progression from a kernel UAF is:

1. Trigger the UAF (or double-free) to free an object of a known size / cache.
2. Reclaim the slot with a **pipe_buffer** array or a **msg_msg** object (for kmalloc caches), or with a **page-table page** (for page-level frees).
3. Use the resulting primitive to build arbitrary kernel read/write, typically by corrupting the `pipe_buffer` → `anon_pipe_buf_ops` function pointer chain, or by corrupting page-table entries directly (Dirty Pagetable).
4. From arbitrary R/W, patch `init_cred`/`uid`/`modprobe_path`, disable SELinux, or modify the hypervisor/SMC state if targeting EL2.

Field work on Mali GPUs (e.g., CVE-2024-4610 on Samsung Galaxy A35) confirms that the practical blocker is often the **initial write primitive** rather than the later R/W chain: without a way to corrupt the first object, the later pipe-buffer / page-table techniques cannot be bootstrapped.

### 2.2 OOB in indexed vs. adjacent forms
Adjacent OOB writes classically target `pipe_buffer` or `msg_msg` to corrupt neighboring objects. Indexed OOB writes allow targeting specific fields of a known structure (e.g., the `f_count`/`f_ops` of a file object, or a `waiter->task` pointer in rt-mutex exploitation). The Samsung 5.15 kernel example from recent field notes shows how an indexed OOB write that misses a target field by even 8 bytes can block an otherwise working chain.

### 2.3 Integer overflow → heap or array corruption
Integer overflows are especially dangerous when they happen in **size calculations** before an allocation. A wrapped size can allocate a tiny buffer while the caller later loops over a huge index, producing an OOB write. CVE-2023-6931 is a canonical example: `perf_event->read_size` can overflow, leading to a heap OOB increment or write in `perf_read_group()`.

---

## 3. From Kernel Bug to EL2 Escalation or Persistence

A successful EL1 exploit rarely stops at root; modern device targets require either escaping to a higher exception level or surviving reboot.

### 3.1 EL1 → EL2 paths
On ARM64 Android there are several routes from a compromised kernel toward EL2:

* **Hypervisor / KVM bugs:** If the device runs pKVM (Android Virtualization Framework) or another hypervisor, a kernel bug that can corrupt hypervisor-managed stage-2 page tables, or issue a malicious HVC, can compromise EL2. The Android 13 security enhancements explicitly introduced the Android Virtualization Framework (AVF), bringing multiple hypervisors under a standardized API.
* **SMC argument tampering:** At EL1 the kernel prepares buffers and arguments for the Secure Monitor / TrustZone. A kernel-level attacker can alter the physical address, size, or command passed to the TEE, or can map arbitrary physical memory into the SMC shared buffer.
* **IOMMU / SMMU manipulation:** GPU drivers already program IOMMU page tables. Corrupting those tables gives the attacker DMA-capable R/W, which can reach hypervisor or secure-world memory depending on SMMU configuration.

### 3.2 Persistence mechanisms
Once EL1 is controlled, persistence can be achieved by:

* **Modifying the boot image / initramfs:** With kernel R/W, an attacker can patch the kernel binary or ramdisk loaded on the next boot, or can patch the kernel module loader.
* **Loading a malicious kernel module:** If module signature enforcement is not enabled (`CONFIG_MODULE_SIG_FORCE`), a root-level attacker can load a `.ko` containing the rootkit. The kernel self-protection guide explicitly warns against allowing unprivileged or even privileged module loading without signature enforcement.
* **Patching SELinux / seccomp / capabilities:** A kernel-level rootkit can neuter MAC enforcement by patching policy or the `avc` cache, drop seccomp filters, or grant arbitrary capabilities.
* **Hypervisor / TEE persistence:** If EL2 or the TEE is also compromised, malicious code can be installed in code that survives device reboots and is outside the reach of the normal OS.

---

## 4. Android GKI Architecture and Security Implications

### 4.1 What GKI changed
Before GKI, every Android device shipped a heavily customized kernel. AOSP documentation states that pre-GKI devices could have **up to 50% of their kernel code as out-of-tree vendor patches**, leading to severe fragmentation.

The Generic Kernel Image (GKI) project addresses this by:

* Building a single, hardware-agnostic **generic kernel** from the Android Common Kernel (ACK) sources.
* Moving SoC and board-specific code into **vendor modules**.
* Exposing a **stable Kernel Module Interface (KMI)** so that vendor modules can continue to work even when Google updates the GKI kernel.
* Requiring devices launching with Android 12 and kernel 5.10+ to use the GKI kernel.

### 4.2 Security implications
* **Faster LTS uptake:** The AOSP GKI documentation notes that on Pixel devices, **90% of kernel issues reported in the Android Security Bulletin had already been fixed upstream** for devices staying current with LTS kernels. GKI removes the per-device merge cost, allowing Google to push LTS updates to many devices faster.
* **Reduced fragmentation:** Fewer per-vendor kernel forks means fewer unique code paths to audit and exploit.
* **Kernel/vendor split attack surface:** The KMI boundary is a new target. A bug in the exported symbol list or in module loading can give a malicious vendor module kernel-level access. However, the model also means vendors can update drivers independently of the core kernel.
* **Binary-only vendor modules:** Because some vendor modules remain closed-source, the total kernel image is a mix of auditable Google/AOSP code and unauditable vendor code. The GKI documentation acknowledges this split but emphasizes that the core kernel is now unified.

---

## 5. ARM64 Kernel Hardening

### 5.1 KASLR (Kernel Address Space Layout Randomization)
`CONFIG_RANDOMIZE_BASE` relocates the physical and virtual base of the kernel at boot, and randomizes module loading offsets. The Linux Kernel Self-Protection documentation treats KASLR as a probabilistic defense: it raises the cost of exploitation by requiring an attacker to discover kernel locations, which makes information leaks much more valuable. Randomization applies to text, module base, stack base, dynamic memory base, and even structure layout (via struct randomization, where used).

### 5.2 PAN / PXN
ARM64 provides **Privileged Access Never (PAN)** and **Privileged eXecute Never (PXN)** to enforce separation between kernel and userspace memory:

* **PXN** ensures that kernel-translation entries can mark userspace pages as non-executable, preventing trivial kernel-code execution from userspace buffers.
* **PAN** prevents the kernel from accidentally accessing userspace data, unless it explicitly uses `access_ok` / `copy_from_user` / `copy_to_user` with validation.
The kernel self-protection guide lists these as either hardware-based restrictions (ARM PXN/PAN) or emulation (ARM Memory Domains), noting that their absence makes execution and data parsing trivially redirectable to userspace memory.

### 5.3 CFI (Control-Flow Integrity)
CFI restricts indirect control transfers so that function calls and returns must target valid function entry points. Android’s security enhancements page notes that **Android 8.0 implemented CFI for the media stack**, and later releases extended CFI to additional userspace and kernel components. In the kernel, CFI is implemented by inserting type-based checks before indirect function calls, frustrating ROP/JOP chains that rely on hijacking function pointers.

### 5.4 Shadow Call Stack (SCS)
Android’s security enhancements page describes **ShadowCallStack** as an LLVM instrumentation mode that stores a function’s return address in a separate **ShadowCallStack** instance in the prologue and restores it from there in the epilogue. This protects against return-address overwrites caused by stack buffer overflows, even if the main stack canary is bypassed.

### 5.5 INIT_ON_ALLOC / Memory Initialization and Poisoning
The kernel self-protection guide emphasizes that memory copied to userspace must be fully initialized, and that freed memory should be poisoned to avoid reuse attacks. **INIT_ON_ALLOC** and **INIT_ON_FREE** are the runtime knobs that enforce this. On hardened Android devices (e.g., Samsung Android 14), `INIT_ON_ALLOC_DEFAULT_ON` zeros page allocations, which prevents exploits from relying on leaked kernel data after a free→reclaim cycle. This directly raises the bar for cross-cache and UAF exploitation that depends on stale object contents.

### 5.6 MTE / HWASan and Memory Tagging
Hardware-assisted AddressSanitizer (HWASan) is Android’s whole-system memory-error detector. The AOSP HWASan documentation explains that it is based on the **memory tagging approach**: a small random tag is associated with both pointers and memory regions; for an access to be valid, the pointer tag and the memory tag must match. HWASan relies on ARMv8’s **Top Byte Ignore (TBI)** to store the tag in the top bits of the address.

ARMv8.5+ extends this concept to **Memory Tagging Extension (MTE)** in hardware, allowing tags to be checked at native memory-access speed with very low overhead. MTE and HWASan both detect UAF, heap/stack OOB, and double-frees. The AOSP documentation notes HWASan has 256 possible tag values, giving a 0.4% chance of missing any given bug in a single execution.

### 5.7 Other deterministic defenses
The kernel self-protection guide also highlights:

* **Strict kernel/module RWX:** executable code is not writable, data is not executable (`CONFIG_STRICT_KERNEL_RWX`, `CONFIG_STRICT_MODULE_RWX`).
* **Function-pointer minimization:** marking function-pointer tables `const` or `__ro_after_init` to place them in read-only sections.
* **Stack canaries** (`CONFIG_STACKPROTECTOR`) and **stack depth holes** to detect stack overflows.
* **Atomic counter wrap detection** and **size-calculation overflow detection** to kill integer-wrap bugs.
* **seccomp** and **SELinux** to reduce the syscall and capability surface available to a compromised app.

---

## 6. Notable CVEs

### 6.1 CVE-2024-53197 — Linux kernel ALSA USB-audio out-of-bounds access
* **Type:** Out-of-bounds access (CWE-787) in `sound/usb/quirks.c`
* **Root cause:** A malicious USB device can provide a `bNumConfigurations` value that exceeds the initial value used by `usb_get_configuration` when allocating `dev->config`, leading to out-of-bounds accesses later, e.g., in `usb_destroy_configuration`.
* **Impact:** Local privilege escalation; CISA added it to the Known Exploited Vulnerabilities catalog on **2025-04-09** with a due date of **2025-04-30**.
* **Android relevance:** The April 2025 Android Security Bulletin lists CVE-2024-53197 as a **Kernel / USB** Elevation-of-Privilege (EoP) High severity issue.
* **CVSS:** NVD lists CISA-ADP CVSS 3.1 score of **7.8** (`AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`).
* **Fix:** Multiple stable kernel commits (e.g., `0b4ea4bfe165`, `b909df18ce2a`) from kernel.org.

### 6.2 CVE-2023-6931 — Linux kernel `perf` heap out-of-bounds write
* **Type:** Heap out-of-bounds write (CWE-787) in the Performance Events subsystem
* **Root cause:** A `perf_event`’s `read_size` can overflow, causing an out-of-bounds increment or write in `perf_read_group()`.
* **Impact:** Local privilege escalation from an unprivileged user with `perf_event_open` access.
* **CVSS:** NVD NIST score **7.0** (`AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`); Google assigned **7.8** (`AC:L`).
* **Fix:** Commit `382c27f4ed28f803b1f1473ac2d8db0afc795a1b` in the upstream stable tree.
* **Field note:** `perf_event_paranoid` settings and the `PERF_SAMPLE_CALLCHAIN` interface are also abused as a **KASLR bypass** on several Samsung/Pixel devices, illustrating how a subsystem intended for profiling becomes a dual-use exploit primitive.

### 6.3 CVE-2023-2008 — Linux kernel `udmabuf` improper array-index validation
* **Type:** Improper validation of array index (CWE-129) / out-of-bounds access
* **Root cause:** The `udmabuf` device driver fault handler lacks proper validation of user-supplied data, resulting in memory access past the end of an array.
* **Impact:** Local privilege escalation and arbitrary kernel code execution.
* **CVSS:** NVD base score **7.8** (`AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`).
* **Affected:** Linux kernels before the 5.19-rc4 fix; Red Hat Bugzilla tracked it as bug 2186862 and the ZDI advisory is ZDI-23-441.
* **Fix:** Commit `05b252cccb2e5c3f56119d25de684b4f810ba4` in the mainline kernel.

### 6.4 CVE-2022-22057 — Qualcomm KGSL graphics fence UAF
* **Type:** Use-after-free due to race condition (CWE-362) in the Qualcomm KGSL driver
* **Root cause:** Race condition while closing a fence file descriptor and destroying the graphics timeline simultaneously, causing a UAF in the graphics fence object.
* **Impact:** Local privilege escalation on a wide range of Snapdragon platforms (Auto, Compute, Connectivity, Industrial IOT, Mobile, Wearables).
* **CVSS:** NVD **7.8** (`AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`); Qualcomm CNA **8.4** (`AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).
* **Affected chips:** SD 8 Gen1 5G, SD888, SD870, SD865 5G, SD778G, SD765/765G, and many automotive/IoT chips.
* **References:** Qualcomm May 2022 security bulletin and Packet Storm exploit notes.
* **Exploit chain relevance:** This class of GPU-driver UAF is typically chained through kernel heap corruption to corrupt `pipe_buffer` or page-table objects, ultimately yielding arbitrary kernel R/W.

### 6.5 CVE-2024-4610 — ARM Mali GPU driver use-after-free
* **Type:** Use-after-free (CWE-416) in ARM Mali Bifrost and Valhall GPU kernel drivers
* **Affected versions:** Bifrost and Valhall drivers from **r34p0 through r40p0**; fixed at **r41p0**.
* **Root cause:** A local non-privileged user can make improper GPU memory-processing operations to access already-freed memory. Independent device analysis on the Samsung Galaxy A35 (Mali-G68 r38p1) indicates the real trigger is a **lock-drop in `kbase_jit_grow()`** during pool growth, not the commonly assumed `NO_USER_FREE` flag race. The r44p0 fix reacquires `vm_lock` after `kbase_mem_pool_grow()` and checks the reference count.
* **Impact:** Local privilege escalation; CISA added it to the KEV catalog on **2024-06-12** with a due date of **2024-07-03**, indicating active exploitation.
* **CVSS:** NVD **7.8** (`AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`).
* **Exploitation observations:** On Samsung devices, JIT softjobs are blocked from the `adb shell` context, forcing exploitation from an APK context. `INIT_ON_ALLOC_DEFAULT_ON` also zeros reclaimed GPU pages, removing content-based leak primitives. The TLStream interface, however, can still leak linear-map kernel addresses, providing a KASLR bypass.

---

## 7. Key Takeaways for Exploit Development and Defense

1. **Select the exploitation technique by bug class first.** UAF in kmalloc caches often leads to DirtyCred/pipe-buffer corruption; UAF at page-level leads to Dirty Pagetable; indexed OOB writes should target specific struct fields; adjacent OOB writes target neighboring objects such as `pipe_buffer` or `msg_msg`.
2. **The initial write primitive is the bottleneck.** Modern devices have KASLR, PAN/PXN, CFI, SCS, and memory-tagging defenses. The hardest step is often the first controlled write; once arbitrary kernel R/W is obtained, the remaining mitigations can be disabled in memory.
3. **INIT_ON_ALLOC and memory-tagging change the reconnaissance phase.** Zeroed allocations and tag mismatches eliminate stale-data leaks and many cross-cache / UAF detection strategies; attackers must rely on deterministic timing or different primitives.
4. **GKI reduces exploit shelf-life but does not eliminate the attack surface.** A unified core kernel makes LTS patching faster, but vendor modules and closed-source GPU drivers remain rich, device-specific targets.
5. **EL1 is a stepping stone, not the final goal.** High-value Android attacks aim for persistence (boot-image modification, malicious kernel modules) or escalation to EL2/TEE via hypervisor/SMC/IOMMU corruption.

---

## Sources

1. National Vulnerability Database — CVE-2024-53197: https://nvd.nist.gov/vuln/detail/CVE-2024-53197
2. National Vulnerability Database — CVE-2023-6931: https://nvd.nist.gov/vuln/detail/CVE-2023-6931
3. National Vulnerability Database — CVE-2023-2008: https://nvd.nist.gov/vuln/detail/CVE-2023-2008
4. National Vulnerability Database — CVE-2022-22057: https://nvd.nist.gov/vuln/detail/CVE-2022-22057
5. National Vulnerability Database — CVE-2024-4610: https://nvd.nist.gov/vuln/detail/CVE-2024-4610
6. Android Open Source Project — Generic Kernel Image (GKI) project: https://source.android.com/docs/core/architecture/kernel/generic-kernel-image
7. Android Open Source Project — Kernel overview / GKI architecture: https://source.android.com/docs/core/architecture/kernel
8. Linux Kernel Documentation — Kernel Self-Protection: https://www.kernel.org/doc/html/latest/security/self-protection.html
9. Android Open Source Project — Security enhancements (CFI, SCS, BoundSan, IntSan, XOM, kernel hardening): https://source.android.com/docs/security/enhancements
10. Android Open Source Project — Android Security features (Trusty TEE, SELinux, Verified Boot): https://source.android.com/docs/security/features
11. Android Open Source Project — Hardware-assisted AddressSanitizer (memory tagging / TBI): https://source.android.com/docs/security/test/hwasan
12. Android Open Source Project — Android Security Bulletin—January 2024: https://source.android.com/docs/security/bulletin/2024-01-01
13. Android Open Source Project — Android Security Bulletin—April 2025: https://source.android.com/docs/security/bulletin/2025-04-01
14. Red Hat Bugzilla — CVE-2023-2008 / udmabuf: https://bugzilla.redhat.com/show_bug.cgi?id=2186862
15. Qualcomm Product Security Bulletins (May 2022): https://www.qualcomm.com/company/product-security/bulletins/may-2022-bulletin

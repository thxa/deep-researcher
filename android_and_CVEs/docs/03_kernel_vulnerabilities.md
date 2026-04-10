# Android Kernel-Level Vulnerabilities and CVEs

## Table of Contents

1. [Introduction](#1-introduction)
2. [Kernel Driver Vulnerabilities](#2-kernel-driver-vulnerabilities)
3. [Binder IPC Subsystem Vulnerabilities](#3-binder-ipc-subsystem-vulnerabilities)
4. [Linux Kernel Vulnerabilities Affecting Android](#4-linux-kernel-vulnerabilities-affecting-android)
5. [Use-After-Free (UAF) Vulnerabilities](#5-use-after-free-uaf-vulnerabilities)
6. [Race Condition Vulnerabilities](#6-race-condition-vulnerabilities)
7. [Memory Corruption Vulnerabilities](#7-memory-corruption-vulnerabilities)
8. [Vendor-Specific Kernel CVEs](#8-vendor-specific-kernel-cves)
9. [Kernel Privilege Escalation Chains](#9-kernel-privilege-escalation-chains)
10. [Summary and Mitigation Strategies](#10-summary-and-mitigation-strategies)

---

## 1. Introduction

The Android kernel represents the most privileged layer of the Android software stack. A single vulnerability here can undermine every security mechanism built above it -- SELinux policies, application sandboxing, verified boot, and hardware-backed key storage all become irrelevant once an attacker gains kernel-level code execution. Android devices ship with a Linux kernel augmented by vendor-specific drivers, the Binder IPC mechanism, and SoC-specific subsystems from Qualcomm, MediaTek, Samsung, and others. Each of these components introduces unique attack surface.

This document catalogs the most significant kernel-level vulnerabilities affecting Android, organized by vulnerability class, with specific CVE identifiers, CVSS scores, root cause analysis, and exploitation status.

---

## 2. Kernel Driver Vulnerabilities

Kernel drivers are the largest and most heterogeneous portion of the Android kernel attack surface. GPU drivers, camera subsystems, and audio codecs are developed by SoC vendors with varying levels of security maturity and are frequently accessible from the application sandbox (e.g., via `/dev/kgsl-3d0`, `/dev/mali0`, `/dev/ion`).

### 2.1 GPU Driver Vulnerabilities

GPU drivers are particularly attractive targets because they are reachable from untrusted app contexts (any app rendering graphics interacts with the GPU driver), they contain complex memory management logic, and they are maintained by SoC vendors rather than the upstream Linux kernel community.

#### Qualcomm Adreno (KGSL) Driver

| CVE ID | CVSS v3.1 | CWE | Affected Component | Exploited in Wild |
|--------|-----------|-----|-------------------|-------------------|
| CVE-2022-22057 | 7.8 HIGH | CWE-362 | kgsl graphics fence | No |
| CVE-2020-11239 | 7.8 HIGH | CWE-416 | kgsl ioctl handler | No |
| CVE-2021-1940 | 7.8 HIGH | CWE-416 | GPU command submission | No |
| CVE-2023-33063 | 7.8 HIGH | CWE-416 | kgsl DSI handler | Yes |
| CVE-2023-33107 | 7.8 HIGH | CWE-190 | kgsl fence timeline | Yes |
| CVE-2024-43047 | 7.8 HIGH | CWE-416 | kgsl DMA-buf reference | Yes |

**CVE-2022-22057** is a use-after-free in the Qualcomm KGSL graphics fence subsystem caused by a race condition between closing a fence file descriptor and destroying the graphics timeline simultaneously. The vulnerability exists in the `kgsl_syncsource_put` function which fails to properly synchronize access to shared fence state. An attacker can trigger the race by issuing concurrent `close()` and timeline destruction ioctls from separate threads, leading to a dangling pointer that can be reclaimed with controlled data. CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (NIST), CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (Qualcomm CNA). Affects Snapdragon 460 through Gen 1 platforms.

**CVE-2023-33063** and **CVE-2023-33107** were both identified by Google TAG as being exploited in targeted attacks. CVE-2023-33063 is a UAF in the DSI handler of the KGSL driver, while CVE-2023-33107 is an integer overflow in the fence timeline handling that leads to an out-of-bounds write. These were used as part of a chain to achieve kernel code execution from an Android app context.

**CVE-2024-43047** is a UAF in the KGSL driver's DMA-buf reference counting logic. Confirmed exploited in the wild by CISA, this vulnerability allows an unprivileged local attacker to corrupt kernel memory through improper reference tracking when mapping and unmapping GPU buffers.

#### ARM Mali Driver

| CVE ID | CVSS v3.1 | CWE | Affected Component | Exploited in Wild |
|--------|-----------|-----|-------------------|-------------------|
| CVE-2021-28663 | 8.8 HIGH | CWE-416 | Mali GPU memory ops | Yes |
| CVE-2021-28664 | 8.8 HIGH | CWE-787 | Mali GPU JIT memory | Yes |
| CVE-2022-36449 | 6.5 MEDIUM | CWE-416 | Mali GPU page handling | Yes |
| CVE-2022-38181 | 8.8 HIGH | CWE-416 | Mali GPU JM/CSF | Yes |
| CVE-2023-4211 | 5.5 MEDIUM | CWE-416 | Mali GPU memory processing | Yes |
| CVE-2023-6241 | 7.8 HIGH | CWE-416 | Mali GPU CSF firmware | Yes |

**CVE-2021-28663** is a UAF in the Mali kernel driver's GPU memory operations. The driver fails to properly handle memory pages transitioning between GPU-mapped and CPU-mapped states. When a page is freed on the GPU side but still referenced on the CPU side, the dangling reference can be exploited to achieve arbitrary kernel read/write. This vulnerability was exploited in the wild and affects Bifrost and Midgard Mali GPU architectures found in Samsung Exynos, MediaTek Dimensity, and other SoCs. The CVSS v3.1 score is 8.8 due to network attack vector considerations in certain deployment scenarios.

**CVE-2022-38181** is a UAF in the Mali GPU driver's Job Manager (JM) and Command Stream Frontend (CSF) components. The vulnerability occurs when the driver incorrectly handles GPU memory regions during concurrent job submission and teardown. This was actively exploited in the wild and was part of exploit chains documented by Google's Threat Analysis Group targeting Samsung devices with Exynos chipsets.

**CVE-2023-4211** involves improper handling of GPU memory operations in the Mali kernel driver. A local non-privileged user can make improper GPU memory processing operations to gain access to already freed memory. Confirmed exploited in targeted attacks.

#### Imagination Technologies PowerVR Driver

| CVE ID | CVSS v3.1 | CWE | Affected Component | Exploited in Wild |
|--------|-----------|-----|-------------------|-------------------|
| CVE-2022-20233 | 7.8 HIGH | CWE-787 | PowerVR GPU driver | No |
| CVE-2023-21106 | 7.8 HIGH | CWE-787 | PowerVR services bridge | No |

PowerVR GPUs are found primarily in older MediaTek SoCs and some Samsung Exynos variants. CVE-2022-20233 is an out-of-bounds write in the PowerVR GPU driver that allows local privilege escalation. The vulnerability stems from improper bounds checking in the driver's ioctl handler when processing GPU command buffers.

### 2.2 Camera Driver Vulnerabilities

| CVE ID | CVSS v3.1 | CWE | Affected Component | Exploited in Wild |
|--------|-----------|-----|-------------------|-------------------|
| CVE-2021-0292 | 7.8 HIGH | CWE-787 | Qualcomm camera driver | No |
| CVE-2019-2308 | 7.8 HIGH | CWE-120 | Qualcomm camera kernel driver | No |
| CVE-2022-25667 | 7.8 HIGH | CWE-120 | Camera ISP buffer | No |

Camera drivers handle complex DMA operations and buffer management between userspace, kernel, and hardware. CVE-2019-2308 is a buffer overflow in the Qualcomm camera kernel driver caused by improper validation of userspace-supplied buffer sizes during ISP (Image Signal Processor) configuration. An attacker can trigger the overflow by sending a crafted ioctl command with oversized parameters.

### 2.3 Audio Driver Vulnerabilities

| CVE ID | CVSS v3.1 | CWE | Affected Component | Exploited in Wild |
|--------|-----------|-----|-------------------|-------------------|
| CVE-2021-0674 | 5.5 MEDIUM | CWE-190 | MediaTek audio HAL | No |
| CVE-2021-0675 | 7.8 HIGH | CWE-787 | MediaTek audio HAL | No |
| CVE-2020-0069 | 7.8 HIGH | CWE-787 | MediaTek command queue driver | Yes |

**CVE-2020-0069** is a critical vulnerability in the MediaTek Command Queue (CMDQ) driver that was widely exploited in the wild. The CMDQ driver provides direct access to hardware registers used by the display and multimedia subsystems. The vulnerability allows a local attacker to read and write physical memory by exploiting improper access control in the CMDQ ioctl interface. Notably, this was used in production exploits to root MediaTek-based devices before it was patched. The trivial exploitation -- essentially reading and writing arbitrary physical addresses -- made it extremely reliable.

---

## 3. Binder IPC Subsystem Vulnerabilities

Binder is Android's custom IPC mechanism implemented as a kernel driver (`/dev/binder`, `/dev/hwbinder`, `/dev/vndbinder`). It is the most exercised kernel attack surface on Android -- virtually every inter-process communication between apps and system services traverses Binder. The driver performs complex memory management, reference counting, and data marshaling, making it a fertile ground for vulnerabilities.

### Critical Binder CVEs

| CVE ID | CVSS v3.1 | CWE | Root Cause | Exploited in Wild |
|--------|-----------|-----|-----------|-------------------|
| CVE-2019-2215 | 7.8 HIGH | CWE-416 | UAF in iovec/epoll interaction | Yes |
| CVE-2020-0041 | 7.8 HIGH | CWE-787 | OOB write in binder transaction | Yes |
| CVE-2020-0423 | 7.8 HIGH | CWE-416 | UAF in binder_release_work | Yes |
| CVE-2022-20421 | 7.8 HIGH | CWE-416 | UAF in binder_inc_ref_for_node | Yes |

### CVE-2019-2215 -- The Binder iovec Use-After-Free

**CVSS:** 7.8 HIGH (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
**CWE:** CWE-416 (Use After Free)
**Affected Versions:** Android kernel versions prior to October 2019 security patch
**Exploited in Wild:** Yes -- confirmed by Google TAG as being used by NSO Group
**CISA KEV:** Added 2021-11-03

This is one of the most significant Android kernel vulnerabilities ever discovered. The root cause is a use-after-free in the interaction between Binder's `binder_thread` cleanup and the Linux `epoll` subsystem.

**Technical Detail:** When a Binder thread is released (e.g., via `BINDER_THREAD_EXIT` ioctl), its wait queue entry (`binder_thread->wait`) is cleaned up. However, if this wait queue was registered with an `epoll` instance via `epoll_ctl(EPOLL_CTL_ADD)`, the `epoll` subsystem retains a pointer to the wait queue entry. After the `binder_thread` is freed, the `epoll` subsystem's reference becomes a dangling pointer. When `epoll_wait` is subsequently called, the kernel follows this dangling pointer, resulting in a use-after-free.

**Exploitation:** The freed `binder_thread` structure (approximately 408 bytes in size on ARM64) can be reclaimed using heap spray techniques, typically via `sendmsg()` with crafted `iovec` structures that match the freed object's slab cache. By controlling the contents of the reclaimed memory, the attacker achieves arbitrary kernel read/write, which is then used to overwrite `task_struct->cred` or `addr_limit` to escalate to root.

**Attribution:** Google's Threat Analysis Group attributed exploitation of this vulnerability to the NSO Group, who used it in the Pegasus spyware targeting Android devices including Pixel 1/1XL/2/2XL, Huawei P20, Samsung Galaxy S7/S8/S9, Xiaomi A1, and Oppo A3.

### CVE-2020-0423 -- Binder release_work UAF

**CVSS:** 7.8 HIGH
**CWE:** CWE-416
**Exploited in Wild:** Yes

This vulnerability exists in the `binder_release_work` function called during transaction cleanup. A race condition between transaction completion and the death notification mechanism causes a double-free of internal binder work structures. When a binder node transitions states while a death notification is being delivered, the work structure can be freed twice, leading to corruption of the kernel's slab allocator metadata.

### CVE-2022-20421 -- Binder Reference Counting Flaw

**CVSS:** 7.8 HIGH
**CWE:** CWE-416
**Exploited in Wild:** Yes

A UAF in `binder_inc_ref_for_node` caused by incorrect handling of strong/weak reference transitions. When a binder reference's strong count drops to zero while an increment operation is in progress, the reference can be freed prematurely, leaving a dangling pointer.

---

## 4. Linux Kernel Vulnerabilities Affecting Android

Android inherits all vulnerabilities present in the upstream Linux kernel version it is based on. Several high-profile Linux kernel vulnerabilities have had direct impact on Android devices.

### 4.1 Dirty COW (CVE-2016-5195)

**CVSS:** 7.0 HIGH (CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H)
**CWE:** CWE-362 (Race Condition)
**Affected Versions:** Linux kernel 2.x through 4.x before 4.8.3; Android devices through November 2016 security patch
**Exploited in Wild:** Yes
**CISA KEV:** Added 2022-03-03

**Root Cause:** A race condition in `mm/gup.c` in the Linux kernel's Copy-on-Write (COW) implementation. The vulnerability exists in `get_user_pages()` and the `follow_page_pte()` functions. When a process writes to a private read-only memory mapping, the kernel is supposed to create a private copy (the COW mechanism). However, a race condition between the page fault handler and `madvise(MADV_DONTNEED)` allows an attacker to write directly to the underlying file-backed pages instead of a private copy.

**Exploitation on Android:** On Android, Dirty COW was used to:
1. Overwrite setuid binaries (e.g., `/system/bin/run-as`) to gain elevated privileges
2. Modify read-only system files to inject persistent backdoors
3. Replace the `vDSO` (virtual dynamic shared object) mapped into every process to achieve code execution

The race window is tight but can be widened by running two threads: one calling `write()` to the mapping and the other calling `madvise(MADV_DONTNEED)` to discard the private copy, forcing the next write to go to the original file. The vulnerability existed in the kernel for approximately nine years (introduced in kernel 2.6.22, September 2007) before being discovered.

### 4.2 Dirty Pipe (CVE-2022-0847)

**CVSS:** 7.8 HIGH (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
**CWE:** CWE-665 (Improper Initialization)
**Affected Versions:** Linux kernel 5.8 through 5.16.11/5.15.25/5.10.102; Android 12 devices with affected kernels
**Exploited in Wild:** Yes
**CISA KEV:** Added 2022-04-25

**Root Cause:** The `flags` member of the `pipe_buffer` structure was not properly initialized in `copy_page_to_iter_pipe()` and `push_pipe()`. When a pipe buffer is spliced from a file, the `PIPE_BUF_FLAG_CAN_MERGE` flag from a previous use of the buffer can persist (stale value). When new data is then written to the pipe, the kernel incorrectly believes it can merge the write into the existing page -- which is the page cache page of the spliced file. This allows an unprivileged user to overwrite data in the page cache of any file they can read, including setuid binaries and system files.

**Exploitation on Android:** Unlike Dirty COW, Dirty Pipe does not require a race condition, making it highly reliable. A proof-of-concept exploit fits in approximately 100 lines of C code. The attack sequence is:
1. Open a target file for reading (e.g., `/etc/passwd`)
2. Create a pipe and fill/drain it to set the `PIPE_BUF_FLAG_CAN_MERGE` flag on all buffers
3. Use `splice()` to load a page from the target file into the pipe
4. Write arbitrary data to the pipe -- this write goes into the page cache

Android 12 devices running kernel 5.10 or later were affected. Google addressed this in the Android March 2022 security bulletin.

### 4.3 io_uring Vulnerabilities

| CVE ID | CVSS v3.1 | CWE | Root Cause | Exploited in Wild |
|--------|-----------|-----|-----------|-------------------|
| CVE-2022-1786 | 7.8 HIGH | CWE-416 | UAF in io_uring msg_ring | No |
| CVE-2022-29582 | 7.0 HIGH | CWE-416 | UAF in io_uring timeout | No |
| CVE-2023-2598 | 7.8 HIGH | CWE-119 | OOB access in io_uring fixed buffers | No |
| CVE-2024-0582 | 7.8 HIGH | CWE-416 | UAF in io_uring buffer ring | No |

The `io_uring` subsystem, introduced in Linux kernel 5.1, has become one of the most prolific sources of kernel vulnerabilities. It implements an asynchronous I/O framework using shared ring buffers between userspace and kernel. Its complexity -- managing thousands of concurrent operations with lock-free data structures -- makes it exceptionally difficult to secure.

**CVE-2022-1786** is a UAF in the `io_msg_ring` function where the target ring can be freed while a message operation is in progress. On Android, `io_uring` was typically available through the `__NR_io_uring_setup` syscall on devices running kernel 5.10+, though Google has increasingly restricted access via seccomp filters.

**Android-specific note:** Google recognized the disproportionate risk of `io_uring` and disabled it entirely for untrusted apps in Android 13 via SELinux policy and seccomp filters. In Android 14, `io_uring` is completely disabled regardless of app context. This is a notable example of reducing kernel attack surface through policy rather than individual bug fixes.

### 4.4 Netfilter / nftables Vulnerabilities

| CVE ID | CVSS v3.1 | CWE | Root Cause | Exploited in Wild |
|--------|-----------|-----|-----------|-------------------|
| CVE-2022-25636 | 7.8 HIGH | CWE-122 | Heap overflow in nf_tables | No |
| CVE-2023-0179 | 7.8 HIGH | CWE-190 | Integer overflow in nftables payload | No |
| CVE-2023-32233 | 7.8 HIGH | CWE-416 | UAF in nf_tables anonymous sets | No |
| CVE-2024-1086 | 7.8 HIGH | CWE-416 | UAF in nf_tables nft_verdict_init | Yes |

**CVE-2024-1086** is a UAF in nf_tables' verdict handling. The `nft_verdict_init()` function allows a positive value for `NF_DROP`, which is then cast to a drop error via `NF_DROP_GETERR()`. This corrupts the verdict structure and leads to a double-free when the associated object is cleaned up. A public exploit achieving reliable privilege escalation on kernels 5.14 through 6.6 was released. While nftables is available in the Android kernel, it is typically not reachable from the app sandbox due to `CAP_NET_ADMIN` requirements, though certain privilege escalation chains may bypass this restriction.

---

## 5. Use-After-Free (UAF) Vulnerabilities

UAF vulnerabilities represent the single most common class of kernel vulnerability exploited on Android. They occur when the kernel frees a memory object but retains a reference (dangling pointer) that is later dereferenced.

### Common UAF Patterns in Android Kernel

**Pattern 1: Reference Count Mismatch**
The most common UAF pattern involves incorrect reference counting. An object's reference count is decremented too early or incremented too late, allowing the object to be freed while still in use.

**Pattern 2: Concurrent Access Without Synchronization**
Two kernel code paths access the same object without proper locking. One path frees the object while the other is still using it.

**Pattern 3: Callback/Notification After Free**
An object registers a callback or notification handler. When the object is freed, the callback registration is not properly cleaned up, leading to invocation of a callback on a freed object.

### Critical UAF Examples

| CVE ID | CVSS v3.1 | Component | UAF Pattern | Exploited in Wild |
|--------|-----------|-----------|-------------|-------------------|
| CVE-2021-1048 | 7.8 HIGH | eventpoll.c | Pattern 2 | Yes |
| CVE-2021-0920 | 6.4 MEDIUM | af_unix garbage collection | Pattern 1 | Yes |
| CVE-2021-22555 | 7.8 HIGH | netfilter x_tables | Pattern 3 | No |
| CVE-2023-0266 | 7.8 HIGH | ALSA USB audio | Pattern 1 | Yes |

**CVE-2021-1048** is a UAF in `ep_loop_check_proc()` of the `eventpoll.c` subsystem. The vulnerability occurs due to a race between `eventpoll` chain loop checking and file descriptor closing. When an epoll file descriptor is closed while the kernel is traversing the epoll chain (checking for loops), a UAF occurs because the traversal holds a reference to an epoll instance that is being freed. CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H. This was exploited in the wild and listed in CISA's KEV catalog (added 2022-05-23).

**CVE-2021-0920** is a UAF in the Unix domain socket garbage collector (`af_unix`). The garbage collector (`unix_gc()`) races with `sendmsg()`, leading to a scenario where file descriptors passed via SCM_RIGHTS can be freed while still being delivered. Google TAG attributed exploitation of this vulnerability (combined with CVE-2021-1048) to a commercial spyware vendor targeting Samsung devices. CISA KEV listed.

**CVE-2023-0266** is a UAF in the ALSA (Advanced Linux Sound Architecture) PCM subsystem's USB audio driver. The vulnerability occurs in the disconnect path when a USB audio device is removed while audio streams are active. The race between `snd_usb_disconnect()` and ongoing audio operations leads to accessing freed `snd_usb_substream` structures. Exploited in the wild as part of a Samsung device exploit chain.

---

## 6. Race Condition Vulnerabilities

Race conditions occur when the outcome of an operation depends on the relative timing of concurrent events. In the kernel, these manifest as TOCTOU (Time-of-Check-to-Time-of-Use) bugs, data races on shared state, and improper synchronization of concurrent operations.

### TOCTOU Bugs

| CVE ID | CVSS v3.1 | Component | Description |
|--------|-----------|-----------|-------------|
| CVE-2016-5195 | 7.0 HIGH | mm/gup.c (Dirty COW) | TOCTOU in COW page fault handler |
| CVE-2022-22057 | 7.8 HIGH | Qualcomm kgsl | Race between fence close and timeline destroy |
| CVE-2021-0399 | 7.8 HIGH | Android kernel | TOCTOU in IPC data validation |

**TOCTOU Pattern in Android Kernel:**

A typical TOCTOU vulnerability in the Android kernel occurs when the kernel validates userspace data (the "check") and then uses it later (the "use") without ensuring the data has not been modified between the two operations. For data in shared memory (e.g., Binder transaction buffers), another thread in the same process can modify the data after validation.

```
Thread A (kernel):              Thread B (userspace):
  1. Read size from user buffer
  2. Validate: size <= MAX_SIZE
                                   3. Modify size to 0xFFFFFFFF
  4. Use size for allocation      (BUG: allocates based on unchecked value)
```

This pattern is especially common in Binder transactions where the kernel reads and validates transaction data from a userspace-shared buffer. The mitigation is to copy data from userspace into kernel memory before validation and use.

### Data Race Exploits

| CVE ID | CVSS v3.1 | Component | Race Description |
|--------|-----------|-----------|-----------------|
| CVE-2021-0920 | 6.4 MEDIUM | af_unix GC | GC vs. sendmsg race |
| CVE-2020-0423 | 7.8 HIGH | Binder | Transaction completion vs. death notification |
| CVE-2023-6817 | 7.8 HIGH | nf_tables | Set element activation race |

Data races in the kernel are particularly dangerous because kernel code typically runs with full privileges. A race that corrupts a single pointer or reference count can be parlayed into arbitrary kernel read/write. KCSAN (Kernel Concurrency Sanitizer) has been instrumental in detecting these in upstream Linux, but vendor kernel branches often lack this instrumentation.

---

## 7. Memory Corruption Vulnerabilities

### 7.1 Out-of-Bounds Read/Write

| CVE ID | CVSS v3.1 | CWE | Component | Direction |
|--------|-----------|-----|-----------|-----------|
| CVE-2020-0041 | 7.8 HIGH | CWE-787 | Binder | Write |
| CVE-2022-20186 | 7.8 HIGH | CWE-787 | Mali GPU driver | Write |
| CVE-2021-39793 | 7.8 HIGH | CWE-787 | Pixel Neural Networks HAL | Write |
| CVE-2023-21400 | 6.7 MEDIUM | CWE-787 | io_uring | Write |
| CVE-2020-0069 | 7.8 HIGH | CWE-787 | MediaTek CMDQ driver | Read/Write |

**CVE-2020-0041** is an OOB write in Binder's transaction handling. The vulnerability occurs when the kernel processes a `BR_TRANSACTION` with a crafted offsets array. The Binder driver fails to properly validate the offsets of flat_binder_object structures within a transaction buffer, allowing an attacker to write beyond the allocated buffer boundary. This was exploited in the wild.

### 7.2 Heap Overflow

| CVE ID | CVSS v3.1 | CWE | Component | Description |
|--------|-----------|-----|-----------|-------------|
| CVE-2022-25636 | 7.8 HIGH | CWE-122 | nf_tables | Heap buffer overflow in flow offload |
| CVE-2019-2308 | 7.8 HIGH | CWE-120 | Qualcomm camera driver | Heap overflow via crafted ioctl |
| CVE-2021-0675 | 7.8 HIGH | CWE-787 | MediaTek audio | Heap overflow in audio buffer |

Heap overflows in the kernel allow an attacker to corrupt adjacent objects in the SLUB/SLAB allocator. The exploitation technique typically involves:

1. **Heap grooming:** Arranging the heap so that a target object (e.g., `cred`, `pipe_buffer`, `msg_msg`) is adjacent to the vulnerable buffer
2. **Triggering the overflow:** Corrupting the adjacent object's function pointers or metadata
3. **Triggering the corrupted object:** Invoking the corrupted function pointer to redirect execution

### 7.3 Stack Buffer Overflow

Stack overflows in the kernel are less common than heap overflows due to the kernel's fixed-size stack (typically 16KB on ARM64 for Android). However, they do occur:

| CVE ID | CVSS v3.1 | CWE | Component | Description |
|--------|-----------|-----|-----------|-------------|
| CVE-2021-28660 | 8.8 HIGH | CWE-121 | rtl8188eu WiFi driver | Stack overflow in SSID handling |
| CVE-2020-9890 | 7.8 HIGH | CWE-121 | Qualcomm WLAN driver | Stack overflow in vendor command |

Modern Android kernels enable stack canaries (`CONFIG_STACKPROTECTOR_STRONG`) which place a random value on the stack before the return address. An overflow must either avoid corrupting the canary or leak it first, making exploitation harder but not impossible.

---

## 8. Vendor-Specific Kernel CVEs

### 8.1 Qualcomm-Specific Vulnerabilities

Qualcomm provides the SoC (Snapdragon) powering the majority of Android devices. Their kernel contributions include the KGSL GPU driver, camera ISP drivers, WLAN drivers, DSP (Hexagon) interface, and various modem-related subsystems.

| CVE ID | CVSS v3.1 | Component | Description | Exploited |
|--------|-----------|-----------|-------------|-----------|
| CVE-2021-1905 | 8.4 HIGH | Adreno GPU | UAF in GPU command processing | Yes |
| CVE-2021-1906 | 5.5 MEDIUM | Adreno GPU | Improper address validation | Yes |
| CVE-2021-28663 | 8.8 HIGH | Mali GPU | UAF in GPU memory ops | Yes |
| CVE-2022-22057 | 7.8 HIGH | KGSL driver | Race condition in fence handling | No |
| CVE-2022-33213 | 7.8 HIGH | Modem interface | Buffer overflow in QMI | No |
| CVE-2024-43047 | 7.8 HIGH | KGSL driver | UAF in DMA-buf handling | Yes |

**CVE-2021-1905** and **CVE-2021-1906** were exploited together as a pair. CVE-2021-1905 is a UAF in the Adreno GPU's handling of `IOCTL_KGSL_GPUOBJ_IMPORT` where a GPU memory object can be freed while still mapped. CVE-2021-1906 is an improper address validation that allows mapping GPU objects at arbitrary kernel addresses. Combined, they provide arbitrary kernel read/write.

### 8.2 MediaTek-Specific Vulnerabilities

| CVE ID | CVSS v3.1 | Component | Description | Exploited |
|--------|-----------|-----------|-------------|-----------|
| CVE-2020-0069 | 7.8 HIGH | CMDQ driver | Physical memory read/write | Yes |
| CVE-2021-0661 | 6.7 MEDIUM | DSP driver | OOB read in audio DSP | No |
| CVE-2021-0662 | 6.7 MEDIUM | DSP driver | OOB write in audio DSP | No |
| CVE-2021-0663 | 6.7 MEDIUM | DSP driver | OOB write in audio DSP | No |
| CVE-2023-20738 | 6.7 MEDIUM | VPU driver | Integer overflow | No |

**CVE-2020-0069** stands out as one of the most impactful MediaTek vulnerabilities. The CMDQ (Command Queue) driver exposes the `/dev/mtk_cmdq` device node accessible to unprivileged apps on affected devices. Through this interface, an attacker can directly read and write physical memory without any authentication or authorization. This vulnerability was publicly disclosed and widely used in rooting tools (e.g., "MTK-su") before being patched. It affected all 64-bit MediaTek SoCs available at the time of disclosure.

### 8.3 Samsung Exynos-Specific Vulnerabilities

| CVE ID | CVSS v3.1 | Component | Description | Exploited |
|--------|-----------|-----------|-------------|-----------|
| CVE-2022-22265 | 7.8 HIGH | Samsung NPU driver | UAF in NPU device node | No |
| CVE-2024-44068 | 8.1 HIGH | Samsung m2m scaler driver | UAF in mobile processor | Yes |
| CVE-2022-36846 | 7.8 HIGH | Samsung kernel | OOB write in MFC driver | No |
| CVE-2023-21492 | 4.4 MEDIUM | Samsung kernel | KASLR bypass via log exposure | Yes |

**CVE-2024-44068** is a UAF vulnerability in the Samsung Exynos mobile processor's m2m (memory-to-memory) scaler driver. The vulnerability allows a local attacker to escalate privileges by exploiting improper memory management in the scaler hardware abstraction layer. Confirmed exploited in the wild.

**CVE-2023-21492** deserves special mention despite its moderate CVSS score. This vulnerability exposes kernel pointer addresses in Samsung's kernel log output, effectively defeating KASLR (Kernel Address Space Layout Randomization). While not directly exploitable for code execution, it removes a critical mitigation that other exploits must bypass, making it a valuable primitive in exploit chains. Exploited in the wild.

---

## 9. Kernel Privilege Escalation Chains

Real-world Android exploitation rarely relies on a single vulnerability. Instead, attackers chain multiple vulnerabilities together, each providing a different primitive needed for the full attack.

### 9.1 Anatomy of a Kernel Exploit Chain

A typical Android kernel exploit chain consists of:

```
Stage 1: Sandbox Escape (Optional)
  - Escape Chrome/WebView renderer sandbox
  - e.g., via V8 bug -> Mojo IPC -> browser process compromise

Stage 2: Kernel Information Leak
  - Defeat KASLR to locate kernel text/data
  - e.g., CVE-2023-21492 (Samsung log leak), /proc/kallsyms (if available)
  - Alternatively: side-channel KASLR bypass, timing attacks

Stage 3: Kernel Memory Corruption
  - Trigger the primary vulnerability (UAF, OOB write, etc.)
  - e.g., CVE-2019-2215 (Binder UAF), CVE-2021-1048 (eventpoll UAF)

Stage 4: Achieving Arbitrary Kernel Read/Write
  - Reclaim freed object with controlled data (heap spray)
  - Corrupt pipe_buffer, msg_msg, or other kernel objects
  - Build read/write primitives using corrupted objects

Stage 5: Privilege Escalation
  - Overwrite current task's cred struct (commit_creds(prepare_kernel_cred(0)))
  - Modify SELinux enforcement state
  - Disable seccomp filters
  - Patch security hooks

Stage 6: Post-Exploitation
  - Install persistent rootkit
  - Exfiltrate data
  - Deploy spyware implant
```

### 9.2 Documented Exploit Chains

#### NSO Group Pegasus (2019)
- **Stage 2:** Kernel info leak via undisclosed vulnerability
- **Stage 3:** CVE-2019-2215 (Binder UAF)
- **Stage 4:** Heap spray with `sendmsg()` iovec to reclaim freed `binder_thread`
- **Stage 5:** Overwrite `addr_limit` to gain kernel read/write, then overwrite creds

#### Commercial Spyware Campaign (2021) -- Samsung Devices
- **Stage 2:** CVE-2023-21492 or similar info leak
- **Stage 3:** CVE-2021-0920 (af_unix GC UAF)
- **Stage 4:** Corrupted file structure via GC race
- **Stage 5:** Combined with CVE-2021-1048 for full kernel R/W

#### In-the-Wild Qualcomm Exploit (2023)
- **Stage 2:** Information leak via undisclosed bug
- **Stage 3:** CVE-2023-33063 (KGSL UAF)
- **Stage 4:** Combined with CVE-2023-33107 (integer overflow for OOB write)
- **Stage 5:** Kernel code execution, SELinux disable, cred overwrite

### 9.3 Common Exploitation Primitives

**Pipe Buffer Manipulation:** Since Linux 5.8, `pipe_buffer` structures have been a preferred target for kernel exploitation. By corrupting a `pipe_buffer`'s page pointer and flags, an attacker can read/write arbitrary physical pages. The `PIPE_BUF_FLAG_CAN_MERGE` flag (as used in Dirty Pipe) enables page cache writes.

**msg_msg Exploitation:** The `msg_msg` structure used by System V message queues is highly flexible for exploitation. Its variable-size allocation (`kmalloc`-based) allows targeting specific slab caches, and the `msg_msg->next` pointer can be corrupted to build arbitrary read primitives.

**Cross-Cache Attacks:** Modern exploits increasingly use cross-cache techniques where an object is freed from one slab cache and the physical page is reallocated to a different cache. This bypasses same-cache hardening measures like `CONFIG_SLAB_FREELIST_HARDENED` and `CONFIG_RANDOM_KMALLOC_CACHES` introduced in recent Android kernels.

---

## 10. Summary and Mitigation Strategies

### Vulnerability Distribution by Class

| Vulnerability Class | Count (in this report) | % Exploited in Wild |
|---------------------|----------------------|---------------------|
| Use-After-Free | 24 | ~58% |
| Race Condition | 8 | ~50% |
| Out-of-Bounds Write | 10 | ~30% |
| Improper Initialization | 2 | ~50% |
| Integer Overflow | 4 | ~25% |
| Buffer Overflow | 5 | ~20% |

### Key Observations

1. **UAF dominates:** Use-after-free is the most common vulnerability class in exploited Android kernel bugs, accounting for the majority of in-the-wild exploitation.

2. **GPU drivers are the primary entry point:** GPU drivers (Qualcomm KGSL, ARM Mali) are reachable from the app sandbox and have the highest density of exploited vulnerabilities among driver subsystems.

3. **Binder remains high-value:** Despite significant hardening, the Binder IPC driver's complexity continues to yield exploitable vulnerabilities.

4. **Vendor code quality varies:** MediaTek's CMDQ driver (CVE-2020-0069) and similar low-level hardware interface drivers demonstrate that some vendor code lacks basic security design (e.g., exposing physical memory read/write to unprivileged users).

5. **Exploit chains are standard practice:** Single-vulnerability exploits are rare in production. Attackers chain information leaks, memory corruption, and privilege escalation primitives.

### Android Kernel Mitigations

| Mitigation | Introduced | Effectiveness |
|-----------|-----------|---------------|
| KASLR | Android 8.0 | Moderate -- defeated by info leaks |
| PAN (Privileged Access Never) | ARM hardware | High -- prevents kernel from accessing user memory |
| CFI (Control Flow Integrity) | Android 9 | High -- prevents ROP/JOP attacks |
| Shadow Call Stack | Android 10 | High -- protects return addresses |
| Memory Tagging (MTE) | Android 14 (ARM v8.5+) | Very High -- probabilistic UAF/overflow detection |
| `CONFIG_SLAB_FREELIST_HARDENED` | Android 10 | Moderate -- detects slab metadata corruption |
| `CONFIG_RANDOM_KMALLOC_CACHES` | Android 14 | Moderate -- randomizes slab allocation |
| io_uring restriction | Android 13+ | High -- removes entire attack surface |
| GKI (Generic Kernel Image) | Android 12 | Moderate -- ensures consistent security patches |
| seccomp-bpf | Android 8.0 | High -- filters dangerous syscalls |

### Recommendations

1. **Apply security patches promptly.** The Android Security Bulletin is published monthly. The gap between patch availability and device update remains the primary risk factor.

2. **Minimize kernel attack surface.** Disable unused kernel features (io_uring, nftables, unused drivers). Use seccomp-bpf to restrict syscall access from the app sandbox.

3. **Deploy MTE where available.** ARM Memory Tagging Extension provides hardware-enforced probabilistic detection of UAF and buffer overflow vulnerabilities. Enable it in both synchronous (for testing) and asymmetric (for production) modes.

4. **Audit vendor driver code.** SoC vendor drivers consistently exhibit lower code quality than upstream Linux kernel code. Prioritize fuzzing and code review of GPU, camera, and audio drivers.

5. **Monitor CISA KEV catalog.** The Known Exploited Vulnerabilities catalog provides actionable intelligence on vulnerabilities confirmed to be exploited in the wild.

---

*Document version: 1.0*
*Last updated: April 2026*
*Sources: NVD (NIST), Android Security Bulletins (Google), CISA KEV Catalog, Google Threat Analysis Group reports, Project Zero disclosures, Qualcomm Product Security Bulletins*

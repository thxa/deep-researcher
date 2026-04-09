# Chapter 8b: Notable CVEs & Case Studies — Modern Kernel Exploitation (2020-2026)

## Table of Contents

1. [CVE-2024-1086: nf_tables Double-Free — The Universal LPE](#1-cve-2024-1086-nf_tables-double-free)
2. [CVE-2023-2008: udmabuf Out-of-Bounds Access](#2-cve-2023-2008-udmabuf-out-of-bounds-access)
3. [Wall of Shame: Kernel Vulnerabilities in Real-World Attacks and CTFs](#3-wall-of-shame)
4. [Android Kernel Exploits: Binder, ION, and DMA-BUF](#4-android-kernel-exploits)
5. [Container Escape Exploits via Kernel Vulnerabilities](#5-container-escape-exploits)
6. [eBPF Verifier Bypass CVEs](#6-ebpf-verifier-bypass-cves)
7. [Trends in Kernel Vulnerability Discovery (2020-2026)](#7-trends-in-kernel-vulnerability-discovery)
8. [Comparison of Kernel Exploit Complexity Over the Years](#8-exploit-complexity-comparison)
9. [The Role of Kernel Vulnerabilities in Privilege Escalation Chains](#9-kernel-vulns-in-privilege-escalation-chains)
10. [References](#10-references)

---

## 1. CVE-2024-1086: nf_tables Double-Free

**The Universal LPE — "Flipping Pages"**

### 1.1 Overview

| Field | Detail |
|-------|--------|
| **CVE** | CVE-2024-1086 |
| **CVSS** | 7.8 HIGH (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |
| **Affected Versions** | Linux v3.15 through v6.7.2 (patched v6.7.3, v6.6.15, v6.1.76, v5.15.149) |
| **Subsystem** | Netfilter / nf_tables |
| **Bug Class** | Input sanitization failure leading to double-free (Use-After-Free) |
| **Discoverer** | notselwyn (2024) |
| **Exploit Success Rate** | 93%-99.4% across tested configurations |
| **CISA KEV** | Added 2024-05-30 (confirmed in-the-wild exploitation) |

CVE-2024-1086 stands as one of the most significant Linux kernel local privilege escalation vulnerabilities of the 2020s decade. Discovered by researcher "notselwyn," it demonstrates the continued danger of the Netfilter subsystem, which has been a persistent source of critical vulnerabilities. The exploit was notable for its universality — a single binary could root nearly all Linux kernels between v5.14 and v6.6 without recompilation, including hardened KernelCTF mitigation instances.

### 1.2 Root Cause Analysis

The vulnerability is an input sanitization failure in `nft_verdict_init()`, the Netlink API handler responsible for constructing Netfilter verdict objects from userspace input.

**The Core Problem:** The function allowed positive values as "drop errors" within a hook verdict. The Netfilter verdict system uses `NF_DROP` (value 0) to drop packets and `NF_ACCEPT` (value 1) to accept them. A crafted verdict value of `0xffff0000` passes validation because:

1. `data->verdict.code & NF_VERDICT_MASK` evaluates to `0x0` (i.e., `NF_DROP`) — validation succeeds.
2. When processed by `nf_hook_slow()`, the packet is freed via `kfree_skb_reason()` because `NF_DROP` is matched.
3. However, `NF_DROP_GETERR(0xffff0000)` returns `1`, which equals `NF_ACCEPT`.
4. The function returns `1` (NF_ACCEPT), causing the caller `NF_HOOK()` to continue processing the already-freed packet.

The result: the caller invokes `okfn(net, sk, skb)` on a freed `sk_buff`, leading to a second free — a classic double-free primitive.

**Vulnerable Code Path:**

```c
// nf_hook_slow() — iterates over nftables rules
int nf_hook_slow(struct sk_buff *skb, struct nf_hook_state *state,
         const struct nf_hook_entries *e, unsigned int s)
{
    unsigned int verdict;
    int ret;

    for (; s < e->num_hook_entries; s++) {
        verdict = nf_hook_entry_hookfn(&e->hooks[s], skb, state);

        switch (verdict & NF_VERDICT_MASK) {
        case NF_ACCEPT:
            break;
        case NF_DROP:
            kfree_skb_reason(skb, SKB_DROP_REASON_NETFILTER_DROP);  // First free
            ret = NF_DROP_GETERR(verdict);  // Returns 1 (NF_ACCEPT)
            if (ret == 0)
                ret = -EPERM;
            return ret;  // Returns 1 = NF_ACCEPT
        // ...
        }
    }
    return 1;
}
```

The caller (`NF_HOOK`) then invokes the "ok function" on the freed skb:

```c
static inline int NF_HOOK(...)
{
    int ret = nf_hook(pf, hook, net, sk, skb, in, out, okfn);
    if (ret == NF_ACCEPT)  // True! Because nf_hook_slow returned 1
        ret = okfn(net, sk, skb);  // Second free — double-free!
    return ret;
}
```

### 1.3 Exploitation Chain — The "Dirty Pagedirectory" Technique

The exploit is remarkable for its sophistication and universality. It chains multiple novel techniques:

#### Step 1: Triggering the Double-Free

The attacker creates a Netfilter rule in an unprivileged user namespace containing an expression that sets the malicious verdict value `0xffff0000`. When a crafted IP packet triggers the rule, the double-free occurs on both:
- The `struct sk_buff` object (in the `skbuff_head_cache` slab cache)
- The `sk_buff->head` data buffer (dynamically sized, from `kmalloc-256` up to order-4 buddy pages)

The exploit crafts a 16-page (64 KiB) IP packet so the `sk_buff->head` is allocated directly from the buddy allocator (order 4), bypassing the slab and PCP allocators.

#### Step 2: IP Fragment Delaying

To create a window between the first and second free (enabling heap manipulation), the exploit abuses IP packet fragmentation. A fragment is sent that enters the IP fragment reassembly queue, "parking" the second reference to the skb for a controllable duration before the second free occurs. The exploit spoofs source `1.1.1.1` and destination `255.255.255.255`, disabling Reverse Path Forwarding (RPF) in the network namespace (which does not require root).

#### Step 3: PCP Draining for Page Conversion

The double-free'd object is an order-4 buddy page, but the PTE/PMD pages needed for the Dirty Pagedirectory technique are order-0. The exploit uses **PCP (Per-CPU Page) draining**: by freeing the order-4 (16 pages) pages to the buddy allocator freelist, then draining the PCP list, the 16 pages are refilled into the order-0 PCP freelist where they can be allocated as individual pages.

#### Step 4: Dirty Pagedirectory — The Novel KSMA Technique

This is the exploit's crown jewel. It achieves unlimited physical memory read/write from userland:

1. **Double-allocate a PTE page and a PMD page to the same physical address.** This is the "pagetable confusion."
2. **Write PTE entries via the PTE-mapped virtual address.** When writing a PTE value (which encodes a physical address and permission flags) to the PTE page, the PMD page interprets the same bytes as a PMD entry.
3. **Dereference the PMD entry.** This causes the CPU to follow the crafted PTE value as if it were a page table pointer, effectively mapping any arbitrary physical address into the attacker's virtual address space.
4. **TLB Flushing from userland.** The exploit uses `fork()` + `munmap()` on the target VMA to force TLB invalidation, as the kernel's normal TLB flush paths are not triggered during exploitation.

#### Step 5: Physical KASLR Defeat and Privilege Escalation

With arbitrary physical memory access:
1. **Bruteforce physical KASLR** by scanning 2 MiB-aligned pages for a kernel binary signature (generated by the `get-sig` tool), leveraging `CONFIG_PHYSICAL_ALIGN` (typically 2 MiB or 16 MiB).
2. **Locate `modprobe_path`** via a memory scan for the string `"/sbin/modprobe"` across ~80 MiB past the kernel base.
3. **Verify the found address** by overwriting `modprobe_path` and checking if `/proc/sys/kernel/modprobe` reflects the change.
4. **Overwrite `modprobe_path`** (or `"/sbin/usermode-helper"` if `CONFIG_STATIC_USERMODEHELPER` is enabled) to point to a privilege escalation script executed via memfd (fileless).
5. **Trigger modprobe** by executing a file with unrecognized magic bytes, causing the kernel to execute the attacker's script as root.
6. **Namespace escape** is achieved by hooking the exploit process's file descriptors to the root shell.

#### Exploitation Properties

| Property | Value |
|----------|-------|
| **Data-only** | Yes — no code pointers corrupted |
| **KSMA** | Kernel-Space Mirroring Attack from userland |
| **Cross-version** | Single binary works across v5.14-v6.6 without recompilation |
| **Fileless** | Uses memfd; no disk writes |
| **Bypasses** | KASLR, SMEP, SMAP, KPTI, KernelCTF mitigations |
| **Prerequisite** | Unprivileged user namespaces enabled |
| **Success rate** | 99.4% (n=1000) on tested configurations |

### 1.4 Fix

The fix (commit `f342de4e2f33`) sanitizes verdicts from userland input in the Netfilter API, disallowing drop errors entirely for user-provided verdicts. If this behavior is needed in the future, only drop errors with `n <= 0` should be allowed to prevent positive values from overlapping with `NF_ACCEPT`.

### 1.5 Significance

CVE-2024-1086 was added to CISA's Known Exploited Vulnerabilities catalog on May 30, 2024, confirming real-world exploitation. It represents the state of the art in modern Linux kernel exploitation:
- **Universal exploits** that work across kernel versions and distributions without recompilation
- **Data-only attacks** that bypass code-pointer integrity mitigations
- **Novel pagetable manipulation techniques** that achieve arbitrary physical memory access
- **Fileless execution** that evades forensic and endpoint detection

---

## 2. CVE-2023-2008: udmabuf Out-of-Bounds Access

### 2.1 Overview

| Field | Detail |
|-------|--------|
| **CVE** | CVE-2023-2008 |
| **CVSS** | 7.8 HIGH (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |
| **Affected Versions** | Linux v4.20 through v5.18.8 (multiple stable branches) |
| **Subsystem** | udmabuf — User DMA-BUF device driver |
| **Bug Class** | Improper Validation of Array Index (CWE-129) |
| **Discoverer** | Reported via ZDI (ZDI-23-441) |

### 2.2 Technical Details

The vulnerability exists in the `udmabuf` device driver's fault handler. The `udmabuf` subsystem provides a way for userspace to create DMA-BUF objects backed by memfd pages, enabling zero-copy data sharing between userspace and kernel-space drivers.

**Root Cause:** The fault handler fails to properly validate user-supplied data when handling page faults on a mapped udmabuf region. Specifically, the offset computation for page lookups does not adequately bounds-check the user-supplied virtual address against the actual size of the backing memfd pages array.

An attacker who can open and interact with the `/dev/udmabuf` device (or has access through a DMA-BUF file descriptor) can trigger a memory access past the end of the internal page array. This results in an out-of-bounds read/write primitive in kernel context.

**Exploitation path:**
1. Create a udmabuf object backed by a memfd with a carefully chosen size.
2. Map the udmabuf file descriptor into the process address space.
3. Trigger page faults at calculated offsets that cause the fault handler to access memory beyond the page array bounds.
4. The out-of-bounds access can be leveraged to read or corrupt adjacent kernel heap objects.
5. Escalate privileges by corrupting security-sensitive kernel structures.

### 2.3 Fix

The fix (commit `05b252cccb2e`) adds proper bounds validation in the udmabuf fault handler, ensuring that the computed page index cannot exceed the actual number of pages backing the udmabuf object. The check verifies `pgoff < ubuf->pagecount` before dereferencing the page array.

### 2.4 Context: DMA-BUF as an Attack Surface

The udmabuf/DMA-BUF subsystem has become an increasingly important attack surface because:
- It bridges userspace and kernel memory management
- It is used extensively in graphics (DRM/KMS), media, and Android (replacing ION)
- Fault handlers in virtual memory are a historically rich source of kernel vulnerabilities
- The complexity of buffer sharing across subsystems creates opportunities for validation gaps

---

## 3. Wall of Shame

**Kernel Vulnerabilities in Real-World Attacks and CTFs**

### 3.1 Vulnerabilities Confirmed Exploited in the Wild

The following kernel CVEs have been confirmed by CISA, Google TAG, or other authoritative sources as exploited in real-world attacks:

| CVE | Year | Subsystem | Bug Class | Exploited By | Notes |
|-----|------|-----------|-----------|-------------|-------|
| **CVE-2024-1086** | 2024 | nf_tables | Double-free | Unknown | CISA KEV; universal LPE |
| **CVE-2024-36971** | 2024 | Networking (route) | UAF | Unknown | Android in-the-wild, CISA KEV Aug 2024 |
| **CVE-2024-53104** | 2024 | USB Video Class | OOB Write | Serbian authorities (Cellebrite) | Used to unlock journalist's phone |
| **CVE-2023-0266** | 2023 | ALSA (sound) | UAF | Spyware vendor | Part of Samsung exploit chain |
| **CVE-2023-4211** | 2023 | ARM Mali GPU | UAF | Unknown | Android zero-day |
| **CVE-2023-33106/33107** | 2023 | Qualcomm Adreno GPU | Multiple | Unknown | Android zero-days |
| **CVE-2022-22706** | 2022 | ARM Mali GPU | UAF | Unknown | Android zero-day |
| **CVE-2022-0185** | 2022 | Filesystem Context | Heap overflow | Unknown | CISA KEV; container escape |
| **CVE-2022-2588** | 2022 | net_sched (cls_route) | UAF/Double-free | Unknown | KernelCTF; real-world exploitation |
| **CVE-2021-22555** | 2021 | Netfilter (x_tables) | OOB write | Unknown | First public KernelCTF exploit |
| **CVE-2021-1048** | 2021 | epoll/binder | UAF | Spyware vendor | Android in-the-wild |
| **CVE-2021-0920** | 2021 | Unix GC (SCM_RIGHTS) | UAF/Race | Spyware vendor | Android zero-day chain |
| **CVE-2020-16010** | 2020 | Android (Freetype) | Heap buffer overflow | Unknown | Chrome on Android chain |
| **CVE-2019-2215** | 2019 | Binder | UAF | NSO Group (Pegasus) | Android zero-day; the "Bad Binder" |
| **CVE-2016-5195** | 2016 | mm (CoW) | Race condition | Multiple actors | "Dirty COW" — years of exploitation |

### 3.2 Notable CTF and KernelCTF Exploits

Google's **KernelCTF** program (launched 2023) has become the premier venue for kernel exploitation research. Notable submissions include:

| CVE | Researcher | Target | Bounty | Technique |
|-----|-----------|--------|--------|-----------|
| CVE-2024-1086 | notselwyn | Mitigation + LTS + Debian | $112K+ | Dirty Pagedirectory |
| CVE-2023-3390 | SSD Labs | LTS | $31,337 | nf_tables UAF |
| CVE-2023-3776 | lonial con | LTS | $31,337 | cls_fw UAF |
| CVE-2023-4622 | SSD Labs | LTS | $31,337 | Unix socket UAF |
| CVE-2023-5345 | ChengYueqi | LTS + Mitigation | $63,337 | SMB client OOB |
| CVE-2022-2588 | Zhenpeng Lin | COS | ~$42K | cls_route double-free |
| CVE-2021-22555 | Andy Nguyen | LTS | N/A (pre-program) | Netfilter heap overflow |

**CTF Competition Trends:** Major CTF competitions (DEF CON, HITCON, 0CTF, Pwn2Own) have increasingly featured kernel exploitation challenges. Common patterns:
- Linux kernel challenges dominate over Windows kernel
- nf_tables and io_uring are the most common modern subsystems targeted
- Data-only / KSMA exploits are now expected at top-tier competitions
- Cross-cache attacks and Dirty Pagetable variants are standard techniques

### 3.3 The Patch Gap Problem

One of the most significant findings from CVE-2019-2215 (Bad Binder) was the "patch gap" — the delay between when a vulnerability is fixed in the upstream Linux kernel and when that fix reaches end-user devices:

- The Binder UAF was found by syzkaller in November 2017
- Patched in upstream Linux 4.14 in February 2018
- **Never flagged as a security vulnerability** — no CVE assigned
- Remained unpatched in Android devices (Pixel 1, Pixel 2) until October 2019
- During that ~20-month gap, it was weaponized by NSO Group for Pegasus spyware

This pattern continues to repeat: security-relevant patches in the upstream kernel are often not backported to stable/LTS branches or vendor kernels because they are not identified as security fixes. The Linux kernel CNA's assignment of CVEs to every potential security-relevant fix (starting 2024) was partially motivated by this problem.

---

## 4. Android Kernel Exploits

**Binder, ION/DMA-BUF, and the Mobile Attack Surface**

### 4.1 The Android Kernel Threat Model

Android's kernel is derived from the upstream Linux kernel but includes significant modifications:
- **Binder IPC** — Android's inter-process communication mechanism (replaces traditional Unix IPC)
- **ION memory allocator** (deprecated) / **DMA-BUF heaps** (replacement) — shared memory management
- **Vendor-specific drivers** — Qualcomm, MediaTek, Samsung, ARM Mali GPU drivers
- **SELinux policies** — Mandatory Access Control (MAC) enforcement
- **seccomp-BPF** — System call filtering for app sandboxing

The attack surface is much larger than desktop Linux due to:
1. Vendor driver code (often lower quality than upstream)
2. Longer patch cycles (monthly security bulletins vs. continuous upstream releases)
3. Device fragmentation (hundreds of OEMs with varying update cadences)
4. User-facing attack surface through the browser and app sandbox

### 4.2 Binder: The Crown Jewel of Android Exploitation

Binder (`drivers/android/binder.c`) is Android's custom IPC mechanism. It is unique in that:
- **Every Android app interacts with Binder** — it is the fundamental IPC mechanism
- It is reachable from every app sandbox (including Chrome's renderer)
- It manages complex object lifecycle across process boundaries
- It implements its own memory management (mmap-based buffer sharing)

#### CVE-2019-2215: Bad Binder — A Case Study in In-the-Wild Exploitation

**Discovery:** Google TAG received intelligence that NSO Group's Pegasus spyware was using an Android kernel zero-day. Based on specific technical details (UAF in kernel, reachable from Chrome sandbox, works on Pixel 1/2 but not Pixel 3, patched in Linux >= 4.14 without CVE, CONFIG_DEBUG_LIST breaks the primitive), Project Zero researcher Maddie Stone narrowed it down to a single Binder commit.

**The Bug:** A use-after-free in the Binder driver where `binder_thread->wait` (a `wait_queue_head_t`) is freed when a binder thread exits via `BINDER_THREAD_EXIT` ioctl, but epoll still holds a reference to the wait queue.

**Trigger:**
```c
fd = open("/dev/binder", O_RDONLY);
epfd = epoll_create(1000);
epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event);
ioctl(fd, BINDER_THREAD_EXIT, NULL);  // Free binder_thread including wait queue
// epoll still references the freed wait queue — UAF
```

**Exploitation (Project Zero PoC):**
1. Trigger UAF to free `binder_thread` (408 bytes)
2. Reallocate the freed memory with an `iovec` array (25 entries = 400 bytes, close enough for same slab)
3. The `wait.task_list` (at offset 0xA8 in `binder_thread`) overlaps with `iovec[10].iov_len` and `iovec[11].iov_base`
4. `ep_remove_wait_queue` performs `list_del` on the freed wait queue, overwriting `iovec[11].iov_base` with a kernel heap pointer
5. **First UAF trigger:** Use `writev` with the corrupted iovec to leak the `task_struct` address
6. **Second UAF trigger:** Use `recvmsg` with the corrupted iovec to overwrite `addr_limit` in the `task_struct`
7. With `addr_limit` raised, the process can read/write arbitrary kernel memory

**Key Properties:**
- Reachable from Chrome sandbox (isolated_app SELinux domain)
- No per-device customization needed
- CONFIG_DEBUG_LIST was the only mitigation that blocked exploitation
- Weaponized as a zero-day by NSO Group before any CVE was assigned

### 4.3 ION and DMA-BUF Heaps

**ION** was Android's custom memory allocator for sharing buffers between hardware components (GPU, camera, display, codec). It was deprecated in Linux 5.6+ and replaced by **DMA-BUF heaps**.

**Why ION/DMA-BUF is a critical attack surface:**
- Manages physical memory directly (page allocation, cache management)
- Bridges userspace, kernel, and hardware device drivers
- Complex reference counting and lifetime management
- Accessible from within app sandboxes through graphics/media APIs

**Notable ION/DMA-BUF vulnerabilities:**
- **CVE-2019-2024:** ION reference count issue allowing page UAF
- **CVE-2023-2008:** udmabuf fault handler OOB (discussed in Section 2)
- Multiple Qualcomm ION heap vulnerabilities used in Android exploit chains

### 4.4 GPU Drivers: The New Frontier

ARM Mali and Qualcomm Adreno GPU drivers have become the most prolific source of Android kernel zero-days:

| CVE | Driver | Year | Bug Class | Status |
|-----|--------|------|-----------|--------|
| CVE-2023-4211 | ARM Mali | 2023 | UAF | In-the-wild zero-day |
| CVE-2023-33106 | Qualcomm Adreno | 2023 | Unknown | In-the-wild zero-day |
| CVE-2023-33107 | Qualcomm Adreno | 2023 | Integer overflow | In-the-wild zero-day |
| CVE-2022-22706 | ARM Mali | 2022 | Improper access | In-the-wild zero-day |
| CVE-2022-46395 | ARM Mali | 2022 | UAF | In-the-wild zero-day |
| CVE-2021-39793 | ARM Mali | 2021 | OOB write | In-the-wild zero-day |

GPU drivers are attractive targets because:
1. They are reachable from app sandboxes (every app that renders graphics)
2. They manage shared memory directly
3. They are maintained by hardware vendors, not the upstream kernel community
4. They have complex state machines for command submission and synchronization
5. They often bypass standard kernel memory management abstractions

---

## 5. Container Escape Exploits via Kernel Vulnerabilities

### 5.1 The Container Security Model

Containers (Docker, Kubernetes pods) share the host kernel with other containers. The isolation boundary consists of:
- **Namespaces** (PID, mount, network, user, cgroup, IPC, UTS)
- **cgroups** (resource limits)
- **seccomp-BPF** (system call filtering)
- **Linux Security Modules** (AppArmor, SELinux)
- **Linux capabilities** (fine-grained privilege decomposition)

Since all containers share the same kernel, **any kernel vulnerability that allows privilege escalation also potentially allows container escape.** This makes kernel vulnerabilities the most critical threat class for containerized environments.

### 5.2 CVE-2022-0185: Filesystem Context Heap Overflow

| Field | Detail |
|-------|--------|
| **CVE** | CVE-2022-0185 |
| **CVSS** | 8.4 HIGH (AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **Affected Versions** | Linux v5.1 through v5.16.1 |
| **Subsystem** | Filesystem Context (VFS) |
| **Bug Class** | Integer underflow leading to heap-based buffer overflow |
| **CISA KEV** | Added 2024-08-21 |

**Root Cause:** The `legacy_parse_param()` function in the Filesystem Context API has an integer underflow when calculating the buffer length for legacy filesystem parameter parsing. When a filesystem does not support the new Filesystem Context API and falls back to legacy handling, user-supplied parameter lengths are validated incorrectly.

The integer underflow occurs in the length calculation:
```c
// Simplified vulnerable logic
if (len > PAGE_SIZE - 2 - size)  // Underflow when size > PAGE_SIZE - 2
    return -ENOMEM;
```

When `size` exceeds `PAGE_SIZE - 2`, the subtraction wraps around to a large positive value, bypassing the bounds check and allowing a heap buffer overflow.

**Container Escape Exploitation:**

1. **Prerequisite:** The attacker needs `CAP_SYS_ADMIN` in their current namespace. In standard Docker, this is not granted. However, the attacker can use `unshare(CLONE_NEWNS|CLONE_NEWUSER)` to create a new namespace where they have `CAP_SYS_ADMIN`.

2. **The Kubernetes Problem:** In Kubernetes clusters, Docker's seccomp filter (which blocks `unshare`) is **disabled by default**. This means any pod in a default Kubernetes deployment can exploit CVE-2022-0185.

3. **Exploitation Flow:**
   - Create a new user namespace (via `unshare`) to gain `CAP_SYS_ADMIN`
   - Open a filesystem that uses the legacy parameter handling path
   - Pass crafted parameters that trigger the integer underflow
   - The resulting heap overflow corrupts adjacent kernel objects
   - Leverage the corruption for arbitrary code execution in kernel context
   - Escape the container by manipulating namespace-related kernel structures

**Mitigation Hierarchy:**
- **Best:** Patch the kernel immediately
- **Good:** Apply seccomp profiles that block `unshare` (the Docker default)
- **Acceptable:** Use PodSecurityPolicy (deprecated) or Pod Security Standards to enforce seccomp profiles in Kubernetes
- **Temporary:** Disable user namespaces: `sysctl -w kernel.unprivileged_userns_clone=0`

### 5.3 CVE-2022-0811: cr8escape — CRI-O Container Engine Escape

This vulnerability, discovered by CrowdStrike, demonstrates that container escapes can come from the container runtime itself, not just the kernel.

**Root Cause:** CRI-O version 1.19+ uses the `pinns` utility to set kernel sysctl parameters for pods. The sysctl value parsing uses `+` as a delimiter between multiple sysctl settings but does not sanitize the value field. An attacker can inject additional sysctl settings through a crafted value:

```yaml
securityContext:
  sysctls:
  - name: kernel.shm_rmid_forced
    value: "1+kernel.core_pattern=|/path/to/malicious_script #"
```

This sets both `kernel.shm_rmid_forced=1` (valid, whitelisted) and `kernel.core_pattern=|/path/to/malicious_script` (arbitrary, allows code execution on core dump). By modifying `kernel.core_pattern` to pipe to an attacker-controlled script, triggering a core dump executes the script as root outside any container.

### 5.4 Additional Container Escape CVEs

| CVE | Year | Vector | Description |
|-----|------|--------|-------------|
| CVE-2022-0847 | 2022 | Dirty Pipe | Pipe buffer flag manipulation allows overwriting arbitrary read-only files, including files in container images |
| CVE-2021-31440 | 2021 | eBPF verifier | eBPF program bypass allows kernel code execution, escaping any container |
| CVE-2020-14386 | 2020 | AF_PACKET | Memory corruption in raw sockets allows privilege escalation from container |
| CVE-2019-5736 | 2019 | runc | Container runtime vulnerability allowing host binary overwrite |
| CVE-2022-23222 | 2022 | eBPF | Verifier bypass allowing arbitrary kernel R/W from unprivileged context |

### 5.5 The Fundamental Problem

Container escapes via kernel vulnerabilities expose a fundamental architectural limitation: **containers are not a security boundary.** They rely entirely on the kernel for isolation, and any kernel vulnerability that provides privilege escalation can break that isolation. This is why:

1. **VM-based isolation** (gVisor, Kata Containers, Firecracker) is recommended for multi-tenant environments
2. **Seccomp profiles** should be mandatory, not optional (Kubernetes is moving toward default seccomp)
3. **Kernel hardening** (lockdown mode, reduced syscall surface) is critical for container hosts
4. **Unprivileged user namespaces** remain a contentious feature — they enable exploitation of many kernel vulnerabilities but are also needed for rootless containers

---

## 6. eBPF Verifier Bypass CVEs

### 6.1 The eBPF Verifier: A Complex Security Boundary

eBPF (extended Berkeley Packet Filter) allows userspace programs to run sandboxed code inside the Linux kernel. The **verifier** is the security-critical component that analyzes eBPF programs before execution to ensure:
- No out-of-bounds memory access
- No unbounded loops (guaranteed termination)
- Correct register types and pointer arithmetic
- No information leaks from kernel to userspace

The verifier performs abstract interpretation with value tracking: it maintains a state machine that tracks the possible range of values in each register at every program point. If the verifier determines that all possible execution paths are safe, the program is loaded.

**Why eBPF verifier bugs are critical:**
- A verifier bypass allows an attacker to load a program that performs arbitrary kernel read/write
- eBPF programs run with kernel privileges (ring 0)
- The complexity of the verifier (~20,000+ lines of code) makes it a rich bug surface
- Until 2020, unprivileged users could load eBPF programs on most distributions (this has since been restricted)

### 6.2 Notable eBPF Verifier CVEs

#### CVE-2021-3490: ALU32 Bounds Tracking Bypass

| Field | Detail |
|-------|--------|
| **CVSS** | 7.8 HIGH |
| **Affected** | Linux v5.7-rc1 through v5.12.3 |
| **Bug Class** | Incorrect 32-bit bounds tracking for bitwise operations |

**Root Cause:** The eBPF verifier's ALU32 bounds tracking for bitwise operations (AND, OR, XOR) did not properly update 32-bit bounds. When performing 32-bit bitwise operations, the verifier tracked the 64-bit bounds correctly but failed to narrow the 32-bit sub-register bounds.

**Exploitation:** An attacker crafts an eBPF program that performs a sequence of ALU32 operations that cause the verifier to believe a register value is within bounds, while at runtime the actual value is out of bounds. This allows:
1. Out-of-bounds map element access (read/write past the end of an eBPF map)
2. Arbitrary kernel memory read/write by using the OOB access to corrupt a map's ops pointer or adjacent kernel objects
3. Privilege escalation by overwriting `modprobe_path` or `cred` structures

#### CVE-2021-31440: eBPF ALU Bounds Propagation

| Field | Detail |
|-------|--------|
| **CVSS** | 7.0-8.8 HIGH |
| **Affected** | Linux v5.7 through v5.12.3 |
| **Bug Class** | Incorrect calculation in bounds propagation |

**Root Cause:** The verifier's bounds tracking for ALU operations failed to properly validate user-supplied eBPF programs. The specific flaw was in how bounds were propagated through arithmetic operations, allowing the verifier to compute incorrect safe ranges.

**Reported via:** Zero Day Initiative (ZDI-21-503)

#### CVE-2022-23222: Pointer Arithmetic Verifier Bypass

| Field | Detail |
|-------|--------|
| **Affected** | Linux v5.8 through v5.16 |
| **Bug Class** | NULL pointer dereference + OOB via verifier confusion |

**Root Cause:** The verifier allowed certain pointer arithmetic operations that could result in a pointer with a verifier-tracked value of NULL (PTR_TO_MEM with offset 0) that at runtime pointed to a valid kernel address. This allowed:
1. Arbitrary kernel read/write from an unprivileged eBPF program
2. The exploit could map page 0 (on systems without `mmap_min_addr` protection) and use the NULL pointer as an arbitrary read/write primitive

#### CVE-2023-2163: Verifier Precision Tracking Bypass

| Field | Detail |
|-------|--------|
| **Affected** | Linux v5.4 through v6.6 |
| **Bug Class** | Logic error in precision back-propagation |

**Root Cause:** A logic error in the verifier's precision back-propagation for conditional jumps allowed crafted programs to bypass bounds checks. The verifier failed to properly mark certain registers as needing precise tracking in specific conditional branch scenarios.

### 6.3 The Pattern of eBPF Verifier Bugs

| Year | CVE Count (notable) | Bug Pattern |
|------|---------------------|-------------|
| 2020 | 3 | 32-bit truncation, ALU bounds |
| 2021 | 6+ | ALU32, pointer arithmetic, type confusion |
| 2022 | 4+ | Pointer arithmetic, speculative execution |
| 2023 | 3+ | Precision tracking, callback verification |
| 2024 | 2+ | JIT compilation, register spilling |
| 2025-26 | Ongoing | Complex value tracking edge cases |

**Recurring themes:**
1. **32-bit vs. 64-bit tracking mismatches** — The verifier must track both 32-bit and 64-bit views of each register, and discrepancies between them are a common bug class
2. **Abstract domain precision** — The verifier uses range-based abstract domains (min/max for signed and unsigned values), and precision loss during operations creates exploitable gaps
3. **Conditional branch handling** — The verifier explores both branches of conditionals and must correctly narrow register ranges in each branch; errors here allow "impossible" states at runtime
4. **JIT compilation mismatches** — The verifier validates the eBPF bytecode, but the JIT compiler may generate machine code with subtly different semantics

### 6.4 Mitigation: Restricting Unprivileged eBPF

Most distributions now set `kernel.unprivileged_bpf_disabled=1` by default (or use `kernel.unprivileged_bpf_disabled=2` for permanent disabling). This is the single most effective mitigation against eBPF verifier bugs, as it restricts eBPF program loading to `CAP_BPF` or `CAP_SYS_ADMIN` holders.

However, this does not eliminate the risk entirely:
- Container runtimes may grant `CAP_BPF` to workloads
- eBPF is increasingly used for observability (Cilium, Falco, bpftrace) and networking, expanding the set of privileged processes that load eBPF programs
- A compromised privileged process (e.g., through a supply chain attack on an eBPF-based tool) can still exploit verifier bugs

---

## 7. Trends in Kernel Vulnerability Discovery (2020-2026)

### 7.1 Vulnerability Volume and Sources

| Year | Estimated Kernel CVEs | Dominant Discovery Methods |
|------|----------------------|---------------------------|
| 2020 | ~300 | Syzkaller, manual audit, variant analysis |
| 2021 | ~400 | Syzkaller, eBPF fuzzing, nf_tables audit |
| 2022 | ~450 | Syzkaller, KernelCTF launch, vendor bug bounties |
| 2023 | ~500 | Syzkaller, KernelCTF maturation, AI-assisted analysis |
| 2024 | ~1000+ | Linux kernel CNA mass-CVE assignment; KernelCTF expansion |
| 2025-26 | ~1500+ | Continued CNA assignment; automated discovery at scale |

**Note:** The dramatic increase in 2024+ reflects the Linux kernel's decision to become its own CVE Numbering Authority (CNA) and assign CVEs to all potentially security-relevant fixes, regardless of whether an exploit is known. This changes the semantics of CVE counts — the raw number no longer indicates increased vulnerability, but rather increased transparency.

### 7.2 Subsystem Hotspots

| Subsystem | Trend (2020-2026) | Key Bug Classes |
|-----------|-------------------|-----------------|
| **Netfilter / nf_tables** | Persistent high severity | UAF, double-free, OOB write |
| **eBPF verifier** | Declining (restrictions) | Bounds tracking, type confusion |
| **io_uring** | Explosive growth (2021-2024) | UAF, race conditions, double-free |
| **Network stack** | Steady | UAF, buffer overflows, race conditions |
| **Filesystem / VFS** | Steady | Integer overflows, logic errors |
| **GPU drivers** | Rapidly increasing | UAF, OOB, command injection |
| **Bluetooth / WiFi** | Increasing | Remote code execution, OOB |
| **USB subsystem** | Steady | OOB, UAF (physical access or USBIP) |
| **DMA-BUF / memory management** | Increasing | Improper validation, race conditions |

### 7.3 The Rise of io_uring

`io_uring` deserves special mention as the newest major attack surface in the Linux kernel. Introduced in Linux 5.1 (2019), it provides high-performance asynchronous I/O but has rapidly accumulated security vulnerabilities:

- Its complexity rivals that of the Netfilter subsystem
- It implements its own parallel code paths for many system calls
- It has been the subject of multiple container escape demonstrations
- Google's ChromeOS and Android have considered disabling it entirely
- Multiple io_uring CVEs have appeared in KernelCTF submissions

### 7.4 Fuzzing at Scale: Syzkaller's Dominance

Google's **syzkaller** (system call fuzzer) is responsible for discovering the majority of kernel vulnerabilities since its introduction:
- It generates syntactically valid sequences of system calls
- It uses coverage-guided feedback to explore new kernel code paths
- It operates continuously on Google's infrastructure (~hundreds of VMs)
- It has found thousands of bugs since 2015
- Many security-critical bugs (including the original Binder UAF) were found by syzkaller but not initially recognized as security vulnerabilities

### 7.5 The Linux Kernel CNA Decision (2024)

In early 2024, the Linux kernel community became its own CVE Numbering Authority. The decision to assign CVEs to all potentially security-relevant fixes was controversial:
- **Pro:** Closes the "patch gap" where security fixes go unrecognized and unbackported
- **Pro:** Forces vendors to track all kernel fixes, not just those with CVEs
- **Con:** Dramatically inflates CVE counts, potentially causing "alert fatigue"
- **Con:** Many assigned CVEs have minimal or no security impact
- **Impact:** Vendors can no longer rely on CVE lists alone; they must evaluate all kernel commits

---

## 8. Comparison of Kernel Exploit Complexity Over the Years

### 8.1 Evolution of Exploitation Difficulty

| Era | Period | Typical Exploit | Mitigations | Effort |
|-----|--------|----------------|-------------|--------|
| **Classic** | Pre-2010 | Direct stack/heap overflow to shellcode | None or minimal | Low |
| **SMEP/SMAP** | 2012-2016 | ROP chains, ret2usr with SMEP bypass | SMEP, KASLR (weak) | Medium |
| **KPTI/Modern** | 2017-2020 | Heap spray + ROP + KPTI bypass | KPTI, KASLR, SMAP, SMEP | High |
| **Post-CFI** | 2021-2024 | Data-only attacks, KSMA, Dirty Pagetable | CFI, KCFI, freelist randomization | Very High |
| **Hardened** | 2024+ | Data-only + novel primitives + race conditions | All above + CONFIG_LIST_HARDENED, RANDSTRUCT, etc. | Extreme |

### 8.2 The Arms Race in Detail

**Mitigation Timeline:**

| Year | Mitigation | Impact on Exploitation |
|------|-----------|----------------------|
| 2012 | SMEP (Supervisor Mode Execution Prevention) | Blocks executing userspace pages in kernel mode |
| 2014 | KASLR (Kernel Address Space Layout Randomization) | Randomizes kernel text base address |
| 2014 | SMAP (Supervisor Mode Access Prevention) | Blocks accessing userspace memory in kernel mode |
| 2017 | KPTI (Kernel Page Table Isolation) | Separates user/kernel page tables (Meltdown mitigation) |
| 2018 | Freelist randomization (SLAB_FREELIST_RANDOM) | Randomizes slab allocator freelist order |
| 2019 | Freelist hardening (SLAB_FREELIST_HARDENED) | Encrypts slab freelist pointers |
| 2020 | init_on_alloc / init_on_free | Zeroes memory on allocation/free |
| 2022 | KCFI (Kernel Control Flow Integrity) | Forward-edge CFI for indirect calls |
| 2023 | CONFIG_LIST_HARDENED | Integrity checks on doubly-linked list operations |
| 2024 | RANDSTRUCT (structure layout randomization) | Randomizes kernel structure field ordering |
| 2024+ | Shadow stacks, MTE (ARM), guarded control stacks | Hardware-assisted backward-edge CFI |

**Attacker Adaptations:**

| Period | Technique | Purpose |
|--------|----------|---------|
| 2012-2016 | ret2usr, physmap spray | Bypass SMEP |
| 2016-2018 | Stack pivot + ROP chains | Execute code with SMAP/SMEP |
| 2018-2020 | msg_msg spray, pipe_buffer spray | Flexible heap primitive construction |
| 2020-2022 | Cross-cache attacks | Bypass slab-level mitigations |
| 2022-2024 | Dirty Pagetable / Dirty Pagedirectory | Data-only KSMA, bypass CFI |
| 2024+ | PCP draining, page-level primitives | Bypass per-CPU page allocator isolation |

### 8.3 The Data-Only Revolution

The most significant trend in modern kernel exploitation is the shift to **data-only attacks**. These attacks:
- Never corrupt code pointers (function pointers, return addresses)
- Bypass KCFI, shadow stacks, and all code-pointer integrity mitigations
- Operate entirely through modifying data values (`modprobe_path`, `addr_limit`, cred structures, page table entries)
- Are harder to detect because they don't trigger control-flow integrity violations

CVE-2024-1086's Dirty Pagedirectory technique exemplifies this: the entire exploit, from initial corruption to root shell, never overwrites a single code pointer.

### 8.4 Reliability and Success Rates

Modern exploits are remarkably reliable compared to earlier generations:

| Era | Typical Success Rate | Stability Method |
|-----|---------------------|-----------------|
| 2010-2015 | 10-50% | Trial and error, simple heap sprays |
| 2015-2019 | 50-80% | MSG_MSG spraying, controlled allocations |
| 2020-2024 | 90-99%+ | Cross-cache attacks, deterministic primitives, CPU-local exploitation |

CVE-2024-1086 achieved 99.4% success rate (n=1000) — a testament to the sophistication of modern heap manipulation techniques.

---

## 9. The Role of Kernel Vulnerabilities in Privilege Escalation Chains

### 9.1 Kernel Vulns as the Keystone

In modern attack chains, kernel vulnerabilities typically serve as the **privilege escalation** or **sandbox escape** component. They are rarely used in isolation but rather as one link in a multi-stage chain:

```
[Remote Code Execution] → [Sandbox Escape] → [Kernel LPE] → [Persistence]
     (Browser, App)        (Renderer escape)   (root/kernel)   (Rootkit)
```

**Typical Chain on Android:**
1. **Browser exploit** (V8/WebKit vulnerability) → code execution in renderer process
2. **Sandbox escape** → escape from Chrome/WebView sandbox
3. **Kernel exploit** (Binder, GPU driver, etc.) → full device compromise
4. **Persistence** → install spyware (Pegasus, Predator, etc.)

**Typical Chain on Linux Server (Container):**
1. **Application vulnerability** (web app, API) → code execution in container
2. **Container escape** (kernel vuln + namespace/seccomp bypass) → host access
3. **Kernel privilege escalation** → root on host
4. **Lateral movement** → access other containers, nodes, and cluster secrets

### 9.2 Zero-Click Attack Chains

The highest-value attack chains require no user interaction ("zero-click"). Kernel vulnerabilities play a critical role:

| Attack | Chain | Kernel Component |
|--------|-------|-----------------|
| **NSO Pegasus** (2019-2023) | iMessage/WhatsApp exploit → sandbox escape → kernel LPE | Binder UAF, ION, GPU drivers |
| **Intellexa Predator** (2023) | Chrome/Android exploit chain | Multiple Android kernel 0-days |
| **Operation Triangulation** (2023, iOS) | iMessage → kernel exploit → hardware backdoor | XNU kernel vulnerability |

### 9.3 The Exploit Broker Market

Kernel exploits command the highest prices in the vulnerability market because they are the critical enabler for full device compromise:

| Exploit Type | Approximate Market Value (2024) |
|-------------|--------------------------------|
| Android full chain (zero-click, persistence) | $2.5M - $5M+ |
| iOS full chain (zero-click, persistence) | $2M - $5M+ |
| Linux kernel LPE (universal) | $150K - $500K |
| Chrome + kernel full chain (Android) | $1M - $3M |
| Container escape (Kubernetes) | $100K - $300K |

These prices reflect the strategic value of kernel vulnerabilities: they are the key that unlocks the highest privilege level on any system.

### 9.4 Defense-in-Depth Implications

The role of kernel vulnerabilities in attack chains has driven specific defensive strategies:

1. **Reduce kernel attack surface:**
   - Disable unused kernel modules (`CONFIG_TRIM_UNUSED_KSYMS`)
   - Restrict unprivileged access to dangerous subsystems (eBPF, user namespaces, io_uring)
   - Use seccomp-BPF to limit available system calls

2. **Harden the kernel:**
   - Enable all available mitigations (SMAP, SMEP, KPTI, KCFI, init_on_alloc/free)
   - Use lockdown mode to prevent runtime kernel modifications
   - Deploy hardened allocators (SLAB_FREELIST_RANDOM, SLAB_FREELIST_HARDENED)

3. **Minimize the blast radius:**
   - Use VM-based isolation for untrusted workloads (gVisor, Kata Containers)
   - Implement mandatory access control (SELinux, AppArmor) to limit what kernel compromise achieves
   - Deploy runtime security monitoring (Falco, Tracee, Tetragon) to detect exploitation attempts

4. **Close the patch gap:**
   - Track all upstream kernel commits, not just CVEs
   - Automate kernel update deployment
   - Use live-patching (kpatch, livepatch) for critical fixes without reboots

---

## 10. References

### Primary Sources

1. notselwyn. "Flipping Pages: An analysis of a new Linux vulnerability in nf_tables and hardened exploitation techniques." pwning.tech, March 2024. https://pwning.tech/nftables/
2. NIST NVD. "CVE-2024-1086." https://nvd.nist.gov/vuln/detail/CVE-2024-1086
3. NIST NVD. "CVE-2023-2008." https://nvd.nist.gov/vuln/detail/CVE-2023-2008
4. NIST NVD. "CVE-2022-0185." https://nvd.nist.gov/vuln/detail/CVE-2022-0185
5. NIST NVD. "CVE-2021-3490." https://nvd.nist.gov/vuln/detail/CVE-2021-3490
6. NIST NVD. "CVE-2021-31440." https://nvd.nist.gov/vuln/detail/CVE-2021-31440
7. Maddie Stone, Project Zero. "Bad Binder: Android In-The-Wild Exploit." November 2019. https://googleprojectzero.blogspot.com/2019/11/bad-binder-android-in-wild-exploit.html
8. Aqua Security. "CVE-2022-0185 in Linux Kernel Can Allow Container Escape in Kubernetes." January 2022. https://blog.aquasec.com/cve-2022-0185-linux-kernel-container-escape-in-kubernetes
9. CrowdStrike. "cr8escape: New Vulnerability in CRI-O Container Engine (CVE-2022-0811)." March 2022. https://www.crowdstrike.com/blog/cr8escape-new-vulnerability-discovered-in-cri-o-container-engine-cve-2022-0811/
10. Notselwyn. "CVE-2024-1086 PoC Repository." GitHub. https://github.com/Notselwyn/CVE-2024-1086

### Kernel Patches and Commits

11. nf_tables fix: commit `f342de4e2f33e0e39165d8639387aa6c19dff660`
12. udmabuf fix: commit `05b252cccb2e5c3f56119d25de684b4f810ba4`
13. CVE-2022-0185 fix: commit `722d94847de2`
14. CVE-2021-3490 fix: commit `049c4e13714ecbca567b4d5f6d563f05d431c80e`
15. CVE-2021-31440 fix: commit `10bf4e83167cc68595b85fd73bb91e8f2c086e36`
16. Binder UAF fix (original): commit `550c01d0e051461437d6e9d72f573759e7bc5047`

### Research Papers and Techniques

17. Yanglingxi (N. Wu). "Dirty Pagetable: A Novel Exploitation Technique To Rule Linux Kernel." https://yanglingxi1993.github.io/dirty_pagetable/dirty_pagetable.html
18. pqlqpql (D. Bouman). "How The Tables Have Turned: An analysis of two new Linux vulnerabilities in nf_tables." April 2022. https://blog.dbouman.nl/2022/04/02/How-The-Tables-Have-Turned-CVE-2022-1015-1016/
19. Smallkirby. "modprobe_path exploitation technique." https://github.com/smallkirby/kernelpwn/blob/master/technique/modprobe_path.md
20. Google. "KernelCTF rules." https://google.github.io/security-research/kernelctf/rules.html
21. Crusaders of Rust. "CVE-2022-0185 Exploit." https://github.com/Crusaders-of-Rust/CVE-2022-0185
22. willsroot. "CVE-2022-0185 Write-up." https://www.willsroot.io/2022/01/cve-2022-0185.html
23. DiShen. "The Art of Exploiting Unconventional Use-after-free Bugs in Android Kernel." Code Blue 2017.

### CISA Known Exploited Vulnerabilities

24. CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
25. CVE-2024-1086 added 2024-05-30 (due 2024-06-20)
26. CVE-2022-0185 added 2024-08-21 (due 2024-09-11)

---

*Last updated: April 2026. This document covers publicly disclosed vulnerabilities and exploitation techniques for educational and defensive security purposes.*

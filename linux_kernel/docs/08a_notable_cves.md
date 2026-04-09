# Chapter 8a: Notable CVEs & Case Studies

## Classic and High-Impact Linux Kernel Vulnerabilities

This chapter provides detailed case studies of some of the most significant Linux kernel vulnerabilities discovered between 2016 and 2024. Each entry covers the vulnerability description, root cause analysis, exploitation technique, real-world impact, and the applied fix. Together, these cases illustrate recurring vulnerability classes---race conditions, use-after-free, type confusion, integer overflows, and uninitialized memory---and how they manifest in different kernel subsystems.

---

## Table of Contents

1. [Dirty COW (CVE-2016-5195)](#1-dirty-cow-cve-2016-5195)
2. [Dirty Pipe (CVE-2022-0847)](#2-dirty-pipe-cve-2022-0847)
3. [Dirty Cred (2022)](#3-dirty-cred-2022)
4. [Sequoia (CVE-2021-33909)](#4-sequoia-cve-2021-33909)
5. [Looney Tunables (CVE-2023-4911)](#5-looney-tunables-cve-2023-4911)
6. [nf_tables Vulnerabilities (CVE-2023-32233, CVE-2024-1086)](#6-nf_tables-vulnerabilities)
7. [io_uring Vulnerabilities](#7-io_uring-vulnerabilities)
8. [StackRot (CVE-2023-3269)](#8-stackrot-cve-2023-3269)

---

## 1. Dirty COW (CVE-2016-5195)

**Subsystem:** Memory Management (Copy-on-Write)
**Affected Versions:** Linux 2.6.22 (2007) through 4.8.3 (October 2016)
**CVSS Score:** 7.8 (High)
**Discoverer:** Phil Oester
**Exploited in the wild:** Yes

### 1.1 Vulnerability Description

Dirty COW (Copy-On-Write) is a privilege escalation vulnerability in the Linux kernel's memory management subsystem. The bug is a race condition in how the kernel handles copy-on-write (COW) breakage of private read-only memory mappings. An unprivileged local user could exploit this flaw to gain write access to otherwise read-only memory mappings and thus escalate privileges.

The name "Dirty COW" is a play on the kernel's copy-on-write mechanism. When a process maps a file read-only via `mmap()` with `MAP_PRIVATE`, the kernel creates a private copy of the page when the process attempts to write to it (this is the COW mechanism). The vulnerability allowed an attacker to bypass this mechanism and write directly to the underlying file's page cache.

### 1.2 Root Cause

The root cause is a race condition between two operations in the kernel's page fault handler and the `madvise()` system call:

1. **`madvise(MADV_DONTNEED)`**: This call advises the kernel that the application no longer needs a specific memory range, causing the kernel to discard the private COW copy of the page.

2. **`write()` to `/proc/self/mem`**: Writing to this pseudo-file triggers a page fault that forces the kernel to resolve the mapping. The write goes through `get_user_pages()` with the `FOLL_WRITE` flag.

The race condition occurs in the `follow_page_mask()` / `get_user_pages()` code path. The sequence is:

```
Thread A (writer):                    Thread B (madvise):
-----------------                     -------------------
get_user_pages(FOLL_WRITE)
  follow_page_mask()
    -> page fault, COW break
    -> creates private copy
  retry with FOLL_WRITE
    -> finds private copy           madvise(MADV_DONTNEED)
                                      -> discards private copy
                                      -> restores original mapping
  retry (FOLL_WRITE dropped)
    -> follows original mapping
    -> writes to original page!
```

The critical issue is that after the COW break and the `MADV_DONTNEED`, the kernel retries the page lookup without the `FOLL_WRITE` flag (since the COW break already occurred). However, `MADV_DONTNEED` discarded the private page in between, reverting the mapping to the original read-only file page. The subsequent write then goes to the *original* file-backed page in the page cache rather than the discarded private copy.

The bug existed in the kernel since version 2.6.22 (2007)---nearly a decade before its discovery.

### 1.3 Exploitation Technique

The exploitation is straightforward and highly reliable:

1. **Setup:** The attacker opens a read-only file (e.g., `/etc/passwd`, a SUID binary) and maps it with `mmap(MAP_PRIVATE)`.

2. **Race Threads:** Two threads race against each other:
   - **Thread 1** repeatedly calls `write()` on `/proc/self/mem` at the target offset.
   - **Thread 2** repeatedly calls `madvise(addr, len, MADV_DONTNEED)` on the mapped region.

3. **Winning the Race:** When the timing aligns, `Thread 2`'s `MADV_DONTNEED` discards the private COW page after the COW break but before the final write. The kernel then writes attacker-controlled data to the original page cache.

4. **Privilege Escalation:** Common attack vectors include:
   - Modifying `/etc/passwd` to add a root user or remove root's password hash.
   - Overwriting a SUID binary with a custom payload.
   - Patching a running process's executable to inject shellcode.

Multiple proof-of-concept exploits were published, including variants for Android devices (which were particularly vulnerable due to slow patching cycles).

### 1.4 Impact

Dirty COW was one of the most impactful Linux kernel vulnerabilities ever discovered:

- **Universal:** Affected virtually every Linux distribution and Android device running kernels from 2007 to October 2016.
- **Exploited in the wild:** Evidence of active exploitation was found before the public disclosure (captured from HTTP packet analysis by Phil Oester).
- **Reliable:** The race condition is easy to win; typical exploitation takes seconds.
- **Stealthy:** Exploitation does not leave abnormal entries in system logs.
- **Android impact:** Android devices were especially vulnerable due to delayed kernel updates, and the bug was used in Android rooting tools.

### 1.5 Fix

The fix was committed by Linus Torvalds on October 18, 2016:

**Commit:** `19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619`

The fix introduces a new GUP (Get User Pages) flag `FOLL_COW` that ensures the kernel does not follow the original page mapping after a COW break has been reverted. Specifically, when retrying after a COW break, the code now verifies that the page is actually the private dirty copy (i.e., the COW page is still present and marked dirty). If it is not, the operation fails rather than writing to the original page:

```c
if ((flags & FOLL_COW) && pte_dirty(pte))
    // Safe to proceed - we have the dirty COW copy
else
    // Not safe - COW page was reclaimed
```

This ensures that even if `MADV_DONTNEED` discards the COW page, the kernel will not inadvertently write to the underlying read-only file page.

---

## 2. Dirty Pipe (CVE-2022-0847)

**Subsystem:** Pipe / Page Cache
**Affected Versions:** Linux 5.8 through 5.16.10, 5.15.24, 5.10.101
**CVSS Score:** 7.8 (High)
**Discoverer:** Max Kellermann (CM4all / IONOS SE)
**Exploited in the wild:** Not confirmed prior to disclosure

### 2.1 Vulnerability Description

Dirty Pipe is a vulnerability that allows overwriting data in arbitrary read-only files through the Linux pipe mechanism. Similar to Dirty COW in its effect (writing to read-only files), Dirty Pipe is considerably easier to exploit: it is deterministic, requires no race condition, and works at an almost arbitrary file offset.

The vulnerability was discovered through a real-world debugging investigation. Max Kellermann noticed that gzip-compressed log files on a server were intermittently being corrupted. After months of investigation, he traced the corruption to an interaction between `splice()` (which creates pipe buffers pointing into the page cache) and `write()` (which appends data to the pipe). The ZIP central directory header bytes ("PK") from an HTTP response were bleeding into the log files on disk.

### 2.2 Root Cause

The root cause is an **uninitialized `flags` field** in `struct pipe_buffer` when the pipe buffer is created by `splice()` to reference a page cache page.

The vulnerability is the result of two separate commits converging:

1. **Commit `241699cd72a8` (Linux 4.9, 2016):** Added `copy_page_to_iter_pipe()` and `push_pipe()`, which allocate new `struct pipe_buffer` entries but **fail to initialize the `flags` member**.

2. **Commit `f6dd975583bd` (Linux 5.8, 2020):** Changed how pipe buffer mergeability is determined. Previously, the kernel used a pointer comparison against `anon_pipe_buf_ops` to decide if data could be appended to an existing pipe buffer. This commit replaced that check with a per-buffer flag: `PIPE_BUF_FLAG_CAN_MERGE`. This flag is set for anonymous pipe buffers (where appending is safe) but should never be set for page-cache-backed buffers.

Because `copy_page_to_iter_pipe()` did not initialize `flags`, a newly created page-cache pipe buffer could inherit `PIPE_BUF_FLAG_CAN_MERGE` from a previously used (and freed) anonymous pipe buffer in the same ring slot. When a subsequent `write()` to the pipe sees `PIPE_BUF_FLAG_CAN_MERGE` on a page-cache buffer, it appends the new data directly into the page cache page instead of creating a new anonymous buffer.

### 2.3 Exploitation Technique

The exploit is elegant and deterministic:

```
1. Create a pipe.
2. Fill the pipe completely with arbitrary data.
   -> Every pipe_buffer in the ring now has PIPE_BUF_FLAG_CAN_MERGE set.
3. Drain the pipe completely.
   -> All pipe_buffers are freed, but their flags remain initialized
      in the ring slots (the ring is reused, not zeroed).
4. Open the target file O_RDONLY.
5. splice() one byte from the target file into the pipe, starting at
   (target_offset - 1).
   -> A new pipe_buffer is created pointing to the page cache page.
   -> Its flags are NOT initialized, so it inherits PIPE_BUF_FLAG_CAN_MERGE
      from the previous occupant of that ring slot.
6. write() arbitrary data into the pipe.
   -> Because PIPE_BUF_FLAG_CAN_MERGE is set, the write appends data
      directly into the page cache page, overwriting file contents.
```

**Constraints:**
- The attacker needs read permission on the target file (for `splice()`).
- The write offset cannot be on a page boundary (at least 1 byte must be spliced first).
- The write cannot cross a page boundary.
- The file cannot be resized (the page cache manages the file's actual size separately).

**Beyond permissions:** The vulnerability works on:
- Read-only mounted filesystems
- Read-only bind mounts
- Immutable files (`chattr +i`)
- CD-ROM mounts (read-only by nature)

This is because the overwrite occurs in the **page cache** (kernel memory), bypassing all filesystem permission checks. The page cache is always writable by the kernel, and writing to a pipe never checks file permissions.

**Practical exploits** include:
- Overwriting `/etc/passwd` to gain root.
- Patching SUID binaries in the page cache to inject shellcode.
- Modifying `/etc/shadow` or SSH `authorized_keys` files.

### 2.4 Impact

- **Deterministic:** Unlike Dirty COW, no race condition is needed. Exploitation is 100% reliable.
- **Fast:** Exploitation completes in microseconds.
- **Wide scope:** Affected all major Linux distributions running kernels 5.8+, including Android devices running the affected kernel range.
- **Ephemeral by default:** Changes are to the page cache only; they do not persist to disk unless the kernel flushes the dirty page. This means attacks can be stealthy---modifications disappear after reboot or page cache eviction. However, this also means an attacker can trigger writeback to make changes persistent.

### 2.5 Fix

**Commit:** `9d2231c5d74e13b2a0546fee6737ee4446017903`

The fix is a one-line change: explicitly initialize the `flags` field to zero in `copy_page_to_iter_pipe()` and `push_pipe()`:

```c
buf->flags = 0;
```

This ensures that page-cache pipe buffers never have `PIPE_BUF_FLAG_CAN_MERGE` set, preventing writes from merging into page cache pages.

Fixed in stable releases: 5.16.11, 5.15.25, 5.10.102.

---

## 3. Dirty Cred (2022)

**Type:** Exploitation Technique (not a single CVE)
**Presented at:** Black Hat USA 2022, ACM CCS 2022
**Researchers:** Zhenpeng Lin, Yuhang Wu, Xinyu Xing
**Demonstrated with:** CVE-2021-4154, CVE-2022-2588, CVE-2022-20409

### 3.1 Technique Description

Dirty Cred is not a specific vulnerability but rather a **generic kernel exploitation technique** that converts heap vulnerabilities (use-after-free, double-free, etc.) into privilege escalation by swapping unprivileged kernel credentials with privileged ones. The name is a reference to Dirty COW and Dirty Pipe, as the technique achieves a similar outcome (privilege escalation through unauthorized data modification) but operates at the credential object level.

The key insight is that the Linux kernel uses heap-allocated credential objects (`struct cred` and `struct file`) to track process privileges and file permissions. If an attacker can free a credential object and reallocate a privileged credential in its place, they effectively "swap" their own credentials for higher-privileged ones.

### 3.2 Root Cause / Conceptual Basis

Linux tracks privileges through two primary credential structures:

1. **`struct cred`:** Contains the process's UID, GID, capabilities, and other security attributes. Allocated from the `cred_jar` slab cache. Size: approximately 192 bytes.

2. **`struct file`:** Contains file access mode, file operations, and ownership. Allocated from the `filp` slab cache. Size: approximately 384 bytes.

The technique exploits the kernel's heap memory reuse mechanism. When a heap vulnerability (UAF/double-free) exists, the attacker:

1. **Frees the victim credential** using the vulnerability.
2. **Triggers allocation of a privileged credential** from the same slab cache at the same memory address.
3. **Uses the dangling reference** from the vulnerability to access the now-privileged credential.

### 3.3 Exploitation Technique

Dirty Cred operates in two variants depending on the target credential type:

#### Variant 1: File Credential Swapping

Target: `struct file` objects.

1. **Trigger the vulnerability** to free a `struct file` associated with a low-privilege operation (e.g., a file opened by the attacker).
2. **Trigger a privileged process** (e.g., a setuid binary, or the kernel itself via a write to `/etc/passwd`) to allocate a new `struct file` at the same address.
3. **Use the dangling pointer** from step 1 to perform operations on the now-privileged file object (e.g., write to it).

A concrete example: The attacker opens a regular writable file, triggers the vulnerability to free its `struct file`, then causes the kernel to open `/etc/passwd` for writing (through another code path). The freed slot is reused for the `/etc/passwd` file object. The attacker's file descriptor now points to the privileged file, allowing writes to `/etc/passwd`.

#### Variant 2: Task Credential Swapping

Target: `struct cred` objects.

1. **Trigger the vulnerability** to free the `struct cred` of the attacker's own process.
2. **Trigger a privileged task** (e.g., a kernel thread or sshd) to allocate new credentials at the same address.
3. The attacker's task now uses the privileged credentials.

### 3.4 Key Advantages

Dirty Cred has several properties that make it a powerful exploitation technique:

- **Data-only:** No need to bypass KASLR, SMEP, SMAP, or leak kernel heap addresses. The attacker never needs to know any kernel addresses.
- **Universal:** Because `struct cred` and `struct file` exist in every Linux kernel, exploits using Dirty Cred can work across different kernel versions, configurations, and even architectures (x86, ARM) without modification.
- **Bypasses mitigations:** Effective against all available upstream exploit mitigations, including stack canaries, KASLR, SMEP/SMAP, and CFI (Control Flow Integrity).
- **Reliability:** Heap spraying techniques for credential objects are well-understood and can be made highly reliable.

### 3.5 Demonstrated Exploits

The researchers demonstrated Dirty Cred with three real-world vulnerabilities:
- **CVE-2021-4154:** A reference counting bug in cgroup handling, exploited via file credential swapping.
- **CVE-2022-2588:** A double-free in the `route4` network classifier, exploited via both file and task credential swapping. The exploit worked unmodified on both Ubuntu 20 and CentOS 8 with different kernel versions.
- **CVE-2022-20409:** An Android kernel vulnerability.

### 3.6 Defense

The researchers proposed a defense mechanism based on **credential-object isolation**: separating privileged and unprivileged credential objects into different slab caches. This prevents an unprivileged credential from being reallocated as a privileged one in the same slab, breaking the core assumption of the attack. This concept is analogous to the existing `AUTOSLAB` and `CONFIG_SLAB_VIRTUAL` proposals for general heap isolation.

---

## 4. Sequoia (CVE-2021-33909)

**Subsystem:** Filesystem (seq_file / VFS)
**Affected Versions:** Linux 3.16 (July 2014) through 5.13.x
**CVSS Score:** 7.8 (High)
**Discoverer:** Qualys Research Team
**Exploited in the wild:** Not confirmed

### 4.1 Vulnerability Description

Sequoia is a local privilege escalation vulnerability caused by a `size_t`-to-`int` type conversion error in the Linux kernel's filesystem layer. By creating, mounting, and deleting a deep directory structure whose total path length exceeds 1 GB, an unprivileged local attacker can write the 10-byte string `"//deleted"` to an offset of exactly -2GB-10 bytes below the beginning of a `vmalloc()`-allocated kernel buffer.

### 4.2 Root Cause

The vulnerability lies in the interaction between `seq_file` (used for `/proc` files) and the VFS path resolution code:

1. **`seq_read_iter()`** (in `fs/seq_file.c`) manages buffers for seq_file output. The buffer size `m->size` is a `size_t` (unsigned 64-bit on x86_64). It doubles the buffer each time the content doesn't fit: `m->size <<= 1`. When the path is longer than 1 GB, this results in a 2 GB buffer.

2. **`dentry_path()`** (in `fs/d_path.c`) takes the buffer and its size, but its `buflen` parameter is an `int` (signed 32-bit). When a 2 GB `size_t` is truncated to an `int`, it becomes `INT_MIN` (-2,147,483,648).

3. **`prepend()`** subtracts from the negative `buflen` and writes `"//deleted"` at the computed (wildly incorrect) position:
   ```c
   static int prepend(char **buffer, int *buflen, const char *str, int namelen)
   {
       *buflen -= namelen;     // INT_MIN - 10 wraps to a large positive
       if (*buflen < 0)
           return -ENAMETOOLONG;
       *buffer -= namelen;     // Points 2GB+10B before the buffer start
       memcpy(*buffer, str, namelen);  // Out-of-bounds write!
   }
   ```

The vulnerability was introduced in commit `058504ed` (July 2014, Linux 3.16) which changed `seq_file` to use `vmalloc()` for large buffers, making it possible to allocate buffers larger than 2 GB.

### 4.3 Exploitation Technique

The Qualys exploit is a sophisticated multi-stage attack:

**Stage 1: Create the deep directory structure**
- Create ~1 million nested directories (using backslash characters in names, which `show_mountinfo()` expands to 4-byte `\134` sequences, reducing the required depth by 4x).
- Bind-mount the structure in an unprivileged user namespace.
- Delete the original directories (creating a "deleted" dentry).

**Stage 2: Fill vmalloc holes**
- Spray large vmalloc buffers (768 MB, 1 GB, 2 GB) by reading `/proc/self/mountinfo` across multiple user namespaces.
- Arrange three sequential vmalloc allocations: a 1 GB buffer, another 1 GB buffer, and a 2 GB buffer.

**Stage 3: Load eBPF programs**
- Create 1024 threads, each loading an eBPF program.
- Block each thread (via `userfaultfd` or FUSE) after the eBPF verifier validates the program but before JIT compilation.

**Stage 4: Trigger the out-of-bounds write**
- Free the first 1 GB buffer to create a vmalloc hole.
- Unblock the eBPF threads so their programs fill the hole.
- Read the 2 GB seq_file buffer to trigger the out-of-bounds `"//deleted"` write, which lands inside an eBPF program.

**Stage 5: Exploit corrupted eBPF**
- The `"//deleted"` string overwrites a verified eBPF instruction, converting `BPF_MOV64_IMM(BPF_REG_2, 0)` into a NOP (`BPF_ALU32_IMM(BPF_LSH, BPF_REG_5, 0x74)`).
- This nullifies the verifier's security checks, enabling:
  - **Information disclosure:** Leaking kernel addresses from eBPF registers.
  - **Limited OOB write:** Corrupting eBPF map metadata to read/write beyond map bounds.
  - **Arbitrary kernel R/W:** Using Manfred Paul's `btf` and `map_push_elem` techniques.
  - **Root shell:** Overwriting `modprobe_path` with a custom executable path.

### 4.4 Impact

- Successfully exploited on default installations of Ubuntu 20.04, 20.10, 21.04, Debian 11, and Fedora 34 Workstation.
- Required approximately 5 GB of memory and 1 million inodes.
- The exploit is complex but highly portable across distributions.

### 4.5 Fix

The fix involves changing the `buflen` parameter type from `int` to `size_t` throughout the path resolution functions (`dentry_path()`, `prepend()`, etc.), eliminating the integer truncation:

```c
// Before (vulnerable):
char *dentry_path(struct dentry *dentry, char *buf, int buflen);

// After (fixed):
char *dentry_path(struct dentry *dentry, char *buf, size_t buflen);
```

Additionally, overflow checks were added to the `seq_file` buffer doubling logic.

**Mitigations:**
- Setting `kernel.unprivileged_userns_clone = 0` prevents the user namespace mount trick.
- Setting `kernel.unprivileged_bpf_disabled = 1` prevents eBPF program loading by unprivileged users (blocks this specific exploit chain, though other vmalloc objects could potentially be targeted).

---

## 5. Looney Tunables (CVE-2023-4911)

**Subsystem:** glibc dynamic loader (`ld.so`) -- kernel-adjacent
**Affected Versions:** glibc 2.34 (April 2021) through glibc 2.38
**CVSS Score:** 7.8 (High)
**Discoverer:** Qualys Research Team
**Exploited in the wild:** Yes (post-disclosure)

### 5.1 Vulnerability Description

Looney Tunables is a buffer overflow vulnerability in the GNU C Library's dynamic loader (`ld.so`). While not a kernel vulnerability per se, it is **kernel-adjacent** because `ld.so` runs with elevated privileges when executing SUID programs, and it directly interacts with kernel facilities (memory mapping, ELF loading, process credentials). It is included here because it is often used in conjunction with kernel exploits and represents the kind of userspace-kernel boundary vulnerability that is critical to Linux security.

The vulnerability is in `ld.so`'s processing of the `GLIBC_TUNABLES` environment variable. This variable allows tuning of various glibc parameters (e.g., `glibc.malloc.mxfast`).

### 5.2 Root Cause

The bug is in the `parse_tunables()` function, introduced in April 2021 by commit `2ed18c` ("Fix SXID_ERASE behavior in setuid programs"). The function is supposed to sanitize the `GLIBC_TUNABLES` environment variable by removing dangerous tunables when running SUID programs.

The vulnerability occurs with a specially crafted `GLIBC_TUNABLES` value of the form:

```
tunable1=tunable2=AAA
```

Where both `tunable1` and `tunable2` are SXID_IGNORE tunables (e.g., `glibc.malloc.mxfast`).

**First iteration:** The parser treats the entire string as a valid tunable-value pair (`tunable1` with value `tunable2=AAA`). It copies this entire string in-place to the output buffer `tunestr`, filling it completely.

**After first iteration:** The pointer `p` is **not advanced** past the value because no `:` separator was found (line 247: `if (p[len] != '\0') p += len + 1` -- but `p[len]` IS `'\0'`). So `p` still points to `tunable2=AAA`.

**Second iteration:** The parser now treats `tunable2=AAA` as a second tunable-value pair and appends it to `tunestr`, which is already full. This causes a **buffer overflow**.

The overflow writes beyond the `mmap()`-allocated buffer returned by `__minimal_malloc()`.

### 5.3 Exploitation Technique

The Qualys exploit achieves root on SUID programs through a data-only attack:

**Step 1: Overflow target selection**

Since `__tunables_init()` can process multiple `GLIBC_TUNABLES` environment variables, and `mmap()` allocates top-down, the attacker places two `GLIBC_TUNABLES` variables:
- The first is allocated normally (without overflow).
- The second is allocated immediately below the first and overflows into the first.

**Step 2: Corrupting `link_map`**

The `ld.so` function `_dl_new_object()` allocates `struct link_map` with `calloc()`, which internally uses `__minimal_calloc()` -> `__minimal_malloc()` -> `mmap()`. It does NOT zero-initialize the returned memory explicitly (since `mmap()` returns zeroed pages). However, the overflow can write non-zero bytes into this "clean" mmap region before `_dl_new_object()` allocates from it.

The key target is `l_info[DT_RPATH]` in the `link_map` structure. By overwriting this pointer, the attacker forces `ld.so` to trust a directory they control as a library search path.

**Step 3: Controlling the overwritten pointer**

The overflow writes bytes from the original `GLIBC_TUNABLES` in the stack (via `valstring`), not from the copy (`tunestr`). By placing empty strings (null bytes) and a target address in the environment, the attacker can write mostly null bytes (safe for the link_map) while setting `l_info[DT_RPATH]` to point to a fake `Elf64_Dyn` structure in the stack.

**Step 4: ASLR bypass via brute force**

`l_info[DT_RPATH]` is set to `0x7ffdfffff010` (center of the stack randomization range). With ~6 MB of environment strings filled with the correct pattern, the probability of guessing correctly is ~1/2730, requiring about 30 seconds on Debian and ~5 minutes on Ubuntu/Fedora.

**Step 5: Root shell**

The fake `DT_RPATH` entry points to a relative directory (`\x08`) in the attacker's current working directory. The attacker places a malicious `libc.so.6` in this directory, which is then loaded by `ld.so` when the SUID program runs, executing arbitrary code as root.

### 5.4 Impact

- Successfully exploited on default installations of Fedora 37/38, Ubuntu 22.04/23.04, and Debian 12/13.
- Works against almost all SUID programs (exceptions: `sudo` with its own RUNPATH, programs protected by SELinux/AppArmor rules).
- **Alpine Linux is not affected** (uses musl libc, not glibc).
- Post-disclosure, functional exploits were developed independently by multiple groups and actively used in attacks.

### 5.5 Fix

The fix sanitizes the `parse_tunables()` function to properly handle the case where a tunable value contains `=` characters, preventing the second-iteration re-parse. Additionally, bounds checking was added to prevent writing beyond the allocated buffer.

---

## 6. nf_tables Vulnerabilities

The Netfilter `nf_tables` subsystem has been a persistent source of critical kernel vulnerabilities. This section covers two high-profile CVEs that represent the broader pattern.

### 6.1 CVE-2023-32233: Anonymous Set Use-After-Free

**Subsystem:** Netfilter / nf_tables
**Affected Versions:** Linux kernel through 6.3.1
**CVSS Score:** 7.8 (High)
**Discoverers:** Patryk Sondej, Piotr Krysiuk

#### 6.1.1 Vulnerability Description

A use-after-free vulnerability in nf_tables when processing batch requests. Netfilter nf_tables allows updating its configuration with batch requests that group multiple basic operations into atomic transactions.

#### 6.1.2 Root Cause

The bug occurs in a specific scenario involving anonymous sets (implicitly created sets used by rules):

1. A batch request contains an operation that **implicitly deletes** an anonymous set (e.g., deleting a rule that uses the set).
2. A subsequent operation in the **same batch** attempts to act on the same anonymous set (e.g., deleting an element from it, or explicitly deleting the set again).

The nf_tables transaction processing fails to detect this invalid sequence. When committing the batch:
- The first operation deletes the anonymous set and frees its memory.
- The second operation accesses the freed memory, causing a use-after-free.

This corrupts the kernel's internal nf_tables state and can be leveraged for arbitrary kernel memory reads and writes.

#### 6.1.3 Exploitation

The exploit uses the UAF to perform arbitrary reads and writes in kernel memory, ultimately achieving local privilege escalation from an unprivileged user to root. The exploit was shared with the kernel security team, and the exploitation technique details were published on the oss-security mailing list.

The accessibility is notable: the exploit requires only `CAP_NET_ADMIN` in a user namespace, which is available to unprivileged users on most default Linux configurations.

#### 6.1.4 Fix

**Commit:** `c1592a89942e9678f7d9c8030efa777c0d57edab`

The fix adds proper validation to nf_tables batch processing to detect and reject invalid sequences where an operation targets an anonymous set that was implicitly deleted by a previous operation in the same batch.

---

### 6.2 CVE-2024-1086: Verdict Input Sanitization Failure (Double-Free)

**Subsystem:** Netfilter / nf_tables
**Affected Versions:** Linux 5.14 through 6.6.14
**CVSS Score:** 7.8 (High)
**Discoverer:** notselwyn
**Success Rate:** 93-99.4%

#### 6.2.1 Vulnerability Description

A double-free vulnerability caused by insufficient input validation of netfilter verdict values. The vulnerability allows an unprivileged local user (with access to user namespaces) to obtain a double-free primitive on `sk_buff` objects, leading to privilege escalation with near-perfect reliability.

#### 6.2.2 Root Cause

The root cause is an input sanitization failure in `nft_verdict_init()`. When a user creates a netfilter verdict through the netlink API, the kernel validates the verdict code by checking `verdict.code & NF_VERDICT_MASK`. However, it fails to check the upper bits of the verdict code.

A malicious verdict value of `0xffff0000` passes validation:
- `0xffff0000 & NF_VERDICT_MASK` = `0x0` = `NF_DROP` (valid).

When this verdict is evaluated in `nf_hook_slow()`:
1. The verdict mask check sees `NF_DROP`, so the kernel **frees the skb** via `kfree_skb_reason()`.
2. The return value is computed via `NF_DROP_GETERR(0xffff0000)` = `1` = `NF_ACCEPT`.
3. The caller (`NF_HOOK()`) sees `NF_ACCEPT` and continues processing the already-freed skb.
4. The skb is eventually freed again, creating a **double-free**.

```c
// In nf_hook_slow():
case NF_DROP:
    kfree_skb_reason(skb, ...);        // First free
    ret = NF_DROP_GETERR(verdict);     // Returns 1 (NF_ACCEPT)
    return ret;                         // Caller sees NF_ACCEPT

// In NF_HOOK():
if (ret == NF_ACCEPT)                   // True!
    ret = okfn(net, sk, skb);           // Second free (eventually)
```

#### 6.2.3 Exploitation Technique

The exploit by notselwyn is a masterpiece of kernel exploitation engineering with several novel techniques:

**Double-Free Setup:**
- Create an nftables rule with the malicious verdict `0xffff0000` in an unprivileged user namespace.
- Send a large IP packet (order-4, 64 KB) to trigger the rule. The `sk_buff->head` buffer is allocated by the buddy allocator at this size.
- Use IP fragmentation to delay the second free, allowing time for memory manipulation between frees.

**Page Conversion (PCP Draining):**
- The double-freed pages are order-4 buddy allocator pages, but PTE/PMD pages are order-0.
- Drain the per-CPU page (PCP) allocator freelist, then refill it from the buddy allocator. This converts the order-4 double-free into control over order-0 pages.

**Dirty Pagedirectory (Novel Technique):**
- Allocate a PTE page and a PMD page to the **same physical address** (the double-freed page).
- When writing a PTE value to a page within the PTE page's span, the PMD page interprets that PTE value when dereferencing the corresponding address range.
- This creates unlimited read/write to **any physical memory address** entirely from userland.

**TLB Flushing from Userland:**
- After modifying page tables, the TLB contains stale entries.
- Flush TLB by calling `fork()` and `munmap()` on the target VMA in the child process.

**Privilege Escalation:**
- Brute-force physical KASLR by scanning 2 MB-aligned physical addresses for a kernel image signature.
- Scan for `modprobe_path` (or `"/sbin/usermode-helper"` if `CONFIG_STATIC_USERMODEHELPER` is enabled).
- Overwrite `modprobe_path` with a path to the exploit's memfd script.
- Trigger `modprobe` by executing a file with invalid magic bytes.
- The kernel executes the attacker's script as root, which hooks a root shell to the exploit's file descriptors for namespace escape.

**Capabilities:**
- Works across kernel versions v5.14 to v6.6.14 without recompilation.
- Works on KernelCTF mitigation instances (one of the most hardened kernel configurations).
- Fileless execution: no files are written to disk.

#### 6.2.4 Fix

The fix sanitizes verdicts from userland input in the netfilter API by disallowing positive drop errors entirely:

```c
// In nft_verdict_init():
if (data->verdict.code == NF_DROP &&
    NF_DROP_GETERR(data->verdict.code) > 0)
    return -EINVAL;  // Reject positive drop errors
```

The maintainer noted that if positive drop errors are ever needed in the future, only values with `n <= 0` should be permitted to prevent overlap with `NF_ACCEPT`.

---

## 7. io_uring Vulnerabilities

**Subsystem:** io_uring
**Multiple CVEs:** CVE-2021-20226, CVE-2021-41073, CVE-2022-29582, CVE-2023-2598, CVE-2024-0582, and many others
**Overall Status:** io_uring has been a consistent source of critical kernel vulnerabilities since its introduction in Linux 5.1 (2019).

### 7.1 Overview

`io_uring` is a high-performance asynchronous I/O interface introduced in Linux 5.1 by Jens Axboe. It uses shared ring buffers (submission queue and completion queue) between userspace and kernelspace to minimize system call overhead. While io_uring delivers significant performance improvements for I/O-heavy workloads, its complexity has made it one of the most prolific sources of kernel vulnerabilities.

The interface supports a wide range of operations beyond simple I/O: file operations, network operations (`accept`, `connect`, `send`, `recv`), `splice`, `tee`, timeouts, linked operations, fixed file tables, registered buffers, and more. This feature surface area, combined with the asynchronous nature of operations (with complex lifetime and reference counting semantics), creates a rich attack surface.

### 7.2 Case Study: CVE-2022-29582 (io_uring Timeout UAF)

**Discoverers:** Jayden (Awarau) and David (pqlqpql)
**Affected Version:** Linux 5.10.x (demonstrated on 5.10.90)
**Target:** Google kCTF (Container Optimized OS)

#### 7.2.1 Vulnerability Description

A use-after-free vulnerability in the interaction between `IORING_OP_TIMEOUT` and `IORING_OP_LINK_TIMEOUT` operations. When a timeout request `T` is linked with a link-timeout `LT`, concurrent completion of both can lead to a race condition where `LT` is freed while `T` still holds a dangling reference to it.

#### 7.2.2 Root Cause

The bug stems from an edge case in concurrent timeout completion:

1. **Timeout `T`** completes through the "flush" path (its completion event count is reached).
2. **Link-timeout `LT`** fires simultaneously through an hrtimer callback.

The race occurs in `io_link_timeout_fn()`:
```c
if (!list_empty(&req->link_list)) {
    prev = list_entry(req->link_list.prev, ...);
    if (refcount_inc_not_zero(&prev->refs))  // T.refs == 0!
        list_del_init(&req->link_list);       // Not reached
    else
        prev = NULL;
}
```

When `T`'s refcount reaches 0 (during its completion) before `LT` checks it, `list_del_init` is never called. Both `T` and `LT` are scheduled for deferred destruction, but if `LT` is destroyed before `T`, `T` follows its dangling `link_list` pointer to the freed `LT`.

#### 7.2.3 Exploitation Technique

The exploit chains multiple techniques:

1. **Object Replacement:** Replace the freed `LT` with `LT'`---an `IORING_OP_TEE` request that blocks indefinitely in `do_tee()` on a pipe, stabilizing the exploit.

2. **Refcount Manipulation:** The worker thread processing `T`'s destruction incorrectly releases references on `LT'`, eventually freeing `LT'`'s `file_in` pipe file object prematurely.

3. **File Use-After-Free:** The attacker retains a file descriptor to the freed pipe file, creating a `struct file` UAF.

4. **Cross-Cache Attack:** The `struct file` is in the dedicated `filp` slab cache. The exploit:
   - Empties the target slab page of all file objects.
   - Overflows the CPU partial list to force the SLUB allocator to return the page to the page allocator.
   - Reallocates the page for `kmalloc-512` using `msg_msgseg` objects via System V IPC.

5. **Information Leak:** Frees the file again (using carefully crafted `f_op` and `f_mode` fields in the msg_msgseg spray), then replaces the dangling `msg_msgseg` with `tls_context` objects. Reading back the message leaks `tls_context->sk_proto` (`tcp_prot`), defeating KASLR.

6. **Code Execution:** Overwrites `tls_context->proto` with a pointer to a forged function table, achieving RIP control via `getsockopt()`, then uses ROP to call `commit_creds(init_cred)` and return to a root shell.

#### 7.2.4 Fix

The fix ensures proper synchronization between the timeout completion paths. Specifically, it guarantees that when `T`'s refcount reaches 0, `LT` is properly removed from the link list before `T`'s destruction proceeds:

```c
// Ensure linked timeouts are properly cleaned up
// before the request refcount reaches 0
```

### 7.3 Broader io_uring Vulnerability Patterns

The io_uring subsystem has exhibited several recurring vulnerability classes:

| CVE | Year | Type | Description |
|-----|------|------|-------------|
| CVE-2021-20226 | 2021 | Reference counting | Incorrect put of file reference in io_uring fixed file table |
| CVE-2021-41073 | 2021 | Type confusion | Type confusion in io_uring `IORING_OP_PROVIDE_BUFFERS` |
| CVE-2022-29582 | 2022 | Use-after-free | Race in linked timeout completion (detailed above) |
| CVE-2023-2598 | 2023 | OOB access | Out-of-bounds access in registered buffer handling |
| CVE-2024-0582 | 2024 | Use-after-free | UAF when returning pages from io_uring mmap'd regions |

**Common root causes include:**
- **Reference counting errors:** Complex object lifetimes with multiple owners.
- **Race conditions:** Asynchronous operations completing concurrently with cleanup.
- **State machine complexity:** Operations can be linked, canceled, timed out, and deferred across different contexts (task, softirq, workqueue).
- **Resource lifetime mismatches:** Fixed file tables, registered buffers, and mmap'd ring pages with complex ownership semantics.

**Security response:** Due to the high volume of vulnerabilities, several high-security environments (Google's COS, Android for non-root apps, various hardened Linux distributions) have disabled io_uring for unprivileged users or entirely.

---

## 8. StackRot (CVE-2023-3269)

**Subsystem:** Memory Management (Maple Tree / VMA handling)
**Affected Versions:** Linux 6.1 through 6.4
**CVSS Score:** 7.8 (High)
**Discoverer:** Ruihan Li (Peking University)
**Exploited in the wild:** Not confirmed

### 8.1 Vulnerability Description

StackRot is a use-after-free vulnerability in the Linux kernel's memory management subsystem, specifically in the maple tree data structure that replaced red-black trees for managing Virtual Memory Areas (VMAs) starting in Linux 6.1. The bug is triggered during stack expansion and affects virtually all kernel configurations.

The vulnerability is a **use-after-free-by-RCU (UAFBR)**, which is particularly notable because this class of bugs was previously considered unexploitable. StackRot is the first demonstrated exploitable UAFBR vulnerability.

### 8.2 Root Cause

The root cause involves the interaction between RCU-safe maple tree operations and the MM (memory management) locking scheme:

**Background:**
- Linux 6.1 replaced the VMA red-black tree with a maple tree---an RCU-safe B-tree optimized for non-overlapping ranges.
- Each maple node (`struct maple_range_64`, 256 bytes) contains up to 16 intervals with pivots and slots pointing to VMAs.
- Concurrent readers can either hold the MM read lock OR enter an RCU critical section.

**The bug in stack expansion:**

When a stack VMA needs to expand (due to a page fault below the current stack), `expand_downwards()` is called. This function holds only the MM read lock, not the write lock. If the expansion eliminates a gap between the stack VMA and a neighboring `MAP_GROWSDOWN` VMA (where no stack guard is enforced), the maple tree must **replace** the node (because the RCU-safe tree cannot modify nodes in-place). This creates a new node and schedules the old node for RCU-deferred freeing via `call_rcu()`.

The race condition:

```
  - CPU 0 -                              - CPU 1 -
  mm_read_lock()                          mm_read_lock()
  expand_stack()                          find_vma_prev()
    expand_downwards()                      mas_walk()
      mas_store_prealloc()                    mas_state_walk()
        mas_replace()                           mas_root()
          mas_free()                              node = rcu_dereference_check()
            call_rcu(&mt_free_rcu)                [Node pointer recorded]
  mm_read_unlock()

  [RCU grace period elapses...]
  rcu_do_batch()                            mas_prev()
    mt_free_rcu()                             mas_prev_entry()
      kmem_cache_free()                         mas_slot()
      [Node is freed]                             rcu_dereference_check(node->...)
                                                  [UAF! Accessing freed node]
```

The critical insight: CPU 1 holds the MM read lock but is NOT in an RCU critical section. The old maple node is freed via RCU callback, which waits only for RCU critical sections to end, not for MM read locks. So the node can be freed while CPU 1 still holds a pointer to it.

### 8.3 Exploitation Technique

Exploiting UAFBR is uniquely challenging because:
- RCU callbacks delay freeing until all pre-existing RCU critical sections complete.
- The attacker cannot directly control when the freed node is reallocated.
- Standard heap exploitation techniques assume immediate free-and-reallocate patterns.

Ruihan Li's exploit overcomes these challenges:

1. **Trigger the race:** Create two adjacent `MAP_GROWSDOWN` VMAs without a stack guard gap. Trigger stack expansion on one CPU while another CPU traverses the VMA tree.

2. **Control RCU timing:** Manipulate RCU grace period timing to ensure the old maple node is freed while another thread still references it.

3. **Reallocate the freed node:** After the RCU callback frees the 256-byte maple node, spray replacement objects into the `kmalloc-256` slab cache to reclaim the memory.

4. **Corrupt VMA metadata:** The replacement object's data is interpreted as maple tree pivots and slots, giving the attacker control over VMA pointers and boundaries.

5. **Privilege escalation:** Use corrupted VMA metadata to achieve arbitrary kernel read/write, then escalate privileges.

The exploit was demonstrated against the Google kCTF VRP environment (`bzImage_upstream_6.1.25`), proving exploitability even without `CONFIG_PREEMPT` or `CONFIG_SLAB_MERGE_DEFAULT`.

### 8.4 Impact

- **Broad applicability:** Affects almost all kernel configurations since the maple tree is used universally for VMA management from Linux 6.1 onward.
- **Minimal capabilities required:** Can be triggered from an unprivileged process.
- **Novel exploitation class:** First public proof that UAFBR bugs are exploitable, opening a new category of vulnerability research.
- **Research significance:** Demonstrates that RCU-deferred freeing is not a sufficient mitigation against use-after-free exploitation.

### 8.5 Fix

The fix was led by Linus Torvalds and required approximately two weeks of development due to the complexity of the maple tree and MM locking interactions. The patch series was merged on June 28, 2023:

**Commit:** `9471f1f2f50282b9e8f59198ec6bb738b4ccc009`

The core fix ensures that stack expansion properly acquires the MM write lock (instead of just the read lock) when the expansion requires maple tree node replacement. This prevents the race condition by serializing the operation with other VMA tree readers and writers.

Backported to stable kernels: 6.1.37, 6.3.11, and 6.4.1.

---

## Cross-Cutting Analysis

### Common Vulnerability Patterns

| CVE | Year | Root Cause Class | Subsystem |
|-----|------|-----------------|-----------|
| Dirty COW | 2016 | Race condition | MM (COW) |
| Dirty Pipe | 2022 | Uninitialized memory | Pipe / Page cache |
| Dirty Cred | 2022 | (Technique) Credential swap | Heap / Credentials |
| Sequoia | 2021 | Integer truncation | Filesystem / seq_file |
| Looney Tunables | 2023 | Buffer overflow | glibc (ld.so) |
| nf_tables (32233) | 2023 | Use-after-free | Netfilter |
| nf_tables (1086) | 2024 | Input validation failure | Netfilter |
| io_uring (29582) | 2022 | Race condition / UAF | io_uring |
| StackRot | 2023 | Race condition / UAFBR | MM (Maple tree) |

### Recurring Themes

1. **Race conditions remain king:** Despite decades of kernel development, TOCTOU bugs and race conditions in concurrent code paths continue to produce critical vulnerabilities (Dirty COW, io_uring, StackRot).

2. **Uninitialized memory is dangerous:** The Dirty Pipe vulnerability was caused by a missing `flags = 0` initialization---a single line of code. Uninitialized fields become exploitable when new semantics are layered on top of existing structures.

3. **Integer type mismatches:** The Sequoia vulnerability demonstrates the danger of passing `size_t` values through `int` parameters. C's implicit type conversions make these bugs easy to introduce and hard to spot.

4. **Netfilter is a persistent attack surface:** The nf_tables subsystem has produced a steady stream of critical vulnerabilities due to its complexity, stateful transaction processing, and extensive userland interface via netlink.

5. **New subsystems attract new bugs:** Both io_uring (2019+) and the maple tree (2022+) introduced significant new code with complex lifetime and concurrency semantics, leading to novel vulnerability classes.

6. **Exploitation techniques evolve:** Dirty Cred, Dirty Pagetable/Pagedirectory, and cross-cache attacks represent the ongoing evolution of kernel exploitation beyond traditional techniques, often achieving data-only attacks that bypass modern mitigations.

---

## References

- Dirty COW: https://dirtycow.ninja/ ; commit `19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619`
- Dirty Pipe: https://dirtypipe.cm4all.com/ ; commit `9d2231c5d74e13b2a0546fee6737ee4446017903`
- Dirty Cred: Lin et al., "DirtyCred: Escalating Privilege in Linux Kernel," ACM CCS 2022 ; https://github.com/Markakd/DirtyCred
- Sequoia: Qualys Security Advisory, https://www.qualys.com/2021/07/20/cve-2021-33909/sequoia-local-privilege-escalation-linux.txt
- Looney Tunables: Qualys Security Advisory, https://www.openwall.com/lists/oss-security/2023/10/03/2
- CVE-2023-32233: https://www.openwall.com/lists/oss-security/2023/05/08/4 ; commit `c1592a89942e9678f7d9c8030efa777c0d57edab`
- CVE-2024-1086: https://pwning.tech/nftables/ ; https://github.com/Notselwyn/CVE-2024-1086
- CVE-2022-1015/1016: https://blog.dbouman.nl/2022/04/02/How-The-Tables-Have-Turned-CVE-2022-1015-1016/
- CVE-2022-29582: https://ruia-ruia.github.io/2022/08/05/CVE-2022-29582-io-uring/
- StackRot: https://github.com/lrh2000/StackRot ; https://www.openwall.com/lists/oss-security/2023/07/05/1
- Dirty Pagetable: N. Wu, https://yanglingxi1993.github.io/dirty_pagetable/dirty_pagetable.html

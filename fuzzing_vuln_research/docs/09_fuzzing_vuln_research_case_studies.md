# Case Studies in Fuzzing and Vulnerability Research

## 1. OSS-Fuzz Success Stories

### 1.1 Overview

OSS-Fuzz, launched in December 2016, is Google's continuous fuzzing service for open-source software. As of 2024, it has found **over 40,000 bugs** across **700+ projects**. These numbers make OSS-Fuzz the most successful fuzzing deployment in history.

**Key statistics:**
- **40,000+ bugs** found (10,000+ with security implications)
- **700+ projects** under continuous fuzzing
- **5,000+ CPU cores** dedicated to fuzzing
- **1,000+ fuzz targets** running simultaneously
- **6-hour build/test cycles**: New builds are fuzzed within 6 hours of code changes

### 1.2 The OSS-Fuzz Pipeline

```
Source Commit → Build System → Fuzz Targets → ClusterFuzz → Crash Triage → Bug Report
     ↓              ↓              ↓              ↓              ↓              ↓
  GitHub/       Docker +       libFuzzer +    Distributed    Minimization   Issue
  Git mirror    build.sh       AFL++         execution      Dedup          tracker
```

**Step-by-step:**
1. **Source mirror**: OSS-Fuzz mirrors project repositories
2. **Build**: Each project is built with fuzzing instrumentation (libFuzzer + ASan, MSan, UBSan)
3. **Fuzz targets**: Project-specific fuzz targets (provided by project maintainers or OSS-Fuzz contributors)
4. **ClusterFuzz**: Runs fuzz targets 24/7 on Google infrastructure
5. **Crash triage**: Automatic crash minimization, deduplication, regression testing
6. **Bug reporting**: Bugs are automatically filed in the project's issue tracker

### 1.3 Notable OSS-Fuzz Discoveries

**Project: OpenSSL**
- **50+ bugs** found, including multiple memory safety violations
- Found during the post-Heartbleed fuzzing push
- Includes bugs in X.509 certificate parsing, ASN.1 handling, and TLS state machine

**Project: libpng**
- **30+ bugs** found, including heap overflows and OOB reads
- CVE-2019-13135: Use-after-free in `png_image_free`
- Critical for web security (libpng is used by every browser)

**Project: SQLite**
- **200+ bugs** found, including logic bugs that could lead to database corruption
- One of the most heavily fuzzed projects
- Fuzzing discovered bugs in the SQL parser, VDBE, and B-tree implementation

**Project: FreeType**
- **100+ bugs** found, including heap overflows in font parsing
- Critical for Android security (FreeType is used by all Android apps)
- Multiple CVEs assigned from OSS-Fuzz findings

**Project: curl**
- **50+ bugs** found, including buffer overflows and OOB reads
- Covers HTTP, FTP, SMTP, IMAP, and many other protocols
- Includes CVE-2023-23916: HTTP multi-header compression OOB write

### 1.4 Impact Analysis

OSS-Fuzz's impact extends beyond bug counts:
- **Security culture change**: Projects now include fuzzing as part of their development process
- **Regression prevention**: Fuzz corpus serves as a regression test suite
- **Coverage dashboards**: Public coverage reports show which code is not tested
- **Community building**: Fuzzing engineers collaborate across project boundaries

## 2. CVE-2016-5195: Dirty COW Variant Analysis

### 2.1 The Original Bug

CVE-2016-5195 (Dirty COW) is a race condition in the Linux kernel's copy-on-write (COW) mechanism for memory-mapped files. The bug allows an unprivileged user to write to any file they have read access to, including setuid root binaries.

**Root cause:** In `mm/memory.c`, the `do_cow_fault()` function checks whether a page is COW and needs to be duplicated before writing. However, a race exists between the COW check and the actual page modification. If another thread unmaps the page between the check and the write, the write goes directly to the original page (bypassing COW).

```c
// Simplified vulnerable code path
static int do_cow_fault(struct vm_fault *vmf) {
    struct page *new_page;
    
    // Allocate a new page for the COW copy
    new_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, vmf->address);
    if (!new_page)
        return VM_FAULT_OOM;
    
    // Copy the original page content to the new page
    copy_user_page(new_page, vmf->page, vmf->address, vma);
    
    // RACE WINDOW: Another thread can unmap the page here
    // If the page is unmapped, the write goes to the original page
    
    // Set up the new page in the page table
    vmf->page = new_page;
    return finish_fault(vmf);  // May write to original page instead of copy
}
```

### 2.2 The Exploit

The Dirty COW exploit uses `madvise(MADV_DONTNEED)` to race with the page fault handler:

```c
// Simplified exploit flow
void *map = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);

// Thread 1: Write to the mapping (triggers COW)
void *write_thread(void *arg) {
    while (1) {
        // Try to write to the read-only mapping
        // This should trigger COW, but the race allows
        // writing directly to the underlying file
        *(char *)map = 'X';
    }
}

// Thread 2: Discard the COW page (races with thread 1)
void *madvise_thread(void *arg) {
    while (1) {
        // Discard the COW copy, forcing the kernel to
        // re-reference the original page
        madvise(map, PAGE_SIZE, MADV_DONTNEED);
    }
}
```

### 2.3 Variant Analysis

After Dirty COW was disclosed, security researchers performed extensive variant analysis:

**Variant 1: COW in THP (Transparent Huge Pages)**
The same race condition existed in the THP COW path. The THP handler had a similar race between COW check and page modification, but used a different code path that wasn't fixed by the original patch.

**Variant 2: COW in userfaultfd**
The userfaultfd mechanism could be used to widen the race window. By pausing the page fault handler with userfaultfd, the attacker could reliably win the race without resorting to `madvise` spinning.

**Variant 3: COW in ptrace**
The ptrace interface could trigger COW on traced process pages, creating a similar race condition with different triggering mechanism.

**Lessons from variant analysis:**
1. **COW is a fundamental pattern**: Any code that checks a page's COW status and then modifies it has a potential race
2. **Fix the pattern, not the instance**: The original fix addressed one specific race but not the general pattern
3. **Use variant fuzzing**: After the fix, fuzzing should target all COW-related code paths, not just the fixed one

## 3. CVE-2022-0847: DirtyPipe Discovery

### 3.1 Discovery Story

CVE-2022-0847 (DirtyPipe) was discovered by Max Kellermann in February 2022 while investigating a corrupted file on a customer's server. He noticed that a log file had unexpected content—bytes from a different file had been written into it.

**Investigation timeline:**
1. Customer reports corrupted log file
2. Kellermann writes a script to detect similar corruption across the filesystem
3. Finds multiple corrupted files, all with the same pattern: pages overwritten with data from other files
4. Hypothesizes a kernel bug in the page cache
5. Narrows down to the pipe buffer code path
6. Discovers that `splice()` from a file to a pipe, followed by writing to the pipe, can overwrite the page cache entry

### 3.2 The Bug

The bug is in `fs/pipe.c`'s `copy_page_to_iter_pipe()` function. When `splice()` transfers data from a file to a pipe, it creates a `pipe_buffer` entry that references the page cache page. The `PIPE_BUF_FLAG_CAN_MERGE` flag is incorrectly set, allowing subsequent `write()` calls to the pipe to merge data into the page cache page—modifying the underlying file.

```c
// The vulnerable code (simplified)
static size_t copy_page_to_iter_pipe(struct page *page, ...) {
    struct pipe_inode_info *pipe = ...;
    struct pipe_buffer *buf = &pipe->bufs[head & mask];
    
    // BUG: This flag should NOT be set for file-backed pages
    buf->flags = PIPE_BUF_FLAG_CAN_MERGE;  // ← THE BUG
    
    buf->page = page;           // Reference to page cache page
    buf->offset = offset;
    buf->len = bytes;
    // ...
}
```

**Why it's dangerous:** An unprivileged user can:
1. Open a file they have read access to (e.g., `/etc/passwd`)
2. `splice()` from the file to a pipe (creates a page cache reference with CAN_MERGE)
3. `write()` arbitrary data to the pipe (overwrites the page cache page)
4. The file on disk is modified—even though the user only has read permission

### 3.3 The Fix

The fix is a one-line change:

```c
// Before (vulnerable)
buf->flags = PIPE_BUF_FLAG_CAN_MERGE;

// After (fixed)
buf->flags = 0;  // Don't allow merging for file-backed pages
```

### 3.4 Introduction Date

The bug was introduced in commit `9d2261d` ("pipe: merge anon_pipe_buf*_ops", 2016), which added the `PIPE_BUF_FLAG_CAN_MERGE` flag and incorrectly applied it to all pipe buffers, including file-backed ones. The bug existed from Linux 4.14 through 5.16.

### 3.5 Lessons

1. **Real-world bugs can be found through operational monitoring**, not just fuzzing
2. **Small code changes can introduce severe vulnerabilities** (a single flag assignment)
3. **Bug patterns transcend components**: Dirty COW and DirtyPipe are both "unintended write to read-only memory" bugs, but in completely different subsystems
4. **Variant analysis should be cross-subsystem**: After Dirty COW, researchers should have looked for similar "write to read-only resource" patterns across all kernel subsystems

## 4. V8 CVE-2024-0519: Fuzzing Discovery

### 4.1 The Bug

CVE-2024-0519 is an out-of-bounds write in V8's WebAssembly SIMD implementation, specifically in `WasmGraphBuilding::S128Shift`. The bug allows an attacker to write beyond the bounds of a typed array, potentially achieving arbitrary memory write from JavaScript.

### 4.2 How Fuzzing Found It

The bug was found by ClusterFuzz running fuzzilli-generated WebAssembly programs. The specific sequence:

1. **fuzzilli generates a Wasm module** that uses SIMD shift operations
2. The module includes an `i8x16.shr_u` (shift right unsigned) instruction with an out-of-range shift count
3. V8's Liftoff JIT compiler generates code that doesn't properly validate the shift count
4. The invalid shift count causes the SIMD operation to write beyond the allocated buffer

### 4.3 Root Cause

In `WasmGraphBuilding::S128Shift`, the shift count was not properly clamped for SIMD operations:

```c++
// Before fix (simplified)
void WasmGraphBuilding::S128Shift(FullDecoder* decoder,
                                    const Value& base,
                                    const Value& shift,
                                    Value* result) {
    // BUG: shift.value() could exceed the valid range [0, element_bits-1]
    // For i8x16 shifts, valid range is [0, 7]
    // For i16x8 shifts, valid range is [0, 15]
    // For i32x4 shifts, valid range is [0, 31]
    result->op = graph()->NewNode(
        machine()->I8x16ShrU(), base.op, shift.op);
}

// After fix
void WasmGraphBuilding::S128Shift(FullDecoder* decoder,
                                    const Value& base,
                                    const Value& shift,
                                    Value* result) {
    // Clamp shift count to valid range
    Node* clamped_shift = graph()->NewNode(
        machine()->Word32And(), shift.op,
        mcgraph()->Int32Constant(element_bits - 1));
    result->op = graph()->NewNode(
        machine()->I8x16ShrU(), base.op, clamped_shift);
}
```

### 4.4 Impact

This vulnerability received a CVSS score of 8.8 (High) and was actively exploited in the wild before the fix. Google classified it as a **Critical** severity bug with a $20,000 bug bounty reward.

### 4.5 Lessons

1. **SIMD operations are a high-risk surface**: The complexity of SIMD validation creates many opportunities for bugs
2. **JIT compiler validation must match interpreter validation**: The Liftoff JIT had a different validation than the Wasm interpreter
3. **Fuzzilli is effective for Wasm bugs**: DSL-based generation creates more valid Wasm programs than random bytes

## 5. Chrome ClusterFuzz Discoveries

### 5.1 Overview

ClusterFuzz has been running continuously since 2012, finding over **30,000 bugs** in Chrome. These include some of the most impactful browser security vulnerabilities.

### 5.2 Notable ClusterFuzz Discoveries

**CVE-2019-5786: V8 Type Confusion in TurboFan**
- **Bug**: TurboFan's type inference incorrectly narrowed the type of a variable after a branch, causing a type confusion
- **Found by**: ClusterFuzz with fuzzilli
- **Impact**: Remote code execution from a malicious website
- **Detection**: ASan detected a heap-buffer-overflow in the JIT-compiled code

**CVE-2020-6418: V8 Type Confusion in pop()**
- **Bug**: `Array.prototype.pop()` could cause type confusion when applied to a `TypedArray` with a detached `ArrayBuffer`
- **Found by**: ClusterFuzz with fuzzilli
- **Impact**: Remote code execution
- **Detection**: ASan detected an OOB write after `pop()` on a detached TypedArray

**CVE-2021-21224: V8 Incorrect Handling of Promise.allSettled**
- **Bug**: V8's implementation of `Promise.allSettled` had an incorrect type assumption that could be violated through prototype pollution
- **Found by**: ClusterFuzz with fuzzilli
- **Impact**: Remote code execution

**CVE-2023-30741: PDFium Type Confusion in Annotation**
- **Bug**: Type confusion in PDFium's annotation handling where a `PDFiumAnnotation` object was accessed through an incorrect type
- **Found by**: ClusterFuzz with PDFium fuzzer
- **Impact**: Sandbox escape from a malicious PDF

### 5.3 ClusterFuzz Impact Metrics

| Year | Total Bugs | Security Bugs | Critical/High |
|------|-----------|---------------|---------------|
| 2016 | 1,500 | 120 | 15 |
| 2017 | 2,000 | 180 | 22 |
| 2018 | 2,500 | 200 | 30 |
| 2019 | 3,000 | 250 | 35 |
| 2020 | 3,500 | 280 | 40 |
| 2021 | 4,000 | 300 | 45 |
| 2022 | 4,500 | 320 | 50 |
| 2023 | 5,000 | 350 | 55 |

## 6. syzkaller Kernel Bug Finds

### 6.1 Overview

syzkaller has found over **5,000 kernel bugs** since its introduction, with hundreds of CVEs assigned. The syzbot dashboard (syzkaller.appspot.com) continuously reports new findings.

### 6.2 Notable syzkaller Discoveries

**CVE-2017-2636: n_hdlc Race Condition**
- **Bug**: Race condition in the HDLC line discipline implementation
- **Found by**: syzkaller (2017)
- **Impact**: Use-after-free in `n_hdlc_send_frames`, leading to local privilege escalation

**CVE-2019-18683: V4L2 Use-After-Free**
- **Bug**: Race condition in the V4L2 video subsystem's buffer management
- **Found by**: syzkaller (2019)
- **Impact**: Use-after-free in `vivid_stop_streaming`, leading to local privilege escalation
- **Notable**: Found by stressing the race between `VIDIOC_STREAMON` and `VIDIOC_STREAMOFF` ioctls

**CVE-2021-4159: io_uring Use-After-Free**
- **Bug**: UAF in `io_sqe_files_register` when registering fixed files
- **Found by**: syzkaller (2021)
- **Impact**: Local privilege escalation from unprivileged user

**CVE-2022-4280: io_uring Double Free**
- **Bug**: Double free in `io_sqe_buffers_register`
- **Found by**: syzkaller (2022)
- **Impact**: Local privilege escalation; the double free can be exploited to gain arbitrary write

**CVE-2023-5345: fsverity OOB Write**
- **Bug**: Out-of-bounds write in `fsverity_verify_signature` due to incorrect buffer size calculation
- **Found by**: syzkaller (2023)
- **Impact**: Local privilege escalation through filesystem corruption

### 6.3 syzkaller Bug Distribution by Subsystem

| Subsystem | Bugs Found | % of Total |
|-----------|-----------|------------|
| Network | 1,200 | 24% |
| Filesystem | 800 | 16% |
| io_uring | 500 | 10% |
| eBPF | 400 | 8% |
| USB | 350 | 7% |
| Bluetooth | 300 | 6% |
| Media/V4L2 | 250 | 5% |
| Crypto | 200 | 4% |
| Other | 1,000 | 20% |

## 7. Shacham Group Research

### 7.1 Overview

Professor Hovav Shacham's research group at UT Austin has produced seminal work on fuzzing and vulnerability research, including:

### 7.2 Notable Contributions

**Rode0day (2019)**
- Fuzzing competition using binaries from DARPA CGC
- Participants fuzzed challenge binaries to find as many bugs as possible
- Showed that AFL++ significantly outperforms AFL and other fuzzers
- Established benchmarks for fuzzer comparison

**EquivRenaming and EquivChecking**
- Techniques for determining whether two binary functions are equivalent
- Applications to patch analysis and vulnerability discovery

**Not All Bugs Are Fuzzed Equal (2020)**
- Study of which bugs fuzzers can and cannot find
- Analysis of bug depth (how many conditions must be satisfied)
- Proposed bug depth as a metric for fuzzer comparison

## 8. Android GPU Driver Bugs Found by Fuzzing

### 8.1 Overview

Android GPU drivers (particularly ARM Mali and Qualcomm Adreno) have been a rich source of security bugs found through fuzzing. These bugs are particularly dangerous because:
- GPU drivers process data from untrusted apps
- GPU driver bugs can be triggered from WebGL/WebGPU content
- GPU driver vulnerabilities can lead to kernel compromise from an untrusted app

### 8.2 ARM Mali GPU Driver Bugs

**CVE-2021-28664: Mali GPU UAF**
- **Bug**: Use-after-free in `mali_kbase_mem_linux` when a GPU memory region is freed while still referenced
- **Found by**: Symlink-based fuzzing + manual analysis
- **Impact**: Android local privilege escalation from untrusted app to kernel

**CVE-2022-22706: Mali GPU OOB Write**
- **Bug**: OOB write in `mali_kbase_gpu_id` when processing GPU commands with invalid IDs
- **Found by**: GraphicsFuzz shader mutation
- **Impact**: Kernel compromise from a malicious Android app
- **Notable**: Exploited in the wild by NSO Group and other surveillance vendors

**CVE-2022-46395: Mali GPU OOB Read**
- **Bug**: OOB read in `mali_kbase_vm_aarch64` when handling address translation for out-of-range GPU addresses
- **Found by**: Symlink-based fuzzing
- **Impact**: Kernel memory leak (can bypass KASLR)

**CVE-2023-4211: Mali GPU UAF in Memory Pool**
- **Bug**: Use-after-free in `mali_kbase_mem_pool_release` when a memory pool page is freed while the GPU still references it
- **Found by**: Fuzzing + manual analysis
- **Impact**: Android kernel compromise

### 8.3 Qualcomm Adreno GPU Driver Bugs

**CVE-2022-25664: Adreno GPU Integer Overflow**
- **Bug**: Integer overflow in GPU command buffer size calculation
- **Found by**: GPU command fuzzing
- **Impact**: Heap overflow leading to kernel compromise

**CVE-2023-33107: Adreno GPU Use-After-Free**
- **Bug**: UAF in GPU synchronization object handling
- **Found by**: Symlink-based fuzzing
- **Impact**: Kernel compromise from a malicious app

### 8.4 GPU Fuzzing Techniques

1. **Shader mutation (GraphicsFuzz)**: Mutate GLSL/SPIR-V shaders to trigger driver bugs
2. **GPU command fuzzing**: Mutate GPU command buffers submitted to the driver
3. **Memory management fuzzing**: Stress GPU memory allocation/deallocation patterns
4. **Synchronization fuzzing**: Fuzz GPU fence/sync object operations
5. **Combined CPU-GPU fuzzing**: Coordinate CPU-side operations with GPU command execution

## 9. Real-World Crash Triage to PoC to Disclosure Workflow

### 9.1 Complete Workflow Example

This section traces a complete vulnerability from crash discovery through disclosure, using a hypothetical but realistic scenario.

**Step 1: Crash Discovery**

```
==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x6020000001f8
READ of size 8 at 0x6020000001f8 thread T0
    #0 0x401234 in process_request /src/server.c:42
    #1 0x401567 in handle_connection /src/server.c:78
freed by thread T0 here:
    #0 0x4a1bcd in free
    #1 0x402345 in cleanup_session /src/server.c:55
previously allocated by thread T0 here:
    #0 0x4a1bcd in malloc
    #1 0x401890 in create_session /src/server.c:30
```

**Step 2: Crash Minimization**

```bash
# Minimize the crashing input
afl-tmin -i crashes/id:000001 -o min_crash -- ./target_asan @@

# Result: 3-byte input (down from 1KB original)
xxd min_crash
00000000: 0301 00                                  ...
```

**Step 3: Root Cause Analysis**

```bash
# Analyze with GDB
gdb --args ./target_asan min_crash

(gdb) run
# Crashes at server.c:42
(gdb) frame 0
(gdb) list
37  void process_request(Session *sess, Request *req) {
38      // BUG: sess might have been freed by another thread
39      // handling the same session's cleanup request
40      // ...
41      // This is a race condition:
42      printf("Processing: %s\n", sess->name);  // UAF HERE
43  }

(gdb) print sess
$1 = (Session *) 0x6020000001d0
(gdb) print *sess
Cannot access memory at address 0x6020000001d0  // Already freed
```

**Root cause**: `process_request` holds a raw pointer to a `Session` object that can be freed by `cleanup_session` in a concurrent handler. This is a **use-after-free race condition**.

**Step 4: Exploitability Assessment**

The freed `Session` object is 64 bytes. After freeing, it goes to glibc's tcache for 64-byte chunks. We can replace it with a string object of the same size:

```c
// Exploit strategy:
// 1. Create a Session (64-byte allocation)
// 2. Trigger cleanup_session (frees the Session, goes to tcache)
// 3. Allocate a controlled string of 64 bytes (replaces freed Session)
// 4. process_request reads from the Session, but it's now the string
// 5. sess->name now points to attacker-controlled data
// 6. Further dereference of sess->name gives controlled read/write
```

**Step 5: PoC Development**

```python
import socket
import struct
import threading

def exploit():
    # Step 1: Create session
    s = socket.socket()
    s.connect(('target', 12345))
    s.send(b'CREATE_SESSION user1\n')
    
    # Step 2: Start cleanup race
    def cleanup_racer():
        s2 = socket.socket()
        s2.connect(('target', 12345))
        for _ in range(1000):
            s2.send(b'CLEANUP_SESSION user1\n')
        s2.close()
    
    t = threading.Thread(target=cleanup_racer)
    t.start()
    
    # Step 3: Spray replacement objects
    for _ in range(100):
        s3 = socket.socket()
        s3.connect(('target', 12345))
        # Send a string that's exactly 64 bytes when allocated
        payload = b'FILL_SESSION ' + b'A' * 48 + b'\n'
        s3.send(payload)
        s3.close()
    
    # Step 4: Trigger use-after-free
    for _ in range(1000):
        s.send(b'PROCESS_SESSION user1\n')
    
    t.join()
    s.close()

exploit()
```

**Step 6: Responsible Disclosure**

```
Subject: [Security] Use-After-Free in session handling (CVSS 7.8)

Summary:
A use-after-free vulnerability exists in the session handling code
of [product] version [version]. An attacker can exploit this race
condition to achieve arbitrary code execution.

Details:
The process_request() function in server.c:42 accesses a Session
object after it has been freed by cleanup_session(). The race
window is wide enough to be reliably exploitable.

Impact:
Local privilege escalation / Remote code execution (depending on
network accessibility).

Reproduction:
1. Connect to the server
2. Create a session
3. Concurrently send cleanup and process requests
4. Spray replacement objects to control freed memory
5. Process request reads from replaced object

Proof of Concept:
[poc.py attached]

Affected Versions:
[version range]

Suggested Fix:
Use reference counting for Session objects. process_request should
increment the reference count before accessing the session, and
decrement it after. cleanup_session should only free when the
reference count reaches zero.

Credit:
[Researcher Name]

Disclosure Timeline:
2024-01-15: Reported to vendor
2024-01-20: Vendor confirmed
2024-02-10: Fix committed
2024-04-15: Public disclosure (90 days)
```

## 10. CVE-2025-0072: MTE Bypass via Mali GPU on Pixel 8 (2025)

### 10.1 The Bug

CVE-2025-0072 demonstrated the second production MTE bypass on Pixel 8. Man Yue Mo discovered a Mali GPU CSF (Command Stream Frontend) queue binding vulnerability that creates a page use-after-free. Unlike CVE-2023-6241 which used GPU operations to access freed memory, CVE-2025-0072 exploits the fact that freed pages remain accessible through user-space mappings established by `mgm_vmf_insert_pfn_prot`.

### 10.2 MTE Bypass Mechanism

The key insight is that GPU memory is NOT tagged by MTE. When a Mali GPU page is freed at the kernel level but remains mapped in user-space through the GPU driver's memory management, accessing it through the user-space mapping completely bypasses MTE tag checking. The exploit chain proceeds:

1. Allocate GPU memory regions via Mali GPU driver
2. Trigger the CSF queue binding bug, causing a page-level UAF
3. The freed page is reclaimed as a kernel page table page
4. Access the page through the still-valid user-space GPU mapping (no MTE check)
5. Corrupt page table entries to gain arbitrary physical memory read/write

### 10.3 Significance

This case study demonstrates a fundamental limitation of MTE on devices with complex GPU subsystems: the GPU driver's memory management creates a parallel path that circumvents MTE protections. Any vulnerability in the GPU driver can potentially serve as an MTE bypass, making the GPU attack surface critical for MTE-protected devices.

## 11. Cross-Cutting Lessons

### 11.1 From All Case Studies

1. **Fuzzing works**: The most impactful vulnerabilities of the last decade were found by fuzzing
2. **Variant analysis multiplies value**: Finding one bug should lead to finding many variants
3. **Operational monitoring finds bugs too**: DirtyPipe was found from production anomalies
4. **Small changes cause big vulnerabilities**: DirtyPipe was a one-line bug
5. **Race conditions are under-explored**: Most fuzzers are single-threaded; race-aware fuzzing is an open problem
6. **GPU drivers are the new kernel**: High-value, under-fuzzed, complex code. GPU memory paths bypass MTE on hardened devices.
7. **Crash triage is critical**: 40,000 OSS-Fuzz crashes are useless without good triage
8. **Disclosure matters**: Responsible disclosure saves users from exploitation
9. **Mitigations create bypass markets**: Each new mitigation (MTE, kCFI, PAC) spawns research into bypass techniques. The GPU attack surface is the current primary bypass vector for MTE-protected Android devices.

## References

[1] Google. *OSS-Fuzz: Continuous Fuzzing for Open Source Software*. https://google.github.io/oss-fuzz/

[2] Kellermann, M. (2022). *The Dirty Pipe Vulnerability*. https://dirtypipe.cm4all.com/

[3] Coward, P. (2016). *Dirty COW (CVE-2016-5195)*. https://dirtycow.ninja/

[4] Groß, S. (2024). *fuzzilli: Fuzzing for JavaScript JIT Compiler Bugs*. Google Project Zero. https://github.com/googleprojectzero/fuzzilli

[5] Shacham, H. *Rode0day Fuzzing Competition*. https://rode0day.mit.edu/

[6] Google. *ClusterFuzz*. https://github.com/google/clusterfuzz

[7] ARM Mali GPU Security. *ARM Mali GPU Driver Vulnerabilities*. https://developer.arm.com/Arm%20Security%20Center/Mali%20GPU%20Driver%20Vulnerabilities

[8] Serebryany, K. (2016). *Announcing OSS-Fuzz*. Google Security Blog. https://security.googleblog.com/2016/12/announcing-oss-fuzz-continuous-fuzzing.html

[9] CVE-2016-5195. *Dirty COW: Race Condition in mm/cow*. https://nvd.nist.gov/vuln/detail/CVE-2016-5195

[10] CVE-2022-0847. *DirtyPipe: File Overwrite via Pipe Buffer Flag*. https://nvd.nist.gov/vuln/detail/CVE-2022-0847

[11] CVE-2024-0519. *V8 WebAssembly SIMD OOB Write*. https://nvd.nist.gov/vuln/detail/CVE-2024-0519

[12] CVE-2019-5786. *V8 Type Confusion in TurboFan*. https://nvd.nist.gov/vuln/detail/CVE-2019-5786

[13] CVE-2022-22706. *ARM Mali GPU OOB Write*. https://nvd.nist.gov/vuln/detail/CVE-2022-22706

[14] Vyukov, D. (2015). *syzkaller: Kernel Fuzzer*. https://github.com/google/syzkaller

[15] Böhme, M., Pham, V.T., & Roychoudhury, A. (2017). *Coverage-Based Greybox Fuzzing as Markov Chain*. IEEE S&P.

[16] Fioraldi, A., et al. (2020). *AFL++: Combining Incremental Steps of Fuzzing Research*. USENIX WOOT.

[17] Chen, T., et al. (2023). *GraphicsFuzz: Shader Compiler Fuzzing*. ISSTA.

[18] Miller, B.P., Fredriksen, L., & So, B. (1990). *An Empirical Study of the Reliability of UNIX Utilities*. Communications of the ACM.

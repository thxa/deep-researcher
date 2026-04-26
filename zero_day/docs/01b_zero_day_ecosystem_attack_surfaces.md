# Zero-Day Vulnerability Ecosystem & Attack Surface Analysis

> A comprehensive reference for CTF competitors and security researchers on zero-day economics, attack surface mapping, vulnerability classes, N-day methodology, and the adversarial mindset.

---

## Table of Contents

1. [Zero-Day Economics & Markets](#1-zero-day-economics--markets)
2. [Attack Surface Mapping for Zero-Day Research](#2-attack-surface-mapping-for-zero-day-research)
3. [Vulnerability Classes by Exploit Type](#3-vulnerability-classes-by-exploit-type)
4. [Zero-Day Discovery vs N-Day Research](#4-zero-day-discovery-vs-n-day-research)
5. [The Mindset of a Zero-Day Hunter](#5-the-mindset-of-a-zero-day-hunter)

---

## 1. Zero-Day Economics & Markets

### 1.1 Grey, White, and Black Markets

The zero-day market operates across three tiers differentiated by legitimacy, transparency, and end-use:

**White Market** — Bug bounty programs and coordinated disclosure platforms. Companies like Google (VRP), Microsoft (MSRC), Apple, and Meta pay for vulnerabilities under terms that presuppose responsible disclosure. Platforms like HackerOne and Bugcrowd aggregate these programs. Payouts range from a few hundred dollars (low-severity web bugs) to $500K+ (full-chain mobile exploits). The 2024 Google VRP awards exceeded $10M total.

**Grey Market** — Brokers and intermediaries who acquire zero-days and resell them, typically to government clients. Zerodium, Exodus Intelligence, and NSO Group operate in this space. Sales are technically legal in many jurisdictions but ethically debatable since exploits may be used against civilian targets. Grey market prices dwarf white market payouts by 5–50x.

**Black Market** — Forums, darknet marketplaces, and private channels where exploits are sold to criminal operators. Zero-day exploits for banking Trojans, ransomware groups, and APT actors trade here. Attribution is difficult, quality is variable, and deals are conducted in cryptocurrency. Prices can be higher than grey market because the buyer is desperate and has no alternative procurement channel.

| Dimension | White Market | Grey Market | Black Market |
|---|---|---|---|
| Legality | Fully legal | Legal gray zone | Illegal |
| Transparency | High (public programs) | Low (private deals) | None |
| Buyer | Vendor | Government/intelligence | Criminal/APT |
| Price Range | $500–$500K | $50K–$2.5M | $100K–$5M+ |
| Ethics | Responsible disclosure | Dual-use | Malicious use |

### 1.2 Bug Bounty Programs vs Broker Prices

The price disparity between responsible disclosure and broker sales is the central economic tension in vulnerability research:

| Vulnerability Type | Bug Bounty Payout | Broker/Zerodium Price | Ratio |
|---|---|---|---|
| iOS Remote Code Execution | $100K–$500K | $1.5M–$2.5M | 5–10x |
| Android RCE + LPE | $100K–$150K | $2.0M–$2.5M | 15–20x |
| Windows RCE | $50K–$250K | $100K–$500K | 2–5x |
| Chrome Full Chain | $60K–$150K | $500K–$1M | 5–8x |
| Linux Local Priv Esc | $5K–$30K | $30K–$80K | 3–5x |
| Messaging App RCE | $50K–$100K | $500K–$1.5M | 10–15x |

This disparity explains why many top researchers choose brokers over bug bounties. A researcher who discovers an iOS RCE must choose between Apple's ~$500K maximum payout and Zerodium's $2M offer — and Zerodium doesn't require a 90-day disclosure timeline that might burn the exploit before payment clears.

**Notable bug bounty milestones:**
- Google paid $6.5M+ in 2023 across all VRP programs
- Apple's Security Bounty offers up to $2M for targeted attack chains
- Microsoft's highest single payout exceeded $250K
- The average time-to-triage across major programs: 14 days

### 1.3 Government Procurement

Intelligence agencies are the largest consumers of zero-day exploits:

**NSA (US)** — Operates the Tailored Access Operations (TAO) unit. Maintains an exploit catalog (partially revealed in the Shadow Brokers leak, 2017). Procures through defense contractors like Cyberpoint International and Hacking Team. Budget lines for "vulnerability equities" — the internal debate over whether to disclose or hoard a zero-day — are classified but estimated in the hundreds of millions.

**GCHQ (UK)** — Works through the Joint Threat Research Intelligence Group (JTRIG). DOCUMENT reveals use of weaponized zero-days for "online covert action." Coordinates closely with Five Eyes partners.

**Unit 8200 (Israel)** — The incubator for NSO Group's Pegasus and the talent pipeline for Israel's offensive cyber industry. Many zero-day brokers trace lineage to Unit 8200 alumni.

**Other notable buyers:**
- BND (Germany) — Operates the " Bundeskriminalamt's Central Office for Information Technology" procurement
- DGSE (France) — Contracts through AMOSS (Agence Nationale de la Sécurité des Systèmes d'Information)
- MSS/PLA (China) — Suspected of operating internal zero-day discovery teams, reducing need for external procurement

The **Vulnerabilities Equities Process (VEP)** in the US formally decides whether the government discloses a zero-day to the vendor or retains it. In practice, the vast majority of discovered vulnerabilities are retained, with disclosure occurring only in exceptional circumstances.

### 1.4 Price Ranges by Vulnerability Type

Prices are driven by **target scarcity**, **exploit reliability**, and **persistence requirements**:

| Target | Vuln Type | Price Range | Notes |
|---|---|---|---|
| iOS (any version) | RCE | $1M–$2.5M | Highest prices; small attack surface, frequent patching |
| Android (any version) | RCE + LPE chain | $1.5M–$2.5M | Requires chain for full compromise |
| Chrome | Full chain (RCE+SBX) | $500K–$1M | Renderer + sandbox escape |
| Safari | Full chain | $800K–$1.5M | WebKit JIT bugs are premium |
| Windows | RCE (remote) | $100K–$500K | Large attack surface = more competition |
| Windows | LPE | $40K–$200K | Elevated prices for post-compromise persistence |
| Linux | LPE (kernel) | $30K–$80K | Lower prices due to open-source patch speed |
| Linux | RCE (network daemon) | $20K–$60K | Open-source transparency hurts pricing |
| macOS | LPE | $40K–$100K | Growing market as enterprise adoption rises |
| VMware/Hypervisors | VM Escape | $100K–$500K | Cloud disruption value is enormous |
| Routers/IoT | RCE | $5K–$50K | Low prices reflect poor target value and high fragmentation |
| Messaging (Signal, WhatsApp) | RCE | $500K–$1.5M | End-to-end encryption + high-value targets = premium |

**Key observation:** iOS and Android zero-days command the highest prices not because they are the hardest to find (they aren't), but because **the buyers place the highest value on mobile access** — people carry their phones everywhere, and phones contain the most intimate data.

### 1.5 The Business Model of Zero-Day Brokers

**Zerodium** — Founded by Chaouki Bekrar. Publishes a public price list that acts as a ceiling for the market. Acquires exclusivity — the researcher cannot sell the same bug elsewhere or disclose it. Zerodium then resells to government clients, marking up the price 3–10x. Their public prices ($2.5M for Android full chain) represent the acquisition cost, not the resale price, which may exceed $10M for exclusive access to a single client.

**Exodus Intelligence** — Founded by Aaron Portnoy. More research-oriented; employs full-time researchers alongside acquiring from independents. Sells subscriptions to its vulnerability intelligence feed, which includes zero-day details and exploitation guidance. Clients include defense contractors, forensic companies, and intelligence agencies.

**Business model economics:**
1. Acquire exclusive exploit: $500K–$2.5M
2. Validate and weaponize: $100K–$300K internal cost
3. Resell to 3–5 clients: $2M–$10M each
4. Revenue per exploit: $6M–$50M total over lifetime
5. Exploit burns (patched) within 6–18 months typically
6. The broker must constantly acquire new exploits to replace burned ones

This creates a **pipeline model** — brokers need a steady stream of incoming exploits because their existing inventory is constantly being depleted. The production rate of novel zero-days worldwide is estimated at 50–200 per year for high-value targets (mobile, browser, OS kernel).

---

## 2. Attack Surface Mapping for Zero-Day Research

### 2.1 Systematic Attack Surface Identification

The foundational principle: **every boundary between trust domains is an attack surface.** The goal of attack surface mapping is to enumerate all such boundaries and then prioritize the code that crosses them.

**Methodology:**

```
1. Enumerate trust boundaries
   ┌─────────────┐         ┌─────────────┐
   │  Untrusted  │ ──────► │   Trusted   │
   │  (Network)  │         │  (Kernel)   │
   └─────────────┘         └─────────────┘
         │                       ▲
         │    ┌──────────┐      │
         └───►│  Sandbox │──────┘
              │  (User)  │
              └──────────┘

2. For each boundary, find code that processes data crossing it
3. Prioritize by: reachability × complexity × privilege gain
4. Audit the highest-priority code paths first
```

**Practical steps:**
1. Identify all entry points (network sockets, file parsers, IPC endpoints, device files)
2. Map the data flow from entry points to privileged code
3. Identify parser code, deserialization logic, and state machines
4. Look for hand-written parsers (more bug-prone than generated ones)
5. Filter for code that runs in a privileged context or can influence privileged execution

### 2.2 Network-Facing Attack Surfaces

Network-facing code is the highest priority because it requires zero user interaction and no local access.

**Parsing code — the goldmine:**

Every protocol parser is an attack surface. The more complex the protocol, the more bugs hide in it:

| Protocol/Service | Key Attack Surface | Notable CVEs |
|---|---|---|
| HTTP servers | Header parsing, chunked encoding, TLS handshake | CVE-2021-44228 (Log4Shell), CVE-2017-7642 |
| DNS resolvers | Response parsing, AXFR zone transfers | CVE-2023-50387 (KeyTrap), CVE-2015-5477 |
| SMB/CIFS | Named pipe handling, dialect negotiation | CVE-2017-0144 (EternalBlue) |
| SMTP | MAIL FROM parsing, MIME handling | CVE-2019-18845 |
| SSH | Key exchange, channel handling | CVE-2023-38408 (OpenSSH agent) |
| RDP | Channel negotiation, bitmap decompression | CVE-2019-0708 (BlueKeep) |
| gRPC/Protobuf | Deserialization, streaming | CVE-2023-33953, CVE-2023-32319 |

**How to systematically audit network daemons:**

```bash
# 1. Find all network-facing services
ss -tlnp  # TCP listeners
ss -ulnp  # UDP listeners

# 2. For each service, identify the parsing entry points
# Example: OpenWiFi stack (802.11 frame parsing)
#   - Look for ieee80211_* functions in kernel source
#   - Trace from netif_receive_skb → 802.11 handler → frame parser

# 3. Identify complex protocol features
#   - Compression (zlib in HTTP, deflate in SSH)
#   - Encryption (TLS implementations, crypto handshakes)
#   - State machines with many states
#   - Backward compatibility code paths
```

**EternalBlue case study (CVE-2017-0144):**

The SMBv1 `SrvOs2FeaListSizeToNt` function had a size miscalculation that caused a buffer overflow when converting OS/2 FEA lists to NT FEA lists. The bug existed because:
1. SMBv1 preserved backward compatibility with OS/2 format (20+ years of technical debt)
2. The conversion function used different integer types for size calculations (`DWORD` vs `USHORT`)
3. The truncation during conversion was not validated
4. The resulting heap overflow was exploitable via a standard pool grooming technique

**Practical tip:** Look for **protocol downgrade mechanisms** and **backward compatibility code**. These are consistently bug-rich because they combine old, under-tested code paths with complex branching logic.

### 2.3 Local Attack Surfaces

Local attack surfaces require code execution on the target, but they are the path to privilege escalation:

**IPC mechanisms:**
```bash
# D-Bus (Linux desktop)
busctl --user list                    # User session services
busctl --system list                  # System services
dbus-send --system --print-reply \
  --dest=org.freedesktop.NetworkManager \
  /org/freedesktop/NetworkManager \
  org.freedesktop.DBus.Introspectable.Introspect

# Unix domain sockets
ss -xlp  # List all Unix domain socket listeners

# /proc and /sys attack surface
ls /proc/sys/kernel/  # Tunable kernel parameters
ls /sys/kernel/debug/ # Debugfs (if mounted)

# Netlink sockets
ip -s link show    # RTM_GETLINK
ss -nl             # Netlink listeners
```

**File format parsers — the local exploit goldmine:**

Every program that opens untrusted files is an attack surface:

| Format | Applications | Risk |
|---|---|---|
| PDF | viewers, indexers, preview engines | High — complex format with scripting |
| Office (OOXML) | LibreOffice, MS Office | High — macro expansion, embedded objects |
| Image formats | ImageMagick, libpng, libtiff | Medium — many obscure formats |
| Media (video/audio) | ffmpeg, VLC, media players | Medium — complex codec parsing |
| Fonts | FreeType, fontconfig | Medium — tricky binary format |
| Archive (zip, tar) | libarchive, zlib | Medium — path traversal, decompression bombs |

**SUID/SGID binaries:**

```bash
# Find all SUID binaries on a Linux system
find / -perm -4000 -type f 2>/dev/null

# Common SUID binaries that have had privilege escalation bugs:
# - pkexec (CVE-2021-4034, PwnKit)
# - sudo (CVE-2021-3156, Baron Samedit)
# - chsh, chfn, newgrp (historical)
# - passwd (historical)
# - Xorg (CVE-2018-14665)
# - nginx (when setuid root for port 80 binding)
```

**PwnKit (CVE-2021-4034) case study:**

`pkexec` was SUID root and processed arguments from `argv` without validating that `argc > 0`. By calling `pkexec` with an empty argument list (via `execve` with an empty `argv`), the program read from `envp` as if it were `argv`, leading to an out-of-bounds write that could be leveraged for full root privilege escalation. This bug existed for 12+ years across every major Linux distribution.

### 2.4 Kernel Attack Surfaces

The kernel is the ultimate local attack surface — compromising it means ring 0 access (or ring -1 with virtualization).

**Syscall surface:**

```c
// Every syscall is an attack surface. Focus on complex ones:
// - bpf() — eBPF verifier bugs (CVE-2022-0500, CVE-2023-2163)
// - perf_event_open() — numerous bugs, complex permission logic
// - io_uring_setup() — rapidly expanding attack surface
// - process_vm_readv/writev() — cross-process memory access
// - keyctl() — keyring management, complex permission model
// - add_key() / request_key() — key type handling
// - userfaultfd() — use-after-free primitive enabler
// - clone3() — PID namespace handling
```

**ioctl surface — the hidden goldmine:**

Device drivers expose hundreds of custom ioctls. Each one is a potential vulnerability:

```bash
# Enumerate device files accessible by unprivileged users
find /dev -readable -not -user root 2>/dev/null

# Find ioctls in kernel modules
grep -r "unlocked_ioctl\|compat_ioctl" linux/drivers/
# Each of these is a callable function from userspace
```

**eBPF attack surface:**

eBPF has been a prolific source of kernel vulnerabilities. The verifier must prove safety of arbitrary user-supplied programs — an extremely difficult problem:

| CVE | Year | Bug Type | Impact |
|---|---|---|---|
| CVE-2022-0500 | 2022 | Incorrect bounds tracking | Local privilege escalation |
| CVE-2022-23222 | 2022 | Pointer arithmetic bypass | LPE |
| CVE-2023-2163 | 2023 | Incorrect branch pruning | LPE |
| CVE-2021-3490 | 2021 | Register bounds mismatch | LPE |
| CVE-2020-8835 | 2020 | Map value bounds | LPE |
| CVE-2017-16995 | 2017 | ALU32 sign extension | LPE |

**The lesson:** eBPF is an attack surface because it combines **user-controllable programs** with **a complex verifier** that must be correct for all inputs. Any verifier bug that lets a malicious program pass verification is an immediate LPE. The same pattern applies to any in-kernel domain-specific language or just-in-time compiler.

**Namespace and cgroup surface:**

```bash
# Each namespace type adds attack surface for container escapes
# user namespace — unprivileged user can "become root" in a namespace
#   CVE-2022-3865, CVE-2023-0361 (OCI bypass)
# network namespace — netfilter rules, routing
# mount namespace — pivot_root, mount propagation
# pid namespace — signal handling, /proc filesystem
```

**Netfilter/iptables surface:**

```c
// Netfilter is historically one of the most bug-rich kernel subsystems
// CVE-2022-32250 — nf_tables UAF
// CVE-2023-32233 — nf_tables set element UAF
// CVE-2023-35001 — nft_validate_register_store integer overflow
// CVE-2022-34918 — nft_set_elem UAF
// CVE-2021-22555 — nft_set destruction UAF

// Why so many bugs?
// 1. Complex state machine for rule processing
// 2. Transactional model with abort/rollback paths
// 3. User-controllable data structures (sets, maps, chains)
// 4. RCU interaction with reference counting
// 5. Per-CPU data structures with subtle race conditions
```

### 2.5 Browser Attack Surfaces

Browsers are the most attacked software on earth. Their attack surface is enormous:

```
┌─────────────────────────────────────────────┐
│                  Browser                     │
│                                              │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐ │
│  │ JS Engine │  │  Renderer │  │  Network │ │
│  │ V8/JSC/SM│  │   Blink   │  │  Stack   │ │
│  └────┬─────┘  └─────┬─────┘  └────┬─────┘ │
│       │              │              │       │
│  ┌────▼──────────────▼──────────────▼─────┐ │
│  │           Sandbox (Broker)              │ │
│  └────────────────┬───────────────────────┘ │
│                   │ IPC                      │
│  ┌────────────────▼───────────────────────┐ │
│  │         Kernel / OS                     │ │
│  └────────────────────────────────────────┘ │
└─────────────────────────────────────────────┘
```

**JavaScript engine attack surfaces:**

| Component | Attack Vector | Notable Bugs |
|---|---|---|
| JIT compiler | Type confusion, incorrect optimization | CVE-2022-1096 (V8 Maglev), CVE-2021-21148 |
| Garbage collector | UAF during concurrent collection | CVE-2019-5794 (V8) |
| RegExp engine | Exponential backtracking, type confusion | CVE-2020-16006 |
| Object model | Prototype pollution, accessor chain bugs | Various |
| Array operations | Side effects during element kind transitions | CVE-2020-6418 (V8 Array.pop) |
| WebAssembly | Bounds checking bugs in codegen | CVE-2022-4230 |

**V8 exploitation pattern:**
1. Trigger a type confusion or bounds check elimination in the JIT compiler
2. Achieve arbitrary read/write within the renderer process
3. Escape the sandbox using a separate sandbox escape bug (e.g., via Mojo IPC)
4. Achieve code execution in the browser process

**Other browser surfaces:**
- **WebGL** — GPU shader compilation is a massive attack surface. Driver bugs in shader compilers are exploitable through WebGL. CVE-2024-4671 (Chrome WebGL).
- **WebRTC** — Complex peer-to-peer protocol with ICE/STUN/DTLS. Multiple implementation bugs. CVE-2023-41993 (Safari WebRTC).
- **WebAudio** — Audio processing graph with user-controlled parameters. CVE-2022-22624.
- **Image decoding** — AVIF, WebP, JPEG XL decoders. CVE-2023-4863 (WebP heap buffer overflow, exploited in the wild).

### 2.6 Hypervisor Attack Surfaces

Hypervisor escapes are the highest-impact vulnerability class in cloud environments:

**VM Exit handlers — the primary surface:**

Every time a guest performs certain operations (I/O, privileged instructions, MSR access), a VM exit occurs and the hypervisor must handle it. Each handler is an attack surface:

```c
// KVM VM exit handlers (linux/arch/x86/kvm/x86.c)
// Key surfaces:
// - KVM_EXIT_IO (I/O port access)
// - KVM_EXIT_MMIO (memory-mapped I/O)
// - KVM_EXIT_HYPERCALL (paravirtual calls)
// - KVM_EXIT_RDMSR/WRMSR (model-specific register access)
// - KVM_EXIT_EXCEPTION (guest exception reflection)
```

**Paravirtual device surfaces:**

| Device | Attack Surface | Notable CVEs |
|---|---|---|
| virtio-net | Packet processing, offload features | CVE-2021-3490-like issues |
| virtio-blk | Block request parsing | CVE-2020-10717 |
| virtio-fs | Filesystem operations | CVE-2019-18845 |
| virtio-gpu | Command buffer parsing | CVE-2019-14378 |
| virtio-balloon | Page balloon stats | Various |
| virtio-serial | Port I/O | Various |

**Hyper-V specific:**
- CVE-2021-38645 — VMBus oxygen UAF
- CVE-2020-17087 — vmswitch heap overflow
- Multiple Hyper-V bugs discovered by the QEMU/KVM research community ported to Hyper-V

**Exploitation strategy:**
1. Map all paravirtual devices exposed to the guest
2. Identify the most complex device (usually network or GPU)
3. Fuzz the device emulation code from within the guest
4. Find memory corruption in the hypervisor process
5. Escape to the host (or another VM on the same host)

---

## 3. Vulnerability Classes by Exploit Type

### 3.1 Code Execution Vulnerabilities

**Typical root causes:**
- Buffer overflows (stack, heap, off-by-one)
- Type confusion (JIT engines, C++ virtual dispatch)
- Use-after-free (dangling pointers, object lifetime bugs)
- Integer overflows leading to undersized allocations
- Format string bugs
- Command injection (web, shell interpretation)
- Deserialization flaws (Java, Python pickle, PHP unserialize)

**Common patterns:**

```c
// Pattern 1: Size calculation overflow
uint32_t count = get_count();
uint32_t size = count * sizeof(struct item);  // overflow if count is large
struct item *items = malloc(size);             // undersized allocation
for (uint32_t i = 0; i < count; i++) {
    items[i] = parse_item(data);               // heap overflow
}

// Pattern 2: TOCTOU (Time-of-check-to-time-of-use)
// Check
if (access(filename, R_OK) == 0) {
    // ... attacker renames filename to symlink here ...
    // Use
    fd = open(filename, O_RDONLY);  // opens different file
}

// Pattern 3: UAF with type confusion (common in browsers)
let obj = new MaliciousObject();
// arr[0] is optimized to expect type Array
// but obj's callback changes arr's element kind
arr[0] = obj.trigger();  // JIT assumed Array, got Object
// now arr[0].length is read as a controlled value — type confusion
```

**Difficulty:** Moderate to Extreme. Stack overflows are "easy" (RIP control in one write), but modern mitigations (ASLR, stack canaries, CFI, PAC) make exploitation significantly harder. UAF exploitation in browsers requires deep understanding of GC internals, heap layout, and type confusion primitives.

**Notable examples:**
- CVE-2021-3156 (Baron Samedit) — heap overflow in sudo's `parse_args()`, exploitable by any local user for root
- CVE-2021-4034 (PwnKit) — argv/envp confusion in pkexec, root for any local user
- CVE-2023-44487 (HTTP/2 Rapid Reset) — protocol-level abuse causing DoS, not RCE, but shows how parsing complexity enables abuse

### 3.2 Denial of Service

**Typical root causes:**
- Resource exhaustion (memory, CPU, file descriptors, connections)
- Infinite loops in parsing or state machines
- Algorithmic complexity (regex catastrophic backtracking)
- Lock contention and deadlock
- Uncontrolled recursion
- Integer division by zero

**Common patterns:**

```c
// Pattern: ReDoS (Regular Expression Denial of Service)
// CVE-2023-36054 (krb5), CVE-2023-51533 (OWASP-java-html-sanitizer)
// Regex like /(a+)+$/ on input "aaaaaaaaaaaaX" causes exponential backtracking

// Pattern: Hash collision DoS (CVE-2011-4858 and successors)
// Thousands of colliding hash keys cause hash table O(n²) behavior
// Input: {"a":1, "aa":1, "aaa":1, ...} where all keys hash to same bucket

// Pattern: Uncontrolled allocation
// CVE-2023-44487 (HTTP/2 Rapid Reset)
// Client sends H2 HEADERS + RST_STREAM in rapid succession
// Server allocates resources for each stream but they're immediately canceled
// Net effect: server exhausts resources while client spends minimal effort
```

**Difficulty:** Easy. DoS vulnerabilities are typically easier to find than RCE because they only require triggering an unexpected state, not controlling the outcome. However, they're lower severity in most bug bounty programs.

### 3.3 Information Disclosure

**Typical root causes:**
- Uninitialized memory reads (kernel heap infoleak, stack data leakage)
- Out-of-bounds reads
- Side channels (cache timing, speculative execution)
- Error messages revealing internal state
- Incorrect permission checks on sensitive files
- Timing side channels in cryptographic operations

**Common patterns:**

```c
// Pattern: Kernel heap infoleak
// CVE-2022-2588 — cls_route use-after-free allows reading adjacent heap data
// When a UAF occurs, the freed object's memory may still contain pointers
// Reading through the dangling reference reveals kernel addresses, defeating ASLR

// Pattern: Speculative execution side channel (Spectre/Meltdown family)
// CVE-2017-5753 (Spectre v1) — bounds check bypass
if (x < array1_size) {
    // Speculative execution reads array1[x] even if condition is false
    // Then accesses array2[array1[x] * 256], which loads a cache line
    // Timing measurement of array2 access reveals array1[x] value
    y = array2[array1[x] * 256];
}

// Pattern: Uninitialized stack data in ioctl return
struct kernel_info info;
copy_to_user(user_buf, &info, sizeof(info));
// If kernel_info has padding bytes that aren't zeroed,
// those bytes contain whatever was on the stack previously
```

**Difficulty:** Easy to Moderate. Finding infoleaks is usually easier than achieving RCE because any out-of-bounds read can be leveraged. The real skill is in using the infoleak as part of a larger exploit chain (defeating ASLR).

### 3.4 Privilege Escalation

**Typical root causes:**
- Kernel use-after-free (most common LPE method)
- Race conditions in privilege checks (TOCTOU)
- Incorrect capability checks in syscalls/ioctls
- Container escape via namespace/cgroup manipulation
- Misconfigured SUID binaries
- Unsafe library loading (LD_LIBRARY_PATH, RPATH)
- Credential theft (shadow file, memory dumps, keyring)

**Common patterns:**

```c
// Pattern: Kernel UAF → LPE (the modern Linux LPE pattern)
// Step 1: Cause a UAF (e.g., double-free, cross-CPU race)
// Step 2: Replace the freed object with a controlled object
// Step 3: Use the dangling reference to modify the replacement object
// Step 4: Through the modified object, gain arbitrary read/write
// Step 5: Overwrite modprobe_path or a cred struct for root

// Example: CVE-2022-32250 (nf_tables UAF)
// 1. Create nft set element
// 2. Trigger race between element removal and lookup
// 3. Replace freed element with controlled kmalloc object
// 4. Read/write through dangling pointer
// 5. Overwrite task cred for root

// Pattern: Container escape via /proc or /sys
// CVE-2022-0185 — integer overflow in filesystem legacy_parse_param
// Can be exploited from within a container for host escape
// The key: find a kernel vulnerability reachable from container context
//   even without CAP_SYS_ADMIN
```

**Difficulty:** Hard. LPE requires chaining multiple primitives (UAF → heap shaping → arb write → cred overwrite). Modern kernels have increasingly effective mitigations (KFENCE, SLAB_QUARANTINE, kFREE, CFI).

### 3.5 Sandbox Escape

**Typical root causes:**
- Mojo IPC message validation bugs (Chrome)
- GPU process compromise leading to browser process RCE
- File format parsing in unsandboxed process (preview engine)
- Thumbnailer/indexer running without sandbox
- XPC/DBus service misconfiguration (macOS, Linux)
- GPU driver bugs accessed through WebGL/WebGPU

**Common patterns:**

```javascript
// Chrome sandbox escape pattern:
// 1. Compromise renderer process via V8 bug
// 2. Send crafted Mojo IPC message to browser process
// 3. Browser process trusts the renderer's message
// 4. Trigger memory corruption in browser process
// 5. Full system compromise

// CVE-2023-2033 (Chrome) — WebP heap buffer overflow
// Exploitation:
// Step 1: Craft a malicious image (WebP) that triggers heap overflow
// Step 2: Use overflow to corrupt adjacent objects in renderer heap
// Step 3: Achieve arbitrary R/W in renderer process
// Step 4: Escape sandbox via Mojo IPC bug (separate vulnerability)
// Step 5: Compromise browser process → system access
```

**Difficulty:** Very Hard. Sandbox escapes typically require a separate vulnerability from the initial renderer compromise (a "chain"). You need at least two bugs: one for the sandboxed process, one to escape the sandbox. The Chrome VRP pays out significantly more for full chains than for renderer-only bugs.

### Vulnerability Difficulty Summary

| Class | Finding Difficulty | Exploitation Difficulty | Bounty Value | Abundance |
|---|---|---|---|---|
| DoS | ★☆☆☆☆ | ★☆☆☆☆ | $ | High |
| Info Disclosure | ★★☆☆☆ | ★☆☆☆☆ | $$ | High |
| Code Execution (local) | ★★★☆☆ | ★★★☆☆ | $$$$ | Medium |
| Code Execution (remote) | ★★★★☆ | ★★★★☆ | $$$$$ | Low |
| Privilege Escalation | ★★★★☆ | ★★★★☆ | $$$$ | Medium |
| Sandbox Escape | ★★★★★ | ★★★★★ | $$$$$ | Very Low |

---

## 4. Zero-Day Discovery vs N-Day Research

### 4.1 Why Study N-Days?

Studying known vulnerabilities (N-days) is the most effective training methodology for finding zero-days. The reasoning:

1. **Attack patterns recur.** The same classes of bugs appear repeatedly because developers make the same kinds of mistakes. Understanding UAF in `nftables` (CVE-2022-32250) prepares you to find UAF in `io_uring` (CVE-2024-0582).
2. **Exploitation techniques compound.** Every heap shaping technique you learn applies to the next vulnerability. The slab cache cross-cache technique used in CVE-2017-17053 applies to CVE-2022-32250 and beyond.
3. **Code areas cluster.** If you find one bug in a subsystem, there are likely more. Researchers who became expert in `nftables` by studying one CVE went on to find dozens more.
4. **Tooling mastery.** Reverse engineering patches, writing PoCs, and debugging crashes build skills that transfer directly to zero-day research.

### 4.2 Reverse Engineering Patches

The process of extracting vulnerability details from a patch:

```
Step 1: Obtain the patch
  git log --all --grep="CVE-YYYY-NNNN"  # Search kernel git
  git log --all --grep="bug" --grep="crash"  # Search for silent fixes

Step 2: Analyze what was fixed
  git show <commit-hash>              # Show the actual changes
  git show <commit-hash> --stat       # Show affected files

Step 3: Understand the vulnerability
  - What was the root cause?
  - What was the developer's mental model vs reality?
  - What assumptions were violated?

Step 4: Reproduce without the patch
  - Check out the version before the fix
  - Write a PoC that triggers the vulnerable path
  - Verify the crash

Step 5: Generalize
  - Are there similar patterns elsewhere in the codebase?
  - Could the same class of bug exist in different drivers/subsystems?
  - What other code shares the same developer or code review history?
```

**Practical example: Reverse engineering CVE-2022-32250**

```bash
# Find the patch
git log --all --grep="32250" linux/
# Result: commit a3a906 forgive me for not looking up exact hash

# Analyze the fix
git show <commit>
# The fix adds nft_set_elem_deactivate() call before removing element
# from set in error path of nft_add_set_elem()

# Root cause: When nft_add_set_elem() fails after element is already
# activated, the element's reference isn't properly dropped, leading
# to UAF when the set is later destroyed.

# Now ask: Where else does nft_add_set_elem() have similar error paths?
# Answer: Look for other nft_* functions that activate objects
# then might fail without deactivating them.
# This pattern led to CVE-2023-32233 and CVE-2023-35001.
```

### 4.3 1-Days as Training Ground

A **1-day** is a vulnerability that has been patched but where the exploit details haven't been widely published. These are ideal training targets because:

- You know a bug exists and roughly where it is
- You must still do the hard work of understanding and exploiting it
- The exploit difficulty is realistic (unlike CTF challenges)
- Success builds confidence and skills that transfer directly

**Training curriculum for kernel exploitation:**

| Phase | N-Day | Skills Developed |
|---|---|---|
| 1 | CVE-2022-2639 (openvswitch) | Basic UAF, simple heap shaping |
| 2 | CVE-2021-4154 (kernel.creds) | Simple LPE, cred overwriting |
| 3 | CVE-2022-32250 (nftables) | Cross-cache attack, complex UAF |
| 4 | CVE-2022-0185 (legacy_parse_param) | Integer overflow, page-level heap |
| 5 | CVE-2024-0582 (io_uring) | Race condition, async UAF |
| 6 | CVE-2023-35001 (nftables) | Advanced heap shaping, arbitrary write |

**Progression principle:** Each N-day should be slightly harder than the last. Start with bugs that have detailed writeups and PoCs available, then work up to bugs with only patches and no public exploit.

### 4.4 From N-Day to Zero-Day: The Transition

The transition from reproducing N-days to finding zero-days follows a predictable path:

```
Phase 1: Reproduction
  - Follow existing writeups
  - Compile and run existing PoCs
  - Understand the mechanics of exploitation

Phase 2: Variation
  - Modify existing exploits
  - Find similar bugs in the same subsystem
  - Develop your own tools and techniques

Phase 3: Independent Discovery
  - Audit code areas where N-days were found
  - Use pattern matching to find new instances
  - Write your own PoCs from patches

Phase 4: Novel Bug Finding
  - Audit new code areas using learned patterns
  - Fuzz strategically based on attack surface analysis
  - Discover bugs in previously-unaudited code
```

**The key insight:** Most zero-days are not found through genius insight. They are found through **systematic application of known patterns to new codebases.** The researcher who found CVE-2022-32250 was an expert in netfilter code because they had previously studied CVE-2021-22555, CVE-2022-1015, and other nftables bugs. Expertise compounds.

---

## 5. The Mindset of a Zero-Day Hunter

### 5.1 Systematic Thinking

Zero-day hunting is not about random poking. It's a systematic process:

1. **Select a target subsystem** based on attack surface analysis
2. **Map the code** — read every source file, understand every state machine
3. **Identify assumptions** — what does the developer assume will always be true?
4. **Challenge assumptions** — what if the assumption is violated? How?
5. **Construct adversarial inputs** — craft inputs that violate assumptions
6. **Verify** — test the inputs, confirm the crash, minimize the PoC

**Example: Auditing io_uring**

```c
// io_uring is a complex async I/O framework added to Linux ~5.1
// It's a massive attack surface — new features are added every release

// Step 1: Read the code
// Start with io_uring.c (100K+ lines)
// Identify key data structures: io_ring_ctx, io_kiocb, io_sqe

// Step 2: Find trust boundaries
// io_uring shares data between kernel and userspace via shared ring buffers
// Userspace writes SQEs (submission queue entries) that the kernel reads
// Every SQE field is untrusted — but which ones does the code trust?

// Step 3: Look for assumption violations
// - Does the code assume sqe->len fits in u32? (CVE-2022-0185 pattern)
// - Are there race conditions between submit and completion? (CVE-2024-0582)
// - Can userspace modify shared ring data after kernel reads it? (TOCTOU)
// - Are error paths properly cleaned up? (UAF pattern from nftables)
```

### 5.2 Adversarial Mindset

Think like an attacker, not a developer. Developers ask "does this work?" Attackers ask "how can I make this not work in a way I control?"

**Key questions to ask about every code path:**

1. **What inputs can I control?** — Trace data from userspace to the point of use. Every byte you control is a potential attack vector.
2. **What assumptions does this code make?** — Spot the gaps between what the code assumes and what is actually enforced.
3. **What error paths exist?** — Every error path is a potential cleanup failure. Did the developer remember to free everything on every exit?
4. **What happens at boundaries?** — Integer overflows happen at type casts. UAFs happen at object lifetime boundaries. Race conditions happen at concurrency boundaries.
5. **Who else uses this code?** — A bug in a library function is multiplied by every caller. `copy_from_user()` bugs affect everything.

### 5.3 Where to Look That Others Don't

Most researchers focus on the obvious attack surfaces. The best zero-days come from overlooked areas:

**Under-audited code areas:**

| Area | Why It's Overlooked | Why It's Rewarding |
|---|---|---|
| New kernel subsystems | Too new for fuzzing to have covered | Feature-rich, complex, rushed |
| Vendor-specific drivers | Not in mainline kernel, less scrutiny | Often poor code quality |
| Firmware/UEFI | Requires hardware, hard to test | Rich attack surface, minimal hardening |
| IoT/embedded | Low-value targets, fragmented | Terrible security practices |
| Legacy protocols | "Nobody uses these anymore" | Still compiled into every kernel |
| Test/debug code | Not considered production | Often accessible in production |
| Optimization passes | Too complex for most auditors | But they handle untrusted input |

**The "boring code" principle:** The most valuable bugs are often in code that looks boring. Filesystem mount options, printer driver parsing, obscure ioctl codes — these receive far less scrutiny than the "sexy" targets like JavaScript engines or network protocols, but they're equally exploitable.

**The "new code" principle:** New kernel features are a goldmine. io_uring, eBPF, and user namespaces were each the source of dozens of vulnerabilities in their first few years. When a new subsystem is added, audit it immediately — before the fuzzers and other researchers get to it.

**The "error path" principle:** Developers write happy paths first and error paths second. Error paths receive far less testing and code review. Audit every `goto err` and `return -EINVAL` path for:
- Missing frees (memory leaks → potential UAF if object is later accessed)
- Double frees (cleanup code that runs twice)
- Missing locks (error path doesn't acquire/release a lock)
- Incomplete state rollback (partially modified data structures)

### 5.4 Common Developer Mistakes

These patterns recur so frequently that they deserve explicit enumeration:

```c
// MISTAKE 1: Integer overflow in size calculations
size = count * sizeof(struct item);  // Can overflow!
// Fix: size = size_mul(count, sizeof(struct item)); // or check with overflow.h

// MISTAKE 2: TOCTOU with userspace pointers
// WRONG:
copy_from_user(&local, user_ptr, sizeof(local));
validate(&local);
process(&local);
// ATTACKEER: modify user_ptr between copy and use? No — copy_from_user is atomic.
// But what about:
if (access(user_path, R_OK) == 0) {  // TOCTOU!
    fd = open(user_path, O_RDONLY);    // Path may have changed!
}

// MISTAKE 3: Missing cleanup in error paths
err = do_something();
if (err) {
    // Forgot to free resource allocated earlier!
    return err;
}

// MISTAKE 4: Trusting lengths from userspace
struct header {
    uint32_t len;
    uint32_t type;
    char data[];
};
// If code does copy_from_user(buf, user_data, hdr->len) without validating
// hdr->len against the actual available data, we have a heap overflow.

// MISTAKE 5: Confusing array bounds with element count
// Off-by-one: allocating size for count elements but accessing [count]
// Very common in C/C++ fixed-size arrays.

// MISTAKE 6: Using atomic_t where refcount_t is needed
// atomic_t doesn't check for underflow/overflow
// refcount_t adds saturation and detection
// Mixing them up can lead to use-after-free via refcount overflow

// MISTAKE 7: RCU dereference without proper lifecycle
// rcu_dereference() guarantees the pointer is valid *now*
// but doesn't guarantee it will remain valid across a context switch
// This is the root cause of many UAF bugs in RCU-protected code
```

### 5.5 Practical Advice for CTF Competitors

1. **Start with kernel exploitation.** Most CTFs include a kernel pwn challenge. The skills transfer directly to real zero-day research. Practice on past CTF challenges:

   - D3CTF, 0CTF, HITCON, DEF CON CTF — all have excellent kernel challenges
   - Write exploits for at least 5 different kernel vulnerabilities before attempting original research

2. **Build a fuzzing infrastructure.**

   ```bash
   # Kernel fuzzing with syzkaller
   git clone https://github.com/google/syzkaller
   # Configure with coverage-guided fuzzing
   # Focus on specific subsystems you've audited manually
   # Unlike random fuzzing, targeted fuzzing after manual audit is far more effective
   ```

3. **Develop a personal playbook.**

   ```
   My Exploitation Playbook:
   1. Trigger bug (UAF, overflow, etc.)
   2. Obtain infoleak (defeat ASLR)
   3. Shape heap (control target object location)
   4. Achieve arb read/write (overwrite function pointer, vtable, etc.)
   5. Escalate privileges (overwrite cred, modprobe_path, etc.)
   6. Stabilize (handle NMIs, RCU callbacks, etc.)
   ```

4. **Read every CVE writeup you can find.**

   - Project Zero blog (Google)
   - SSD Secure Disclosure advisories
   - Qualys advisories
   - Corelan Team articles (older but foundational)
   - Promptly's open bug reports
   - Linux kernel mailing list (LKML) security fixes

5. **Keep a vulnerability pattern database.**

   Track patterns you've seen, exploitation techniques that worked, and code structures that are suspicious. Over time, you'll develop an intuition for where bugs hide that no fuzzer can replicate.

---

## Appendix: Quick Reference

### Kernel Exploitation Primitives

| Primitive | How to Obtain | What It Enables |
|---|---|---|
| Infoleak | OOB read, uninitialized memory | ASLR bypass |
| UAF | Double-free, race condition, refcount bug | Type confusion, arbitrary R/W |
| Heap overflow | Buffer overflow in kmalloc'd region | Adjacent object corruption |
| Stack overflow | Large local array from userspace data | RIP control (if no canary) |
| Null deref | Missing NULL check | DoS; sometimes LPE via mmap(0) |
| Arb write | Any of the above + heap shaping | Struct overwrite, code exec |

### Key Kernel Structures for Exploitation

```c
struct cred {
    int uid, gid;          // Overwrite for root
    int euid, egid;        // Effective IDs
    // ... capability sets ...
};

// modprobe_path overwrite pattern:
// 1. Get arbitary write
// 2. Overwrite modprobe_path to "/tmp/x"
// 3. Execute unknown binary format
// 4. Kernel calls modprobe_path as root
// 5. /tmp/x runs as root → game over

// Other targets for arbitrary write:
// - core_pattern
// - poweroff_cmd
// - task_struct->fs (for cwd manipulation)
// - page tables (PTE overwrite for physical R/W)
```

### Tools

| Tool | Purpose | Link |
|---|---|---|
| syzkaller | Kernel fuzzer | github.com/google/syzkaller |
| pwndbg | GDB for exploitation | github.com/pwndbg/pwndbg |
| QEMU | Kernel debugging with GDB | qemu.org |
| Ghidra | Binary reverse engineering | ghidra-sre.org |
| AFL++ | Userspace fuzzing | github.com/AFLplusplus/AFLplusplus |
| kraftite | io_uring fuzzer | github.comPalantir |

---

*This document is a living reference. The zero-day landscape evolves constantly — new mitigations, new attack surfaces, new exploit techniques. The principles outlined here are durable; the specific CVEs and prices will date quickly. Always verify current information.*
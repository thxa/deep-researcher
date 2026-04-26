# Vulnerability Discovery Methodology — Fuzzing & Dynamic Analysis

*A comprehensive technical reference for vulnerability researchers, CTF players, and security engineers.*

---

## 1. Fuzzing Fundamentals

### 1.1 What Is Fuzzing?

Fuzzing is an automated software testing technique that provides invalid, unexpected, or random data as input to a program. The core idea is deceptively simple: generate inputs, feed them to a target, and monitor for anomalous behavior (crashes, hangs, assertion failures, memory corruption). Fuzzing is responsible for the majority of discovered vulnerabilities in widely deployed software—Google's OSS-Find alone has found over 37,000 bugs across 500+ projects.

The fuzzing loop:

```
┌──────────────────────────────────────────────────┐
│  1. Select a seed input from the corpus           │
│  2. Mutate the input (bit flips, Havoc, splicing)│
│  3. Execute the target with the mutated input     │
│  4. Collect coverage feedback                     │
│  5. If new coverage → add to corpus               │
│  6. If crash → save to crashes/ directory         │
│  7. Goto 1                                       │
└──────────────────────────────────────────────────┘
```

### 1.2 Fuzzer Taxonomy

#### Coverage-Guided (Feedback-Directed) Fuzzers

These fuzzers instrument the target binary to collect edge/path coverage information. When a mutated input discovers a new code path, it is retained in the corpus for further mutation. This creates a powerful evolutionary search that systematically explores the target's state space.

- **AFL++, libFuzzer, Honggfuzz** are the dominant tools in this category.
- They excel at discovering deep bugs in complex programs by continuously expanding path coverage.
- Coverage is typically measured via edge coverage with a compact hash: `(prev_block ^ cur_block)` stored in a shared bitmap.

#### Generational (Grammar-Based) Fuzzers

These fuzzers generate inputs from a specification or grammar describing the input format. They understand the structure of valid inputs and produce syntactically correct (but semantically manipulative) test cases.

- **Sulley, boofuzz, Peach Fuzzer, DOMATO** fall here.
- Best for protocol fuzzing, file-format fuzzing, and any target where random bytes are overwhelmingly rejected by early parsing.
- Example: generating valid HTTP requests with malformed headers, valid SQL with injected predicates.

#### Mutation-Based Fuzzers

These fuzzers take existing seed inputs and apply transformations—bit flips, byte substitutions, arithmetic operations, insertion, deletion, splicing of multiple inputs—to produce new inputs. They require no grammatical knowledge of the input format.

- **zzuf** is a classic example; AFL++'s mutation engine is also mutation-based (but guided by coverage).
- Fast and simple but inefficient when the target requires highly structured input.

**Decision heuristic**: Use coverage-guided fuzzing as your default. Switch to generational/grammar-based fuzzing when random mutations almost never pass the target's initial parser. Combine both for maximum effectiveness (coverage-guided mutation + grammar hints).

### 1.3 AFL++ Architecture Deep-Dive

AFL++ is the actively maintained successor to American Fuzzy Lop (AFL) by Michal Zalewski. It represents the state of the art in coverage-guided fuzzing.

#### Instrumentation

AFL++ supports multiple instrumentation backends, ranked by performance and coverage granularity:

| Backend | Command | Quality | Speed |
|---------|---------|--------|-------|
| LTO (link-time optimization) | `afl-clang-lto` | Best | Fast |
| LLVM | `afl-clang-fast` | Very Good | Fast |
| GCC plugin | `afl-gcc-fast` | Good | Medium |
| Classic (binary rewriting) | `afl-gcc` | Basic | Slow |

**LTO instrumentation** (`afl-clang-lto`) operates at link time, giving it a whole-program view. It can optimize instrumentation placement, remove redundant edges, and achieve the highest coverage for a given number of executions. This is the recommended default.

```bash
# Build with AFL++ LTO instrumentation
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export AFL_USE_ASAN=1  # optional: enable ASan
./configure --disable-shared
make -j$(nproc)
```

For binary-only targets where source is unavailable, AFL++ offers QEMU mode (`afl-qemu-trace`) and Unicorn mode (`afl-unicorn`). These use runtime instrumentation via CPU emulation, which is 2–10x slower but requires no source:

```bash
# Build for QEMU mode
./configure --disable-shared
make -j$(nproc)
# Run with QEMU
afl-fuzz -Q -i corpus/ -o findings/ -- ./target_binary @@
```

#### Fork Server

AFL++ uses a **fork server** to avoid the overhead of `execve()` for every test case. At startup, the instrumented binary pauses at `__AFL_LOOP` and sends a message to `afl-fuzz` via a control pipe. For each new input, `afl-fuzz` signals the fork server, which calls `fork()`—much cheaper than a full process re-execution.

```
afl-fuzz  ←——control pipe——→  fork server (in target process)
                                  │
                                  ├── fork() → child executes input
                                  │
                                  └── waitpid() → report result
```

This reduces per-input overhead from ~5–10ms (full execve) to ~0.5ms (fork). The fork server is automatically inserted when using `afl-clang-fast` or `afl-clang-lto`.

#### Feedback Loop and Coverage Tracking

AFL++ tracks **edge coverage** using a 64KB shared memory bitmap. Each edge `(A → B)` maps to bitmap index `((A << 12) ^ B) & 0xFFFF`. The fuzzer also tracks hit counts per edge (rounded to 8 buckets: 1, 2, 3, 4-7, 8-15, 16-31, 32-127, 128+), yielding typically 10–30x more useful coverage signals than simple edge coverage.

When a mutated input triggers a new edge or a new hit-count bucket for an existing edge, it is marked as "interesting" and added to the fuzzing queue. This is the core evolutionary pressure that drives exploration.

#### Mutations

AFL++ applies mutations in a deterministic phase followed by a stochastic phase:

**Deterministic phase** (applied sequentially to each input):
- Bit flip (1, 2, 4 bits at every position)
- Byte flip
- Arithmetic operations (`±1..35` on 8/16/32/64-bit values)
- Known integer replacements (`0, 1, -1, MAX_INT, MIN_INT, ...`)
- Dictionary token insertion (if a dictionary is provided)

**Stochastic phase** (Havoc and Splice):
- **Havoc**: Apply 2–128 random mutations from the above set in a single step
- **Splice**: Take two queue entries, pick a random splice point, and merge their bytes
- **Custom mutators**: AFL++ supports Python/shared-library mutators via `AFL_CUSTOM_MUTATOR`, enabling structure-aware mutation

The CMPLOG feature (`AFL_CMPLOG=1`) records comparison operands during execution (e.g., `if (input == 0xDEADBEEF)`), then uses these concrete values as dictionary tokens, dramatically improving the fuzzer's ability to pass magic-byte checks.

### 1.4 libFuzzer for In-Process Fuzzing

libFuzzer (part of LLVM) runs the fuzz target **in-process**, avoiding fork overhead entirely. The user provides a `LLVMFuzzerTestOneInput` function:

```c
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Parse/fuzz your target here
    parse_input(data, size);
    return 0;
}
```

Compile and run in a single step:

```bash
clang -g -fsanitize=fuzzer,address -o fuzz_target fuzz_target.c
./fuzz_target corpus/ -dict=my.dict -max_len=4096 -jobs=4
```

Key advantages:
- **Speed**: No fork overhead; 10,000+ executions/sec even for complex targets
- **Integration**: Built into LLVM/Clang, works natively with sanitizers
- **OSS-Fuzz compatible**: Google's continuous fuzzing infrastructure uses libFuzzer

When to use libFuzzer over AFL++:
- Library APIs with a clean entry point (parsers, decoders, crypto)
- When targeting OSS-Fuzz integration
- When you need maximum throughput on a single core

When to prefer AFL++:
- Fuzzing standalone binaries you cannot link into a harness
- Multi-process targets
- When you need QEMU/binary-only fuzzing
- When you want custom mutators, CMPLOG, or other advanced AFL++ features

### 1.5 SYZKaller for Kernel Syscall Fuzzing

SYZKaller is a coverage-guided kernel fuzzer developed by Google. It fuzzes *syscalls* rather than byte streams, making it ideal for filesystem, networking, and driver bug hunting.

**Architecture**:

```
┌──────────────┐      ┌──────────────────────┐
│  syz-manager │◄────►│  VM (sut)            │
│  (host)      │      │  ┌─────────────┐     │
│              │      │  │ syz-executor │     │
│  corpus      │      │  └─────────────┘     │
│  crash DB    │      │  kernel (kcov inst.) │
└──────────────┘      └──────────────────────┘
```

- **syz-manager** orchestrates fuzzing across multiple VMs, manages the corpus, and collects crashes
- **syz-executor** runs inside each VM, executing sequences of syscalls generated by the mutator
- **Syz descriptions** define syscall templates with struct types, flags, and resource relationships
- **kcov** provides coverage feedback from the kernel

SYZKaller has found thousands of kernel bugs and is the primary tool for Linux kernel fuzzing. It has also been adapted for FreeBSD, Windows, and Fuchsia.

### 1.6 Comparing Fuzzers: When to Use What

| Scenario | Recommended Fuzzer | Rationale |
|----------|-------------------|-----------|
| C/C++ library with API | libFuzzer | In-process speed, sanitizer integration |
| Standalone binary (source available) | AFL++ | Fork server, CMPLOG, custom mutators |
| Binary-only target | AFL++ QEMU mode | No source needed |
| Kernel syscall interfaces | SYZKaller | Syscall-aware, VM management |
| Network protocol | boofuzz | Stateful protocol definition |
| Browser engine | libFuzzer + ASan | In-process, high throughput |
| Structured file format | AFL++ + protobuf mutator | Structure-aware via custom mutator |
| Embedded firmware | AFL++ Unicorn mode | CPU emulation for arbitrary arch |
| OSS-Fuzz submission | libFuzzer | Required format for OSS-Fuzz |

---

## 2. Fuzzing Setup for CTF & Research

### 2.1 Building AFL++ from Source

```bash
# Clone with submodules
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
git submodule update --init --recursive

# Build everything (includes QEMU and Unicorn modes)
make distrib -j$(nproc)
sudo make install

# Verify
afl-fuzz --version
afl-clang-lto --version

# Check which instrumentation is available
ls /usr/local/bin/afl-*
```

**Performance tuning**:

```bash
# Increase shared memory limits (required for AFL++ bitmap)
echo core >/proc/sys/kernel/core_pattern
echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null

# For Linux KVM: ensure KSM is disabled for stability
echo 0 >/sys/kernel/mm/ksm/run

# Set CPU affinity for best throughput
taskset -c 0,2,4,6 afl-fuzz -i corpus/ -o findings/ -M main -- ./target @@
taskset -c 1,3,5,7 afl-fuzz -i corpus/ -o findings/ -S s1 -- ./target @@
```

### 2.2 Writing Harness Functions

A well-written harness is the single most important factor in effective fuzzing. The harness should:

1. Accept raw bytes from the fuzzer
2. Parse/convert them into the target's expected format
3. Call the target function
4. Return quickly (no unnecessary I/O, no sleeps)
5. Not exit on error—let the fuzzer control the lifecycle

**C harness for file-based targets (AFL++ persistent mode)**:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "afl-fuzz.h"

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
    // Optional: deferred forkserver
    __AFL_INIT();

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;

        // Call target directly with in-memory buffer
        target_parse(buf, len);
    }

    return 0;
}
```

**C harness for libFuzzer**:

```c
#include <stdint.h>
#include <stddef.h>

extern int parse_xml(const uint8_t *data, size_t len);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;  // minimum size gate
    parse_xml(data, size);
    return 0;
}
```

**Python harness for AFL++ (via custom mutator or file-based)**:

For Python targets, use the `python` mode:

```bash
afl-fuzz -i corpus/ -o findings/ -D -U -- python3 harness.py @@
```

```python
# harness.py
import sys
import target_module

def main():
    if len(sys.argv) < 2:
        sys.exit(1)
    with open(sys.argv[1], 'rb') as f:
        data = f.read()
    try:
        target_module.parse(data)
    except Exception:
        pass  # catch all exceptions; only crashes (SEGV etc.) count

if __name__ == '__main__':
    main()
```

### 2.3 Seed Corpus Creation and Minimization

A good seed corpus dramatically accelerates fuzzing by providing the fuzzer with starting points that reach deep code paths.

**Creating a seed corpus**:

```bash
# Gather valid input files
mkdir -p corpus
cp /path/to/samples/*.png corpus/
cp /path/to/edge_cases/*.png corpus/

# Validate seeds (remove files that crash or hang the target)
for f in corpus/*; do
    timeout 5 ./target "$f" || mv "$f" corpus_invalid/
done
```

**Minimizing the corpus** to remove redundant entries:

```bash
# AFL++ built-in corpus minimization
afl-cmin -i corpus/ -o corpus_min/ -- ./target @@

# Further reduce each test case to its minimal form
mkdir -p corpus_min_min
for f in corpus_min/*; do
    afl-tmin -i "$f" -o "corpus_min_min/$(basename $f)" -- ./target @@
done
```

For libFuzzer, the fuzzer automatically manages the corpus. You can still minimize post-fuzz:

```bash
# Merge and minimize a libFuzzer corpus
./fuzz_target corpus/ merge_corpus/ && \
  mv corpus/ corpus_old/ && mv merge_corpus/ corpus/
```

### 2.4 Dictionary Creation

Dictionaries tell the fuzzer about magic values, keywords, and structural tokens that appear in the target's input format. This is critical for passing parser checkpoints (magic bytes, version fields, etc.).

**Manual dictionary**:

```
# my.dict
"PNG\x89"
"\x1a\x0d\x0a\x1a"
"IHDR"
"IDAT"
"IEND"
"tEXt"
"PLTE"
```

**Auto-generating dictionaries**:

AFL++ can extract dictionary tokens from the binary itself:

```bash
# Extract tokens from the binary using AFL++'s built-in analysis
afl-clang-lto -o target target.c   # compile with AFL
afl-analyze -i corpus/ -o analyze/ -- ./target @@
# Check analyze/dict for extracted tokens
```

For CMPLOG (an even more powerful approach):

```bash
# Compile with CMPLOG support
afl-clang-lto -DCMPLOG -o target_cmplog target.c

# Run fuzzing with CMPLOG
afl-fuzz -i corpus/ -o findings/ -c 0 -- ./target_cmplog @@
```

CMPLOG automatically extracts comparison operands (the exact values the target compares input against) and uses them as mutation hints, eliminating most manual dictionary work.

### 2.5 Persistent Mode and Deferred Forkserver

**Persistent mode** avoids fork() overhead entirely for libraries with a clean C API:

```c
#include "afl-fuzz.h"

__AFL_FUZZ_INIT();

int main(void) {
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        my_library_parse(buf, len);
    }

    return 0;
}
```

- `__AFL_LOOP(N)` runs up to N iterations before re-forking (for leak/reset hygiene)
- `__AFL_FUZZ_TESTCASE_BUF` and `__AFL_FUZZ_TESTCASE_LEN` provide zero-copy access to the fuzzer's input buffer
- This can achieve **100,000+ exec/sec** vs. **5,000–10,000 exec/sec** with fork

**Deferred forkserver** delays the fork server initialization until the program has completed its startup phase, avoiding repeated initialization:

```c
int main(void) {
    // Expensive initialization that doesn't depend on input
    load_config("config.ini");
    init_database();
    
    // Signal forkserver *after* init—saves init cost per execution
    __AFL_INIT();
    
    // Rest of program
    while (__AFL_LOOP(10000)) {
        process_input();
    }
}
```

Compile normally:

```bash
afl-clang-lto -o target_persistent target.c
afl-fuzz -i corpus/ -o findings/ -- ./target_persistent
```

Thoroughput comparison (typical):

| Mode | Exec/sec | Notes |
|------|----------|-------|
| Standard (fork per input) | 1,000–10,000 | General purpose |
| Fork server | 5,000–15,000 | Saves execve overhead |
| Persistent mode | 50,000–500,000 | Library targets only |
| In-process (libFuzzer) | 100,000–1,000,000+ | Best possible speed |

---

## 3. Advanced Fuzzing Techniques

### 3.1 Structure-Aware Fuzzing

Random mutations on structured input formats (protobuf, SQL, programming languages) almost never produce valid enough inputs to pass deep validation. Structure-aware fuzzing addresses this by maintaining input validity through the mutation process.

**Protobuf Mutator (for protocol buffer targets)**:

```bash
# Install libprotobuf-mutator
git clone https://github.com/google/libprotobuf-mutator
cd libprotobuf-mutator && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$(nproc) && sudo make install
```

Define your `.proto`:

```protobuf
// request.proto
syntax = "proto3";
message HttpRequest {
    string method = 1;
    string path = 2;
    map<string, string> headers = 3;
    bytes body = 4;
}
```

Write the fuzz target:

```c
#include <libprotobuf-mutator/port/protobuf.h>
#include "request.pb.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    HttpRequest req;
    if (req.ParseFromArray(data, size)) {
        // Fuzz the parser with valid-ish protobuf
        target_handle_http(req);
    }
    return 0;
}

extern "C" size_t LLVMFuzzerCustomMutator(
    uint8_t *data, size_t size, size_t max_size, unsigned int seed) {
    // Use libprotobuf-mutator for structure-preserving mutations
    protobuf_mutator::ProtobufMutator mutator(seed);
    HttpRequest req;
    req.ParseFromArray(data, size);
    mutator.Mutate(&req, max_size);
    return req.SerializeToArray(data, max_size) ? req.ByteSizeLong() : 0;
}
```

**Grammar-based fuzzing (GramFuzz / Grammar Mutator)**:

For targets requiring valid syntax (compilers, interpreters, SQL engines), define a grammar:

```
# sql.grammar (Grammar Mutator format)
<start> ::= <select_stmt>
<select_stmt> ::= "SELECT" <col_list> "FROM" <table> <where_clause>?
<col_list> ::= <col> | <col> "," <col_list>
<col> ::= "id" | "name" | "email" | "*"
<table> ::= "users" | "orders" | "products"
<where_clause> ::= "WHERE" <col> "=" <value>
<value> ::= <string> | <int>
<string> ::= "'" <alpha>+ "'"
<int> ::= <digit>+
```

AFL++ grammar mutator integration:

```bash
# Build grammar mutator
git clone https://github.com/AFLplusplus/Grammar-Mutator
cd Grammar-Mutator && make -j$(nproc)

# Generate mutator from grammar
./grammar-generator/gramfuzz-mutator sql.grammar

# Run AFL++ with grammar mutator
export AFL_CUSTOM_MUTATOR_LIBRARY=./sql_mutator.so
afl-fuzz -i corpus/ -o findings/ -- ./sql_target @@
```

### 3.2 Fuzzing with Sanitizers

Sanitizers dramatically increase bug detection by instrumenting the target to detect undefined behavior at runtime.

| Sanitizer | Flag | Detects | Overhead |
|-----------|------|---------|----------|
| AddressSanitizer | `-fsanitize=address` | Buffer overflows, UAF, leaks | 2x |
| UndefinedBehaviorSanitizer | `-fsanitize=undefined` | UB (shift, overflow, null deref) | 1.2x |
| MemorySanitizer | `-fsanitize=memory` | Uninitialized memory reads | 3x |
| ThreadSanitizer | `-fsanitize=thread` | Data races | 5-10x |

**Building with sanitizers for fuzzing**:

```bash
# ASan + UBSan (recommended default)
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export AFL_USE_ASAN=1
export AFL_USE_UBSAN=1

./configure && make -j$(nproc)

# For MSan (must be used alone—conflicts with ASan)
export CC=clang
export CXX=clang++
export CFLAGS="-fsanitize=memory -fno-omit-frame-pointer"
export CXXFLAGS="-fsanitize=memory -fno-omit-frame-pointer"
export LIB_FUZZING_ENGINE=-fsanitize=fuzzer

./configure && make -j$(nproc)
```

**Important**: Do NOT mix ASan and MSan in the same binary. They are mutually exclusive. Use separate builds.

**Interpreting ASan crash reports**:

```
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014
READ of size 4 at 0x602000000014 thread T0
    #0 0x401234 in parse_header /src/target/parser.c:42:13
    #1 0x401567 in main /src/target/main.c:15:5
    #2 0x7f12345678 in __libc_start_main

0x602000000014 is located 0 bytes to the right of 20-byte region
allocated by thread T0 here:
    #0 0x40a123 in malloc
    #1 0x401234 in parse_header /src/target/parser.c:35:20
```

Key information to extract:
- **Bug type**: `heap-buffer-overflow` (buffer overflow on heap)
- **Access**: `READ of size 4` (an out-of-bounds read of 4 bytes)
- **Location**: `parser.c:42` where the out-of-bounds access occurs
- **Allocation**: `parser.c:35` where the too-small buffer was allocated
- **Offset**: `0 bytes to the right` — the read is exactly at the boundary

### 3.3 Distributed Fuzzing

AFL++ supports distributed fuzzing out of the box with a main/secondary architecture.

**Main node** (deterministic + havoc):
```bash
afl-fuzz -i corpus/ -o findings/ -M main -- ./target @@
```

**Secondary nodes** (havoc-only, for throughput):
```bash
afl-fuzz -i corpus/ -o findings/ -S s1 -- ./target @@
afl-fuzz -i corpus/ -o findings/ -S s2 -- ./target @@
afl-fuzz -i corpus/ -o findings/ -S s3 -- ./target @@
```

All nodes share the `findings/` directory. The main node performs deterministic fuzzing while secondary nodes focus on stochastic mutation, maximizing throughput.

**For multi-machine fuzzing**, use `afl-proxy` or sync over NFS/SSHFS:

```bash
# On the main machine
afl-fuzz -i corpus/ -o /shared/findings/ -M main -- ./target @@

# On worker machines
afl-fuzz -i corpus/ -o /shared/findings/ -S worker1 -- ./target @@

# Alternatively, use AFL++'s built-in remote sync
afl-fuzz -i corpus/ -o findings/ -M main -R -- ./target @@
```

### 3.4 Kernel Fuzzing with SYZKaller

**Setting up SYZKaller**:

```bash
# Build syzkaller
git clone https://github.com/google/syzkaller
cd syzkaller
make -j$(nproc)

# Create a configuration file (syz-manager.cfg)
cat > syz-manager.cfg << 'EOF'
{
    "target": "linux/amd64",
    "http":   "127.0.0.1:56741",
    "workdir": "/syzkaller/workdir",
    "kernel_src": "/linux-source",
    "image":  "/syzkaller/bullseye.img",
    "syzkaller": "/syzkaller/bin",
    "type": "qemu",
    "vm": {
        "count":  4,
        "cpu":    2,
        "mem":    2048,
        "kernel": "/syzkaller/linux/arch/x86/boot/bzImage",
        "image":  "/syzkaller/bullseye.img"
    },
    "enable_syscalls": [
        "openat", "read", "write", "ioctl",
        "mmap", "munmap", "socket", "bind",
        "connect", "sendmsg", "recvmsg"
    ]
}
EOF

# Build a kernel with coverage (kcov) enabled
cd /linux-source
make defconfig
# Enable required kernel configs:
scripts/config --enable CONFIG_KCOV
scripts/config --enable CONFIG_KASAN
scripts.config --enable CONFIG_DEBUG_INFO
scripts/config --enable CONFIG_CONFIGFS_FS
scripts/config --enable CONFIG_SECURITYFS
scripts/config --enable CONFIG_DEBUG_KMEMLEAK
scripts/config --enable CONFIG_FAULT_INJECTION
make -j$(nproc)

# Run
/syzkaller/bin/syz-manager -config=syz-manager.cfg
```

**SYZKaller syscall descriptions** are defined in `sys/linux/` as `.const` files. Adding new descriptions:

```
# sys/linux/my_ioctl.txt
openat$my_device(fd const[AT_FDCWD], file ptr[in, string["/dev/my_device"]], \
    flags flags[open_flags], mode flags[open_mode]) fd
ioctl$my_device_cmd(fd fd, cmd const[MY_IOCTL_CMD], arg ptr[in, my_ioctl_args])
my_ioctl_args {
    type    flags[mydev_type, int32]
    data    array[int8, 64]
}
```

**Reproducing crashes**:

```bash
# Syzkaller provides repro programs
/syzkaller/bin/syz-repro -config=syz-manager.cfg crash_id

# Or manually: use the C repro program generated by syzkaller
cat workdir/crashes/12345/repro.c
# Compile and run in a VM to reproduce
```

### 3.5 Fuzzing Network Protocols

**boofuzz** (successor to Sulley) is a Python-based protocol fuzzer with stateful awareness:

```python
from boofuzz import *

session = Session(
    target=Target(
        connection=TCPSocketConnection("192.168.1.100", 80)
    ),
)

s_initialize("HTTP-Request")
s_string("GET", name="method")
s_delim(" ")
s_string("/", name="path")
s_delim(" ")
s_string("HTTP/1.1", name="version")
s_static("\r\n")
s_string("Host:", name="header-name")
s_delim(" ")
s_string("example.com", name="header-value")
s_static("\r\n\r\n")

session.connect(s_get("HTTP-Request"))
session.fuzz()
```

**AFL++ network fuzzing** via `afl-network-server` or pre-recording:

```bash
# Method 1: Record network traffic, then replay+mutate
# Use pcap2c or similar tool to convert captures to test cases

# Method 2: Use AFL++ persistent mode with network I/O
cat > harness.c << 'EOF'
#include <arpa/inet.h>
#include <unistd.h>
#include "afl-fuzz.h"

__AFL_FUZZ_INIT();

int main(void) {
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(1000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port = htons(9999),
            .sin_addr.s_addr = inet_addr("127.0.0.1")
        };
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0)
            send(sock, buf, len, 0);
        close(sock);
    }
}
EOF

# Method 3: Use preeny (LD_PRELOAD) to redirect network to stdin
# preeny's desock.so replaces socket reads with stdin
LD_PRELOAD=/path/to/preeny/desock.so afl-fuzz -i corpus/ -o findings/ -- ./server
```

### 3.6 Fuzzing Browsers

Browser fuzzing requires in-process libFuzzer harnesses targeting specific parsers:

```bash
# Clone Chrome's V8 with fuzzing support
fetch v8
cd v8
tools/dev/gm.py x64.release fuzzer

# The resulting binary fuzzes V8's JavaScript parser
out/x64.release/d8_fuzzer
```

For layout engine fuzzing, use CSS/HTML fuzzers:

```bash
# Build Firefox with fuzzing support
hg clone https://hg.mozilla.org/mozilla-central/
cd mozilla-central
echo 'ac_add_options --enable-fuzzing' >> .mozconfig
echo 'ac_add_options --enable-address-sanitizer' >> .mozconfig
./mach build

# Run the layout fuzzer
./mach fuzz
```

**Practical CTF tip**: Instead of fuzzing the full browser, target the specific vulnerable component (JS engine, image decoder, CSS parser, WebSocket handler). Build a minimal harness that exercises just that component.

### 3.7 Fuzzing Binary-Only Targets (QEMU Mode)

When source code is unavailable, AFL++ can instrument binaries via QEMU:

```bash
# Build AFL++ with QEMU support (done during `make distrib`)
cd AFLplusplus/qemu_mode
./build_qemu_support.sh

# Fuzz a binary-only target
afl-fuzz -Q -i corpus/ -o findings/ -- ./target_binary @@

# With CMPLOG for binary-only targets
afl-fuzz -Q -i corpus/ -o findings/ -c 0 -- ./target_binary @@
```

**Unicorn mode** for unsupported architectures:

```python
# unicorn_harness.py
from unicorn import *
from unicorn.x86_const import *
import afl

def fuzz(data):
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mu.mem_map(0, 0x10000)
    mu.mem_write(0, data)
    mu.mem_map(0x10000, 0x10000)  # stack
    mu.reg_write(UC_X86_REG_ESP, 0x20000)
    mu.reg_write(UC_X86_REG_EIP, 0)
    try:
        mu.emu_start(0, 0, timeout=5*UC_SECOND_SCALE)
    except UcError:
        pass

afl.init(fuzz)
```

```bash
afl-fuzz -U -i corpus/ -o findings/ -- python3 unicorn_harness.py
```

---

## 4. Crash Triage & Analysis

### 4.1 Crash Deduplication

A single bug can produce thousands of crashing inputs. Deduplication identifies unique root causes.

**AFL++ automatic deduplication**: AFL++ groups crashes by the last executed edge tuple (the coverage edge at the point of crash). This is a fast but imprecise heuristic.

**ASan-based deduplication**: When using AddressSanitizer, each crash report includes an allocation/deallocation stack trace. Group crashes by the `(allocation_site, access_site)` pair for precise deduplication.

```bash
# Cluster ASan crashes by stack trace hash
for crash in findings/crashes/*; do
    ./target_asan "$crash" 2>&1 | \
        grep -A5 '#0' | md5sum | \
        awk -v f="$crash" '{print $1, f}'
done | sort
```

**GDB-based deduplication**:

```bash
# Get backtrace hash for each crash
for crash in findings/crashes/*; do
    gdb -batch -ex "run" -ex "bt" -ex "quit" \
        --args ./target "$crash" 2>&1 | \
        grep '^#' | md5sum | \
        awk -v f="$crash" '{print $1, f}'
done | sort
```

### 4.2 Minimizing Test Cases

AFL++ provides `afl-tmin` for single-input minimization and `afl-cmin` for corpus minimization:

```bash
# Minimize a single crash input
afl-tmin -i findings/crashes/id:000000,sig:11,src:000001 -o minimized_crash -- ./target @@

# Verify the minimized crash still triggers the bug
./target minimized_crash

# Minimize across the entire corpus (keep only unique-coverage inputs)
afl-cmin -i findings/queue/ -o corpus_cmin/ -- ./target @@
```

For libFuzzer, use the `-minimize_crash` flag:

```bash
./fuzz_target -minimize_crash=1 -max_total_time=60 crash_file
```

### 4.3 Determining Exploitability

#### Using ASan Reports

ASan categorizes bugs, which directly informs exploitability:

| Bug Type | Exploitability | Notes |
|----------|---------------|-------|
| heap-buffer-overflow (write) | **High** | Direct arbitrary write primitive |
| heap-buffer-overflow (read) | Medium | Info leak; often convertible to write |
| stack-buffer-overflow (write) | **High** | RIP control via return address overwrite |
| heap-use-after-free | **High** | Type confusion, arbitrary R/W |
| stack-use-after-return | High | Variable shadowing on stack |
| global-buffer-overflow | Medium | Limited control but exploitable |
| SEGV on unknown address | Variable | Could be null deref (low) or controlled (high) |

#### Using `!exploitable` (WinDbg) or `exploitable` (GDB)

```bash
# Install GDB exploitability plugin
pip install gdb-exploitability

# Analyze crash
gdb -batch -ex "run" -ex "exploitable" -ex "quit" ./target crash_input
```

The `exploitable` classifier outputs one of:
- **Exploitable**: Likely controllable execution flow (e.g., RIP overwrite)
- **Probably Exploitable**: Crash near controllable memory, likely exploitable
- **Probably Not Exploitable**: Likely null deref, controlled abort
- **Unknown**: Insufficient information

#### Manual Exploitability Assessment

For each crash, determine:

1. **Crash type**: Write vs read, stack vs heap, controlled offset?
2. **RIP control**: Does the crash address come from attacker-controlled data?
3. **RIP influencing**: Can attacker data influence which path leads to the crash?
4. **Primitive**: What memory access does this grant? (read/write/execute, how many bytes, at what offset?)

```bash
# Examine crash in GDB
gdb ./target
(gdb) run < crash_input
# Program received signal SIGSEGV
(gdb) info registers      # Check if RIP/controlled
(gdb) x/20x $rsp          # Check stack contents
(gdb) x/10i $rip-20       # Check faulting instruction
(gdb) p/x $rdi             # Check if dereferenced pointer is controlled
```

### 4.4 Going from Crash to Vulnerability Understanding

The systematic process for crash-to-vuln analysis:

**Step 1: Reproduce reliably**
```bash
for i in {1..50}; do ./target crash_input; done
# Must crash 100% of the time (no heisenbugs)
```

**Step 2: Minimize the test case**
```bash
afl-tmin -i crash_input -o min_crash -- ./target @@
```

**Step 3: Build with full debug and sanitizers**
```bash
CFLAGS="-g -O0 -fsanitize=address,undefined" make
./target_asan min_crash 2>&1 | tee asan_report.txt
```

**Step 4: Analyze in GDB with ASan**
```bash
# ASan breakpoints
export ASAN_OPTIONS=abort_on_error=1:halt_on_error=1
gdb ./target_asan
(gdb) set environment ASAN_OPTIONS=abort_on_error=1:halt_on_error=1
(gdb) run < min_crash
# Program aborts at the ASan error
(gdb) bt full          # Get full backtrace with local variables
(gdb) info registers   # Check register state
(gdb) frame 0          # Switch to crash frame
(gdb) list             # Show source code
(gdb) print corrupted_var  # Inspect variables
```

**Step 5: Trace the data flow** — How does attacker input reach the crash point?

```bash
# Reverse the data flow from crash point to input
# 1. What buffer was accessed? (ASan tells you)
# 2. How was that buffer allocated? (ASan tells you)
# 3. Where was input copied into that buffer? (use GDB watchpoints)
(gdb) watch *(int*)0x602000000010  # Watch the overflowed buffer
(gdb) run < min_crash
# GDB stops every time the buffer is written — trace back to input
```

**Step 6: Determine the vulnerability class and impact**

Based on the analysis, classify:
- **Buffer overflow**: Stack/heap overflow with controlled size and data → RCE
- **Use-after-free**: Dangling pointer with controlled reuse → arbitrary R/W → RCE
- **Integer overflow**: Wraparound leading to undersized alloc → secondary overflow
- **Type confusion**: Incorrect cast allowing field misinterpretation → info leak or RCE
- **Race condition**: TOCTOU between check and use → bypass security check
- **NULL deref**: Often DoS only, but in kernel context may be exploitable

---

## 5. Dynamic Analysis Beyond Fuzzing

### 5.1 Dynamic Binary Instrumentation (DBI)

DBI frameworks inject analysis code into running binaries without recompilation. They enable function tracing, memory access monitoring, and custom analysis.

**Frida** — Node.js/Python bindings, multi-platform, ideal for rapid prototyping:

```javascript
// Trace all calls to malloc and free
Interceptor.attach(Module.getExportByName(null, "malloc"), {
    onEnter: function(args) {
        this.size = args[0].toInt32();
        console.log("malloc(" + this.size + ")");
    },
    onLeave: function(retval) {
        console.log("  => " + retval);
    }
});

// Hook a function and modify arguments
Interceptor.attach(Module.findExportByName("libcrypto.so", "AES_encrypt"), {
    onEnter: function(args) {
        console.log("AES_encrypt called");
        console.log("  Input: " + hexdump(args[0], { length: 16 }));
        // Modify the key argument
        args[1] = Memory.alloc(16);  // Replace key with all zeros
    }
});
```

```bash
# Attach to a running process
frida -U -n com.target.app -l trace.js

# Or spawn with Frida
frida -U -f com.target.app -l trace.js --no-pause
```

**Pin** — Intel's DBI framework, C/C++, powerful for performance analysis:

```c
// pin_tool.c — Trace memory writes to detect potential overflows
#include "pin.H"

VOID RecordMemWrite(VOID *addr, UINT32 size) {
    fprintf(trace, "W %p %u\n", addr, size);
}

VOID Instruction(INS ins, VOID *v) {
    if (INS_IsMemoryWrite(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
                       IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
    }
}
```

```bash
pin -t obj-intel64/pin_tool.so -- ./target input_file
```

**DynamoRIO** — Similar to Pin but open-source, supports ARM:

```c
// memtrace.c — Log all memory accesses
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    dr_register_bb_event(event_bb_app2app);
    dr_register_bb_event(event_bb_analysis);
    // Instrument each memory instruction
}
```

```bash
drrun -c memtrace.so -- ./target input_file
```

### 5.2 Taint Analysis

Taint analysis tracks how attacker-controlled data flows through a program, identifying which computation results are influenced by input.

**Using QEMU-based taint analysis (for research)**:

```bash
# Build QEMU with taint support (e.g., QEMU-TAINT or PANDA)
git clone https://github.com/panda-re/panda
cd panda && mkdir build && cd build
../configure --target-list=x86_64-softmmu && make -j$(nproc)

# Record execution
panda-system-x86_64 -hda disk.img -monitor stdio
# (interact with the target)

# Replay with taint analysis
panda-system-x86_64 -replay recording -taint \
    -taint_file input_offset_file
# input_offset_file specifies which bytes in the input to taint
```

**Libdft** (Princeton) provides fine-grained taint tracking at the instruction level:

```c
// libdft callback for data flow tracking
extern void libdft_taint_mem(DWORD addr, DWORD size, DWORD taint_id);
extern DWORD libdft_get_taint_mem(DWORD addr);

// Taint all read() input
void hook_read(CONTEXT *ctx, SYSCALL_STANDARD std) {
    DWORD fd = (DWORD)PIN_GetSyscallArgument(ctx, std, 0);
    if (fd == 0) {  // stdin
        DWORD buf = (DWORD)PIN_GetSyscallArgument(ctx, std, 1);
        DWORD size = (DWORD)PIN_GetSyscallArgument(ctx, std, 2);
        for (DWORD i = 0; i < size; i++)
            libdft_taint_mem(buf + i, 1, TAINT_TAG);
    }
}
```

**CTF Application**: Taint analysis reveals which program outputs (e.g., a comparison result) are influenced by which input bytes. This directly identifies format string vulnerabilities, info leaks (where input bytes reach a network send), and authentication bypasses (where input bytes influence a branch that decides access).

### 5.3 Concolic Execution

Concolic execution (concrete + symbolic) tracks symbolic constraints on program paths, then solves constraints to explore new paths. This excels at solving magic-byte checks that block pure fuzzing.

**KLEE** — Symbolic execution for C/C++ programs:

```c
// fuzz_target.c
#include <klee/klee.h>

int vulnerable_function(const char *input, int len) {
    if (len < 4) return 0;
    if (input[0] == 'H' && input[1] == 'E' && 
        input[2] == 'L' && input[3] == 'L') {
        // Trigger bug
        char buf[4];
        memcpy(buf, input + 4, len - 4);  // overflow!
    }
    return 0;
}

int main() {
    char input[32];
    klee_make_symbolic(input, sizeof(input), "input");
    vulnerable_function(input, 32);
    return 0;
}
```

```bash
# Compile to LLVM bitcode
clang -emit-llvm -g -O0 -Xclang -disable-O0-optnone -c fuzz_target.c

# Run KLEE
klee fuzz_target.bc

# KLEE will explore all paths and find the HELLO prefix automatically
# Generate test cases for all explored paths
ktest-tool klee-last/test000001.ktest
```

**angr** — Python-based binary analysis platform combining symbolic execution with concrete execution:

```python
import angr

proj = angr.Project('./target', auto_load_libs=False)

# Start from the program entry
state = proj.factory.entry_state(
    stdin=angr.SimFileStream(name='stdin', content=b'A' * 64, has_end=True)
)

# Or start from a specific address
state = proj.factory.call_state(0x4005a0)

simgr = proj.factory.simulation_manager(state)

# Explore until we reach the vulnerable function
simgr.explore(find=0x400700, avoid=0x400800)

if simgr.found:
    found = simgr.found[0]
    # Print the input that reaches the target
    print(found.posix.dumps(0))

    # Get constraint on specific bytes
    for byte_idx in range(8):
        byte_val = found.solver.eval(found.posix.stdin.content[byte_idx][0])
        print(f"byte[{byte_idx}] = {chr(byte_val)} (0x{byte_val:02x})")
```

**S2E** — Platform for selective symbolic execution within a full system:

```bash
# Launch S2E with a QEMU image
./launch-s2e.sh -d my_analysis

# S2E configuration (s2e-config.lua) defines analysis plugins:
-- plugins = {
--     "FunctionTracker",
--     "MemoryChecker",
--     "TaintAnalyzer"
-- }
```

S2E is the most powerful but also the most complex symbolic execution platform. It's best suited for:
- Analyzing kernel-mode code (drivers, filesystems)
- Fuzzing targets that require full-system state (BIOS, firmware)
- Scenarios where concrete and symbolic execution must interleave (device I/O, multi-process)

**Choosing between concolic tools**:

| Tool | Best For | Language | Complexity |
|------|----------|----------|------------|
| KLEE | Pure C/C++, source available | C/LLVM | Medium |
| angr | Binary analysis, reversing | Python | Medium |
| S2E | Full-system, kernel, firmware | C++/Lua | High |
| Triton | Lightweight binary SEA | Python/C++ | Low |
| Z3 (direct) | Constraint solving, custom tools | Python/C++/SMT-LIB | Medium |

**Practical CTF workflow** combining fuzzing and symbolic execution:

1. **Fuzz with AFL++** until you hit a coverage plateau (magic-byte check, complex condition)
2. **Extract the failing path constraints** using angr or Triton
3. **Solve the constraints** with Z3 to generate an input that passes the check
4. **Feed the solved input back** into AFL++ as a new seed
5. **Repeat** until full coverage or bug found

```bash
# Convert AFL++ crash to angr starting point
python3 << 'EOF'
import angr, claripy

proj = angr.Project('./target')
flag = claripy.BVS('flag', 16 * 8)  # 16-byte symbolic input

state = proj.factory.entry_state(
    stdin=angr.SimFileStream(content=flag, has_end=True)
)
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0xdeadbeef)  # address of win function

if simgr.found:
    solved = simgr.found[0].solver.eval(flag, cast_to=bytes)
    with open('solved_input', 'wb') as f:
        f.write(solved)
EOF

# Feed solved input back to AFL++
cp solved_input findings/corpus/
afl-fuzz -i findings/corpus/ -o findings2/ -- ./target @@
```

This hybrid approach combines the exploration breadth of fuzzing with the constraint-solving depth of symbolic execution, yielding results neither technique can achieve alone.

---

## Quick Reference: Common Commands

```bash
# AFL++ basic fuzzing
afl-fuzz -i corpus/ -o findings/ -M fuzzer01 -- ./target @@

# AFL++ with CMPLOG (recommended)
afl-fuzz -i corpus/ -o findings/ -c 0 -M fuzzer01 -- ./target_cmplog @@

# AFL++ persistent mode
afl-fuzz -i corpus/ -o findings/ -- ./target_persistent

# AFL++ QEMU mode (binary-only)
afl-fuzz -Q -i corpus/ -o findings/ -- ./binary_only @@

# libFuzzer basic
clang -g -fsanitize=fuzzer,address -o fuzz_target fuzz_target.c
./fuzz_target corpus/

# SYZKaller
./syz-manager -config=syz-manager.cfg

# Crash minimization
afl-tmin -i crash -o min_crash -- ./target @@

# Corpus minimization
afl-cmin -i findings/queue/ -o corpus_min/ -- ./target @@

# angr symbolic execution
python3 -c "
import angr; p = angr.Project('./target')
s = p.factory.entry_state()
p.factory.simulation_manager(s).explore(find=0x41414141)
print(s.found[0].posix.dumps(0)) if s.found else print('no path')
"

# GDB crash analysis
gdb -batch -ex run -ex bt -ex "info registers" --args ./target crash_file

# AddressSanitizer crash reproduction
ASAN_OPTIONS=abort_on_error=1 gdb ./target_asan crash_file
```

## References

1. [AFL++ — American Fuzzy Lop Plus Plus](https://github.com/AFLplusplus/AFLplusplus) — State-of-the-art mutation-based fuzzer
2. [libprotobuf-mutator](https://github.com/google/libprotobuf-mutator) — Structure-aware fuzzing with Protocol Buffers
3. [Grammar-Mutator](https://github.com/AFLplusplus/Grammar-Mutator) — Grammar-based input mutation for AFL++
4. [syzkaller — Kernel Fuzzer](https://github.com/google/syzkaller) — Coverage-guided syscall fuzzing for Linux kernels
5. [Mozilla Central Repository](https://hg.mozilla.org/mozilla-central/) — Firefox source for browser fuzzing targets
6. [PANDA — Platform for Architecture-Neutral Dynamic Analysis](https://github.com/panda-re/panda) — Record/replay framework for taint analysis
7. [Google OSS-Fuzz](https://github.com/google/oss-fuzz) — Continuous fuzzing infrastructure for open-source projects
8. [LLVM libFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html) — In-process, coverage-guided fuzzing engine
9. [Honggfuzz](https://github.com/google/honggfuzz) — Feedback-driven fuzzing with hardware counters
10. [AFL — American Fuzzy Lop (Original)](https://lcamtuf.coredump.cx/afl/) — Michal Zalewski's original coverage-guided fuzzer
11. [CVE — Common Vulnerabilities and Exposures](https://cve.mitre.org/) — Standardized vulnerability identifier database
12. [Vincent Arciuli — Fuzzing101](https://github.com/antonio-morales/Fuzzing101) — Step-by-step fuzzing tutorials for beginners

---

*This document serves as a comprehensive reference for fuzzing and dynamic analysis techniques in vulnerability research. For static analysis and vulnerability assessment methodology, see the companion document on static analysis.*
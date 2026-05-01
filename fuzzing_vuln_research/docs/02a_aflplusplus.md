# AFL++ Deep Dive

## 1. Architecture Overview

AFL++ is the community-driven successor to Michał Zalewski's AFL, maintained primarily by Andrea Fioraldi, Marc van Heerden, and Heiko Eißfeldt. It extends AFL's coverage-guided fuzzing paradigm with modern techniques while preserving AFL's ease of use and reliability. AFL++ consistently outperforms AFL in head-to-head benchmarks and has become the default mutation-based fuzzer for security researchers.

### 1.1 Core Components

AFL++ consists of several integrated components:

1. **Instrumentation backends**: Compiler passes that insert coverage-tracking code into the target binary
2. **Fork server**: A persistent parent process that forks children for each test case, avoiding repeated `execve()` overhead
3. **Shared memory feedback**: A 64K bitmap (expandable) shared between the fuzzer and target for real-time coverage reporting
4. **Mutation engine**: Extended from AFL with additional operators and scheduling strategies
5. **Scheduler**: Selects corpus entries for fuzzing based on various policies (fast, COE, rare, explore)

### 1.2 Compilation Pipeline

AFL++ supports multiple instrumentation backends, each with different tradeoffs:

```
Source Code → [Instrumentation Pass] → Instrumented Binary → [Fork Server] → Fuzzing
                     ↓
              afl-cc (compiler wrapper)
              ├── afl-gcc (GCC plugin, basic)
              ├── afl-clang (LLVM pass, standard)
              ├── afl-clang-lto (LTO, best coverage)
              └── afl-clang-fast (LLVM, good performance)
```

## 2. Compiler Instrumentation

### 2.1 afl-clang-fast (LLVM Pass)

The `afl-clang-fast` instrumentation uses an LLVM pass to insert coverage-tracking code at each basic block edge. The instrumentation:

1. Assigns each basic block a random ID
2. At each control-flow edge, increments the corresponding bitmap entry: `shared_mem[(src_id << 5) ^ dst_id]++`
3. The bitmap entry saturates at 255 (no wraparound)

This is the standard instrumentation mode and offers a good balance between coverage granularity and performance overhead (~10–15% compared to uninstrumented code).

**Compilation:**
```bash
export CC=afl-clang-fast
export CXX=afl-clang-fast++
./configure
make -j$(nproc)
```

### 2.2 afl-clang-lto (LTO Mode)

LTO (Link-Time Optimization) mode provides the best coverage by instrumenting at link time, after all optimizations have been applied. This ensures coverage tracking survives aggressive compiler optimizations (inlining, dead code elimination, etc.).

Key advantages:
- **No missed edges**: All edges are instrumented, even in heavily inlined code
- **Better coverage of library code**: LTO can instrument static libraries linked at LTO time
- **CmpLog integration**: Comparison logging is built into the LTO pass
- **Auto-dictionary**: Extracts comparison values during LTO for automatic dictionary generation

**Compilation:**
```bash
export CC=afl-clang-lto
export CXX=afl-clang-lto++
# Enable CmpLog for constraint solving
export AFL_LLVM_CMPLOG=1
./configure
make -j$(nproc)
```

### 2.3 afl-gcc (GCC Plugin)

The GCC-based instrumentation is simpler and less capable than the LLVM modes but works when LLVM is unavailable. It uses a GCC plugin to insert coverage code at the GIMPLE level.

```bash
export CC=afl-gcc
export CXX=afl-g++
```

### 2.4 Instrumentation Flags

AFL++ exposes several environment variables to control instrumentation:

| Variable | Description |
|----------|-------------|
| `AFL_LLVM_INSTRUMENT` | Select instrumentation type: `classic`, `LTO`, `PCGUARD`, `CFG` |
| `AFL_LLVM_CMPLOG` | Enable comparison logging (CmpLog) |
| `AFL_LLVM_LAF_SPLIT_SWITCHES` | Split switch statements into individual branches |
| `AFL_LLVM_LAF_TRANSFORM_COMPARES` | Transform string compares into byte-by-byte compares |
| `AFL_LLVM_LAF_SPLIT_COMPARES` | Split multi-byte comparisons into byte comparisons |
| `AFL_DONT_OPTIMIZE` | Disable AFL++'s own optimizations on the target |

## 3. Fork Server

### 3.1 Architecture

The fork server is AFL's key performance innovation. Instead of calling `execve()` for every test case (which involves loading the binary, resolving shared libraries, running initializers), the fork server:

1. **Once**: The target binary starts, completes initialization, and signals readiness to the fuzzer
2. **Per test case**: The fork server `fork()`s a child process, the child processes the input, and the parent collects the result

```
Fuzzer Process                Fork Server (target binary)
    │                              │
    ├── send test case ──────────→ │
    │                              ├── fork()
    │                              │    ├── child: process input
    │                              │    └── child: exit
    │←──── status (exit/signal) ──┤
    │                              │
```

This eliminates the overhead of repeated program loading and initialization. The fork server typically provides 5–10x throughput improvement over naive `execve()`-per-input.

### 3.2 Fork Server Configuration

```bash
# Disable fork server (use execve for each input)
AFL_NO_FORKSRV=1 afl-fuzz -i in -o out -- ./target @@

# Fork server is enabled by default for instrumented binaries
afl-fuzz -i in -o out -- ./target @@
```

## 4. Shared Memory Feedback

### 4.1 Bitmap Structure

AFL++ uses a shared memory region (default 64K, can be expanded) as the coverage bitmap. The target binary writes to this bitmap during execution; the fuzzer reads it after each test case.

**Bitmap entry semantics:**
- `0`: Edge never executed
- `1–255`: Edge executed, with approximate hit count
- Saturation at 255 prevents overflow-based loss of signal

**New coverage detection:**
- An edge transitions from 0 → non-zero: **new edge discovered**
- An edge transitions across a power-of-2 boundary (e.g., 3→4, 7→8): **new hit count discovered** (indicates a new path to this edge)

This "new hit count" heuristic is surprisingly effective: it helps the fuzzer distinguish between paths that traverse the same edges but with different frequencies (e.g., a loop iteration count).

### 4.2 Expanded Bitmap

For large targets (>100K edges), the default 64K bitmap suffers from hash collisions, causing the fuzzer to miss new coverage. AFL++ supports larger bitmaps:

```bash
# Use 1MB bitmap (16x larger)
AFL_MAP_SIZE=1048576 afl-fuzz -i in -o out -- ./target @@
```

This must be set during **both** compilation and fuzzing.

## 5. Configuration Options

### 5.1 Performance Options

| Variable | Description |
|----------|-------------|
| `AFL_TRY_AFFINITY` | Try to bind the fuzzer to a specific CPU core for better cache locality |
| `AFL_FAST_CAL` | Skip the expensive calibration phase for new corpus entries |
| `AFL_HANG_TMOUT` | Timeout for hang detection (default: 1/10 of `-t` value, min 1s) |
| `AFL_KILL_SIGNAL` | Signal to send to hung children (default: SIGKILL) |
| `AFL_FORKSRV_INIT_TMOUT` | Timeout for fork server startup (default: 2000ms) |
| `AFL_MAX_FILE` | Maximum input size (default: 1MB) |

### 5.2 Mutation Options

| Variable | Description |
|----------|-------------|
| `AFL_DISABLE_HARNESS` | Disable AFL's internal checks for custom harness support |
| `AFL_CUSTOM_MUTATOR` | Path to custom mutator library |
| `AFL_CUSTOM_MUTATOR_ONLY` | Use only the custom mutator (skip built-in mutations) |
| `AFL_PYTHON_MODULE` | Python custom mutator module name |

### 5.3 Scheduling Options

AFL++ supports multiple corpus scheduling policies:

```bash
# Default: explore (balanced exploration/exploitation)
afl-fuzz -i in -o out -L 0 -- ./target @@

# Coe (Cut-Off-Edges): prioritize edges with few parent inputs
afl-fuzz -i in -o out -L 1 -- ./target @@

# Rare: prioritize edges that are hit least often
afl-fuzz -i in -o out -L 2 -- ./target @@

# Fast: prioritize inputs with fast execution time
afl-fuzz -i in -o out -L -1 -- ./target @@
```

## 6. CmpLog

### 6.1 Overview

CmpLog is AFL++'s most powerful constraint-solving feature. It records the operands of comparison instructions during execution, then uses these values to guide mutation.

**Without CmpLog**, the fuzzer must guess magic values through random mutation. **With CmpLog**, the fuzzer knows exactly what value a comparison expects and can insert it directly.

### 6.2 How CmpLog Works

1. **Instrumentation phase**: The compiler instruments comparison instructions (`cmp`, `cmpl`, `switch`, string comparisons) to log their operands to a shared memory region
2. **Execution phase**: When the target processes an input, comparison operands are recorded
3. **Fuzzer phase**: The fuzzer reads the logged comparison values and uses them as mutation candidates

**Example:**
```c
// Target code
if (*(uint32_t*)buf == 0x89504E47) { // PNG magic
    parse_png(buf, len);
}
```

Without CmpLog, the fuzzer has a 1/2^32 chance of generating the PNG magic number. With CmpLog, the fuzzer sees that a comparison expects `0x89504E47` and can insert this value directly.

### 6.3 Enabling CmpLog

```bash
# Compile with CmpLog instrumentation
export CC=afl-clang-lto
export AFL_LLVM_CMPLOG=1
./configure && make -j$(nproc)

# Run fuzzer with CmpLog
afl-fuzz -i in -o out -c 0 -- ./target @@
```

The `-c 0` flag tells the fuzzer to use CmpLog with the most aggressive mode (replace compared values with logged values). Alternative values:
- `-c 0`: Replace comparison operands with CmpLog values (most aggressive)
- `-c 1`: Insert CmpLog values at nearby positions
- `-c 2`: Transform comparison inputs (less aggressive)

## 7. Persistent Mode

### 7.1 Architecture

Persistent mode eliminates even the `fork()` overhead by processing multiple inputs in a single process. The target initializes once, then processes inputs in a loop.

```c
#include <stdint.h>
#include <stddef.h>

__AFL_FUZZ_INIT();

int main(void) {
    // One-time initialization
    init_global_state();

    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_INIT()) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        
        // Reset state between iterations
        reset_state();
        
        // Process input
        process(buf, len);
    }
    return 0;
}
```

### 7.2 __AFL_FUZZ_INIT() and Related Macros

| Macro | Description |
|-------|-------------|
| `__AFL_INIT()` | Start the fork server / persistent loop |
| `__AFL_LOOP(n)` | Process up to n inputs before re-forking (legacy API) |
| `__AFL_FUZZ_INIT()` | Declare shared memory for testcase buffer |
| `__AFL_FUZZ_TESTCASE_BUF` | Pointer to the current testcase in shared memory |
| `__AFL_FUZZ_TESTCASE_LEN` | Length of the current testcase |

### 7.3 State Leakage Concerns

Persistent mode introduces the risk of **state leakage**: leftover state from a previous iteration affecting the current iteration. This can cause:
- **False crashes**: A bug in cleanup code, not in the target logic
- **Missed bugs**: A bug that only manifests with specific state from a previous iteration
- **Non-deterministic coverage**: Coverage that depends on previous inputs, confusing the fuzzer

Mitigation: Reset all relevant state between iterations. For complex targets, use `__AFL_LOOP(1)` (effectively fork-server mode) or limit to a moderate number of iterations (e.g., `__AFL_LOOP(1000)`).

## 8. LTO Mode

### 8.1 Overview

Link-Time Optimization mode instruments the target at the LTO stage, after all other compiler optimizations. This provides maximum coverage because:

1. Inlined functions are instrumented (they'd be invisible to post-link instrumentation)
2. Dead code is eliminated before instrumentation (no wasted bitmap entries)
3. Cross-language optimization (C + Rust + assembly) is handled uniformly

### 8.2 Auto-Dictionary

LTO mode automatically extracts comparison values from the target binary. If the code contains:

```c
if (strcmp(ext, ".png") == 0) { ... }
```

The auto-dictionary feature extracts `".png"` and adds it to the fuzzer's dictionary automatically.

```bash
export AFL_LLVM_CMPLOG=1
export AFL_LLVM_LAF_SPLIT_SWITCHES=1
export AFL_LLVM_LAF_TRANSFORM_COMPARES=1
export AFL_LLVM_LAF_SPLIT_COMPARES=1
```

The LAF (LTO-AFL) transforms are crucial:
- **SPLIT_SWITCHES**: Converts `switch(x)` into `if-else` chains, making each case individually discoverable
- **TRANSFORM_COMPARES**: Converts `memcmp(a, b, 4)` into four individual byte comparisons, making partial matches discoverable
- **SPLIT_COMPARES**: Splits multi-byte integer comparisons into byte-by-byte comparisons

## 9. QEMU Mode

### 9.1 Overview

QEMU mode enables fuzzing of **closed-source binaries** without recompilation. It uses a modified QEMU user-mode emulator that instruments translated basic blocks for coverage tracking.

```bash
# Build QEMU support
cd qemu_mode && ./build_qemu_support.sh

# Fuzz with QEMU mode
afl-fuzz -i in -o out -Q -- ./target_binary @@
```

### 9.2 Performance

QEMU mode is significantly slower than native instrumentation (~3–5x overhead from binary translation plus ~2x from coverage tracking). Despite this, it's invaluable for:
- Closed-source firmware components
- Proprietary libraries
- Binary-only targets
- Quick triage when source isn't available

### 9.3 QEMU Mode Internals

AFL++'s QEMU mode patches QEMU's Tiny Code Generator (TCG) to insert coverage instrumentation at each basic block translation. The instrumentation:
1. Computes an edge hash: `(source_pc << 5) ^ target_pc`
2. Increments the corresponding shared memory bitmap entry
3. The bitmap is the same format as the compiler-instrumented mode

## 10. Unicorn Mode

### 10.1 Overview

Unicorn mode enables fuzzing of **raw firmware blobs** and embedded code using the Unicorn CPU emulator. Unlike QEMU mode (which emulates a full user-space process), Unicorn mode emulates only the CPU, allowing researchers to fuzz bare-metal code.

```bash
# Build Unicorn support
cd unicorn_mode && ./build_unicorn_support.sh

# Fuzz with Unicorn mode
afl-fuzz -i in -o out -U -- ./fuzz_harness.py @@
```

### 10.2 Unicorn Harness Example

```python
import unicorn
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_PROT_ALL
from unicorn import UC_HOOK_CODE
import struct

MEMORY_BASE = 0x10000
STACK_BASE   = 0x800000
STACK_SIZE   = 0x10000

def fuzz_harness(data, size):
    if size < 4:
        return
    
    mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    mu.mem_map(MEMORY_BASE, 0x100000, UC_PROT_ALL)
    mu.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
    
    # Load firmware code
    with open("firmware.bin", "rb") as f:
        code = f.read()
    mu.mem_write(MEMORY_BASE, code)
    
    # Write fuzz input to memory
    mu.mem_write(MEMORY_BASE + 0x50000, bytes(data[:size]))
    
    # Set up registers
    mu.reg_write(unicorn.arm_const.UC_ARM_REG_R0, MEMORY_BASE + 0x50000)
    mu.reg_write(unicorn.arm_const.UC_ARM_REG_R1, size)
    mu.reg_write(unicorn.arm_const.UC_ARM_REG_SP, STACK_BASE + STACK_SIZE - 4)
    
    # Execute
    try:
        mu.emu_start(MEMORY_BASE | 1, MEMORY_BASE + len(code))
    except unicorn.UcError:
        pass
```

## 11. AFL++ Proxy

### 11.1 Overview

AFL++ proxy mode allows an external tool to drive the fuzzing loop while using AFL++'s mutation engine and coverage tracking. This is useful for:
- **Custom fuzzing strategies**: Implement your own scheduling, corpus management, etc.
- **Hybrid fuzzing**: Combine AFL++ with symbolic execution, concolic execution, etc.
- **Network fuzzing**: Use AFL++'s mutations for protocol fuzzing with a custom transport layer

### 11.2 Proxy API

The proxy communicates with AFL++ via shared memory:

```c
#include "afl-fuzz.h"

typedef struct custom_mutator {
    afl_state_t *afl;
    // Custom state
} custom_mutator_t;

custom_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {
    custom_mutator_t *cm = calloc(1, sizeof(custom_mutator_t));
    cm->afl = afl;
    return cm;
}

size_t afl_custom_fuzz(custom_mutator_t *cm, uint8_t *buf, size_t buf_size,
                       uint8_t **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {
    // Custom mutation logic
    *out_buf = buf;
    return buf_size;
}

void afl_custom_deinit(custom_mutator_t *cm) {
    free(cm);
}
```

## 12. Grammar-Based Fuzzing with AFL++

### 12.1 Overview

AFL++ supports grammar-based fuzzing through custom mutators that respect the structure of the input format. This is essential for targets that require highly structured input (SQL, XML, programming languages, network protocols).

### 12.2 Grammar Mutator

The `grammar_mutator` is an AFL++ custom mutator that uses a grammar description to generate and mutate structured inputs:

```bash
# Compile with grammar mutator
cd custom_mutators/grammar_mutator
make

# Create grammar description (JSON format)
cat > grammar.json << 'EOF'
{
  "rule_name": "sql_query",
  "rules": {
    "sql_query": ["SELECT", ["select_list"], "FROM", ["table_name"], ["where_opt"]],
    "select_list": ["*", [["column_name", ",", ["column_name"]]]],
    "column_name": ["id", "name", "email", "password"],
    "table_name": ["users", "accounts", "sessions"],
    "where_opt": [["WHERE", ["condition"]], ""],
    "condition": [["column_name"], ["op"], ["value"]],
    "op": ["=", "!=", "<", ">", "LIKE"],
    "value": ["1", "'test'", "'OR 1=1--'"]
  }
}
EOF

# Fuzz with grammar mutator
AFL_CUSTOM_MUTATOR=1 \
AFL_CUSTOM_MUTATOR_ONLY=1 \
afl-fuzz -i in -o out -- ./target @@
```

## 13. Custom Mutators

### 13.1 C Custom Mutator

```c
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "afl-fuzz.h"

typedef struct {
    afl_state_t *afl;
    uint8_t *mut_buf;
} my_mutator_t;

my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {
    my_mutator_t *m = calloc(1, sizeof(my_mutator_t));
    m->afl = afl;
    m->mut_buf = malloc(MAX_FILE);
    srand(seed);
    return m;
}

size_t afl_custom_fuzz(my_mutator_t *m, uint8_t *buf, size_t buf_size,
                       uint8_t **out_buf, uint8_t *add_buf,
                       size_t add_buf_size, size_t max_size) {
    // Custom mutation: swap two random bytes
    if (buf_size < 2) {
        *out_buf = buf;
        return buf_size;
    }
    
    memcpy(m->mut_buf, buf, buf_size);
    
    size_t pos1 = rand() % buf_size;
    size_t pos2 = rand() % buf_size;
    uint8_t tmp = m->mut_buf[pos1];
    m->mut_buf[pos1] = m->mut_buf[pos2];
    m->mut_buf[pos2] = tmp;
    
    *out_buf = m->mut_buf;
    return buf_size;
}

const char *afl_custom_int_havoc_mutation_supported(my_mutator_t *m) {
    return "swap";
}

uint8_t afl_custom_int_havoc(my_mutator_t *m, uint8_t *buf, size_t buf_size,
                              size_t max_size) {
    // Optional: custom havoc mutation
    return 0;
}

void afl_custom_deinit(my_mutator_t *m) {
    free(m->mut_buf);
    free(m);
}
```

Compile as a shared library:
```bash
gcc -shared -fPIC -o my_mutator.so my_mutator.c
```

### 13.2 Python Custom Mutator

```python
import random
from custom_mutator import CustomMutator

class MyMutator(CustomMutator):
    def __init__(self, afl_state, seed):
        super().__init__(afl_state, seed)
        self.rng = random.Random(seed)
    
    def fuzz(self, buf, add_buf, max_size):
        # Custom mutation logic
        buf = bytearray(buf)
        if len(buf) < 4:
            return bytes(buf)
        
        # Insert a known token at a random position
        tokens = [b"SELECT", b"FROM", b"WHERE", b"DROP", b"UNION"]
        token = self.rng.choice(tokens)
        pos = self.rng.randint(0, max(0, len(buf) - len(token)))
        buf[pos:pos+len(token)] = token
        
        return bytes(buf[:max_size])
```

```bash
# Run with Python mutator
AFL_PYTHON_MODULE=my_mutator \
AFL_CUSTOM_MUTATOR_ONLY=1 \
afl-fuzz -i in -o out -- ./target @@
```

## 14. Dictionary Usage

### 14.1 What Are Dictionaries?

Dictionaries are lists of tokens that the fuzzer can insert into inputs. They dramatically improve the fuzzer's ability to pass magic number checks and keyword comparisons.

### 14.2 Dictionary Format

```
# AFL++ dictionary format
# One token per line, as a quoted string or hex value
"SELECT"
"FROM"
"WHERE"
"INSERT"
"UPDATE"
"DELETE"
0x89504E47   # PNG magic
0x504B0304   # ZIP magic
0x25504446   # PDF magic
```

### 14.3 Using Dictionaries

```bash
# Built-in dictionaries (AFL++ ships with many)
ls /usr/share/afl/dictionaries/

# Use a dictionary
afl-fuzz -i in -o out -x dict.txt -- ./target @@

# Auto-dictionary (LTO mode extracts from binary automatically)
export AFL_LLVM_CMPLOG=1  # Enables auto-dictionary
```

### 14.4 Creating Custom Dictionaries

**Method 1: Manual extraction from specification**
```bash
# Extract keywords from RFC/spec
cat rfc.txt | grep -oP '"[A-Z_]+"' | sort -u > dict.txt
```

**Method 2: Auto-extraction from source**
```bash
# Extract string literals from binary
strings target_binary | grep -P '^.{2,20}$' > dict.txt
```

**Method 3: AFL++ auto-dictionary (LTO mode)**
The compiler automatically extracts comparison values during LTO instrumentation.

## 15. Corpus Minimization

### 15.1 Why Minimize?

Over time, the corpus grows with entries that provide overlapping coverage. Corpus minimization reduces the corpus to the smallest set that provides the same coverage, saving disk space and improving scheduling efficiency.

### 15.2 Minimization Commands

```bash
# Minimize corpus (keep only entries providing unique coverage)
afl-cmin -i corpus/ -o corpus_min/ -- ./target @@

# Minimize individual test cases (find shortest input for each crash)
afl-tmin -i crashes/id:000001 -o min_crash -- ./target @@

# Minimize with timeout
afl-tmin -i crashes/id:000001 -o min_crash -t 1000 -- ./target @@
```

### 15.3 Corpus Minimization Algorithm

`afl-cmin` works by:
1. Collecting coverage from every corpus entry
2. Iteratively removing entries whose coverage is a subset of other entries' coverage
3. This is an NP-hard problem (set cover), so a greedy heuristic is used

`afl-tmin` works by:
1. Starting with the original test case
2. Trying to truncate from the end
3. Trying to remove blocks of bytes
4. Trying to replace bytes with zeros
5. Keeping the smallest input that still produces the same behavior (crash/coverage)

## 16. Crash Triage

### 16.1 Overview

After a fuzzing campaign, you'll have potentially hundreds of crash files. Crash triage is the process of determining which crashes are:
- **Exploitable**: Can lead to arbitrary code execution or significant privilege escalation
- **Casual**: Crashes that don't have security implications (null dereference in a CLI tool)
- **Duplicate**: Same root cause as another crash

### 16.2 Crash Classification with AFL++

```bash
# Basic crash triage
for crash in out/default/crashes/id:*; do
    echo "=== $crash ==="
    # Run under ASan for detailed error report
    ./target_asan "$crash" 2>&1 | head -20
    echo
done
```

### 16.3 Exploitable Classification with !exploitable

The `!exploitable` (bang exploitable) tool classifies crashes based on the crash context:

| Classification | Description |
|---------------|-------------|
| **EXPLOITABLE** | Likely exploitable (e.g., write to controlled address) |
| **PROBABLY_EXPLOITABLE** | May be exploitable (e.g., read from controlled address) |
| **PROBABLY_NOT_EXPLOITABLE** | Unlikely exploitable (e.g., null dereference) |
| **NOT_EXPLOITABLE** | Not exploitable (e.g., assertion failure) |

### 16.4 ASan-Based Triage

```bash
# Compile with ASan for crash triage
export CC=afl-clang-fast
export CFLAGS="-fsanitize=address -g -O1"
./configure && make

# Triage each crash
for crash in out/default/crashes/id:*; do
    ./target_asan "$crash" 2>&1 | grep -E "ERROR|SUMMARY|heap-|stack-|global-"
done | sort | uniq -c | sort -rn
```

### 16.5 Stack-Hash Deduplication

Crashes are deduplicated based on the stack trace hash. Two crashes with the same top-N frames are considered duplicates. AFL++ performs this automatically during fuzzing, producing only "unique" crashes.

However, stack-hash deduplication is imperfect:
- Two different bugs can have the same crash site (false negative)
- The same bug can crash at different sites depending on the input (false positive)

For accurate deduplication, use root-cause analysis:
```bash
# GDB-based root cause analysis
gdb -batch -ex run -ex bt ./target_asan < crash_file
```

## 17. Parallel Fuzzing

### 17.1 Multi-Core Fuzzing

AFL++ supports parallel fuzzing with multiple fuzzer instances sharing a single output directory:

```bash
# Main fuzzer (primary)
afl-fuzz -i in -o out -M main -- ./target @@

# Secondary fuzzers (different mutation strategies)
afl-fuzz -i in -o out -S sub1 -- ./target @@
afl-fuzz -i in -o out -S sub2 -- ./target @@
afl-fuzz -i in -o out -S sub3 -- ./target @@
```

Primary (`-M`) and secondary (`-S`) fuzzers coordinate through the shared output directory:
- Corpus entries are shared via the `out/main/queue/` and `out/sub*/queue/` directories
- Crashes from all instances are collected centrally
- Each instance reads new entries from other instances' queues

### 17.2 Cloud Fuzzing with AFL++

```bash
# On each VM, start a secondary fuzzer pointing to shared storage
# (NFS, GCS FUSE, etc.)
afl-fuzz -i in -o /shared/out -S host$(hostname) -- ./target @@
```

## 18. Advanced Techniques

### 18.1 Zero-Call-Function Mode

For functions that don't call other functions (e.g., crypto primitives), AFL++ can use basic block coverage instead of edge coverage:

```bash
AFL_LLVM_INSTRUMENT=CFG afl-clang-fast -o target target.c
```

### 18.2 Fuzzing with Address Sanitizer and Persistence

Combining ASan with persistent mode is possible but requires care:

```c
// Persistent mode + ASan: use ASAN_UNPOISON_MEMORY_REGION
// if you manage memory manually
__AFL_FUZZ_INIT();

int main(void) {
    init();
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(1000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        process(buf, len);
    }
    return 0;
}
```

### 18.3 Post-Processing Crashes

After a campaign, use `afl-plot` for visualization:

```bash
# Generate coverage/crash plots
afl-plot out/default/ /tmp/afl_plots/

# View stats
cat out/default/fuzzer_stats
```

## References

[1] Fioraldi, A., Maier, D., Eißfeldt, H., & Heuse, M. (2020). *AFL++: Combining Incremental Steps of Fuzzing Research*. USENIX WOOT.

[2] Zalewski, M. (2013). *American Fuzzy Lop (AFL)*. https://lcamtuf.coredump.cx/afl/

[3] AFL++ Project. *AFL++ Documentation*. https://github.com/AFLplusplus/AFLplusplus

[4] Fioraldi, A. (2021). *CmpLog: Speeding Up Fuzzing by Recording Comparison Results*. IEEE S&P Workshop.

[5] Böhme, M., Pham, V.T., & Roychoudhury, A. (2017). *Coverage-Based Greybox Fuzzing as Markov Chain*. IEEE S&P. DOI: 10.1109/SP.2017.41

[6] Nguyen, H. & Böhme, M. (2021). *MOpt: Multi-Object Particle Swarm Optimization for Fuzzing*. IEEE PPT.

[7] Serebryany, K. (2016). *Announcing OSS-Fuzz: Continuous Fuzzing for Open Source Software*. Google Security Blog. https://security.googleblog.com/2016/12/announcing-oss-fuzz-continuous-fuzzing.html

[8] Wang, J., et al. (2020). *Superion: Grammar-Aware Greybox Fuzzing*. ICSE.

[9] Aschermann, K., et al. (2019). *REDQUEEN: Fuzzing with Input-to-State Correspondence*. NDSS.

[10] Google. *ClusterFuzz Documentation*. https://google.github.io/clusterfuzz/

[11] HexRays. *IDA Pro Disassembler*. https://hex-rays.com/ida-pro/

[12] Schwitalla, J. & Eißfeldt, H. (2021). *AFL++ QEMU Mode*. AFL++ Documentation.

[13]unicorn-engine.org. *Unicorn: CPU Emulator Framework*. https://www.unicorn-engine.org/

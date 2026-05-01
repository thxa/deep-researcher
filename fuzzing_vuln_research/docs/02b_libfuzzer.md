# libFuzzer Deep Dive

## 1. In-Process Fuzzing Model

### 1.1 Architecture

libFuzzer, part of the LLVM project since LLVM 6.0, implements an **in-process** fuzzing model. Unlike AFL which forks a new process for each test case, libFuzzer calls the fuzz target function repeatedly within the same process. This eliminates fork/exec overhead and achieves orders-of-magnitude higher throughput.

```
┌─────────────────────────────────────────────────────┐
│  libFuzzer Process                                  │
│                                                     │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐     │
│  │ Mutator  │───→│ Target   │───→│ Coverage │     │
│  │ Engine   │    │ Function │    │ Tracker  │     │
│  └──────────┘    └──────────┘    └──────────┘     │
│       ↑              │                │             │
│       │              ↓                ↓             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐     │
│  │ Corpus   │    │ Sanitizer│    │ Feedback │     │
│  │ Manager  │    │ Runtime  │    │ Loop     │     │
│  └──────────┘    └──────────┘    └──────────┘     │
└─────────────────────────────────────────────────────┘
```

**Key advantages of in-process fuzzing:**
- **10–1000x throughput** compared to out-of-process fuzzers
- **No fork overhead**: No `fork()`, `execve()`, or process initialization per test case
- **Direct coverage access**: Coverage data is available in-process, no shared memory overhead
- **Integrated sanitizer support**: ASan, MSan, UBSan, TSan run in the same process

**Key risks of in-process fuzzing:**
- **State leakage**: Global state from one iteration affects the next
- **Memory leaks accumulate**: Leaks in the target accumulate across iterations
- **No isolation**: A crash kills the entire fuzzer process (mitigated by `fork()` mode)
- **Global state corruption**: A bug in one iteration may corrupt state that affects subsequent iterations

### 1.2 The Fuzz Target Function

Every libFuzzer target must implement the `LLVMFuzzerTestOneInput` function:

```c
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Process fuzz input
    process_data(data, size);
    return 0;
}
```

The function must:
- Return 0 (the return value is currently unused but must be 0 for forward compatibility)
- Not exit the process (don't call `exit()` or `abort()` except on error)
- Be thread-safe if the fuzzer is run with `-jobs=` flag
- Handle any input, including empty input (size=0)
- Clean up allocated memory (to avoid MSan false positives and leak reports)

### 1.3 Initialization

libFuzzer supports one-time initialization via `LLVMFuzzerInitialize`:

```c
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    // One-time setup
    init_global_state();
    return 0;
}
```

This is called once before the fuzzing loop begins. Use it for:
- Loading configuration files
- Initializing global data structures
- Setting up network connections (for protocol fuzzing)
- Configuring sanitizers

## 2. FuzzedDataProvider

### 2.1 Overview

`FuzzedDataProvider` is a utility class that provides a convenient way to consume structured data from the fuzz input. It handles reading typed values, strings, and random selections from the input buffer.

### 2.2 C++ API

```cpp
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    
    // Consume primitive types
    uint8_t byte_val = fdp.ConsumeIntegral<uint8_t>();
    uint16_t short_val = fdp.ConsumeIntegral<uint16_t>();
    uint32_t int_val = fdp.ConsumeIntegral<uint32_t>();
    int64_t long_val = fdp.ConsumeIntegral<int64_t>();
    bool flag = fdp.ConsumeBool();
    
    // Consume values within a range
    uint8_t bounded = fdp.ConsumeIntegralInRange<uint8_t>(0, 100);
    
    // Consume floating-point values
    float f = fdp.ConsumeFloatingPoint<float>();
    double d = fdp.ConsumeProbability<double>();  // [0.0, 1.0]
    
    // Consume strings
    std::string str = fdp.ConsumeString(32);
    std::string random_str = fdp.ConsumeRandomLengthString(256);
    
    // Consume bytes
    std::vector<uint8_t> bytes = fdp.ConsumeBytes<uint8_t>(64);
    std::vector<uint8_t> remaining = fdp.ConsumeRemainingBytes<uint8_t>();
    
    // Pick from an enum
    enum Op { READ, WRITE, DELETE, CREATE };
    Op op = fdp.ConsumeEnum<Op>();
    
    // Pick from a fixed set
    auto choice = fdp.PickValueInArray({1, 2, 5, 10, 100});
    
    // Use consumed values
    handle_request(op, bounded, str, remaining);
    
    return 0;
}
```

### 2.3 Consumption Strategy

`FuzzedDataProvider` consumes data from the **end** of the input buffer. This is intentional: mutation-based fuzzers tend to add new data at the end of inputs, so consuming from the end ensures that newly added bytes are used by the most recent `Consume*` calls.

This design has important implications for fuzz target design:
- Put the most important fields (the ones you want the fuzzer to explore) first in the consumption sequence
- Use `ConsumeRemainingBytes` for the payload (the data the fuzzer should most freely mutate)

## 3. Custom Mutators

### 3.1 libFuzzer Custom Mutator API

libFuzzer allows you to replace or augment its built-in mutation engine with a custom mutator:

```c
size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
                                size_t max_size, unsigned int seed) {
    // Custom mutation logic
    // data: current input (modify in place)
    // size: current input size
    // max_size: maximum allowed size
    // seed: random seed for this mutation
    
    // Example: swap two random bytes
    if (size < 2) return size;
    
    srand(seed);
    size_t i = rand() % size;
    size_t j = rand() % size;
    uint8_t tmp = data[i];
    data[i] = data[j];
    data[j] = tmp;
    
    return size;
}
```

### 3.2 Custom Crossover

For combining two inputs (analogous to AFL's splice):

```c
size_t LLVMFuzzerCustomCrossOver(const uint8_t *data1, size_t size1,
                                  const uint8_t *data2, size_t size2,
                                  uint8_t *out, size_t max_out_size,
                                  unsigned int seed) {
    // Combine data1 and data2 into out
    srand(seed);
    size_t cut1 = rand() % size1;
    size_t cut2 = rand() % size2;
    size_t out_size = cut1 + (size2 - cut2);
    
    if (out_size > max_out_size) out_size = max_out_size;
    
    memcpy(out, data1, cut1);
    memcpy(out + cut1, data2 + cut2, out_size - cut1);
    
    return out_size;
}
```

### 3.3 Structure-Aware Custom Mutators

For highly structured inputs, the custom mutator can maintain an internal representation:

```c
typedef struct {
    uint16_t msg_type;
    uint32_t seq_num;
    uint8_t  flags;
    // ...
} __attribute__((packed)) msg_t;

static thread_local msg_t *g_msg = NULL;

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
                                size_t max_size, unsigned int seed) {
    if (size < sizeof(msg_t)) {
        // Generate a new message from scratch
        if (max_size < sizeof(msg_t)) return 0;
        msg_t *msg = (msg_t *)data;
        msg->msg_type = rand() % 16;
        msg->seq_num = rand();
        msg->flags = rand() % 4;
        return sizeof(msg_t);
    }
    
    // Mutate a specific field
    msg_t *msg = (msg_t *)data;
    srand(seed);
    int field = rand() % 3;
    switch (field) {
        case 0: msg->msg_type = rand() % 16; break;
        case 1: msg->seq_num = rand(); break;
        case 2: msg->flags ^= (1 << (rand() % 8)); break;
    }
    
    return size;
}
```

## 4. Dictionary Usage

### 4.1 Specifying Dictionaries

libFuzzer supports dictionaries for keyword-aware mutation:

```bash
# Run with dictionary
./fuzz_target -dict=token.dict corpus/
```

### 4.2 Dictionary Format

The libFuzzer dictionary format is the same as AFL's:

```
# Keywords
"SELECT"
"INSERT"
"UPDATE"
"DELETE"
# Binary tokens
\x89PNG\r\n\x1a\n
PK\x03\x04
%PDF
```

### 4.3 Dictionary Effectiveness

Dictionaries are most effective when:
- The target performs exact-match comparisons against known strings
- The target parses keywords or identifiers from the input
- The target checks magic numbers or headers

Empirically, providing a dictionary can increase coverage by 20–50% for keyword-heavy targets.

## 5. Corpus Management

### 5.1 Automatic Corpus Management

libFuzzer automatically manages the corpus:
1. New inputs that produce new coverage are added to the corpus
2. The corpus is stored on disk in the specified corpus directory
3. Each entry is a file whose name is a hash of its contents

### 5.2 Merge Operation

The merge operation combines multiple corpora, keeping only entries that add unique coverage:

```bash
# Merge corpus1 and corpus2 into merged_corpus
./fuzz_target -merge=1 merged_corpus/ corpus1/ corpus2/
```

This is essential for:
- **Distributed fuzzing**: Merge results from multiple workers
- **Corpus cleanup**: Remove redundant entries after a long campaign
- **Bringing in new seeds**: Add discovered inputs from other sources

### 5.3 Minimize Operation

The minimize operation reduces the corpus to the smallest set of files that provides the same coverage:

```bash
# Minimize corpus
./fuzz_target -minimize_crash=1 -runs=100000 corpus/ min_corpus/
```

Individual crash minimization:
```bash
# Find smallest input that triggers a crash
./fuzz_target -minimize_crash=1 crash_file -runs=100000
```

### 5.4 Merge-Minimize Workflow

The recommended workflow for long-running campaigns:

```bash
# Step 1: Run fuzzer for a while
./fuzz_target corpus/

# Step 2: Periodically merge with known corpus
./fuzz_target -merge=1 corpus/ seed_corpus/ new_findings/

# Step 3: At the end, minimize the corpus
mkdir min_corpus
./fuzz_target -merge=1 min_corpus/ corpus/

# Step 4: Verify coverage
./fuzz_target corpus/ -runs=0
```

## 6. Value Profile

### 6.1 Overview

Value profile (also called "value coverage" or "cmp coverage") extends coverage tracking to include the **values** seen at comparison instructions. This helps the fuzzer discover paths guarded by specific values.

### 6.2 How It Works

Without value profile, the fuzzer only knows that a branch was taken or not taken. With value profile, the fuzzer knows *what values were compared*, enabling it to generate inputs that pass specific checks.

**Example:**
```c
if (x == 0xDEADBEEF) {
    // Hidden path
}
```

Without value profile, the fuzzer would need to randomly generate `0xDEADBEEF`. With value profile, the fuzzer sees that the comparison expects `0xDEADBEEF` and can insert this value.

### 6.3 Enabling Value Profile

```bash
# Compile with value profile instrumentation
clang -g -O1 -fsanitize=fuzzer,address \
      -fsanitize-coverage=trace-cmp,pc-table \
      -o fuzz_target fuzz_target.c

# Run with value profile
./fuzz_target corpus/ -use_value_profile=1
```

Value profile is particularly effective for:
- Magic number comparisons
- Switch statements with many cases
- Hash table lookups
- Command/opcode dispatch

## 7. Fuzz Target Design Patterns

### 7.1 The Split-Input Pattern

For targets that accept multiple inputs or have a structured format:

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Split input into header and body
    const size_t HEADER_SIZE = 16;
    if (size < HEADER_SIZE) return 0;
    
    const uint8_t *header = data;
    const uint8_t *body = data + HEADER_SIZE;
    size_t body_size = size - HEADER_SIZE;
    
    // Parse header
    uint32_t flags = *(uint32_t *)(header + 0);
    uint32_t count = *(uint32_t *)(header + 4);
    uint64_t reserved = *(uint64_t *)(header + 8);
    
    // Validate
    if (count > body_size / 4) return 0;
    
    // Process
    process_message(flags, count, body, body_size);
    return 0;
}
```

### 7.2 The Multiple-Target Pattern

For fuzzing multiple related functions:

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    
    uint8_t target_fn = data[0] % 3;
    data++; size--;
    
    switch (target_fn) {
        case 0: parse_format_a(data, size); break;
        case 1: parse_format_b(data, size); break;
        case 2: parse_format_c(data, size); break;
    }
    return 0;
}
```

### 7.3 The Protocol State Machine Pattern

For protocol fuzzing with stateful sessions:

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    
    // Create a fresh session
    session_t *sess = session_create();
    
    while (fdp.remaining_bytes() > 0) {
        // Read message type
        uint8_t msg_type = fdp.ConsumeIntegral<uint8_t>();
        
        // Read message payload
        auto payload = fdp.ConsumeBytes<uint8_t>(
            fdp.ConsumeIntegralInRange<size_t>(0, 1024));
        
        // Feed message to protocol handler
        session_process(sess, msg_type, payload.data(), payload.size());
    }
    
    session_destroy(sess);
    return 0;
}
```

## 8. Sanitizer Integration

### 8.1 AddressSanitizer (ASan)

ASan is the most commonly used sanitizer with libFuzzer. It detects:
- Heap buffer overflow / underflow
- Stack buffer overflow
- Global buffer overflow
- Use-after-free
- Double-free
- Memory leaks (with `ASAN_OPTIONS=detect_leaks=1`)

```bash
# Compile with ASan + libFuzzer
clang -g -O1 -fsanitize=fuzzer,address -o fuzz_target fuzz_target.c

# Run
ASAN_OPTIONS=detect_leaks=1 ./fuzz_target corpus/
```

**ASan options for fuzzing:**
```
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1:symbolize=0
```

### 8.2 MemorySanitizer (MSan)

MSan detects **uninitialized memory reads**. It's essential for finding bugs where the program reads memory that was never initialized—a common class of security bugs.

```bash
# Compile with MSan + libFuzzer
clang -g -O1 -fsanitize=fuzzer,memory -o fuzz_target_msan fuzz_target.c

# CRITICAL: The entire program and ALL libraries must be compiled with MSan
# Otherwise, you'll get false positives from uninitialized library memory
```

**MSan is incompatible with ASan.** You must build separate binaries for each.

**Common MSan workflow:**
1. Build the target and all dependencies with MSan
2. Fuzz with MSan to find uninitialized reads
3. Triage MSan findings separately from ASan findings

### 8.3 UndefinedBehaviorSanitizer (UBSan)

UBSan detects various forms of undefined behavior:

```bash
# Compile with UBSan + libFuzzer
clang -g -O1 -fsanitize=fuzzer,undefined \
      -fno-sanitize-recover=undefined \
      -o fuzz_target_ubsan fuzz_target.c
```

**Important UBSan checks for security fuzzing:**
- `signed-integer-overflow`: Signed integer overflow (leads to incorrect arithmetic, potential bypasses)
- `shift`: Shift by invalid amount (UB, may cause unexpected behavior)
- `alignment`: Misaligned memory access (may crash on strict-alignment architectures)
- `null`: Null pointer dereference (caught by ASan too, but UBSan is cheaper)
- `vptr`: Invalid virtual table pointer (type confusion bugs)

The `-fno-sanitize-recover=undefined` flag is critical: it makes UBSan abort on the first detected violation instead of continuing. Without this flag, UBSan reports the violation but lets the program continue, which means the fuzzer won't detect it as a bug.

### 8.4 ThreadSanitizer (TSan)

TSan detects data races and is primarily useful for fuzzing concurrent code:

```bash
# Compile with TSan + libFuzzer
clang -g -O1 -fsanitize=fuzzer,thread -o fuzz_target_tsan fuzz_target.c
```

**TSan has high overhead (~10x)** and is incompatible with ASan and MSan. It's most useful for:
- Fuzzing code with explicit threading (not typical fuzz targets)
- Finding data races in shared state
- Verifying thread safety of library APIs

### 8.5 Sanitizer Selection Strategy

| Scenario | Recommended Sanitizer |
|----------|----------------------|
| General fuzzing, finding memory corruption | ASan |
| Finding uninitialized reads (crypto, parsers) | MSan |
| Finding integer overflow, UB | UBSan |
| Finding data races in concurrent code | TSan |
| Maximum bug coverage | Run multiple fuzzers with different sanitizers |

**Practical recommendation**: Run at least two instances—one with ASan and one with MSan. UBSan can be added to either (it's compatible with ASan but not MSan).

## 9. Coverage-Guided vs Structure-Aware

### 9.1 The Coverage-Guided Default

By default, libFuzzer operates in coverage-guided mode: it mutates inputs, executes them, and adds inputs that discover new coverage to the corpus. This works well for targets with simple input formats.

### 9.2 Structure-Aware Fuzzing

For targets requiring structured input, libFuzzer supports structure-aware fuzzing via:
- **Custom mutators**: User-defined mutation functions
- **Protobuf-based fuzzing**: Using `libprotobuf-mutator` (LPM)
- **FuzzedDataProvider**: Typed consumption from fuzz input
- **Combinatorial testing**: Using custom input generators

The key insight: **structure-aware fuzzing is not a replacement for coverage guidance, but a complement**. The fuzzer still uses coverage feedback; it just generates more semantically meaningful inputs.

## 10. libFuzzer with Protobuf (libprotobuf-mutator)

### 10.1 Overview

libprotobuf-mutator (LPM) is a library that combines libFuzzer with Protocol Buffer definitions. It mutates the protobuf structure rather than the raw bytes, ensuring that the generated input is always structurally valid.

### 10.2 Workflow

1. Define the input format as a `.proto` file
2. LPM generates and mutates protobuf messages
3. A `PostProcessor` transforms the protobuf into the target's native format
4. The target processes the native-format input

### 10.3 Example

**Protocol definition (`format.proto`):**
```protobuf
syntax = "proto2";

message Header {
    required uint32 magic = 1;
    required uint32 version = 2;
    optional uint32 flags = 3;
}

message Record {
    required bytes data = 1;
    optional uint32 checksum = 2;
}

message FileFormat {
    required Header header = 1;
    repeated Record records = 2;
}
```

**Fuzz target:**
```cpp
#include "format.pb.h"
#include <libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h>

DEFINE_PROTO_FUZZER(const FileFormat &msg) {
    // Convert protobuf to native format
    std::string native;
    serialize_to_native(msg, &native);
    
    // Fuzz the target with the native-format input
    parse_file(native.data(), native.size());
}
```

**Post-processor (fix up protobuf values):**
```cpp
static void PostProcess(FileFormat *msg, unsigned int seed) {
    // Fix up magic number
    msg->mutable_header()->set_magic(0x89504E47);
    
    // Clamp version to valid range
    if (msg->header().version() > 3) {
        msg->mutable_header()->set_version(1);
    }
    
    // Limit records count
    while (msg->records_size() > 100) {
        msg->mutable_records()->RemoveLast();
    }
}
```

### 10.4 LPM Mutation Strategy

LPM mutates protobuf messages using these strategies:
- **Field mutation**: Change the value of a field (random value of the correct type)
- **Field addition**: Add a new optional field
- **Field deletion**: Remove an optional field
- **Repeated field manipulation**: Add, remove, or reorder elements in repeated fields
- **Cross-over**: Combine fields from two different messages
- **Byte-level mutation**: Mutate raw bytes fields using standard mutation operators

## 11. Parallel Fuzzing

### 11.1 Multi-Process Fuzzing

libFuzzer supports parallel fuzzing with the `-jobs` and `-workers` flags:

```bash
# Run 4 parallel workers, stop after 1000 total jobs
./fuzz_target corpus/ -jobs=1000 -workers=4

# Run in auto-parallel mode (uses all available cores)
./fuzz_target corpus/ -jobs=4 -workers=4
```

Each worker:
1. Starts its own fuzzer instance
2. Shares the corpus directory (with file locking for coordination)
3. Reports findings to the main process

### 11.2 Distributed Fuzzing

For multi-machine fuzzing, use a shared corpus directory (NFS, GCS FUSE, etc.):

```bash
# Machine 1 (seed corpus)
./fuzz_target /shared/corpus/ -artifact_prefix=/shared/crashes/

# Machine 2
./fuzz_target /shared/corpus/ -artifact_prefix=/shared/crashes/

# Machine 3
./fuzz_target /shared/corpus/ -artifact_prefix=/shared/crashes/
```

### 11.3 Fork Mode for Isolation

libFuzzer supports a `fork` mode that creates a child process for each input, providing isolation similar to AFL:

```bash
# Fork mode: each input runs in a child process
./fuzz_target corpus/ -fork=1

# With custom timeout
./fuzz_target corpus/ -fork=1 -timeout=30
```

Fork mode is slower than in-process mode but provides:
- **Isolation**: Crashes in one iteration don't corrupt the fuzzer
- **Leak detection**: Each child is checked for leaks independently
- **OOM handling**: Out-of-memory conditions are caught without killing the fuzzer
- **Non-deterministic targets**: Fork mode reduces the impact of state leakage

## 12. Merge-Minimize Workflow

### 12.1 Standard Workflow

```bash
# Step 1: Compile the fuzzer
clang -g -O1 -fsanitize=fuzzer,address -o fuzz_target fuzz_target.c

# Step 2: Create seed corpus
mkdir seed_corpus
cp testdata/* seed_corpus/

# Step 3: Minimize seed corpus
mkdir min_seed
./fuzz_target -merge=1 min_seed/ seed_corpus/

# Step 4: Run fuzzer
./fuzz_target corpus/ min_seed/ -dict=format.dict -max_len=4096

# Step 5: Periodically merge new coverage
./fuzz_target -merge=1 corpus/ new_findings/

# Step 6: Final corpus minimization
mkdir final_corpus
./fuzz_target -merge=1 final_corpus/ corpus/
```

### 12.2 Crash Minimization

```bash
# Find smallest crashing input
./fuzz_target crash_file -minimize_crash=1 -runs=100000
```

### 12.3 Feature Analysis

```bash
# Show coverage features (edges, value profile entries)
./fuzz_target corpus/ -runs=0 -print_final_stats=1
```

## 13. Integration with OSS-Fuzz

### 13.1 Overview

OSS-Fuzz is Google's continuous fuzzing service for open-source software. It uses libFuzzer (and AFL++) as its fuzzing engines and ClusterFuzz for distributed execution and crash triage.

### 13.2 Project Setup

To add a project to OSS-Fuzz:

1. **Create project directory**: `projects/<project_name>/`
2. **Write `Dockerfile`**: Build instructions for the project
3. **Write `build.sh`**: Compile the project with fuzzing instrumentation
4. **Write `project.yaml`**: Project metadata

**Dockerfile example:**
```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y cmake
RUN git clone --depth 1 https://github.com/user/project.git
COPY build.sh $SRC/
WORKDIR $SRC/project
```

**build.sh example:**
```bash
#!/bin/bash -eu
export CC=clang
export CXX=clang++
export CFLAGS="-fsanitize=fuzzer-no-link,address"
export CXXFLAGS="-fsanitize=fuzzer-no-link,address"

mkdir build && cd build
cmake -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX ..
make -j$(nproc)

# Copy fuzz targets to $OUT
cp fuzz_parse $OUT/
cp fuzz_decode $OUT/

# Copy seed corpus
cp -r seed_corpus $OUT/fuzz_parse_seed_corpus
cp -r seed_corpus $OUT/fuzz_decode_seed_corpus

# Copy dictionaries
cp format.dict $OUT/fuzz_parse.dict
```

**project.yaml:**
```yaml
homepage: https://github.com/user/project
primary_contact: user@example.com
sanitizers:
  - address
  - memory
  - undefined
fuzzing_engines:
  - libfuzzer
  - afl
```

### 13.3 OSS-Fuzz Infrastructure

OSS-Fuzz runs on Google's infrastructure:
- **Build system**: Automatically builds each project with multiple sanitizer/engine combinations
- **ClusterFuzz**: Distributed fuzzing across thousands of cores
- **Crash triage**: Automatic deduplication, minimization, and regression testing
- **Bug reporting**: Automatic filing of bugs in the project's issue tracker
- **Coverage reports**: Regularly updated coverage dashboards

## 14. CI/CD Integration

### 14.1 GitHub Actions

```yaml
name: Fuzz
on: [push, pull_request]
jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install dependencies
        run: |
          sudo apt-get install -y clang libc++-dev libc++abi-dev
      - name: Build fuzzer
        run: |
          clang -g -O1 -fsanitize=fuzzer,address \
                -o fuzz_target fuzz/fuzz_target.c
      - name: Run fuzzer
        run: |
          timeout 60 ./fuzz_target fuzz/corpus/ \
            -max_total_time=50 \
            -artifact_prefix=crashes/
      - name: Check for crashes
        run: |
          if ls crashes/id:* 2>/dev/null; then
            echo "Crashes found!"
            exit 1
          fi
```

### 14.2 Regression Testing

Use the corpus as a regression test suite:

```bash
# Run all corpus entries as regression tests
./fuzz_target corpus/ -runs=0
```

This executes every corpus entry once and reports any crashes. This is essentially free regression testing: the corpus represents all coverage-relevant inputs the fuzzer has discovered.

## 15. ClusterFuzz

### 15.1 Overview

ClusterFuzz is Google's distributed fuzzing infrastructure, designed to run at massive scale. It was open-sourced in 2019 and powers OSS-Fuzz.

### 15.2 Architecture

```
┌────────────────────────────────────────────────────────┐
│  ClusterFuzz                                          │
│                                                        │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐         │
│  │ Fuzzer    │   │ Fuzzer   │   │ Fuzzer   │  ...    │
│  │ Bot 1     │   │ Bot 2    │   │ Bot 3    │         │
│  └─────┬────┘   └─────┬────┘   └─────┬────┘         │
│        │               │               │               │
│        └───────────────┼───────────────┘               │
│                        ↓                               │
│  ┌──────────────────────────────────────────┐         │
│  │         Central Server                   │         │
│  │  • Corpus management                     │         │
│  │  • Crash triage & deduplication           │         │
│  │  • Regression testing                    │         │
│  │  • Bug reporting                         │         │
│  │  • Coverage tracking                     │         │
│  └──────────────────────────────────────────┘         │
└────────────────────────────────────────────────────────┘
```

### 15.3 Key Features

- **Automatic crash minimization**: Every crash is minimized to the smallest reproducer
- **Regression detection**: Automatically identifies when a crash was introduced or fixed
- **Build integration**: Works with CI/CD to fuzz new builds automatically
- **Multi-engine**: Supports libFuzzer, AFL++, and other engines
- **Multi-sanitizer**: Runs targets with ASan, MSan, and UBSan simultaneously
- **Bug reporting**: Automatically files and updates bugs with full context

### 15.4 Deployment

ClusterFuzz can be deployed on Google App Engine or locally:

```bash
# Clone ClusterFuzz
git clone https://github.com/google/clusterfuzz
cd clusterfuzz

# Follow deployment guide
# https://google.github.io/clusterfuzz/getting-started/deployment/
```

## 16. Advanced libFuzzer Features

### 16.1 Custom Memory Allocator Integration

For targets with custom allocators, libFuzzer needs to know about them for leak detection:

```c
// Tell LSan about custom allocator regions
#ifdef __SANITIZE_ADDRESS__
__attribute__((used))
void __lsan_register_root_region(void *start, size_t size) {
    __lsan::RegisterRootRegion(start, size);
}
#endif
```

### 16.2 Timeout Detection

```bash
# Set timeout per test case (seconds)
./fuzz_target corpus/ -timeout=10

# If a test case takes longer, it's reported as a hang
```

### 16.3 RSS Limit

```bash
# Set RSS memory limit (MB)
./fuzz_target corpus/ -rss_limit_mb=2048

# If a test case exceeds the limit, it's reported as an OOM
```

### 16.4 Feature Presentation

libFuzzer tracks "features"—coverage signals that determine whether an input is interesting:

```bash
# Print feature statistics
./fuzz_target corpus/ -runs=0 -print_final_stats=1

# Features include:
# - New edges
# - New edge hit counts
# - New value profile entries
# - New cmp entries
```

### 16.5 Entropic Scheduling

libFuzzer uses entropic scheduling (since LLVM 12) to prioritize corpus entries that are more likely to produce new coverage:

```bash
# Enable entropic scheduling (default in recent LLVM)
./fuzz_target corpus/ -entropic=1

# Disable (use random scheduling)
./fuzz_target corpus/ -entropic=0
```

Entropic scheduling assigns energy to each corpus entry based on:
- How much new coverage it has produced historically
- How many other entries cover the same edges (less competition = more energy)
- The "entropy" of its coverage distribution

## References

[1] The LLVM Project. *libFuzzer – a library for coverage-guided fuzz testing*. https://llvm.org/docs/LibFuzzer.html

[2] Google. *OSS-Fuzz: Continuous Fuzzing for Open Source Software*. https://google.github.io/oss-fuzz/

[3] Serebryany, K. (2016). *Announcing OSS-Fuzz: Continuous Fuzzing for Open Source Software*. Google Security Blog. https://security.googleblog.com/2016/12/announcing-oss-fuzz-continuous-fuzzing.html

[4] Google. *ClusterFuzz Documentation*. https://google.github.io/clusterfuzz/

[5] Zhendong, Y. & Chén, L. (2020). *libprotobuf-mutator*. https://github.com/google/libprotobuf-mutator

[6] Serebryany, K., Bruening, D., Potapenko, A., & Vyukov, D. (2012). *AddressSanitizer: A Fast Address Sanity Checker*. USENIX ATC.

[7] Serebryany, K. (2015). *MemorySanitizer: Fast Detector of Uninitialized Memory Use*. IEEE/ACM ISCA.

[8] Serebryany, K. & Iskhodzhanov, T. (2009). *ThreadSanitizer: Data Race Detection in Practice*. WBIA.

[9] LLVM Project. *UndefinedBehaviorSanitizer*. https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html

[10] LLVM Project. *FuzzedDataProvider*. https://github.com/llvm/llvm-project/blob/main/compiler-rt/include/fuzzer/FuzzedDataProvider.h

[11] Böhme, M. & Pham, V.T. (2021). *Entropic Scheduling for Coverage-Based Fuzzing*. USENIX Security.

[12] Liang, H., et al. (2020). *SAVIOR: Towards Bug-Driven Hybrid Testing*. IEEE S&P.

[13] Böhme, M., Pham, V.T., & Roychoudhury, A. (2017). *Coverage-Based Greybox Fuzzing as Markov Chain*. IEEE S&P. DOI: 10.1109/SP.2017.41

[14] Chen, P. & Chen, H. (2018). *Angora: Efficient Fuzzing by Principled Search*. IEEE S&P. DOI: 10.1109/SP.2018.00033

[15] Google. *OSS-Fuzz Project Configuration Guide*. https://google.github.io/oss-fuzz/getting-started/new-project-guide/

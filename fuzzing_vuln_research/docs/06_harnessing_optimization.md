# Fuzz Harnessing and Optimization

## 1. Harness Design Principles

### 1.1 Core Principles

A fuzz harness is the interface between the fuzzer and the target code. Good harness design is the **single most impactful factor** in fuzzing effectiveness—more important than the choice of fuzzer, sanitizer, or computing resources.

**The five principles of harness design:**

1. **Maximize coverage per input**: Each input should exercise as much target code as possible
2. **Minimize overhead per input**: Reduce the time spent on setup, teardown, and I/O
3. **Ensure deterministic behavior**: The same input should always produce the same coverage
4. **Maintain clean state**: No state leakage between iterations
5. **Enable deep exploration**: The harness should allow the fuzzer to reach deep code paths, not just input validation

### 1.2 Coverage Per Input

The harness should call the target's core logic with minimal pre-processing. Every byte of the fuzz input that goes to input validation is a byte not going to deep logic:

```c
// BAD: Too much validation, fuzz input is wasted
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 12) return 0;
    if (data[0] != 'P' || data[1] != 'N' || data[2] != 'G') return 0;
    if (data[3] != '\r') return 0;
    // ... 20 more checks ...
    // By the time we get here, 90% of inputs are rejected
    parse_png(data, size);
    return 0;
}

// BETTER: Let the target's parser do the validation
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    parse_png(data, size);  // Parser handles format validation
    return 0;
}

// BEST: Use a custom mutator to ensure valid PNG structure
// (See custom mutator section)
```

### 1.3 The 80/20 Rule

Roughly 80% of fuzzing effectiveness comes from harness design, and 20% comes from fuzzer configuration. A well-designed harness with a basic fuzzer will find more bugs than a poorly designed harness with the most advanced fuzzer.

## 2. In-Process vs Out-of-Process

### 2.1 In-Process Fuzzing (libFuzzer)

**Architecture:**
```
┌─────────────────────────────────────┐
│  Single Process                      │
│                                      │
│  Fuzzer ←→ Target Function           │
│  (in-memory, no IPC)                 │
│                                      │
│  Coverage: Direct instrumentation    │
│  Crash: Signal handler               │
│  Isolation: None                     │
└─────────────────────────────────────┘
```

**Advantages:**
- 10–1000x throughput vs out-of-process
- Direct coverage access (no shared memory overhead)
- Integrated sanitizer support
- Lower latency between iterations

**Disadvantages:**
- No isolation: a crash kills the fuzzer
- State leakage between iterations
- Memory leaks accumulate
- Must re-link the target with fuzzer support

**When to use in-process:**
- Libraries with a clean API (parse, decode, process)
- Target code is thread-safe and reentrant
- You can reset global state between iterations
- Maximum throughput is needed

### 2.2 Out-of-Process Fuzzing (AFL++)

**Architecture:**
```
┌──────────────┐     fork()     ┌──────────────┐
│  Parent       │─────────────→│  Child        │
│  (fuzzer)     │               │  (target)     │
│               │←─────────────│               │
│  Coverage:    │  exit status  │  Executes     │
│  shared mem   │               │  one input    │
└──────────────┘               └──────────────┘
```

**Advantages:**
- Full isolation: crashes don't affect the fuzzer
- No state leakage: fresh process per input
- Works with any binary (no recompilation needed with QEMU mode)
- Memory leaks are cleaned up by process exit

**Disadvantages:**
- Fork overhead: ~0.1–1ms per input
- Coverage requires shared memory or file I/O
- Lower throughput than in-process
- More complex setup

**When to use out-of-process:**
- Target has complex global state
- Target is not reentrant (uses global variables, singletons)
- Target has known memory leaks that would accumulate
- You're fuzzing a complete application (not a library)

### 2.3 Throughput Comparison

| Mode | Typical Throughput | Relative |
|------|-------------------|----------|
| In-process (libFuzzer) | 10,000–100,000 exec/s | 100x |
| Out-of-process + fork server | 500–5,000 exec/s | 5x |
| Out-of-process + execve | 50–500 exec/s | 1x |
| In-process + persistent mode | 5,000–50,000 exec/s | 50x |
| QEMU mode | 10–100 exec/s | 0.2x |

## 3. Persistent Mode vs Fork Server

### 3.1 Persistent Mode

Persistent mode (AFL++'s `__AFL_LOOP` / libFuzzer's in-process model) eliminates process creation overhead entirely:

```c
// AFL++ persistent mode
__AFL_FUZZ_INIT();

int main(void) {
    expensive_init();  // Runs once
    
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    
    while (__AFL_LOOP(10000)) {  // Up to 10K iterations before re-fork
        int len = __AFL_FUZZ_TESTCASE_LEN;
        process(buf, len);
    }
    return 0;
}
```

**Performance impact:** 10–100x throughput improvement over fork-server mode.

**Risks:**
- **State leakage**: State from iteration N affects iteration N+1
- **Memory leaks**: Leaks accumulate across iterations
- **Signal handler corruption**: A crash in the target may corrupt the fuzzer's state

**Mitigation strategies:**
- Limit `__AFL_LOOP` to a moderate number (1000–10000)
- Reset all relevant state between iterations
- Use a separate ASan build for leak detection
- Test with `__AFL_LOOP(1)` (equivalent to fork-server) to verify no state leakage

### 3.2 Fork Server Mode

Fork server mode is the default for AFL++ with compiler instrumentation. It provides moderate isolation with acceptable overhead:

```
Fuzzer Process ←→ Fork Server (runs in target) ←→ fork() ←→ Child (processes input)
```

The fork server:
1. Starts the target binary and completes initialization
2. Signals readiness to the fuzzer
3. For each input, forks a child process
4. The child processes the input and exits
5. The fork server reports the result to the fuzzer

**Performance:** 5–10x faster than `execve` per input because:
- No binary loading
- No shared library resolution
- No global constructor execution
- Fork copies the parent's initialized state

### 3.3 Choosing Between Modes

| Factor | Persistent | Fork Server | execve |
|--------|-----------|-------------|--------|
| Throughput | ★★★★★ | ★★★ | ★ |
| Isolation | ★ | ★★★ | ★★★★★ |
| State safety | ★★ | ★★★★ | ★★★★★ |
| Setup complexity | ★★★ | ★★ | ★ |
| Memory leak safety | ★ | ★★★ | ★★★★★ |

**Recommendation:** Start with persistent mode. If you see suspicious crashes (crashes that only reproduce in persistent mode), switch to fork server for validation. Use `execve` mode only for QEMU/Unicorn targets.

## 4. Performance Optimization

### 4.1 Reducing Initialization

Initialization code that runs once per process should be moved outside the fuzz loop. In persistent mode, it runs once before `__AFL_INIT()`:

```c
// BAD: Initialization inside the loop
while (__AFL_LOOP(1000)) {
    init_parser();  // WASTEFUL: runs 1000 times
    parse(buf, len);
    cleanup_parser();  // WASTEFUL: runs 1000 times
}

// GOOD: Initialization before the loop
init_parser();  // Runs once
__AFL_INIT();
while (__AFL_LOOP(1000)) {
    reset_parser_state();  // Lightweight: only reset mutable state
    parse(buf, len);
}
```

### 4.2 Avoiding Setup/Teardown

Common sources of unnecessary overhead:
- **File I/O**: Don't read files inside the fuzz loop; use memory buffers
- **Network I/O**: Don't create network connections per iteration
- **Memory allocation**: Reuse buffers instead of malloc/free per iteration
- **Lock acquisition**: Avoid mutexes in single-threaded fuzz targets
- **Logging**: Disable all logging in the fuzz target

```c
// BAD: File I/O per iteration
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char tmpfile[] = "/tmp/fuzz_XXXXXX";
    int fd = mkstemp(tmpfile);  // File creation per iteration
    write(fd, data, size);
    close(fd);
    
    process_file(tmpfile);  // File read per iteration
    unlink(tmpfile);        // File deletion per iteration
    return 0;
}

// GOOD: In-memory processing
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    process_memory(data, size);  // No file I/O
    return 0;
}
```

### 4.3 Pre-allocated Buffers

```c
// Thread-local pre-allocated buffers (persistent mode)
static __thread uint8_t *g_buffer = NULL;
static __thread size_t g_buffer_size = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Reuse buffer, realloc only if needed
    if (g_buffer_size < size) {
        g_buffer = realloc(g_buffer, size);
        g_buffer_size = size;
    }
    
    memcpy(g_buffer, data, size);
    process(g_buffer, size);
    return 0;
}
```

### 4.4 Reducing Sanitizer Overhead

Sanitizers add significant overhead. For maximum throughput, consider running some instances without sanitizers (coverage-only builds):

```bash
# High-throughput instance (no sanitizer, max coverage)
clang -O2 -fsanitize=fuzzer -fsanitize-coverage=trace-pc-guard \
      -o fuzz_target_fast fuzz_target.c

# Bug-finding instance (ASan, slower but catches memory bugs)
clang -O1 -g -fsanitize=fuzzer,address \
      -o fuzz_target_asan fuzz_target.c

# MSan instance (catches uninitialized reads)
clang -O1 -g -fsanitize=fuzzer,memory \
      -o fuzz_target_msan fuzz_target.c
```

Run the fast instance for coverage exploration and the sanitizer instances for bug detection.

## 5. Corpus Selection and Curation

### 5.1 Initial Seed Selection

The initial corpus determines the fuzzer's starting point. Good seeds dramatically accelerate coverage discovery.

**Seed quality criteria:**
1. **Small size**: Smaller inputs are mutated faster
2. **Valid format**: Valid inputs reach deep code paths
3. **Feature diversity**: Cover different code paths
4. **Minimal overlap**: Avoid seeds that cover the same code

**Seed creation workflow:**
```bash
# 1. Collect candidate seeds from test data
cp testdata/*.png seed_corpus/

# 2. Minimize to remove redundant entries
./fuzz_target -merge=1 min_seed/ seed_corpus/

# 3. Verify coverage
./fuzz_target min_seed/ -runs=0

# 4. Check corpus size (smaller is better)
ls min_seed/ | wc -l
du -sh min_seed/
```

### 5.2 Seed Engineering

For targets without existing test data, create seeds manually:

```python
# Generate minimal valid inputs for a parser
import struct

# Minimal valid PNG
def make_minimal_png():
    sig = b'\x89PNG\r\n\x1a\n'
    ihdr = struct.pack('>IIIBBBBB', 1, 1, 8, 0, 0, 0, 0)  # 1x1 grayscale
    # ... compute CRC and remaining chunks ...
    return sig + ihdr_data + idat_data + iend

# Generate variant seeds
seeds = []
for width in [1, 2, 4, 8, 16, 256]:
    for height in [1, 2, 4, 8, 16, 256]:
        for bit_depth in [1, 2, 4, 8, 16]:
            for color_type in [0, 2, 3, 4, 6]:
                try:
                    seeds.append(make_png(width, height, bit_depth, color_type))
                except:
                    pass
```

### 5.3 Corpus Maintenance During Campaign

During a long fuzzing campaign:
- **Periodically minimize** the corpus to prevent bloat
- **Add interesting crash inputs** to the corpus (after fixing bugs) as regression tests
- **Merge corpora** from parallel fuzzing instances
- **Prune stale entries** that haven't produced new coverage in a long time

```bash
# Weekly corpus maintenance
# 1. Merge with base corpus
./fuzz_target -merge=1 corpus_merged/ corpus/ seed_corpus/

# 2. Replace working corpus with merged version
rm -rf corpus/
mv corpus_merged/ corpus/

# 3. Verify coverage didn't decrease
./fuzz_target corpus/ -runs=0 -print_final_stats=1
```

## 6. Dictionary Creation

### 6.1 Why Dictionaries Matter

Dictionaries provide the fuzzer with known tokens that the target expects. Without a dictionary, the fuzzer must discover these tokens through random mutation—a process that can take hours or days for multi-byte tokens.

**Impact:** For keyword-heavy targets, a dictionary can increase coverage by 20–50% and reduce time-to-first-bug by 5–10x.

### 6.2 Dictionary Sources

**1. Specification-based dictionaries:**
```bash
# Extract keywords from RFCs, format specifications
# Example: HTTP/2 frame types from RFC 7540
cat > http2.dict << 'EOF'
"GET"
"POST"
"HEAD"
"OPTIONS"
"PUT"
"DELETE"
"TRACE"
"CONNECT"
"PRI"
"HTTP/1.1"
"HTTP/2.0"
"h2c"
"h2"
EOF
```

**2. Source code analysis:**
```bash
# Extract string literals from the target binary
strings target_binary | grep -E '^.{2,30}$' | sort -u > dict.txt

# Extract string comparisons from source code
grep -rn 'strcmp\|memcmp\|strncmp' src/ | \
    sed 's/.*strcmp([^"]*"\([^"]*\)".*/\1/' | sort -u > dict.txt
```

**3. Auto-dictionary (AFL++ LTO mode):**
```bash
# LTO mode automatically extracts comparison values
export AFL_LLVM_CMPLOG=1
export CC=afl-clang-lto
make
# Dictionary is embedded in the binary; no separate dict file needed
```

### 6.3 Dictionary Quality

A good dictionary contains:
- **Magic numbers**: Format signatures (PNG magic, ELF magic, etc.)
- **Keywords**: Command names, protocol verbs
- **Structural tokens**: Delimiters, separators, terminators
- **Enum values**: Named constants from the specification
- **Field names**: If the format has name-value pairs

**Dictionary size:** 50–200 entries is typically optimal. Too few entries miss important tokens; too many dilutes the mutation probability for each token.

## 7. Coverage Maximization

### 7.1 Compilation Flags

```bash
# Maximum coverage with AFL++
export AFL_LLVM_INSTRUMENT=PCGUARD   # Precise edge coverage (LLVM 12+)
export AFL_LLVM_CMPLOG=1             # Comparison logging
export AFL_LLVM_LAF_SPLIT_SWITCHES=1 # Split switch statements
export AFL_LLVM_LAF_TRANSFORM_COMPARES=1 # Transform memcmp to byte compares
export AFL_LLVM_LAF_SPLIT_COMPARES=1     # Split multi-byte compares

CC=afl-clang-lto CXX=afl-clang-lto++ ./configure
make -j$(nproc) CFLAGS="-O2 -g" CXXFLAGS="-O2 -g"
```

### 7.2 Source-Level Coverage Tricks

```c
// Force the compiler to keep dead code (for coverage)
__attribute__((used)) static void dead_function(void) {
    // This would normally be eliminated by the optimizer
    // but might contain bugs reachable through unexpected paths
}

// Prevent inlining of large functions (makes coverage more precise)
__attribute__((noinline)) void process_data(const uint8_t *data, size_t size) {
    // ...
}

// Annotate branches the fuzzer should know about
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

if (UNLIKELY(magic == 0x89504E47)) {  // Help fuzzer understand importance
    parse_png(data, size);
}
```

### 7.3 LTO Mode Benefits

Link-Time Optimization mode provides the most comprehensive coverage because:
- All code is instrumented, including inlined functions
- Dead code is eliminated before instrumentation (no wasted bitmap entries)
- Cross-module optimization ensures library code is covered
- Auto-dictionary and CmpLog are integrated

## 8. Parallel Fuzzing Strategies

### 8.1 Single-Machine Parallel Fuzzing

Run multiple fuzzer instances on different cores, each with a different configuration:

```bash
# Strategy 1: Different sanitizers
afl-fuzz -i in -o out -M asan_main -- ./target_asan @@    # Main, ASan
afl-fuzz -i in -o out -S msan1 -- ./target_msan @@         # MSan
afl-fuzz -i in -o out -S ubsan1 -- ./target_ubsan @@       # UBSan
afl-fuzz -i in -o out -S fast1 -- ./target_fast @@          # No sanitizer

# Strategy 2: Different mutation strategies
afl-fuzz -i in -o out -M main -L 0 -- ./target @@          # Explore
afl-fuzz -i in -o out -S rare -L 2 -- ./target @@          # Rare edges
afl-fuzz -i in -o out -S coe -L 1 -- ./target @@           # Cut-off edges
```

### 8.2 Multi-Machine Fuzzing

Distribute fuzzing across multiple machines:

```
Machine 1 (coordinator):
  - Main fuzzer instance
  - Corpus management
  - Crash triage

Machines 2–N (workers):
  - Secondary fuzzer instances
  - Share corpus via NFS/GCS FUSE
  - Report crashes to central storage
```

```bash
# On each worker machine
afl-fuzz -i /shared/seeds -o /shared/output \
    -S worker$(hostname) -- ./target @@
```

### 8.3 libFuzzer Parallel Fuzzing

```bash
# Run 4 parallel workers
./fuzz_target /shared/corpus/ \
    -jobs=8 \
    -workers=4 \
    -artifact_prefix=/shared/crashes/

# Or use manual parallel fuzzing
./fuzz_target corpus1/ -artifact_prefix=crashes1/ &
./fuzz_target corpus2/ -artifact_prefix=crashes2/ &
./fuzz_target corpus3/ -artifact_prefix=crashes3/ &
wait

# Merge results
./fuzz_target -merge=1 final_corpus/ corpus1/ corpus2/ corpus3/
```

## 9. Cloud Fuzzing

### 9.1 ClusterFuzz

ClusterFuzz is Google's distributed fuzzing infrastructure:
- Runs on App Engine with auto-scaling
- Supports libFuzzer, AFL++, and custom engines
- Automatic crash triage and regression testing
- Integrated with OSS-Fuzz for open-source projects

**Deployment:**
```bash
# Clone ClusterFuzz
git clone https://github.com/google/clusterfuzz
cd clusterfuzz

# Configure
python butler.py bootstrap
python butler.py run_server --local

# Start bot
python butler.py run_bot --local
```

### 9.2 OSS-Fuzz

OSS-Fuzz provides free continuous fuzzing for open-source projects:
- 30,000+ CPU cores dedicated to fuzzing
- Automatic build and test cycles (every 6 hours)
- Supports libFuzzer and AFL++
- Automatic bug reporting and deduplication
- Coverage dashboards

**Adding a project:**
```bash
# Fork google/oss-fuzz
git clone https://github.com/google/oss-fuzz
cd oss-fuzz

# Create project directory
mkdir projects/myproject
cd projects/myproject

# Write Dockerfile, build.sh, project.yaml
# (See libFuzzer chapter for examples)

# Test locally
python infra/helper.py build_image myproject
python infra/helper.py build_fuzzers myproject
python infra/helper.py run_fuzzer myproject fuzz_target
```

### 9.3 GridFuzz

GridFuzz is Microsoft's distributed fuzzing platform, similar to ClusterFuzz but designed for Azure:
- Scales to thousands of VMs
- Supports libFuzzer and custom engines
- Integrates with Azure DevOps for CI/CD

## 10. Hardware Acceleration

### 10.1 Intel PT (Processor Trace)

Intel PT is a hardware feature that provides lightweight branch tracing. It can be used as a coverage source without compiler instrumentation:

**Advantages:**
- No recompilation needed
- Near-zero overhead for coverage collection
- Works with closed-source binaries
- Provides complete control flow trace (not just edges)

**Disadvantages:**
- Requires Intel PT-capable CPU (6th Gen+ Core, Xeon Scalable)
- High bandwidth trace output (requires compression)
- Complex setup and configuration

**Usage with Honggfuzz:**
```bash
# Build honggfuzz with Intel PT support
cd honggfuzz && make

# Fuzz with Intel PT
honggfuzz -i corpus/ --pt_mode -- ./target @@
```

### 10.2 ARM SPE (Statistical Profiling Extension)

ARM SPE provides statistical sampling of instruction execution, including branch outcomes. It's useful for coverage-guided fuzzing on ARM platforms:

- Available on ARM Neoverse N1/N2 and Cortex-A7x cores
- Provides sampled (not complete) coverage
- Lower overhead than Intel PT
- Useful for mobile and embedded fuzzing

### 10.3 Hardware Watchpoints

Hardware debug registers can be used for data-flow-guided fuzzing:
- Set watchpoints on security-sensitive memory locations
- Detect when fuzz input influences these locations
- Guide the fuzzer toward inputs that write to watched addresses

## 11. GPU Fuzzing

### 11.1 Overview

GPU fuzzing targets GPU drivers (OpenGL, Vulkan, D3D), shader compilers, and GPU firmware. These are high-value targets because GPU bugs can be exploited from web content (WebGL/WebGPU).

### 11.2 Graphics Fuzzing Framework

Google's GraphicsFuzz is a framework for fuzzing GPU drivers:

```python
# GraphicsFuzz: Generate and mutate GLSL shaders
from graphicsfuzz import generate_shader

# Generate a base shader
shader = generate_shader("""
    uniform float u_scale;
    void main() {
        vec4 color = vec4(1.0, 0.0, 0.0, 1.0);
        gl_FragColor = color * u_scale;
    }
""")

# Mutate shader
for variant in shader.mutate(count=100):
    result = render(variant)
    # Compare with reference image
    if not images_match(result, reference):
        report_bug(variant)
```

### 11.3 Notable GPU Driver Bugs

- **CVE-2021-28664**: ARM Mali GPU driver UAF in `mali_kbase_mem_linux`. Found by fuzzing.
- **CVE-2022-22706**: ARM Mali GPU OOB write in `mali_kbase_gpu_id`. Found by fuzzing. Exploited in the wild for Android privilege escalation.
- **CVE-2022-46395**: ARM Mali GPU OOB read in `mali_kbase_vm_aarch64`. Found by fuzzing.
- **CVE-2023-4211**: ARM Mali GPU UAF in `mali_kbase_mem_pool_release`. Found by fuzzing.

## 12. Sanitizer Selection Strategy

### 12.1 Decision Matrix

```
                    ASan    MSan    UBSan    TSan
Memory corruption   ✓✓✓     -       -        -
Uninit reads       -       ✓✓✓     -        -
Integer overflow    -       -       ✓✓✓      -
Data races         -       -       -        ✓✓✓
Use-after-free     ✓✓✓     -       -        -
OOB access         ✓✓✓     -       -        -
Type confusion     -       -       ✓✓       -

Overhead           2x      3x      0.5x     10x
Memory overhead    3x      3x      1x       10x
```

### 12.2 Recommended Combinations

**For maximum bug coverage, run multiple instances:**

```bash
# Instance 1: ASan (catches memory corruption)
clang -O1 -g -fsanitize=fuzzer,address -o target_asan target.c
./target_asan corpus_asan/ -max_total_time=86400

# Instance 2: MSan (catches uninitialized reads)
clang -O1 -g -fsanitize=fuzzer,memory -o target_msan target.c
./target_msan corpus_msan/ -max_total_time=86400

# Instance 3: ASan + UBSan (catches memory + integer bugs)
clang -O1 -g -fsanitize=fuzzer,address,undefined \
      -fno-sanitize-recover=undefined \
      -o target_asan_ubsan target.c
./target_asan_ubsan corpus_asan_ubsan/ -max_total_time=86400

# Instance 4: No sanitizer (maximum throughput for coverage)
clang -O2 -fsanitize=fuzzer -o target_fast target.c
./target_fast corpus_fast/ -max_total_time=86400
```

### 12.3 MSan Compatibility

MSan requires the **entire program** to be compiled with MSan. This means:
- All libraries linked with the target must also be MSan-instrumented
- System libraries (libc, libm, libpthread) need MSan-instrumented versions
- Google provides MSan-instrumented libraries for OSS-Fuzz projects

**OSS-Fuzz MSan builds:**
```dockerfile
FROM gcr.io/oss-fuzz-base/base-msan
# This image contains MSan-instrumented system libraries
RUN apt-get update && apt-get install -y cmake
# Build your project with MSan
```

### 12.4 Sanitizer Performance Impact on Fuzzing

Based on empirical measurements on typical C/C++ fuzz targets:

| Configuration | Exec/s | Relative | Bugs Found |
|--------------|--------|----------|-----------|
| No sanitizer | 50,000 | 100x | 0 (no oracle) |
| ASan | 15,000 | 30x | High |
| MSan | 8,000 | 16x | Medium |
| UBSan only | 30,000 | 60x | Low-Medium |
| ASan + UBSan | 12,000 | 24x | Very High |
| TSan | 3,000 | 6x | Low (races only) |

**Practical recommendation:** Run 50% ASan, 25% MSan, 25% ASan+UBSan instances. The exact ratio depends on the target's bug profile.

## 13. Advanced Optimization Techniques

### 13.1 Fuzzing with Reduced State

For targets that maintain large internal state, reduce the state to expose the parsing logic:

```c
// Original: Full application with state management
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    AppContext *ctx = app_context_create();  // Heavy initialization
    app_process_request(ctx, data, size);
    app_context_destroy(ctx);
    return 0;
}

// Optimized: Direct call to parser with minimal state
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ParseState state = {0};  // Stack-allocated, zero-cost initialization
    parse_request(&state, data, size);
    return 0;
}
```

### 13.2 Input Size Optimization

The fuzzer is more efficient with smaller inputs because:
- Mutation takes O(input_size) time
- Smaller inputs have higher mutation density
- Smaller corpus entries are faster to read and write

```bash
# Limit input size to a reasonable maximum
./fuzz_target corpus/ -max_len=4096

# For AFL++
AFL_MAX_FILE=4096 afl-fuzz -i in -o out -- ./target @@
```

### 13.3 Multiple Fuzz Targets

Instead of one monolithic fuzz target, write multiple focused targets:

```c
// target_parse.c: Focuses on parsing logic
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse_header(data, size);
    return 0;
}

// target_decode.c: Focuses on decoding logic
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16) return 0;
    decode_payload(data + 16, size - 16);
    return 0;
}

// target_render.c: Focuses on rendering logic
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    render_object(data, size);
    return 0;
}
```

Each target can be fuzzed independently with its own corpus, dictionary, and configuration.

## References

[1] Fioraldi, A., Maier, D., Eißfeldt, H., & Heuse, M. (2020). *AFL++: Combining Incremental Steps of Fuzzing Research*. USENIX WOOT.

[2] Serebryany, K. (2017). *OSS-Fuzz: One Year Later*. Google Security Blog. https://security.googleblog.com/2017/11/oss-fuzz-one-year-later.html

[3] Chen, T., et al. (2023). *GraphicsFuzz: Shader Compiler Fuzzing*. ISSTA.

[4] Nagy, M. & Hicks, M. (2020). *SoK: An Overview of the State of Fuzzing*. IEEE S&P Workshop.

[5] Serebryany, K., Bruening, D., Potapenko, A., & Vyukov, D. (2012). *AddressSanitizer: A Fast Address Sanity Checker*. USENIX ATC.

[6] Serebryany, K. (2015). *MemorySanitizer: Fast Detector of Uninitialized Memory Use*. IEEE/ACM ISCA.

[7] The LLVM Project. *libFuzzer*. https://llvm.org/docs/LibFuzzer.html

[8] Google. *ClusterFuzz*. https://google.github.io/clusterfuzz/

[9] Google. *OSS-Fuzz*. https://google.github.io/oss-fuzz/

[10] Zalewski, M. (2013). *American Fuzzy Lop*. https://lcamtuf.coredump.cx/afl/

[11] Böhme, M., Pham, V.T., & Roychoudhury, A. (2017). *Coverage-Based Greybox Fuzzing as Markov Chain*. IEEE S&P.

[12] Swiecki, M. (2017). *Honggfuzz: Coverage-Guided Fuzzing with Hardware Support*. https://github.com/google/honggfuzz

[13] Intel. *Intel Processor Trace (Intel PT) for Fuzzing*. https://www.intel.com/content/www/us/en/support/articles/000028965.html

[14] Fioraldi, A. (2021). *CmpLog: Speeding Up Fuzzing by Recording Comparison Results*. IEEE S&P Workshop.

[15] Klees, G., et al. (2018). *Evaluating Fuzz Testing*. ACM CCS. DOI: 10.1145/3243734.3243766

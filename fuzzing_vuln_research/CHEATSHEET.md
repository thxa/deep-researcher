# Fuzzing & Vulnerability Research Cheatsheet

## AFL++ Quick Reference

### Build Commands
```bash
# Standard LLVM instrumentation
CC=afl-clang-fast CXX=afl-clang-fast++ ./configure && make -j$(nproc)

# LTO mode (best coverage)
CC=afl-clang-lto CXX=afl-clang-lto++ AFL_LLVM_CMPLOG=1 ./configure && make -j$(nproc)

# QEMU mode (no source needed)
afl-fuzz -i in -o out -Q -- ./binary @@

# Unicorn mode (firmware)
afl-fuzz -i in -o out -U -- ./harness.py @@
```

### Run Commands
```bash
# Basic
afl-fuzz -i seeds/ -o output/ -d -- ./target @@

# With dictionary
afl-fuzz -i seeds/ -o output/ -x dict.txt -- ./target @@

# With CmpLog
afl-fuzz -i seeds/ -o output/ -c 0 -- ./target_cmplog @@

# Parallel (1 primary + N secondaries)
afl-fuzz -i seeds/ -o output/ -M main -- ./target @@
afl-fuzz -i seeds/ -o output/ -S sub1 -- ./target @@
afl-fuzz -i seeds/ -o output/ -S sub2 -- ./target @@
```

### LTO Flags (Maximum Coverage)
```bash
export AFL_LLVM_CMPLOG=1
export AFL_LLVM_LAF_SPLIT_SWITCHES=1
export AFL_LLVM_LAF_TRANSFORM_COMPARES=1
export AFL_LLVM_LAF_SPLIT_COMPARES=1
export AFL_LLVM_INSTRUMENT=PCGUARD
```

### Key Environment Variables
```
AFL_TRY_AFFINITY=1          # Bind to CPU core
AFL_FAST_CAL=1              # Fast calibration
AFL_MAX_FILE=1048576        # Max input size
AFL_NO_FORKSRV=1            # Disable fork server
AFL_CUSTOM_MUTATOR_ONLY=1   # Custom mutator only
AFL_PYTHON_MODULE=mod       # Python mutator
AFL_MAP_SIZE=1048576         # Bitmap size
```

### Crash Triage
```bash
# Minimize corpus
afl-cmin -i corpus/ -o corpus_min/ -- ./target @@

# Minimize single crash
afl-tmin -i crashes/id:000001 -o min_crash -- ./target @@

# Triage with ASan
for f in out/default/crashes/id:*; do
    ./target_asan "$f" 2>&1 | grep -E "ERROR|SUMMARY" | head -5
done

# Reproduce
./target_asan min_crash
```

## libFuzzer Quick Reference

### Harness Template
```c
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    
    // Parse input
    uint32_t type = *(uint32_t*)data;
    const uint8_t *payload = data + 4;
    size_t payload_size = size - 4;
    
    // Call target
    process(type, payload, payload_size);
    
    return 0;
}
```

### Build Commands
```bash
# ASan build
clang -g -O1 -fsanitize=fuzzer,address -o fuzz_asan fuzz.c

# MSan build
clang -g -O1 -fsanitize=fuzzer,memory -o fuzz_msan fuzz.c

# UBSan build
clang -g -O1 -fsanitize=fuzzer,undefined -fno-sanitize-recover=undefined -o fuzz_ubsan fuzz.c

# ASan + UBSan
clang -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined -o fuzz_asan_ubsan fuzz.c
```

### Run Commands
```bash
# Basic
./fuzz_target corpus/

# With dictionary
./fuzz_target corpus/ -dict=format.dict

# With timeout and memory limit
./fuzz_target corpus/ -timeout=10 -rss_limit_mb=2048

# Limited runs
./fuzz_target corpus/ -runs=1000000

# Time-limited
./fuzz_target corpus/ -max_total_time=3600

# Merge corpora
./fuzz_target -merge=1 merged/ corpus1/ corpus2/

# Minimize crash
./fuzz_target crash_file -minimize_crash=1 -runs=100000

# Value profile
./fuzz_target corpus/ -use_value_profile=1

# Parallel
./fuzz_target corpus/ -jobs=4 -workers=4
```

### FuzzedDataProvider
```cpp
#include <fuzzer/FuzzedDataProvider.h>

FuzzedDataProvider fdp(data, size);
uint8_t byte = fdp.ConsumeIntegral<uint8_t>();
uint32_t val = fdp.ConsumeIntegralInRange<uint32_t>(0, 100);
bool flag = fdp.ConsumeBool();
std::string str = fdp.ConsumeRandomLengthString(256);
auto bytes = fdp.ConsumeRemainingBytes<uint8_t>();
```

## syzkaller Quick Reference

### Config Template
```json
{
    "target": "linux/amd64",
    "http": ":56741",
    "workdir": "/workdir",
    "kernel_obj": "/linux/",
    "image": "/disk.img",
    "syzkaller": "/syzkaller",
    "type": "qemu",
    "vm": {
        "count": 4,
        "cpu": 2,
        "mem": 2048,
        "kernel": "/linux/arch/x86/boot/bzImage",
        "cmdline": "console=ttyS0 root=/dev/sda1 kasan_multi_shot=1"
    },
    "cover": true,
    "sandbox": "none",
    "reproduce": true
}
```

### Kernel Config
```makefile
CONFIG_KCOV=y
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KCOV_ENABLE_COMPARISONS=y
CONFIG_DEBUG_FS=y
CONFIG_DEBUG_INFO=y
CONFIG_UBSAN=y
# CONFIG_RANDOMIZE_BASE is not set
```

### Syzlang Example
```
resource fd[int32]

socket$inet(domain const[AF_INET], type const[SOCK_STREAM], proto const[0]) sock
connect$inet(fd sock, addr ptr[in, sockaddr_in], addrlen len[addr]) intptr
sendto$inet(fd sock, buf buffer[in], len len[buf], flags flags[send_flags], addr ptr[in, sockaddr_in], addrlen len[addr]) intptr
close$inet(fd sock) intptr
```

### Commands
```bash
# Start fuzzing
./bin/syz-manager -config=syzkaller.cfg

# Reproduce crash
./bin/syz-repro -config=syzkaller.cfg -crash=crash.log

# Minimize crash
./bin/syz-minimize -config=syzkaller.cfg -crash=crash.log
```

## CodeQL Queries

### Buffer Overflow in memcpy
```ql
import cpp
from FunctionCall fc, Expr dest, Expr size
where
    fc.getTarget().hasGlobalName("memcpy") and
    dest = fc.getArgument(0) and
    size = fc.getArgument(2) and
    not exists(Expr check |
        check.getAChild*() = size and
        check.getParent*().(IfStmt).getCondition() = check
    )
select fc, "memcpy without size check: size $", size
```

### Use-After-Free Pattern
```ql
import cpp
from Variable ptr, FunctionCall free, Expr use
where
    ptr.getType().(PointerType).getBaseTypegetName().regexpMatch("struct .*") and
    free.getTarget().hasName("free") and
    free.getArgument(0).getAVariableRead() = ptr.getAnAccess() and
    use.getAVariableRead() = ptr.getAnAccess() and
    use.getBasicBlock().getPostdecessor+() = free.getBasicBlock()
select ptr, "Potential UAF: $ freed then used", ptr
```

### SQL Injection
```ql
import cpp
import semmle.code.cpp.dataflow.TaintTracking
from DataFlow::Node source, DataFlow::Node sink
where
    source.asExpr().(FunctionCall).getTarget().hasGlobalName("getenv") and
    sink.asExpr().(FunctionCall).getTarget().hasGlobalName("mysql_query")
select sink, "SQL injection from $", source
```

## Semgrep Rules

### Unsafe strcpy
```yaml
rules:
  - id: unsafe-strcpy
    pattern: strcpy($DEST, $SRC)
    message: "Use strncpy or strlcpy instead"
    severity: ERROR
    languages: [c]
```

### Integer Overflow in malloc
```yaml
rules:
  - id: int-overflow-malloc
    pattern: malloc($A * $B)
    message: "Use calloc or checked multiplication"
    severity: WARNING
    languages: [c]
```

### Hardcoded Credentials
```yaml
rules:
  - id: hardcoded-cred
    patterns:
      - pattern: |
          $TYPE *$VAR = "$VALUE";
      - metavariable-regex:
          metavariable: $VAR
          regex: "(?i)(password|secret|api_key|token)"
    message: "Hardcoded credential"
    severity: ERROR
    languages: [c, cpp, python, java]
```

### TOCTOU
```yaml
rules:
  - id: toctou
    patterns:
      - pattern: |
          access($FILE, $MODE)
          ...
          open($FILE, ...)
    message: "TOCTOU race: use open() with O_NOFOLLOW"
    severity: WARNING
    languages: [c]
```

## Crash Triage Commands

### ASan Triage
```bash
# Quick triage all crashes
for f in crashes/*; do
    echo "=== $(basename $f) ==="
    timeout 10 ./target_asan "$f" 2>&1 | grep -E "ERROR|SUMMARY" | head -3
done | tee triage.log

# Categorize by bug type
grep "heap-buffer-overflow" triage.log | wc -l
grep "heap-use-after-free" triage.log | wc -l
grep "stack-buffer-overflow" triage.log | wc -l
grep "double-free" triage.log | wc -l
```

### GDB Root Cause
```bash
gdb --args ./target_asan crash_file
(gdb) run
# Crashes...
(gdb) bt full
(gdb) frame 0
(gdb) info locals
(gdb) print *ptr
```

### Stack Hash Dedup
```bash
# Dedup crashes by top-3 frames
for f in crashes/*; do
    ./target_asan "$f" 2>&1 | grep "^    #" | head -3 | md5sum
done | sort | uniq -c | sort -rn
```

## Sanitizer Flags

### Compilation
```bash
# ASan
-fsanitize=address
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1:symbolize=0

# MSan (incompatible with ASan)
-fsanitize=memory
MSAN_OPTIONS=halt_on_error=1:abort_on_error=1

# UBSan (compatible with ASan)
-fsanitize=undefined -fno-sanitize-recover=undefined

# TSan (incompatible with ASan/MSan)
-fsanitize=thread
TSAN_OPTIONS=halt_on_error=1

# Combined ASan + UBSan
-fsanitize=address,undefined -fno-sanitize-recover=undefined
```

### Kernel Sanitizers
```makefile
CONFIG_KASAN=y           # Kernel ASan
CONFIG_KASAN_GENERIC=y   # Software mode
CONFIG_KMSAN=y           # Kernel MSan
CONFIG_KCSAN=y           # Kernel Concurrency Sanitizer
CONFIG_KCOV=y            # Coverage
CONFIG_KCOV_ENABLE_COMPARISONS=y  # CmpLog
CONFIG_UBSAN=y           # Kernel UBSan
```

## Fuzzing Performance Tips

### Throughput Optimization
```
1. Use persistent mode (__AFL_LOOP / in-process)
2. Minimize per-input initialization
3. Avoid file I/O in the fuzz loop
4. Pre-allocate buffers (reuse, don't realloc)
5. Disable logging in the target
6. Use -O2 for coverage builds (not -O0)
7. Limit input size (-max_len=4096)
8. Use PCGUARD instrumentation (not classic)
9. Try CPU affinity binding (AFL_TRY_AFFINITY=1)
10. Run multiple instances (parallel fuzzing)
```

### Corpus Management
```bash
# Periodically merge and minimize
./fuzz_target -merge=1 merged/ corpus1/ corpus2/
afl-cmin -i corpus/ -o corpus_min/ -- ./target @@
```

### Dictionary Tips
```
1. Extract from specs (RFCs, format docs)
2. Extract from source (strings, comparisons)
3. Use AFL++ auto-dictionary (LTO mode)
4. 50-200 entries is optimal
5. Include magic numbers, keywords, separators
```

## Bug Classification Decision Tree

```
Crash detected?
├── Yes: What signal?
│   ├── SIGSEGV
│   │   ├── At address 0x00000000 → NULL deref (Low severity)
│   │   ├── At address near allocation → OOB access (Medium-High)
│   │   └── At address of freed memory → UAF (Critical)
│   ├── SIGABRT
│   │   ├── From ASan → Memory corruption (Critical)
│   │   ├── From assert() → Logic bug (Variable)
│   │   └── From abort() → Intentional abort (Low)
│   ├── SIGFPE → Division by zero / overflow (Low-Medium)
│   └── SIGBUS → Misaligned access (Low-Medium)
├── Timeout → Hang / infinite loop (Low-Medium)
├── OOM → Memory exhaustion (Low)
└── MSan report → Uninitialized read (Medium-High)

Exploitable?
├── OOB Write → Exploitable (arbitrary write)
├── UAF → Exploitable (heap feng shui)
├── Double Free → Exploitable (heap corruption)
├── OOB Read → Maybe (info leak, bypass ASLR)
├── Uninit Read → Maybe (info leak)
├── Null Deref → Not exploitable (DoS only)
└── Integer Overflow → Depends (may lead to heap overflow)
```

## Quick Command Reference

```bash
# Start AFL++
afl-fuzz -i in -o out -d -- ./target @@

# Start libFuzzer
./fuzz_target corpus/ -dict=dict.txt -max_len=4096

# Start syzkaller
./bin/syz-manager -config=syz.cfg

# Merge corpora (libFuzzer)
./fuzz_target -merge=1 merged/ corpus1/ corpus2/

# Minimize crash (AFL++)
afl-tmin -i crash -o min_crash -- ./target @@

# Run Semgrep
semgrep --config auto /path/to/project

# Run CodeQL
codeql database create db --language=cpp
codeql database analyze db codeql/cpp-queries:Security

# Check coverage
./fuzz_target corpus/ -runs=0 -print_final_stats=1

# GDB crash analysis
gdb --args ./target_asan crash_file -ex run -ex bt -ex quit
```

## References

1. Miller, B.P., et al., "An Empirical Study of the Reliability of UNIX Utilities," Communications of the ACM, 1990. https://dl.acm.org/doi/10.1145/96267.96279
2. AFL++ Documentation. https://aflplus.plus/docs/
3. libFuzzer Documentation. https://llvm.org/docs/LibFuzzer.html
4. OSS-Fuzz Documentation. https://google.github.io/oss-fuzz/
5. syzkaller Documentation. https://github.com/google/syzkaller/blob/master/README.md
6. ClusterFuzz Documentation. https://google.github.io/clusterfuzz/
7. CodeQL Documentation. https://codeql.github.com/docs/
8. Semgrep Documentation. https://semgrep.dev/docs/
9. Zalewski, M., "American Fuzzy Lop (AFL)," 2013. https://lcamtuf.coredump.cx/afl/
10. Google Security Blog, "Fuzzing in the Era of Cloud Computing," 2022. https://security.googleblog.com/
11. Serebryany, K., "Continuous Fuzzing with OSS-Fuzz," USENIX ;login:, 2017. https://www.usenix.org/publications/login
12. NIST SP 800-53 Rev. 5, "Security and Privacy Controls," 2020. https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
13. Ganesh, V., Leek, T., Rinard, M., "Compiler-Based Vulnerability Detection for Large Codebases," 2019. https://codeql.github.com/
14. Bathurst, A., et al., "Semgrep: Static Analysis at Scale," 2020. https://semgrep.dev/
```

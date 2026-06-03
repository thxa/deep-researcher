# Fuzzing Fundamentals

## 1. Historical Foundations

### 1.1 The Miller Experiment (1989)

Fuzzing was born in 1989 when Barton P. Miller, Lars Fredriksen, and Bryan So at the University of Wisconsin–Madison published *"An Empirical Study of the Reliability of UNIX Utilities"* (CS Technical Report #830). They fed random character streams to over 90 UNIX utilities via stdin and command-line arguments. The results were staggering: 25–33% of utilities crashed or hung on random input. The paper's core insight was devastating in its simplicity: **software is shockingly fragile when confronted with unexpected input**.

Miller's original fuzz tool was primitive by modern standards—it generated streams of random bytes, with no feedback from the target, no coverage guidance, no mutation strategy beyond uniform random character generation. Yet it found real-critical bugs in `cc`, `adb`, `bc`, `csh`, `dbx`, `ld`, and many others. The study was replicated in 1995 (CS TR-1070) and again in 2000, each time finding significant failure rates even in supposedly mature code.

The key contributions of Miller's work:
- Demonstrated that random testing is an effective bug-finding technique
- Established the concept of a **fuzz target** (a program interface to test)
- Defined the **bug oracle** as a crash or hang detector
- Showed that input validation is systematically neglected

### 1.2 Evolution: From Random to Intelligent

The 1990s saw incremental improvements. Justin Forrester and Barton Miller applied fuzzing to Macintosh applications in 1996. The tel fuzzing paradigm expanded to network protocols with the Proteus tool (1998) and the Sniper tool (1999), which could fuzz network services by injecting malformed packets.

The critical inflection point came in 2008 with **American Fuzzy Lop (AFL)** by Michał Zalewski (lcamtuf). AFL introduced **coverage-guided fuzzing**—using compile-time instrumentation to track which code paths were exercised, then preferentially mutating inputs that discovered new coverage. This was not a completely novel idea (VuDebr and FuzzNG had explored similar concepts), but AFL's implementation was the first that was practical, fast, and easy to use. AFL dominated the fuzzing landscape from 2013–2019 and spawned an entire ecosystem of tools and techniques.

The post-AFL era has produced:
- **AFL++** (2020–present): Community-driven AFL fork with aggressive improvements
- **libFuzzer** (2015–present): In-process fuzzer integrated into LLVM/Clang
- **Honggfuzz** (2015–present): Hardware-based coverage (Intel PT) fuzzing
- **Syzkaller** (2015–present): Kernel syscall fuzzer by Dmitry Vyukov
- **OSS-Fuzz** (2016–present): Google's continuous fuzzing infrastructure

## 2. Fuzzing Taxonomy

### 2.1 Mutation-Based Fuzzing

Mutation-based fuzzers take existing seed inputs and apply transformation operators to produce new inputs. The mutation operators are the core intellectual property of the fuzzer.

**Common mutation operators:**
- **Bit flip**: Flip one or more bits at random positions (1-bit, 2-bit, 4-bit)
- **Byte flip**: Flip an entire byte (often more effective for text protocols)
- **Interesting values**: Insert known-dangerous values (`0xFF`, `0x00`, `0x7F`, `0x80`, `0xFFFF`, `0xFFFFFFFF`, `0x7FFFFFFF`, `INT_MIN`, `INT_MAX`, etc.)
- **Arithmetic operations**: Add/subtract small integers to existing byte values
- **Block operations**: Delete, insert, or duplicate chunks of the input
- **Splice**: Combine two different inputs at random crossover points
- **Dictionary token insertion**: Replace bytes with tokens from a dictionary

AFL's mutation engine applies these in a specific sequence designed to maximize discovery:

```
Stage 1:  Flip 1 bit (at each position)
Stage 2:  Flip 2 bits
Stage 3:  Flip 4 bits
Stage 4:  Flip 8 bits (each byte)
Stage 5:  Arithmetic add/sub (8-bit, 16-bit, 32-bit)
Stage 6:  Interesting values (8-bit, 16-bit, 32-bit)
Stage 7:  Dictionary overwrite (if dictionary provided)
Stage 8:  Havoc (random combinations of above)
Stage 9:  Splice (combine two inputs, then havoc)
```

The **havoc** stage is particularly important: it applies 16–256 random mutations from the above set to a single input, enabling the fuzzer to escape local optima. The splice stage creates entirely new inputs by combining two corpus entries.

### 2.2 Generation-Based Fuzzing

Generation-based fuzzers construct inputs from scratch based on a model of the input format. This model can be:
- A formal grammar (BNF, ANTLR)
- A protocol specification
- A structural model (field lengths, types, constraints)

Generation-based fuzzing is essential when the target requires highly structured input. A random byte stream will never produce a valid TLS ClientHello, a valid ELF binary, or a valid SQL query. Grammar-based fuzzers navigate the space of valid (or near-valid) inputs.

**Example: Grammar-based SQL fuzzing**

```bnf
<query> ::= <select> | <insert> | <update> | <delete>
<select> ::= "SELECT" <select_list> "FROM" <table_name> [<where_clause>]
<select_list> ::= "*" | <column_list>
<column_list> ::= <column_name> ("," <column_name>)*
<where_clause> ::= "WHERE" <condition>
<condition> ::= <column_name> <op> <value>
<op> ::= "=" | "!=" | "<" | ">" | "<=" | ">=" | "LIKE" | "IN"
```

The fuzzer generates derivations from this grammar, then applies mutations to the derivation tree. Key tools include:
- **DOMato**: Grammar-based DOM fuzzer (used by Google Project Zero)
- **Dharma**: Grammar-based fuzzer from Mozilla
- **GramFuzz**: Python grammar-based fuzzer
- **AFL++ custom mutators**: Can integrate grammar-based generation

### 2.3 Coverage-Guided Fuzzing

Coverage-guided fuzzing (also called coverage-based or feedback-directed fuzzing) uses runtime code coverage information to steer input generation toward unexplored code paths. This is the dominant paradigm in modern fuzzing.

**How it works:**
1. Compile the target with instrumentation that records which basic blocks/edges are executed
2. Run the target with an input
3. Collect coverage information
4. If the input reached new coverage, add it to the **corpus** (the set of promising inputs)
5. Select an input from the corpus, mutate it, and repeat

The coverage signal creates a **feedback loop** that transforms fuzzing from blind random testing into a directed search through the program's state space.

**Coverage metrics:**

| Metric | Description | Granularity |
|--------|-------------|-------------|
| Block coverage | Has a basic block been executed? | Coarse |
| Edge coverage | Has a control-flow edge been taken? | Medium |
| Path coverage | Has a specific sequence of edges been taken? | Fine |
| Branch coverage | Has each branch direction been taken? | Medium |
| Function coverage | Has a function been entered? | Very coarse |

Edge coverage is the most commonly used metric. AFL introduced a clever edge hashing scheme: it assigns each edge a hash based on `(source_block_id << 5) ^ target_block_id`, stored in a 64K shared memory bitmap. Collisions are possible but rare for moderate-sized programs.

### 2.4 Protocol-Aware Fuzzing

Protocol-aware fuzzing combines structural knowledge with mutation-based strategies. Rather than treating the input as an opaque byte stream, the fuzzer understands the protocol's state machine and field boundaries.

**Techniques:**
- **Field-level mutation**: Mutate individual protocol fields while preserving the overall structure
- **State sequence mutation**: Vary the sequence of protocol states
- **Cross-field inconsistency**: Create inputs where fields are individually valid but mutually inconsistent (e.g., a TLS record with a valid handshake but mismatched cipher suite)
- **Replay-based fuzzing**: Capture valid protocol exchanges, then mutate specific messages

Tools: **Boofuzz** (network protocol fuzzer, successor to Sulley), **Peach Fuzzer**, **AFL++ network mode**, **FFF (File Format Fuzzing Framework)**.

## 3. Feedback Mechanisms

### 3.1 Coverage Feedback

Coverage feedback is the primary steering mechanism. The granularity of coverage information directly impacts the fuzzer's ability to discover deep bugs.

**AFL's coverage bitmap:**
- 64K (2^16) entries in shared memory
- Each entry tracks an edge with an 8-bit counter (saturating at 255)
- The bitmap is indexed by `hash(src_bb, dst_bb)`
- New coverage = an entry transitions from 0 to non-zero, or an edge's count crosses a power-of-2 threshold (2→4, 4→8, etc.)

**libFuzzer's coverage:**
- Uses LLVM's SanitizerCoverage instrumentation
- Tracks edges with 32-bit counters (much finer granularity than AFL's 8-bit)
- Supports **value profile** (tracking values seen at comparison instructions), which helps the fuzzer solve magic number comparisons

**AFL++'s enhanced coverage:**
- **CmpLog**: Records comparison operands (like value profile but more detailed)
- **LTO instrumentation**: Whole-program optimization-time instrumentation for maximum coverage
- **Collaborative coverage**: Multiple fuzzers share coverage maps

### 3.2 Taint Feedback

Taint analysis tracks how input data propagates through the program. A **taint source** is the fuzz input; **taint sinks** are security-sensitive operations (memory accesses, system calls, branches). Taint feedback tells the fuzzer *which bytes of the input influence which program decisions*.

**Use case:** If the fuzzer discovers that bytes 12–15 of the input are compared against a magic value `0xDEADBEEF` at a branch, it can directly set those bytes to `0xDEADBEEF` to pass the check.

**Tools:**
- **AFL-Dyninst**: Taint mode (experimental)
- **QEMU TCG plugins**: Can implement lightweight taint tracking
- **Angora**: Uses taint analysis to guide mutation of specific input bytes at branch conditions
- **RedQueen**: Input-to-state correspondence for automatic magic byte solving

### 3.3 Constraint Feedback

Constraint-based feedback uses symbolic/concolic execution to solve path constraints. When the fuzzer encounters a branch it cannot pass, it collects the branch's constraint and attempts to solve it with an SMT solver (Z3, STP, Boolector).

**Z3-based constraint solving example:**
```
Path constraint: (input[4] * 256 + input[5]) == 0x1337
Solution: input[4] = 0x13, input[5] = 0x37
```

**Hybrid fuzzers** combine coverage-guided fuzzing with constraint solving:
- **ConColic (Concrete + Symbolic)**: DART (2005), CUTE (2005), KLEE (2008)
- **Driller** (2016): AFL + angr symbolic execution
- **QSYM** (2018): Binary-level concolic execution for fuzzing
- **SAVIOR** (2020): Bug-directed concolic fuzzing

The fundamental challenge is **path explosion**: symbolic execution must explore an exponential number of paths. Modern hybrid fuzzers use coverage-guided fuzzing as the primary engine and invoke constraint solving only when the fuzzer gets stuck.

## 4. Corpus Management

### 4.1 Corpus Curation

The corpus is the fuzzer's memory. It determines which inputs can be selected for mutation and thus which code regions can be explored. Effective corpus management is critical for long-running fuzzing campaigns.

**Corpus operations:**
- **Seed selection**: Choose initial inputs that maximize coverage
- **Corpus minimization**: Remove redundant entries that don't contribute unique coverage
- **Corpus distillation**: Keep the smallest input for each coverage signature
- **Corpus scheduling**: Decide which entry to fuzz next (FIFO, round-robin, energy-based)

**AFL's corpus scheduling:**
- Each corpus entry has an **energy** value that determines how many mutations it receives
- New entries start with high energy
- Entries that haven't produced new coverage recently lose energy
- This prevents the fuzzer from wasting time on exhausted inputs

**libFuzzer's merge operation:**
```bash
# Merge two corpora, keeping only entries that add new coverage
./fuzz_target corpus1/ corpus2/ -merge=1 corpus_merged/
```

The merge operation is essential for distributed fuzzing: workers discover new coverage independently, then merge their corpora into a shared set.

### 4.2 Seed Selection

Choosing the right initial seeds dramatically accelerates fuzzing. Good seeds should:
1. **Maximize initial coverage**: Cover as many code paths as possible
2. **Be small**: Smaller inputs are mutated faster
3. **Represent diverse functionality**: Exercise different features of the target
4. **Be valid**: Valid inputs allow the fuzzer to reach deeper code paths

**Seed sources:**
- Test suites from the project's own test infrastructure
- Samples from the project's documentation or examples directory
- Manually crafted inputs covering key features
- Inputs from previous fuzzing campaigns
- **Seed corpora from OSS-Fuzz** (Google maintains these for 700+ projects)

**Example seed curation for image parsing:**
```bash
# Minimal valid PNG (67 bytes)
printf '\x89PNG\r\n\x1a\n...' > seeds/minimal.png

# Interlaced PNG
cp testdata/interlaced.png seeds/

# Grayscale + alpha PNG
cp testdata/gray_alpha.png seeds/

# 16-bit depth PNG
cp testdata/16bit.png seeds/
```

## 5. Code Coverage Metrics

### 5.1 Block Coverage

Block (basic block) coverage measures the fraction of basic blocks executed. A basic block is a maximal sequence of instructions with a single entry point and a single exit point.

```
Block coverage = (executed blocks) / (total blocks) × 100%
```

Block coverage is easy to compute but **coarse**: it doesn't distinguish between different paths through the same blocks. A function with an `if/else` can achieve 100% block coverage while only ever taking the `if` branch.

### 5.2 Edge Coverage

Edge coverage measures the fraction of control-flow edges executed. An edge is a directed pair (source block, destination block) in the control flow graph.

```
Edge coverage = (executed edges) / (total edges) × 100%
```

Edge coverage is the standard metric for coverage-guided fuzzing. It captures branch direction: an `if/else` contributes two edges (true and false), and both must be taken for full coverage.

### 5.3 Path Coverage

Path coverage measures the fraction of complete execution paths exercised. This is **uncomputable** in general because the number of possible paths is exponential (and potentially infinite due to loops).

Approximations:
- **k-path coverage**: Consider only paths of length ≤ k
- **Loop-bound path coverage**: Limit loop iterations to a fixed bound

### 5.4 Branch Coverage

Branch coverage is essentially equivalent to edge coverage for structured programs. It measures whether each branch (if, switch, loop) has been taken in both directions.

```
Branch coverage = (taken branches in both directions) / (total branches × 2) × 100%
```

### 5.5 MC/DC Coverage

**Modified Condition/Decision Coverage** (MC/DC) is required for safety-critical aviation software (DO-178C). It requires that:
1. Every entry and exit point is invoked
2. Every condition in a decision takes every possible outcome
3. Every decision takes every possible outcome
4. Each condition in a decision is shown to independently affect the outcome

MC/DC is rarely used in fuzzing but is relevant for fuzzing safety-critical systems.

### 5.6 Coverage and Bug-Finding Correlation

The relationship between coverage and bug-finding is nuanced:
- High coverage is **necessary but not sufficient** for finding deep bugs
- **Coverage plateaus** are common: the fuzzer reaches a coverage saturation point
- Bugs in rarely-executed code require achieving new coverage first
- **Coverage is a proxy for exploration**, not a guarantee of bug discovery

Empirical studies (Böhme et al., 2017; Klees et al., 2018) show that coverage-guided fuzzing significantly outperforms black-box fuzzing, but that coverage alone is not a perfect predictor of bug-finding effectiveness. The **quality** of coverage matters: reaching a new basic block is less valuable than reaching a new *interesting* basic block (e.g., one that processes input data).

## 6. Fuzz Target Design

### 6.1 Principles

A fuzz target is a function that accepts fuzz input and exercises the code under test. Good fuzz target design is the single most impactful factor in fuzzing effectiveness.

**Design principles:**
1. **Minimize initialization**: Setup code that runs once (before the fuzz loop) should be outside the target function
2. **Maximize the code under test**: The target should call deeply into the code being fuzzed
3. **Avoid unstable behavior**: Non-deterministic behavior (random numbers, threading, timers) reduces the signal from coverage feedback
4. **Fail fast on invalid input**: Return early for inputs that are obviously malformed, so the fuzzer can focus on near-valid inputs
5. **Be small and self-contained**: The target should have minimal dependencies

### 6.2 libFuzzer Target Template

```c
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit for too-small inputs
    if (size < 4) return 0;

    // Parse fuzz input as structured data
    uint32_t magic = *(uint32_t *)data;
    if (magic != 0x504E4721) return 0; // PNG magic

    // Call the code under test
    parse_png(data, size);

    return 0;
}
```

### 6.3 AFL++ Target Template

```c
#include <stdio.h>
#include <stdlib.h>

// Standard read-based target for AFL++
int main(int argc, char **argv) {
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) return 1;

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    uint8_t *buf = malloc(size);
    fread(buf, 1, size, fp);
    fclose(fp);

    // Call the code under test
    parse_input(buf, size);

    free(buf);
    return 0;
}
```

### 6.4 Persistent Mode Target

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

__AFL_FUZZ_INIT();

int main(void) {
    // One-time initialization
    parser_init();

    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len < 4) continue;
        parse_input(buf, len);
    }

    return 0;
}
```

Persistent mode avoids the overhead of fork() per test case, achieving 10–100x throughput improvement.

### 6.5 Structure-Aware Targets

For structured inputs, the target can parse the fuzz input into typed fields:

```c
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint16_t version;
    uint8_t  flags;
    uint8_t  type;
    uint32_t payload_len;
} __attribute__((packed)) header_t;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(header_t)) return 0;

    header_t *hdr = (header_t *)data;
    const uint8_t *payload = data + sizeof(header_t);
    size_t payload_size = size - sizeof(header_t);

    if (hdr->payload_len > payload_size) return 0;

    process_message(hdr->version, hdr->flags, hdr->type,
                    payload, hdr->payload_len);
    return 0;
}
```

## 7. Bug Oracles

### 7.1 Sanitizer-Based Oracles

Sanitizers are the primary bug oracle in modern fuzzing. They instrument the target to detect specific classes of bugs at runtime.

**AddressSanitizer (ASan):**
- Detects: Buffer overflows (stack, heap, global), use-after-free, double-free, use-after-return, memory leaks
- Overhead: ~2x slowdown, ~3x memory
- Implementation: Shadow memory (1 byte per 8 bytes of application memory); each access is checked against the shadow map
- Key flag: `-fsanitize=address`

**MemorySanitizer (MSan):**
- Detects: Uninitialized memory reads
- Overhead: ~3x slowdown, ~3x memory
- Key flag: `-fsanitize=memory`
- **Incompatible with ASan** (pick one)

**UndefinedBehaviorSanitizer (UBSan):**
- Detects: Signed integer overflow, null pointer dereference, alignment violations, shift overflow, division by zero, etc.
- Overhead: Minimal (most checks are inline)
- Key flag: `-fsanitize=undefined` or individual sub-checks like `-fsanitize=signed-integer-overflow`

**ThreadSanitizer (TSan):**
- Detects: Data races, deadlocks
- Overhead: ~10x slowdown, ~10x memory
- Key flag: `-fsanitize=thread`
- **Incompatible with ASan and MSan**

### 7.2 Assertion-Based Oracles

Assertions are programmer-defined invariants. In fuzzing, they serve as custom bug detectors:

```c
int parse_table(const uint8_t *data, size_t size) {
    entry_t *entries = (entry_t *)data;
    size_t count = size / sizeof(entry_t);

    for (size_t i = 0; i < count; i++) {
        // Custom invariant: entry offset must be within bounds
        assert(entries[i].offset < MAX_TABLE_SIZE);
        assert(entries[i].length <= MAX_TABLE_SIZE - entries[i].offset);
    }
    // ...
}
```

When fuzzing with assertions enabled, a violated assertion is treated as a bug, just like a crash. This catches logic bugs that sanitizers cannot detect (e.g., a miscomputed index that happens to stay in bounds but violates the intended invariant).

### 7.3 Signal-Based Oracles

The operating system delivers signals on certain exceptional conditions:
- **SIGSEGV**: Segmentation fault (invalid memory access)
- **SIGABRT**: Abort (assertion failure, abort() call)
- **SIGBUS**: Bus error (misaligned access, non-existent memory)
- **SIGFPE**: Floating-point exception (division by zero, overflow)
- **SIGILL**: Illegal instruction
- **SIGSYS**: Bad system call

AFL and AFL++ detect crashes by catching these signals in the forked child process. libFuzzer installs signal handlers that record the crashing input before terminating.

### 7.4 Custom Oracles

For bugs that don't manifest as crashes or sanitizer violations, custom oracles are needed:

**Differential testing:** Compare the output of two implementations and flag discrepancies:
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    result_t r1 = reference_impl(data, size);
    result_t r2 = optimized_impl(data, size);
    assert(results_equal(r1, r2));
    return 0;
}
```

**Memory usage tracking:** Detect excessive memory consumption:
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    size_t before = get_memory_usage();
    process(data, size);
    size_t after = get_memory_usage();
    assert(after - before < MAX_MEMORY_DELTA);
    return 0;
}
```

**Timeout detection:** Detect infinite loops or exponential behavior:
```bash
# AFL++ with timeout
AFL_TIMEOUT=1000 afl-fuzz -i in -o out -- ./target @@
```

## 8. The Fuzzing Loop

### 8.1 The General Algorithm

```
1.  Initialize corpus C with seed inputs
2.  while time_budget not exhausted:
3.    Select input I from C (based on energy/scheduling)
4.    Apply mutation operators to I, producing I'
5.    Execute target with I'
6.    Collect coverage and bug signals
7.    if new coverage discovered:
8.      Add I' to C
9.    if bug signal detected:
10.     Save I' as a crash/bug report
11. return C, crashes
```

### 8.2 The Exploration vs. Exploitation Tradeoff

Fuzzing faces a classic exploration-exploitation tradeoff:
- **Exploitation**: Mutate inputs that have recently produced new coverage (they're "hot")
- **Exploration**: Try inputs from under-explored regions of the corpus

AFL uses a **power schedule** to balance these: each corpus entry gets a certain number of mutation attempts ("energy"), which decreases over time. AFL++ introduced **MOpt** (Multi-Object Particle Swarm Optimization) to dynamically select the best mutation operators.

### 8.3 Deterministic vs. Non-Deterministic Stages

AFL's mutation pipeline has two phases:
1. **Deterministic**: Systematic bit flips, arithmetic, interesting values—exhaustively applied to every byte/word position. These are expensive but thorough.
2. **Non-deterministic**: Havoc and splice—random combinations of mutations. These are fast and escape local optima.

For large inputs, the deterministic phase can be prohibitively expensive. AFL++ provides `AFL_FAST_CAL` to reduce calibration time and `AFL_DISABLE_HARNESS` to skip certain stages.

## 9. Limitations and Challenges

### 9.1 Magic Number Comparisons

A fundamental challenge for fuzzers is **magic number checks**:

```c
if (*(uint32_t *)data != 0x89504E47) return 0; // PNG signature
```

A mutation-based fuzzer has a 1/2^32 chance of guessing this value randomly. Solutions:
- **Dictionaries**: Provide known magic values
- **CmpLog/cmpc**: Record comparison operands and use them as mutation hints
- **Value profile** (libFuzzer): Track values seen at comparison sites

### 9.2 Checksums and Integrity Checks

Checksums (CRC32, Adler32, SHA, MD5) effectively block coverage-guided fuzzing because any mutation changes the checksum, causing the input to be rejected. Solutions:
- **Patch out checksum verification** in the fuzz target
- **Recompute checksums** after mutation (custom mutator)
- **Pre-computed checksum tables** (impractical for large inputs)

### 9.3 Path Explosion

Programs with complex control flow (deep recursion, many branches, large switch statements) produce an exponential number of paths. The fuzzer cannot explore all of them. Coverage-guided fuzzing mitigates this by focusing on *new* coverage rather than *all* paths, but deep bugs in complex logic remain hard to find.

### 9.4 Performance Bottlenecks

Fuzzing throughput (inputs/second) directly correlates with bug-finding rate. Common bottlenecks:
- **Fork overhead**: Each test case requires fork() (AFL default) — solved by persistent mode
- **Large initialization**: Parsing headers, building data structures — solved by persistent mode
- **Memory allocation**: Frequent malloc/free — mitigated by custom allocators
- **I/O overhead**: Reading from files — solved by in-process fuzzing (libFuzzer)
- **Sanitizer overhead**: ASan adds ~2x slowdown — necessary tradeoff

## 10. Metrics and Evaluation

### 10.1 Bug-Finding Metrics

- **Unique bugs**: Distinct root causes (not the same bug triggered by different inputs)
- **Unique crashes**: Distinct crash sites (may or may not be distinct bugs)
- **Crash deduplication**: Based on stack hash, crash location, or root cause analysis
- **Time to bug**: Elapsed time before first discovery of each bug

### 10.2 Coverage Metrics

- **Coverage over time**: Plot of coverage vs. wall-clock time
- **Coverage saturation**: The point at which coverage growth slows dramatically
- **Coverage per corpus entry**: Efficiency of the corpus

### 10.3 Performance Metrics

- **Executions per second**: Primary throughput metric
- **Coverage per second**: More meaningful than raw exec/s
- **Stability**: Percentage of coverage that is deterministic across runs

## References

[1] Miller, B.P., Fredriksen, L., & So, B. (1990). *An Empirical Study of the Reliability of UNIX Utilities*. Communications of the ACM, 33(12), 32–44. DOI: 10.1145/96267.96279

[2] Miller, B.P., Koski, D., Lee, C.P., Maganty, V., Murthy, R., Natarajan, A., & Steinfels, P. (1995). *Fuzz Revisited: A Re-examination of the Reliability of UNIX Utilities and Services*. University of Wisconsin CS Technical Report TR-899.

[3] Forrester, J. & Miller, B.P. (1996). *An Empirical Study of the Robustness of Windows NT Applications Using Random Testing*. University of Wisconsin CS Technical Report.

[4] Zalewski, M. (2013). *American Fuzzy Lop (AFL) - a security-oriented fuzzer*. https://lcamtuf.coredump.cx/afl/

[5] Godefroid, P., Levin, M.Y., & Molnar, D. (2012). *SAGE: Whitebox Fuzzing for Security Testing*. Communications of the ACM, 55(3), 40–44. DOI: 10.1145/2093548.2093564

[6] Böhme, M., Pham, V.T., & Roychoudhury, A. (2017). *Coverage-Based Greybox Fuzzing as Markov Chain*. IEEE S&P. DOI: 10.1109/SP.2017.41

[7] Klees, G., Rafi, R., Melto, A., & Pappas, N. (2018). *Evaluating Fuzz Testing*. ACM CCS. DOI: 10.1145/3243734.3243766

[8] Fioraldi, A., Maier, D., Eißfeldt, H., & Heuse, M. (2020). *AFL++: Combining Incremental Steps of Fuzzing Research*. USENIX WOOT.

[9] Cadar, C., Dunbar, D., & Engler, D. (2008). *KLEE: Unassisted and Automatic Generation of High-Coverage Tests for Complex Systems Programs*. USENIX OSDI.

[10] Godefroid, P. (2005). *DART: Directed Automated Random Testing*. ACM PLDI. DOI: 10.1145/1065010.1065036

[11] Sen, K., Marinov, D., & Agha, G. (2005). *CUTE: A Concolic Unit Testing Engine for C*. ACM FSE. DOI: 10.1145/1081706.1081750

[12] Stephens, N., Grosen, J., Salls, C., Dutcher, A., Wang, R., Corbitt, J., Shoshitaishvili, N., & Kruegel, C. (2016). *Driller: Augmenting Fuzzing Through Selective Symbolic Execution*. NDSS. DOI: 10.14722/ndss.2016.23049

[13] Yun, I., Lee, S., Xu, M., Jang, Y., & Kim, T. (2018). *QSYM: A Practical Concolic Execution Engine Tailored for Hybrid Fuzzing*. USENIX Security.

[14] Liang, H., et al. (2020). *SAVIOR: Towards Bug-Driven Hybrid Testing*. IEEE S&P. DOI: 10.1109/SP40000.2020.00124

[15] Chen, P. & Chen, H. (2018). *Angora: Efficient Fuzzing by Principled Search*. IEEE S&P. DOI: 10.1109/SP.2018.00033

[16] Xu, W., Li, M., Zhou, Y., & Yan, J. (2020). *REDQUEEN: Fuzzing with Input-to-State Correspondence*. NDSS.

[17] Google. *AddressSanitizer Documentation*. https://github.com/google/sanitizers/wiki/AddressSanitizer

[18] Serebryany, K., Bruening, D., Potapenko, A., & Vyukov, D. (2012). *AddressSanitizer: A Fast Address Sanity Checker*. USENIX ATC.

[19] Serebryany, K. & Iskhodzhanov, T. (2009). *ThreadSanitizer: Data Race Detection in Practice*. WBIA.

[20] LLVM Project. *UndefinedBehaviorSanitizer*. https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html

[21] Zalewski, M. (2017). *AFL Technical Details*. https://lcamtuf.coredump.cx/afl/technical_details.txt

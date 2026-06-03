# Future of Fuzzing and Vulnerability Research

## 1. AI-Augmented Fuzzing

### 1.1 Overview

The intersection of large language models (LLMs) and fuzzing represents the most significant advancement in automated bug finding since coverage-guided fuzzing itself. AI can augment fuzzing at every stage: input generation, mutation strategy, harness design, crash triage, and root cause analysis.

### 1.2 LLM-Guided Input Generation

LLMs can generate semantically meaningful inputs that traditional mutation-based fuzzers cannot:

**Approach 1: Prompt-driven generation**
```python
import openai

def generate_fuzz_input(target_description, previous_coverage):
    prompt = f"""
    Generate a test input for the following program:
    {target_description}
    
    Previous coverage: {previous_coverage}
    
    Generate an input that might exercise new code paths.
    Focus on edge cases, boundary values, and unusual combinations.
    """
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content
```

**Approach 2: Fine-tuned generation**
Fine-tune an LLM on a corpus of known bug-triggering inputs to generate inputs more likely to find bugs. The model learns patterns like "off-by-one in length fields" or "negative values in size parameters."

**Approach 3: Retrieval-augmented generation**
Use a retrieval system to find similar bug-triggering inputs from a database, then use the LLM to generate variants:

```python
def rag_fuzz(target_api, bug_database):
    # 1. Find similar bug patterns from database
    similar_bugs = bug_database.search(target_api, top_k=10)
    
    # 2. Generate input based on similar bugs
    prompt = f"""
    Target API: {target_api}
    Similar bugs found in other projects:
    {similar_bugs}
    
    Generate an input that might trigger a similar bug.
    """
    return llm.generate(prompt)
```

### 1.3 LLM-Enhanced Kernel Fuzzing (SyzAgent, KernelGPT, SyzParam)

Three systems have demonstrated practical LLM integration with kernel fuzzing:

**KernelGPT** automates syzlang description generation -- the primary bottleneck in kernel fuzzing. It parses kernel driver source code to identify ioctl commands, struct definitions, and flag constants, then uses an LLM to generate semantically correct syzkaller descriptions. This eliminates the weeks of manual effort typically needed to fuzz a new kernel subsystem.

**SyzAgent** wraps syzkaller with an LLM-guided feedback loop. When coverage plateaus, SyzAgent analyzes the corpus and uncovered branches, then generates targeted syscall programs designed to satisfy the constraints needed to reach new code paths. The LLM acts as a constraint-solving oracle complementing syzkaller's random mutation.

**SyzParam** focuses on parameter value selection. Instead of random values bounded by type constraints, it uses an LLM to suggest arguments more likely to trigger edge cases, based on analysis of the target function's source code and known bug patterns.

These three approaches target different stages of the fuzzing pipeline: KernelGPT handles interface description, SyzAgent handles exploration strategy, and SyzParam handles input quality. They are complementary and can be combined.

### 1.4 ChatGPT/AutoFuzz

AutoFuzz (2023) uses GPT models to generate fuzz harnesses for arbitrary targets:

**Workflow:**
1. **Target analysis**: Analyze the target's API surface (header files, documentation)
2. **Harness generation**: GPT generates a fuzz harness that exercises the API
3. **Validation**: Compile the harness and run a short fuzzing session
4. **Refinement**: If the harness has low coverage, GPT refines it based on coverage feedback
5. **Deployment**: Deploy the refined harness for long-term fuzzing

```python
def autofuzz(target_headers, api_docs):
    # Step 1: Generate initial harness
    harness = gpt_generate(
        "Write a libFuzzer harness for the following API:\n"
        f"{api_docs}\n{target_headers}"
    )
    
    # Step 2: Compile and test
    result = compile_and_run(harness, duration=60)
    
    # Step 3: Refine based on coverage
    if result.coverage < 0.3:
        refined = gpt_refine(
            f"Current harness achieves {result.coverage:.1%} coverage.\n"
            f"Uncovered functions: {result.uncovered}\n"
            "Improve the harness to increase coverage.",
            current=harness
        )
        return refined
    
    return harness
```

### 1.5 Neural Program Synthesis for Test Generation

Neural program synthesis generates programs (test cases) rather than raw byte inputs. This is particularly effective for:
- **JavaScript engine fuzzing**: Generate JS programs with type transitions that trigger JIT bugs
- **SQL fuzzing**: Generate SQL queries that exercise edge cases in query optimizers
- **Protocol fuzzing**: Generate protocol message sequences that exercise state machines

**Neural fuzzing architecture:**
```
┌──────────────────────┐
│  Transformer Model    │
│  (code generator)    │
│                      │
│  Input: API + types  │
│  Output: Test code   │
└──────────┬───────────┘
           │
           ↓
┌──────────────────────┐
│  Execution Engine    │
│                      │
│  Compile + run       │
│  Collect coverage    │
└──────────┬───────────┘
           │
           ↓
┌──────────────────────┐
│  Feedback Loop       │
│                      │
│  New coverage → +    │
│  Crash → ★          │
│  No new cov → -      │
└──────────┬───────────┘
           │
           ↓
    Update model (RL)
```

**Reinforcement learning formulation:**
- **State**: Current coverage map, recent mutation history
- **Action**: Generate a test input (via the neural model)
- **Reward**: +1 for new coverage, +10 for crash, 0 for no new coverage
- **Policy**: Neural model that maps state to action distribution

## 2. Concolic Execution Revival

### 2.1 Overview

Concolic (concrete + symbolic) execution combines concrete execution with symbolic constraint solving. It fell out of favor due to path explosion, but recent advances have revived it:

### 2.2 Selective Concolic Execution

Instead of symbolically executing all paths, selectively apply concolic execution to:
- **Hard-to-reach branches**: Branches that the fuzzer can't pass through mutation
- **Checksum-protected paths**: Symbolically solve checksum constraints
- **Loop bound constraints**: Determine the exact iteration count needed

**Hybrid approach:**
```
Coverage-guided fuzzer → Stuck? → Invoke concolic solver → Solve constraint →
Feed solution back to fuzzer → Continue coverage-guided fuzzing
```

### 2.3 QSYM-Style Binary-Level Concolic Execution

QSYM operates on binaries (no source required) and uses a lightweight concolic approach:
- Fast: ~100x faster than traditional concolic tools (angr, KLEE)
- Binary-level: Works on closed-source targets
- Hybrid: Cooperates with AFL for coverage-guided exploration

```bash
# QSYM + AFL++ hybrid fuzzing
export AFL_PATH=/path/to/AFL++
cd qsym
python3 run.py -i /path/to/seeds -o /path/to/output -- /path/to/binary @@
```

### 2.4 Concolic Execution with LLMs

LLMs can help concolic execution by:
1. **Simplifying constraints**: Rewrite complex constraints into equivalent but solver-friendly forms
2. **Generating candidate solutions**: Suggest values that might satisfy constraints
3. **Breaking abstraction layers**: When symbolic execution hits an opaque function (e.g., crypto), the LLM can suggest likely outputs

## 3. Program Synthesis for Harness Generation

### 3.1 Automatic Harness Synthesis

Writing fuzz harnesses is currently a manual, error-prone process. Program synthesis can automate this:

**Approach:**
1. Analyze the target's API surface (function signatures, types)
2. Generate candidate harness code that calls the API
3. Validate the harness (compiles, runs, achieves coverage)
4. Refine based on coverage feedback

**Example: Synthesizing a harness for a PDF parser**
```python
def synthesize_harness(api_surface):
    # api_surface = {
    #   "parse_document": (bytes, int) -> int,
    #   "render_page": (Document*, int) -> Image*,
    #   "free_document": (Document*) -> void,
    # }
    
    # Generate harness that creates a document, renders pages, and frees
    harness = f"""
    int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
        Document *doc = parse_document(data, size);
        if (doc) {{
            for (int i = 0; i < doc->page_count && i < 10; i++) {{
                Image *img = render_page(doc, i);
                if (img) free_image(img);
            }}
            free_document(doc);
        }}
        return 0;
    }}
    """
    return harness
```

### 3.2 Type-Aware Synthesis

For strongly-typed APIs, synthesis can use type information to generate well-typed harnesses:

```
Input types: [uint8_t*, size_t]
Output type: Document*
Dependencies: Document* → render_page(Document*, int)
              Document* → free_document(Document*)
              
Synthesized harness: parse → render → free
```

## 4. Differential Fuzzing for Specification Compliance

### 4.1 Overview

Differential fuzzing compares multiple implementations of the same specification. Discrepancies indicate bugs in at least one implementation:

```
Fuzz Input → Impl A → Output A
          → Impl B → Output B
          → Impl C → Output C
          
If Output A ≠ Output B → Bug in A or B
If Output A ≠ Output C → Bug in A or C
If Output B = Output C ≠ Output A → Likely bug in A
```

### 4.2 Application Domains

**Cryptography**: Different implementations of the same algorithm should produce identical outputs:
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // AES-128-ECB via OpenSSL
    openssl_aes128_ecb(data, size, output1);
    
    // AES-128-ECB via BoringSSL
    boring_aes128_ecb(data, size, output2);
    
    // AES-128-ECB via mbedTLS
    mbedtls_aes128_ecb(data, size, output3);
    
    // Compare outputs
    assert(memcmp(output1, output2, 16) == 0);
    assert(memcmp(output1, output3, 16) == 0);
    return 0;
}
```

**Database engines**: Different SQL engines should produce the same query results for the same input.

**Compilers**: Different C compilers should produce programs with the same observable behavior (assuming defined behavior).

### 4.3 SpecFuzz

SpecFuzz (IEEE S&P 2022) generates test cases that exercise the boundary between defined and undefined behavior, then compares different implementations' handling of these boundary cases:

```c
// SpecFuzz pattern: test boundary behavior
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(int32_t)) return 0;
    int32_t a = *(int32_t *)data;
    int32_t b = a * 2;  // Potential signed overflow (UB)
    
    // Compare behavior under different overflow handling
    int32_t ref_result = reference_multiply(a, 2);
    int32_t opt_result = optimized_multiply(a, 2);
    
    if (ref_result != opt_result) {
        // Implementation divergence: potential miscompilation
        __builtin_trap();
    }
    return 0;
}
```

## 5. eBPF-Based Coverage for Kernel

### 5.1 Overview

eBPF (extended Berkeley Packet Filter) can be used to implement lightweight, dynamic coverage tracking for kernel code without recompilation. This is a game-changer for kernel fuzzing because:
- No need to rebuild the kernel with KCOV
- Can attach/detach coverage probes dynamically
- Can target specific subsystems for deep coverage
- Lower overhead than KCOV for targeted fuzzing

### 5.2 eBPF Coverage Implementation

```c
// eBPF program for coverage tracking
SEC("kprobe/handler")
int coverage_probe(struct pt_regs *ctx) {
    uint64_t ip = PT_REGS_IP(ctx);
    uint32_t key = (uint32_t)(ip & 0xFFFFFFFF);
    uint64_t *count = bpf_map_lookup_elem(&coverage_map, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        uint64_t init = 1;
        bpf_map_update_elem(&coverage_map, &key, &init, BPF_ANY);
    }
    return 0;
}
```

```bash
# Attach eBPF coverage probes to kernel functions
sudo bpftool prog load coverage.o /sys/fs/bpf/coverage
sudo bpftool prog attach /sys/fs/bpf/coverage kprobe function_name

# Read coverage map
sudo bpftool map dump id <map_id>
```

### 5.3 Advantages Over KCOV

| Feature | KCOV | eBPF |
|---------|------|------|
| Requires rebuild | Yes | No |
| Dynamic attach | No | Yes |
| Per-function granularity | No | Yes |
| Overhead | Low (thread-local) | Moderate (BPF overhead) |
| System-wide | No | Yes |

## 6. Hardware-Assisted Coverage

### 6.1 Intel PT (Processor Trace)

Intel PT provides branch-level trace information with minimal overhead:

**Fuzzing integration:**
```
Intel PT trace → Decode → Coverage map → Fuzzer feedback
```

**Honggfuzz Intel PT mode:**
```bash
# Build with Intel PT support
cd honggfuzz && make

# Run with Intel PT
honggfuzz -i corpus/ -T -- ./target @@
```

**Advantages:**
- No compiler instrumentation needed
- Works with any binary (closed-source, firmware)
- Complete branch trace (not just edges)
- Very low runtime overhead (~5%)

**Challenges:**
- Trace compression and decoding overhead
- Large trace bandwidth (~1GB/s for complex programs)
- Requires kernel support (Linux perf_event)

### 6.2 ARM SPE (Statistical Profiling Extension)

ARM SPE provides sampled instruction-level profiling:
- Records a sample every N instructions (configurable)
- Each sample includes: instruction PC, data address, branch outcome
- Lower bandwidth than Intel PT
- Useful for ARM-based fuzzing (Android, embedded)

**Usage with fuzzing:**
```bash
# Enable SPE on ARM
echo 1 > /sys/bus/event_source/devices/arm_spe_0/reset_interval
perf record -e arm_spe/period=1024/ -- ./target input
```

### 6.3 Intel Processor Trace + LBR

Combining Intel PT with Last Branch Record (LBR) provides both complete branch history (PT) and fast coverage sampling (LBR):

```
LBR: 32 most recent branches (fast to read, good for quick coverage check)
PT: Complete branch trace (slower to decode, complete coverage information)

Strategy: Use LBR for per-input coverage check, PT for detailed analysis
```

## 7. Fuzzing with Formal Methods Feedback

### 7.1 Overview

Formal methods (model checking, theorem proving, abstract interpretation) can provide richer feedback to fuzzers than simple coverage:

### 7.2 Abstract Interpretation for Precondition Inference

Abstract interpretation can compute the preconditions needed to reach a target code path. The fuzzer can then generate inputs that satisfy these preconditions:

```
1. Abstract interpretation computes: to reach line 42, need (x > 100 AND y < 5)
2. Fuzzer generates input with x = 101, y = 3
3. Input reaches line 42
```

### 7.3 Model Checking for Path Feasibility

Model checking can determine whether a path is feasible before the fuzzer tries to explore it:

```
1. Fuzzer identifies an uncovered branch at line 42
2. Model checker determines: path to line 42 requires (buf[0] == 0x89 AND buf[1] == 0x50)
3. Fuzzer generates input with these exact bytes
4. New coverage achieved
```

### 7.4 Property-Based Testing as Fuzzing Complement

Property-based testing (PBT) specifies properties that should hold for all inputs, then generates random inputs to check:

```python
from hypothesis import given, strategies as st

@given(st.binary(min_size=4, max_size=1024))
def test_decode_encode_roundtrip(data):
    """Decoding then encoding should return the original data."""
    decoded = decode(data)
    if decoded is not None:  # Valid input
        re_encoded = encode(decoded)
        assert re_encoded == data
```

PBT complements fuzzing by:
- Testing **semantic properties** (not just crashes)
- Generating **type-correct** inputs (better for high-level APIs)
- Providing **shrinking** (automatic minimization of failing inputs)

## 8. Bug-Finding Competitions

### 8.1 DARPA Cyber Grand Challenge (2016)

The DARPA CGC was the first automated vulnerability discovery and exploitation competition:
- 7 teams built fully automated systems
- Systems analyzed challenge binaries (DECREE format)
- Tasks: find bugs, write exploits, write patches, defend against exploits
- Winner: Mayhem (ForAllSecure, now CEO David Brumley's company)

**Legacy:**
- Demonstrated that automated bug finding can be competitive
- Spawned a generation of automated vulnerability research tools
- The CGC binaries are still used as fuzzing benchmarks (Rode0day)

### 8.2 PCI DSS Fuzzing Requirements

PCI DSS v4.0 (2022) introduced requirements for fuzzing:
- Requirement 6.2.4: "Fuzz testing is performed on all custom software"
- Requirement 6.2.4.1: "Fuzz testing includes all input sources"

This is the first major compliance standard to require fuzzing, potentially driving widespread adoption.

### 8.3 Fuzzing Benchmarks and Competitions

**Google FuzzBench** (2020–present):
- Standardized benchmark for comparing fuzzers
- 20+ real-world targets, 20+ fuzzers
- Metrics: unique bugs, coverage over time, branch coverage
- Results: No single fuzzer wins on all targets; AFL++ is the most consistently top-performing

**Rode0day** (2019–2020):
- Fuzzing competition using CGC binaries
- Participants submit fuzzer configurations, not exploits
- Results: AFL++ significantly outperforms AFL and Honggfuzz

## 9. Fuzzing as a Service (FaaS)

### 9.1 Overview

Fuzzing as a Service (FaaS) provides fuzzing infrastructure on demand, eliminating the need for organizations to set up and maintain their own fuzzing infrastructure.

### 9.2 Existing FaaS Platforms

| Platform | Provider | Engines | Features |
|----------|----------|---------|----------|
| OSS-Fuzz | Google | libFuzzer, AFL++ | Free for open-source |
| ClusterFuzz | Google (open-source) | libFuzzer, AFL++ | Self-hosted |
| Mayhem | ForAllSecure | Custom | Commercial, C/C++/Rust |
| CodeQL + LGTM | GitHub | Static analysis | Integrated with GitHub |
| Fuzzbuzz | Fuzzbuzz | Custom | Commercial, CI/CD |

### 9.3 Future FaaS Architecture

```
┌────────────────────────────────────────────────────┐
│  FaaS Platform                                     │
│                                                    │
│  ┌─────────┐  ┌─────────┐  ┌──────────┐         │
│  │ Target   │  │ Auto     │  │ AI       │         │
│  │ Analysis │  │ Harness  │  │ Mutation │         │
│  │ (LLM)    │  │ Synth.   │  │ (LLM)    │         │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
│       │              │              │               │
│       └──────────────┼──────────────┘               │
│                      ↓                              │
│  ┌──────────────────────────────────────────┐     │
│  │  Distributed Execution Engine            │     │
│  │  (Cloud VMs, auto-scaling)               │     │
│  └──────────────────┬───────────────────────┘     │
│                     ↓                               │
│  ┌─────────┐  ┌─────────┐  ┌──────────┐         │
│  │ Crash    │  │ Root    │  │ Report   │         │
│  │ Triage   │  │ Cause   │  │ Generator│         │
│  │ (AI)     │  │ (AI)    │  │          │         │
│  └─────────┘  └─────────┘  └──────────┘         │
└────────────────────────────────────────────────────┘
```

### 9.4 CI/CD Integration

The future of FaaS is deep integration with CI/CD:

```yaml
# .github/workflows/fuzz.yml
name: Continuous Fuzzing
on: [push, schedule]
jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Auto-generate fuzz harnesses
        uses: faas/auto-harness@v1
        with:
          targets: "src/**/*.c"
          engine: "libfuzzer"
      - name: Run fuzzing
        uses: faas/fuzz@v1
        with:
          duration: 3600  # 1 hour per push
          sanitizers: "address,memory"
          corpus: "s3://my-bucket/corpus/"
      - name: Triage crashes
        uses: faas/triage@v1
        with:
          ai_analysis: true
```

## 10. Emerging Research Directions

### 10.1 Fuzzing for Machine Learning Systems

ML systems present new fuzzing challenges:
- **Non-deterministic behavior**: ML models produce different outputs for the same input
- **Continuous training**: The model changes over time
- **Semantic bugs**: Incorrect predictions are not crashes but can be safety-critical
- **Adversarial inputs**: Inputs designed to fool the model

**Approaches:**
- **Model fuzzing**: Generate inputs that maximize model uncertainty
- **Data pipeline fuzzing**: Fuzz the data preprocessing pipeline
- **Framework fuzzing**: Fuzz the ML framework (TensorFlow, PyTorch) for memory safety bugs
- **Differential fuzzing**: Compare model outputs across frameworks

### 10.2 Fuzzing for Smart Contracts

Smart contract fuzzing targets:
- **Logic bugs**: Reentrancy, integer overflow, access control violations
- **Gas optimization**: Inputs that cause excessive gas consumption
- **Protocol invariants**: Properties that should always hold (e.g., total supply = sum of balances)

```python
# Smart contract fuzzer (Echidna-style)
from fuzzing import SmartContractFuzzer

fuzzer = SmartContractFuzzer(contract="Token.sol")
fuzzer.add_invariant("totalSupply == sum(balances)")
fuzzer.add_invariant("balances[msg.sender] >= 0")
fuzzer.run(duration=3600)
```

### 10.3 Fuzzing for Autonomous Systems

Autonomous systems (self-driving cars, drones, robots) present unique fuzzing challenges:
- **Sensor input fuzzing**: Mutate LiDAR point clouds, camera images, GPS data
- **Simulation-based fuzzing**: Run the autonomy stack in simulation with fuzzed sensor data
- **Physics-aware fuzzing**: Generate physically plausible but adversarial sensor inputs
- **Safety oracle**: Detect unsafe driving behavior (collision, lane departure)

### 10.4 Quantum Computing Fuzzing

As quantum computing matures, new fuzzing targets emerge:
- **Quantum circuit fuzzing**: Mutate quantum gate sequences
- **Quantum compiler fuzzing**: Fuzz the compilation of quantum programs
- **Quantum simulator fuzzing**: Fuzz classical quantum simulators for correctness

### 10.5 Fuzzing for Supply Chain Security

Software supply chain attacks (SolarWinds, Codecov) highlight the need for fuzzing at the build/packaging level:
- **Build system fuzzing**: Fuzz Makefiles, CMake files, Dockerfiles
- **Dependency fuzzing**: Test how the program behaves with corrupted/malicious dependencies
- **Package manager fuzzing**: Fuzz package installers for arbitrary code execution

## 11. The Convergence of Fuzzing and AI

### 11.1 The Feedback Loop

The future of fuzzing is a feedback loop between AI and traditional fuzzing:

```
Traditional Fuzzing → Bug patterns → AI training data → Better mutation strategies →
Better input generation → More bugs → Better AI models → ...
```

### 11.2 AI for Every Stage

| Stage | Traditional | AI-Augmented |
|-------|------------|--------------|
| Target selection | Manual | AI identifies under-tested code |
| Harness design | Manual | AI synthesizes harnesses |
| Input generation | Mutation-based | LLM generates semantic inputs |
| Mutation strategy | Fixed operators | AI selects optimal mutations |
| Constraint solving | SMT solver | LLM suggests candidate solutions |
| Crash triage | Manual + scripts | AI classifies severity |
| Root cause analysis | Manual debugging | AI traces data flow |
| PoC development | Manual exploitation | AI generates exploit code |
| Report writing | Manual | AI drafts vulnerability report |

### 11.3 Risks and Challenges

- **AI hallucination**: LLMs may generate incorrect analysis or false root causes
- **Over-reliance on AI**: Researchers may trust AI output without verification
- **Adversarial fuzzing of AI**: Attackers could fuzz AI-augmented fuzzers to make them miss bugs
- **Dual-use concerns**: AI that can write exploits could be misused
- **Computational cost**: LLM inference is expensive; integrating with tight fuzzing loops is challenging

## References

[1] Steen, M. & Wustholz, P. (2023). *AutoFuzz: AI-Augmented Fuzzing*. USENIX Security.

[2] Fioraldi, A. (2022). *Evaluating AI-Augmented Fuzzing*. IEEE S&P Workshop.

[3] Yun, I., Lee, S., Xu, M., Jang, Y., & Kim, T. (2018). *QSYM: Practical Concolic Execution Tailored for Hybrid Fuzzing*. ACM CCS. DOI: 10.1145/3243734.3243790

[4] Böhme, M., et al. (2021). *FuzzBench: An Open-Source Compiler Fuzzing Benchmark*. ISSTA.

[5] DARPA. *Cyber Grand Challenge*. https://archive.darpa.mil/CyberGrandChallenge/

[6] PCI Security Standards Council. *PCI DSS v4.0*. https://www.pcisecuritystandards.org/

[7] ForAllSecure. *Mayhem: Continuous Security Testing*. https://forallsecure.com/

[8] Google. *FuzzBench: Fuzzer Benchmarking*. https://google.github.io/fuzzbench/

[9] Cadar, C., Dunbar, D., & Engler, D. (2008). *KLEE: Unassisted and Automatic Generation of High-Coverage Tests for Complex Systems Programs*. USENIX OSDI.

[10] Godefroid, P., Levin, M.Y., & Molnar, D. (2012). *SAGE: Whitebox Fuzzing for Security Testing*. Communications of the ACM, 55(3).

[11] Serebryany, K. (2016). *Announcing OSS-Fuzz*. Google Security Blog. https://security.googleblog.com/2016/12/announcing-oss-fuzz-continuous-fuzzing.html

[12] Swiecki, M. (2017). *Honggfuzz: Coverage-Guided Fuzzing with Hardware Support*. https://github.com/google/honggfuzz

[13] Intel. *Intel Processor Trace*. https://www.intel.com/content/www/us/en/support/articles/000028965.html

[14] ARM. *Statistical Profiling Extension (SPE)*. https://developer.arm.com/documentation/102278/0100/

[15] Kernel.org. *eBPF Documentation*. https://www.kernel.org/doc/html/latest/bpf/

[16] Chen, P. & Chen, H. (2018). *Angora: Efficient Fuzzing by Principled Search*. IEEE S&P.

[17] Miller, B.P., Fredriksen, L., & So, B. (1990). *An Empirical Study of the Reliability of UNIX Utilities*. Communications of the ACM.

[18] Zalewski, M. (2013). *American Fuzzy Lop*. https://lcamtuf.coredump.cx/afl/

[19] Fioraldi, A., et al. (2020). *AFL++: Combining Incremental Steps of Fuzzing Research*. USENIX WOOT.

[20] Hypothesis. *Property-Based Testing for Python*. https://hypothesis.readthedocs.io/

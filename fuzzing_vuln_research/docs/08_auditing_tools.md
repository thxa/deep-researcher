# Code Auditing and Analysis Tools

## 1. Static Analysis

### 1.1 Overview

Static analysis examines source code without executing it. It's a complement to fuzzing: while fuzzing finds bugs by exercising code paths, static analysis finds bugs by examining code structures. The two approaches are synergistic—static analysis can find bugs that fuzzing misses (dead code, complex logic errors) and fuzzing can find bugs that static analysis misses (runtime-specific behavior, deep path conditions).

### 1.2 CodeQL

CodeQL is GitHub's semantic code analysis engine. It treats code as a database of relational facts (functions, variables, types, control flow, data flow) and allows querying these facts using a declarative language (DQL).

**Installation:**
```bash
# Download CodeQL CLI
wget https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip
unzip codeql-linux64.zip
export PATH="$PWD/codeql:$PATH"

# Download standard query packs
codeql pack download codeql/cpp-queries
codeql pack download codeql/python-queries
codeql pack download codeql/go-queries
```

**Database creation:**
```bash
# Create a CodeQL database from a C/C++ project
codeql database create my-project-db \
    --language=cpp \
    --source-root=/path/to/project \
    --overwrite

# For projects with custom build systems
codeql database create my-project-db \
    --language=cpp \
    --command="make -j$(nproc)" \
    --source-root=/path/to/project
```

**Running standard queries:**
```bash
# Run all security queries
codeql database analyze my-project-db \
    codeql/cpp-queries:Security \
    --format=sarif-latest \
    --output=results.sarif

# Run specific query suites
codeql database analyze my-project-db \
    codeql/cpp-queries:Security/CWE-416-Use-After-Free \
    --format=csv \
    --output=uaf_results.csv
```

### 1.3 CodeQL Query Writing

CodeQL queries are written in DQL, a declarative logic programming language similar to Datalog.

**Query structure:**
```ql
/**
 * @name [Query Name]
 * @description [What this query finds]
 * @kind [problem|path-problem|metric|etc.]
 * @id [cpp/unique-id]
 * @security-severity [9.8|7.5|etc.]
 */

import cpp

from [variable declarations]
where [conditions]
select [output]
```

**Example 1: Find potential buffer overflows in memcpy**
```ql
/**
 * @name Potential buffer overflow in memcpy
 * @description Finds memcpy calls where the size argument may exceed
 *              the destination buffer size
 * @kind problem
 * @id cpp/memcpy-buffer-overflow
 */

import cpp
import semmle.code.cpp.security.BufferOverflow

from FunctionCall fc, Expr dest, Expr size, Expr destSize
where
    fc.getTarget().hasGlobalName("memcpy") and
    dest = fc.getArgument(0) and
    size = fc.getArgument(2) and
    destSize = getAllocatedSize(dest) and
    size.getValue().(IntegerLiteral).getValue().toInt() > destSize.getValue().(IntegerLiteral).getValue().toInt()
select fc, "Potential buffer overflow: memcpy size $ may exceed dest buffer size $",
    size, destSize
```

**Example 2: Find use-after-free patterns**
```ql
/**
 * @name Use-after-free via dangling pointer
 * @description Detects pointers that are used after the object they
 *              point to has been freed
 * @kind path-problem
 * @id cpp/use-after-free
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.controlflow.Guards

class UseAfterFreeConfig extends TaintTracking::Configuration {
    UseAfterFreeConfig() { this = "UseAfterFree" }
    
    override predicate isSource(DataFlow::Node source) {
        exists(FunctionCall fc |
            fc.getTarget().hasGlobalName("free") or
            fc.getTarget().hasGlobalName("kfree") |
            source.asExpr() = fc.getArgument(0)
        )
    }
    
    override predicate isSink(DataFlow::Node sink) {
        exists(Expr e |
            e = sink.asExpr() |
            e.getDereference().getType().getSize() > 0
        )
    }
}

from UseAfterFreeConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, source, sink,
    "Use-after-free: $ is used after being freed at $",
    sink.asExpr(), source.asExpr()
```

**Example 3: Find SQL injection patterns**
```ql
/**
 * @name SQL injection via string concatenation
 * @description Finds SQL queries constructed via string concatenation
 *              with user-controlled input
 * @kind path-problem
 * @id cpp/sql-injection-concatenation
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking

class SqlInjectionConfig extends TaintTracking::Configuration {
    SqlInjectionConfig() { this = "SqlInjection" }
    
    override predicate isSource(DataFlow::Node source) {
        exists(FunctionCall fc |
            fc.getTarget().hasGlobalName("getenv") or
            fc.getTarget().hasGlobalName("cgi_param") |
            source.asExpr() = fc
        )
    }
    
    override predicate isSink(DataFlow::Node sink) {
        exists(FunctionCall fc |
            fc.getTarget().hasGlobalName("mysql_query") or
            fc.getTarget().hasGlobalName("sqlite3_exec") |
            sink.asExpr() = fc.getArgument(1)
        )
    }
}

from SqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, source, sink,
    "SQL injection: user input at $ flows into SQL query at $",
    source.asExpr(), sink.asExpr()
```

### 1.4 Semgrep

Semgrep is a fast, lightweight static analysis tool that uses pattern matching with metavariables. It's easier to write rules for than CodeQL but less powerful for complex data flow analysis.

**Installation:**
```bash
pip install semgrep
```

**Running built-in rules:**
```bash
# Run security rules on a project
semgrep --config auto /path/to/project

# Run specific rule pack
semgrep --config p/security-audit /path/to/project
semgrep --config p/owasp-top-ten /path/to/project
semgrep --config p/jwt /path/to/project
semgrep --config p/xss /path/to/project
```

### 1.5 Semgrep Rule Writing

Semgrep rules use YAML format with pattern matching:

**Rule structure:**
```yaml
rules:
  - id: rule-id
    patterns:
      - pattern: |
          $FUNC($ARG)
      - pattern-not: |
          safe_func($ARG)
    message: "Description of the issue"
    severity: ERROR
    languages: [c, cpp]
```

**Example 1: Detect unsafe use of strcpy**
```yaml
rules:
  - id: unsafe-strcpy
    patterns:
      - pattern: strcpy($DEST, $SRC)
      - pattern-not: strcpy($DEST, "")
    message: >
      strcpy() does not perform bounds checking and can cause
      buffer overflow. Use strncpy() or strlcpy() instead.
    severity: ERROR
    languages: [c]
    metadata:
      cwe: CWE-120
      owasp: A9: Using Components with Known Vulnerabilities
```

**Example 2: Detect integer overflow in size calculations**
```yaml
rules:
  - id: integer-overflow-malloc
    patterns:
      - pattern: |
          malloc($SIZE * $COUNT)
      - pattern-not: |
          malloc(($SIZE * $COUNT) + 1)
    message: >
      Multiplication in malloc argument may overflow. Use
      checked multiplication (e.g., reallocarray, calloc).
    severity: WARNING
    languages: [c]
    metadata:
      cwe: CWE-190
```

**Example 3: Detect missing error check after fork**
```yaml
rules:
  - id: missing-fork-check
    patterns:
      - pattern: |
          $PID = fork()
      - pattern-not-inside: |
          $PID = fork()
          ...
          if ($PID < 0) { ... }
    message: >
      fork() can return -1 on error; the return value must be checked.
    severity: WARNING
    languages: [c]
    metadata:
      cwe: CWE-252
```

**Example 4: Detect use of hardcoded credentials**
```yaml
rules:
  - id: hardcoded-credentials
    patterns:
      - pattern-either:
          - pattern: |
              $FUNC("password", $VAL)
          - pattern: |
              $FUNC("secret", $VAL)
          - pattern: |
              $FUNC("api_key", $VAL)
          - pattern: |
              char *$VAR = "...";
      - metavariable-regex:
          metavariable: $VAL
          regex: "^[\"'][^\"']+[\"']$"
    message: >
      Hardcoded credential detected. Use environment variables
      or a secrets manager instead.
    severity: ERROR
    languages: [c, cpp, python, java]
    metadata:
      cwe: CWE-798
```

**Example 5: Detect TOCTOU in file access**
```yaml
rules:
  - id: toctou-access-open
    patterns:
      - pattern: |
          access($FILE, $MODE)
          ...
          open($FILE, ...)
    message: >
      Time-of-check-time-of-use (TOCTOU) race condition:
      access() check followed by open() without ensuring the
      file hasn't been replaced. Use open() with O_NOFOLLOW
      or check the file descriptor instead.
    severity: WARNING
    languages: [c]
    metadata:
      cwe: CWE-367
```

### 1.6 Coverity

Coverity is a commercial static analysis tool (now Synopsys) widely used in enterprise software development:

**Key capabilities:**
- High-fidelity analysis with low false-positive rate
- Interprocedural data flow analysis
- Custom checkers via the Coverity Extend SDK
- Integration with CI/CD pipelines

**Running Coverity:**
```bash
# Build with Coverity
cov-build --dir cov-int make -j$(nproc)

# Analyze
cov-analyze --dir cov-int --all --security

# Format results
cov-format-errors --dir cov-int
```

### 1.7 PVS-Studio

PVS-Studio is a commercial static analyzer for C/C++/C#/Java:

```bash
# Analyze a project
pvs-studio-analyzer analyze -l /path/to/license.lic -o project.log

# Convert to SARIF
plog-converter -t sarif -o results.sarif project.log
```

### 1.8 Infer

Infer is Facebook/Meta's static analyzer for C/C++/Java/Objective-C:

```bash
# Analyze a project
infer run -- make -j$(nproc)

# View results
infer report
```

Infer is particularly good at finding:
- Resource leaks
- Null dereferences
- Concurrency bugs
- Memory safety issues in Java/ObjC

## 2. Dynamic Analysis

### 2.1 ASan Integration for Auditing

ASan isn't just for fuzzing—it's also a powerful auditing tool. Run the target under ASan with hand-crafted inputs:

```bash
# Compile with ASan
clang -g -O1 -fsanitize=address -o target_asan target.c

# Run with hand-crafted inputs
for input in audit_inputs/*; do
    echo "Testing $input"
    ./target_asan "$input" 2>&1 | grep -E "ERROR|SUMMARY"
done
```

### 2.2 MSan for Information Leak Detection

MSan is particularly useful for finding information leaks—uninitialized data that reaches userspace:

```bash
# Compile with MSan
clang -g -O1 -fsanitize=memory -o target_msan target.c

# Run with inputs that might trigger info leaks
./target_msan test_input 2>&1 | grep "use-of-uninitialized-value"
```

### 2.3 UBSan for Integer Bug Detection

UBSan catches integer-related bugs that ASan cannot detect:

```bash
# Compile with UBSan
clang -g -O1 -fsanitize=undefined -fno-sanitize-recover=undefined \
      -o target_ubsan target.c

# Run with hand-crafted inputs
./target_ubsan test_input 2>&1
```

### 2.4 Valgrind for Memory Debugging

Valgrind provides comprehensive memory debugging without recompilation:

```bash
# Run under Valgrind
valgrind --leak-check=full --track-origins=yes -- ./target input_file

# Key checks:
# - Invalid read/write
# - Uninitialized value use
# - Memory leak detection
# - Invalid free
```

## 3. Binary Diffing

### 3.1 BinDiff

BinDiff is the industry-standard binary diffing tool (now part of Google's zynamics):

**Workflow:**
1. Analyze both binaries with IDA Pro
2. Run BinDiff to compare the two IDA databases
3. Review function-level and basic-block-level differences

**Installation:**
```bash
# BinDiff requires IDA Pro 7.x+
# Install the BinDiff plugin for IDA
# Copy bindiff.dll/bindiff64.dll to IDA plugins directory
```

**Analysis steps:**
1. Open unpatched binary in IDA Pro
2. Wait for auto-analysis to complete
3. Open patched binary in a second IDA instance
4. Run BinDiff: Edit → Plugins → BinDiff → Compare to...
5. Select the IDA database of the other binary
6. BinDiff produces a comparison database with:
   - **Matched functions**: Same logic (no change)
   - **Changed functions**: Different logic (potential fix)
   - **Unmatched functions**: New or removed functions

**Interpreting results:**
- Focus on **changed functions**: These are the most likely security fixes
- Compare pseudocode: Use Hex-Rays decompiler on both sides
- Look for added checks, bounds validations, and error handling

### 3.2 Diaphora

Diaphora is an open-source binary diffing tool:

**Installation:**
```bash
git clone https://github.com/joxeankoret/diaphora
cd diaphora
pip install -r requirements.txt
```

**Usage:**
```python
# Export IDA databases to JSON
# In IDA Python console:
import diaphora
diaphora.export_database("/path/to/export.json")

# Compare databases
python diaphora.py /path/to/unpatched.json /path/to/patched.json
```

**Diaphora comparison metrics:**
- **Similarity score**: 0.0–1.0 (1.0 = identical)
- **Confidence score**: 0.0–1.0 (1.0 = high confidence in match)
- **Match type**: Best match, partial match, unreliable match

### 3.3 bbcmp

bbcmp is a lightweight binary diffing tool for comparing basic blocks:

```bash
# Compare two binaries at the basic block level
python bbcmp.py unpatched_binary patched_binary
```

## 4. Developer Tools for Vulnerability Research

### 4.1 Git Blame for Vulnerability History

```bash
# Find who wrote a specific line (and when)
git blame -L 42,55 src/vulnerable.c

# Find the commit that introduced a specific line
git blame -L 42 src/vulnerable.c | head -1
# Output: ^a1b2c3d (Author Name 2023-01-15 42) vulnerable_code();

# View the full commit
git show a1b2c3d

# Find the original commit that introduced a feature
git log --follow --all -p -- src/vulnerable.c | head -200
```

### 4.2 git log -p for Vulnerability History

```bash
# Show the full diff history of a file
git log -p -- src/vulnerable.c

# Search for security-relevant changes
git log -p --grep="security\|CVE\|bug\|fix\|crash" -- src/vulnerable.c

# Find when a specific function was changed
git log -p -S "vulnerable_function" -- src/vulnerable.c

# Find when a specific pattern was introduced or removed
git log -p -G "memcpy.*sizeof" -- src/vulnerable.c

# Show only changes to specific lines
git log -p -L 42,55:src/vulnerable.c

# Find merge commits that may have introduced bugs
git log --merges --oneline
```

### 4.3 git bisect for Finding Bug-Introducing Commits

```bash
# Start bisecting
git bisect start

# Mark current (bad) version
git bisect bad HEAD

# Mark known-good version
git bisect good v1.0

# For each step, test and mark
git bisect good   # If this version works
git bisect bad    # If this version has the bug

# When bisect finishes, it shows the introducing commit
# a1b2c3d is the first bad commit
```

Automated bisect:
```bash
# Automated bisect with a test script
git bisect start HEAD v1.0
git bisect run ./test_for_bug.sh
```

## 5. Patch Analysis Techniques

### 5.1 Understanding Security Patches

Security patches typically follow one of these patterns:

1. **Bounds check addition**: Add size/length validation before access
2. **Type validation**: Add type checks before type-specific operations
3. **Reference count fix**: Add missing get/put calls
4. **Lock acquisition fix**: Add missing lock/unlock pairs
5. **Error path fix**: Add cleanup in error paths
6. **Input validation**: Sanitize input before processing

### 5.2 1-Day Exploitation from Patches

When a security patch is published, attackers can:
1. Diff the patched and unpatched versions
2. Understand the bug from the patch
3. Develop an exploit for the unpatched version

This is called **1-day exploitation** and highlights the importance of:
- Rapid patch deployment
- Minimal information leakage in commit messages
- Not publishing detailed exploit information before patches are deployed

### 5.3 Patch Diffing Workflow

```bash
# 1. Get the patch commit
git log --all --oneline --grep="CVE-2022-0847"
# abc1234 fix: validate pipe buffer flags

# 2. View the patch
git show abc1234

# 3. Find the introducing commit
git log -p -S "the vulnerable line" -- src/file.c

# 4. Build both versions
git checkout abc1234^    # Before fix
make -j$(nproc)
cp target target_unpatched

git checkout abc1234     # After fix
make -j$(nproc)
cp target target_patched

# 5. Binary diff
# Open both in IDA Pro, run BinDiff

# 6. Develop exploit for unpatched version
```

## 6. Source Code Audit Methodology

### 6.1 Top-Down Auditing

Start from the entry points (API surface) and trace data flow inward:

1. **Identify all entry points**: System calls, API endpoints, IPC handlers, parser entry points
2. **Trace input validation**: For each entry point, check how input is validated
3. **Follow data flow**: Track how input data flows through the code
4. **Check error handling**: Verify that error paths don't leak resources or state
5. **Verify invariants**: Check that security invariants hold across all paths

### 6.2 Bottom-Up Auditing

Start from the sensitive operations and trace backward to entry points:

1. **Identify sensitive sinks**: Memory allocation, pointer dereference, system calls, IPC
2. **Trace backward**: How does data reach each sink?
3. **Check each path**: Is there a path from attacker-controlled input to this sink?
4. **Validate assumptions**: Are the preconditions for each sink always satisfied?

### 6.3 Combined Approach

Most effective auditing combines both approaches:

```
Top-Down: Entry → Validation → Processing → Sensitive operations
Bottom-Up: Sensitive operations ← Processing ← Validation ← Entry
                     ↑                                    ↓
                     └────── Meet in the middle ──────────┘
```

### 6.4 Audit Checklist for C/C++ Projects

```
[ ] Input validation
    [ ] All external input is validated before use
    [ ] Length/size checks before buffer operations
    [ ] Integer overflow checks before arithmetic
    [ ] Type checks before type-specific operations

[ ] Memory management
    [ ] No use-after-free (dangling pointers)
    [ ] No double-free
    [ ] No buffer overflows (read/write)
    [ ] No memory leaks (especially in error paths)
    [ ] No uninitialized memory reads

[ ] Concurrency
    [ ] Proper lock ordering (no deadlocks)
    [ ] No data races (shared state protected)
    [ ] No TOCTOU issues
    [ ] Reference counts are correct

[ ] Error handling
    [ ] All error paths clean up resources
    [ ] Error codes are checked
    [ ] No silent failures
    [ ] No information leaks in error messages

[ ] Cryptography
    [ ] No hardcoded keys
    [ ] Proper random number generation
    [ ] No timing side channels
    [ ] Proper certificate validation

[ ] Privilege management
    [ ] Least privilege principle
    [ ] No privilege escalation paths
    [ ] Proper sandbox escape prevention
    [ ] Input sanitization before privilege operations
```

## 7. Bug Bounty Hunting Methodology

### 7.1 Reconnaissance

1. **Identify the attack surface**: What can an attacker control?
2. **Map the codebase**: Understand the architecture and data flow
3. **Identify high-value targets**: What bugs would have the most impact?
4. **Find under-explored areas**: Code that hasn't been fuzzed or audited recently

### 7.2 Automated Analysis

```bash
# Step 1: Run static analysis
semgrep --config auto /path/to/project
codeql database analyze project-db codeql/cpp-queries:Security

# Step 2: Run fuzzing
# (See other chapters for detailed fuzzing methodology)

# Step 3: Analyze crashes
for crash in crashes/*; do
    ./target_asan "$crash" 2>&1 | tee "triage/$(basename $crash).txt"
done
```

### 7.3 Manual Analysis

Focus on code that automated tools can't analyze effectively:
- Complex state machines (protocol handling)
- Business logic (authorization, access control)
- Race conditions (concurrent access patterns)
- Cryptographic protocol implementations

### 7.4 Variant Hunting

After finding one bug:
1. Understand the root cause completely
2. Generalize the bug pattern
3. Search the entire codebase for similar patterns
4. Use CodeQL or Semgrep for automated variant detection
5. Create a targeted fuzzer for the variant pattern

### 7.5 Bug Bounty Hunting Tips

**Scope assessment:**
- Read the bounty program scope carefully
- Identify the highest-paying bug categories
- Focus on code that's in scope but not well-fuzzed
- Check for recently added features (new code = less tested)

**Triage efficiency:**
- Use automated tools first (Semgrep, CodeQL)
- Focus manual effort on high-impact areas
- Write fuzz harnesses for interesting code paths
- Document findings clearly for the bounty submission

**Common high-value targets:**
- Memory corruption in privileged processes
- Sandbox escape vectors
- Authentication/authorization bypasses
- Cryptographic implementation flaws
- Race conditions in security-critical code

## 8. Combining Static and Dynamic Analysis

### 8.1 The Hybrid Approach

Static analysis and dynamic analysis (fuzzing, sanitizers) are most powerful when combined:

```
Static Analysis → Identify suspicious code paths → Write targeted fuzz harnesses →
Dynamic Analysis → Fuzz the suspicious code → Validate static findings →
Crash Analysis → Root cause → Variant analysis with static tools → More bugs
```

### 8.2 Practical Workflow

```bash
# Step 1: Static analysis to find suspicious code
semgrep --config p/security-audit project/ > semgrep_results.json
codeql database analyze db codeql/cpp-queries:Security > codeql_results.csv

# Step 2: Extract interesting code locations
grep -E "buffer-overflow|use-after-free|integer-overflow" codeql_results.csv | \
    cut -d, -f3 > interesting_locations.txt

# Step 3: Write targeted fuzz harnesses for each location
while IFS= read -r location; do
    python3 generate_harness.py "$location" > "harness_$(echo $location | md5sum | cut -c1-8).c"
done < interesting_locations.txt

# Step 4: Fuzz each harness
for harness in harness_*.c; do
    clang -fsanitize=fuzzer,address -o "${harness%.c}" "$harness"
    ./"${harness%.c}" "corpus_$(basename $harness .c)/" -max_total_time=600
done

# Step 5: Triage crashes and validate static analysis findings
```

### 8.3 False Positive Reduction

Static analysis tools produce many false positives. Reduce them by:
1. **Cross-reference with coverage**: If static analysis flags unreachable code, it's a false positive
2. **Run under sanitizers**: If the flagged code path doesn't trigger sanitizer violations, the finding may be unexploitable
3. **Use data flow analysis**: CodeQL's taint tracking reduces false positives by verifying that attacker input reaches the sink
4. **Manual verification**: For high-severity findings, always verify manually before reporting

## References

[1] GitHub. *CodeQL Documentation*. https://codeql.github.com/docs/

[2] Return to Corporation. *Semgrep Documentation*. https://semgrep.dev/docs/

[3] Zynamics. *BinDiff Manual*. https://www.zynamics.com/bindiff.html

[4] Joxean Koret. *Diaphora*. https://github.com/joxeankoret/diaphora

[5] Synopsys. *Coverity Static Analysis*. https://www.synopsys.com/software-integrity/security-testing/static-analysis-sast.html

[6] Meta. *Infer Static Analyzer*. https://fbinfer.com/

[7] NIST. *National Vulnerability Database (NVD)*. https://nvd.nist.gov/

[8] MITRE. *Common Weakness Enumeration (CWE)*. https://cwe.mitre.org/

[9] Serebryany, K., Bruening, D., Potapenko, A., & Vyukov, D. (2012). *AddressSanitizer: A Fast Address Sanity Checker*. USENIX ATC.

[10] Serebryany, K. (2015). *MemorySanitizer: Fast Detector of Uninitialized Memory Use*. IEEE/ACM ISCA.

[11] LLVM Project. *UndefinedBehaviorSanitizer*. https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html

[12] Nethercote, N. & Seward, J. (2007). *Valgrind: A Framework for Heavyweight Dynamic Binary Instrumentation*. ACM PLDI. DOI: 10.1145/1250734.1250746

[13] Zaddach, J. & Francillon, A. (2013). *AVATAR: A Framework to Support Dynamic Testing of Embedded Systems*. NDSS.

[14] PVS-Studio. *PVS-Studio Static Analyzer*. https://pvs-studio.com/

[15] CVE-2022-0847. *DirtyPipe Vulnerability*. https://dirtypipe.cm4all.com/

[16] CVE-2016-5195. *Dirty COW*. https://dirtycow.ninja/

[17] GitHub. *CodeQL Query Repository*. https://github.com/github/codeql

[18] GitHub. *Semgrep Rules Registry*. https://semgrep.dev/p/

[19] Chaudhary, A. (2020). *The Art of Exploitation: Practical Reverse Engineering*. No Starch Press.

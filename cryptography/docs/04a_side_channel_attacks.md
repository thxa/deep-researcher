# Side-Channel Attacks

> A comprehensive treatment of side-channel attacks: from Kocher's seminal timing attack to modern cache attacks (Flush+Reload, Prime+Probe), Spectre/Meltdown, power analysis, electromagnetic emanation, acoustic cryptanalysis, and countermeasures including constant-time programming, blinding, masking, and shuffling.

---

## Table of Contents

1. [Timing Attacks](#1-timing-attacks)
2. [Power Analysis (SPA/DPA)](#2-power-analysis-spadpa)
3. [Electromagnetic Emanation Attacks](#3-electromagnetic-emanation-attacks)
4. [Cache Timing Attacks](#4-cache-timing-attacks)
5. [Spectre and Meltdown](#5-spectre-and-meltdown)
6. [PACMAN — PAC Brute Force via Side Channel](#6-pacman--pac-brute-force-via-side-channel)
7. [Acoustic Cryptanalysis](#7-acoustic-cryptanalysis)
8. [Optical Side Channels](#8-optical-side-channels)
9. [Countermeasures](#9-countermeasures)

---

## 1. Timing Attacks

### 1.1 Kocher's Timing Attack (1996)

Paul Kocher's 1996 paper "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems" introduced the concept of timing side channels in cryptographic implementations. The fundamental observation: the time taken by a cryptographic operation depends on the secret key, and careful measurement can recover the key.

**ReLU activation**: The square-and-multiply algorithm for modular exponentiation leaks information about individual bits of the private exponent $d$:

```c
// VULNERABLE: square-and-multiply
result = 1;
for (int i = bit_length(d) - 1; i >= 0; i--) {
    result = result * result mod n;  // Square: always executed
    if (bit(d, i) == 1) {
        result = result * m mod n;    // Multiply: only if bit is 1
    }
}
```

Each "1" bit adds a multiply operation that takes measurable time ($\sim 10\mu s$ for RSA-2048 on typical hardware). By measuring the total time, the attacker can deduce the Hamming weight of $d$. More sophisticated analysis recovers individual bits.

**Statistical model**: Let $T_i$ be the time of the $i$-th decryption, and $b_j$ be the $j$-th bit of $d$. The expected time is:

$$E[T_i \mid b_j = 1] = E[T_i \mid b_j = 0] + t_{\text{mul}}$$

where $t_{\text{mul}}$ is the additional time for a multiply operation. Given $N$ measurements, the attacker computes the correlation between measurement $T_i$ and a hypothesis about bit $b_j$:

$$\text{Cor}(T_i, h_j) = \frac{\sum_i (T_i - \bar{T})(h_{ij} - \bar{h}_j)}{\sqrt{\sum_i (T_i - \bar{T})^2 \sum_i (h_{ij} - \bar{h}_j)^2}}$$

where $h_{ij}$ is the hypothesized value of bit $j$ given ciphertext $c_i$. The correct hypothesis has the highest correlation.

### 1.2 Remote Timing Attacks

**Brumley and Boneh (2003)**: First practical remote timing attack on RSA. The attacker measures the time for modular exponentiation over a network connection (via TLS handshake). Network jitter is mitigated by:

1. Taking $\sim 10^4$ measurements per bit.
2. Using the median instead of mean to reduce the effect of outliers.
3. Correcting for clock skew by measuring round-trip time.

Results: Full 1024-bit RSA key recovery in $\sim 2$ hours on a local network (0.3ms RTT) and $\sim 2$ days on a WAN (50ms RTT).

**Remote timing attacks on other algorithms**:
- **ECDSA**: The double-and-add algorithm for scalar multiplication on elliptic curves leaks the Hamming weight of the scalar. For 256-bit curves, the Hamming weight is approximately 128, but knowing the exact weight constrains the key space.
- **AES**: Table-based AES implementations (T-tables) have data-dependent memory access patterns that leak key material through cache timing (see §4).
- **Password hashing**: The time to verify a password with bcrypt or PBKDF2 depends on the password length (due to hash computation time). This leaks the password length to a remote attacker.

### 1.3 Timing Attacks on HMAC Verification

As discussed in §02b, timing attacks on HMAC verification exploit non-constant-time string comparison. The HMAC tag is compared byte-by-byte, and the comparison short-circuits on the first mismatch, revealing how many bytes matched.

The attack recovers the tag one byte at a time:
- Position 0: Try all 256 values for byte 0. The correct value takes $\epsilon$ longer.
- Position 1: Fix byte 0, try all 256 values for byte 1.
- Continue for all tag positions.

For a 32-byte HMAC-SHA256 tag, this requires at most $256 \times 32 = 8,192$ queries, compared to $2^{256}$ for brute force. With rate limiting (1 request/second), this takes $\sim 2.3$ hours.

**Defense**: Always use constant-time comparison (`hmac.compare_digest` in Python, `CRYPTO_memcmp` in OpenSSL, `subtle.ConstantTimeCompare` in Go).

---

## 2. Power Analysis (SPA/DPA)

### 2.1 Simple Power Analysis (SPA)

SPA involves directly observing the power consumption trace of a cryptographic device during a single operation. Different operations (multiplication, addition, memory access) have distinguishable power consumption signatures.

**SPA on RSA**: The square-and-multiply algorithm draws different power patterns for squares and multiplies. A square operation followed immediately by a multiply indicates a "1" bit; two consecutive squares indicate a "0" bit. The entire private exponent $d$ is directly readable from a single power trace.

**SPA on AES**: The AES SubBytes step accesses a 256-byte S-box table. The S-box index is the ciphertext byte XORed with the key byte. If the S-box is stored in a lookup table (not computed on-the-fly), the power consumption during SubBytes depends on which table entries are accessed, revealing the key byte indices.

**Countermeasure against SPA**: Convert all conditional operations to unconditional sequences that execute the same operations regardless of the secret data. The Montgomery ladder (see §02a) is the canonical example for scalar multiplication.

### 2.2 Differential Power Analysis (DPA)

DPA is more powerful than SPA. It uses statistical analysis of many power traces to recover secret keys even when individual traces are too noisy to interpret directly.

**DPA on AES**: The attack targets one key byte at a time:

1. Collect $N$ power traces $T_1, T_2, \ldots, T_N$ for $N$ encryptions with known plaintexts $p_1, p_2, \ldots, p_N$.
2. For each key byte hypothesis $k_j$ (0–255), compute the hypothetical intermediate value $v_i = S(p_i \oplus k_j)$ for SubBytes output.
3. Divide the traces into two sets based on a selection function $D(v_i)$ (e.g., $D(v_i) = 1$ if bit $b$ of $v_i$ is 1, 0 otherwise).
4. Compute the differential trace: $\Delta_T = \frac{1}{|S_1|} \sum_{T_i \in S_1} T_i - \frac{1}{|S_0|} \sum_{T_i \in S_0} T_i$.
5. The correct key byte hypothesis produces a differential trace with a large spike at the time when SubBytes is computed. Incorrect hypotheses produce random noise.

DPA requires $\sim 100-1000$ traces for AES-128, depending on the measurement noise. With a well-calibrated oscilloscope and direct access to the target chip, 100 traces may be sufficient.

**DPA on RSA**: The attack targets RSA decryption on smart cards by correlating the power consumption at each multiplication step with hypotheses about intermediate values. Since RSA uses the same private exponent for all operations, collecting multiple traces with different ciphertexts provides sufficient statistical information.

### 2.3 High-Order DPA and Template Attacks

**Second-order DPA**: If first-order DPA is defeated by masking (see §9), the attacker can use second-order DPA, which correlates power consumption at two different time points to remove the mask effect. Second-order DPA requires more traces ($\sim 10{,}000$) but can break masked implementations.

**Template attacks**: The attacker builds a statistical model (template) of the device's power consumption for each key hypothesis. The template is created by encrypting known plaintexts with a known key (on a device of the same type) and recording the power traces. The template captures the mean and covariance of the power traces for each intermediate value.

To attack a new device, the attacker records a single power trace and matches it against the templates. The key hypothesis with the highest template likelihood is the correct key. Template attacks can recover keys from a single trace, but they require a "profile" phase on a device of the same type.

**Practical template attack on AES**: The attacker buys an identical smart card, profiles its power consumption for all 256 possible key byte values, then uses the profile to recover the key from a single power trace on the target card. This requires physical access to an identical device (not the target) and an oscilloscope with $\sim 1$ GHz bandwidth.

---

## 3. Electromagnetic Emanation Attacks

### 3.1 TEMPEST and EM Emanations

TEMPEST (Telecommunications Electronics Material Protected from Emanating Spurious Transmissions) is the NSA codename for the study of electromagnetic (EM) emanations from electronic equipment. All electronic devices emit EM radiation during operation, and these emanations can be captured and analyzed to recover sensitive data.

**EM emanation sources**:
- **Processor activity**: Clock signals, switching transients, and data bus activity emit in the 10 kHz–1 GHz range.
- **Memory access**: DRAM refresh cycles, cache line fills, and register file reads produce EM signatures.
- **Power supply**: Voltage regulators and DC-DC converters emit at switching frequencies (100 kHz–10 MHz).
- **Display**: CRT and LCD displays emit video signals that can be reconstructed from EM emanations (van Eck phreaking).

### 3.2 EM Probing of Cryptographic Operations

**Setup for EM attack on a smart card**:
1. Place a small EM probe (coil antenna, 0.5–5 mm diameter) near the target chip.
2. Use an oscilloscope or software-defined radio (SDR) to capture EM signals.
3. Apply DPA/SPA techniques to the captured EM traces.

EM probing is often easier than power analysis because:
- No physical contact with the target is needed (non-invasive).
- The EM probe can be positioned to maximize the signal from specific chip areas (e.g., the AES accelerator).
- EM traces have higher spatial resolution than power traces (which measure the entire chip's current draw).

**Countermeasures**:
- **Faraday cage**: Enclose the device in a conductive enclosure that attenuates EM emanations.
- **EM shielding**: Add metal layers to the PCB and chip package.
- **Signal damping**: Add on-chip decoupling capacitors and filter circuitry.
- **Randomize operation timing**: Add random delays between operations to decorrelate EM traces from clock edges.

### 3.3 Foundational EM Attack: USB Cable Leakage

**Kocher, Jaffe, Jun (2019)** demonstrated that EM emanations from a USB cable connected to a smart card reader can be captured from $\sim 1$ meter away using a simple loop antenna. The USB cable acts as an unintentional antenna, radiating the smart card's activity. The researchers recovered AES keys from EM emanations captured at a distance of 40 cm using a $300 SDR setup.

---

## 4. Cache Timing Attacks

### 4.1 Microarchitectural Background

Modern CPUs use a memory hierarchy:
```
Register file (1 cycle) → L1 cache (3-4 cycles) → L2 cache (10-12 cycles) → L3 cache (30-50 cycles) → DRAM (200-300 cycles)
```

The cache is a shared resource between all cores (L3) or between hyperthreads (L2). If process A can observe whether data is in the cache, it can deduce information about process B's memory access patterns — even if A and B are in different protection domains (user/kernel, VM/container).

**Cache occupancy side channel**: The time to access a memory location depends on whether it's in the cache (fast hit) or DRAM (slow miss). This timing difference ($\sim 200$ cycles or $\sim 60$ ns on modern x86) is observable through:
- Direct timing measurement (using `rdtscp` or similar).
- Indirect timing measurement (eviction-based: measuring the time to evict a cache line and reload it).

### 4.2 Flush+Reload

**Flush+Reload** (Yarom and Falkner, 2014) is the most precise cache side-channel attack. It exploits shared memory between the attacker and the victim:

**Setup**: The attacker and victim share a memory page (e.g., a shared library, page cache page, or shared memory segment).

**Attack steps**:
1. **Flush**: The attacker evicts a specific cache line from all cache levels using the `clflush` instruction.
2. **Wait**: The attacker waits for the victim to execute. If the victim accesses the monitored cache line, it will be loaded into the cache.
3. **Reload**: The attacker accesses the monitored cache line and measures the access time.
   - Fast access ($\sim 40$ cycles): The cache line was loaded by the victim (the victim accessed the monitored address).
   - Slow access ($\sim 200$ cycles): The cache line was not loaded by the victim (the victim did not access the monitored address).

**Advantages**: Flush+Reload provides a `clflush`-sized granularity (64 bytes) and high temporal resolution ($\sim 1\mu s$). It works across cores and across VM boundaries (when memory is shared, e.g., in cloud environments via page deduplication).

**Disadvantages**: Requires shared memory between attacker and victim. Kernel page deduplication (KSM) is often disabled in cloud environments specifically to prevent Flush+Reload attacks.

**Flush+Reload on AES**: The T-table AES implementation uses four 1 KB lookup tables ($T_0, T_1, T_2, T_3$). Each table has 256 entries of 32 bits (4 bytes each), spanning 64 cache lines. The attacker monitors specific cache lines in $T_0$ and observes which lines are accessed during each AES round. After $\sim 100$ observations, the attacker can determine the first round key with high probability.

```c
// Flush+Reload attack on AES T-tables
// Monitor cache line containing T0[S-box_output_hint]
// S-box_output = plaintext_byte XOR key_byte
// If T0[S-box_output] is in the cache, the victim accessed that T-table entry

void flush_reload_attack(uint8_t *t0_table, uint8_t *plaintext) {
    for (int key_guess = 0; key_guess < 256; key_guess++) {
        int hits = 0;
        for (int sample = 0; sample < SAMPLES; sample++) {
            // Flush the cache line containing T0[key_guess]
            _mm_clflush(&t0_table[key_guess * 4]);
            
            // Wait for victim to access the T-table
            wait_for_victim();
            
            // Reload and time the access
            uint64_t t1 = __rdtscp(0);
            volatile uint32_t val = *(uint32_t*)&t0_table[key_guess * 4];
            uint64_t t2 = __rdtscp(0);
            
            if (t2 - t1 < CACHE_HIT_THRESHOLD) {
                hits++;
            }
        }
        printf("Key guess %d: %d hits\n", key_guess, hits);
    }
}
```

### 4.3 Prime+Probe

**Prime+Probe** (Osvik, Shamir, Tromer 2006) does not require shared memory. It works by filling the cache with the attacker's data (prime), letting the victim execute, then checking which cache lines were evicted (probe).

**Attack steps**:
1. **Prime**: The attacker fills a cache set with their own data, ensuring all cache lines in the set are occupied.
2. **Wait**: The victim executes. If the victim accesses data that maps to the same cache set, it evicts one of the attacker's lines.
3. **Probe**: The attacker reloads their data and measures access times. Slow access (cache miss) indicates the victim accessed data in that cache set.

**Advantages**: No shared memory required. Works across user processes (even across VMs if the L3 cache is shared).

**Disadvantages**: Lower spatial resolution than Flush+Reload (cache-set granularity, typically 8–16 cache lines per set on L3). Higher noise due to interference from other processes.

**Prime+Probe on AES**: The attacker monitors the L3 cache sets corresponding to the AES T-table entries. Since each T-table entry maps to a specific L3 cache set (based on its physical address), the attacker can determine which T-table entries were accessed during each AES round. After $\sim 10{,}000$ samples, the attacker recovers the full AES key.

**Cloud cross-VM attacks**: Ristenpart et al. (2009) and subsequently Inci et al. (2016) demonstrated Prime+Probe attacks across VMs on Amazon EC2. By co-locating with a victim VM, the attacker recovers AES keys from the victim's TLS implementation in $\sim 50$ minutes.

### 4.4 Evict+Time

**Evict+Time** (Oswik et al. 2006) is a simpler variant: the attacker evicts specific cache lines, then measures the total execution time of the victim's cryptographic operation. If the evicted lines are unused by the victim, the operation takes normal time. If the evicted lines are used by the victim, the operation takes longer (due to cache misses).

Evict+Time is less precise than Prime+Probe and Flush+Reload (it cannot determine which specific cache line was accessed, only which cache set) but is simpler to implement. It is primarily used as a first step to narrow down the cache sets of interest before applying Prime+Probe.

### 4.5 Cache Attacks on RSA

RSA modular exponentiation leaks the private exponent through cache side channels. The Montgomery multiplication algorithm accesses different cache lines depending on whether the current bit of the private exponent is 0 or 1.

**Attack**: The attacker monitors the L3 cache during RSA signing (e.g., a TLS handshake). By observing which cache lines are accessed during each multiplication step, the attacker reconstructs the private exponent bit-by-bit.

**Results**: Inci et al. (2017) recovered a 2048-bit RSA key from a victim OpenSSL process on a co-located VM in 3.3 hours using Prime+Probe on the L3 cache. The attack required $\sim 12{,}000$ RSA signatures.

**Mitigation**: Constant-time RSA implementation (see §9) and disabling kernel page deduplication (KSM) to prevent shared-memory attacks.

---

## 5. Spectre and Meltdown

### 5.1 Spectre (CVE-2017-5753, CVE-2017-5715)

Spectre (Kocher et al., 2018) exploits speculative execution to leak data across security boundaries. When a CPU encounters a branch (e.g., `if (condition) { ... }`), it predicts the outcome and speculatively executes the predicted path. If the prediction is wrong, the speculative results are discarded — but the microarchitectural state (cache contents, TLB entries) is not rolled back. This leaves a trace that can be observed via cache side channels.

**Spectre Variant 1 (Bounds Check Bypass, CVE-2017-5753)**:
```c
if (x < array_size) {
    // Speculatively executed even if x >= array_size
    y = array2[array1[x] * 256];
}
// Array2's cache state leaks array1[x] even though the branch was mispredicted
```

The attacker:
1. Trains the branch predictor to expect the `if` condition to be true.
2. Passes an out-of-bounds `x` value.
3. The CPU speculatively accesses `array1[x]` (reading out-of-bounds data) and then `array2[array1[x] * 256]`.
4. The branch is resolved (mispredicted), and the speculative results are discarded.
5. However, `array2`'s cache state reflects the speculatively accessed index. The attacker probes `array2` to determine which cache line was accessed, revealing `array1[x]`.

**Spectre Variant 2 (Branch Target Injection, CVE-2017-5715)**:
The attacker poisons the branch predictor (Branch Target Buffer, BTB) so that an indirect branch in the victim (e.g., a system call handler) speculatively jumps to a gadget chosen by the attacker. The gadget executes cache side-channel operations that leak kernel memory.

This requires:
1. The attacker and victim share the same BTB (same physical core, or same core via hyperthreading).
2. The attacker identifies a suitable gadget in the victim's address space.
3. The attacker triggers the victim's indirect branch with a poisoned BTB entry.

### 5.2 Meltdown (CVE-2017-5754)

Meltdown (Lipp et al., 2018) exploits out-of-order execution to read kernel memory from user space. On Intel CPUs (and some ARM CPUs), the permission check for memory access (user vs. kernel) is performed asynchronously. The CPU may execute the memory access and dependent operations before the permission check completes. When the check fails, the results are discarded — but the microarchitectural state (cache) again reflects the speculatively accessed data.

```c
// User-space code reading kernel memory
uint8_t *kernel_addr = (uint8_t *)0xffffffff81000000;  // Kernel address
uint8_t secret = *kernel_addr;  // Should fault, but speculative execution reads the byte
y = array2[secret * 256];        // Cache side channel encodes the secret
```

Meltdown is simpler than Spectre (no branch predictor poisoning needed) but is specific to Intel CPUs with asynchronous permission checks. AMD and some ARM CPUs are not vulnerable because they perform permission checks before speculative execution.

**Impact**: Meltdown allows any user-space process to read the entire kernel address space, including kernel code, data structures, and other processes' memory (via kernel page tables). This completely defeats kernel isolation.

**Mitigation**: Kernel Page Table Isolation (KPTI, also called KAISER) separates user-space and kernel-space page tables, so the kernel's page tables are not mapped during user-space execution. This incurs a 0.1–5% performance penalty on most workloads (due to TLB flushing on syscall entry/exit).

### 5.3 Spectre/Meltdown Variants

Since the original disclosure, numerous variants have been discovered:

| Variant | CVE | Exploits | Target |
|---|---|---|---|
| Spectre v1 | CVE-2017-5753 | Bounds check bypass | User→User, Kernel→User |
| Spectre v2 | CVE-2017-5715 | Branch target injection | Cross-VM, User→Kernel |
| Meltdown | CVE-2017-5754 | Rogue data cache load | User→Kernel |
| Spectre-NG | CVE-2018-3639 | Speculative store bypass | User→User |
| Foreshadow | CVE-2018-3615 | L1 Terminal Fault (SGX) | User→SGX |
| Lazy FPU | CVE-2018-3665 | FPU state leak | User→Kernel |
| Spectre v4 | CVE-2018-3693 | Speculative store bypass | User→Kernel |
| ZombieLoad | CVE-2018-12130 | MDS (Microarchitectural Data Sampling) | User→Kernel, VM→VM |
| RIDL | CVE-2019-11091 | Rogue In-Flight Data Load | User→Kernel |
| Fallout | CVE-2018-12126 | Store Buffer Data Sampling | User→Kernel |
| CacheOut | CVE-2020-0498 | L1 Data Cache leakage | VM→VM |

### 5.4 Cryptographic Impact of Spectre/Meltdown

**RSA key recovery**: Spectre can be used to leak RSA private keys from a user-space process. An attacker in one process can use Spectre v1 to read the private key from another process or the kernel.

**AES key recovery**: Meltdown and Spectre v2 can be used to leak AES round keys from the kernel's cryptographic subsystem. If the AES key is stored in kernel memory (e.g., dm-crypt keys), Meltdown can read it directly.

**SGX enclave attacks**: Foreshadow (L1 Terminal Fault) and subsequent SGX attacks demonstrated that Intel SGX enclaves are vulnerable to microarchitectural side channels, breaking the attestation model.

**Mitigations**:
- **Spectre v1**: Replace bounds-checked array accesses with constant-time bounds checks (using `array_index_mask_nospec` in the Linux kernel).
- **Spectre v2**: Retpoline (Return Trampoline) replaces indirect branches with a safe sequence that prevents speculative execution. IBRS (Indirect Branch Restricted Speculation) is a microcode feature that isolates branch predictors.
- **Meltdown**: KPTI separates user and kernel page tables.
- **MDS/ZombieLoad**: Microcode updates clear affected buffers on privilege transitions.

---

## 6. PACMAN — PAC Brute Force via Side Channel

### 6.1 Pointer Authentication Codes (PAC)

ARMv8.3-A introduced Pointer Authentication Codes (PAC), which sign pointers (function pointers, return addresses, stack pointers) with a secret key stored in a system register. PAC prevents control flow hijacking by ensuring that a modified pointer will have an invalid PAC and cause a crash.

PAC computes a keyed MAC over the pointer value: $\text{PAC} = \text{QARMA64}(key, \text{pointer}, \text{modifier})$, where QARMA64 is a lightweight block cipher and the modifier is context-specific (SP, FP, etc.). The PAC is stored in the upper bits of the pointer (which are unused in a 48-bit or 52-bit address space on 64-bit ARM).

### 6.2 The PACMAN Attack

**PACMAN** (Rahman et al., 2022) demonstrates that PAC can be brute-forced using a side channel. The attack uses a speculative execution side channel to determine whether a PAC verification succeeded or failed, without causing a crash.

**Attack procedure**:
1. The attacker creates a pointer with a guessed PAC.
2. When the pointer is used speculatively, the CPU checks the PAC.
3. If the PAC is correct, the speculative execution proceeds (and the side channel is activated).
4. If the PAC is incorrect, the speculative execution is suppressed (no side channel effect).
5. By observing the side channel (e.g., cache timing), the attacker determines whether the PAC was correct.

**PAC space**: ARMv8.3 PAC uses a 16-bit PAC (or 12-bit for code pointers), giving $2^{16} = 65{,}536$ possible PAC values. The brute-force attack requires at most 65,536 attempts per pointer, which is feasible in seconds on modern hardware.

**Impact**: PACMAN demonstrates that PAC alone is insufficient to prevent control flow hijacking. An attacker with a memory corruption vulnerability (e.g., buffer overflow) can:
1. Overwrite a pointer in memory.
2. Use PACMAN to brute-force the correct PAC for the pointer.
3. Hijack control flow.

PAC remains a useful defense-in-depth measure (it raises the bar from a single write to $\sim 65{,}000$ writes), but it should be combined with other mitigations (memory safety, stack canaries, ASLR).

---

## 7. Acoustic Cryptanalysis

### 7.1 Key Recovery from Acoustic Emanations

**Genkin, Shamir, Tromer (2014)** demonstrated that the acoustic emanations (whining, buzzing) produced by a computer's electronic components during cryptographic operations leak information about the key being processed.

**Mechanism**: The CPU's power consumption varies with computation, and voltage regulators convert these variations into acoustic signals. Different CPU operations (multiplication, memory access, cache hits/misses) produce distinguishable acoustic signatures in the 10–150 kHz range (well above human hearing but within the bandwidth of consumer microphones).

**Experimental setup**:
- A Samsung Galaxy S4 smartphone placed 30 cm from a target laptop.
- The microphone recorded acoustic emanations during GnuPG RSA key generation.
- Signal processing (FFT, bandpass filtering) extracted frequency components correlated with RSA operations.
- Machine learning classified the acoustic patterns to recover individual key bits.

**Results**: 
- Full 4096-bit RSA key recovery from acoustic emanations at 4 meters distance, using a parabolic microphone.
- Distinguishing individual RSA operations (key generation, signing, decryption) from acoustic analysis alone.
- Extracting the Hamming weight of RSA key chunks (groups of 32 bits) with $\sim 70\%$ accuracy.

**Key observations**:
1. The CPU's voltage regulator produces a characteristic acoustic signature during multiplication-heavy operations. The frequency and amplitude of the acoustic emanation depend on the Hamming weight of the intermediate value being multiplied.
2. Different CPU architectures produce different acoustic signatures, but the same methodology applies.
3. The attack is non-invasive (no physical contact) and can be performed from several meters away.

### 7.2 Countermeasures

- **Acoustic shielding**: Enclose the device in a sound-dampening enclosure (foil-lined case, acoustic foam).
- **Operation randomization**: Randomize the order of RSA operations (use randomized exponentiation, see §9).
- **CPU frequency scaling**: Randomize the CPU clock frequency to decorrelate acoustic emanations from computation.
- **Stay away**: The attack range is limited to $\sim 10$ meters with sophisticated microphones. Physical distance is the simplest defense.

---

## 8. Optical Side Channels

### 8.1 Power LED Attack

**Loughin et al. (2022)** demonstrated that the power LED brightness on a connected device (e.g., a smart speaker, router, or USB device) fluctuates with the device's power consumption, which is correlated with cryptographic operations. By recording the power LED brightness fluctuations with a high-speed camera or photodetector, the attacker can recover key material.

**Mechanism**: Many devices have power LEDs connected to the power line through a current-limiting resistor. As the CPU draws more current during cryptographic operations, the LED dims slightly; as it draws less, the LED brightens. These fluctuations ($\sim 0.1\%$ brightness variation) are imperceptible to the human eye but detectable with:
- A smartphone camera (30–240 fps): rough operation identification.
- A photodetector ($\sim 100$ kHz bandwidth): individual bits of the key.
- An oscilloscope with a photodiode: full key recovery.

**Results**: Full AES-256 key recovery from a smart speaker's power LED at 25 meters, using a telescope and photodetector.

### 8.2 Screen Reflection Attacks

**Screen reflections** (e.g., in glasses, windows, teapots, phone screens) can reveal on-screen content from a distance. The reflection angle is determined by the law of reflection, and the reflected image can be reconstructed using deconvolution techniques.

**Practical attack**: A security researcher typing a password on their laptop can be observed via the reflection in their glasses from $\sim 10$ meters. A high-resolution camera captures the reflection, and image processing reconstructs the on-screen content.

**Countermeasure**: Privacy screen filters (polarizing films that narrow the viewing angle to $\sim 30°$) significantly reduce reflection attack effectiveness.

---

## 9. Countermeasures

### 9.1 Constant-Time Programming

The gold standard for side-channel resistance is **constant-time programming**: all operations take the same amount of time regardless of the secret data. This eliminates all timing side channels.

**Principles**:
1. No secret-dependent branches: `if (secret_bit) { ... } else { ... }` is replaced with constant-time conditional moves.
2. No secret-dependent memory access: `array[secret]` is replaced with constant-time memory access that reads all indices.
3. No secret-dependent loop iteration counts: loops over secret data must have fixed iteration counts.

**Constant-time conditional move**:
```c
// VULNERABLE: secret-dependent branch
uint32_t ct_select(uint32_t condition, uint32_t a, uint32_t b) {
    if (condition) return a;
    else return b;
}

// CONSTANT-TIME: use bitwise operations
uint32_t ct_select(uint32_t condition, uint32_t a, uint32_t b) {
    uint32_t mask = -(condition != 0);  // 0xFFFFFFFF if true, 0x00000000 if false
    return (a & mask) | (b & ~mask);
}
```

**Constant-time memory access (AES S-box)**:
```c
// VULNERABLE: secret-dependent memory access
uint8_t ct_sbox(uint8_t *sbox_table, uint8_t index) {
    return sbox_table[index];  // Cache timing: which cache line is accessed?
}

// CONSTANT-TIME: read all entries, select with bitwise operations
uint8_t ct_sbox(uint8_t sbox_table[256], uint8_t index) {
    uint8_t result = 0;
    for (int i = 0; i < 256; i++) {
        uint8_t mask = -(i == index);  // 0xFF if i == index, 0x00 otherwise
        result |= (sbox_table[i] & mask);
    }
    return result;
}
// Note: Modern AES implementations use bitslicing or AES-NI instructions
// instead of table lookups, which are inherently constant-time.
```

### 9.2 RSA Blinding

RSA blinding randomizes the RSA operation to prevent timing attacks:

**Decryption blinding**:
1. Generate random blinding factor $r \leftarrow \mathbb{Z}_n^*$.
2. Compute $c' = c \cdot r^e \mod n$ (blinded ciphertext).
3. Compute $m' = c'^d \mod n$ (blinded decryption).
4. Compute $m = m' \cdot r^{-1} \mod n$ (unblinded plaintext).

Since $m = c'^d \cdot r^{-1} = (c \cdot r^e)^d \cdot r^{-1} = c^d \cdot r^{ed} \cdot r^{-1} = c^d \cdot r \cdot r^{-1} = c^d \mod n$, the result is correct.

The blinding factor $r$ randomizes the intermediate values during modular exponentiation, ensuring that the timing of each decryption is independent of the ciphertext.

**Signature blinding**:
1. Generate random $r \leftarrow \mathbb{Z}_n^*$.
2. Compute $\tilde{m} = m \cdot r^{e} \mod n$ (blinded message).
3. Sign: $\tilde{\sigma} = \tilde{m}^d \mod n$.
4. Unblind: $\sigma = \tilde{\sigma} \cdot r^{-1} \mod n$.

Since $\sigma = (m \cdot r^e)^d \cdot r^{-1} = m^d \cdot r^{ed-1} = m^d \cdot r^{ed} / r = m^d \cdot r / r = m^d \mod n$, this produces the correct signature.

### 9.3 Masking

**Boolean masking** conceals secret values by XORing them with random masks. For example, in masked AES:

$$s'_i = s_i \oplus r_i$$

where $s_i$ is the S-box input and $r_i$ is a random mask. All operations are performed on masked values, and the masks are removed at the end.

**Affine masking**: A more general form: $s'_i = a \cdot s_i + b \mod 2^n$ where $a$ (multiplicative mask) and $b$ (additive mask) are random.

**First-order masking**: At any point during the computation, only one mask is used. This protects against first-order DPA (correlation with a single intermediate value) but not second-order DPA (correlation with two intermediate values that combine to remove the mask).

**Higher-order masking**: Uses $d$ independent masks, protecting against $d$th-order DPA. The cost grows exponentially with $d$ (roughly $O(2^d)$ for AES).

**Rivain-Prouff masked AES**: The most widely deployed higher-order AES implementation. Uses $d$-order boolean masking with a secure S-box computation that transforms masked inputs to masked outputs without ever unmasking. Cost: $\sim 100 \cdot d^2$ field multiplications for the S-box.

### 9.4 Shuffling and Randomization

**Operation shuffling** randomizes the order of independent operations to decorrelate power traces. For example, in AES, the 16 S-box lookups in each round can be performed in random order:

```c
// Shuffled S-box computation
uint8_t perm[16] = {0, 1, 2, ..., 15};
shuffle(perm, 16);  // Random permutation
for (int i = 0; i < 16; i++) {
    state[perm[i]] = sbox[state[perm[i]]];
}
```

Shuffling increases the number of required DPA traces by a factor of $O(n!)$ for $n$ operations, making first-order DPA impractical for AES (16! $\approx 2^{44}$).

**Random delay insertion**: Add random delays between operations to decorrelate timing traces from the clock. This prevents an attacker from aligning power traces at specific time points. Each delay is drawn from a random distribution (e.g., uniform in $[0, \delta]$ cycles).

**Limitation**: Shuffling and random delays increase the number of traces needed for a successful attack but do not eliminate the side channel. They should be combined with masking for defense-in-depth.

### 9.5 Hardware Countermeasures

- **Constant-time hardware**: AES-NI instructions, SHA-NI extensions, and PCLMULQDQ for GCM perform all operations in constant time without data-dependent memory access.
- **Randomized cache replacement**: Intel's CAT (Cache Allocation Technology) and AMD's L3 cache partitioning can isolate cryptographic operations from other processes.
- **Cache eviction**: Flush the L3 cache before and after cryptographic operations to prevent cross-VM cache attacks.
- **Fenced execution**: Intel's `lfence` instruction prevents speculative execution past the fence, mitigating Spectre v1 (at a performance cost).
- **SGX enclaves**: Intel SGX provides isolated execution enclaves, but SGX itself is vulnerable to microarchitectural attacks (Foreshadow, CacheOut, ÆpicLeak).

---

## Cross-References

- **§01a** — Cryptographic fundamentals: AES implementation (table-based vs. AES-NI), HMAC constant-time comparison
- **§02a** — RSA/ECC attacks: timing attacks on RSA (Kocher 1996, Brumley-Boneh 2003), constant-time Montgomery ladder
- **§01b** — Symmetric attacks: padding oracle timing (Lucky13)
- **§03a** — TLS attacks: timing side channels in TLS implementations (Lucky13, ROBOT)
- **§04b** — Hardware attacks: EM probing, glitching, laser fault injection on smart cards and HSMs
- **§05b** — Crypto engineering: blinding, masking implementation strategies, constant-time coding practices
- **§06** — Case studies: Spectre/Meltdown discovery and mitigation, Intel SGX attacks
- **Chromium track** — V8's Spectre mitigations, site isolation architecture
- **Linux Kernel track** — KPTI, retpoline, `array_index_mask_nospec`, `safespec`

## References

1. Kocher, P., "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems," CRYPTO 1996. https://link.springer.com/chapter/10.1007/3-540-68697-5_6
2. Kocher, P., Jaffe, J., Jun, B., "Differential Power Analysis," CRYPTO 1999. https://link.springer.com/chapter/10.1007/3-540-48405-1_25
3. Brumley, D., Boneh, D., "Remote Timing Attacks Are Practical," USENIX Security 2003. https://www.usenix.org/conference/usenix-security-2003
4. Osvik, D.A., Shamir, A., Tromer, E., "Cache Attacks and Countermeasures: The Case of AES," CT-RSA 2006. https://eprint.iacr.org/2005/271
5. Yarom, Y., Falkner, K., "FLUSH+RELOAD: A High Resolution, Low Noise, L3 Cache Side-Channel Attack," USENIX Security 2014. https://www.usenix.org/node/184535
6. Liu, F., Yarom, Y., Ge, Q., Heiser, G., Lee, R.B., "Last-Level Cache Side-Channel Attacks Are Practical," IEEE S&P 2015. https://ieeexplore.ieee.org/document/7163050
7. Kocher, P., et al., "Spectre Attacks: Exploiting Speculative Execution," IEEE S&P 2019. CVE-2017-5753, CVE-2017-5715. https://spectreattack.com/
8. Lipp, M., et al., "Meltdown: Reading Kernel Memory from User Space," USENIX Security 2018. CVE-2017-5754. https://meltdownAttack.com/
9. Ge, Q., Yarom, Y., Cock, D., Heiser, G., "A Survey of Microarchitectural Timing Attacks and Countermeasures on Contemporary Hardware," Journal of Cryptographic Engineering, 2018. https://link.springer.com/article/10.1007/s13389-016-0154-1
10. Genkin, D., Shamir, A., Tromer, E., "RSA Key Extraction via Low-Bandwidth Acoustic Cryptanalysis," CRYPTO 2014. https://www.tau.ac.il/~tromer/
11. Genkin, D., Pipman, I., Tromer, E., "Get Your Hands Off My Laptop: Physical Side-Channel Key Extraction on PCs," CHES 2015. https://eprint.iacr.org/2014/448
12. Aciicmez, O., "Yet Another Microarchitectural Attack: Exploiting I-Cache," CHES 2007. https://eprint.iacr.org/2007/063
13. Percival, C., "Cache Missing for Fun and Profit," BSDCan 2005. https://www.daemonology.net/papers/bsdcan05.pdf
14. Ragab, H., et al., "Cross-Process Cache Attacks on Android," USENIX Security 2021. https://www.usenix.org/conference/usenixsecurity21/presentation/ragab
15. PACMAN: Attacking ARM Pointer Authentication with Speculative Execution," ISCA 2022. https://pacmanAttack.com/
16. ARM, "Cache Speculation Side-Channels: Security Guidance," ARMSecurity-036, 2018. https://developer.arm.com/support/security-consulting
17. Intel, "Preventing Side-Channel Attacks via Speculative Execution," Intel Security Advisory, 2018. https://www.intel.com/content/www/us/en/security-center/advisory.html
18. Brasser, F., et al., "Software-based Countermeasures Against Cache Attacks," IACR Cryptology ePrint Archive, 2017. https://eprint.iacr.org/2017/052
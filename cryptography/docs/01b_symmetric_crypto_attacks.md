# Symmetric Cryptography Attacks

> A systematic analysis of attacks against symmetric encryption: from ECB pattern leakage to padding oracles, from IV reuse catastrophes to meet-in-the-middle key recovery. Each attack is presented with mathematical formalization, practical exploitation steps, and real-world CVE references.

---

## Table of Contents

1. [ECB Mode Detection and Exploitation](#1-ecb-mode-detection-and-exploitation)
2. [CBC Bit-Flipping Attacks](#2-cbc-bit-flipping-attacks)
3. [Padding Oracle Attacks](#3-padding-oracle-attacks)
4. [IV Reuse Attacks in CTR and GCM Modes](#4-iv-reuse-attacks-in-ctr-and-gcm-modes)
5. [Birthday Attacks on Cipher Modes](#5-birthday-attacks-on-cipher-modes)
6. [Related-Key Attacks and Key Recovery](#6-related-key-attacks-and-key-recovery)
7. [Meet-in-the-Middle Attacks](#7-meet-in-the-middle-attacks)
8. [Slide Attacks](#8-slide-attacks)
9. [Brute Force Economics](#9-brute-force-economics)

---

## 1. ECB Mode Detection and Exploitation

### 1.1 Why ECB Fails: The Block Dictionary Attack

Electronic Codebook (ECB) mode encrypts each 16-byte block independently: $C_i = E_K(P_i)$. This creates a deterministic mapping from plaintext blocks to ciphertext blocks. Identical plaintext blocks map to identical ciphertext blocks, making ECB a ****codebook*** — a fixed substitution cipher at the block level.

**Detection via ECB penguin**: The canonical demonstration encrypts an image (Tux the Linux penguin) in ECB mode. Since each 16-byte pixel-block maps deterministically, regions of identical color (same 16-byte pixel sequence) produce identical ciphertext blocks, preserving the image's spatial structure. The ciphertext "penguin" is visually recognizable.

```python
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def detect_ecb(ciphertext, block_size=16):
    blocks = [ciphertext[i:i+block_size] 
              for i in range(0, len(ciphertext), block_size)]
    unique_blocks = len(set(blocks))
    total_blocks = len(blocks)
    ratio = unique_blocks / total_blocks if total_blocks > 0 else 1.0
    # ECB produces many duplicate blocks; other modes produce near-unique blocks
    return ratio < 0.95  # threshold depends on message structure
    
# More robust: chi-squared test on block frequency distribution
from collections import Counter
def ecb_chi_squared(ciphertext, block_size=16):
    blocks = [ciphertext[i:i+block_size] 
              for i in range(0, len(ciphertext), block_size)]
    freq = Counter(blocks)
    n = len(blocks)
    expected = n / (2 ** (8 * block_size))  # expected count per block value
    chi2 = sum((count - expected) ** 2 / max(expected, 1) 
               for count in freq.values())
    return chi2  # high chi2 indicates ECB (non-uniform distribution)
```

**ECB detection heuristic**: Given ciphertext $C = C_1 \| C_2 \| \cdots \| C_n$, compute the fraction of unique blocks. If more than ~10% of blocks are duplicates (for natural language plaintext), ECB mode is likely. For random data (compressed files, already-encrypted content), this heuristic is unreliable.

### 1.2 Block Rearrangement Attack

Since ECB encrypts each block independently, an attacker who can observe and manipulate ciphertext can reorder, delete, or replay blocks without detection:

```
Original plaintext:  P1 | P2 | P3 | P4 | P5 | P6
Ciphertext:          C1 | C2 | C3 | C4 | C5 | C6

Attacker reorders:   C3 | C1 | C6 | C4 | C2 | C5
Decrypted:           P3 | P1 | P6 | P4 | P2 | P5
```

**Real-world scenario**: An online banking application encrypts account transfer parameters in ECB mode:

```
Block 1: user_id=12345678
Block 2: account=00001111
Block 3: amount=00100000
Block 4: target_acct=22
```

An attacker who controls the ciphertext can rearrange blocks to change the amount, swap source and target accounts, or duplicate transfer blocks.

**Mitigation**: Use an AEAD mode (GCM, ChaCha20-Poly1305) that authenticates the ciphertext integrity and ordering. Block rearrangement is impossible when authentication detects tampering.

### 1.3 Chosen-Plaintext Attack on ECB

In a chosen-plaintext scenario, the attacker can submit arbitrary plaintexts for encryption and observe the corresponding ciphertexts. This enables **byte-at-a-time secret recovery**:

**Setup**: An oracle $O$ that prepends a secret prefix $S$, appends a secret suffix $T$, and encrypts with ECB:

$$O(P) = \text{ECB}_K(S \| P \| T)$$

**Attack procedure** (recovering $S$ byte-by-byte):

1. Submit $P$ such that $S \| P$ fills exactly one block, leaving $T$'s first byte in the next block. Record the second ciphertext block $C_{\text{target}}$.
2. For each candidate byte $b \in [0, 255]$, submit $P' \| b$ where $P'$ aligns the known blocks. Compute $C' = \text{ECB}_K(\text{known}_1 \| b \| \text{known}_2)$.
3. Find $b^*$ such that the block containing $b^*$ matches $C_{\text{target}}$.
4. Repeat, shifting alignment by one byte each iteration.

This recovers the secret one byte at a time, requiring at most $256 \times |S|$ oracle queries.

**Practical example**: Many web applications encrypt session tokens or API parameters using ECB. If the attacker can influence part of the plaintext (e.g., a username embedded before a role field), they can use the chosen-plaintext attack to recover or manipulate the encrypted data.

```python
def ecb_byte_at_a_time(oracle, block_size=16, unknown_length=None):
    """Recover unknown suffix appended by ECB oracle."""
    if unknown_length is None:
        # Determine unknown length by finding length change
        base_len = len(oracle(b''))
        for i in range(1, block_size + 1):
            if len(oracle(b'A' * i)) > base_len:
                unknown_length = base_len - (i - 1)
                break
    
    known = b''
    for i in range(unknown_length):
        # Pad to push next unknown byte to end of block
        padding_len = (block_size - 1 - (len(known) % block_size))
        padding = b'A' * padding_len
        target_block_idx = (len(padding) + len(known)) // block_size
        target = oracle(padding)
        target_block = target[target_block_idx * block_size:(target_block_idx + 1) * block_size]
        
        # Try all 256 possible bytes
        for b in range(256):
            test = padding + known + bytes([b])
            result = oracle(test)
            result_block = result[target_block_idx * block_size:(target_block_idx + 1) * block_size]
            if result_block == target_block:
                known += bytes([b])
                break
    return known
```

### 1.4 ECB Cut-and-Paste Attack

ECB's block-level determinism enables **cut-and-paste** attacks where an attacker assembles a desired ciphertext from blocks of known ciphertexts:

**Example**: Consider a user profile cookie encrypted in ECB mode:

```
email=user@example.com&uid=10&role=user
```

Alignment into 16-byte blocks:
```
Block 0: email=user@exam
Block 1: ple.com&uid=10&ro
Block 2: le=userPPPPPPPPP  (padded)
```

The attacker:
1. Creates an account with email `user@example.com` to get the ciphertext above.
2. Creates an account with email `AAAAAAAAAAAadminPPPPX@example.com`:

```
Block 0: email=AAAAAAAAAA
Block 1: AadminPPPPPPPPP   ← target block
Block 2: X@example.com&ui
Block 3: d=11&role=userPP  (padded)
```

3. Takes Block 1 from the second ciphertext (which encrypts `adminPPPPPPPPP`) and replaces the last block of the first ciphertext:

```
Block 0: email=user@exam    ← from original
Block 1: ple.com&uid=10&ro  ← from original
Block 2: AadminPPPPPPPPP    ← from crafted account
```

Result: `email=user@example.com&uid=10&role=admin` — privilege escalation via block substitution.

This attack works because ECB provides no integrity protection and no chaining between blocks.

---

## 2. CBC Bit-Flipping Attacks

### 2.1 Mechanics of CBC Bit-Flipping

In CBC mode, decryption computes:

$$P_i = D_K(C_i) \oplus C_{i-1}$$

The XOR dependency means that flipping bit $j$ in ciphertext block $C_{i-1}$ flips bit $j$ in the decrypted plaintext $P_i$. This is by design — it's the fundamental mechanism for error propagation. But it also means an attacker who can modify ciphertext can make **controlled, predictable changes** to the decrypted plaintext.

**Key insight**: The modification to $C_{i-1}$ also scrambles the decryption of block $C_{i-1}$ itself (since $P_{i-1} = D_K(C_{i-1}) \oplus C_{i-2}$, changing $C_{i-1}$ changes $D_K(C_{i-1})$ unpredictably). So the attacker sacrifices one block (which becomes garbage) to make controlled changes to the next block.

### 2.2 Targeted Bit-Flipping

**Setup**: An application decrypts a CBC ciphertext and parses the resulting plaintext as structured data (e.g., JSON, query parameters):

```
Ciphertext: IV | C0 | C1 | C2
Plaintext:  user=AAAAAAAA;role=user;padding=PP
```

The attacker wants to change `role=user` to `role=admin`.

**Step 1**: Identify which block contains the target string and which byte position. Suppose `role=user` spans bytes 8–16 of block $P_2$.

**Step 2**: Identify the preceding ciphertext block $C_1$ (which is XORed with $D_K(C_2)$ during decryption). Compute the desired flip:

$$C'_1[j] = C_1[j] \oplus P_2[j] \oplus P'_2[j]$$

where $P_2$ is the original plaintext byte at position $j$, and $P'_2$ is the desired byte. Since XOR is its own inverse:

$$D_K(C_2) \oplus C'_1 = D_K(C_2) \oplus (C_1 \oplus P_2 \oplus P'_2) = P_2 \oplus P_2 \oplus P'_2 = P'_2$$

```python
def cbc_bitflip(ciphertext, block_size, target_block_idx, 
                 original_bytes, desired_bytes):
    """Flip bits in target_block by modifying the preceding ciphertext block."""
    prev_block_start = (target_block_idx - 1) * block_size
    result = bytearray(ciphertext)
    
    for i, (orig_byte, des_byte) in enumerate(zip(original_bytes, desired_bytes)):
        offset = prev_block_start + i
        result[offset] = ciphertext[offset] ^ orig_byte ^ des_byte
    
    return bytes(result)

# Example: Change "user" to "admin" in block 2
# Known: block 1 of plaintext is "role=user\x00\x00\x00\x00\x00\x00\x00\x00" (padded)
iv = os.urandom(16)
key = os.urandom(32)
plaintext = b'userid=10;role=user'
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
# Need to pad to block boundary first
from cryptography.hazmat.primitives.padding import PKCS7
padder = PKCS7(128).padder()
padded = padder.update(plaintext) + padder.finalize()
ct = encryptor.update(padded) + encryptor.finalize()

# Now flip: target is "user" -> "admin" in the second plaintext block
# We need to flip the preceding ciphertext block (or IV for block 0)
flipped = cbc_bitflip(ct, 16, 1, b'user', b'admin')
```

### 2.3 Real-World CBC Bit-Flipping Exploits

**ASP.NET ViewState (CVE-2010-3332)**: ASP.NET used CBC-encrypted ViewState parameters. Attackers could flip bits in the ViewState to escalate privileges — changing `role=0` (user) to `role=1` (admin). The "garbage block" from the preceding ciphertext was often ignored by the parser or placed in a non-critical field.

**Encrypted session tokens**: Many web frameworks (pre-2014 Rails, Django, PHP) encrypted session cookies with AES-CBC without authentication. Bit-flipping allowed modifying user IDs, privilege levels, or CSRF tokens.

**Mitigation**: AEAD modes (GCM, ChaCha20-Poly1305) include an authentication tag that detects any ciphertext modification. **Never use CBC without a separate MAC** (and never use MAC-then-Encrypt composition — use Encrypt-then-MAC or, better, an AEAD mode).

---

## 3. Padding Oracle Attacks

### 3.1 PKCS#7 Padding and the Oracle

PKCS#7 padding for a block cipher of size $b$ fills the last $p$ bytes ($1 \leq p \leq b$) with the value $p$:

```
If plaintext length is a multiple of b: append a full block of b bytes, each set to b.
Otherwise: append p bytes of value p.
```

A **padding oracle** is any system that, given a ciphertext, reveals whether the decrypted plaintext has valid PKCS#7 padding. This can be an explicit error message ("Invalid padding"), a timing difference, or even a behavioral difference (one code path for valid padding, another for invalid).

### 3.2 Vaudenay's Padding Oracle Attack (2002)

Vaudenay demonstrated that a padding oracle completely breaks CBC confidentiality. Given ciphertext $C = IV \| C_0 \| C_1 \| \cdots \| C_n$, the attacker decrypts any block $C_i$ using only the padding oracle and $C_{i-1}$ (the preceding ciphertext block).

**Decryption of one byte**:

To decrypt byte $j$ (from the right, 0-indexed) of block $P_i[15-j]$, the attacker:

1. Constructs a modified preceding block $C'_{i-1}$ where:
   - Bytes at positions $> j$ are set so that $P'_i[k] = j+1$ (valid padding for the already-known suffix).
   - Byte at position $j$ is set to candidate value $v$.
   - Bytes at positions $< j$ can be arbitrary (they don't affect padding validity at position $j$).

2. Submits $C'_{i-1} \| C_i$ to the oracle.

3. If the oracle reports valid padding, then $\text{last}(j+1)$ bytes of $P'_i$ form valid padding of value $j+1$, meaning:
$$P_i[15-j] = v \oplus C'_{i-1}[15-j] \oplus C_{i-1}[15-j]$$

Wait, let me be more precise. Let's use the correct formulation.

The attacker wants to find $P_i[15]$ (the last byte of block $i$). They construct $C'_{i-1}$ as:

$$C'_{i-1}[k] = \begin{cases} C_{i-1}[k] & \text{if } k \neq 15 \\ C_{i-1}[15] \oplus P_i[15] \oplus 0x01 & \text{(unknown, testing)} \end{cases}$$

Actually, the correct approach is:

1. Set all bytes of $C'_{i-1}$ to arbitrary values except the last byte.
2. Vary $C'_{i-1}[15]$ through all 256 values.
3. For each value $v$, submit $(C'_{i-1} \| C_i)$ to the oracle, where $C'_{i-1}[15] = v$.
4. When the oracle reports valid padding, we know $D_K(C_i)[15] \oplus v = 0x01$ (valid single-byte padding).
5. Therefore $D_K(C_i)[15] = v \oplus 0x01$, and $P_i[15] = D_K(C_i)[15] \oplus C_{i-1}[15]$.

After finding $P_i[15]$, the attacker sets $C'_{i-1}[15]$ so that $P'_i[15] = 0x02$, then varies $C'_{i-1}[14]$ until the oracle reports valid padding (indicating the last two bytes decrypt to $0x02, 0x02$). This reveals $P_i[14]$. The process repeats for all 16 bytes.

**Complexity**: Each byte requires at most 256 oracle queries, so decrypting a 16-byte block requires at most $16 \times 256 = 4096$ queries. On average, it's $16 \times 128 = 2048$ queries per block. A 1 KB message requires $\sim131,072$ queries — trivially achievable over a network in seconds.

### 3.3 Full Attack Implementation

```python
def padding_oracle_decrypt(oracle, ciphertext, block_size=16):
    """Decrypt AES-CBC ciphertext using a padding oracle."""
    assert len(ciphertext) % block_size == 0
    blocks = [ciphertext[i:i+block_size] 
              for i in range(0, len(ciphertext), block_size)]
    
    plaintext = b''
    
    for block_idx in range(1, len(blocks)):
        prev_block = bytearray(blocks[block_idx - 1])
        target_block = blocks[block_idx]
        intermediate = bytearray(block_size)  # D_K(target_block)
        
        # Decrypt byte by byte, from last to first
        for byte_pos in range(block_size - 1, -1, -1):
            padding_value = block_size - byte_pos  # target padding byte
            
            # Set already-known suffix bytes to produce valid padding
            crafted = bytearray(prev_block)
            for k in range(byte_pos + 1, block_size):
                crafted[k] = intermediate[k] ^ padding_value
            
            # Try all 256 values for the target byte
            found = False
            for guess in range(256):
                crafted[byte_pos] = guess
                if oracle(bytes(crafted) + target_block):
                    # Verify it's not a false positive (for byte_pos == block_size-1)
                    if byte_pos == block_size - 1:
                        # Flip second-to-last byte to check it's really 0x01
                        verify = bytearray(crafted)
                        verify[byte_pos - 1] ^= 0x01
                        if not oracle(bytes(verify) + target_block):
                            continue  # false positive
                    
                    intermediate[byte_pos] = guess ^ padding_value
                    found = True
                    break
            
            if not found:
                raise ValueError(f"Oracle failed at byte position {byte_pos}")
        
        # Recover plaintext: P = intermediate XOR original prev_block
        for i in range(block_size):
            plaintext += bytes([intermediate[i] ^ prev_block[i]])
    
    # Remove PKCS#7 padding
    pad_len = plaintext[-1]
    if pad_len > block_size or plaintext[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding in decrypted text")
    return plaintext[:-pad_len]
```

### 3.4 POODLE Variant (SSLv3 CBC Padding)

**CVE-2014-3566 — POODLE** (Padding Oracle On Downgraded Legacy Encryption):

SSLv3's CBC padding validation was fatally flawed: the padding structure was:

$$\text{padding} = \underbrace{0x00 \| \cdots \| 0x00}_{\text{padding\_length}-1 \text{ zeros}} \| \text{padding\_length}$$

where `padding_length` is 1 byte indicating the padding length (1–256). Crucially, only the last byte of padding was validated — the rest were **not checked** by SSLv3 implementations. An attacker who could control the plaintext and downgrade the connection to SSLv3 could:

1. Force a downgrade from TLS 1.0+ to SSLv3 (many servers supported SSLv3 for compatibility).
2. Use the CBC bit-flip attack to align the target secret byte (e.g., a session cookie) at the position corresponding to the last byte of a block.
3. Flip the padding length byte to 0x01 (valid single-byte padding).
4. If the server accepts, the target byte XORed with the known flip value equals the decrypted byte.

Since only 1 in 256 connections has valid padding by chance, the average number of requests per byte is 256. For a 16-byte cookie, this requires ~4,096 connections — achievable in hours on a JavaScript-based attack via same-origin policy circumvention.

**Mitigation**: Disable SSLv3 entirely. Modern browsers and servers no longer support SSLv3 (TLS 1.0 minimum, with TLS 1.2+ preferred).

### 3.5 The Last Byte Problem and CBC-R

A subtle issue in padding oracle attacks is **false positives** when decrypting the last byte. When testing value $v$ for $C'_{i-1}[15]$, the oracle returns valid padding not only when the last byte decrypts to $\mathtt{0x01}$, but also when it decrypts to $\mathtt{0x02}$ and the second-to-last byte also decrypts to $\mathtt{0x02}$, or $\mathtt{0x03}$ with the two preceding bytes also $\mathtt{0x03}$, etc.

To disambiguate: flip $C'_{i-1}[14]$ and resubmit. If the oracle still reports valid padding, the last byte was indeed $\mathtt{0x01}$. If not, it was a false positive and the attacker must continue testing.

**CBC-R (CBC-Reverse)**: The padding oracle also enables **encryption** of arbitrary plaintext. Given a padding oracle and a target ciphertext $C$, the attacker can construct a valid ciphertext for any chosen plaintext $P$:

1. Start from the last block. Choose $C_{n-1}$ such that $D_K(C_n) \oplus C_{n-1} = P_n$.
2. This requires knowing $D_K(C_n)$, which is obtained via the padding oracle.
3. Then $C_n$ becomes the "ciphertext" for the next iteration, and the process continues backward.

This is devastating: not only can the attacker decrypt any message, but they can also **encrypt** arbitrary messages without knowing the key.

---

## 4. IV Reuse Attacks in CTR and GCM Modes

### 4.1 CTR Mode Nonce Reuse

Counter mode computes keystream blocks $K_i = E_K(\text{nonce} \| i)$ and ciphertext $C_i = P_i \oplus K_i$. If two messages $M_1, M_2$ are encrypted with the same nonce:

$$C_1 = M_1 \oplus K, \quad C_2 = M_2 \oplus K$$
$$C_1 \oplus C_2 = M_1 \oplus M_2$$

The XOR of ciphertexts equals the XOR of plaintexts. This immediately enables:

1. **Known-plaintext recovery**: If any part of $M_1$ is known (e.g., a protocol header), XOR with $C_1 \oplus C_2$ reveals the corresponding part of $M_2$:

$$M_2[j] = M_1[j] \oplus C_1[j] \oplus C_2[j]$$

2. **Crib dragging**: With no known plaintext, an attacker guesses likely substrings (common words, file headers, protocol fields) and XORs them with $C_1 \oplus C_2$. If the guess is correct, the corresponding position in $M_2$ produces readable text.

```python
def CTR_nonce_reuse_attack(c1, c2, known_plaintext):
    """Recover M2 given C1, C2, and known M1 partial content."""
    keystream_fragment = bytes(a ^ b for a, b in 
                               zip(known_plaintext, c1[:len(known_plaintext)]))
    m2_fragment = bytes(k ^ c for k, c in 
                        zip(keystream_fragment, c2[:len(known_plaintext)]))
    return m2_fragment

def crib_drag(c1, c2, crib):
    """Try all positions for a crib (known plaintext fragment) against C1 XOR C2."""
    xored = bytes(a ^ b for a, b in zip(c1, c2))
    results = []
    for offset in range(len(xored) - len(crib) + 1):
        candidate = bytes(x ^ ord(c) for x, c in 
                          zip(xored[offset:offset+len(crib)], crib.encode()))
        if all(32 <= b < 127 for b in candidate):  # printable ASCII
            results.append((offset, candidate))
    return results
```

**Real-world incidences**:
- **PS4 4.55 kernel exploit**: The PS4 kernel used AES-CTR with a hardcoded IV for encrypting kernel memory. Developers exploited the keystream reuse to decrypt kernel memory and develop a full jailbreak.
- **802.11 WEP**: While not CTR mode, the RC4 key reuse in WEP had the same XOR property, enabling the FMS/KoreK attacks (see Network Security track).
- **Microsoft PST encryption**: Outlook PST files used a static key and static nonce for CTR-mode encryption, enabling recovery of email contents.

### 4.2 GCM Nonce Reuse and Authentication Key Recovery

AES-GCM uses a nonce-based encryption where the authentication key is $H = E_K(0^{128})$. If two messages are encrypted with the same nonce:

$$T_1 = S_1 \oplus E_K(J_0), \quad T_2 = S_2 \oplus E_K(J_0)$$

where $S_i = \text{GHASH}_H(C_i, A_i)$ is the GHASH of the ciphertext and associated data.

**Key recovery**: $T_1 \oplus T_2 = S_1 \oplus S_2$, which eliminates $E_K(J_0)$ entirely. The attacker knows the ciphertexts and can compute $S_1 \oplus S_2 = \text{GHASH}_H(C_1, A_i) \oplus \text{GHASH}_H(C_2, A_2)$.

For messages of the same length with no associated data (simplified):

$$T_1 \oplus T_2 = \text{GHASH}_H(C_1) \oplus \text{GHASH}_H(C_2) = (C_1 \oplus C_2) \cdot H^m$$

The attacker can solve for $H$ in $\mathbb{F}_{2^{128}}$ using polynomial arithmetic over the Galois field.

**Forgery attack**: Once $H$ is known, the attacker can forge tags for arbitrary messages:

$$T_{\text{forgery}} = \text{GHASH}_H(C_{\text{forgery}}, A) \oplus E_K(J_0)$$

$E_K(J_0)$ can be recovered from any valid ciphertext-tag pair: $E_K(J_0) = T_{\text{valid}} \oplus S_{\text{valid}}$.

**Concrete impact**: A single nonce reuse with AES-GCM completely destroys both confidentiality and integrity. The attacker can:
1. Recover the GHASH authentication key $H$.
2. Compute $E_K(J_0)$ from any valid (ciphertext, tag) pair.
3. Forge tags for any message, bypassing authentication entirely.
4. Decrypt any message encrypted with that nonce using crib dragging.

```python
def gcm_forge_tag(H, E_J0, ciphertext, aad):
    """Forge a GCM tag given leaked H and E_K(J0)."""
    # Compute GHASH over AAD and ciphertext
    # This requires multiplication in GF(2^128)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    # Simplified: in practice, implement GHASH over GF(2^128)
    # S = GHASH_H(A, C, len(A), len(C))
    # T = S XOR E_K(J0)
    S = ghash(H, aad, ciphertext)
    tag = bytes(a ^ b for a, b in zip(S, E_J0))
    return tag
```

**GCM nonce reuse in practice**: The most notorious case was the **Slobs/Streamlabs OBS** incident where a static IV was used for AES-GCM, enabling trivial forgery and decryption. In protocol design, the IETF RFC 9006 (TLS 1.3) mandates that connections must never reuse a nonce and must enforce nonce uniqueness at the protocol level.

### 4.3 Counter Collision in CTR Mode

Even without exact nonce reuse, CTR mode is vulnerable if counter values collide. For a $b$-bit counter, the birthday bound gives a 50% collision probability after approximately $2^{b/2}$ blocks. For AES-CTR with a 32-bit counter (as in some implementations), this is $2^{16} = 65,536$ blocks — only 1 MB of data. For a 96-bit nonce + 32-bit counter split, encrypting more than $2^{32}$ blocks ($2^{36}$ bytes = 64 GB) with the same key creates a collision probability of ~0.5.

NIST SP 800-38A limits the total number of blocks encrypted under a single key to $2^{61}$ for CTR mode, but practical implementations often impose tighter limits (TLS limits the record sequence number to $2^{64}-1$).

---

## 5. Birthday Attacks on Cipher Modes

### 5.1 The Birthday Paradox and Cryptography

The birthday paradox states that in a set of $n$ randomly chosen elements from a universe of size $N$, the probability of a collision exceeds 50% when $n \approx \sqrt{2N \ln 2} \approx 1.177\sqrt{N}$.

In cryptography, this means:
- A 64-bit block cipher (DES, 3DES, Blowfish) has collision probability 50% after $\approx 2^{32}$ blocks.
- A 128-bit hash has collision probability 50% after $\approx 2^{64}$ evaluations.
- AES (128-bit block) has collision probability 50% after $\approx 2^{64}$ blocks — but this requires encrypting $2^{64} \times 16 = 256$ exabytes, which is beyond practical reach.

### 5.2 Sweet32: Birthday Attack on 64-bit Block Ciphers

**CVE-2016-2183 — Sweet32**: Karthikeyan Bhargavan and Gaëtan Leurent demonstrated that 64-bit block ciphers (3DES, Blowfish) in CBC or CTR mode become vulnerable after encrypting approximately $2^{32}$ blocks.

For CBC mode, the attacker needs to capture $2^{32}$ ciphertext blocks (about 32 GB of data). Colliding ciphertext blocks reveal:

$$C_i = C_j \implies P_i \oplus C_{i-1} = P_j \oplus C_{j-1}$$
$$P_i \oplus P_j = C_{i-1} \oplus C_{j-1}$$

Since the attacker knows $C_{i-1}$ and $C_{j-1}$ (they're part of the ciphertext), they learn $P_i \oplus P_j$, which enables plaintext recovery via statistical analysis (especially for structured data like HTTP with known headers).

For a long-lived TLS connection (e.g., a VPN), 32 GB is realistic: a 1 Gbps connection generates 32 GB in ~4.5 minutes.

**OpenSSL mitigation**: Since version 1.1.0, OpenSSL limits the amount of data encrypted under a single 64-bit cipher key to $2^{20}$ blocks (16 MB), then triggers a key renegotiation.

**Recommendation**: Disable all 64-bit block ciphers (3DES, Blowfish, RC4). Use AES-128 or AES-256 with 128-bit blocks, where the birthday bound is $2^{64}$ blocks ($2^{68}$ bytes = 256 exabytes).

### 5.3 Birthday Attacks on CBC with Fixed IV

If CBC uses a fixed IV (e.g., all-zeros) instead of a random one, the first block of every message encrypted under the same key uses the same "IV." The birthday paradox tells us that after approximately $2^{n/2}$ messages (where $n$ is the block size in bits), two messages will have $C_0 = C'_0$ (identical first ciphertext blocks), revealing $P_0 \oplus P'_0 = \text{IV} \oplus \text{IV} = 0$ — i.e., $P_0 = P'_0$, leaking the first block of plaintext equality.

This is why CBC requires a **random, unpredictable IV** for each message — not a fixed IV, and not a counter (which is predictable, enabling BEAST — see §03a).

---

## 6. Related-Key Attacks and Key Recovery

### 6.1 Related-Key Attack Model

In the **related-key attack** model, the attacker can request encryptions under keys $K'$ that are related to the target key $K$ by a known relationship $\phi$: $K' = \phi(K)$. This model was initially considered artificial but has practical relevance in protocols that derive keys from a master key using simple operations (hash, increment).

**Formal definition**: An $(\ell, t, \epsilon)$ related-key attack against cipher $E$ uses $\ell$ related-key queries in time $t$ and distinguishes $E_K$ from a random permutation with advantage $\epsilon$, where keys are related by functions from a set $\Phi$.

### 6.2 AES Related-Key Attacks

Biryukov, Khovratovich, and others demonstrated related-key attacks on AES:

- **AES-256** (full 14 rounds): Related-key boomerang attack with complexity $2^{99.5}$ (Biryukov, Khovratovich 2009). This is below the brute-force $2^{256}$ but requires the attacker to control key relationships — an unrealistic scenario for most applications.
- **AES-192** (full 12 rounds): Related-key attack with complexity $2^{176}$ (ibid.).
- **AES-128** (full 10 rounds): No related-key attack better than brute force is known.

These attacks are theoretically significant but pose no practical threat because:
1. They require the attacker to request encryptions under related keys, which no real protocol allows.
2. Even the best attack on AES-256 ($2^{99.5}$) is completely infeasible.

However, related-key attacks are relevant to hash functions built on block ciphers. For example, the SHA-2 compression function could be modeled as a block cipher in Davies-Meyer mode, and related-key attacks on the underlying cipher could translate into collisions or preimages for the hash.

### 6.3 Key Recovery from Nonce Reuse

In protocols that derive session keys from a master key and a nonce (e.g., 802.11 WEP), nonce reuse enables key recovery:

**WEP RC4 key recovery**: The Fluhrer, Mantin, and Shamir (FMS) attack exploits the RC4 key scheduling algorithm (KSA) when the IV is prepended to the key. For weak IVs (of the form $(a, 255, b)$), the first byte of the keystream biases toward the key byte. Collecting $\sim 4$ million encrypted frames with weak IVs enables full 104-bit key recovery.

### 6.4 Slide Attacks

Slide attacks (Biryukov, Wagner 1999) exploit the self-similarity of block cipher rounds when all rounds use the same subkey (i.e., the cipher is a repeated application of the same round function $F$).

**Mechanism**: If cipher $E_K$ encrypts as $E_K(P) = F_K^r(P)$ (r rounds of $F_K$), then for any plaintext $P$, the pair $(P, F_K(P))$ is a "slid pair." Two plaintexts $P, P'$ with $P' = F_K(P)$ produce ciphertexts $C, C'$ where $C = F_K^{r-1}(P')$ and $C' = F_K^r(P')$, giving $C' = F_K(C)$.

The attacker queries the encryption oracle for many plaintexts, looking for pairs $(P, P')$ where $P' = F_K(P)$ (they don't know $F_K$, but can check pairs by verifying that the round function relationship holds between $C$ and $C'$). For a Feistel cipher with round function $F$, this check is:

$$C_L = C'_R \oplus f(C'_L, K), \quad C'_L = C_R \oplus f(C_L, K)$$

This yields the key $K$ directly for each valid slid pair.

**Slide attacks on modified DES**: If all 16 DES rounds use the same subkey $K$ (instead of 16 different derived subkeys), a slide attack recovers the key with $2^{32}$ known plaintexts and $2^{32}$ work — far below the $2^{56}$ brute-force complexity. This demonstrates why key schedule expansion is a critical part of block cipher design.

**Byte-wise slide attacks** (Biryukov, Wagner 2000) extend the technique to ciphers with slightly different round keys, as long as the key schedule has a short cycle.

---

## 7. Meet-in-the-Middle Attacks

### 7.1 The Principle

The meet-in-the-middle (MITM) attack applies to **composition ciphers** — encryption schemes that apply multiple independent keys in sequence. The attacker exploits the fact that the middle value can be computed from both directions, reducing the search space.

Given double encryption $C = E_{K_2}(E_{K_1}(P))$:

- **Forward direction**: For each candidate $K_1' \in \{0,1\}^k$, compute $M_{K_1'} = E_{K_1'}(P)$.
- **Backward direction**: For each candidate $K_2' \in \{0,1\}^k$, compute $M_{K_2'} = D_{K_2'}(C)$.
- **Match**: Find $K_1', K_2'$ such that $M_{K_1'} = M_{K_2'}$.

Total work: $2^{k+1}$ (two exhaustive searches) instead of $2^{2k}$ (exhaustive search of the combined key space). The space requirement is $2^k$ (to store the forward computation table).

**Double DES**: $k = 56$, so double DES provides only $2^{57}$ security instead of the intended $2^{112}$. This is exactly the attack that drove the adoption of Triple DES.

### 7.2 Triple DES (3DES)

Triple DES applies DES three times with two or three independent keys:

- **3DES with two keys (EDE2)**: $C = E_{K_1}(D_{K_2}(E_{K_1}(P)))$ — 112-bit security (meet-in-the-middle still gives $2^{112}$, not $2^{168}$, when using three keys — but with two keys, brute force is $2^{112}$, meeting the design goal).
- **3DES with three keys (EDE3)**: $C = E_{K_3}(D_{K_2}(E_{K_1}(P)))$ — 168-bit key space, but meet-in-the-middle reduces effective security to $2^{112}$.

The middle decryption ($D_{K_2}$) is not a design error — it provides backward compatibility with single DES: if $K_1 = K_2 = K_3$, then $E_K(D_K(E_K(P))) = E_K(E_K(P)) = D_K(P) \cdot E_K(P)$... actually, with all three keys equal, $C = E_K(D_K(E_K(P))) = E_K(P)$, which is single DES.

**Deprecated status**: NIST deprecated 3DES in 2023 (SP 800-131A Rev. 2). As noted in §5, the 64-bit block size makes it vulnerable to Sweet32 birthday attacks. The maximum number of blocks under a single key is limited to $2^{20}$ (16 MB) by SP 800-38A.

### 7.3 Advanced MITM Techniques

**Splice-and-cut MITM**: Bogdanov and Shibutani extended MITM to single-key ciphers by splitting the cipher at an intermediate round and matching in the middle. For AES-128, this gives a $2^{126}$ attack (better than brute force but still infeasible).

**All-subkeys recovery (ASK)**: Isobe and Shibutani developed techniques that recover all round subkeys independently, then reconstruct the master key. This approach has been applied to reduced-round AES and other block ciphers.

**MITM on hash functions**: The MITM approach also applies to preimage attacks on hash functions. For an $n$-bit hash with $r$ rounds, if the attacker can split the computation at round $r/2$ and compute forward from the IV and backward from the target hash, they find a preimage in $2^{n/2+1}$ time instead of $2^n$.

---

## 8. Slide Attacks

### 8.1 Basic Slide Attack

The slide attack exploits ciphers where the same subkey is used in every round. If $E_K = \rho_K^r$ (r rounds of the same permutation $\rho_K$), then for any two plaintexts $P, P'$:

$(P, P')$ is a **slid pair** if $P' = \rho_K(P)$

For a slid pair, the corresponding ciphertexts satisfy $C' = \rho_K(C)$, which means the attacker obtains two input-output pairs for the round function $\rho_K$:

$$P \xrightarrow{\rho_K} P' \xrightarrow{\rho_K^{r-1}} C'$$
$$P \xrightarrow{\rho_K^{r-1}} C \xrightarrow{\rho_K} C'$$

Checking the slid pair condition: $C' = \rho_K(C)$, which depends on the unknown key $K$. The attacker can verify a candidate key $K^*$ by checking if $\rho_{K^*}(P) = P'$ AND $\rho_{K^*}(C) = C'$.

**Attack complexity**: The attacker needs approximately $2^{n/2}$ known plaintext-ciphertext pairs to find a slid pair (birthday paradox), and verifying each candidate takes constant time. The total attack complexity is $2^{n/2+1}$, where $n$ is the block size — far below $2^k$ (key space) for typical key sizes.

### 8.2 Slide Attacks with Different Round Keys

The slide attack can be generalized to ciphers with periodic key schedules. If the key schedule has period $p$ (i.e., $K_i = K_{i \mod p}$), the attacker can construct a "slid set" of $p$ plaintext-ciphertext pairs that, when shifted by the period, form a valid attack.

**Example**: A cipher with 20 rounds where the key schedule alternates between two subkeys $K_A, K_B$ (period 2) is vulnerable to a slide attack with $2^{n/2}$ chosen plaintexts.

**Defense**: Ensure the key schedule generates distinct, non-periodic subkeys. AES's key schedule expands the 128/192/256-bit key into 11/13/15 round keys using a non-periodic recurrence, making slide attacks infeasible.

### 8.3 Complementation Slide Attack

For Feistel ciphers with a key complementation property, the slide attack can be combined with the complementation property to reduce complexity further. DES has a well-known complementation property: if all bits of the key are complemented, the ciphertext is the complement of the original ciphertext. This property halves the effective key space for brute-force attacks ($2^{55}$ instead of $2^{56}$) and interacts with slide attacks in interesting ways for reduced-round variants.

---

## 9. Brute Force Economics

### 9.1 Key Space vs. Attack Cost

Brute force is the baseline attack: enumerate all possible keys and test each against known plaintext-ciphertext pairs. The cost is proportional to the key space $2^k$:

| Key Size | Key Space | Time (1 attempt/ns) | Time (1M attempts/ns, GPU) | Time (10B attempts/ns, ASIC) |
|---|---|---|---|---|
| 56 (DES) | $2^{56}$ | 2.3 years | 12.6 hours | 76 seconds |
| 80 | $2^{80}$ | 38,000 years | 38 years | 2.7 days |
| 112 | $2^{112}$ | $1.07 \times 10^{19}$ years | $1.07 \times 10^{13}$ years | $1.07 \times 10^{9}$ years |
| 128 (AES-128) | $2^{128}$ | $1.08 \times 10^{22}$ years | $1.08 \times 10^{16}$ years | $1.08 \times 10^{12}$ years |
| 192 | $2^{192}$ | Infeasible | Infeasible | Infeasible |
| 256 (AES-256) | $2^{256}$ | Infeasible | Infeasible | Infeasible |

"Infeasible" means the energy required to perform the computation exceeds the energy available in the observable universe (Landauer's limit sets a minimum energy of $kT \ln 2 \approx 2.9 \times 10^{-21}$ J per bit operation at room temperature; $2^{256}$ operations require $\sim 10^{56}$ J, far exceeding the Earth's total energy output).

### 9.2 Bitcoin Hashrate as a Benchmark

Bitcoin's proof-of-work provides a real-world benchmark for brute-force computation at scale:

| Period | Bitcoin Network Hashrate | Daily Energy Cost |
|---|---|---|
| 2015 | ~400 PH/s ($4 \times 10^{17}$ H/s) | ~$400K/day |
| 2020 | ~120 EH/s ($1.2 \times 10^{20}$ H/s) | ~$12M/day |
| 2024 | ~600 EH/s ($6 \times 10^{20}$ H/s) | ~$60M/day |
| 2025 | ~1 ZH/s ($10^{21}$ H/s) projected | ~$100M/day |

If the Bitcoin network were repurposed to brute-force AES-128 keys (at the same hashrate, assuming 1 SHA-256 hash ≈ 1 AES encryption):

$$2^{128} \text{ keys} / 10^{21} \text{ keys/s} = 3.4 \times 10^{16} \text{ seconds} \approx 10^{9} \text{ years}$$

Even the entire Bitcoin mining network would take a billion years to brute-force AES-128. AES-256 requires $2^{128} \approx 10^{38}$ times more work — literally beyond the physical limits of computation.

### 9.3 Specialized Cracking Hardware

**FPGA-based crackers**: Deep Crack (EFF, 1998) cost $250,000 and brute-forced DES in 22 hours. Modern FPGAs (Xilinx VU9P) can test ~$10^9$ DES keys/s per chip at ~$5K, yielding a DES cracking cost of ~$50/hour.

**GPU-based crackers**: An NVIDIA RTX 4090 achieves:
- Hashcat benchmark: ~$2.5 \times 10^{10}$ MD5/s, $\sim 1.8 \times 10^{9}$ SHA-256/s, $\sim 3.5 \times 10^{6}$ bcrypt (cost=12)/s
- For AES-128 brute force: the GPU cannot parallelize multiple key schedules efficiently; achievable rate is ~$10^8$ key tests/s per GPU, giving $2^{128} / 10^8 \approx 10^{30}$ years.

**ASIC-based crackers**: Custom ASICs achieve higher throughput at lower cost per hash:
- Antminer S21: ~$10^{14}$ SHA-256/s at ~$3K, ~17.5 J/TH
- Extrapolated to AES: ~$10^{13}$ AES-128 key tests/s per chip
- Cost for AES-128 brute force: $2^{128} / 10^{13}$ s per chip $\times$ $3K/chip$ — still $\sim 10^{20}$ years

**Conclusion**: AES-128 provides adequate security against brute force for the next several decades. AES-256 provides security beyond any conceivable classical computing capability. The threat to current symmetric cryptography comes not from improved brute force but from quantum computing (Grover's algorithm reduces AES-256 to 128-bit security — see §05a).

### 9.4 Key Length Recommendations

| Security Level | Application | Symmetric Key | RSA Modulus | ECC Curve | Hash |
|---|---|---|---|---|---|
| Legacy (do not use) | N/A | 80 bits (SKIPJACK) | 1024 bits | 160 bits | SHA-1 |
| Minimum | Short-term protection | 112 bits (3KDES) | 2048 bits | P-224 | SHA-224 |
| Standard | General use (2024) | 128 bits (AES-128) | 3072 bits | P-256/X25519 | SHA-256 |
| High | Long-term / government | 192 bits (AES-192) | 7680 bits | P-384 | SHA-384 |
| Ultra | Post-quantum / max | 256 bits (AES-256) | 15360 bits | P-521/X448 | SHA-512 |

**NIST SP 800-57 Part 1 Rev. 5** recommends minimum 128-bit security for new systems (published 2020). Keys below 112 bits should no longer be used for any purpose.

---

## Cross-References

- **§01a** — Cryptographic fundamentals: the block cipher modes, hash functions, and AEAD constructions attacked here
- **§02a** — RSA/ECC attacks on asymmetric primitives
- **§03a** — TLS protocol attacks: BEAST (CBC IV prediction), POODLE (SSLv3 CBC padding), Lucky13 (CBC padding timing), Sweet32 (64-bit birthday)
- **§03b** — PKI/certificate attacks
- **§04a** — Side-channel attacks that recover symmetric keys from timing, cache, and power analysis
- **§04b** — Hardware attacks: fault injection on AES, glitching to bypass key checks
- **§05a** — Post-quantum cryptography: Grover's algorithm halves effective symmetric key length
- **§06** — Case studies: the Debian OpenSSL fiasco (broken CSPRNG → predictable keys), WEP key recovery

## References

1. Vaudenay, S., "Security Flaws Induced by CBC Padding — Applications to SSL, IPSEC, WTLS," EUROCRYPT 2002. https://link.springer.com/chapter/10.1007/3-540-46035-7_4
2. Bardou, R., Focardi, R., Kawahara, Y., Lanet, J.-L., Simionato, L., "Efficient Padding Oracle Attacks on Cryptographic Hardware," CRYPTO 2012. https://eprint.iacr.org/2012/411
3. Bhargavan, K., Leurent, G., "On the Practical (In-)Security of 64-bit Block Ciphers — Collision Attacks on Sweet32," CCS 2016. CVE-2016-2183. https://sweet32.info/
4. Duong, T., Rizzo, J., "BEAST: A Practical Attack Against SSL/TLS," 2011. CVE-2011-3389. https://www.beastAttack.com/
5. Möglen, H., Kocher, P., "SSL 3.0 Protocol — CBC Mode Vulnerability," 2011.
6. AlFardan, N., Paterson, K.G., "Lucky Thirteen: Breaking the TLS and DTLS Protocols," IEEE S&P 2013. CVE-2013-0169. https://www.ieee-security.org/TC/SP2013/
7. Meyer, C., Schwenk, J., "Lessons Learned From Previous SSL/TLS Attacks," IACR Cryptology ePrint Archive, 2013. https://eprint.iacr.org/2013/049
8. Biryukov, A., Khovratovich, D., "Related-Key Cryptanalysis of the Full AES-192 and AES-256," ASIACRYPT 2009. https://eprint.iacr.org/2009/317
9. Biryukov, A., Wagner, D., "Slide Attacks," EUROCRYPT 1999. https://link.springer.com/chapter/10.1007/3-540-48910-X_18
10. Diffie, W., Hellman, M., "Exhaustive Cryptanalysis of the NBS Data Encryption Standard," Computer, 1977. https://doi.org/10.1109/C-M.1977.217750
11. Electronic Frontier Foundation, "Cracking DES: Secrets of Encryption Research, Wiretap Politics & Chip Design," O'Reilly, 1998. https://www.eff.org/
12. NIST, "Transitioning the Use of Cryptographic Algorithms and Key Lengths," SP 800-131A Rev. 2, 2019. https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final
13. Fluhrer, S., Mantin, I., Shamir, A., "Weaknesses in the Key Scheduling Algorithm of RC4," SAC 2001. https://link.springer.com/chapter/10.1007/3-540-45537-X_7
14. NIST, "Recommendation for Block Cipher Modes of Operation," SP 800-38A, 2001. https://csrc.nist.gov/publications/detail/sp/800-38a/final
15. RFC 7465, "Prohibiting RC4 Cipher Suites," February 2015. https://www.rfc-editor.org/rfc/rfc7465
16. Barker, E., "Recommendation for Key Management — Part 1: General," SP 800-57 Rev. 5, 2020. https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final
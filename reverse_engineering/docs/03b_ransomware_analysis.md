# Ransomware Analysis Methodology

> Deep-dive into ransomware reverse engineering: crypto implementation analysis, file enumeration, persistence, C2 communication, family-specific analysis, and decryption tool development.

---

## Table of Contents

1. [Ransomware Overview](#1-ransomware-overview)
2. [Crypto Implementation Analysis](#2-crypto-implementation-analysis)
3. [File Enumeration & Encryption](#3-file-enumeration--encryption)
4. [Volume Shadow Copy Deletion](#4-volume-shadow-copy-deletion)
5. [Persistence Mechanisms](#5-persistence-mechanisms)
6. [C2 Communication Protocols](#6-c2-communication-protocols)
7. [Ransomware Family Analysis](#7-ransomware-family-analysis)
8. [Ransomware Negotiator Tools](#8-ransomware-negotiator-tools)
9. [Decryption Tool Development](#9-decryption-tool-development)

---

## 1. Ransomware Overview

Ransomware follows a consistent attack pattern despite family variation:

```
Ransomware Kill Chain:
┌──────────────────────────────────────────────────────────────────┐
│ 1. INITIAL ACCESS      │ Phishing, RDP, exploit, supply chain    │
│ 2. EXECUTION           │ Drop and execute payload                  │
│ 3. PERSISTENCE         │ Registry, scheduled tasks, services      │
│ 4. PRIVILEGE ESCALATION│ UAC bypass, token manipulation           │
│ 5. DEFENSE EVASION     │ Disable AV, clear logs, anti-debug      │
│ 6. DISCOVERY           │ Enumerate files, network shares          │
│ 7. LATERAL MOVEMENT   │ SMB, PsExec, WMI, RDP                   │
│ 8. C2 COMMUNICATION   │ Register victim, exchange keys            │
│ 9. ENCRYPTION          │ Hybrid encryption of target files        │
│ 10. IMPACT             │ Ransom note, data destruction, extortion │
└──────────────────────────────────────────────────────────────────┘
```

Ransomware encryption almost universally uses a **hybrid encryption scheme**:

```
┌───────────────┐                          ┌───────────────┐
│  Victim's File │ ──── AES-256-CBC ────→  │ Encrypted File │
│  (plaintext)   │     random file key      │  (.encrypted)  │
└───────────────┘                          └───────────────┘
        │                                         │
        │ The random file key must be              │
        │ available for decryption                 │
        │                                         │
        ▼                                         ▼
┌───────────────┐                     ┌───────────────────┐
│  Random File  │ ──── RSA-2048+ ───→ │ Encrypted File Key │
│  Key (per file)│     C2 public key    │ (stored in header) │
└───────────────┘                     └───────────────────┘
                                              │
                                              │ Only C2 private key
                                              │ can decrypt this
                                              ▼
                                     ┌───────────────┐
                                     │  C2 Server     │
                                     │  (RSA private)  │
                                     └───────────────┘

Without the C2 private key, the file encryption key cannot be recovered,
and files cannot be decrypted. This is why ransomware is effective.
```

---

## 2. Crypto Implementation Analysis

### 2.1 Identifying Crypto Algorithms

```python
# Crypto algorithm identification by constants
import struct

CRYPTO_CONSTANTS = {
    # AES S-box (first 16 bytes)
    'AES_SBOX': bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                       0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76]),
    
    # AES inverse S-box (first 16 bytes)
    'AES_INV_SBOX': bytes([0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
                           0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB]),
    
    # AES Rijndael key schedule constants (first 4 round constants)
    'AES_RCON': bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
                       0x1B, 0x36]),
    
    # MD5 initialization values
    'MD5_INIT': struct.pack('<IIII', 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476),
    
    # SHA-1 initialization values
    'SHA1_INIT': struct.pack('>IIIII', 0x67452301, 0xEFCDAB89, 0x98BADCFE,
                             0x10325476, 0xC3D2E1F0),
    
    # SHA-256 initialization values (first 4)
    'SHA256_INIT': struct.pack('>IIII', 0x6A09E667, 0xBB67AE85,
                               0x3C6EF372, 0xA54FF53A),
    
    # SHA-256 round constants (first 16)
    'SHA256_K': struct.pack('>IIIIIIIIIIIIIIII',
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174),
    
    # CRC32 polynomial table (first 16 entries)
    'CRC32_TABLE': struct.pack('<IIIIIIIIIIIIIIII',
        0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
        0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
        0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
        0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91),
    
    # RSA public exponent (very common)
    'RSA_E_65537': struct.pack('>I', 0x00010001),
    
    # ChaCha20 constant ("expand 32-byte k")
    'CHACHA20_CONST': b'expand 32-byte k',
    
    # Salsa20 constant ("expand 32-byte k")
    'SALSA20_CONST': b'expand 32-byte k',
    
    # Blowfish S-box (first P-array values)
    'BLOWFISH_P': struct.pack('>II', 0x243F6A88, 0x85A308D3),
}

def identify_crypto(binary_data):
    """Identify crypto algorithms used in a binary by their constants."""
    found = []
    
    for name, pattern in CRYPTO_CONSTANTS.items():
        offset = 0
        while True:
            offset = binary_data.find(pattern, offset)
            if offset == -1:
                break
            found.append({
                'algorithm': name,
                'offset': offset,
                'context': binary_data[max(0, offset-16):offset+len(pattern)+16].hex()
            })
            offset += len(pattern)
    
    # Also search for crypto API function names
    crypto_apis = [
        b'CryptEncrypt', b'CryptDecrypt', b'CryptDeriveKey', b'CryptGenKey',
        b'CryptHashData', b'CryptCreateHash',
        b'BCryptEncrypt', b'BCryptDecrypt', b'BCryptGenerateKeyPair',
        b'AES_set_encrypt_key', b'AES_encrypt', b'AES_decrypt',
        b'EVP_EncryptInit', b'EVP_EncryptUpdate', b'EVP_EncryptFinal',
        b'EVP_DecryptInit', b'EVP_DecryptUpdate', b'EVP_DecryptFinal',
        b'RSA_public_encrypt', b'RSA_private_decrypt',
        b'RC4_set_key', b'RC4',
    ]
    
    for api in crypto_apis:
        offset = binary_data.find(api)
        if offset != -1:
            found.append({
                'algorithm': f'API: {api.decode()}',
                'offset': offset,
            })
    
    return found
```

### 2.2 Hybrid Encryption Scheme Analysis

```c
// Typical ransomware hybrid encryption implementation (pseudocode)

// Step 1: Generate a random AES-256 key for each file (or per session)
void encrypt_file(const char *filepath, RSA *rsa_public_key) {
    // Generate random AES key for this file
    unsigned char aes_key[32];  // AES-256
    unsigned char aes_iv[16];   // IV for CBC mode
    RAND_bytes(aes_key, sizeof(aes_key));
    RAND_bytes(aes_iv, sizeof(aes_iv));
    
    // Step 2: Encrypt the file with AES-256-CBC
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
    
    // Read file, encrypt in chunks, write encrypted data
    FILE *in = fopen(filepath, "rb");
    FILE *out = fopen(encrypted_filepath, "wb");
    
    // Write header: [magic][iv][encrypted_aes_key][file_size][original_extension]
    fwrite(MAGIC, 4, 1, out);           // File magic
    fwrite(aes_iv, 16, 1, out);         // IV (plaintext - needed for decryption)
    
    // Step 3: Encrypt the AES key with RSA public key
    unsigned char encrypted_key[256]; // RSA-2048 output size
    int encrypted_len = RSA_public_encrypt(
        sizeof(aes_key), aes_key,
        encrypted_key, rsa_public_key,
        RSA_PKCS1_PADDING           // Or OAEP for more secure implementations
    );
    fwrite(&encrypted_len, 4, 1, out);   // Encrypted key length
    fwrite(encrypted_key, encrypted_len, 1, out); // Encrypted AES key
    
    // Encrypt file data
    int out_len;
    unsigned char in_buf[4096], out_buf[4096 + 16]; // +16 for block alignment
    int bytes_read;
    while ((bytes_read = fread(in_buf, 1, sizeof(in_buf), in)) > 0) {
        EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, bytes_read);
        fwrite(out_buf, 1, out_len, out);
    }
    
    EVP_EncryptFinal_ex(ctx, out_buf, &out_len);
    fwrite(out_buf, 1, out_len, out);
    
    fclose(in);
    fclose(out);
    
    // Step 4: Delete original file (or overwrite then delete)
    secure_delete(filepath);
}
```

**Key weaknesses to look for**:

```python
# Common crypto implementation mistakes in ransomware

WEAKNESSES = {
    # 1. Static/hardcoded AES key (no per-file key generation)
    'static_key': {
        'description': 'Same AES key used for all files',
        'detection': 'Search for fixed key reference in encryption routine',
        'exploitation': 'Extract key from memory during execution, decrypt all files',
    },
    
    # 2. Weak random number generation
    'weak_rng': {
        'description': 'Using rand()/srand() instead of CryptGenRandom/RAND_bytes',
        'detection': 'Look for rand(), srand(), GetTickCount as seed',
        'exploitation': 'Reconstruct key from seed (if seed is time-based)',
    },
    
    # 3. ECB mode instead of CBC
    'ecb_mode': {
        'description': 'AES-ECB mode encrypts blocks independently',
        'detection': 'Look for EVP_aes_256_ecb() or AES_MODE_ECB',
        'exploitation': 'Known-plaintext attack on repeated blocks',
    },
    
    # 4. Hardcoded RSA key
    'hardcoded_rsa': {
        'description': 'RSA public key embedded in binary',
        'detection': 'Search for base64-encoded RSA key or PEM header',
        'exploitation': 'If private key is also embedded (rare), extract and decrypt',
    },
    
    # 5. Key derivation with known salt
    'weak_kdf': {
        'description': 'Using SHA-256(password) instead of PBKDF2/scrypt/argon2',
        'detection': 'Look for SHA256(password) without iteration count',
        'exploitation': 'Brute force derive key from password space',
    },
    
    # 6. Partial encryption (only encrypting portion of file)
    'partial_encrypt': {
        'description': 'Only encrypting first N bytes or every other block',
        'detection': 'Look for size checks or offset calculations before encryption loop',
        'exploitation': 'Recover unencrypted portions; may enable file repair',
    },
    
    # 7. Key stored in encrypted file header
    'key_in_header': {
        'description': 'AES key encrypted with symmetric key also stored in binary',
        'detection': 'Look for two layers of key encryption',
        'exploitation': 'If inner key is derived from known value, decrypt',
    },
}
```

### 2.3 Extracting RSA Public Keys

```python
# Ransomware often embeds the RSA public key in the binary
import base64
import re

def extract_rsa_keys(binary_data):
    """Extract RSA public keys from ransomware binary."""
    keys = []
    
    # Method 1: Search for PEM-encoded keys
    pem_pattern = rb'-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/=\n]+)\n-----END PUBLIC KEY-----'
    for match in re.finditer(pem_pattern, binary_data):
        key_data = match.group(0).decode('utf-8')
        keys.append({
            'type': 'PEM_PUBLIC_KEY',
            'offset': match.start(),
            'key': key_data,
        })
    
    # Method 2: Search for DER-encoded RSA public key (ASN.1 header)
    # RSA public key in DER starts with SEQUENCE { SEQUENCE { OID, NULL }, BITSTRING }
    # OID for rsaEncryption: 1.2.840.113549.1.1.1
    rsa_oid = bytes([0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
                     0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00])
    
    offset = 0
    while True:
        offset = binary_data.find(rsa_oid, offset)
        if offset == -1:
            break
        # Back up to find the full SEQUENCE header
        key_start = binary_data.rfind(b'\x30', max(0, offset - 20), offset)
        if key_start != -1:
            # Read length from ASN.1
            length_byte = binary_data[key_start + 1]
            if length_byte & 0x80:  # Long form
                length_bytes = (length_byte & 0x7F)
                offset_start = key_start + 2
                key_length = int.from_bytes(binary_data[offset_start:offset_start+length_bytes], 'big')
                total_length = key_start + 2 + length_bytes + key_length
            else:
                key_length = length_byte
                total_length = key_start + 2 + key_length
            
            key_der = binary_data[key_start:total_length]
            keys.append({
                'type': 'DER_PUBLIC_KEY',
                'offset': key_start,
                'key_der': key_der.hex(),
                'key_length': len(key_der),
            })
        offset += 1
    
    # Method 3: Search for base64-encoded keys without PEM headers
    # Many ransomware store keys as raw base64
    b64_pattern = rb'[A-Za-z0-9+/]{200,}={0,2}'
    for match in re.finditer(b64_pattern, binary_data):
        try:
            decoded = base64.b64decode(match.group())
            # Check if decoded data starts with ASN.1 SEQUENCE
            if decoded[0] == 0x30:
                keys.append({
                    'type': 'BASE64_ASN1',
                    'offset': match.start(),
                    'key_length': len(decoded),
                })
        except Exception:
            pass
    
    return keys
```

---

## 3. File Enumeration & Encryption

### 3.1 Target File Selection

Ransomware selectively encrypts files based on extensions. Understanding the target file list reveals the ransomware's impact scope:

```python
# Common ransomware target extensions
TARGET_EXTENSIONS = {
    # Documents
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.pdf',
    '.txt', '.rtf', '.csv', '.wpd', '.wps', '.xlr',
    
    # Images
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tif', '.tiff', '.psd', '.raw',
    '.svg', '.indd', '.ai', '.eps',
    
    # Video
    '.avi', '.mp4', '.mov', '.mkv', '.wmv', '.flv', '.mpg', '.mpeg', '.3gp',
    
    # Audio  
    '.mp3', '.wav', '.flac', '.aac', '.wma', '.m4a', '.ogg',
    
    # Database
    '.sql', '.mdb', '.accdb', '.dbf', '.mdf', '.ldf', '.ndf', '.ora',
    
    # Archives
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
    
    # Virtual machines
    '.vmdk', '.vhd', '.vhdx', '.vdi', '.qcow2',
    
    # Backups
    '.bak', '.bac', '.bkp', '.wbcat', '.vhd', '.tib',
    
    # Certificates and keys
    '.pem', '.p12', '.pfx', '.key', '.crt', '.cer',
    
    # Configuration
    '.config', '.ini', '.cfg', '.conf', '.json', '.xml', '.yaml', '.yml',
}

# Extensions ransomware typically SKIPS
SKIP_EXTENSIONS = {
    '.exe', '.dll', '.sys', '.drv',  # System files
    '.lnk', '.url',                   # Shortcuts
    '.ini',                           # Some skip this
}

# Extensions ransomware typically SKIPS (for operational reasons)
SKIP_DIRECTORIES = {
    'C:\\Windows\\',       # System directory
    'C:\\Program Files\\', # Application directories
    'C:\\ProgramData\\',   # Application data
    'C:\\System Volume Information\\',  # System restore
    'AppData\\Local\\',    # Local app data
}
```

### 3.2 Encryption Strategies

```python
# Different ransomware families use different encryption strategies

ENCRYPTION_STRATEGIES = {
    'full_file': {
        'description': 'Encrypt the entire file',
        'families': ['WannaCry', 'Locky', 'Cerber'],
        'time_impact': 'Slow for large files',
        'analysis': 'Simple to detect; look for encrypted file header',
    },
    'partial_start': {
        'description': 'Encrypt only the first N bytes (e.g., first 5-10MB)',
        'families': ['REvil', 'Conti', 'LockBit'],
        'time_impact': 'Fast even for large files',
        'analysis': 'Look for encryption loop limit; may enable partial recovery',
    },
    'interleaved': {
        'description': 'Encrypt every Nth block (e.g., every 64KB)',
        'families': ['Ryuk', 'Egregor'],
        'time_impact': 'Moderate',
        'analysis': 'Look for skip/stride calculations in encryption loop',
    },
    'header_only': {
        'description': 'Encrypt only the file header (first 1-5 KB)',
        'families': ['Some early ransomware'],
        'time_impact': 'Very fast',
        'analysis': 'Trivial corruption; may be repairable if format is known',
    },
}

# Analyzing the encryption routine in assembly
def analyze_encryption_routine(disassembly):
    """Identify the encryption strategy from disassembly patterns."""
    
    # Pattern: Full file encryption
    # Look for: loop that reads entire file, encrypts, writes back
    # Key instruction: cmp read_bytes, file_size (or similar end condition)
    
    # Pattern: Partial start encryption
    # Look for: size limit check before encryption loop
    # Key instruction: cmp offset, MAX_ENCRYPTION_SIZE or similar
    # Example:
    #   mov r8d, 5000000h   ; Max encryption size = 5MB
    #   cmp rax, r8          ; Compare current offset to max
    #   jl  continue_encrypt ; If below max, continue encryption
    
    # Pattern: Interleaved encryption
    # Look for: stride/step calculation in the loop
    # Key instruction: add rax, 10000h (64KB stride)
    # Example:
    #   add file_offset, 10000h   ; Move forward by 64KB
    #   jmp encryption_loop
    
    # Pattern: Header-only encryption
    # Look for: small fixed-size encryption followed by file copy
    # Key instruction: mov key_size, 400h (1KB) or similar
    
    return None  # Analysis result depends on specific binary
```

---

## 4. Volume Shadow Copy Deletion

Ransomware deletes Volume Shadow Copies to prevent file recovery:

```bash
# Commands used by ransomware to delete VSS
vssadmin delete shadows /all /quiet
vssadmin delete shadows /for={volume_guid} /quiet
wmic shadowcopy delete
wbadmin delete catalog -quiet
wbadmin delete systemstatebackup -keepVersions:0
bcdedit /set {default} recoveryenabled No
bcdedit /set {default} bootstatuspolicy ignoreallfailures

# PowerShell equivalents
Get-WmiObject Win32_ShadowCopy | Remove-WmiObject
Get-CimInstance -ClassName Win32_ShadowCopy | Remove-CimInstance

# Detection: Monitor for these commands in process creation events
# Sysmon Event ID 1 (Process Create):
#   Image: vssadmin.exe, Command: delete shadows
#   Image: wbadmin.exe, Command: delete catalog
#   Image: wmic.exe, Command: shadowcopy delete

# Recovery options after VSS deletion:
# 1. Third-party backup solutions
# 2. File recovery tools (PhotoRec, TestDisk)
# 3. Previous versions (if enabled before attack)
# 4. Cloud backup (OneDrive, Google Drive)
# 5. NAS/servers that weren't affected
```

---

## 5. Persistence Mechanisms

```python
# Common ransomware persistence techniques

PERSISTENCE_TECHNIQUES = {
    # Registry Run keys (most common)
    'registry_run': {
        'keys': [
            r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        ],
        'detection': 'Monitor registry Run key modifications (Sysmon Event ID 13)',
    },
    
    # Scheduled tasks
    'scheduled_task': {
        'commands': [
            'schtasks /create /tn "SystemUpdate" /tr "C:\\malware.exe" /sc onstart /ru SYSTEM',
            'schtasks /create /tn "WindowsDefender" /tr "malware.exe" /sc minute /mo 1',
        ],
        'detection': 'Monitor schtasks.exe execution and Task Scheduler logs',
    },
    
    # Services
    'windows_service': {
        'commands': [
            'sc create ServiceName binPath= "C:\\malware.exe" start= auto',
            'net start ServiceName',
        ],
        'detection': 'Monitor service creation (Sysmon Event ID 7045, sc.exe)',
    },
    
    # Startup folder
    'startup_folder': {
        'paths': [
            r'C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup',
            r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup',
        ],
        'detection': 'Monitor file creation in startup folders',
    },
    
    # WMI persistence
    'wmi_subscription': {
        'commands': [
            'wmic /namespace:\\\\root\\subscription path __EventFilter',
            'wmic /namespace:\\\\root\\subscription path __FilterToConsumerBinding',
            'wmic /namespace:\\\\root\\subscription path CommandLineEventConsumer',
        ],
        'detection': 'Monitor WMI subscription creation (Sysmon Event ID 19, 20, 21)',
    },
    
    # Boot/startup registry keys
    'boot_keys': {
        'keys': [
            r'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute',
            r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell',
            r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit',
        ],
        'detection': 'Monitor these registry keys for modification',
    },
}

# Indicator extraction from ransomware binary
def extract_persistence_indicators(binary_data):
    """Extract persistence-related indicators from ransomware binary."""
    indicators = []
    
    # Registry key patterns
    registry_patterns = [
        rb' SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        rb' SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
        rb'System\\CurrentControlSet\\Services',
    ]
    
    for pattern in registry_patterns:
        offset = binary_data.find(pattern)
        while offset != -1:
            end = binary_data.find(b'\x00', offset)
            key = binary_data[offset:end].decode('utf-8', errors='replace')
            indicators.append(f"Registry key: {key}")
            offset = binary_data.find(pattern, offset + 1)
    
    # Command patterns
    command_patterns = [
        rb'schtasks', rb'sc create', rb'net start', rb'wmic',
        rb'vssadmin', rb'wbadmin', rb'bcdedit',
    ]
    
    for pattern in command_patterns:
        offset = binary_data.find(pattern)
        while offset != -1:
            indicators.append(f"Command: {pattern.decode()}")
            offset = binary_data.find(pattern, offset + 1)
    
    return indicators
```

---

## 6. C2 Communication Protocols

### 6.1 Common C2 Protocols

```python
# Ransomware C2 communication analysis

C2_PROTOCOLS = {
    # Raw TCP/TLS
    'raw_tcp': {
        'description': 'Direct TCP/TLS connection to C2 server',
        'families': ['WannaCry', 'Petya'],
        'indicators': ['socket()', 'connect()', 'send()', 'recv()'],
        'analysis': 'Wireshark/tcpdump capture, TLS SNI extraction',
    },
    
    # HTTP/HTTPS
    'http': {
        'description': 'HTTP POST/GET requests to C2',
        'families': ['LockBit', 'REvil', 'Conti'],
        'indicators': ['InternetOpenA', 'HttpOpenRequest', 'HttpSendRequest',
                       'URLDownloadToFile'],
        'analysis': 'Proxy intercept (mitmproxy/Burp), extract URLs from binary',
    },
    
    # Tor/onion
    'tor': {
        'description': 'C2 communication over Tor network',
        'families': ['REvil', 'BlackBateria'],
        'indicators': ['tor.exe', '.onion', '127.0.0.1:9050', 'SOCKS5'],
        'analysis': 'Traffic analysis, Tor relay detection',
    },
    
    # Custom protocol
    'custom': {
        'description': 'Proprietary binary protocol over TCP',
        'families': ['Many modern families'],
        'indicators': ['Unknown protocol patterns', 'Binary framing'],
        'analysis': 'Protocol RE (see 05b_protocol_re.md)',
    },
}

# Typical C2 registration protocol
# Step 1: Generate victim ID
# victim_id = SHA256(computer_name + volume_serial + random_bytes)

# Step 2: Register with C2
# POST /register HTTP/1.1
# Content-Type: application/octet-stream
# Body: [victim_id][public_key][system_info][encrypted_file_count]

# Step 3: C2 responds with configuration
# Response: [encryption_config][c2_servers][payment_address]

# Step 4: Periodic check-in
# GET /check?victim_id=<id>
# Response: [status][payment_status][decrypt_key_if_paid]
```

### 6.2 C2 Extraction from Binary

```python
def extract_c2_indicators(binary_data):
    """Extract C2 communication indicators from ransomware binary."""
    import re
    
    indicators = {
        'urls': [],
        'ips': [],
        'domains': [],
        'onion_addresses': [],
        'crypto_addresses': [],
    }
    
    # Extract URLs
    url_pattern = rb'https?://[^\x00\x01\x02\x03\x04]{5,256}'
    for match in re.finditer(url_pattern, binary_data):
        url = match.group().decode('utf-8', errors='replace').rstrip('\x00')
        indicators['urls'].append({'url': url, 'offset': match.start()})
    
    # Extract IP addresses
    ip_pattern = rb'(?:\d{1,3}\.){3}\d{1,3}'
    for match in re.finditer(ip_pattern, binary_data):
        ip = match.group().decode()
        # Filter out obviously non-IP patterns
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            if not ip.startswith(('0.', '255.', '127.')):  # Skip loopback, broadcast
                indicators['ips'].append({'ip': ip, 'offset': match.start()})
    
    # Extract .onion addresses
    onion_pattern = rb'[a-z2-7]{16,56}\.onion'
    for match in re.finditer(onion_pattern, binary_data):
        indicators['onion_addresses'].append({
            'address': match.group().decode(),
            'offset': match.start()
        })
    
    # Extract cryptocurrency addresses
    # BTC addresses (Base58Check, starts with 1 or 3)
    btc_pattern = rb'[13][a-km-zA-HJ-NP-Z1-9]{25,34}'
    for match in re.finditer(btc_pattern, binary_data):
        addr = match.group().decode()
        if not addr.startswith('1A1zP'):  # Skip genesis block address
            indicators['crypto_addresses'].append({
                'address': addr,
                'type': 'BTC',
                'offset': match.start()
            })
    
    return indicators
```

---

## 7. Ransomware Family Analysis

### 7.1 WannaCry Analysis

```
WannaCry (2017) — Key Technical Details:

Encryption:
  - AES-128-CBC per file
  - RSA-2048 for file key encryption  
  - Two RSA keys per infection:
    1. Embedded public key (encryption)
    2. Per-victim key pair (generated on infection)
  - Key generation: CryptGenRandom (secure RNG)
  
C2 Communication:
  - Kill switch domain: iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
  - Hardcoded Tor C2 addresses
  - Attempts to connect to C2 before encryption
  
Propagation:
  - EternalBlue (MS17-010) — SMB vulnerability
  - DoublePulsar backdoor for persistence
  - Scans port 445 (SMB) on local and remote networks
  
File Analysis:
  - Encrypts 176 file extensions
  - Appends .WNCRY extension
  - Creates @WanaDecryptor@.exe lipid
  - Drops @Please_Read_Me@.txt ransom note
  
Vulnerability (led to decryption):
  - WannaCry generates per-victim key pair, encrypts private key with
    embedded public key, then stores the encrypted private key
  - On Windows XP, CryptGenRandom usesCryptGenRandom with 
    ADVAPI32!SystemFunction036 which can be predicted if the 
    PRNG state is known at infection time
  - This led to the "wanakiwi" decryption tool for WinXP
```

### 7.2 NotPetya Analysis

```
NotPetya (2017) — Key Technical Details:

Encryption:
  - Two-stage encryption:
    Stage 1: MFT (Master File Table) encryption with AES-128
      - Uses Salsa20 stream cipher for file encryption
      - NotPetya then overwrites MFT entries
    Stage 2: Disk sector-level encryption
      - Encrypts first 25 sectors of disk
      - Modifies MBR to display ransom note on boot
  
  - Key generation: Uses Windows CryptoAPI
  - Encryption key is encrypted with hard-coded RSA public key
  
  - CRITICAL WEAKNESS: Early versions used a platform-dependent PRNG
    for AIK (Additional Identity Key) generation.
    Guessed key: A 64-byte seed derived from CryptGenRandom
    On Windows Vista+: CryptGenRandom was used (secure)
    On some configurations: simpler PRNG was used
    
  - NOT A TRUE RANSOMWARE: The second-stage encryption destroys
    the master file table, making decryption impossible even
    with the key. NotPetya is a WIPER with ransomware UI.

Propagation:
  - EternalBlue (same as WannaCry)
  - PSExec + admin$ share
  - WMI remote execution
  - Credential harvesting (Mimikatz)
  
File Analysis:
  - Modifies MBR (Master Boot Record)
  - Encrypts entire disk using Salsa20
  - No individual file encryption — disk-level only
  - Ransom note replaces bootloader
```

### 7.3 REvil (Sodinokibi) Analysis

```
REvil/Sodinokibi (2019-2021) — Key Technical Details:

Architecture:
  - RaaS (Ransomware-as-a-Service)
  - Affiliate model: operators provide RaaS, affiliates distribute
  - Custom affiliate panel for managing victims
  
Encryption:
  - AES-256-CBC for file encryption (per-file random key)
  - RSA-2048 for file key encryption
  - Two RSA keys:
    1. Per-affiliate public key (embedded in config)
    2. Per-victim public key (generated dynamically)
  - Partial encryption: only encrypts ~6.6% of files > 2MB
  - Segmented encryption: 8 bytes encrypted / 128 bytes skipped
  
Configuration:
  - Embedded configuration blob (encrypted)
  - JSON-based config decoded at runtime
  - Includes: C2 servers, file extensions, kill processes, notes
  
Anti-Analysis:
  - String obfuscation (stack strings, XOR)
  - Anti-debug: IsDebuggerPresent, NtQueryInformationProcess
  - Anti-VM: MAC address check, driver checks
  - Code obfuscation: control flow flattening (custom VM?)
  
C2 Communication:
  - HTTP/HTTPS to backend server
  - Victim registration with unique ID
  - Payment verification through C2 API
  - Chat support for victims
  
Impact:
  - $11M ransom demand from JBS Foods
  - $10M from ASM (Brazillian government)
  - Kaseya supply chain attack: 1,500+ organizations
  - FBI confirmed REvil infrastructure seized (2021)
```

### 7.4 Conti Analysis

```
Conti (2020-2022) — Key Technical Details:

Architecture:
  - RaaS operation, Conti Team operates core infrastructure
  - Leaked source code (2021) revealed internal operations
  - Affiliates get 70-80% of ransom
  - Dedicated negotiators, help desk for victims
  
Encryption:
  - AES-256 for files (per-file key)
  - RSA-4096 for file keys (stronger than typical)
  - Multi-threaded encryption for speed
  - Encrypts files in 2 phases:
    1. Local files (fast, multi-threaded)
    2. Network shares (recursive enumeration)
  
Propagation:
  - Cobalt Strike for initial access
  - Cobalt Strike + Rclone for data exfiltration
  - Mimikatz for credential harvesting
  - PsExec, WMI, SMB for lateral movement
  - ZeroLogon (CVE-2020-1472) for domain compromise
  
Configuration (from leaked source):
  - JSON configuration with affiliate ID
  - Encryption settings per file type
  - Process kill list (databases, backup software)
  - Network share enumeration
  - C2 endpoint list
  
Key Management:
  - Unique RSA key pair per victim
  - Public key embedded, private key on C2
  - Affiliate key pair for attribution
  
The Conti Leaks (2021-2022):
  - disgruntled affiliate leaked ~170k internal messages
  - Revealed: operational playbook, negotiation scripts
  - Monthly revenue: $10M+
  - 366 affiliates over operation lifetime
  - Political ties (Russian intelligence connections)
```

### 7.5 LockBit Analysis

```
LockBit (2019-2023) — Key Technical Details:

Evolution:
  - LockBit 1.0 (ABCD ransomware, 2019)
  - LockBit 2.0 (2021) — improved encryption, bug fixes
  - LockBit 3.0 (2022) — bug bounty program, new features
  
Encryption:
  - AES-256 + ECC (Elliptic Curve Cryptography)
  - Per-file random AES key
  - File key encrypted with ECC public key
  - Fast encryption (multi-threaded, I/O optimized)
  - Partial encryption for large files (>100MB)
  
Configuration:
  - Encrypted configuration blob
  - Includes: C2 servers, ransom note template, extensions list
  - Affiliate ID embedded (for attribution)
  
Anti-Analysis:
  - Anti-debug (IsDebuggerPresent, NtQueryInformationProcess)
  - Anti-VM (driver checks, timing)
  - String obfuscation (XOR with rolling key)
  - Code obfuscation (controlled flow flattening)
  
Self-Propagation:
  - Uses own propagation module (no EternalBlue dependency)
  - Scans local subnet for RDP access
  - Uses Group Policy Objects (GPO) for deployment
  - Exploits: PrintNightmare, EternalBlue, ZeroLogon
  
LockBit 3.0 Innovation:
  - Bug bounty program (paying researchers for found bugs)
  - .NET loader for initial execution
  - StealC information stealer integration
  - Support for encrypting Windows shares via SMB
  
Operation disruption:
  - December 2023: Operation Cronos — international law enforcement
    seized LockBit infrastructure, arrested operators
  - However, LockBit has attempted comebacks
```

---

## 8. Ransomware Negotiator Tools

```python
# Tools and techniques for ransomware negotiation

NEGOTIATOR_TOOLS = {
    'RansomLook': {
        'description': 'Open-source ransomware negotiation tracker',
        'url': 'https://ransomlook.io',
        'features': ['Track ransom payments', 'Monitor onion sites', 'Family tracking'],
    },
    'ID Ransomware': {
        'description': 'Free service to identify ransomware by ransom note or encrypted file',
        'url': 'https://id-ransomware.malwarehunterteam.com/',
        'features': ['Family identification', 'Free decryptor check', 'Support forum'],
    },
    'No More Ransom': {
        'description': 'Europol-backed project with free decryptors',
        'url': 'https://www.nomoreransom.org/',
        'features': ['Free decryptors for 140+ families', 'Prevention advice', 'Reporting'],
    },
    'VirusTotal': {
        'description': 'Multi-engine malware scanner with decryptor info',
        'url': 'https://www.virustotal.com/',
        'features': ['Hash lookup', 'Behavioral analysis', 'Community comments'],
    },
}

# Negotiation best practices
NEGO_BEST_PRACTICES = {
    'never_pay': 'Paying does not guarantee decryption; funds further criminal activity',
    'consult_experts': 'Engage incident response firms with ransomware expertise',
    'backup_verification': 'Before paying, verify that the threat actor can actually decrypt',
    'legal_considerations': 'Check OFAC sanctions list; paying sanctioned entities is illegal',
    'law_enforcement': 'Report to FBI/IC3, local law enforcement before negotiation',
    'decryptor_verification': 'Request proof of decryption capability before payment',
    'payment_method': 'Bitcoin is standard; never pay in privacy coins',
    'time_pressure': 'Threat actors often increase ransom after deadlines; don\'t rush',
}
```

---

## 9. Decryption Tool Development

### 9.1 When Decryption Is Possible

```python
# Scenarios where decryption without the attacker's key is possible

DECRYPTABLE_SCENARIOS = {
    # 1. Implementation flaw: key stored in encrypted file
    'key_in_file': {
        'description': 'AES file key stored unencrypted or weakly encrypted',
        'families': ['Some early ransomware', 'Petya variants'],
        'approach': 'Extract key from encrypted file header',
    },
    
    # 2. Weak key generation
    'weak_rng': {
        'description': 'Key generated with insecure RNG (time-based, predictable)',
        'families': ['Early LockCrypt', 'Some open-source ransomware'],
        'approach': 'Reconstruct key from known seed (timestamp, hostname)',
    },
    
    # 3. Shared key across victims
    'shared_key': {
        'description': 'Same encryption key used for all victims',
        'families': ['Some early ransomware', 'Tutorial ransomware'],
        'approach': 'Extract key from one victim, use for all',
    },
    
    # 4. Server seizure
    'server_seizure': {
        'description': 'Law enforcement seizes C2 server with private keys',
        'families': ['WannaCry (partial)', 'GandCrab', 'NoMoreRansom decryptors'],
        'approach': 'Use recovered master private key to decrypt',
    },
    
    # 5. Key disclosure by attacker
    'key_disclosure': {
        'description': 'Attacker releases keys (rare; happens after shutdown)',
        'families': ['TeslaCrypt (released keys)', 'Shade (released keys)'],
        'approach': 'Use published master key',
    },
    
    # 6. Implementation flaw: key derivation from known data
    'weak_derivation': {
        'description': 'Key derived from predictable data (hostname, etc.)',
        'families': ['Some ransomware'],
        'approach': 'Recreate key derivation process with known inputs',
    },
}
```

### 9.2 Decryption Tool Template

```python
#!/usr/bin/env python3
"""
Generic ransomware decryption tool template.
Adapt for specific families based on analysis.
"""

import os
import sys
import struct
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5

class RansomwareDecryptor:
    def __init__(self, encrypted_dir, output_dir):
        self.encrypted_dir = encrypted_dir
        self.output_dir = output_dir
        self.magic = b'ENCRYPTED'  # File magic header
        self.key = None
    
    def identify_family(self, filepath):
        """Identify ransomware family from encrypted file header."""
        with open(filepath, 'rb') as f:
            header = f.read(16)
        
        # Family identification by magic/header
        if header[:4] == b'WCRY':
            return 'WannaCry'
        elif header[:3] == b'ANC':
            return 'LockCrypt'
        elif header[:8] == self.magic:
            return 'Generic'
        # Add more family markers...
        return None
    
    def extract_key_from_header(self, filepath):
        """Extract encrypted AES key from file header."""
        with open(filepath, 'rb') as f:
            # Read header structure
            magic = f.read(4)           # Magic bytes
            iv = f.read(16)             # AES IV (usually stored plaintext)
            key_length = struct.unpack('<I', f.read(4))[0]  # Encrypted key length
            encrypted_key = f.read(key_length)    # RSA-encrypted AES key
            # Remaining: encrypted file data
        
        return {
            'magic': magic,
            'iv': iv,
            'key_length': key_length,
            'encrypted_key': encrypted_key,
        }
    
    def decrypt_with_rsa_key(self, encrypted_key, rsa_private_key):
        """Decrypt the per-file AES key using the RSA private key."""
        key = RSA.import_key(rsa_private_key)
        
        # Try PKCS1 padding first (most common)
        try:
            cipher = PKCS1_v1_5.new(key)
            aes_key = cipher.decrypt(encrypted_key, None)
            if aes_key:
                return aes_key
        except Exception:
            pass
        
        # Try OAEP padding
        try:
            cipher = PKCS1_OAEP.new(key)
            aes_key = cipher.decrypt(encrypted_key)
            return aes_key
        except Exception:
            pass
        
        # Try raw RSA (no padding)
        try:
            aes_key_int = pow(int.from_bytes(encrypted_key, 'big'), key.d, key.n)
            aes_key = aes_key_int.to_bytes(32, 'big')
            return aes_key
        except Exception:
            pass
        
        return None
    
    def decrypt_file(self, filepath, aes_key, iv):
        """Decrypt a single file using AES-256-CBC."""
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        
        with open(filepath, 'rb') as f:
            header = self.extract_key_from_header(filepath)
            # Skip header to get encrypted data
            f.seek(4 + 16 + 4 + header['key_length'])  # magic + IV + key_len + enc_key
            encrypted_data = f.read()
        
        decrypted = cipher.decrypt(encrypted_data)
        
        # Remove PKCS7 padding
        pad_len = decrypted[-1]
        if pad_len <= AES.block_size:
            decrypted = decrypted[:-pad_len]
        
        return decrypted
    
    def batch_decrypt(self, rsa_private_key=None, aes_key=None):
        """Decrypt all encrypted files in the target directory."""
        os.makedirs(self.output_dir, exist_ok=True)
        
        for root, dirs, files in os.walk(self.encrypted_dir):
            for filename in files:
                filepath = os.path.join(root, filename)
                output_path = os.path.join(self.output_dir, 
                                          filename.replace('.encrypted', ''))
                
                try:
                    if aes_key:
                        # Direct AES key (no RSA layer)
                        header = self.extract_key_from_header(filepath)
                        decrypted = self.decrypt_file(filepath, aes_key, header['iv'])
                    elif rsa_private_key:
                        # Decrypt per-file AES key with RSA
                        header = self.extract_key_from_header(filepath)
                        file_aes_key = self.decrypt_with_rsa_key(
                            header['encrypted_key'], rsa_private_key)
                        if file_aes_key:
                            decrypted = self.decrypt_file(
                                filepath, file_aes_key, header['iv'])
                        else:
                            print(f"Failed to decrypt key: {filepath}")
                            continue
                    
                    with open(output_path, 'wb') as f:
                        f.write(decrypted)
                    print(f"Decrypted: {filepath} -> {output_path}")
                    
                except Exception as e:
                    print(f"Error decrypting {filepath}: {e}")

# Usage example
if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: decryptor.py <encrypted_dir> <output_dir> [--key <key_file>]")
        sys.exit(1)
    
    decryptor = RansomwareDecryptor(sys.argv[1], sys.argv[2])
    
    if '--key' in sys.argv:
        with open(sys.argv[sys.argv.index('--key') + 1], 'rb') as f:
            key_data = f.read()
        decryptor.batch_decrypt(rsa_private_key=key_data)
    else:
        print("No key provided — attempting known weaknesses...")
```

### 9.3 Known Decryptor Resources

```python
# Resources for finding existing decryptors

DECRYPTOR_RESOURCES = {
    'No More Ransom': {
        'url': 'https://www.nomoreransom.org/',
        'description': 'Europol-backed project with decryptors for 140+ families',
        'decryptors': [
            'AES_NI', 'Alcatraz Locker', 'APL', 'Aura', 'BadBlock',
            'BarRax', 'Chimera', 'Coinvault', ' Crybola', 'Cryakl',
            'Crysis (partial)', 'Crypt888', 'CryptConsole', 'Cryptok.,
            'Dharma (partial)', 'EncrypTile', 'FindZip', 'Fonix',
            'GandCrab', 'Globe', 'Globe2', 'Globe3', 'Horon',
            'InsaneCrypt', 'Jaff', 'LambaCry', 'Lortok', 'MacCrypt',
            'MasterBuster', 'MegaLocker', 'Merry', 'NamPoHyu',
            'Nemucod', 'NoobCrypt', 'Ozozalock', 'Paradise (partial)',
            'Petya (partial)', 'Planet Locker', 'Rakhni', 'RansomwareX',
            'Rannoh', 'Rozena', 'Ryin', 'Shade', 'ShiOne', 'Snail',
            'Stampado', 'Teamx', 'TeslaCrypt', 'Thanatos', 'Troldesh',
            'Venus', 'Victim (partial)', 'WannaCry (WinXP)', 'Wildfire',
            'Xorist', 'ZQ',
        ],
    },
    'Emsisoft Decryptors': {
        'url': 'https://www.emsisoft.com/ransomware-decryption-tools/',
        'description': 'Free decryptors from Emsisoft',
        'note': 'Frequently updated; covers many active families',
    },
    'Kaspersky Decryptors': {
        'url': 'https://noransom.kaspersky.com/',
        'description': 'Free decryptors from Kaspersky',
    },
    'AVAST Decryptors': {
        'url': 'https://www.avast.com/ransomware-decryption-tools',
        'description': 'Free decryptors from Avast',
    },
}
```

> **Cross-reference**: See [03a_malware_analysis.md](03a_malware_analysis.md) for general malware analysis methodology. See [04b_anti_tamper_obfuscation.md](04b_anti_tamper_obfuscation.md) for ransomware obfuscation techniques. See [05b_protocol_re.md](05b_protocol_re.md) for C2 protocol analysis. See [02b_dynamic_analysis.md](02b_dynamic_analysis.md) for debugging ransomware samples.

---

*This document is part of the Deep Researcher Reverse Engineering track. Never pay ransoms without consulting incident response professionals and law enforcement.*

## References

1. Michael Sikorski & Andrew Honig, "Practical Malware Analysis," No Starch Press, 2012.
2. Mandiant, "Ransomware Playbook," 2021.
3. Dennis Yurichev, "Reverse Engineering for Beginners," https://yurichev.com/writings/RE_for_beginners-en.pdf
4. Cuckoo Sandbox documentation, https://cuckoosandbox.org/
5. IDA Ransomware Decryptor projects, various GitHub repositories.
6. NIST, "Ransomware Prevention and Response," https://www.nist.gov/
7. Europol, "Internet Organised Crime Threat Assessment (IOCTA)," 2023.
8. SANS Institute, "Ransomware Incident Response," https://www.sans.org/
9. Dennis Andriesse, "Practical Binary Analysis," No Starch Press, 2018.
10. No More Ransom Project, https://www.nomoreransom.org/
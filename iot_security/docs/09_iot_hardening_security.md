# IoT Hardening and Security

## 1. Secure Boot for Embedded Systems

### TF-A (Trusted Firmware for Arm)

TF-A (formerly ARM Trusted Firmware) provides a secure boot implementation for ARMv8-A (Cortex-A) processors. It implements the PSCI (Power State Coordination Interface) and handles secure world initialization.

**TF-A Boot Chain**:

```
Boot ROM (immutable)
  └─► Validates BL2 (Trusted Boot Firmware) via RSA/ECDSA signature
       └─► Validates BL31 (EL3 Runtime Firmware) via signature
            └─► Validates BL32 (Secure Payload, e.g., OP-TEE)
                 └─► Validates BL33 (Non-secure Firmware, e.g., U-Boot)
                      └─► Linux kernel
```

**TF-A Configuration**:

```dts
// TF-A device tree snippet for secure boot
/ {
    firmware {
        bl2: bl2@0x1000 {
            // BL2 image hash stored in ROTPK (Root of Trust Public Key)
        };
    };
    
    // Root of Trust Public Key Hash (ROTPK)
    // Stored in eFuse or OTP (one-time programmable) memory
    // Hash of the ROTPK is compared with the hash embedded in BL2
    secure-boot {
        rot-pk-hash = [00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
                       00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff];
    };
};
```

```bash
# Building TF-A with secure boot
make CROSS_COMPILE=aarch64-linux-gnu- \
    PLAT=rpi4 \
    TRUSTED_BOARD_BOOT=1 \
    GENERATE_COT=1 \
    ROT_KEY=rot_key.pem \
    MBEDTLS_DIR=/usr/include/mbedtls \
    SPD=opteed \
    BL32=tee-pager_v2.bin \
    BL33=u-boot.bin \
    all fip

# Key generation
openssl genrsa -out rot_key.pem 2048
openssl req -new -x509 -key rot_key.pem -out rot_key.crt -days 3650

# Creating FIP (Firmware Image Package) with certificates
fiptool create \
    --tb-fw-cert tb_fw.crt \
    --sos-fw-cert sos_fw.crt \
    --tos-fw-cert tos_fw.crt \
    --nt-fw-cert nt_fw.crt \
    --tb-fw-config tb_fw_config.bin \
    --soc-fw-config soc_fw_config.bin \
    --tos-fw-config tos_fw_config.bin \
    --nt-fw-config nt_fw_config.bin \
    fip.bin
```

### MCUboot for Cortex-M

MCUboot is a secure bootloader for Cortex-M microcontrollers. It provides cryptographic verification of firmware images before execution.

**MCUboot Features**:
- RSA-2048, RSA-3072, ECDSA-P256, and Ed25519 signature verification
- Image integrity verification (SHA-256)
- Firmware update support with rollback prevention
- Encrypted image support (AES-CTR-128, AES-CTR-256)
- Multiple image support (swap and overwrite strategies)

**MCUboot Image Header**:

```
┌──────────────────────────────────┐
│ Magic (0x96F3B83C)              │ 4 bytes
│ Load Address                     │ 4 bytes
│ Header Size                      │ 2 bytes
│ Protected TLV Size              │ 2 bytes
│ Image Size                       │ 4 bytes
│ Flags                           │ 4 bytes
│ ───────────────────────────────│
│ TLV Area:                       │
│   SHA-256 Hash                  │ 32 bytes
│   RSA-3072 Signature            │ 384 bytes
│   ECDSA-P256 Signature          │ 64 bytes
│   Key ID                        │ 4 bytes
└──────────────────────────────────┘
```

```c
// MCUboot configuration for Zephyr
// prj.conf
CONFIG_BOOTLOADER_MCUBOOT=y
CONFIG_MCUBOOT_SIGNATURE_TOOL=y
CONFIG_MCUBOOT_ENC_KEY=y
CONFIG_MCUBOOT_HW_KEY=y
CONFIG_MCUBOOT_VERIFY_IMG_SIGNATURE=y

// Signing a firmware image with imgtool
// imgtool is part of MCUboot
imgtool sign \
    --key signing_key.pem \
    --header-size 0x200 \
    --align 8 \
    --version 1.0.0 \
    --pad-header \
    --slot-size 0x60000 \
    app.bin \
    app_signed.bin

// Generating encryption key (for encrypted images)
imgtool keygen -k encryption_key.pem -t aes-128
imgtool keygen -k signing_key.pem -t ecdsa-p256

// Creating an encrypted and signed image
imgtool sign \
    --key signing_key.pem \
    --enc-key encryption_key.pem \
    --header-size 0x200 \
    --align 8 \
    --version 1.0.0 \
    --pad-header \
    --slot-size 0x60000 \
    app.bin \
    app_signed_encrypted.bin
```

**Rollback Prevention**:

MCUboot uses image version numbers and a hardware counter to prevent downgrade attacks:

```c
// MCUboot swap strategy with version enforcement
// Image versions are compared during boot:
// - If primary image version < secondary image version → swap
// - If primary image version > secondary image version → no swap
// - Hardware counter (in OTP/eFuse) prevents reversion to a version
//   below the stored minimum

// Zephyr configuration for rollback prevention
CONFIG_MCUBOOT_DOWNGRADE_PREVENTION=y
CONFIG_MCUBOOT_HW_ROLLBACK_PROT=y
```

### U-Boot Secure Boot

U-Boot supports verified boot using FIT (Flattened Image Tree) images with RSA/ECDSA signatures:

```bash
# Generate signing keys
openssl genrsa -F4 -out dev.key 2048
openssl req -new -x509 -key dev.key -out dev.crt

# Create FIT image with signature
mkimage -f fit.its fit.itb

# fit.its (Image Tree Source)
/dts-v1/;
/ {
    description = "Secure boot FIT image";
    images {
        kernel@1 {
            description = "Linux kernel";
            data = /incbin/("zImage");
            type = "kernel";
            arch = "arm";
            os = "linux";
            compression = "none";
            signature {
                algo = "sha256,rsa2048";
                key-name-hint = "dev";
                sign-images = "kernel";
            };
        };
        fdt@1 {
            description = "Flattened Device Tree";
            data = /incbin/("devicetree.dtb");
            type = "flat_dt";
            arch = "arm";
            signature {
                algo = "sha256,rsa2048";
                key-name-hint = "dev";
                sign-images = "fdt";
            };
        };
    };
    configurations {
        default = "config@1";
        config@1 {
            description = "Linux";
            kernel = "kernel@1";
            fdt = "fdt@1";
        };
    };
};

# SignFIT image
mkimage -f fit.its -k keys/ -K u-boot.dtb -r fit.itb

# U-Boot verified boot commands
# In U-Boot:
=> setenv bootcmd 'mmc read 0x82000000 0x800 0x2000; bootm 0x82000000#config@1'
=> setenv verifiesha256 yes
=> boot
```

## 2. Hardware Root of Trust

### Trusted Platform Module (TPM)

TPM 2.0 provides hardware-backed security functions:

```c
// TPM 2.0 for IoT: Key operations
#include <tss2/tss2_esys.h>

// Generate a storage seed (primary key)
ESYS_TR primary_handle;
TPM2B_PUBLIC primary_template = {
    .size = 0,
    .publicArea = {
        .type = TPM2_ALG_ECC,
        .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT 
                          | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT
                          | TPMA_OBJECT_SENSITIVEDATAORIGIN,
        .parameters.eccDetail = {
            .symmetric = {.algorithm = TPM2_ALG_AES, .keyBits.aes = 128},
            .scheme = {.scheme = TPM2_ALG_NULL},
            .curveID = TPM2_ECC_NIST_P256,
        },
    },
};

// Create primary key
TSS2_RC rc = Esys_CreatePrimary(
    esys_ctx,
    ESYS_TR_RH_OWNER,
    ESYS_TR_PASSWORD,
    ESYS_TR_NONE,
    ESYS_TR_NONE,
    &primary_sensitive,
    &primary_template,
    NULL, NULL, NULL,
    &primary_handle,
    &primary_public,
    &primary_name,
    &primary_creation_hash,
    &primary_creation_ticket
);
```

**TPM use cases for IoT**:
1. **Secure storage**: Keys, certificates, and passwords stored in TPM NVRAM
2. **Measured boot**: Each boot stage hash stored in Platform Configuration Registers (PCRs)
3. **Remote attestation**: TPM signs PCR values with Attestation Identity Key (AIK)
4. **Key derivation**: Storage keys derived from TPM seed, never leaving the TPM
5. **Random number generation**: Hardware RNG from TPM entropy source

### Secure Element (SE)

Secure Elements are dedicated cryptographic processors with tamper resistance:

**ATECC608B (Microchip)**: The most widely used IoT secure element.

```c
// ATECC608B usage with cryptoauthlib
#include "cryptoauthlib.h"

// Initialize
ATCAIfaceCfg cfg = {
    .iface_type = ATCA_I2C_IFACE,
    .devtype = ATECC608B,
    .atcai2c.address = 0x60,
    .atcai2c.bus = 1,
    .wake_delay = 1500,
    .rx_retries = 20,
};

atcab_init(&cfg);

// Generate key pair in slot 0
atcab_genkey(ATCA_GENKEY_MODE_RANDOM, 0, NULL, NULL);

// Sign data with private key in slot 0
uint8_t signature[64];
atcab_sign(0, message_digest, signature);

// Verify signature externally
bool verified;
atcab_verify_extern(message_digest, signature, &public_key, &verified);

// Read device certificate (stored in slot configuration)
uint8_t cert[72];
size_t cert_size;
atcab_read_cert(&cert_def, signer_public_key, cert, &cert_size);

// Secure storage: Read/write data slots
uint8_t stored_data[32];
atcab_read_zone(ATCA_ZONE_DATA, 4, 0, 0, stored_data, 32);

// Write data (one-time programmable or updatable)
atcab_write_zone(ATCA_ZONE_DATA, 4, 0, 0, data_to_store, 32);
```

**ATECC608B Slot Configuration**:

| Slot | Type | Key Type | Access |
|------|------|----------|--------|
| 0 | Private | ECC P-256 | Read: Never, Write: GenKey |
| 1 | Private | ECC P-256 | Read: Never, Write: GenKey |
| 2 | Private | ECC P-256 | Read: Never, Write: GenKey |
| 3 | Symmetric | AES-256 | Read: Encrypt, Write: Encrypt |
| 4-7 | Data | 256-bit | Read: Always, Write: Auth |
| 8-12 | Data | 256-bit | Read: Always, Write: Auth |
| 13 | Private | ECC P-256 | Device key (readable as cert) |
| 14 | Data | 416-bit | Secure boot digest |
| 15 | Data | 72 bytes | Device cert |

**OPTIGA Trust M (Infineon)**: Alternative secure element with similar features.

```c
// OPTIGA Trust M usage
#include "optiga/optiga_util.h"

optiga_util_t *util = optiga_util_create(0);

// Generate key pair
optiga_key_id_t key_id = OPTIGA_KEY_ID_E0FC;
optiga_util_generate_key_pair(
    util,
    OPTIGA_ECC_CURVE_NIST_P_256,
    key_id,
    false,
    &public_key,
    &public_key_len
);

// Sign data
optiga_util_sign(
    util,
    key_id,
    OPTIGA_CRYPTO_SERVICE_SHA256,
    digest,
    sizeof(digest),
    signature,
    &signature_len
);
```

### ARM TrustZone for Cortex-M

TrustZone-M (ARMv8-M) provides hardware-enforced isolation between Secure and Non-secure worlds:

```c
// TF-M (Trusted Firmware for Cortex-M) configuration
// Secure partition configuration (secure_partition.c)

// Define a secure service: cryptographic operations
static void psa_encrypt_service(psa_msg_t *msg) {
    switch (msg->type) {
        case PSA_IPC_CONNECT:
            // Connection handling
            break;
        case PSA_IPIC_CALL:
            // Encrypt data using key stored in secure world
            uint8_t plaintext[128];
            uint8_t ciphertext[128];
            size_t bytes_read = psa_read(msg->handle, 0, plaintext, sizeof(plaintext));
            
            // Use hardware crypto accelerator (ADS/CRU)
            // Key never leaves secure world
            status = crypto_aes_encrypt(plaintext, bytes_read, ciphertext);
            
            psa_write(msg->handle, 0, ciphertext, sizeof(ciphertext));
            psa_reply(msg->handle, PSA_SUCCESS);
            break;
        case PSA_IPIC_DISCONNECT:
            break;
    }
}

// Register secure service
PSA_IPC_SERVICE(crypto_service, 0, psa_encrypt_service);

// Non-secure callable function
__attribute__((cmse_nonsecure_entry))
psa_status_t crypto_encrypt(const uint8_t *plaintext, size_t len, uint8_t *ciphertext) {
    // This function can be called from non-secure world
    //但其 implementation runs in secure world
    
    // Validate non-secure pointers!
    if (cmse_nonsecure_address_range(plaintext, len, CMSE_NONSECURE) == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    // Perform encryption in secure world
    return internal_encrypt(plaintext, len, ciphertext);
}
```

## 3. Firmware Signing and Verification

### Firmware Signing Process

```
Developer Build Server:
  1. Compile firmware → firmware.bin
  2. Generate SHA-256 hash: hash = SHA256(firmware.bin)
  3. Sign hash with private key: signature = RSA-3072-Sign(hash, private_key)
  4. Package: firmware.bin + signature + certificate_chain
  5. Publish to update server

Device Boot Process:
  1. Boot ROM verifies BL2 signature using ROTPK
  2. BL2 verifies BL31/BL32/BL33 signatures using key chain
  3. BL33 (U-Boot) verifies Linux kernel signature
  4. Linux kernel verifies rootfs hash (dm-verity)
```

```bash
# Firmware signing with OpenSSL
# Generate signing key pair
openssl genrsa -out firmware_signing_key.pem 3072
openssl rsa -in firmware_signing_key.pem -pubout -out firmware_signing_key_pub.pem

# Sign firmware
openssl dgst -sha256 -sign firmware_signing_key.pem -out firmware.sig firmware.bin

# Verify firmware on device
openssl dgst -sha256 -verify firmware_signing_key_pub.pem -signature firmware.sig firmware.bin

# With certificate chain (more secure: rotate keys without changing root key)
# Root CA signs intermediate CA, which signs firmware signing key
openssl req -new -x509 -key root_ca.pem -out root_ca.crt -days 3650
openssl req -new -key intermediate_ca.pem -out intermediate_ca.csr
openssl x509 -req -in intermediate_ca.csr -CA root_ca.crt -CAkey root_ca.pem \
    -CAcreateserial -out intermediate_ca.crt -days 1825
openssl req -new -key firmware_signing.pem -out firmware_signing.csr
openssl x509 -req -in firmware_signing.csr -CA intermediate_ca.crt \
    -CAkey intermediate_ca.pem -CAcreateserial -out firmware_signing.crt -days 365
```

### Encrypted Firmware Updates

Firmware encryption prevents intellectual property theft and protects pre-update packages from analysis:

```c
// Encrypted firmware update flow
// Using AES-256-GCM for firmware encryption

// Build side:
void encrypt_firmware(const uint8_t *firmware, size_t len, 
                      const uint8_t *key, const uint8_t *iv,
                      uint8_t *ciphertext, uint8_t *tag) {
    // AES-256-GCM encryption
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, len,
                               iv, 12, NULL, 0,
                               firmware, ciphertext, 16, tag);
    mbedtls_gcm_free(&ctx);
}

// Device side:
// 1. Download encrypted firmware from update server
// 2. Decrypt with device-unique key (stored in SE or OTP)
// 3. Verify signature
// 4. Apply update

// MCUboot encrypted image support:
// Key encryption key (KEK) is stored in the secure element
// The firmware image is encrypted with a random data encryption key (DEK)
// The DEK is encrypted with the KEK and included in the image header
// During boot, MCUboot:
//   a. Reads the encrypted DEK from the image header
//   b. Decrypts DEK using KEK from secure element
//   c. Decrypts the firmware image using DEK
//   d. Verifies the firmware signature
//   e. Boots the firmware
```

## 4. Secure Element Integration

### ATECC608B Integration Best Practices

```c
// Production provisioning flow for ATECC608B
// Step 1: Generate device certificate signing request (CSR)
// Step 2: Sign CSR with manufacturer CA
// Step 3: Store signed certificate in slot 14/15

// Provisioning sequence (in secure factory environment):
void provision_atecc608b(void) {
    ATCAIfaceCfg cfg = atecc608b_default_config();
    atcab_init(&cfg);
    
    // 1. Generate device private key in slot 0 (never extractable)
    uint8_t public_key[64];
    atcab_genkey(ATCA_GENKEY_MODE_RANDOM, 0, public_key, NULL);
    
    // 2. Create CSR from device key
    atcac_cert_def_t cert_def = {
        .type = CERTTYPE_DEVICE,
        .template_id = 0,
        .chain_depth = 0,
        // ... certificate definition
    };
    uint8_t csr[256];
    size_t csr_len;
    atcab_create_csr(&cert_def, csr, &csr_len);
    
    // 3. Send CSR to manufacturer CA (over secure channel)
    // CA signs and returns certificate
    
    // 4. Store signed certificate in slot 14
    atcab_write_cert(&cert_def, signed_cert, signer_pub_key);
    
    // 5. Lock configuration zone (permanent!)
    atcab_lock_config_zone();
    
    // 6. Lock data zone (permanent!)
    atcab_lock_data_zone();
    
    // 7. Lock slot 0 (private key, permanent!)
    atcab_lock_data_slot(0);
}
```

### Device Identity and Certificate Provisioning

```
Manufacturer CA (Root)
  │
  ├─► Product Line CA
  │     │
  │     ├─► Device Certificate (per device)
  │     │     - Serial number
  │     │     - Public key (from SE slot 0)
  │     │     - Manufacturing date
  │     │     - Product ID
  │     │
  │     └─► Batch Certificate (optional)
  │           - Production batch ID
  │           - Manufacturing line
  
  └─► Commissioning CA
        │
        └─► Cloud Connection Certificate
              - Device identity
              - Cloud endpoint whitelist
```

## 5. OTA Update Security

### SUIT Manifest (RFC 9019)

The Software Updates for Internet of Things (SUIT) manifest defines the metadata for firmware updates:

```json
{
    "suit-manifest": {
        "manifest-version": "1",
        "manifest-sequence-number": 42,
        "suit-common": {
            "suit-dependencies": [],
            "suit-components": [
                {
                    "component-identifier": "0x08000000",
                    "component-class": "firmware"
                }
            ]
        },
        "suit-payload": {
            "suit-install": {
                "suit-parameter-image-size": 131072,
                "suit-parameter-uri": "https://updates.vendor.com/fw/v2.1.0.bin",
                "suit-parameter-image-digest": {
                    "algorithm": "sha256",
                    "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                }
            },
            "suit-validate": {
                "suit-condition-image-matches-digest": true,
                "suit-condition-version-minimum": "2.0.0"
            }
        },
        "suit-signature": {
            "algorithm": "ecdsa-p256",
            "key-id": "vendor-signing-key-1",
            "value": "3045022100a3b2c1..."
        }
    }
}
```

### SWUpdate for Embedded Linux

SWUpdate is a robust OTA update framework for embedded Linux:

```bash
# SWUpdate configuration (swupdate.cfg)
[globals]
verbose = true

[bootloader]
timeout = 300

# SWUpdate hardware compatibility file
# /etc/hardware-compatibility
# Format: major.minor
1.0

# SWUpdate image description (sw-description)
software =
{
    version = "2.1.0";
    
    images: ({
        filename = "rootfs.ext4.gz";
        device = "/dev/mmcblk0p2";
        type = "raw";
        compressed = true;
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    });
    
    scripts: ({
        filename = "update_script.sh";
        type = "postinstall";
    });
}
```

```python
# SWUpdate OTA update security checklist:
# 1. Verify image signature (RSA-3072 or ECDSA-P256)
# 2. Check hardware compatibility version
# 3. Verify minimum software version (anti-rollback)
# 4. Decrypt encrypted images (AES-256-GCM)
# 5. Verify image integrity (SHA-256)
# 6. Atomic update (A/B partition swap)
# 7. Fallback to previous version if update fails
# 8. Report update status to cloud
```

### A/B Partition Scheme

```
┌─────────────────────┬──────────────────────┐
│   Partition A        │   Partition B         │
│ ┌─────────────────┐ │ ┌─────────────────┐   │
│ │ Bootloader      │ │ │ Bootloader      │   │
│ ├─────────────────┤ │ ├─────────────────┤   │
│ │ Kernel A        │ │ │ Kernel B        │   │
│ ├─────────────────┤ │ ├─────────────────┤   │
│ │ Rootfs A        │ │ │ Rootfs B        │   │
│ ├─────────────────┤ │ ├─────────────────┤   │
│ │ Recovery        │ │ │ Recovery        │   │
│ └─────────────────┘ │ └─────────────────┘   │
│                     │                        │
│ Boot: A (active)    │ Boot: B (passive)      │
│ Next boot: B        │ Next boot: A           │
│ Status: Verified    │ Status: Pending update │
│ Tries: 3            │ Tries: 0               │
│ Version: 2.0.0      │ Version: 2.1.0         │
└─────────────────────┴──────────────────────┘
```

## 6. MQTT Broker Hardening

```bash
# Mosquitto MQTT broker hardening
# /etc/mosquitto/mosquitto.conf

# 1. Disable anonymous access
allow_anonymous false

# 2. Use TLS
listener 8883
cafile /etc/mosquitto/ca.crt
certfile /etc/mosquitto/server.crt
keyfile /etc/mosquitto/server.key
tls_version tlsv1.3

# 3. Require client certificates
require_certificate true
use_identity_as_username true

# 4. Configure ACLs
acl_file /etc/mosquitto/acl

# 5. Set maximum connections
max_connections 1000

# 6. Set maximum message size
max_packet_size 1048576

# 7. Disable outdated protocols
protocol mqtt

# ACL file (/etc/mosquitto/acl)
# Device can only publish to its own topic and subscribe to its command topic
user device_001
topic write sensor/device_001/data
topic read command/device_001

user device_002
topic write sensor/device_002/data
topic read command/device_002

# Admin can subscribe to all topics
user admin
topic read #

# /etc/mosquitto/passwords
# Generate with: mosquitto_passwd -c /etc/mosquitto/passwords admin
admin:$7$101$<hashed_password>
device_001:$7$101$<hashed_password>
```

### MQTT TLS Configuration

```bash
# Generate CA and certificates for MQTT broker
# 1. Create CA
openssl genpkey -algorithm RSA -out ca.key -pkeyopt rsa_keygen_bits:4096
openssl req -new -x509 -key ca.key -out ca.crt -days 3650 -subj "/CN=IoT CA"

# 2. Create server certificate
openssl genpkey -algorithm RSA -out server.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -key server.key -out server.csr -subj "/CN=mqtt.example.com"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 -extfile server_ext.cnf

# server_ext.cnf:
# subjectAltName = DNS:mqtt.example.com, IP:192.168.1.1
# extendedKeyUsage = serverAuth

# 3. Create client certificates (per device)
openssl genpkey -algorithm RSA -out device_001.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -key device_001.key -out device_001.csr \
    -subj "/CN=device_001/O=IoT Devices"
openssl x509 -req -in device_001.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out device_001.crt -days 365 -extfile client_ext.cnf

# client_ext.cnf:
# extendedKeyUsage = clientAuth
```

## 7. Minimum Viable Security for IoT (OWASP IoT Top 10)

### OWASP IoT Top 10 (2024)

| # | Vulnerability | Mitigation |
|---|--------------|------------|
| I1 | Weak, Guessable, or Hardcoded Passwords | Unique per-device passwords, no defaults, minimum 8 chars |
| I2 | Insecure Network Services | Disable unnecessary services, use TLS, mutual auth |
| I3 | Insecure Ecosystem Interfaces | AuthN/AuthZ on all APIs, input validation, rate limiting |
| I4 | Lack of Secure Update Mechanism | Signed updates, encrypted transport, rollback prevention |
| I5 | Use of Insecure or Outdated Components | SBOM, vulnerability scanning, timely patching |
| I6 | Insufficient Privacy Protection | Data minimization, encryption, consent management |
| I7 | Insecure Data Transfer and Storage | TLS, encryption at rest, certificate pinning |
| I8 | Lack of Device Management | Inventory, lifecycle management, remote wipe |
| I9 | Insecure Default Configuration | Change defaults, disable debug, least privilege |
| I10 | Lack of Physical Hardening | Disable debug ports, encase in epoxy, tamper detection |

### Practical Security Baseline for IoT

```yaml
# Minimum IoT security configuration checklist

# 1. Authentication
- No default passwords
- Unique credential per device (derived from SE)
- Rate-limited login (5 attempts, then 5-minute lockout)
- Multi-factor auth for admin access

# 2. Network security
- TLS 1.3 for all external communication
- Certificate pinning on device and cloud
- mTLS (mutual TLS) for device-to-cloud
- Network segmentation (devices on separate VLAN)
- Disable unnecessary services (Telnet, FTP, UPnP)
- Firewall: deny-all, allow-by-exception

# 3. Firmware security
- Secure boot (TF-A, MCUboot, or U-Boot verified boot)
- Signed firmware images (RSA-3072 or ECDSA-P256)
- Encrypted firmware updates (AES-256-GCM)
- Rollback prevention (version counter in OTP/fuse)
- SBOM (Software Bill of Materials)

# 4. Hardware security
- Debug access disabled in production (SWD/JTAG locked)
- Unique device identity in OTP/eFuse
- Secure element for key storage (ATECC608B, OPTIGA)
- Tamper detection (case open switch, voltage monitor)

# 5. Data protection
- Encryption at rest (AES-256-XTS for flash, AES-256 for files)
- Encryption in transit (TLS 1.3)
- Data minimization (only collect needed data)
- Secure data deletion (crypto erase)
- Privacy by design (GDPR compliance)

# 6. Lifecycle management
- Vulnerability disclosure program (VDP)
- Security update policy (minimum 5 years of updates)
- End-of-life plan (secure decommissioning)
- Incident response plan
- Regular security audit (annual penetration test)

# 7. Logging and monitoring
- Centralized logging (syslog/CEF)
- Anomaly detection (behavioral baselines)
- Remote attestation (PCR-based boot verification)
- Firmware version monitoring
- Failed authentication alerting
```

## 8. IoT Security Labels and Regulations

### EU Cyber Resilience Act (CRA)

The EU Cyber Resilience Act (proposed 2022, expected enforcement 2027) mandates cybersecurity requirements for all products with digital elements sold in the EU:

**Key requirements**:
1. **Security by design**: Products must be designed with appropriate cybersecurity measures
2. **Security by default**: Products must be secure out of the box (no default passwords)
3. **SBOM**: Manufacturers must provide a Software Bill of Materials
4. **Vulnerability handling**: Report vulnerabilities to ENISA within 24 hours of awareness
5. **Security updates**: Free security updates for at least 5 years
6. **Conformity assessment**: CE marking requires cybersecurity assessment
7. **Incident reporting**: Report active exploitation within 72 hours

**Exemptions**: Products already covered by sector-specific regulation (medical devices under MDR, vehicles under UNECE WP.29).

### UK PSTI Act (Product Security and Telecommunications Infrastructure Act 2022)

The UK PSTI Act requires:
1. No default passwords (passwords must be unique per device or user-defined)
2. Vulnerability disclosure policy (clear contact point for reporting vulnerabilities)
3. Information on minimum update period (how long security updates will be provided)

Enforcement: Fines up to £10 million or 4% of worldwide revenue.

### California IoT Security Law (SB-327)

Effective January 1, 2020. Requires:
1. "Reasonable security features" appropriate to the device's function
2. Either: unique pre-installed passwords per device, or require the user to change the password on first use
3. Applies to any device connected to the Internet sold in California

### NIST Baseline for IoT Devices (NIST SP 800-53 / NISTIR 8259)

NISTIR 8259 provides a baseline of cybersecurity requirements for IoT device manufacturers:

**Core baseline**:
1. Unique device identifier (UDI)
2. Secure configuration (changeable defaults)
3. Data protection (encryption)
4. Logging (audit trail)
5. Authorized access (authentication, authorization)

**Extended baseline** (for higher-risk devices):
6. Cryptographic verification of software and firmware
7. Secure update mechanism
8. System event and fault logging
9. Self-test and health monitoring
10. Automatic recovery from failure

### IoT Security Certification Schemes

| Scheme | Region | Requirements | Status |
|--------|--------|-------------|--------|
| ETSI EN 303 645 | Europe | Consumer IoT baseline | Published (2020) |
| EU CRA | EU | All connected products | Proposed (2022) |
| UK PSTI | UK | Consumer IoT minimum | Law (2022) |
| NISTIR 8259 | USA | IoT baseline | Published (2020) |
| UL 2900 | USA | Network-connected products | Published |
| ISO 27400 | International | IoT security guidelines | Published (2022) |
| IEC 62443 | International | Industrial IoT (IIoT) | Published |

## 9. References

- ARM Trusted Firmware: trustedfirmware.org
- MCUboot: mcuboot.com
- ATECC608B Datasheet: microchip.com
- OPTIGA Trust M: infineon.com
- SUIT Manifest (RFC 9019): datatracker.ietf.org
- NISTIR 8259: csrc.nist.gov
- ETSI EN 303 645: etsi.org
- OWASP IoT Top 10: owasp.org/www-project-iot-top-10
- EU CRA: digital-strategy.ec.europa.eu
- UK PSTI Act: gov.uk/guidance/product-security-and-telecommunications-infrastructure
- California SB-327: leginfo.legislature.ca.gov
- TF-M (Trusted Firmware for Cortex-M): trustedfirmware.org
- SWUpdate: swupdate.org

## References

1. ARM Trusted Firmware Documentation. https://trustedfirmware.org/
2. MCUboot: Secure Bootloader for Cortex-M. https://mcuboot.com/
3. ATECC608B Datasheet. Microchip Technology. https://www.microchip.com/
4. OPTIGA Trust M Documentation. Infineon Technologies. https://www.infineon.com/
5. SUIT Manifest (RFC 9019): Software Updates for Internet of Things. IETF. https://datatracker.ietf.org/doc/html/rfc9019
6. NISTIR 8259: Foundational Cybersecurity Activities for IoT Device Manufacturers. National Institute of Standards and Technology (2020). https://csrc.nist.gov/publications/detail/nistir/8259/final
7. ETSI EN 303 645: Cyber Security for Consumer Internet of Things: Baseline Requirements. European Telecommunications Standards Institute (2020). https://www.etsi.org/
8. OWASP IoT Top 10 (2014, 2024 drafts). https://owasp.org/www-project-top-ten/
9. EU Cyber Resilience Act. European Commission (2022). https://digital-strategy.ec.europa.eu/
10. UK Product Security and Telecommunications Infrastructure Act (PSTI) (2022). https://www.gov.uk/government/organisations/department-for-science-innovation-and-technology
11. California SB-327: Information Privacy: Connected Devices. https://leginfo.legislature.ca.gov/
12. TF-M (Trusted Firmware for Cortex-M). https://trustedfirmware.org/
13. SWUpdate: Software Update for Embedded Linux. https://swupdate.org/
14. NIST SP 800-183: Networks of Things. National Institute of Standards and Technology.
15. IEC 62443: Industrial Communication Networks — Network and System Security.
16. FDA Premarket Cybersecurity Guidance (2023). U.S. Food and Drug Administration.
17. ARM Security Technology — Building a Secure System using TrustZone for ARMv8-M (ARM DEN0028A). ARM Limited.
18. RISC-V Privileged Architecture Specification. RISC-V International. https://riscv.org/
19. *The Hardware Hacking Handbook* by Colin O'Flynn and Jasper van Woudenberg. No Starch Press (2022).
20. *Practical IoT Hacking* by Fotios Chantzis et al. No Starch Press (2021).
21. ISO 27400: Security and Privacy for IoT. International Organization for Standardization (2022).
22. UL 2900: Standard for Cybersecurity of Network-Connectable Products. Underwriters Laboratories.
23. DEF CON IoT Village Presentations. https://iotvillage.org/
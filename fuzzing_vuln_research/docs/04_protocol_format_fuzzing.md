# Protocol and Format Fuzzing

## 1. TLS Fuzzing

### 1.1 Overview

Transport Layer Security (TLS) is the backbone of Internet encryption. TLS implementations are high-value targets because bugs can compromise encrypted communications. TLS fuzzing targets the handshake protocol, record layer, and state machine transitions.

### 1.2 TLS State Machine Fuzzing

TLS is a stateful protocol with a complex state machine. The handshake involves:

```
ClientHello → ServerHello → Certificate → ServerKeyExchange →
ServerHelloDone → ClientKeyExchange → ChangeCipherSpec → Finished →
ChangeCipherSpec → Finished → [Application Data]
```

A TLS fuzzer must:
1. Generate valid and invalid state transitions
2. Mutate handshake messages at the field level
3. Test unexpected message ordering (e.g., receiving Finished before ChangeCipherSpec)
4. Test version downgrade and renegotiation

### 1.3 tlslite-ng Fuzzing

tlslite-ng is a pure-Python TLS implementation used as a fuzzing target:

```python
from tlslite.api import TLSConnection, HandshakeSettings
from FuzzedDataProvider import FuzzedDataProvider

def fuzz_tls_handshake(data):
    fdp = FuzzedDataProvider(data)
    
    # Create a mock TLS connection
    conn = TLSConnection(mock_socket())
    
    # Fuzz handshake parameters
    version = fdp.ConsumeIntegralInRange(0x0300, 0x0304)  # SSL3.0 - TLS1.3
    cipher_suites = fdp.ConsumeBytes(fdp.ConsumeIntegralInRange(0, 64))
    
    # Feed fuzzed ClientHello
    client_hello = build_client_hello(version, cipher_suites, ...)
    conn.handshakeClientPure(channel=client_hello)
```

### 1.4 NSS Fuzzing

Mozilla's NSS (Network Security Services) library is fuzzed extensively through OSS-Fuzz:

```c
// NSS TLS fuzz target (simplified)
#include <ssl.h>
#include <sslproto.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create a mock SSL socket with fuzz data as input
    PRFileDesc *fd = create_mock_socket(data, size);
    
    // Configure SSL
    SSL_VersionRangeSet(fd, &versions);
    SSL_CipherPrefSet(fd, cipher, PR_TRUE);
    
    // Perform handshake
    SSL_ForceHandshake(fd);
    
    // Read application data
    char buf[4096];
    PR_Read(fd, buf, sizeof(buf));
    
    // Cleanup
    PR_Close(fd);
    return 0;
}
```

### 1.5 Notable TLS Bugs Found by Fuzzing

- **CVE-2014-0160 (Heartbleed)**: OpenSSL buffer over-read in the TLS heartbeat extension. While not found by fuzzing, it inspired massive TLS fuzzing efforts.
- **CVE-2016-0800 (DROWN)**: SSLv2 protocol vulnerability allowing TLS decryption.
- **CVE-2016-6309**: OpenSSL memory safety violation in `MDC2_Update()`.
- **Chromium TLS bugs**: Multiple TLS parsing bugs found by ClusterFuzz, including OOB reads in certificate parsing and state machine violations.

## 2. SSH Protocol Fuzzing

### 2.1 Overview

SSH (Secure Shell) is a network protocol for secure remote access. The protocol consists of:
- **Transport layer**: Key exchange, server authentication
- **Authentication layer**: User authentication (password, public key, keyboard-interactive)
- **Connection layer**: Channels, port forwarding, SFTP

### 2.2 SSH Fuzzing Targets

- **Key exchange**: Fuzz the DH group exchange, curve25519 key exchange, ECDH parameters
- **Authentication**: Fuzz public key blobs, password strings, keyboard-interactive responses
- **Channel handling**: Fuzz channel open requests, window size negotiations, extended data
- **Packet layer**: Fuzz the SSH binary packet protocol (length fields, padding, MAC)

### 2.3 OpenSSH Fuzzing with libFuzzer

```c
#include <sshbuf.h>
#include <sshkey.h>
#include <ssh2.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct sshbuf *buf = sshbuf_from(data, size);
    
    // Fuzz key parsing
    struct sshkey *key = NULL;
    if (sshkey_from_blob(data, size, &key) == 0) {
        sshkey_free(key);
    }
    
    // Fuzz kex initialization
    struct kex *kex = NULL;
    if (kex_setup(NULL, buf, &kex) == 0) {
        kex_free(kex);
    }
    
    sshbuf_free(buf);
    return 0;
}
```

### 2.4 Notable SSH Bugs Found by Fuzzing

- **CVE-2023-25136**: OpenSSH double-free in `kex_setup` during key exchange. Found by OSS-Fuzz/libFuzzer.
- **CVE-2023-38240**: OpenSSH SSH2_MSG_KEX_DH_GEX_REQUEST parsing OOB read. Found by fuzzing.
- **PuTTY vulnerabilities**: Multiple integer overflows and buffer overflows in SSH2 key exchange found by fuzzing.

## 3. HTTP/2 Fuzzing

### 3.1 Overview

HTTP/2 is a binary protocol with multiple frame types, header compression (HPACK), flow control, and stream multiplexing. Its complexity makes it a rich fuzzing target.

### 3.2 HTTP/2 Frame Types

| Frame Type | Code | Fuzzing Surface |
|-----------|------|-----------------|
| DATA | 0x0 | Stream data, padding, flow control |
| HEADERS | 0x1 | HPACK-encoded headers, priority |
| PRIORITY | 0x2 | Stream dependencies, weight |
| RST_STREAM | 0x3 | Error codes |
| SETTINGS | 0x4 | Parameter values, ACK handling |
| PUSH_PROMISE | 0x5 | Promised stream ID, headers |
| PING | 0x6 | Opaque data |
| GOAWAY | 0x7 | Last stream ID, error code |
| WINDOW_UPDATE | 0x8 | Increment value, flow control |
| CONTINUATION | 0x9 | Header block fragments |

### 3.3 HTTP/2 Fuzzing Approach

```c
#include <nghttp2/nghttp2.h>

typedef struct {
    nghttp2_session *session;
    uint8_t *data;
    size_t size;
    size_t pos;
} h2_fuzz_ctx;

static ssize_t send_callback(nghttp2_session *session,
                              const uint8_t *data, size_t len,
                              int flags, void *user_data) {
    return len;  // Consume all output
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    nghttp2_session_callbacks *callbacks;
    nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
    
    nghttp2_session *session;
    nghttp2_session_client_new(&session, callbacks, NULL);
    
    // Feed fuzz data as incoming frames
    nghttp2_session_mem_recv(session, data, size);
    
    nghttp2_session_del(session);
    nghttp2_session_callbacks_del(callbacks);
    return 0;
}
```

### 3.4 Notable HTTP/2 Bugs Found by Fuzzing

- **CVE-2019-9512 (Ping Flood)**: Exploiting HTTP/2 ping to cause denial of service.
- **CVE-2019-9513 (Resource Loop)**: HTTP/2 request smuggling via manipulation of flow control windows.
- **CVE-2023-44487 (HTTP/2 Rapid Reset)**: Exploiting stream cancellation to bypass flow control and cause DoS. This was found through analysis of anomalous traffic patterns, but fuzzing could have found it.

## 4. DNS Protocol Fuzzing

### 4.1 Overview

DNS (Domain Name System) is the Internet's phone book. DNS implementations must parse wire-format messages with complex structures (question sections, resource records, EDNS options). DNS parsing bugs can affect the entire Internet.

### 4.2 DNS Wire Format

```
DNS Message:
┌──────────────────────────────────────────┐
│ Header (12 bytes)                         │
│   ID (16-bit)                            │
│   Flags (16-bit): QR, OPCODE, AA, TC,    │
│     RD, RA, Z, RCODE                     │
│   QDCOUNT (16-bit)                       │
│   ANCOUNT (16-bit)                        │
│   NSCOUNT (16-bit)                        │
│   ARCOUNT (16-bit)                        │
├──────────────────────────────────────────┤
│ Question Section                          │
│   QNAME (variable, DNS wire format)      │
│   QTYPE (16-bit)                          │
│   QCLASS (16-bit)                         │
├──────────────────────────────────────────┤
│ Answer/Authority/Additional Sections      │
│   RR: NAME, TYPE, CLASS, TTL, RDATA      │
└──────────────────────────────────────────┘
```

### 4.3 DNS Fuzzing with libFuzzer

```c
#include <ldns/ldns.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Parse DNS wire format
    ldns_pkt *pkt = NULL;
    if (ldns_wire2pkt(&pkt, data, size) != LDNS_STATUS_OK) {
        return 0;
    }
    
    // Try to access all sections
    ldns_rr_list *questions = ldns_pkt_question(pkt);
    ldns_rr_list *answers   = ldns_pkt_answer(pkt);
    ldns_rr_list *authority = ldns_pkt_authority(pkt);
    ldns_rr_list *additional = ldns_pkt_additional(pkt);
    
    // Iterate through records
    for (size_t i = 0; i < ldns_rr_list_rr_count(answers); i++) {
        ldns_rr *rr = ldns_rr_list_rr(answers, i);
        ldns_rdf *rdf = ldns_rr_rdf(rr, 0);
        if (rdf) ldns_rdf_print(stderr, rdf);
    }
    
    ldns_pkt_free(pkt);
    return 0;
}
```

### 4.4 Notable DNS Bugs Found by Fuzzing

- **CVE-2023-2828**: BIND 9 DNS resolver OOB read in DNS message parsing. Found by fuzzing.
- **CVE-2023-3341**: BIND 9 AD (Authenticated Denial of existence) handling OOB read. Found by fuzzing.
- **CVE-2020-8617**: BIND 9 `tcpdial` OOB read in zone transfer handling. Found by OSS-Fuzz.
- **PowerDNS bugs**: Multiple DNS parsing bugs found by OSS-Fuzz fuzzing campaigns.

## 5. Wi-Fi Protocol Fuzzing (IEEE 802.11)

### 5.1 Overview

IEEE 802.11 (Wi-Fi) frame fuzzing targets the MAC layer management, authentication, association, and encryption protocols. Wi-Fi fuzzing requires either:
- A wireless NIC in monitor/promiscuous mode
- A software-defined radio (SDR) platform
- A virtual Wi-Fi stack (e.g., `hwsim` in Linux)

### 5.2 802.11 Frame Structure

```
┌────────────────────────────────────────────────────┐
│ Frame Control (2 bytes)                             │
│   Protocol Version (2 bits)                        │
│   Type (2 bits): Mgmt, Ctrl, Data                  │
│   Subtype (4 bits): Assoc, Auth, Deauth, etc.      │
│   ToDS, FromDS, MoreFrag, Retry, PM, MoreData,     │
│   Protected, Order                                  │
├────────────────────────────────────────────────────┤
│ Duration/ID (2 bytes)                               │
├────────────────────────────────────────────────────┤
│ Address 1-4 (6 bytes each)                          │
├────────────────────────────────────────────────────┤
│ Sequence Control (2 bytes)                          │
├────────────────────────────────────────────────────┤
│ Frame Body (variable)                              │
│   For management frames:                            │
│     Fixed fields + IE (Information Elements) chain  │
├────────────────────────────────────────────────────┤
│ FCS (4 bytes)                                       │
└────────────────────────────────────────────────────┘
```

### 5.3 Linux `hwsim` Wi-Fi Fuzzing

Linux's `mac80211_hwsim` module creates virtual Wi-Fi interfaces that can be fuzzed without physical hardware:

```bash
# Load hwsim module
modprobe mac80211_hwsim radios=2

# Create a monitor interface
iw dev wlan0 interface add mon0 type monitor
ifconfig mon0 up

# Inject fuzzed frames
# Using scapy or custom injection tool
python3 wifi_fuzz.py mon0
```

```python
from scapy.all import *
import random

def fuzz_wifi(iface):
    # Generate fuzzed management frames
    frame_types = [0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b]
    
    for _ in range(10000):
        # Random management frame subtype
        fc = random.choice(frame_types) << 4 | 0x00
        
        # Build frame with random IEs
        ies = b""
        ie_types = list(range(256))
        for ie_type in random.sample(ie_types, min(10, len(ie_types))):
            ie_len = random.randint(0, 255)
            ie_data = bytes([random.randint(0, 255) for _ in range(ie_len)])
            ies += bytes([ie_type, ie_len]) + ie_data
        
        frame = RadioTap() / Dot11(
            type=0, subtype=random.randint(0, 15),
            addr1="ff:ff:ff:ff:ff:ff",
            addr2="00:11:22:33:44:55",
            addr3="00:11:22:33:44:55"
        ) / Raw(load=ies)
        
        sendp(frame, iface=iface, verbose=0)
```

### 5.4 Notable Wi-Fi Bugs

- **CVE-2019-11506**: Linux `cw1200` driver heap overflow in SDIO message handling.
- **Kr00k (CVE-2019-15126)**: Broadcom and Cypress Wi-Fi chips used all-zero encryption key after disconnection.
- **FragAttacks (2021)**: Multiple Wi-Fi fragmentation and aggregation vulnerabilities across implementations.

## 6. Bluetooth Fuzzing

### 6.1 Overview

Bluetooth is a short-range wireless protocol with multiple layers:
- **L2CAP**: Logical Link Control and Adaptation Protocol (multiplexing, segmentation)
- **ATT**: Attribute Protocol (GATT operations: read, write, notify, indicate)
- **SMP**: Security Manager Protocol (pairing, key exchange)
- **RFCOMM**: Serial port emulation
- **OBEX**: Object exchange protocol

### 6.2 L2CAP Fuzzing

L2CAP is the core Bluetooth protocol layer:

```c
// L2CAP fuzz target (simplified)
#include <bluetooth/l2cap.h>
#include <bluetooth/hci.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(l2cap_hdr_t)) return 0;
    
    l2cap_hdr_t *hdr = (l2cap_hdr_t *)data;
    uint16_t psm = le16toh(hdr->psm);
    uint16_t cid = le16toh(hdr->cid);
    uint16_t len = le16toh(hdr->len);
    
    const uint8_t *payload = data + sizeof(l2cap_hdr_t);
    size_t payload_len = size - sizeof(l2cap_hdr_t);
    
    if (len > payload_len) return 0;
    
    // Process based on channel ID
    switch (cid) {
        case L2CAP_CID_ATT:
            process_att(payload, len);
            break;
        case L2CAP_CID_SMP:
            process_smp(payload, len);
            break;
        case L2CAP_CID_SIGNALING:
            process_signaling(payload, len);
            break;
        default:
            process_l2cap(psm, cid, payload, len);
            break;
    }
    return 0;
}
```

### 6.3 ATT (Attribute Protocol) Fuzzing

ATT is the protocol behind BLE (Bluetooth Low Energy) GATT services:

```c
// ATT fuzz target
typedef struct __attribute__((packed)) {
    uint8_t  opcode;
    uint16_t handle;
    uint16_t value_handle;
    uint8_t  data[];
} att_pdu_t;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    
    uint8_t opcode = data[0];
    const uint8_t *params = data + 1;
    size_t params_len = size - 1;
    
    // ATT opcodes
    switch (opcode & 0x3F) {
        case ATT_OP_READ_BY_TYPE_REQ:
        case ATT_OP_READ_BY_TYPE_RSP:
        case ATT_OP_READ_REQ:
        case ATT_OP_READ_RSP:
        case ATT_OP_WRITE_REQ:
        case ATT_OP_WRITE_RSP:
        case ATT_OP_PREPARE_WRITE_REQ:
        case ATT_OP_EXECUTE_WRITE_REQ:
            process_att_pdu(opcode, params, params_len);
            break;
    }
    return 0;
}
```

### 6.4 Notable Bluetooth Bugs Found by Fuzzing

- **CVE-2020-0022**: Android Bluetooth heap overflow in `BtMhcHciRsp` message handling. Found by fuzzing.
- **CVE-2020-26555**: Bluetooth BR/EDR PIN pairing vulnerability (authentication bypass).
- **CVE-2023-27249**: BlueZ `g_dbus_object_type_add_interface` OOB access in GATT handling.
- **BleedingTooth (CVE-2020-12351)**: Linux Bluetooth heap overflow in `l2cap_parse_conf_rsp`. Found by Google's security team.

## 7. Binary Format Fuzzing

### 7.1 Overview

Binary format parsing is ubiquitous: image viewers, document readers, archive tools, and media players all parse binary formats. These parsers are prime fuzzing targets because:
- They must process untrusted input from external sources
- They handle complex, nested data structures
- They have a long history of security vulnerabilities

### 7.2 JPEG Fuzzing

JPEG format structure:
```
SOI (0xFFD8) → [Marker segments] → Entropy-coded data → EOI (0xFFD9)

Markers:
- APP0 (0xFFE0): JFIF
- APP1 (0xFFE1): EXIF
- DQT (0xFFDB): Quantization tables
- SOF0 (0xFFC0): Start of frame (baseline)
- DHT (0xFFC4): Huffman tables
- SOS (0xFFDA): Start of scan
```

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Use libjpeg-turbo for decompression
    jpeg_decompress_struct cinfo;
    jpeg_error_mgr jerr;
    
    cinfo.err = jpeg_std_error(&jerr);
    jpeg_create_decompress(&cinfo);
    jpeg_mem_src(&cinfo, data, size);
    
    if (jpeg_read_header(&cinfo, TRUE) != JPEG_HEADER_OK) {
        jpeg_destroy_decompress(&cinfo);
        return 0;
    }
    
    jpeg_start_decompress(&cinfo);
    
    // Read scanlines
    JSAMPARRAY buffer = (*cinfo.mem->alloc_sarray)
        ((j_common_ptr)&cinfo, JPOOL_IMAGE,
         cinfo.output_width * cinfo.output_components, 1);
    
    while (cinfo.output_scanline < cinfo.output_height) {
        jpeg_read_scanlines(&cinfo, buffer, 1);
    }
    
    jpeg_finish_decompress(&cinfo);
    jpeg_destroy_decompress(&cinfo);
    return 0;
}
```

### 7.3 PNG Fuzzing

```c
#include <png.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    png_image image;
    memset(&image, 0, sizeof(image));
    image.version = PNG_IMAGE_VERSION;
    
    // Decode PNG
    if (png_image_begin_read_from_memory(&image, data, size)) {
        image.format = PNG_FORMAT_RGBA;
        png_bytep buffer = malloc(PNG_IMAGE_SIZE(image));
        if (buffer) {
            png_image_finish_read(&image, NULL, buffer, 0, NULL);
            free(buffer);
        }
    }
    
    png_image_free(&image);
    return 0;
}
```

### 7.4 PDF Fuzzing

PDF is one of the most complex binary formats in widespread use. It combines:
- A text-based header and cross-reference table
- Binary streams (FlateDecode, DCTDecode, etc.)
- A rich object model (dictionaries, arrays, streams, names)
- Interactive elements (JavaScript, forms, annotations)

```c
// PDFium fuzz target (Chromium's PDF renderer)
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    IPDFium *pdf = PDFium_Create();
    if (!pdf) return 0;
    
    // Load document
    FPDF_DOCUMENT doc = FPDF_LoadMemDocument(pdf, data, size, NULL);
    if (!doc) {
        PDFium_Destroy(pdf);
        return 0;
    }
    
    // Iterate pages
    int page_count = FPDF_GetPageCount(doc);
    for (int i = 0; i < page_count && i < 10; i++) {
        FPDF_PAGE page = FPDF_LoadPage(doc, i);
        if (page) {
            // Render page to bitmap
            FPDF_BITMAP bitmap = FPDF_Bitmap_Create(640, 480, 0);
            FPDF_RenderPageBitmap(bitmap, page, 0, 0, 640, 480, 0, 0);
            FPDF_Bitmap_Destroy(bitmap);
            FPDF_ClosePage(page);
        }
    }
    
    FPDF_CloseDocument(doc);
    PDFium_Destroy(pdf);
    return 0;
}
```

### 7.5 ELF Fuzzing

ELF (Executable and Linkable Format) fuzzing targets:
- **Linkers** (ld, lld): Parse ELF objects and produce executables
- **Loaders** (ld-linux, dyld): Parse ELF headers and load programs
- **Debuggers** (gdb, lldb): Parse DWARF debug information
- **Analysis tools** (readelf, objdump): Display ELF information

```c
#include <elf.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(Elf64_Ehdr)) return 0;
    
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)data;
    
    // Validate ELF magic
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) return 0;
    
    // Parse program headers
    if (ehdr->e_phoff + ehdr->e_phnum * sizeof(Elf64_Phdr) > size) return 0;
    
    Elf64_Phdr *phdr = (Elf64_Phdr *)(data + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            // Process loadable segment
            if (phdr[i].p_offset + phdr[i].p_filesz <= size) {
                process_segment(data + phdr[i].p_offset, phdr[i].p_filesz);
            }
        }
    }
    
    // Parse section headers
    if (ehdr->e_shoff + ehdr->e_shnum * sizeof(Elf64_Shdr) > size) return 0;
    
    Elf64_Shdr *shdr = (Elf64_Shdr *)(data + ehdr->e_shoff);
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_SYMTAB) {
            // Process symbol table
            process_symbols(data + shdr[i].sh_offset, shdr[i].sh_size);
        }
    }
    
    return 0;
}
```

### 7.6 ZIP/Archive Fuzzing

ZIP is ubiquitous (ZIP, JAR, APK, DOCX, ODT are all ZIP-based):

```c
#include <zip.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    zip_error_t error;
    zip_source_t *src = zip_source_buffer_create(data, size, 0, &error);
    if (!src) return 0;
    
    zip_t *za = zip_open_from_source(src, 0, &error);
    if (!za) {
        zip_source_free(src);
        return 0;
    }
    
    // Iterate entries
    zip_int64_t num_entries = zip_get_num_entries(za, 0);
    for (zip_int64_t i = 0; i < num_entries && i < 100; i++) {
        zip_stat_t st;
        zip_stat_index(za, i, 0, &st);
        
        if (st.size > 0 && st.size < 1024 * 1024) {
            char *buf = malloc(st.size);
            if (buf) {
                zip_file_t *zf = zip_fopen_index(za, i, 0);
                if (zf) {
                    zip_fread(zf, buf, st.size);
                    zip_fclose(zf);
                }
                free(buf);
            }
        }
    }
    
    zip_close(za);
    return 0;
}
```

### 7.7 Notable Binary Format Bugs

- **CVE-2019-13135**: libpng use-after-free in `png_image_free`. Found by OSS-Fuzz.
- **CVE-2022-26733**: Apple ImageIO heap overflow in TIFF parsing. Found by fuzzing.
- **CVE-2023-3420**: Chrome PDFium type confusion in annotation handling. Found by ClusterFuzz.
- **CVE-2023-43642**: libarchive heap overflow in RAR4 filter handling. Found by OSS-Fuzz.

## 8. IPC Fuzzing

### 8.1 Mojo IPC (Chromium)

Mojo is Chromium's IPC system, replacing Chrome's legacy IPC. It uses message pipes with typed message validation:

```c
// Mojo fuzz target (Chromium)
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    mojo::InvalidMessageHandler handler;
    
    // Parse as Mojo message
    mojo::Message message;
    if (!mojo::Message::ParseFromWire(data, size, &message)) {
        return 0;
    }
    
    // Dispatch to interface handler
    handler.OnMessage(std::move(message));
    return 0;
}
```

### 8.2 Binder IPC (Android)

Binder is Android's IPC mechanism. Fuzzing Binder targets the ioctl interface:

```c
#include <linux/android/binder.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int fd = open("/dev/binder", O_RDWR);
    if (fd < 0) return 0;
    
    // Fuzz BINDER_WRITE_READ
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    
    bwr.write_buffer = (uintptr_t)data;
    bwr.write_size = size;
    bwr.write_consumed = 0;
    bwr.read_buffer = (uintptr_t)malloc(4096);
    bwr.read_size = 4096;
    bwr.read_consumed = 0;
    
    ioctl(fd, BINDER_WRITE_READ, &bwr);
    
    free((void *)bwr.read_buffer);
    close(fd);
    return 0;
}
```

### 8.3 XPC (macOS)

XPC is Apple's IPC mechanism on macOS/iOS:

```c
#include <xpc/xpc.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create an XPC object from fuzz data
    xpc_object_t obj = xpc_create_from_plist_data(data, size);
    if (!obj) return 0;
    
    // Access object properties
    xpc_type_t type = xpc_get_type(obj);
    if (type == XPC_TYPE_DICTIONARY) {
        xpc_dictionary_apply(obj, ^(const char *key, xpc_object_t value) {
            // Recursively access nested objects
            xpc_type_t vtype = xpc_get_type(value);
            return true;
        });
    }
    
    xpc_release(obj);
    return 0;
}
```

## 9. Structure-Aware Fuzzing with Protobuf

### 9.1 Overview

Structure-aware fuzzing with protobuf (libprotobuf-mutator) ensures that fuzz inputs are always structurally valid, enabling deeper exploration of the target's logic rather than its input validation.

### 9.2 Protocol Fuzzing with LPM

```protobuf
syntax = "proto2";

message TLSRecord {
    required uint32 content_type = 1;  // 20-24
    required uint32 version = 2;       // 0x0300-0x0304
    required bytes payload = 3;
}

message TLSHandshake {
    required uint32 msg_type = 1;
    required uint32 length = 2;
    required bytes body = 3;
}

message TLSMessage {
    oneof msg {
        TLSRecord record = 1;
        TLSHandshake handshake = 2;
    }
}

message TLSSession {
    repeated TLSMessage messages = 1;
}
```

```cpp
#include "tls.pb.h"
#include <libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h>

DEFINE_PROTO_FUZZER(const TLSSession &session) {
    for (const auto &msg : session.messages()) {
        if (msg.has_record()) {
            process_tls_record(msg.record());
        } else if (msg.has_handshake()) {
            process_tls_handshake(msg.handshake());
        }
    }
}
```

## 10. Peach Fuzzer for Binary Protocols

### 10.1 Overview

Peach Fuzzer (now Peachi) is a protocol-aware fuzzer that uses XML-based data models to describe binary protocols. It's particularly effective for network protocol fuzzing.

### 10.2 Peach Data Model Example

```xml
<Peach xmlns="http://peachfuzzer.com/2012/Peach" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <DataModel name="TCPHeader">
    <Number name="SrcPort" size="16" endian="big"/>
    <Number name="DstPort" size="16" endian="big"/>
    <Number name="SeqNum" size="32" endian="big"/>
    <Number name="AckNum" size="32" endian="big"/>
    <Number name="DataOffset" size="4"/>
    <Number name="Reserved" size="3"/>
    <Flags name="Flags" size="9">
      <Flag name="NS" position="0" size="1"/>
      <Flag name="CWR" position="1" size="1"/>
      <Flag name="ECE" position="2" size="1"/>
      <Flag name="URG" position="3" size="1"/>
      <Flag name="ACK" position="4" size="1"/>
      <Flag name="PSH" position="5" size="1"/>
      <Flag name="RST" position="6" size="1"/>
      <Flag name="SYN" position="7" size="1"/>
      <Flag name="FIN" position="8" size="1"/>
    </Flags>
    <Number name="WindowSize" size="16" endian="big"/>
    <Number name="Checksum" size="16" endian="big"/>
    <Number name="UrgentPtr" size="16" endian="big"/>
  </DataModel>

  <StateModel name="TCPHandshake" initialState="SendSYN">
    <State name="SendSYN">
      <Action type="output">
        <DataModel ref="TCPHeader">
          <Field name="Flags.SYN" value="1"/>
        </DataModel>
      </Action>
      <Action type="input">
        <DataModel ref="TCPHeader"/>
      </Action>
    </State>
  </StateModel>
</Peach>
```

### 10.3 Peach Pit Elements

| Element | Description |
|---------|-------------|
| `DataModel` | Describes the structure of a message |
| `StateModel` | Describes the protocol state machine |
| `Publisher` | Defines the transport (TCP, UDP, file) |
| `Agent` | Runs on the target machine, monitors for crashes |
| `Strategy` | Fuzzing strategy (sequential, random) |
| `Mutator` | Mutation operators (flip, swap, insert, etc.) |

## References

[1] RFC 8446. *The Transport Layer Security (TLS) Protocol Version 1.3*. IETF. https://datatracker.ietf.org/doc/html/rfc8446

[2] RFC 9000. *QUIC: A UDP-Based Multiplexed and Secure Transport*. IETF. https://datatracker.ietf.org/doc/html/rfc9000

[3] RFC 1035. *Domain Names – Implementation and Specification*. IETF. https://datatracker.ietf.org/doc/html/rfc1035

[4] IEEE 802.11-2020. *IEEE Standard for Information Technology – WLAN MAC and PHY Specifications*. IEEE.

[5] Bluetooth SIG. *Bluetooth Core Specification v5.4*. https://www.bluetooth.com/specifications/specs/core-specification-5-4/

[6] Eddington, M. (2016). *Peach Fuzzer Platform*. https://peachfuzzer.com/

[7] Google. *OSS-Fuzz Project List*. https://github.com/google/oss-fuzz/tree/master/projects

[8] CVE-2014-0160. *OpenSSL Heartbleed*. https://nvd.nist.gov/vuln/detail/CVE-2014-0160

[9] CVE-2019-9512. *HTTP/2 Ping Flood*. https://nvd.nist.gov/vuln/detail/CVE-2019-9512

[10] CVE-2023-44487. *HTTP/2 Rapid Reset*. https://nvd.nist.gov/vuln/detail/CVE-2023-44487

[11] CVE-2020-0022. *Android Bluetooth Heap Overflow*. https://nvd.nist.gov/vuln/detail/CVE-2020-0022

[12] CVE-2020-12351. *Linux Bluetooth L2CAP Heap Overflow (BleedingTooth)*. https://nvd.nist.gov/vuln/detail/CVE-2020-12351

[13] CVE-2023-2828. *BIND 9 OOB Read*. https://nvd.nist.gov/vuln/detail/CVE-2023-2828

[14] CVE-2019-13135. *libpng Use-After-Free*. https://nvd.nist.gov/vuln/detail/CVE-2019-13135

[15] CVE-2023-3420. *Chrome PDFium Type Confusion*. https://nvd.nist.gov/vuln/detail/CVE-2023-3420

[16] Google. *libprotobuf-mutator*. https://github.com/google/libprotobuf-mutator

[17] Google. *Boofuzz: Network Protocol Fuzzing Framework*. https://github.com/jtpereyda/boofuzz

[18] Mozilla. *Dharma: Grammar-Based Fuzzer*. https://github.com/MozillaSecurity/dharma

[19] Google Project Zero. *DOMato: DOM Fuzzer*. https://github.com/googleprojectzero/DOMATO

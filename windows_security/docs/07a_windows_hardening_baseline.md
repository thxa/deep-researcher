# Windows Hardening Baseline — DISA STIG, CIS Benchmarks, ASR, Credential Guard, WDAC & LAPS

> A deep-technical reference on Windows hardening: security baselines (DISA STIG, CIS, Microsoft), Group Policy hardening, Windows Defender configuration, Attack Surface Reduction, exploit protection mitigations, Windows Sandbox, Microsoft Defender for Endpoint, Credential Guard, Device Guard/WDAC, and LAPS. Written for security engineers and defenders.

---

## Table of Contents

1. [Security Baselines Overview](#1-security-baselines-overview)
2. [Group Policy Hardening](#2-group-policy-hardening)
3. [Windows Defender Configuration](#3-windows-defender-configuration)
4. [Attack Surface Reduction (ASR)](#4-attack-surface-reduction-asr)
5. [Exploit Protection Mitigations](#5-exploit-protection-mitigations)
6. [Windows Sandbox](#6-windows-sandbox)
7. [Microsoft Defender for Endpoint](#7-microsoft-defender-for-endpoint)
8. [Credential Guard Deep Dive](#8-credential-guard-deep-dive)
9. [Device Guard & WDAC](#9-device-guard--wdac)
10. [Local Administrator Password Solution (LAPS)](#10-local-administrator-password-solution-laps)

---

## 1. Security Baselines Overview

### 1.1 Baseline Comparison

Three major security baselines exist for Windows hardening:

| Baseline | Publisher | Scope | Update Frequency | Depth |
|----------|-----------|-------|-----------------|-------|
| **DISA STIG** | DoD Defense Information Systems Agency | DoD systems | Quarterly | Very deep (1000+ settings) |
| **CIS Benchmarks** | Center for Internet Security | Commercial | Annual | Deep (500+ settings) |
| **Microsoft Security Baselines** | Microsoft | All Windows | Per Windows release | Moderate (300+ settings) |

### 1.2 Microsoft Security Baselines

```powershell
# Download and apply Microsoft Security Baselines:
# https://www.microsoft.com/en-us/download/details.aspx?id=55319

# Apply baseline via Group Policy:
# 1. Import GPO backups into Group Policy Management Console
# 2. Link GPOs to appropriate OUs
# 3. Verify settings with Policy Analyzer

# Key baseline GPOs:
# - Microsoft Windows 11 Security Baseline
# - Microsoft Windows 11 Defenders Security Baseline
# - Microsoft Edge Security Baseline
# - Microsoft Office 365 Security Baseline

# Verify baseline compliance:
Get-GpoReport -Name "Microsoft Windows 11 Security Baseline" -ReportType HTML | Out-File baseline_report.html
```

### 1.3 DISA STIG Key Settings

```
DISA STIG for Windows 11 (selected critical settings):
═══════════════════════════════════════════════════════════════
Account Policies:
  - Account lockout threshold: 3 invalid logon attempts
  - Account lockout duration: 15 minutes
  - Reset account lockout counter: 15 minutes
  - Minimum password length: 14 characters
  - Password complexity: Enabled
  - Maximum password age: 60 days
  - Minimum password age: 1 day

Audit Policies:
  - Audit logon events: Success, Failure
  - Audit account logon: Success, Failure
  - Audit account management: Success, Failure
  - Audit object access: Success, Failure
  - Audit policy change: Success, Failure
  - Audit privilege use: Success, Failure
  - Audit system events: Success, Failure

Security Options:
  - Accounts: Administrator account status: Disabled
  - Accounts: Rename administrator account: (renamed)
  - Accounts: Guest account status: Disabled
  - Interactive logon: Do not display last user name: Enabled
  - Interactive logon: Smart card required: Enabled (for high security)
  - Network security: Do not store LAN Manager hash: Enabled
  - Network security: LAN Manager authentication level: Send NTLMv2 only
  - Shutdown: Allow system to be shut down without logon: Disabled

Windows Defender:
  - Windows Defender Antivirus: Enabled
  - Real-time protection: Enabled
  - Cloud protection: Enabled
  - Sample submission: Enabled
  - Tamper protection: Enabled

Firewall:
  - Domain profile: Enabled
  - Private profile: Enabled
  - Public profile: Enabled
  - Inbound connections: Block (default)
  - Outbound connections: Allow (default)

BitLocker:
  - BitLocker on OS drive: Enabled
  - BitLocker on fixed data drives: Enabled
  - BitLocker on removable data drives: Enabled
  - Recovery password: Stored in AD DS
  - TPM required: Yes
═══════════════════════════════════════════════════════════════
```

---

## 2. Group Policy Hardening

### 2.1 Critical Group Policy Settings

```powershell
# Group Policy hardening via PowerShell (local):
# Account Policies
net accounts /lockoutthreshold:3 /lockoutduration:15 /maxpwage:60 /minpwage:1 /minpwlen:14 /uniquepw:24
net accounts /maxpwage:60

# Security Options (via Local Security Policy)
# Disable SMBv1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "SMB1" -Value 0 -Type DWord

# Disable LM hash storage
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1 -Type DWord

# Configure NTLM authentication level
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord

# Enable Credential Guard (requires VBS)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 1 -Type DWord

# Enable LSA Protection (RunAsPPL)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord

# Configure Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -EnableNetworkProtection Advanced
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAll
Set-MpPreference -PUAProtection Enabled

# Enable exploit protection
# (See Section 5 for detailed exploit protection settings)
```

### 2.2 AppLocker Policy Configuration

```powershell
# Create AppLocker policy (baseline):
$AppLockerPolicy = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="fd783ea6-578e-4e31-a087-f071c50d3c6f" Name="Allow Program Files" Action="Allow" Condition="Path=%PROGRAMFILES%\*">
      <FilePathCondition Path="%PROGRAMFILES%\*" />
    </FilePathRule>
    <FilePathRule Id="84cf1983-3f1e-4538-9f4e-7dba8e3e47c9" Name="Allow Windows" Action="Allow" Condition="Path=%SYSTEM32%\*">
      <FilePathCondition Path="%SYSTEM32%\*" />
    </FilePathRule>
    <FilePathRule Id="53f83bd9-3fa1-4b27-8fae-7f7c67e9bad6" Name="Deny All" Action="Deny" Condition="Path=*">
      <FilePathCondition Path="*" />
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Dll" EnforcementMode="Enabled">
    <FilePathRule Id="b7b4a6ec-4594-48fd-96ae-e5c7f6b6dd8c" Name="Allow Program Files DLLs" Action="Allow" Condition="Path=%PROGRAMFILES%\*\*.dll">
      <FilePathCondition Path="%PROGRAMFILES%\*\*.dll" />
    </FilePathRule>
    <FilePathRule Id="e88c6b40-5996-4d2f-8c16-46e0f8f7e5c6" Name="Allow System32 DLLs" Action="Allow" Condition="Path=%SYSTEM32%\*.dll">
      <FilePathCondition Path="%SYSTEM32%\*.dll" />
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
"@

# Apply AppLocker policy
Set-AppLockerPolicy -XmlPolicy $AppLockerPolicyPolicy -LDAPPath "LDAP://CN={GUID},CN=Policies,CN=System,DC=corp,DC=local"

# Verify AppLocker policy
Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path "C:\temp\test.exe"
```

---

## 3. Windows Defender Configuration

```powershell
# Windows Defender optimal configuration:

# Real-time protection
Set-MpPreference -DisableRealtimeMonitoring $false       ; Enable real-time scanning
Set-MpPreference -DisableIOAVProtection $false           ; Enable IOAV protection
Set-MpPreference -DisableBehaviorMonitoring $false        ; Enable behavior monitoring
Set-MpPreference -DisableBlockAtFirstSeen $false        ; Enable block at first seen
Set-MpPreference -DisableArchiveScanning $false          ; Enable archive scanning
Set-MpPreference -DisableAutoExclusion $false           ; Enable auto exclusions
Set-MpPreference -DisableIntrusionPreventionSystem $false; Enable IPS

# Cloud protection
Set-MpPreference -MAPSReporting Advanced                  ; Enable MAPS (advanced)
Set-MpPreference -SubmitSamplesConsent SendAll            ; Send all samples
Set-MpPreference -CloudBlockLevel ZeroTolerance          ; Most aggressive cloud blocking
Set-MpPreference -CloudExtendedTimeout 50                 ; Extended cloud timeout (seconds)

# Network protection
Set-MpPreference -EnableNetworkProtection Enabled        ; Enable network protection

# PUA (Potentially Unwanted Applications)
Set-MpPreference -PUAProtection Enabled                  ; Block PUA

# Tamper protection (cannot be changed via PowerShell, must use GUI or GPO)
# Enable via: Windows Security → Virus & threat protection → Manage settings → Tamper protection

# Attack Surface Reduction (see Section 4)

# Controlled folder access (ransomware protection)
Set-MpPreference -EnableControlledFolderAccess Enabled

# Defender for Endpoint onboarding (enterprise)
# Download onboarding script from Microsoft 365 Defender portal
# .\WindowsDefenderATPOnboardingScript.cmd
```

---

## 4. Attack Surface Reduction (ASR)

### 4.1 ASR Rules

```powershell
# Attack Surface Reduction Rules (Windows Defender):
# Each rule has three modes: Enabled, Audit, Disabled

# Rule IDs and descriptions:
$ASRRules = @{
    "56beb09e-6e68-4401-a4a8-7505ef3e8849" = "Block executables from email clients and webmail"
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block Office applications from creating child processes"
    "7674ba4f-8634-4d21-8d6c-2920b5cb7332" = "Block Office applications from creating executable content"
    "3b576869-a4ec-4529-8536-b7b3b5b24962" = "Block Office applications from injecting code into other processes"
    "e63977c9-3a3f-4f27-9c15-44c31c7c24c4" = "Block JavaScript or VBScript from launching downloaded executable content"
    "d3e037e1-3eb8-44c6-8870-5f9fe9e5b76b" = "Block executable content from email client and webmail"
    "be9ba2b9-0f54-4e6f-9520-0c3ece6369cb" = "Block executable files from running unless they meet prevalence, age, or trusted list criteria"
    "92b97f9f-3e1f-41e5-9340-6d5e3d3c3c3c" = "Block Win32 API calls from Office macros"
    "c1db55a8-5961-4473-a06e-5d64c51a31c1" = "Block process creation originating from PSExec and WMI commands"
    "b2b3f03d-7740-4d4d-9a6e-3d33e68e6988" = "Block untrusted and unsigned processes that run from USB"
    "9e862cf9-7e7a-4c2e-9e0e-b0e4e3d3cb3c" = "Block abuse of exploited vulnerable signed drivers"
    "0d3a1e5c-6c12-4b1e-9789-c7be7325c6a3" = "Block executable content from email client"
    "26190899-1602-49e8-8b27-eb1c034bc247" = "Block Office communication application from creating child processes"
    "e42ad5a0-4c0e-4689-a6e5-7a7e5c3c3c3c" = "Block Adobe Reader from creating child processes"
    "488b6c5c-93d3-4ed3-bf43-31e8f0d3e3e3" = "Block persistence through WMI event subscription"
    "c28e31eb-0e9c-4d21-9e6d-3c3c3c3c3c3c" = "Block use of copied or impersonated system tools (preview)"
}

# Enable all ASR rules in Audit mode first (for testing):
foreach ($rule in $ASRRules.Keys) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $rule -AttackSurfaceReductionRules_Actions AuditMode
}

# After testing, enable in Block mode:
foreach ($rule in $ASRRules.Keys) {
    Set-MpPreference -AttackSurfaceReductionRules_Ids $rule -AttackSurfaceReductionRules_Actions Enabled
}

# ASR rule exclusions (allowed paths):
Add-MpPreference -AttackSurfaceReductionRules_Ids "56beb09e-6e68-4401-a4a8-7505ef3e8849" -AttackSurfaceReductionRules_Paths "C:\AllowedApp.exe"
```

---

## 5. Exploit Protection Mitigations

### 5.1 Per-Process Exploit Protection

```xml
<!-- Exploit Protection configuration (export from Windows Security) -->
<ExploitProtection>
  <ProcessConfig>
    <!-- System-wide settings -->
    <System DEP="Enabled" EMET="Enabled" />
    
    <!-- Microsoft Office applications -->
    <App Path="C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE">
      <DEP Enabled="true" />
      <ASLR ForceRelocateImages="true" BottomUp="true" HighEntropy="true" />
      <CFG Enabled="true" Strict="true" />
      <ACG Enabled="true" />
      <CIG Enabled="true" />
      <StrictHandle Enabled="true" />
      <ExtensionDisableEnabled="true" />
      <FontsDisableEnabled="true" />
      <ChildProcess Enabled="true" />
      <EAF Enabled="true" />
      <EAFPlus Enabled="true" />
    </App>
    
    <!-- Adobe Acrobat Reader -->
    <App Path="C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe">
      <DEP Enabled="true" />
      <ASLR ForceRelocateImages="true" BottomUp="true" HighEntropy="true" />
      <CFG Enabled="true" />
      <ACG Enabled="true" />
      <CIG Enabled="true" />
      <StrictHandle Enabled="true" />
      <ChildProcess Enabled="true" />
    </App>
    
    <!-- Web browsers -->
    <App Path="C:\Program Files\Google\Chrome\Application\chrome.exe">
      <DEP Enabled="true" />
      <ASLR ForceRelocateImages="true" BottomUp="true" HighEntropy="true" />
      <CFG Enabled="true" />
      <ACG Enabled="false" />  ; Chrome uses JIT, can't enable ACG
      <CIG Enabled="true" />
      <StrictHandle Enabled="true" />
    </App>
  </ProcessConfig>
</ExploitProtection>

<!-- Apply exploit protection settings -->
<!-- Save as ExploitProtection.xml, then apply with: -->
<!-- ProcessMitigations.exe -apply ExploitProtection.xml -->
```

```powershell
# View current exploit protection settings:
Get-ProcessMitigation -System

# Set exploit protection for a specific process:
Set-ProcessMitigation -Name "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" -Enable DEP, ForceRelocateImages, HighEntropy, CFG, StrictHandle

# Export current settings:
ProcessMitigations.exe -Export C:\ExploitProtection.xml

# Import settings:
ProcessMitigations.exe -Apply C:\ExploitProtection.xml
```

---

## 6. Windows Sandbox

```powershell
# Enable Windows Sandbox (Windows 10 Pro/Enterprise, 1903+):
Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -All -Online

# Windows Sandbox configuration file (.wsb):
<SandboxConfig>
  <VGpu>Enable</VGpu>
  <Networking>Enable</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>C:\temp\sandbox_files</HostFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>C:\temp\sandbox_files\test_payload.exe</Command>
  </LogonCommand>
  <AudioInput>Enable</AudioInput>
  <VideoInput>Enable</VideoInput>
  <ProtectedClient>Enable</ProtectedClient>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ClipboardRedirection>Enable</ClipboardRedirection>
</SandboxConfig>

# Security properties of Windows Sandbox:
# - Runs in a lightweight Hyper-V container
# - Starts from a clean Windows image
# - Changes are discarded on close (no persistence)
# - Cannot access host filesystem (except mapped folders)
# - Cannot access host clipboard (if disabled)
# - Uses hardware-enforced isolation (VBS)
# - Ideal for malware analysis and untrusted software execution
```

---

## 7. Microsoft Defender for Endpoint

### 7.1 MDE Architecture

```
Microsoft Defender for Endpoint (ATP) Architecture:
┌──────────────────────────────────────────────────────┐
│ Endpoint Behavioral Sensor                            │
│  - Process creation monitoring                         │
│  - File modify/delete/rename monitoring                │
│  - Registry modification monitoring                    │
│  - Network connection monitoring                      │
│  - Image (DLL) loading monitoring                     │
│  - Driver loading monitoring                          │
│  - ETW event collection                               │
│  - AMSI integration                                   │
├──────────────────────────────────────────────────────┤
│ Cloud Security Analytics                              │
│  - Machine learning models                            │
│  - Behavioral analytics                                │
│  - Threat intelligence correlation                    │
│  - Automated investigation                             │
│  - Advanced hunting (KQL)                              │
├──────────────────────────────────────────────────────┤
│ Threat & Vulnerability Management                    │
│  - Vulnerability discovery and assessment              │
│  - Secure score analysis                               │
│  - Configuration assessment                            │
│  - Software inventory                                   │
├──────────────────────────────────────────────────────┤
│ Automated Response                                    │
│  - Automated investigation and remediation (AIR)     │
│  - Live response                                      │
│  - Containment actions (isolate, restrict)            │
│  - Tamper protection                                   │
└──────────────────────────────────────────────────────┘
```

### 7.2 MDE Advanced Hunting

```kusto
// Advanced Hunting queries (KQL):

// Find Mimikatz execution:
DeviceProcessEvents
| where ProcessCommandLine has_any ("mimikatz", "sekurlsa", "logonpasswords", "lsadump", "kerberos::golden")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName

// Find LSASS dumping:
DeviceProcessEvents
| where ProcessCommandLine has "lsass" and (ProcessCommandLine has "procdump" or ProcessCommandLine has "rundll32" and ProcessCommandLine has "comsvcs")
| project Timestamp, DeviceName, ProcessCommandLine

// Find PowerShell obfuscation:
DeviceProcessEvents
| where ProcessCommandLine has "powershell" and (ProcessCommandLine has "-enc" or ProcessCommandLine has "-encodedcommand" or ProcessCommandLine has "frombase64string")
| project Timestamp, DeviceName, ProcessCommandLine

// Find LOLBin abuse:
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("certutil.exe", "mshta.exe", "mavinject.exe", "cmstp.exe", "regsvr32.exe")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName

// Find credential dumping:
DeviceProcessEvents
| where ProcessCommandLine has_any ("sekurlsa::", "lsadump::", "kerberos::", "privilege::debug")
| project Timestamp, DeviceName, ProcessCommandLine

// Find lateral movement:
DeviceNetworkEvents
| where ActionType == "InboundConnectionAccepted"
| where RemotePort in (135, 445, 3389, 5985, 5986)
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName

// Find suspicious registry modifications:
DeviceRegistryEvents
| where RegistryKey has_any ("CurrentVersion\\Run", "CurrentVersion\\RunOnce", "Image File Execution Options", "Services")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```

---

## 8. Credential Guard Deep Dive

### 8.1 Credential Guard Implementation

```powershell
# Enable Credential Guard (requires VBS, UEFI, TPM 2.0):

# Method 1: Group Policy
# Computer Configuration > Administrative Templates > System > Device Guard
# "Turn on Virtualization Based Security" = Enabled
# "Select Platform Security Level" = Secure Boot and DMA Protection
# "Virtualization Based Protection of Code Integrity" = Enabled with UEFI lock
# "Credential Guard Configuration" = Enabled with UEFI lock

# Method 2: Registry (for testing, NOT persistent across reboots)
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" -Name "Enabled" -Value 1 -PropertyType DWord -Force

# Method 3: PowerShell (persistent)
# This requires the Device Guard/Credential Guard GPO or deployment script
# Download from: https://www.microsoft.com/en-us/download/details.aspx?id=53357

# Verify Credential Guard status:
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
# Check: CredentialGuardConfiguration = 1 (Enabled)

# Or via WinDBG:
# In kernel debugger:
# dd nt!HvlEnablings+0xC L1
# If value is 1, VBS is enabled
```

### 8.2 Credential Guard Limitations and Bypasses

```
Credential Guard Bypasses:
1. SPN-based Kerberoasting (not protected by Credential Guard)
   - Request TGS for SPN → TGS contains encrypted service password hash
   - Crack service account password offline
   - Credential Guard does NOT protect against this

2. Pass-the-hash with NTLM (protected but not completely)
   - If NTLM is not fully protected by Credential Guard
   - Some protocols may still accept NTLM hash directly

3. Credential theft from non-LSASS sources
   - Chrome saved passwords (DPAPI protected, not Credential Guard)
   - Firefox saved passwords (not Credential Guard protected)
   - WiFi passwords (not Credential Guard protected)
   - RDP saved credentials (not Credential Guard protected)

4. Direct system access
   - If attacker gains SYSTEM privileges via kernel exploit
   - Can read Credential Guard-protected memory from VTL 0
   - But the VTL 1 (secure world) secrets are not accessible

5. Skeleton key attack (not fully mitigated)
   - Injects into LSASS process in VTL 0
   - Adds a secondary password to domain accounts
   - Credential Guard does not prevent LSASS injection in VTL 0
   - But the Skeleton key cannot extract VTL 1 credentials
```

---

## 9. Device Guard & WDAC

### 9.1 WDAC Policy Creation

```powershell
# Create WDAC policy (Windows Defender Application Control):

# Step 1: Create base policy (audit mode)
New-CIPolicy -Level Publisher -FilePath "C:\WDAC\InitialPolicy.xml" -Audit -Fallback Hash

# Step 2: Scan for applications (audit mode)
# Run the system normally for 1-2 weeks to collect application usage data
# Check audit events in Event Viewer:
# Applications and Services Logs > Microsoft > Windows > CodeIntegrity > Operational

# Step 3: Create supplemental policy from audit data
New-CIpolicy -Level Publisher -FilePath "C:\WDAC\SupplementalPolicy.xml" -AuditPaths "C:\AuditLogs"

# Step 4: Merge policies
Merge-CIPolicy -PolicyPaths "C:\WDAC\InitialPolicy.xml","C:\WDAC\SupplementalPolicy.xml" -OutputFilePath "C:\WDAC\MergedPolicy.xml"

# Step 5: Convert to binary policy
ConvertFrom-CIPolicy -XmlFilePath "C:\WDAC\MergedPolicy.xml" -BinaryFilePath "C:\WDAC\MergedPolicy.bin"

# Step 6: Deploy policy (enforcement mode)
# Copy policy to C:\Windows\System32\CodeIntegrity\SIPolicy.p7b
Copy-Item "C:\WDAC\MergedPolicy.bin" "C:\Windows\System32\CodeIntegrity\SIPolicy.p7b"

# Step 7: Reboot to apply policy
Restart-Computer

# WDAC policy modes:
# - Audit: Logs violations but does not block
# - Enforcement: Blocks unsigned/unauthorized code
```

### 9.2 WDAC Policy Best Practices

```
WDAC Deployment Best Practices:
1. Start in audit mode for 2-4 weeks
2. Review audit events daily
3. Create rules for all legitimate applications
4. Test enforcement mode on a small group of devices
5. Gradually roll out enforcement to all devices
6. Use supplemental policies for business apps
7. Create per-department policies for different application sets
8. Monitor WDAC events in Microsoft Defender for Endpoint

WDAC Policy Elements:
- AllowMicrosoft: Trust Microsoft-signed binaries
- AllowWindows: Trust Windows-signed binaries
- AllowStoreApps: Trust Microsoft Store apps
- AllowEvince: Require EV signing
- AllowWHQL: Trust WHQL-signed drivers
- KernelMode: Trust kernel-mode code

Key Rule Types:
- Publisher: Trust by publisher certificate
- FilePublisher: Trust by publisher + file name
- Hash: Trust by file hash (most restrictive)
- FilePath: Trust by file path (location-based)
- IDMEF: Trust by Intelligent Security Graph authorization
```

---

## 10. Local Administrator Password Solution (LAPS)

### 10.1 LAPS Architecture

```
LAPS Architecture:
┌───────────────────────────────────────────────────────────────┐
│ Domain Controller                                               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ AD Schema Extensions                                    │   │
│  │  - ms-Mcs-AdmPwd (stores encrypted password)            │   │
│  │  - ms-Mcs-AdmPwdExpirationTime (stores expiration)      │   │
│  │                                                         │   │
│  │ ACL on ms-Mcs-AdmPwd:                                  │   │
│  │  - SELF: WRITE (computer can update its password)       │   │
│  │  - Domain Admins: READ (admins can read passwords)      │   │
│  │  - Custom Groups: READ (helpdesk, security teams)      │   │
│  └─────────────────────────────────────────────────────────┘   │
├───────────────────────────────────────────────────────────────┤
│ Client Computer                                                │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ LAPS GPO Extension (admpwd.dll)                        │   │
│  │  - Installed via Group Policy or manually              │   │
│  │  - Runs as SYSTEM on client                           │   │
│  │  - Generates random password for local admin           │   │
│  │  - Writes password to AD attribute (ms-Mcs-AdmPwd)     │   │
│  │  - Sets expiration time (ms-Mcs-AdmPwdExpirationTime) │   │
│  │  - Password is encrypted with AD permissions           │   │
│  └─────────────────────────────────────────────────────────┘   │
├───────────────────────────────────────────────────────────────┤
│ LAPS UI Tool                                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ LAPS UI (LAPS.UI.exe)                                  │   │
│  │  - Displays computer name and admin password            │   │
│  │  - Allows manual password reset                        │   │
│  │  - Audits password access                               │   │
│  └─────────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────┘
```

### 10.2 LAPS Deployment

```powershell
# LAPS deployment steps:

# Step 1: Run LAPS installer on DC (installs schema extensions and UI)
# Download: https://www.microsoft.com/en-us/download/details.aspx?id=46899

# Step 2: Extend AD schema (requires Schema Admins)
Update-AdmPwdADSchema

# Step 3: Create LAPS GPO
# Computer Configuration > Policies > Administrative Templates > LAPS
# - Enable local admin password management: Enabled
# - Password Settings: Complexity, Length, Age
# - Name of administrator account to manage: Administrator

# Step 4: Set ACLs on OUs
# Grant SELF write permission on ms-Mcs-AdmPwd and ms-Mcs-AdmPwdExpirationTime
Set-AdmPwdComputerSelfPermission -Identity "OU=Computers,DC=corp,DC=local"

# Grant read permission to authorized groups
Add-AdmPwdReaders -Identity "OU=Computers,DC=corp,DC=local" -Readers "Domain Admins"
Add-AdmPwdReaders -Identity "OU=Computers,DC=corp,DC=local" -Readers "HelpDesk"

# Step 5: Install LAPS GPO extension on clients
# Via Group Policy Software Installation or SCCM
# Or copy admpwd.dll to C:\Program Files\LAPS\ and register with regsvr32

# Step 6: Verify password is set
Get-AdmPwdPassword -ComputerName WS01
```

### 10.3 LAPS Security Consider

```
LAPS Security Best Practices:
1. Password Complexity
   - Minimum 20 characters (recommended: 30+)
   - Include upper, lower, digits, special characters
   - Avoid ambiguous characters (0/O, 1/l/I)

2. Password Age
   - Maximum 30 days (recommended: 7-14 days)
   - Shorter age = less window for credential reuse

3. ACL Management
   - Grant read access only to necessary groups
   - Audit read access regularly
   - Use fine-grained permissions for different OU levels

4. Password Encryption
   - LAPS stores passwords in plaintext in AD (by default)
   - For additional encryption, use Windows LAPS (legacy LAPS successor)
   - Windows LAPS supports encryption of passwords stored in AD

5. Monitoring
   - Monitor Event ID 4662 for ms-Mcs-AdmPwd reads
   - Alert on unauthorized password reads
   - Monitor password expiration (ms-Mcs-AdmPwdExpirationTime)

6. Windows LAPS (New, Windows 11 23H2+)
   - Built into Windows (no additional installation needed)
   - Supports password encryption in AD
   - Supports backup to Azure Key Vault
   - Enabled via Group Policy:
     Computer Configuration > Administrative Templates > System > LAPS
```

---

> **Cross-references**:
> - Windows security architecture (tokens, ACLs, VBS) → `→ 01b_windows_security_architecture`
> - Memory protections (DEP, ASLR, CFG, HVCI) → `→ 03a_windows_memory_protections`
> - Defense evasion → `→ 06b_defense_evasion_lateral`
> - AD attacks (Kerberoasting, DCSync) → `→ 06a_active_directory_attacks`
> - Malware techniques (AMSI bypass, ETW bypass) → `→ 05a_windows_malware_techniques`
> - LAPS bypass → `→ 06a_active_directory_attacks` (Section 8)

---

## References

1. DISA. "Windows 10 Security Technical Implementation Guide (STIG)." <https://www.stigviewer.com/stigs/> — Comprehensive hardening baseline: 1000+ security settings covering Group Policy, Defender, exploit protection, and Credential Guard.
2. CIS. "Microsoft Windows 11 Benchmark v2.0." *Center for Internet Security*, 2023. — Security configuration baselines for Group Policy, ASR, WDAC, and Defender.
3. Microsoft Learn. "Windows Security Baselines." <https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines>
4. Microsoft Learn. "Attack Surface Reduction (ASR) Rules." <https://learn.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction>
5. Microsoft Learn. "Credential Guard." <https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/> — Virtualization-based LSASS protection deployment and configuration.
6. Microsoft Learn. "Windows Defender Application Control (WDAC)." <https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/>
7. Microsoft Learn. "Exploit Protection Reference." <https://learn.microsoft.com/en-us/windows/security/threat-protection/> — System-wide and per-app DEP, ASLR, CFG, ACG settings.
8. MITRE ATT&CK. "Harden System — M1041." <https://attack.mitre.org/mitigations/M1041/> — System hardening mitigations mapped to ATT&CK techniques.
9. MITRE ATT&CK. "Credential Access Protection — M1013." <https://attack.mitre.org/mitigations/M1013/>
10. Dormann, W. "Windows Hardening Effectiveness." *CERT/CC Vulnerability Analysis Blog*, 2022. — STIG and CIS baseline effectiveness analysis, exploit protection configuration.
11. McGarr, C. "WDAC and AppLocker Bypass Analysis." *Connor McGarr's Blog*, 2023. — Policy enforcement gaps, managed installer abuse, and WDAC bypass techniques.
12. Chester, A. "Credential Guard and LSA Protection." *XPN InfoSec Blog*, 2022. — Credential Guard architecture, VBS requirements, and practical deployment challenges.
13. Microsoft Security Response Center (MSRC) Blog. "Security Baselines and STIG Alignment." <https://msrc.microsoft.com/blog/> — Baseline updates, STIG mapping, and exploit protection guidance.
14. National Vulnerability Database. CVE-2020-1472. "Zerologon — NetLogon EoP." <https://nvd.nist.gov/vuln/detail/CVE-2020-1472> — Demonstrates necessity of secure channel enforcement in hardening baselines.
15. DISA. "Windows Server STIG — LAPS Deployment." <https://www.stigviewer.com/stigs/> — LAPS deployment, fine-grained password policies, and local admin management.
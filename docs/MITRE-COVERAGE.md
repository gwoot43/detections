# MITRE ATT&CK coverage

Generated from the rules' `mitre:` front-matter against **ATT&CK Enterprise v19.2** by `tools/mitre_coverage.py`. Re-run it after adding or changing rules. A technique counts as covered when at least one rule maps to it or to one of its sub-techniques. Percentages count only techniques that apply to this estate's platforms (Containers, IaaS, Identity Provider, Linux, Office Suite, PRE, SaaS, Windows).

Coverage means a rule *targets* the technique, not that every way of doing it is caught. Use it to find empty areas, not to claim completeness.

**178 rules · 102 techniques covered** (189 technique and sub-technique IDs).

For the interactive heat map, open `tools/attack-coverage-map.html` in a browser (download it from GitHub first, because GitHub shows HTML as source). It is a single self-contained file you can also share or host.

To see it as a heat map, import `docs/attack-navigator-layer.json` into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) (Open Existing Layer > Upload from local). The score is the number of rules.

## Kill chain at a glance

```mermaid
flowchart LR
  T0["Reconnaissance<br/>1/12 techniques · 2 rules"]:::low
  T1["Resource Development<br/>0/9 techniques · 0 rules"]:::none
  T2["Initial Access<br/>5/11 techniques · 55 rules"]:::high
  T3["Execution<br/>11/19 techniques · 26 rules"]:::high
  T4["Persistence<br/>15/22 techniques · 75 rules"]:::high
  T5["Privilege Escalation<br/>12/13 techniques · 72 rules"]:::high
  T6["Stealth<br/>16/30 techniques · 48 rules"]:::high
  T7["Defense Impairment<br/>8/14 techniques · 35 rules"]:::high
  T8["Credential Access<br/>12/17 techniques · 56 rules"]:::high
  T9["Discovery<br/>14/34 techniques · 12 rules"]:::high
  T10["Lateral Movement<br/>6/9 techniques · 30 rules"]:::high
  T11["Collection<br/>7/16 techniques · 18 rules"]:::high
  T12["Command and Control<br/>9/18 techniques · 23 rules"]:::high
  T13["Exfiltration<br/>6/9 techniques · 7 rules"]:::high
  T14["Impact<br/>4/15 techniques · 5 rules"]:::mid
  T0 --> T1 --> T2 --> T3 --> T4 --> T5 --> T6 --> T7 --> T8 --> T9 --> T10 --> T11 --> T12 --> T13 --> T14
  classDef none fill:#f3f3f1,stroke:#9b9a95,color:#52514e
  classDef low fill:#cde2fb,stroke:#3987e5,color:#0b0b0b
  classDef mid fill:#6da7ec,stroke:#256abf,color:#0b0b0b
  classDef high fill:#1c5cab,stroke:#0d366b,color:#ffffff
```

Shading: grey = nothing, light = under 15% of the tactic's techniques, mid = 15-35%, dark = over 35%.

## Coverage by tactic

| Tactic | Techniques covered | Share | Rules |
|---|---|---|---|
| Reconnaissance (TA0043) | 1 / 12 | `██░░░░░░░░░░░░░░░░░░` 8% | 2 |
| Resource Development (TA0042) | 0 / 9 | `░░░░░░░░░░░░░░░░░░░░` 0% | 0 |
| Initial Access (TA0001) | 5 / 11 | `█████████░░░░░░░░░░░` 45% | 55 |
| Execution (TA0002) | 11 / 19 | `████████████░░░░░░░░` 58% | 26 |
| Persistence (TA0003) | 15 / 22 | `██████████████░░░░░░` 68% | 75 |
| Privilege Escalation (TA0004) | 12 / 13 | `██████████████████░░` 92% | 72 |
| Stealth (TA0005) | 16 / 30 | `███████████░░░░░░░░░` 53% | 48 |
| Defense Impairment (TA0112) | 8 / 14 | `███████████░░░░░░░░░` 57% | 35 |
| Credential Access (TA0006) | 12 / 17 | `██████████████░░░░░░` 71% | 56 |
| Discovery (TA0007) | 14 / 34 | `████████░░░░░░░░░░░░` 41% | 12 |
| Lateral Movement (TA0008) | 6 / 9 | `█████████████░░░░░░░` 67% | 30 |
| Collection (TA0009) | 7 / 16 | `█████████░░░░░░░░░░░` 44% | 18 |
| Command and Control (TA0011) | 9 / 18 | `██████████░░░░░░░░░░` 50% | 23 |
| Exfiltration (TA0010) | 6 / 9 | `█████████████░░░░░░░` 67% | 7 |
| Impact (TA0040) | 4 / 15 | `█████░░░░░░░░░░░░░░░` 27% | 5 |

## Priority techniques

Techniques that show up most often in real intrusions against a Windows, Microsoft 365 and Azure estate. A gap here matters more than a gap in the long tail.

| Technique | Tactic | Rules |
|---|---|---|
| T1566.001 Spearphishing Attachment | Initial Access | E02, E04, E13, E14, W02 |
| T1566.002 Spearphishing Link | Initial Access | E01, E04, E05, E13, E14 |
| T1078.004 Cloud Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | C03, C11, D02, E09, I07, S01, S02, S03, S04, S05, S06, S07, S08, S09, S11, S19, S22, X02 |
| T1190 Exploit Public-Facing Application | Initial Access | AD11, L03, N05, N06, X04 |
| T1133 External Remote Services | Persistence, Initial Access | C08, N01, N02, N03, X03 |
| T1199 Trusted Relationship | Initial Access | **gap** |
| T1059.001 PowerShell | Execution | DV02, W03, W04 |
| T1059.003 Windows Command Shell | Execution | DV02 |
| T1059.004 Unix Shell | Execution | L01, L02, L03 |
| T1047 Windows Management Instrumentation | Execution | W08 |
| T1053.005 Scheduled Task | Execution, Persistence, Privilege Escalation | CS07, W08, WE14 |
| T1569.002 Service Execution | Execution | W08, WE08, WE14 |
| T1204.002 Malicious File | Execution | E02, W02, W03, W12 |
| T1547.001 Registry Run Keys / Startup Folder | Persistence, Privilege Escalation | CS02 |
| T1543.003 Windows Service | Persistence, Privilege Escalation | WE08 |
| T1098.001 Additional Cloud Credentials | Persistence, Privilege Escalation | C04, C05, C12 |
| T1136.001 Local Account | Persistence | W07 |
| T1505.003 Web Shell | Persistence | AD11, CS10, L03, WE10, X04 |
| T1546.003 Windows Management Instrumentation Event Subscription | Privilege Escalation, Persistence | WE11 |
| T1068 Exploitation for Privilege Escalation | Privilege Escalation | AD05, AD07, CS01, L06, W05, WE05, WE08, WE10 |
| T1134 Access Token Manipulation | Stealth, Privilege Escalation | I14, WE03, WE05 |
| T1548.002 Bypass User Account Control | Privilege Escalation | **gap** |
| T1027 Obfuscated Files or Information | Stealth | W04 |
| T1036 Masquerading | Stealth | **gap** |
| T1055 Process Injection | Stealth, Privilege Escalation | CS06, WE10 |
| T1685.005 Clear Windows Event Logs | Defense Impairment | WE01 |
| T1218.011 Rundll32 | Stealth | W04 |
| T1564.001 Hidden Files and Directories | Stealth | **gap** |
| T1685 Disable or Modify Tools | Defense Impairment | C09, CP01, CP02, CP03, CP04, CP05, CP06, CS01, CS05, DV04, E10, L07, N04, W05, WE01, WE02, WE07, X05 |
| T1003.001 LSASS Memory | Credential Access | D01, W01, WE07, WE10 |
| T1003.006 DCSync | Credential Access | AD02, I01, S06 |
| T1558.003 Kerberoasting | Credential Access | D01, I03, I13, W09 |
| T1110.003 Password Spraying | Credential Access | D02, I05, S02, S15 |
| T1555.003 Credentials from Web Browsers | Credential Access | B08 |
| T1621 Multi-Factor Authentication Request Generation | Credential Access | C11, I07, S11, S12 |
| T1552.001 Credentials In Files | Credential Access | B07, B08, D01, D02, D03, IN09, L05 |
| T1539 Steal Web Session Cookie | Credential Access | B08, S08, S23 |
| T1087.002 Domain Account | Discovery | B04, W09 |
| T1482 Domain Trust Discovery | Discovery | B09, W09 |
| T1018 Remote System Discovery | Discovery | B01, B04, CS12, D04, W09 |
| T1069.002 Domain Groups | Discovery | B04, B09, W09 |
| T1083 File and Directory Discovery | Discovery | D03, IN09 |
| T1082 System Information Discovery | Discovery | B09 |
| T1021.001 Remote Desktop Protocol | Lateral Movement | CS15, W07, WE15 |
| T1021.002 SMB/Windows Admin Shares | Lateral Movement | B05, W08, WE14 |
| T1021.006 Windows Remote Management | Lateral Movement | W08 |
| T1570 Lateral Tool Transfer | Lateral Movement | B04 |
| T1550.002 Pass the Hash | Lateral Movement | B05, WE04, WE12 |
| T1560.001 Archive via Utility | Collection | **gap** |
| T1114.002 Remote Email Collection | Collection | IN04 |
| T1213.002 Sharepoint | Collection | D03, IN01, IN02, IN07, IN09 |
| T1005 Data from Local System | Collection | B07, C10 |
| T1071.001 Web Protocols | Command and Control | B06, B10, N07 |
| T1105 Ingress Tool Transfer | Command and Control | L02, N07, W03, W04, W10 |
| T1219 Remote Access Tools | Command and Control | CS13, W10, X06 |
| T1572 Protocol Tunneling | Command and Control | CS03, CS09, CS10, CS11, CS13, CS14, CS15, CS16, N09, W10 |
| T1090.003 Multi-hop Proxy | Command and Control | N09, S07 |
| T1567.002 Exfiltration to Cloud Storage | Exfiltration | N08 |
| T1048 Exfiltration Over Alternative Protocol | Exfiltration | CS03, IN05, N08 |
| T1041 Exfiltration Over C2 Channel | Exfiltration | N08 |
| T1052.001 Exfiltration over USB | Exfiltration | DV01, DV03, DV05 |
| T1486 Data Encrypted for Impact | Impact | L10, X05 |
| T1490 Inhibit System Recovery | Impact | IN06, L10, W06, X05 |
| T1489 Service Stop | Impact | CP05, X05 |
| T1485 Data Destruction | Impact | IN06, L10, W06 |

**5 of 65 priority techniques have no rule.**

## Technique detail by tactic

### Reconnaissance

| Technique | Rules | Sub-techniques covered |
|---|---|---|
| T1595 Active Scanning | N06, N10 | T1595.002 Vulnerability Scanning (N06, N10); T1595.003 Wordlist Scanning (N10) |

### Initial Access

| Technique | Rules | Sub-techniques covered |
|---|---|---|
| T1078 Valid Accounts | AD05, B05, C03, C11, D01, D02, E09, E10, I02, I06, I07, I11, N01, N03, N04, S01, S02, S03, S04, S05, S06, S07, S08, S09, S11, S19, S22, WE04, WE05, WE06, X02, X03, X07 | T1078.002 Domain Accounts (AD05, D01, I02, I06, I11, WE05, WE06, X07); T1078.004 Cloud Accounts (C03, C11, D02, E09, I07, S01, S02, S03, S04, S05, S06, S07, S08, S09, S11, S19, S22, X02) |
| T1566 Phishing | CP02, E01, E02, E03, E04, E05, E11, E13, E14, W02, X01, X06 | T1566.001 Spearphishing Attachment (E02, E04, E13, E14, W02); T1566.002 Spearphishing Link (E01, E04, E05, E13, E14); T1566.003 Spearphishing via Service (E03) |
| T1190 Exploit Public-Facing Application | AD11, L03, N05, N06, X04 | - |
| T1133 External Remote Services | C08, N01, N02, N03, X03 | - |
| T1200 Hardware Additions | DV02, DV03, DV05 | - |

### Execution

| Technique | Rules | Sub-techniques covered |
|---|---|---|
| T1059 Command and Scripting Interpreter | DV02, L01, L02, L03, N05, W02, W03, W04, WE10, X01, X04 | T1059.001 PowerShell (DV02, W03, W04); T1059.003 Windows Command Shell (DV02); T1059.004 Unix Shell (L01, L02, L03) |
| T1204 User Execution | E01, E02, E05, W02, W03, W12, WE10, X01, X06 | T1204.001 Malicious Link (E01, E05); T1204.002 Malicious File (E02, W02, W03, W12); T1204.004 Malicious Copy and Paste (W03) |
| T1053 Scheduled Task/Job | C12, CS07, L04, W08, WE14 | T1053.003 Cron (L04); T1053.005 Scheduled Task (CS07, W08, WE14) |
| T1569 System Services | W08, WE08, WE14 | T1569.002 Service Execution (W08, WE08, WE14) |
| T1197 BITS Jobs | W04 | - |
| T1651 Cloud Administration Command | C07 | - |
| T1610 Deploy Container | L08 | - |
| T1574 Hijack Execution Flow | AD07 | - |
| T1648 Serverless Execution | C12 | - |
| T1072 Software Deployment Tools | W13 | - |
| T1047 Windows Management Instrumentation | W08 | - |

### Persistence

| Technique | Rules | Sub-techniques covered |
|---|---|---|
| T1078 Valid Accounts | AD05, B05, C03, C11, D01, D02, E09, E10, I02, I06, I07, I11, N01, N03, N04, S01, S02, S03, S04, S05, S06, S07, S08, S09, S11, S19, S22, WE04, WE05, WE06, X02, X03, X07 | T1078.002 Domain Accounts (AD05, D01, I02, I06, I11, WE05, WE06, X07); T1078.004 Cloud Accounts (C03, C11, D02, E09, I07, S01, S02, S03, S04, S05, S06, S07, S08, S09, S11, S19, S22, X02) |
| T1098 Account Manipulation | AD02, AD10, C03, C04, C05, C06, C07, C12, E08, I02, I04, I10, I11, I12, I13, I14, L04, S06, S11, S16, S17, S18, S20, S22, W07, WE03, X02, X07 | T1098.001 Additional Cloud Credentials (C04, C05, C12); T1098.002 Additional Email Delegate Permissions (E08); T1098.003 Additional Cloud Roles (C03, C06); T1098.004 SSH Authorized Keys (L04); T1098.005 Device Registration (I10, S11, S16, S17, S18, S20, S22, X02) |
| T1556 Modify Authentication Process | C02, C11, CP03, I10, I12, L11, N03, N04, S02, S03, S16, WE07 | T1556.002 Password Filter DLL (WE07); T1556.003 Pluggable Authentication Modules (L11); T1556.006 Multi-Factor Authentication (I10, S02, S03, S16); T1556.009 Conditional Access Policies (C02, C11) |
| T1133 External Remote Services | C08, N01, N02, N03, X03 | - |
| T1053 Scheduled Task/Job | C12, CS07, L04, W08, WE14 | T1053.003 Cron (L04); T1053.005 Scheduled Task (CS07, W08, WE14) |
| T1505 Server Software Component | AD11, CS10, L03, WE10, X04 | T1505.001 SQL Stored Procedures (AD11); T1505.003 Web Shell (AD11, CS10, L03, WE10, X04) |
| T1546 Event Triggered Execution | CS02, L04, W11, WE11 | T1546.003 Windows Management Instrumentation Event Subscription (WE11); T1546.004 Unix Shell Configuration Modification (L04); T1546.015 Component Object Model Hijacking (W11) |
| T1547 Boot or Logon Autostart Execution | CS02, L09, WE07 | T1547.001 Registry Run Keys / Startup Folder (CS02); T1547.002 Authentication Package (WE07); T1547.005 Security Support Provider (WE07); T1547.006 Kernel Modules and Extensions (L09) |
| T1543 Create or Modify System Process | L04, L11, WE08 | T1543.002 Systemd Service (L04); T1543.003 Windows Service (WE08) |
| T1136 Create Account | AD05, W07 | T1136.001 Local Account (W07); T1136.002 Domain Account (AD05) |
| T1112 Modify Registry | CP06, WE07 | - |
| T1197 BITS Jobs | W04 | - |
| T1137 Office Application Startup | W11 | T1137.006 Add-ins (W11) |
| T1542 Pre-OS Boot | DV04 | - |
| T1205 Traffic Signaling | L09 | T1205.002 Socket Filters (L09) |

### Privilege Escalation

| Technique | Rules | Sub-techniques covered |
|---|---|---|
| T1078 Valid Accounts | AD05, B05, C03, C11, D01, D02, E09, E10, I02, I06, I07, I11, N01, N03, N04, S01, S02, S03, S04, S05, S06, S07, S08, S09, S11, S19, S22, WE04, WE05, WE06, X02, X03, X07 | T1078.002 Domain Accounts (AD05, D01, I02, I06, I11, WE05, WE06, X07); T1078.004 Cloud Accounts (C03, C11, D02, E09, I07, S01, S02, S03, S04, S05, S06, S07, S08, S09, S11, S19, S22, X02) |
| T1098 Account Manipulation | AD02, AD10, C03, C04, C05, C06, C07, C12, E08, I02, I04, I10, I11, I12, I13, I14, L04, S06, S11, S16, S17, S18, S20, S22, W07, WE03, X02, X07 | T1098.001 Additional Cloud Credentials (C04, C05, C12); T1098.002 Additional Email Delegate Permissions (E08); T1098.003 Additional Cloud Roles (C03, C06); T1098.004 SSH Authorized Keys (L04); T1098.005 Device Registration (I10, S11, S16, S17, S18, S20, S22, X02) |
| T1068 Exploitation for Privilege Escalation | AD05, AD07, CS01, L06, W05, WE05, WE08, WE10 | - |
| T1053 Scheduled Task/Job | C12, CS07, L04, W08, WE14 | T1053.003 Cron (L04); T1053.005 Scheduled Task (CS07, W08, WE14) |
| T1484 Domain or Tenant Policy Modification | AD06, C01, WE03, WE06 | T1484.001 Group Policy Modification (WE03, WE06); T1484.002 Trust Modification (C01) |
| T1546 Event Triggered Execution | CS02, L04, W11, WE11 | T1546.003 Windows Management Instrumentation Event Subscription (WE11); T1546.004 Unix Shell Configuration Modification (L04); T1546.015 Component Object Model Hijacking (W11) |
| T1134 Access Token Manipulation | I14, WE03, WE05 | T1134.001 Token Impersonation/Theft (I14); T1134.005 SID-History Injection (WE03) |
| T1547 Boot or Logon Autostart Execution | CS02, L09, WE07 | T1547.001 Registry Run Keys / Startup Folder (CS02); T1547.002 Authentication Package (WE07); T1547.005 Security Support Provider (WE07); T1547.006 Kernel Modules and Extensions (L09) |
| T1543 Create or Modify System Process | L04, L11, WE08 | T1543.002 Systemd Service (L04); T1543.003 Windows Service (WE08) |
| T1055 Process Injection | CS06, WE10 | T1055.012 Process Hollowing (CS06) |
| T1548 Abuse Elevation Control Mechanism | L06 | T1548.001 Setuid and Setgid (L06); T1548.003 Sudo and Sudo Caching (L06) |
| T1611 Escape to Host | L08 | - |

### Stealth

| Technique | Rules | Sub-techniques covered |
|---|---|---|
| T1078 Valid Accounts | AD05, B05, C03, C11, D01, D02, E09, E10, I02, I06, I07, I11, N01, N03, N04, S01, S02, S03, S04, S05, S06, S07, S08, S09, S11, S19, S22, WE04, WE05, WE06, X02, X03, X07 | T1078.002 Domain Accounts (AD05, D01, I02, I06, I11, WE05, WE06, X07); T1078.004 Cloud Accounts (C03, C11, D02, E09, I07, S01, S02, S03, S04, S05, S06, S07, S08, S09, S11, S19, S22, X02) |
| T1134 Access Token Manipulation | I14, WE03, WE05 | T1134.001 Token Impersonation/Theft (I14); T1134.005 SID-History Injection (WE03) |
| T1070 Indicator Removal | CS05, L07 | T1070.003 Clear Command History (L07); T1070.006 Timestomp (L07) |
| T1055 Process Injection | CS06, WE10 | T1055.012 Process Hollowing (CS06) |
| T1014 Rootkit | DV04, L09 | - |
| T1684 Social Engineering | E03, E11 | T1684.001 Impersonation (E03, E11) |
| T1197 BITS Jobs | W04 | - |
| T1140 Deobfuscate/Decode Files or Information | L02 | - |
| T1211 Exploitation for Stealth | CS01 | - |
| T1564 Hide Artifacts | E06 | T1564.008 Email Hiding Rules (E06) |
| T1574 Hijack Execution Flow | AD07 | - |
| T1027 Obfuscated Files or Information | W04 | T1027.010 Command Obfuscation (W04) |
| T1542 Pre-OS Boot | DV04 | - |
| T1620 Reflective Code Loading | CS06 | - |
| T1218 System Binary Proxy Execution | W04 | T1218.005 Mshta (W04); T1218.007 Msiexec (W04); T1218.010 Regsvr32 (W04); T1218.011 Rundll32 (W04) |
| T1205 Traffic Signaling | L09 | T1205.002 Socket Filters (L09) |

### Defense Impairment

| Technique | Rules | Sub-techniques covered |
|---|---|---|
| T1685 Disable or Modify Tools | C09, CP01, CP02, CP03, CP04, CP05, CP06, CS01, CS05, DV04, E10, L07, N04, W05, WE01, WE02, WE07, X05 | T1685.001 Disable or Modify Windows Event Log (WE02); T1685.002 Disable or Modify Cloud Log (C09); T1685.005 Clear Windows Event Logs (WE01); T1685.006 Clear Linux or Mac System Logs (L07) |
| T1556 Modify Authentication Process | C02, C11, CP03, I10, I12, L11, N03, N04, S02, S03, S16, WE07 | T1556.002 Password Filter DLL (WE07); T1556.003 Pluggable Authentication Modules (L11); T1556.006 Multi-Factor Authentication (I10, S02, S03, S16); T1556.009 Conditional Access Policies (C02, C11) |
| T1484 Domain or Tenant Policy Modification | AD06, C01, WE03, WE06 | T1484.001 Group Policy Modification (WE03, WE06); T1484.002 Trust Modification (C01) |
| T1686 Disable or Modify System Firewall | C02, C08, W07 | T1686.001 Cloud Firewall (C02, C08); T1686.003 Windows Host Firewall (W07) |
| T1112 Modify Registry | CP06, WE07 | - |
| T1553 Subvert Trust Controls | DV04, W12 | T1553.005 Mark-of-the-Web Bypass (W12); T1553.006 Code Signing Policy Modification (DV04) |
| T1222 File and Directory Permissions Modification | L07 | T1222.002 Linux and Mac Permissions (L07) |
| T1207 Rogue Domain Controller | AD01 | - |

### Credential Access

| Technique | Rules | Sub-techniques covered |
|---|---|---|
| T1110 Brute Force | D01, D02, I05, N02, S02, S05, S09, S12, S13, S14, S15, WE04 | T1110.001 Password Guessing (S13, S14); T1110.003 Password Spraying (D02, I05, S02, S15) |
| T1556 Modify Authentication Process | C02, C11, CP03, I10, I12, L11, N03, N04, S02, S03, S16, WE07 | T1556.002 Password Filter DLL (WE07); T1556.003 Pluggable Authentication Modules (L11); T1556.006 Multi-Factor Authentication (I10, S02, S03, S16); T1556.009 Conditional Access Policies (C02, C11) |
| T1003 OS Credential Dumping | AD02, AD04, AD09, D01, I01, L05, S06, W01, W09, WE07, WE09, WE10 | T1003.001 LSASS Memory (D01, W01, WE07, WE10); T1003.003 NTDS (WE09); T1003.006 DCSync (AD02, I01, S06); T1003.008 /etc/passwd and /etc/shadow (L05) |
| T1552 Unsecured Credentials | AD03, AD09, B07, B08, C10, D01, D02, D03, IN09, L05 | T1552.001 Credentials In Files (B07, B08, D01, D02, D03, IN09, L05); T1552.004 Private Keys (AD03, L05); T1552.005 Cloud Instance Metadata API (L05) |
| T1528 Steal Application Access Token | C05, C11, D02, S05, S16, S19, S20, S23, X02 | - |
| T1558 Steal or Forge Kerberos Tickets | AD08, D01, I03, I04, I13, W09 | T1558.001 Golden Ticket (AD08); T1558.003 Kerberoasting (D01, I03, I13, W09); T1558.004 AS-REP Roasting (D01, I04) |
| T1621 Multi-Factor Authentication Request Generation | C11, I07, S11, S12 | - |
| T1557 Adversary-in-the-Middle | AD12, S07, WE13 | T1557.001 Name Resolution Poisoning and SMB Relay (WE13) |
| T1539 Steal Web Session Cookie | B08, S08, S23 | - |
| T1649 Steal or Forge Authentication Certificates | AD03, AD06, I09 | - |
| T1555 Credentials from Password Stores | AD04, B08 | T1555.003 Credentials from Web Browsers (B08) |
| T1187 Forced Authentication | WE13 | - |

### Discovery

| Technique | Rules | Sub-techniques covered |
|---|---|---|
| T1087 Account Discovery | B04, B09, IN07, S04, S21, W09 | T1087.002 Domain Account (B04, W09); T1087.004 Cloud Account (S04, S21) |
| T1018 Remote System Discovery | B01, B04, CS12, D04, W09 | - |
| T1069 Permission Groups Discovery | B04, B09, S21, W09 | T1069.002 Domain Groups (B04, B09, W09); T1069.003 Cloud Groups (S21) |
| T1046 Network Service Discovery | B01, CS12, D04 | - |
| T1526 Cloud Service Discovery | S04, S21 | - |
| T1482 Domain Trust Discovery | B09, W09 | - |
| T1083 File and Directory Discovery | D03, IN09 | - |
| T1049 System Network Connections Discovery | B04, B09 | - |
| T1613 Container and Resource Discovery | L08 | - |
| T1135 Network Share Discovery | D04 | - |
| T1057 Process Discovery | B09 | - |
| T1082 System Information Discovery | B09 | - |
| T1016 System Network Configuration Discovery | B09 | - |
| T1033 System Owner/User Discovery | B09 | - |

### Lateral Movement

| Technique | Rules | Sub-techniques covered |
|---|---|---|
| T1021 Remote Services | B04, B05, C07, CS10, CS15, CS16, D04, I06, L12, W07, W08, WE14, WE15, X03 | T1021.001 Remote Desktop Protocol (CS15, W07, WE15); T1021.002 SMB/Windows Admin Shares (B05, W08, WE14); T1021.003 Distributed Component Object Model (W08); T1021.004 SSH (CS15, L12); T1021.006 Windows Remote Management (W08); T1021.008 Direct Cloud VM Connections (C07) |
| T1550 Use Alternate Authentication Material | B05, C04, CP01, I07, S07, S08, S17, S19, S20, S22, S23, WE04, WE12 | T1550.001 Application Access Token (C04, I07, S07, S19, S20, S22, S23); T1550.002 Pass the Hash (B05, WE04, WE12); T1550.004 Web Session Cookie (S08) |
| T1534 Internal Spearphishing | E03, E09 | - |
| T1570 Lateral Tool Transfer | B04 | - |
| T1563 Remote Service Session Hijacking | AD13 | T1563.002 RDP Hijacking (AD13) |
| T1072 Software Deployment Tools | W13 | - |

### Collection

| Technique | Rules | Sub-techniques covered |
|---|---|---|
| T1213 Data from Information Repositories | D03, IN01, IN02, IN03, IN04, IN07, IN09 | T1213.001 Confluence (IN03); T1213.002 Sharepoint (D03, IN01, IN02, IN07, IN09) |
| T1114 Email Collection | E06, E07, E09, IN04, IN05, X02 | T1114.002 Remote Email Collection (IN04); T1114.003 Email Forwarding Rule (E06, E07, X02) |
| T1557 Adversary-in-the-Middle | AD12, S07, WE13 | T1557.001 Name Resolution Poisoning and SMB Relay (WE13) |
| T1119 Automated Collection | B07, IN01, IN03 | - |
| T1530 Data from Cloud Storage | C10, IN01, IN04 | - |
| T1005 Data from Local System | B07, C10 | - |
| T1074 Data Staged | DV01 | T1074.001 Local Data Staging (DV01) |

### Command and Control

| Technique | Rules | Sub-techniques covered |
|---|---|---|
| T1572 Protocol Tunneling | CS03, CS09, CS10, CS11, CS13, CS14, CS15, CS16, N09, W10 | - |
| T1090 Proxy | CS09, CS10, CS11, CS14, CS16, N09, S07, S14, S15, W10 | T1090.001 Internal Proxy (CS09, CS10, CS11, CS16); T1090.002 External Proxy (CS14, S14, S15); T1090.003 Multi-hop Proxy (N09, S07) |
| T1071 Application Layer Protocol | B06, B10, CS03, L01, N07, WE10 | T1071.001 Web Protocols (B06, B10, N07); T1071.004 DNS (CS03) |
| T1105 Ingress Tool Transfer | L02, N07, W03, W04, W10 | - |
| T1219 Remote Access Tools | CS13, W10, X06 | T1219.001 IDE Tunneling (CS13) |
| T1573 Encrypted Channel | B06, N09 | - |
| T1571 Non-Standard Port | CS11, N07 | - |
| T1095 Non-Application Layer Protocol | B06 | - |
| T1205 Traffic Signaling | L09 | T1205.002 Socket Filters (L09) |

### Exfiltration

| Technique | Rules | Sub-techniques covered |
|---|---|---|
| T1048 Exfiltration Over Alternative Protocol | CS03, IN05, N08 | T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol (CS03, IN05) |
| T1052 Exfiltration Over Physical Medium | DV01, DV03, DV05 | T1052.001 Exfiltration over USB (DV01, DV03, DV05) |
| T1567 Exfiltration Over Web Service | IN02, IN05, N08 | T1567.002 Exfiltration to Cloud Storage (N08) |
| T1041 Exfiltration Over C2 Channel | N08 | - |
| T1011 Exfiltration Over Other Network Medium | DV03 | - |
| T1537 Transfer Data to Cloud Account | IN02 | - |

### Impact

| Technique | Rules | Sub-techniques covered |
|---|---|---|
| T1490 Inhibit System Recovery | IN06, L10, W06, X05 | - |
| T1485 Data Destruction | IN06, L10, W06 | - |
| T1486 Data Encrypted for Impact | L10, X05 | - |
| T1489 Service Stop | CP05, X05 | - |

## Every rule and its techniques

| Rule | Name | Techniques |
|---|---|---|
| C01 | Entra domain federation or authentication settings changed | T1484.002 |
| C02 | Conditional Access policy created, modified or deleted | T1556.009, T1686.001 |
| C03 | Privileged Entra role assigned or PIM-activated | T1078.004, T1098.003 |
| C04 | Credential added to an application or service principal | T1098.001, T1550.001 |
| C05 | Admin consent or high-privilege Graph permission granted to an application | T1098.001, T1528 |
| C06 | Azure RBAC Owner, User Access Administrator, RBAC Administrator or Contributor assigned at subscription or wider scope | T1098.003 |
| C07 | Azure VM run command, custom script extension or VMAccess password reset | T1021.008, T1098, T1651 |
| C08 | Network security group rule exposes management ports to the internet | T1133, T1686.001 |
| C09 | Azure logging, diagnostics or Defender for Cloud disabled | T1685.002 |
| C10 | Storage account keys listed, disk SAS generated or snapshot exported by unusual principal | T1005, T1530, T1552 |
| C11 | Device code auth outcomes, and Conditional Access block followed by success (bypass) | T1078.004, T1528, T1556.009, T1621 |
| C12 | Azure Automation runbook created or modified, or webhook added | T1053, T1098.001, T1648 |
| E01 | User clicked a URL Mimecast rated malicious, or clicked through a warning | T1204.001, T1566.002 |
| E02 | Malicious attachment verdict on a message that was delivered or released | T1204.002, T1566.001 |
| E03 | Impersonation Protect hit targeting executives or finance | T1534, T1566.003, T1684.001 |
| E04 | Zero-hour auto purge removed a message the user had already clicked | T1566.001, T1566.002 |
| E05 | Safe Links block page clicked through | T1204.001, T1566.002 |
| E06 | Inbox rule that forwards externally, deletes, or hides security-related mail | T1114.003, T1564.008 |
| E07 | Mailbox forwarding to an external address, or transport rule that redirects or BCCs mail out | T1114.003 |
| E08 | Full access, Send As or folder owner/editor permission granted on a mailbox | T1098.002 |
| E09 | Internal account sending outbound mail that Mimecast holds as spam or rejects, at volume | T1078.004, T1114, T1534 |
| E10 | Mimecast protection policy weakened or bypass created | T1078, T1685 |
| E11 | Email bombing (inbound flood to a single recipient) | T1566, T1684.001 |
| E13 | ZAP post-delivery removal across many recipients (phishing or malware wave) | T1566.001, T1566.002 |
| E14 | Message rated malicious after delivery but still in the inbox (remediation gap) | T1566.001, T1566.002 |
| W01 | LSASS memory dump via known tooling or LOLBIN | T1003.001 |
| W02 | Office, browser, mail client or archiver spawning a script host or LOLBIN | T1059, T1204.002, T1566.001 |
| W03 | Script host or LOLBIN launched from Explorer - ClickFix, FileFix or CrashFix pasted command, or a script file opened from Downloads, temp or an archive | T1059.001, T1105, T1204.002, T1204.004 |
| W04 | LOLBIN download cradle or remote script execution | T1027.010, T1059.001, T1105, T1197, T1218.005, T1218.007, T1218.010, T1218.011 |
| W05 | Defender or security service stopped, Defender engine wiped, EDR-killer tooling, or safe boot configured | T1068, T1685 |
| W06 | Shadow copy deletion, backup catalog wipe or boot recovery disabled | T1485, T1490 |
| W07 | Local account created, added to Administrators, or RDP enabled by command line | T1021.001, T1098, T1136.001, T1686.003 |
| W08 | Remote execution landing on a host via service, WMI, WinRM, DCOM or remote scheduled task | T1021.002, T1021.003, T1021.006, T1047, T1053.005, T1569.002 |
| W09 | Active Directory attack tool signature (SharpHound/BloodHound, Rubeus, Certify/Certipy, PowerView, AdFind and similar) by argument or binary name | T1003, T1018, T1069.002, T1087.002, T1482, T1558.003 |
| W10 | Unapproved remote management or tunnelling tool executed | T1090, T1105, T1219, T1572 |
| W11 | COM hijack or Office add-in persistence | T1137.006, T1546.015 |
| W12 | Disk image mounted then a process runs from the new volume | T1204.002, T1553.005 |
| W13 | Endpoint management platform used to deploy a script or app at scale | T1072 |
| W14 | Microsoft Defender for Endpoint high-severity alerts as first-class alerts | (vendor alerts, various) |
| L01 | Reverse shell launched | T1059.004, T1071 |
| L02 | Remote script piped straight into a shell or interpreter | T1059.004, T1105, T1140 |
| L03 | Web or application server process spawning a shell or interpreter | T1059.004, T1190, T1505.003 |
| L04 | Persistence via cron, systemd unit, shell profile or SSH authorized_keys | T1053.003, T1098.004, T1543.002, T1546.004 |
| L05 | Credential file access, SSH key harvesting or cloud metadata theft | T1003.008, T1552.001, T1552.004, T1552.005 |
| L06 | Privilege escalation via SUID abuse, sudo misconfig or known exploit pattern | T1068, T1548.001, T1548.003 |
| L07 | Log clearing, shell history tamper or timestomping | T1070.003, T1070.006, T1222.002, T1685, T1685.006 |
| L08 | Container escape, privileged container launch or Docker socket abuse | T1610, T1611, T1613 |
| L09 | Suspicious kernel module load or rootkit indicator | T1014, T1205.002, T1547.006 |
| L10 | Rapid mass file modification consistent with encryption or wiping | T1485, T1486, T1490 |
| L11 | PAM module or NSS configuration changed (authentication backdoor) | T1543, T1556.003 |
| L12 | SSH fan-out from one Linux host to many internal hosts | T1021.004 |
| I01 | DCSync by a non-domain-controller principal | T1003.006 |
| I02 | Membership change to a Tier-0 / privileged group | T1078.002, T1098 |
| I03 | Kerberoasting: TGS requests with weak encryption at volume | T1558.003 |
| I04 | AS-REP roasting or Kerberos pre-authentication disabled | T1098, T1558.004 |
| I05 | Password spray against Active Directory (failed logons across many accounts from one source) | T1110.003 |
| I06 | Privileged account interactive logon to a workstation or unusual host | T1021, T1078.002 |
| I07 | Entra impossible travel, risky sign-in, or session token replay | T1078.004, T1550.001, T1621 |
| I09 | AD Certificate Services abuse (ESC1/ESC6 style certificate issuance) | T1649 |
| I10 | MFA method registered from a new context, or authentication policy weakened | T1098.005, T1556.006 |
| I11 | AdminSDHolder object modified | T1078.002, T1098 |
| I12 | Shadow credentials written to a user or computer (msDS-KeyCredentialLink) | T1098, T1556 |
| I13 | Service principal name added to a user account (targeted Kerberoasting setup) | T1098, T1558.003 |
| I14 | Delegation configured on an account (unconstrained, constrained, protocol transition or resource-based) | T1098, T1134.001 |
| N01 | F5 APM VPN successful logon showing impossible travel or two countries | T1078, T1133 |
| N02 | F5 APM VPN brute force or spray followed by success | T1110, T1133 |
| N03 | F5 APM session established without expected MFA step | T1078, T1133, T1556 |
| N04 | F5 APM/TMOS administrative change or access policy modification | T1078, T1556, T1685 |
| N05 | Imperva WAF high-severity attack that was not blocked | T1059, T1190 |
| N06 | Imperva source heavily blocked then receives an application success | T1190, T1595.002 |
| N07 | Zscaler C2, malware callback or known-bad category from an endpoint, allowed or blocked | T1071.001, T1105, T1571 |
| N08 | Zscaler large upload to a new or risky destination (possible exfiltration) | T1041, T1048, T1567.002 |
| N09 | Zscaler anonymizer, proxy-avoidance, unsanctioned VPN or DNS-over-HTTPS use | T1090.003, T1572, T1573 |
| N10 | External reconnaissance scan against the Imperva-protected web edge (one source, many URIs) | T1595.002, T1595.003 |
| CS01 | Vulnerable or unsigned driver loaded (BYOVD) | T1068, T1211, T1685 |
| CS02 | Persistence written to Run keys, Winlogon, IFEO or other ASEPs (not services) | T1546, T1547.001 |
| CS03 | DNS tunnelling - many long, distinct names under one parent domain from one host | T1048.003, T1071.004, T1572 |
| CS04 | CrowdStrike Falcon platform detections (high/critical) as first-class alerts | (vendor alerts, various) |
| CS05 | Falcon sensor uninstalled, stopped, or stopped reporting | T1070, T1685 |
| CS06 | Process injection, hollowing or suspicious remote thread | T1055, T1055.012, T1620 |
| CS07 | Scheduled task created or modified pointing at a suspicious payload | T1053.005 |
| CS08 | Reference: push these to Falcon custom IOAs, not just Elastic | (vendor alerts, various) |
| CS09 | Windows port forward created with netsh portproxy (traffic relayed through this host) | T1090.001, T1572 |
| CS10 | Web server process connects to internal RDP, SMB, SSH, WinRM or RPC on a host it has never contacted (webshell tunnel or pivot) | T1021, T1090.001, T1505.003, T1572 |
| CS11 | Program starts accepting connections from other internal hosts, new on this host and rare in the fleet (implant listener or pivot) | T1090.001, T1571, T1572 |
| CS12 | Network scanner run (nmap, masscan, rustscan, zmap, naabu, Advanced IP/Port Scanner, SoftPerfect NetScan, Angry IP Scanner, nbtscan, fscan) | T1018, T1046 |
| CS13 | VS Code tunnel started on an endpoint (code tunnel, Remote Tunnel Access) | T1219.001, T1572 |
| CS14 | Tunnel service agent running on an endpoint (Cloudflare, ngrok, Tailscale, ZeroTier, SSH tunnel services, bore and others) | T1090.002, T1572 |
| CS15 | RDP or SSH reached from the host itself (traffic relayed in by a tunnel, whatever it's called) | T1021.001, T1021.004, T1572 |
| CS16 | Rare program connects to RDP, SSH, SMB or WinRM on other internal hosts (pivot through a tunnel or implant) | T1021, T1090.001, T1572 |
| X01 | Email phishing interaction followed by endpoint alert on the same user's host | T1059, T1204, T1566 |
| X02 | Identity compromise fan-out: risky sign-in then persistence or privilege action | T1078.004, T1098, T1098.005, T1114.003, T1528 |
| X03 | VPN logon anomaly followed by internal attack behaviour | T1021, T1078, T1133 |
| X04 | WAF exploitation attempt followed by shell or callback on the web host | T1059, T1190, T1505.003 |
| X05 | Ransomware precursor chain on one host | T1486, T1489, T1490, T1685 |
| X06 | External Teams contact followed by remote-access tool on the same user's host | T1204, T1219, T1566 |
| X07 | Directory persistence written shortly after the actor gained privileged access | T1078.002, T1098 |
| S01 | Break-glass (emergency access) account sign-in | T1078.004 |
| S02 | Successful legacy authentication, ROPC flow, or known spray-tool user agent | T1078.004, T1110.003, T1556.006 |
| S03 | Privileged account signed in with a single factor to an admin surface | T1078.004, T1556.006 |
| S04 | Microsoft first-party CLI or PowerShell app used by a non-administrator | T1078.004, T1087.004, T1526 |
| S05 | Service principal sign-in from a new network, or secret-guessing failures | T1078.004, T1110, T1528 |
| S06 | On-premises directory synchronization account used outside the Entra Connect server | T1003.006, T1078.004, T1098 |
| S07 | Sign-in from hosting, VPN or anonymizer infrastructure on an unregistered device (high when MFA was satisfied by a replayed token claim) | T1078.004, T1090.003, T1550.001, T1557 |
| S08 | One sign-in session used from multiple countries or networks | T1078.004, T1539, T1550.004 |
| S09 | Sign-in attempts against disabled or leaver accounts | T1078.004, T1110 |
| S11 | Help-desk MFA reset followed by sign-in from a new location | T1078.004, T1098.005, T1621 |
| S12 | MFA fatigue (repeated denied or unanswered MFA prompts), critical if then accepted | T1110, T1621 |
| S13 | Brute force against one account from a single IP | T1110.001 |
| S14 | Distributed brute force against one account from many IPs | T1090.002, T1110.001 |
| S15 | Password spray across many accounts, from many IPs (client fingerprint) or from one IP | T1090.002, T1110.003 |
| S16 | Windows Hello for Business key enrolled after a device-code sign-in (PRT phishing chain) | T1098.005, T1528, T1556.006 |
| S17 | Device-less Windows Hello or passkey sign-in followed by device registration (borrowed Hello key) | T1098.005, T1550 |
| S18 | Device registered with roadtx default fingerprint or a non-standard registration client | T1098.005 |
| S19 | Microsoft Authentication Broker sign-in from a non-standard client | T1078.004, T1528, T1550.001 |
| S20 | Broker refresh token redeemed for device registration, device registered, then PRT used from an unmanaged device | T1098.005, T1528, T1550.001 |
| S21 | ROADrecon-style tenant enumeration through Azure AD Graph | T1069.003, T1087.004, T1526 |
| S22 | Several different people signing in successfully from one Entra-registered or joined device | T1078.004, T1098.005, T1550.001 |
| S23 | Non-interactive (refresh token) sign-in from a network the user has never signed in from interactively | T1528, T1539, T1550.001 |
| WE01 | Security or System event log cleared | T1685.005 |
| WE02 | Audit logging removed from a monitored subcategory, or per-user audit policy set | T1685.001 |
| WE03 | Domain trust, SID History or DSRM password change | T1098, T1134.005, T1484.001 |
| WE04 | Explicit credentials used to log on to many remote hosts from one machine (RunAs / per-connection credential fan-out) | T1078, T1110, T1550.002 |
| WE05 | Sensitive privilege assigned or special logon to a non-admin account | T1068, T1078.002, T1134 |
| WE06 | Default domain GPO modified, or a GPO given a scheduled task, script or software install | T1078.002, T1484.001 |
| WE07 | WDigest re-enabled, LSA protection weakened, LSA packages changed, or DSRM network logon enabled | T1003.001, T1112, T1547.002, T1547.005, T1556.002, T1685 |
| WE08 | New service or kernel driver installed on a domain controller or server | T1068, T1543.003, T1569.002 |
| WE09 | NTDS.dit access, volume shadow copy creation, or ntdsutil on a domain controller | T1003.003 |
| WE10 | Microsoft Defender detection or Exploit Guard block (malware, high-signal ASR rule, non-browser network protection) | T1003.001, T1055, T1059, T1068, T1071, T1204, T1505.003 |
| WE11 | WMI permanent event subscription with a script or command consumer | T1546.003 |
| WE12 | New-credentials logon consistent with pass-the-hash | T1550.002 |
| WE13 | Domain controller machine account authenticating with NTLM to a non-DC or from an unexpected IP | T1187, T1557.001 |
| WE14 | Admin share or remote management pipe accessed from a workstation | T1021.002, T1053.005, T1569.002 |
| WE15 | RDP logon from one workstation to another | T1021.001 |
| B01 | Internal network or port scan - one process probes many internal host:port endpoints | T1018, T1046 |
| B04 | Lateral sweep over SMB, RPC, RDP, WinRM or LDAP from one host (catches by behaviour: SharpHound/BloodHound collection, PsExec/Impacket sweeps, CrackMapExec/NetExec) | T1018, T1021, T1049, T1069.002, T1087.002, T1570 |
| B05 | Network logon sweep - catches CrackMapExec, NetExec and pass-the-hash lateral movement by behaviour | T1021.002, T1078, T1550.002 |
| B06 | C2 beaconing - catches Cobalt Strike, Sliver, Mythic, Havoc, Brute Ratel by behaviour | T1071.001, T1095, T1573 |
| B07 | Mass file read or collection - catches TruffleHog, gitleaks and data-collection tools by behaviour | T1005, T1119, T1552.001 |
| B08 | Credential store harvesting - catches LaZagne and infostealers by behaviour | T1539, T1552.001, T1555, T1555.003 |
| B09 | Host discovery command burst, high when it includes domain enumeration - catches post-exploitation recon and loaders by behaviour | T1016, T1033, T1049, T1057, T1069.002, T1082, T1087, T1482 |
| B10 | Steady beaconing to an uncategorised or newly registered domain, by at most three users (Zscaler) | T1071.001 |
| IN01 | Mass SharePoint or OneDrive download by one user, at any hour or as a smaller after-hours burst | T1119, T1213.002, T1530 |
| IN02 | External or anonymous sharing of SharePoint/OneDrive content at volume | T1213.002, T1537, T1567 |
| IN03 | Confluence space or site export, or page export at volume | T1119, T1213.001 |
| IN04 | eDiscovery or content search created, exported or downloaded by a non-eDiscovery user | T1114.002, T1213, T1530 |
| IN05 | Outbound mail with attachments to personal webmail at volume | T1048.003, T1114, T1567 |
| IN06 | Mass file or site deletion (insider sabotage) | T1485, T1490 |
| IN07 | Broad SharePoint access across many sites the user does not own | T1087, T1213.002 |
| IN09 | SharePoint search for secrets followed by sensitive file access or bulk download | T1083, T1213.002, T1552.001 |
| CP01 | Defender for Office 365 protection rule or policy disabled, deleted or switched off, including zero-hour auto purge (ZAP) | T1550, T1685 |
| CP02 | Quarantine release of malware or high-confidence phish, or release at volume | T1566, T1685 |
| CP03 | Tenant Allow/Block List allow entry added for a sender, domain, URL, file or spoofed sender | T1556, T1685 |
| CP04 | CrowdStrike sensor stuck in Reduced Functionality Mode, or in RFM and no longer reporting | T1685 |
| CP05 | Microsoft Defender health degraded, or the Defender AV or MDE sensor service stopped and stayed down | T1489, T1685 |
| CP06 | Microsoft Defender protection weakened (real-time off, exclusion added, ASR or network protection off, tamper attempt) | T1112, T1685 |
| AD01 | Rogue domain controller registration (DCShadow) | T1207 |
| AD02 | Directory replication (DCSync) rights granted on the domain root | T1003.006, T1098 |
| AD03 | Certificate authority private key backed up or exported (golden certificate) | T1552.004, T1649 |
| AD04 | Domain DPAPI backup key retrieved from a domain controller | T1003, T1555 |
| AD05 | Computer account changed to impersonate a domain controller, or created by a standard user | T1068, T1078.002, T1136.002 |
| AD06 | AD CS template, CA configuration or certificate-mapping enforcement weakened | T1484, T1649 |
| AD07 | DNS server plugin DLL configured on a domain controller (DnsAdmins abuse) | T1068, T1574 |
| AD08 | Kerberos service tickets used by an account with no TGT issued (possible forged golden ticket) | T1558.001 |
| AD09 | Group managed service account password read by a user account | T1003, T1552 |
| AD10 | Password of a Tier-0 account reset by another account | T1098 |
| AD11 | SQL Server or IIS application spawning a shell (xp_cmdshell, Exchange or SharePoint webshell) | T1190, T1505.001, T1505.003 |
| AD12 | ADIDNS wildcard, WPAD or ISATAP record created by a user account | T1557 |
| AD13 | RDP session hijacked with tscon | T1563.002 |
| DV01 | Bulk copy of documents or archives to removable media | T1052.001, T1074.001 |
| DV02 | New keyboard device followed within seconds by a shell launched from Explorer (keystroke injection, Rubber Ducky, O.MG cable) | T1059.001, T1059.003, T1200 |
| DV03 | USB or Bluetooth network adapter, storage or phone connected to a server or domain controller | T1011, T1052.001, T1200 |
| DV04 | Boot integrity weakened (test signing, integrity checks off or kernel debugging on), set by bcdedit or loaded at boot | T1014, T1542, T1553.006, T1685 |
| DV05 | Device installation blocked by policy (network adapter, keyboard, storage or phone; any block on a server; repeated attempts) | T1052.001, T1200 |
| D01 | Honey AD account touched (kerberoast of honey SPN, AS-REP roast, or any logon or authentication attempt with honey credentials) | T1003.001, T1078.002, T1110, T1552.001, T1558.003, T1558.004 |
| D02 | Sign-in attempt by a honey Entra user or honey service principal (any result) | T1078.004, T1110.003, T1528, T1552.001 |
| D03 | Decoy SharePoint/OneDrive file or Confluence page opened, previewed, downloaded or copied | T1083, T1213.002, T1552.001 |
| D04 | Decoy host name looked up, or decoy host connected to (OpenCanary, decoy DNS records) | T1018, T1021, T1046, T1135 |

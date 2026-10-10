# AD attack detections

Detections for Active Directory attack paths from the "Active Directory Attack Architecture Map v2.0" (kypvas/ad_attack_architecture) that the library did not already cover. Every technique on the map was checked against the existing 157 rules first. A technique already detected elsewhere gets no new rule here, and a variant of an existing rule was added to that rule instead of becoming a new one.

## New rules, ranked by criticality

Rank reflects impact (how close the technique is to full domain compromise) and fidelity (how rarely the signal occurs legitimately).

| Rank | Rule | Detects | Severity | Prerequisite |
|---|---|---|---|---|
| 1 | AD01 | Rogue domain controller registration (DCShadow) | critical | SACL on the Sites container (5137) |
| 2 | AD02 | Replication (DCSync) rights granted on the domain root | critical | Directory-object auditing (5136) |
| 3 | AD03 | CA private key backed up or exported (golden certificate) | critical | CA backup auditing (4876/4877); list CA hosts |
| 4 | AD04 | Domain DPAPI backup key retrieved | critical | 4662 for LSA secret objects on DCs |
| 5 | AD05 | Computer account changed to impersonate a DC (sAMAccountName or dNSHostName spoofing, anonymous change), or created by a standard user | critical / medium | Account management auditing |
| 6 | AD06 | AD CS template, CA configuration or certificate-mapping enforcement weakened (ESC4, 6, 7, 9, 10, 11, 16) | high | Template auditing (5136), CA config auditing |
| 7 | AD07 | DNS server plugin DLL configured on a DC (DnsAdmins abuse) | high | FDR registry events |
| 8 | AD08 | Service tickets used with no TGT issued (forged golden ticket) | high | 4768/4769/4770 from every DC; tune first |
| 9 | AD09 | gMSA password read by a user account | high | SACL on gMSA objects (4662) |
| 10 | AD10 | Tier-0 account password reset by another account | high | 4724 |
| 11 | AD11 | SQL Server or IIS application spawning a shell (xp_cmdshell, Exchange or SharePoint webshell) | high | FDR process events |
| 12 | AD12 | ADIDNS wildcard, WPAD or ISATAP record created by a user | medium | SACL on DNS partitions (5137) |
| 13 | AD13 | RDP session hijacked with tscon | medium | FDR process events |

## Existing rules extended instead of duplicated

| Rule | Added |
|---|---|
| I14 | Now covers all four delegation types (unconstrained, constrained, protocol transition, resource-based) in one rule, instead of resource-based only. File renamed to `I14-delegation-configured.md`. |
| WE07 | Now also covers LSA security, authentication and notification package changes (custom SSP, password filters) and `DsrmAdminLogonBehavior` set to 2 (DSRM backdoor). |

## Coverage of the map

| Map section | Covered by |
|---|---|
| Kerberos attacks: Kerberoasting, AS-REP roasting, targeted Kerberoasting (WriteSPN) | I03, I04, I13 |
| Golden ticket | AD08 (diamond, sapphire and silver tickets have no reliable log signal without Defender for Identity) |
| Credential dumping: LSASS, SAM, NTDS.dit, DCSync | W01, WE09, I01 |
| DPAPI | AD04 (domain backup key); B08 (user credential stores) |
| Coercion and NTLM relay | WE13; AD12 for ADIDNS-based capture |
| Delegation: unconstrained, constrained, RBCD | I14 (extended) |
| ACL abuse: AdminSDHolder, DCSync rights, password reset, gMSA and LAPS reads, shadow credentials | I11, AD02, AD10, AD09, I12 |
| GPO abuse | WE06 |
| AD CS ESC1 to ESC16, golden certificate | I09 (malicious issuance), AD06 (configuration), AD03 (CA key) |
| Trusts and SID History | WE03 |
| Persistence: DCShadow, DSRM, custom SSP, SID History, AdminSDHolder, GPO | AD01, WE03 + WE07, WE07, WE03, I11, WE06 |
| CVEs: noPac, Certifried, ZeroLogon | AD05 |
| DnsAdmins | AD07; I02 for DnsAdmins membership |
| MSSQL and Exchange | AD11 |
| Lateral movement: pass-the-hash, remote execution, RDP | WE12, W08, B04, B05, WE14, WE15, AD13 |
| Machine account quota abuse, KrbRelayUp | AD05 (computer created by user) + I14 |
| Entra hybrid: Entra Connect, PRT theft, device code, consent phishing | S06, S16 to S21, I08, C05 |
| Local privilege escalation, AMSI and EDR evasion | W05, CS01, CS06; mostly Falcon's own detections (CS04) |

### Not built, and why
- **SCCM and WSUS attacks:** need SCCM and WSUS server logs, which are not in the current data sources.
- **Skeleton Key:** an in-memory LSASS patch on a DC; Falcon's own detections (CS04) and LSASS access rules (W01, CS06) are the realistic coverage.
- **Diamond, sapphire and silver tickets:** they use genuinely issued tickets or skip the DC entirely, so domain controller logs have no dependable signal.
- **Password cracking, physical access, macOS and mobile:** offline or outside the current telemetry.
- **The map's 2025 to 2026 CVE list:** patch-driven. Some entries could not be verified, and at least one ID is wrong on the map (it labels SMBGhost as CVE-2025-53770; SMBGhost is CVE-2020-0796).

## Overlap in the existing library, and a recommendation

The three Kerberoasting rules detect three different things, but one of them also duplicates other rules:
- **I03** detects the roast itself: a burst of weak-encryption service-ticket requests. It is the behavioural Kerberoasting rule and catches any tool.
- **I13** detects a different step: someone writing an SPN onto a user so that user can be roasted (targeted Kerberoasting). It stays.
- **W09** is the real duplicate. Its keyword branch matches tool arguments (`kerberoast`, `asreproast`, `asktgt`) already covered by behaviour in I03 and I04, and credential-dumping keywords (`sekurlsa`, `lsadump`, `dcsync`) already owned by W01 and I01. Its recon branch counts the same nine discovery utilities as B09.

Recommended: trim W09 to a tool-signature rule only (BloodHound/SharpHound, AdFind, Certify/Certipy, Whisker and similar collectors and their arguments), and drop its roasting keywords, its credential-dumping keywords and its recon branch. One trade-off: I03 needs eight or more SPNs in ten minutes, so a single-account roast with an unrenamed tool would then rely on I13 catching the SPN write that usually precedes it. This change has not been made.

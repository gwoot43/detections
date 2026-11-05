# Active Directory attacks — detection reference

What each commonly used AD attack achieves, the Windows events that record it, and the fields that decide
whether a detection is possible at all. Written for the AD/platform team: every row implies an audit-policy
prerequisite, and the field column is what must survive into the pipeline — an event that is collected but
missing a field below cannot be detected, only correlated.

Audit prerequisites are grouped at the end, so the switches can be turned on once rather than per row.

## A. Credential replication and ticket forgery

| Attack | What the attacker gets | Events | Fields required |
|---|---|---|---|
| **DCSync** (T1003.006) — impersonate a DC and ask it to replicate | Every password hash in the domain, including `krbtgt` | `4662` on the DC | `ObjectName` (the domain NC), `Properties` (the ACE GUIDs), `AccessMask`, `SubjectUserName`, `SubjectUserSid`. The rights are `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes-All) and `89e95b76-444d-4c62-991a-0facbeda640c` (…-In-Filtered-Set); `1131f6aa-…` alone is ordinary directory sync. Without the control-access mask (`0x100`) the row can still be found by GUID — which is why the GUIDs matter more than the mask |
| **Golden ticket** (T1558.001) — forge a TGT with the `krbtgt` hash | Unbounded, long-lived domain admin access | No single event. `4769` with anomalous encryption, `4624` with no matching `4768`, `4724` where `TargetUserName = krbtgt` | `ServiceName`, `TicketEncryptionType`, `TicketOptions`, `IpAddress`, `LogonType`, `TargetUserName`. Only the `krbtgt` password reset is crisp; the rest is correlation |
| **Kerberoasting** (T1558.003) — request RC4 service tickets for offline cracking | A crackable hash for any account with an SPN, often a service account with rights | `4769` | `ServiceName` (this is the **SPN**, e.g. `MSSQLSvc/host`, never an account name), `TicketEncryptionType` (`0x17` = RC4), `TicketOptions`, `Status`, `TargetUserName` (the requester), `IpAddress` |
| **AS-REP roasting** (T1558.004) — target accounts with pre-authentication disabled | An offline-crackable AS-REP with no credentials needed | `4768` | `PreAuthType` (`0` = no pre-auth), `Status`, `TargetUserName`, `IpAddress` |
| **Pass-the-hash** (T1550.002) — authenticate with an NTLM hash | Lateral movement with no plaintext or ticket | `4624`, `4776` | `LogonType` (`3`, `9`), `AuthenticationPackageName` (`NTLM`), `WorkstationName`, `IpAddress`, `TargetUserName`; on `4776` the `Workstation` and `Status` |
| **Overpass-the-hash / pass-the-ticket** (T1550.003) — hash to TGT, or replay a stolen ticket | Kerberos access without the account's password | `4624`, `4768`, `4769` | `AuthenticationPackageName` (`Kerberos`), `LogonType`, `IpAddress`, `TicketEncryptionType`; the tell is a logon with no corresponding AS-REQ from the same address |

## B. Privilege escalation and directory permissions

| Attack | What the attacker gets | Events | Fields required |
|---|---|---|---|
| **SID History injection** (T1134.005) — write a privileged SID into an account's `sIDHistory` | Silent inheritance of another account's rights, including domain admin | `4765`, `4766` (failure), `4738` | `TargetUserName`, `SidHistory`, `SubjectUserName`, `TargetSid` |
| **AdminSDHolder ACL modification** (T1098, T1222) — write an ACE on the template SDProp copies hourly | Persistent rights over every protected account, restored after cleanup | `5136` | `ObjectDN` (`CN=AdminSDHolder,CN=System,…`), `AttributeLDAPDisplayName` (`nTSecurityDescriptor`), `AttributeValue` (the ACE), `OperationType`, `SubjectUserName` |
| **ACL grant on the domain object** (T1098) — add DCSync or `GenericAll` for an owned account | Domain replication or full control, without touching a group | `5136` | `ObjectDN` (the domain NC), `AttributeLDAPDisplayName` (`nTSecurityDescriptor`), `AttributeValue` — the added ACE names the trustee and the replication GUID |
| **Tier-0 group membership** (T1098.007) — add an account to Domain/Enterprise/Schema Admins | Direct domain or forest control | `4728` (global), `4732` (local), `4756` (universal) | `MemberName`, `MemberSid`, `TargetUserName` and `TargetSid` (the group), `SubjectUserName`. Match the group by **RID** (`-512`, `-519`, `-518`, `-516`, `-520`), not by name |
| **`primaryGroupID` escalation** — point a user's primary group at Domain Admins | Membership with **no group-membership event at all** | `4738`, and `4662` when written over LDAP | `PrimaryGroupID` (or the changed-attribute list on `4738`), `TargetUserName`, `ObjectName`/`ObjectDN`, `SubjectUserName` |
| **RBCD and delegation changes** (T1134.001) — write `msDS-AllowedToActOnBehalfOfOtherIdentity`, or set TRUSTED_FOR_DELEGATION | Impersonate any user to a target service, or capture a DC's credentials | `5136` | `ObjectDN` (the computer), `AttributeLDAPDisplayName` (`msDS-AllowedToActOnBehalfOfOtherIdentity` or `userAccountControl`), `AttributeValue`, `SubjectUserName` |
| **Shadow credentials** (T1098) — write `msDS-KeyCredentialLink` on a target | Passwordless takeover of the target account or computer | `5136` | `ObjectDN`, `AttributeLDAPDisplayName` (`msDS-KeyCredentialLink`), `AttributeValue`, `SubjectUserName` |
| **Computer account takeover** (T1098) — reset an existing machine account's password, or create one via `ms-DS-MachineAccountQuota` | Authenticate as that machine; the route into RBCD and silver tickets | `4724` (reset), `4741` (created) | `TargetUserName` (ends `$`), `SubjectUserName`, `TargetSid` — a machine account reset by a *user* account is the finding |

## C. Persistence in the directory

| Attack | What the attacker gets | Events | Fields required |
|---|---|---|---|
| **DCShadow** (T1207) — register a rogue DC and push changes through replication | Writes to AD that bypass change auditing entirely | `5137` (object created), `5136` (SPN added) | `ObjectClass` (`nTDSDSA`, `server`), `ObjectDN`/`DN` (under `CN=Sites,CN=Configuration`), `AttributeLDAPDisplayName` (`servicePrincipalName`), `AttributeValue` (`E3514235-4B06-11D1-AB04-00C04FC2DCD2/…` or `GC/…`), `OperationType`, `SubjectUserName` |
| **Domain trust creation or modification** (T1484.001) — add or re-point a trust | Cross-forest access, and SID-filtering bypass when combined with SID History | `4706`, `4716` (`4707` on removal) | `DomainName`, `TargetDomainName`, `TdoAttributes`, `Direction`, `SubjectUserName`. `4716` also fires on the trust's scheduled password rotation, so the **subject** is what separates routine from hostile |
| **DSRM password change** (T1098) — set the Directory Services Restore Mode password | Local admin on a domain controller, outside the domain's control | `4794` | `SubjectUserName`, `TargetUserName` (the DC) |
| **GPO abuse** (T1484.001) — modify a GPO that applies to Tier-0 or to all hosts | Code execution on every host the policy reaches | `5136` (groupPolicyContainer), `4663`/`5145` on `SYSVOL` | `ObjectDN`, `AttributeLDAPDisplayName` (`versionNumber`, `gPCFileSysPath`, or `gPLink` on the OU), `AttributeValue`, `SubjectUserName` |
| **Service or driver install on a DC** (T1543.003) | System-level execution, and a persistence foothold on a Tier-0 host | `7045`, `4697` | `ServiceName`, `ImagePath`, `ServiceType`, `StartType`, `SubjectUserName` |

## D. Certificate services (AD CS)

| Attack | What the attacker gets | Events | Fields required |
|---|---|---|---|
| **ESC1/2/3/4/9/10 certificate abuse** (T1649) — request a certificate that authenticates as another principal | A credential that works for Kerberos, and survives a password reset | `4886`, `4887` on the CA; `4768` (PKINIT) on the DC | CA: `RequestId`, `RequesterName`, `Attributes` (template name, SAN, and whether the requester supplied the subject). DC: `PreAuthType` (`15`/`16`/`17`), `CertIssuerName`, `CertSerialNumber`, `TargetUserName` |
| **UnPAC-the-hash** — certificate logon, then a service ticket to the account itself | The account's NT hash, from a certificate alone | `4768` then `4769` | `TargetSid` on the logon and `ServiceSid` on the ticket (the same SID when the ticket is to itself), `IpAddress`, `ServiceName` |
| **Certificate-mapping failure** (T1649) — use a certificate that does not belong to the account | The attempt itself, before it succeeds elsewhere | KDC `39`, `40`, `41` (System channel) | `TargetUserName`/`AccountName` and the provider name (the IDs are reused by other providers) |
| **ESC8 / NTLM relay to the CA** (T1557) | A certificate for a relayed machine or user, with no cracking | CA IIS logs, `4624` on the CA, `5145` on `\pipe\cert` | `IpAddress`, `SubjectUserName`, `RelativeTargetName` (the pipe) |

## E. Reconnaissance and defence evasion

| Attack | What the attacker gets | Events | Fields required |
|---|---|---|---|
| **Directory enumeration** (T1087.002, BloodHound/SharpHound) — read ACLs, group membership, sessions | The attack graph: who can reach what | `1644` (LDAP searches, needs high diagnostics); `4662` for object reads; `5145` for the SMB/RPC half | `1644`: `SearchFilter`, `SDFlags`, client address. `4662`: `ObjectName`, `Properties`, `AccessMask`, `SubjectUserName`. `5145`: `RelativeTargetName` (`srvsvc`, `samr`, `wkssvc`, `winreg`, `lsarpc`, `efsr`) |
| **NTLM relay / coercion** (T1557, T1187) — force a machine to authenticate to the attacker | A machine or DC credential to relay | `4624` type 3 on the target, `5145` pipe access, network telemetry | `TargetUserName` (ends `$`), `IpAddress`, `AuthenticationPackageName`, `LogonType`, `RelativeTargetName` |
| **Audit policy tampering** (T1562.002) | Detection switched off before the attack | `4719`, `4907` | `CategoryId`, `SubcategoryGuid`, `AuditPolicyChanges`, `SubjectUserName` |
| **Log clearing** (T1070.001) | The evidence of everything above | `1102` (Security), `104` (System) | `SubjectUserName`, `SubjectDomainName` |
| **Kerberos or NTLM spray** (T1110.003) | A valid credential among many attempts | `4625`, `4771`, `4776` | `TargetUserName`, `Status`/`SubStatus`, `IpAddress`, `WorkstationName` |

## Audit prerequisites

| Requirement | Where | Enables |
|---|---|---|
| **Audit Directory Service Access** + a SACL on the domain NC auditing **Control Access** and **Read Property** | Default Domain Controllers Policy → Advanced Audit Policy → DS Access; SACL on the domain object | DCSync, ACL reads, security-descriptor enumeration, replication-rights grants (`4662`) |
| **Audit Directory Service Changes** + SACLs on the domain NC, `CN=System`, the configuration partition, and the site container (`Create Child`) | Same policy; SACLs on the objects | DCShadow, AdminSDHolder, RBCD, shadow credentials, GPO and trust changes, `primaryGroupID` writes (`5136`/`5137`) |
| **Audit Account Management** | Advanced Audit Policy → Account Management | Tier-0 group changes, account creation and resets, SID History (`4720`–`4794`) |
| **Audit Kerberos Authentication Service** and **Audit Kerberos Service Ticket Operations** | Account Logon, on the DCs | Kerberoasting, AS-REP roasting, PKINIT, ticket-to-self (`4768`/`4769`) |
| **Audit Detailed File Share** | Object Access, on DCs and file servers | Pipe names for SMB/RPC collection and relays (`5145`, `RelativeTargetName`) |
| **Audit File System** + a SACL on `C:\Windows\NTDS` and the shadow-copy paths | Object Access | `ntds.dit` and hive reads (`4663`) |
| **NTDS diagnostics `15 Field Engineering` = 5** | `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics` | LDAP search filters and `SDFlags` (`1644`). Expensive — 10-50k events/sec on a busy DC, so a bounded window rather than a permanent setting |
| **Audit Filtering Platform Connection** | Object Access, on the DCs only | Client attribution for connections the DC records as `::1`, notably ADWS (`5156`) |
| **Certificate Services auditing** (default when the CA role is installed) | CA properties | `4886`/`4887`/`4888` request and issuance records |

## Field notes for the pipeline team

- **`4662.Properties` carries ACE GUIDs, not names.** Match the GUIDs (`1131f6aa…`, `1131f6ad…`, `89e95b76…`), and note that `AccessMask` may legitimately be absent while the GUID still identifies the right.
- **`4769.ServiceName` is the SPN**, not an account. Machine accounts appear as `$`-suffixed *requesters* (`HOST$@DOMAIN`), never as the service name.
- **`4728`/`4732`/`4756` differ by group scope**, not by importance: Domain Admins is global, Administrators on a DC is local, Enterprise and Schema Admins are universal.
- **SIDs should be compared upper-case.** A pipeline that lowercases them makes `S-1-5-21-…-512` match nothing, silently.
- **`5136` has one event per changed attribute**, so a single change can produce several rows; group by `OpCorrelationID` to see the change as one action.
- **`4716` fires on the trust's scheduled password rotation.** Filter by the acting account before treating it as hostile.
- **`39`/`40`/`41` are reused by other providers** in the System channel — filter on the KDC provider name.

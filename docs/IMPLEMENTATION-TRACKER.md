# Detection Implementation Tracker

Tick each box as you build, tune and promote to production. Suggested columns of progress:
- **Draft**: rule logic written (all are drafted in this repo).
- **Fields mapped**: the ECS / near-ECS fields in the query confirmed against your live data.
- **Tuned**: run in a test/low-priority queue, exclusions added, false-positive rate acceptable.
- **Live**: enabled as a production detection with an owner and a response playbook.

Each line ends with the rule's alert suppression key and window. Configure it in the rule's alert suppression settings when you enable the rule. See docs/ESQL-CONVENTIONS.md.

Legend for phase: **P0** do first (fastest, highest value), **P1** core, **P2** depth.

---

## Phase 0 — do these first (days, not weeks)
- [ ] **CS04** Route Falcon high/critical detections into Elastic as alerts _(P0, instant endpoint coverage)_ · `suppress: host.name, technique / 1h`
- [ ] **CS05** Falcon sensor uninstalled/stopped/silent host _(P0, protect visibility)_ · `suppress: host.name / 24h`
- [ ] **C09** Azure logging / Defender for Cloud disabled _(P0, protect visibility)_ · `suppress: none`
- [ ] **E10** Mimecast protection policy weakened or bypass created _(P0, protect visibility)_ · `suppress: mimecast.user, atype / 1h`
- [ ] Build the shared lookups: Tier-0 group list, break-glass accounts, Entra Connect (MSOL_) account, VIP/finance mailbox list, approved RMM, corporate VPN egress ranges, sanctioned device-code users.

## Cloud (Azure / Entra)
- [ ] **C01** Domain federation / auth settings changed _(P1, critical)_ · `suppress: none`
- [ ] **C02** Conditional Access policy created/modified/deleted _(P1)_ · `suppress: actor, azure.auditlogs.properties.target_resources.0.display_name / 1h`
- [ ] **C03** Privileged Entra role assigned / PIM activated _(P1)_ · `suppress: azure.auditlogs.properties.target_resources.0.user_principal_name, role / 8h`
- [ ] **C04** Credential added to app / service principal _(P1)_ · `suppress: actor, azure.auditlogs.properties.target_resources.0.display_name / 1h`
- [ ] **C05** Admin consent / high-privilege Graph permission granted _(P1)_ · `suppress: azure.auditlogs.properties.initiated_by.user.userPrincipalName, azure.auditlogs.properties.target_resources.0.display_name / 1h`
- [ ] **C06** Azure RBAC Owner/UAA/Contributor at sub or MG scope _(P2)_ · `suppress: none`
- [ ] **C07** VM run command / custom script extension / VMAccess _(P2)_ · `suppress: actor, azure.resource.name / 1h`
- [ ] **C08** NSG opens management ports to internet _(P2)_ · `suppress: azure.activitylogs.identity.claims_initiated_by_user.name, azure.resource.name / 1h`
- [ ] **C09** Azure logging / diagnostics / Defender disabled _(P0)_ · `suppress: none`
- [ ] **C10** Storage keys listed / disk SAS / snapshot export _(P2)_ · `suppress: actor, azure.subscription_id / 1h`
- [ ] **C11** Device code outcomes + CA block-then-success bypass _(P1)_ · `suppress: azure.signinlogs.properties.user_principal_name, severity / 24h`

## Email (Mimecast + O365)
- [ ] **E01** Mimecast malicious URL clicked / click-through _(P1)_ · `suppress: mimecast.userEmailAddress, mimecast.url / 24h`
- [ ] **E02** Malicious attachment delivered or released _(P1)_ · `suppress: mimecast.recipientAddress, mimecast.fileHash / 24h`
- [ ] **E03** Impersonation hit targeting execs/finance _(P2)_ · `suppress: mimecast.senderAddress, rcpt / 24h`
- [ ] **E04** O365 ZAP removed a message user had opened/clicked _(P1)_ · `suppress: msg, usr / 24h`
- [ ] **E05** Safe Links block page clicked through _(P1)_ · `suppress: o365.audit.UserId, o365.audit.Url / 24h`
- [ ] **E06** Inbox rule forwards externally / hides security mail _(P1)_ · `suppress: o365.audit.UserId, rule_name / 1h`
- [ ] **E07** Mailbox forwarding / transport rule redirect or BCC _(P1)_ · `suppress: o365.audit.UserId, o365.audit.ObjectId / 1h`
- [ ] **E08** Mailbox delegation (FullAccess/SendAs) added _(P2)_ · `suppress: actor, target / 1h`
- [ ] **E09** Internal account sending outbound phish at volume _(P2)_ · `suppress: sender / 24h`
- [ ] **E10** Mimecast policy weakened / bypass created _(P0)_ · `suppress: mimecast.user, atype / 1h`

## Endpoint — Windows (CrowdStrike FDR)
- [ ] **W01** LSASS credential dump _(P1, critical)_ · `suppress: host.name, process.name / 1h`
- [ ] **W02** Office/browser/mail spawns script host or LOLBIN _(P1)_ · `suppress: host.name, parent, child / 1h`
- [ ] **W03** ClickFix / FileFix / CrashFix from Explorer _(P1)_ · `suppress: host.name, user.name / 1h`
- [ ] **W04** LOLBIN download cradle / remote script exec _(P1)_ · `suppress: host.name, pname / 1h`
- [ ] **W05** Defender/Falcon tamper / EDR-killer / safe boot _(P0-P1, critical)_ · `suppress: host.name / 1h`
- [ ] **W06** Shadow copy / backup destruction _(P1, critical)_ · `suppress: host.name / 1h`
- [ ] **W07** Local admin created / RDP enabled _(P2)_ · `suppress: host.name, user.name / 1h`
- [ ] **W08** Lateral movement execution (PsExec/WMI/WinRM/DCOM) _(P1)_ · `suppress: host.name, user.name / 1h`
- [ ] **W09** AD attack tooling / recon burst _(P1)_ · `suppress: host.name, user.name / 1h`
- [ ] **W10** Unapproved RMM / tunnel tool _(P1)_ · `suppress: host.name, pname / 24h`

## Endpoint — Linux (CrowdStrike FDR)
- [ ] **L01** Reverse shell _(P1, critical)_ · `suppress: host.name / 1h`
- [ ] **L02** Remote script piped into shell _(P1)_ · `suppress: host.name, user.name / 1h`
- [ ] **L03** Web/app server spawns shell _(P1, critical)_ · `suppress: host.name, parent / 1h`
- [ ] **L04** Persistence: cron/systemd/profile/authorized_keys _(P1)_ · `suppress: host.name, user.name / 1h`
- [ ] **L05** Credential file / SSH key / cloud metadata access _(P1)_ · `suppress: host.name, user.name / 1h`
- [ ] **L06** Privilege escalation (SUID/sudo/exploit) _(P2)_ · `suppress: host.name, user.name / 1h`
- [ ] **L07** Log/history tamper, timestomping _(P2)_ · `suppress: host.name / 1h`
- [ ] **L08** Container escape / privileged container / docker.sock _(P2)_ · `suppress: host.name / 1h`
- [ ] **L09** Suspicious kernel module / rootkit _(P2)_ · `suppress: host.name / 24h`
- [ ] **L10** Mass file encryption / wiper _(P1, critical)_ · `suppress: host.name / 1h`

## Identity (AD + authentication, hybrid)
- [ ] **I01** DCSync by non-DC principal _(P1, critical)_ · `suppress: subject / 1h`
- [ ] **I02** Tier-0 group membership change _(P1, critical)_ · `suppress: none`
- [ ] **I03** Kerberoasting (RC4 TGS volume) _(P1)_ · `suppress: acct / 1h`
- [ ] **I04** AS-REP roast / pre-auth disabled _(P2)_ · `suppress: none`
- [ ] **I05** Password spray (AD + Entra) _(P1)_ · `suppress: source.ip, landed / 4h`
- [ ] **I06** Anomalous privileged logon _(P1)_ · `suppress: acct, dest / 8h`
- [ ] **I07** Entra risky sign-in / impossible travel / token replay _(P1)_ · `suppress: usr, source.ip / 24h`
- [ ] **I08** Device code / OAuth phishing _(P1)_ · `suppress: user.name, source.ip / 24h`
- [ ] **I09** AD CS abuse (ESC1/ESC6) _(P2)_ · `suppress: req_user, san / 1h`
- [ ] **I10** MFA method registered / auth policy weakened _(P1)_ · `suppress: target, op / 1h`

## Network (F5 APM, Imperva WAF, Zscaler)
- [ ] **N01** F5 APM VPN impossible travel _(P1)_ · `suppress: usr / 24h`
- [ ] **N02** F5 APM brute force then success _(P1)_ · `suppress: source.ip / 4h`
- [ ] **N03** F5 APM session without expected MFA _(P2)_ · `suppress: user.name, source.ip / 24h`
- [ ] **N04** F5 APM/TMOS admin or policy change _(P2)_ · `suppress: usr / 1h`
- [ ] **N05** Imperva high-severity attack not blocked _(P1)_ · `suppress: source.ip, url.domain / 1h`
- [ ] **N06** Imperva block-then-success (bypass) _(P1)_ · `suppress: source.ip, url.domain / 1h`
- [ ] **N07** Zscaler C2 / malware callback _(P1)_ · `suppress: source.ip, destination.domain / 24h`
- [ ] **N08** Zscaler large upload / exfil _(P2)_ · `suppress: user.name, destination.domain / 24h`
- [ ] **N09** Zscaler anonymizer / tunnel / DoH bypass _(P2)_ · `suppress: user.name, destination.domain / 24h`
- [ ] **N10** Edge scanning / internal port-scan fan-out _(P2)_ · `suppress: src / 1h`

## CrowdStrike FDR (bonus, sensor-native telemetry)
- [ ] **CS01** BYOVD vulnerable driver load _(P1, critical)_ · `suppress: host.name, img / 24h`
- [ ] **CS02** Run key / service / ASEP persistence _(P1)_ · `suppress: host.name, k / 24h`
- [ ] **CS03** Suspicious DNS / DGA / tunneling _(P2)_ · `suppress: host.name, parent / 24h`
- [ ] **CS04** Falcon detections passthrough _(P0)_ · `suppress: host.name, technique / 1h`
- [ ] **CS05** Falcon sensor health / tamper _(P0)_ · `suppress: host.name / 24h`
- [ ] **CS06** Process injection / hollowing _(P2)_ · `suppress: host.name, src / 1h`
- [ ] **CS07** Suspicious scheduled task / service _(P1)_ · `suppress: host.name, payload / 24h`
- [ ] **CS08** (Reference) promote stable rules to Falcon custom IOAs _(ongoing)_


## Entra sign-in extended (high-fidelity sign-on signals)
- [ ] **S01** Break-glass account sign-in _(P0, critical)_ · `suppress: user.name, source.ip / 1h`
- [ ] **S02** Legacy auth / ROPC success / spray-tool user agent _(P1)_ · `suppress: user.name, client / 24h`
- [ ] **S03** Privileged account single-factor sign-in to admin surface _(P1)_ · `suppress: usr, app / 8h`
- [ ] **S04** First-party CLI/PowerShell app used by non-admin (AzureHound/ROADtools) _(P1)_ · `suppress: usr / 24h`
- [ ] **S05** Service principal sign-in from new network / secret-guessing _(P1)_ · `suppress: sp / 24h`
- [ ] **S06** Directory sync account used outside Entra Connect server _(P0, critical)_ · `suppress: usr, source.ip / 24h`
- [ ] **S07** MFA claim replay from unregistered device on hosting/anonymizer _(P1)_ · `suppress: user.name, source.ip / 24h`
- [ ] **S08** One session used from multiple countries/networks (token theft) _(P1)_ · `suppress: usr, sid / 24h`
- [ ] **S09** Sign-in attempts against disabled/leaver accounts _(P2)_ · `suppress: source.ip / 24h`
- [ ] **S10** Workforce sign-in from hosting/VPN/anonymizer to sensitive app _(P2)_ · `suppress: user.name, source.ip / 24h`

## Windows event logs (event-code based)
- [ ] **WE01** Security/System event log cleared (1102/104) _(P0, critical)_ · `suppress: host.name / 1h`
- [ ] **WE02** Audit policy changed outside GPO (4719) _(P1)_ · `suppress: host.name, subject / 1h`
- [ ] **WE03** Domain trust / SID History / DSRM change (4706/4765/4794) _(P1, critical)_ · `suppress: none`
- [ ] **WE04** Lockout storm / explicit-credential fan-out (4740/4648) _(P2)_ · `suppress: host.name / 1h`
- [ ] **WE05** Sensitive privilege / special logon to non-admin (4672) _(P2)_ · `suppress: acct, host.name / 24h`
- [ ] **WE06** GPO modified in sensitive OU / default policy (5136) _(P1)_ · `suppress: actor, dn / 1h`
- [ ] **WE07** WDigest re-enabled / LSA protection disabled (registry) _(P1)_ · `suppress: host.name, k / 24h`
- [ ] **WE08** New service / kernel driver on DC or server (7045/4697) _(P1)_ · `suppress: host.name, svc / 24h`
- [ ] **WE09** NTDS.dit / shadow copy / ntdsutil on a DC (4656/4663) _(P1, critical)_ · `suppress: host.name / 1h`
- [ ] **WE10** Defender detection / protection disabled (1116/5001) _(P1)_ · `suppress: host.name, threat / 24h`

## Correlation (build after the single-source rules feeding them are live)
- [ ] **X01** Phish click -> endpoint alert (same user) _(P1, critical)_ · `suppress: usr, host.name / 24h`
- [ ] **X02** Risky sign-in -> persistence/privilege action _(P1, critical)_ · `suppress: usr, persist_action / 24h`
- [ ] **X03** VPN anomaly -> internal attack _(P2)_ · `suppress: usr, host.name / 4h`
- [ ] **X04** WAF exploit -> shell on web host _(P1, critical)_ · `suppress: h / 24h`
- [ ] **X05** Ransomware precursor chain (one host) _(P1, critical)_ · `suppress: host.name / 1h`

---


## New detections: persistence / lateral movement / initial access (batch 2)
- [ ] **I11** AdminSDHolder modified _(critical)_ · `suppress: op_id / 1h`
- [ ] **I12** Shadow credentials (msDS-KeyCredentialLink) _(high)_ · `suppress: op_id / 1h`
- [ ] **I13** SPN added to a user account _(high)_ · `suppress: op_id / 1h`
- [ ] **I14** Resource-based constrained delegation write _(high)_ · `suppress: op_id / 1h`
- [ ] **WE11** WMI permanent event subscription _(high)_ · `suppress: host.name / 24h`
- [ ] **WE12** Pass-the-hash logon (type 9 / seclogo) _(high)_ · `suppress: host.name, outbound / 1h`
- [ ] **WE13** Coerced DC authentication (NTLM) _(high)_ · `suppress: acct, dest / 1h`
- [ ] **WE14** Admin share / pipe from a workstation _(medium)_ · `suppress: source.ip, host.name / 1h`
- [ ] **WE15** Workstation-to-workstation RDP _(medium)_ · `suppress: source.ip, dest / 4h`
- [ ] **W11** COM hijack / Office add-in persistence _(high)_ · `suppress: host.name, user.name / 24h`
- [ ] **W12** Disk image mounted then execution _(high)_ · `suppress: host.name, exe / 1h`
- [ ] **W13** Intune/SCCM mass deployment _(high)_ · `suppress: actor, op / 1h`
- [ ] **L11** PAM / NSS authentication backdoor _(high)_ · `suppress: host.name, f / 1h`
- [ ] **L12** SSH lateral fan-out _(high)_ · `suppress: host.name, user.name / 1h`
- [ ] **C12** Automation runbook / webhook _(high)_ · `suppress: actor, azure.resource.name / 1h`
- [ ] **C13** Rogue device registration _(high)_ · `suppress: actor / 24h`
- [ ] **E11** Email bombing _(medium)_ · `suppress: rcpt / 24h`
- [ ] **S11** Help-desk MFA reset then new-location sign-in _(high)_ · `suppress: usr / 24h`
- [ ] **X06** External Teams contact then remote tool _(high)_ · `suppress: usr, host.name / 24h`
- [ ] **X07** Persistence after admin elevation _(critical)_ · `suppress: actor / 1h`


## Entra brute force, MFA fatigue and Windows Hello abuse
- [ ] **S12** MFA fatigue, critical if then accepted _(P1, high)_ · `suppress: usr, severity / 4h`
- [ ] **S13** Brute force against one account from a single IP _(P1, high)_ · `suppress: usr, source.ip, landed / 4h`
- [ ] **S14** Distributed brute force against one account from many IPs _(P1, high)_ · `suppress: usr, landed / 4h`
- [ ] **S15** Distributed password spray by client fingerprint _(P2, high)_ · `suppress: ua, app, landed / 4h`
- [ ] **S16** Windows Hello key enrolled after a device-code sign-in _(P1, high/critical)_ · `suppress: uid, severity / 24h`
- [ ] **S17** Device-less Windows Hello sign-in then device registration _(P1, high)_ · `suppress: uid / 24h`


## ROADtools / roadtx
- [ ] **S18** Device registered with roadtx default fingerprint or non-standard client _(P1, high/medium)_ · `suppress: uid, device / 24h`
- [ ] **S19** Microsoft Authentication Broker sign-in from a non-standard client _(P1, high/medium)_ · `suppress: uid, ua / 24h`
- [ ] **S20** Broker refresh token to device registration to PRT chain _(P1, critical)_ · `suppress: uid / 24h`
- [ ] **S21** ROADrecon enumeration through Azure AD Graph _(P2, high; needs AAD Graph activity logs)_ · `suppress: user.id / 1h`

## Suggested build order
1. Phase 0 (visibility + Falcon passthrough) — a few days.
2. Identity + Cloud P1 (I01, I02, I05, I07, I08, C01-C05, C11) — these catch the attacks you are most likely to face first.
3. Endpoint P1 (W01-W06, W08-W10, L01-L05, L10, CS01, CS07) — you already have full FDR, so these are high value.
4. Email P1 (E01, E02, E04-E07) and Network P1 (N01, N02, N05-N07).
5. Correlation (X-series) once their inputs exist. These are your best signals; they just need the feeders first.
6. Remaining P2 rules for depth.

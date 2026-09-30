# Detection Implementation Tracker

Tick each box as you build, tune and promote to production. Suggested columns of progress:
- **Draft**: rule logic written (all are drafted in this repo).
- **Fields mapped**: the ECS / near-ECS fields in the query confirmed against your live data.
- **Tuned**: run in a test/low-priority queue, exclusions added, false-positive rate acceptable.
- **Live**: enabled as a production detection with an owner and a response playbook.

Legend for phase: **P0** do first (fastest, highest value), **P1** core, **P2** depth.

---

## Phase 0 — do these first (days, not weeks)
- [ ] **CS04** Route Falcon high/critical detections into Elastic as alerts _(P0, instant endpoint coverage)_
- [ ] **CS05** Falcon sensor uninstalled/stopped/silent host _(P0, protect visibility)_
- [ ] **C09** Azure logging / Defender for Cloud disabled _(P0, protect visibility)_
- [ ] **E10** Mimecast protection policy weakened or bypass created _(P0, protect visibility)_
- [ ] Build the shared lookups: Tier-0 group list, break-glass accounts, Entra Connect (MSOL_) account, VIP/finance mailbox list, approved RMM, corporate VPN egress ranges, sanctioned device-code users.

## Cloud (Azure / Entra)
- [ ] **C01** Domain federation / auth settings changed _(P1, critical)_
- [ ] **C02** Conditional Access policy created/modified/deleted _(P1)_
- [ ] **C03** Privileged Entra role assigned / PIM activated _(P1)_
- [ ] **C04** Credential added to app / service principal _(P1)_
- [ ] **C05** Admin consent / high-privilege Graph permission granted _(P1)_
- [ ] **C06** Azure RBAC Owner/UAA/Contributor at sub or MG scope _(P2)_
- [ ] **C07** VM run command / custom script extension / VMAccess _(P2)_
- [ ] **C08** NSG opens management ports to internet _(P2)_
- [ ] **C09** Azure logging / diagnostics / Defender disabled _(P0)_
- [ ] **C10** Storage keys listed / disk SAS / snapshot export _(P2)_
- [ ] **C11** Device code outcomes + CA block-then-success bypass _(P1)_

## Email (Mimecast + O365)
- [ ] **E01** Mimecast malicious URL clicked / click-through _(P1)_
- [ ] **E02** Malicious attachment delivered or released _(P1)_
- [ ] **E03** Impersonation hit targeting execs/finance _(P2)_
- [ ] **E04** O365 ZAP removed a message user had opened/clicked _(P1)_
- [ ] **E05** Safe Links block page clicked through _(P1)_
- [ ] **E06** Inbox rule forwards externally / hides security mail _(P1)_
- [ ] **E07** Mailbox forwarding / transport rule redirect or BCC _(P1)_
- [ ] **E08** Mailbox delegation (FullAccess/SendAs) added _(P2)_
- [ ] **E09** Internal account sending outbound phish at volume _(P2)_
- [ ] **E10** Mimecast policy weakened / bypass created _(P0)_

## Endpoint — Windows (CrowdStrike FDR)
- [ ] **W01** LSASS credential dump _(P1, critical)_
- [ ] **W02** Office/browser/mail spawns script host or LOLBIN _(P1)_
- [ ] **W03** ClickFix / FileFix / CrashFix from Explorer _(P1)_
- [ ] **W04** LOLBIN download cradle / remote script exec _(P1)_
- [ ] **W05** Defender/Falcon tamper / EDR-killer / safe boot _(P0-P1, critical)_
- [ ] **W06** Shadow copy / backup destruction _(P1, critical)_
- [ ] **W07** Local admin created / RDP enabled _(P2)_
- [ ] **W08** Lateral movement execution (PsExec/WMI/WinRM/DCOM) _(P1)_
- [ ] **W09** AD attack tooling / recon burst _(P1)_
- [ ] **W10** Unapproved RMM / tunnel tool _(P1)_

## Endpoint — Linux (CrowdStrike FDR)
- [ ] **L01** Reverse shell _(P1, critical)_
- [ ] **L02** Remote script piped into shell _(P1)_
- [ ] **L03** Web/app server spawns shell _(P1, critical)_
- [ ] **L04** Persistence: cron/systemd/profile/authorized_keys _(P1)_
- [ ] **L05** Credential file / SSH key / cloud metadata access _(P1)_
- [ ] **L06** Privilege escalation (SUID/sudo/exploit) _(P2)_
- [ ] **L07** Log/history tamper, timestomping _(P2)_
- [ ] **L08** Container escape / privileged container / docker.sock _(P2)_
- [ ] **L09** Suspicious kernel module / rootkit _(P2)_
- [ ] **L10** Mass file encryption / wiper _(P1, critical)_

## Identity (AD + authentication, hybrid)
- [ ] **I01** DCSync by non-DC principal _(P1, critical)_
- [ ] **I02** Tier-0 group membership change _(P1, critical)_
- [ ] **I03** Kerberoasting (RC4 TGS volume) _(P1)_
- [ ] **I04** AS-REP roast / pre-auth disabled _(P2)_
- [ ] **I05** Password spray (AD + Entra) _(P1)_
- [ ] **I06** Anomalous privileged logon _(P1)_
- [ ] **I07** Entra risky sign-in / impossible travel / token replay _(P1)_
- [ ] **I08** Device code / OAuth phishing _(P1)_
- [ ] **I09** AD CS abuse (ESC1/ESC6) _(P2)_
- [ ] **I10** MFA method registered / auth policy weakened _(P1)_

## Network (F5 APM, Imperva WAF, Zscaler)
- [ ] **N01** F5 APM VPN impossible travel _(P1)_
- [ ] **N02** F5 APM brute force then success _(P1)_
- [ ] **N03** F5 APM session without expected MFA _(P2)_
- [ ] **N04** F5 APM/TMOS admin or policy change _(P2)_
- [ ] **N05** Imperva high-severity attack not blocked _(P1)_
- [ ] **N06** Imperva block-then-success (bypass) _(P1)_
- [ ] **N07** Zscaler C2 / malware callback _(P1)_
- [ ] **N08** Zscaler large upload / exfil _(P2)_
- [ ] **N09** Zscaler anonymizer / tunnel / DoH bypass _(P2)_
- [ ] **N10** Edge scanning / internal port-scan fan-out _(P2)_

## CrowdStrike FDR (bonus, sensor-native telemetry)
- [ ] **CS01** BYOVD vulnerable driver load _(P1, critical)_
- [ ] **CS02** Run key / service / ASEP persistence _(P1)_
- [ ] **CS03** Suspicious DNS / DGA / tunneling _(P2)_
- [ ] **CS04** Falcon detections passthrough _(P0)_
- [ ] **CS05** Falcon sensor health / tamper _(P0)_
- [ ] **CS06** Process injection / hollowing _(P2)_
- [ ] **CS07** Suspicious scheduled task / service _(P1)_
- [ ] **CS08** (Reference) promote stable rules to Falcon custom IOAs _(ongoing)_


## Entra sign-in extended (high-fidelity sign-on signals)
- [ ] **S01** Break-glass account sign-in _(P0, critical)_
- [ ] **S02** Legacy auth / ROPC success / spray-tool user agent _(P1)_
- [ ] **S03** Privileged account single-factor sign-in to admin surface _(P1)_
- [ ] **S04** First-party CLI/PowerShell app used by non-admin (AzureHound/ROADtools) _(P1)_
- [ ] **S05** Service principal sign-in from new network / secret-guessing _(P1)_
- [ ] **S06** Directory sync account used outside Entra Connect server _(P0, critical)_
- [ ] **S07** MFA claim replay from unregistered device on hosting/anonymizer _(P1)_
- [ ] **S08** One session used from multiple countries/networks (token theft) _(P1)_
- [ ] **S09** Sign-in attempts against disabled/leaver accounts _(P2)_
- [ ] **S10** Workforce sign-in from hosting/VPN/anonymizer to sensitive app _(P2)_

## Windows event logs (event-code based)
- [ ] **WE01** Security/System event log cleared (1102/104) _(P0, critical)_
- [ ] **WE02** Audit policy changed outside GPO (4719) _(P1)_
- [ ] **WE03** Domain trust / SID History / DSRM change (4706/4765/4794) _(P1, critical)_
- [ ] **WE04** Lockout storm / explicit-credential fan-out (4740/4648) _(P2)_
- [ ] **WE05** Sensitive privilege / special logon to non-admin (4672) _(P2)_
- [ ] **WE06** GPO modified in sensitive OU / default policy (5136) _(P1)_
- [ ] **WE07** WDigest re-enabled / LSA protection disabled (registry) _(P1)_
- [ ] **WE08** New service / kernel driver on DC or server (7045/4697) _(P1)_
- [ ] **WE09** NTDS.dit / shadow copy / ntdsutil on a DC (4656/4663) _(P1, critical)_
- [ ] **WE10** Defender detection / protection disabled (1116/5001) _(P1)_

## Correlation (build after the single-source rules feeding them are live)
- [ ] **X01** Phish click -> endpoint alert (same user) _(P1, critical)_
- [ ] **X02** Risky sign-in -> persistence/privilege action _(P1, critical)_
- [ ] **X03** VPN anomaly -> internal attack _(P2)_
- [ ] **X04** WAF exploit -> shell on web host _(P1, critical)_
- [ ] **X05** Ransomware precursor chain (one host) _(P1, critical)_

---

## Suggested build order
1. Phase 0 (visibility + Falcon passthrough) — a few days.
2. Identity + Cloud P1 (I01, I02, I05, I07, I08, C01-C05, C11) — these catch the attacks you are most likely to face first.
3. Endpoint P1 (W01-W06, W08-W10, L01-L05, L10, CS01, CS07) — you already have full FDR, so these are high value.
4. Email P1 (E01, E02, E04-E07) and Network P1 (N01, N02, N05-N07).
5. Correlation (X-series) once their inputs exist. These are your best signals; they just need the feeders first.
6. Remaining P2 rules for depth.

# detection_plus — the 35 that matter, plus two meta-detections

A prioritised working set: the 35 detections most breaches cross, in the order an intrusion meets them, plus the two
meta-detections that keep the rest honest. Every row links to the rule that implements it.

**This is a manifest of links, not copies.** It works the same way as `pentest_detections/`. Each rule lives once, in
`rules/`, where it is linted and maintained. A copy here would drift from the version that is tuned. Rules written
for this set (marked **new**) were added to `rules/` in their proper category and are linked from here like the rest.
To hand the set over as files, export the linked rules at that time (e.g. `git archive`) rather than committing a
second copy.

**Coverage key:** **existing** = already in the catalogue · **new** = written for this set · **partial** = covered, with
a stated gap.

**Mode:** *Alert* goes straight to the queue. *Risk* feeds a risk score (RBA) and alerts only in combination. *Risk to
Alert* means the rule carries a `tier` / `finding` column so one query serves both.

---

## Identity and email (most breaches start here now)

| # | Detection | Key signal | ATT&CK | Mode | Rule(s) | Coverage |
|---|---|---|---|---|---|---|
| 1 | New MFA method registered after a risky sign-in | MFA device added within a short window of an anomalous login (AiTM token theft) | T1098.005 | Alert | [`X02`](../rules/08-correlation/X02-identity-compromise-fanout.md) (the chain) · [`I10`](../rules/05-identity/I10-auth-agent-and-mfa-tamper.md) (registration from a new context) · [`S11`](../rules/09-entra-signin-extended/S11-mfa-reset-then-new-signin.md) (help-desk reset variant) | existing |
| 2 | Malicious inbox rules | Forward to external, or move/delete rules with keywords like "invoice" or "payment" | T1564.008 | Alert | [`E06`](../rules/02-email/E06-inbox-rule-forward-delete-hide.md) (inbox rules, incl. the invoice/password keyword shape) · [`E07`](../rules/02-email/E07-mailbox-forwarding-and-transport-rules.md) (mailbox and transport forwarding) | existing |
| 3 | Illicit OAuth consent / app credential added | Risky permissions granted to a new app, or a secret/cert added to an existing app | T1528 | Alert | [`C05`](../rules/01-cloud/C05-admin-consent-high-privilege-app.md) (consent and high-privilege Graph grants) · [`C04`](../rules/01-cloud/C04-service-principal-credential-added.md) (credential added to an app or SP) | existing |
| 4 | Password spray followed by success | One source failing across many users, then a success | T1110.003 | Alert | [`I16`](../rules/05-identity/I16-password-spray-then-success.md) (AD, NTLM and Kerberos) · [`S15`](../rules/09-entra-signin-extended/S15-distributed-password-spray.md) (Entra) · [`N02`](../rules/06-network/N02-f5-apm-brute-force-then-success.md) (F5 VPN) · [`I05`](../rules/05-identity/I05-password-spray.md) (the spray alone) | **new** (AD) + existing |
| 5 | Privileged group changes | Adds to DA/EA/Global Admin/AWS admin roles outside a change window | T1098 | Alert | [`I02`](../rules/05-identity/I02-tier0-group-change.md) · [`I15`](../rules/05-identity/I15-domain-admins-member-added.md) (AD Tier-0) · [`C03`](../rules/01-cloud/C03-privileged-entra-role-assignment.md) · [`S25`](../rules/09-entra-signin-extended/S25-entra-permanent-role-assignment.md) (Entra) · [`AWS-03`](../rules/01-cloud/AWS-03-iam-persistence.md) (AWS admin policy) | partial: no rule gates on a change window yet. Add the window as a label, not a filter |
| 6 | Kerberoasting | 4769 with RC4 (0x17) across many SPNs from one account | T1558.003 | Alert | [`I03`](../rules/05-identity/I03-kerberoasting.md) · [`D01`](../rules/16-deception/D01-honey-ad-account-activity.md) (honey-SPN lure) | existing |
| 7 | DCSync | 4662 replication GUIDs from a host that isn't a DC | T1003.006 | Alert | [`I01`](../rules/05-identity/I01-dcsync-with-origin.md) · [`AD02`](../rules/14-ad-attack/AD02-replication-rights-granted.md) (replication rights granted) | partial: **`I01` cannot fire here yet.** `4662` arrives without `access_mask 0x100` (see `pentest_detections/README.md`). Fix ingest first |

## Endpoint execution and persistence

| # | Detection | Key signal | ATT&CK | Mode | Rule(s) | Coverage |
|---|---|---|---|---|---|---|
| 8 | Credential dumping | Non-standard process accessing LSASS, comsvcs MiniDump, ntdsutil IFM, shadow copy of NTDS | T1003 | Alert | [`W01`](../rules/03-endpoint-windows/W01-lsass-credential-dump.md) (LSASS, incl. comsvcs) · [`WE09`](../rules/10-windows-event-logs/WE09-ntds-dit-access.md) (NTDS + shadow copy on a DC) · [`W18`](../rules/03-endpoint-windows/W18-credential-hive-dumped.md) (SAM/SYSTEM/SECURITY hives) | existing |
| 9 | Office/PDF reader spawning a shell | winword/excel/outlook spawning powershell/cmd/mshta/wscript | T1204 | Alert | [`W02`](../rules/03-endpoint-windows/W02-office-browser-spawns-script-host.md) | existing |
| 10 | Suspicious PowerShell | -enc, download cradles, AMSI bypass strings (needs 4104 logging on) | T1059.001 | Risk to Alert | [`WE20`](../rules/10-windows-event-logs/WE20-suspicious-powershell-script-block.md) (4104: AMSI/ETW bypass, reflective load, cradles) · [`W04`](../rules/03-endpoint-windows/W04-lolbin-download-cradle.md) (`-enc` and cradles on the command line) | **new** + existing |
| 11 | LOLBin proxy execution | rundll32/regsvr32/mshta with network or odd paths, certutil -urlcache | T1218 | Risk | [`W04`](../rules/03-endpoint-windows/W04-lolbin-download-cradle.md) (incl. `certutil -urlcache`) · [`W03`](../rules/03-endpoint-windows/W03-clickfix-filefix-explorer-to-lolbin.md) · [`W15`](../rules/03-endpoint-windows/W15-certutil-trust-store-write.md) (certutil trust store) | existing |
| 12 | Persistence creation | New services (7045), scheduled tasks (4698), Run keys, all from user-writable paths | T1543/T1053 | Risk | [`CS02`](../rules/07-crowdstrike-fdr/CS02-registry-writes-that-matter.md) (Run keys and service ImagePath, native event) · [`CS07`](../rules/07-crowdstrike-fdr/CS07-scheduled-task-that-matters.md) (tasks, fleet rarity) · [`WE08`](../rules/10-windows-event-logs/WE08-service-and-driver-install-on-dc.md) (services on servers) · [`W17`](../rules/03-endpoint-windows/W17-startup-folder-entry.md) · [`WE11`](../rules/10-windows-event-logs/WE11-wmi-event-subscription.md) | partial: tasks and registry come from Falcon events. `4698` and workstation `7045` are not read directly |
| 13 | Unapproved RMM tools | AnyDesk, ScreenConnect, Atera, etc. not on your allowlist | T1219 | Alert | [`W10`](../rules/03-endpoint-windows/W10-unauthorised-rmm-or-tunnel.md) · [`CS14`](../rules/07-crowdstrike-fdr/CS14-tunnel-service-agent.md) (tunnel agents) | existing |

## Lateral movement and discovery

| # | Detection | Key signal | ATT&CK | Mode | Rule(s) | Coverage |
|---|---|---|---|---|---|---|
| 14 | Remote execution | PsExec-style services, WMI/WinRM process creation, admin share writes from non-admin hosts | T1021/T1569 | Risk to Alert | [`W08`](../rules/03-endpoint-windows/W08-lateral-movement-execution.md) · [`LATMOV-02`](../rules/10-windows-event-logs/LATMOV-02-remote-exec-pipes-and-service-installs.md) · [`WE14`](../rules/10-windows-event-logs/WE14-admin-share-and-pipe-from-workstation.md) · [`B05`](../rules/11-behaviour/B05-network-logon-sweep.md) | existing |
| 15 | AD recon bursts | AdFind, nltest /domain_trusts, net group "domain admins", SharpHound-level LDAP volume | T1087/T1482 | Risk | [`B09`](../rules/11-behaviour/B09-discovery-command-burst.md) · [`W09`](../rules/03-endpoint-windows/W09-ad-attack-tooling-and-recon.md) · [`WE16`](../rules/10-windows-event-logs/WE16-bloodhound-smb-enumeration.md) · [`CS21`](../rules/07-crowdstrike-fdr/CS21-ldap-directory-reach.md) · [`AD19`](../rules/14-ad-attack/AD19-adws-directory-access.md) | existing |

## Impact and defence evasion (ransomware precursors)

| # | Detection | Key signal | ATT&CK | Mode | Rule(s) | Coverage |
|---|---|---|---|---|---|---|
| 16 | Backup/recovery tampering | vssadmin/wmic shadow deletes, bcdedit recoveryenabled no, wbadmin delete | T1490 | Alert | [`W06`](../rules/03-endpoint-windows/W06-shadow-copy-and-backup-destruction.md) · [`W19`](../rules/03-endpoint-windows/W19-endpoint-tampering.md) | existing |
| 17 | Security tool tampering | EDR sensor stopped or uninstalled, Defender exclusions added, 1102 log cleared, CloudTrail stopped | T1562 | Alert | [`W05`](../rules/03-endpoint-windows/W05-security-tool-tamper.md) · [`CS05`](../rules/07-crowdstrike-fdr/CS05-falcon-sensor-health-tamper.md) · [`CP06`](../rules/13-controlplane/CP06-defender-protection-weakened.md) (Defender exclusions) · [`WE01`](../rules/10-windows-event-logs/WE01-security-log-cleared.md) (1102) · [`AWS-05`](../rules/01-cloud/AWS-05-logging-or-security-service-disabled.md) (CloudTrail, GuardDuty, Config) · [`C09`](../rules/01-cloud/C09-logging-or-defender-disabled.md) (Azure) | **new** (AWS) + existing |

## Perimeter and network

| # | Detection | Key signal | ATT&CK | Mode | Rule(s) | Coverage |
|---|---|---|---|---|---|---|
| 18 | Web/app server spawning a shell | w3wp/java/tomcat/nginx/CrushFTP spawning cmd/sh/powershell | T1190/T1505.003 | Alert | [`W21`](../rules/03-endpoint-windows/W21-app-server-spawning-shell-windows.md) (Java, Tomcat, CrushFTP on Windows) · [`AD11`](../rules/14-ad-attack/AD11-server-application-spawns-shell.md) (IIS, SQL Server) · [`L03`](../rules/04-endpoint-linux/L03-web-service-spawns-shell.md) (Linux) · [`CS22`](../rules/07-crowdstrike-fdr/CS22-webshell-write-and-execute.md) (webshell write + execute) | **new** + existing |
| 19 | Exfil to cloud storage | rclone/MEGAsync execution, or an outbound volume spike to file-sharing domains | T1567 | Risk to Alert | [`CS18`](../rules/07-crowdstrike-fdr/CS18-attacker-tools-by-name.md) (rclone, MEGA by name) · [`N08`](../rules/06-network/N08-zscaler-exfil-and-anomalous-volume.md) (Zscaler upload volume) · [`N13`](../rules/06-network/N13-shared-cloud-exfil-upload.md) (shared-cloud exfil) | existing |
| 20 | C2 beaconing / new domains | Periodic connections, newly registered domains, threat-intel matches (weak on its own) | T1071 | Risk | [`B06`](../rules/11-behaviour/B06-c2-beaconing.md) · [`B10`](../rules/11-behaviour/B10-zscaler-c2-beacon-unknown-domain.md) · [`B11`](../rules/11-behaviour/B11-zscaler-c2-beacon-known-domain.md) · [`N07`](../rules/06-network/N07-zscaler-c2-and-malware-callback.md) · [`CS26`](../rules/07-crowdstrike-fdr/CS26-requestbin-callback-rotation.md) | existing |

---

## Cloud and SaaS

| # | Detection | Key signal | ATT&CK | Mode | Rule(s) | Coverage |
|---|---|---|---|---|---|---|
| 21 | AWS root / no-MFA console use | Any root activity, or a console login without MFA | T1078.004 | Alert | [`AWS-02`](../rules/01-cloud/AWS-02-root-or-console-login-without-mfa.md) | **new**: needs CloudTrail ingested |
| 22 | IAM persistence | Access key created for another user, admin policy attached, new IAM user or role trust change | T1098.001 | Alert | [`AWS-03`](../rules/01-cloud/AWS-03-iam-persistence.md) | **new**: needs CloudTrail ingested |
| 23 | Cloud storage exposure | Bucket policy or ACL made public, or a GetObject/ListBuckets burst from a new principal or ASN | T1530 | Risk to Alert | [`AWS-04`](../rules/01-cloud/AWS-04-s3-bucket-made-public.md) · [`C10`](../rules/01-cloud/C10-storage-keys-or-disk-export.md) (Azure storage keys and SAS) | **new**: `GetObject` needs S3 data events, which are off by default |
| 24 | K8s/EKS abuse | Privileged or hostPath pods, exec into pods, new binding to cluster-admin, anonymous API calls | T1610/T1611 | Alert | [`K8S-01`](../rules/01-cloud/K8S-01-kubernetes-eks-abuse.md) · [`L08`](../rules/04-endpoint-linux/L08-container-escape-and-docker-abuse.md) (escape seen on the node) | **new**: EKS audit logging is off by default |
| 25 | SaaS mass download / sharing | A spike in SharePoint/OneDrive downloads, or new anonymous "anyone" links | T1213/T1567 | Risk | [`IN01`](../rules/12-insider/IN01-mass-sharepoint-onedrive-download.md) · [`IN02`](../rules/12-insider/IN02-external-sharing-spike.md) | existing |

## AD and identity edge cases

| # | Detection | Key signal | ATT&CK | Mode | Rule(s) | Coverage |
|---|---|---|---|---|---|---|
| 26 | AS-REP roasting | 4768 with pre-auth type 0, or accounts flipped to "no preauth" | T1558.004 | Alert | [`I04`](../rules/05-identity/I04-asreproast-and-preauth-disabled.md) | existing |
| 27 | ADCS abuse (ESC1 etc.) | 4886/4887 where the cert's SAN doesn't match the requester, or vulnerable template changes | T1649 | Alert | [`I09`](../rules/05-identity/I09-adcs-abuse-esc.md) · [`AD06`](../rules/14-ad-attack/AD06-adcs-template-or-ca-tampering.md) (template / CA changes) · [`AD14`](../rules/14-ad-attack/AD14-adcs-denied-request-issued-or-subca-requested.md) (ESC7) | existing |
| 28 | Service / dormant account misuse | Service accounts doing interactive or RDP logons (type 2/10), or dormant accounts coming back to life | T1078 | Risk to Alert | [`WE22`](../rules/10-windows-event-logs/WE22-service-or-dormant-account-misuse.md) · [`I06`](../rules/05-identity/I06-anomalous-privileged-logon.md) (Tier-0 on a workstation) · [`S09`](../rules/09-entra-signin-extended/S09-disabled-account-attempts.md) (disabled and leaver accounts in Entra) | **new** + existing |
| 29 | Local admin creation | 4720 plus 4732 (new account added to local Administrators) on servers | T1136.001 | Alert | [`WE21`](../rules/10-windows-event-logs/WE21-local-admin-created-on-server.md) · [`W07`](../rules/03-endpoint-windows/W07-local-admin-created-or-rdp-enabled.md) (the command-line half) | **new** + existing: needs member-server Security logs |
| 30 | VPN anomalies | F5 APM logins from new countries or VPS ASNs, concurrent sessions, users who never VPN suddenly connecting | T1133 | Risk | [`N01`](../rules/06-network/N01-f5-apm-vpn-impossible-travel.md) (impossible travel) · [`N02`](../rules/06-network/N02-f5-apm-brute-force-then-success.md) (spray then success) · [`N03`](../rules/06-network/N03-f5-apm-mfa-not-satisfied.md) (no MFA step) · [`X03`](../rules/08-correlation/X03-vpn-then-internal-attack.md) (VPN then internal attack) | partial: VPS-ASN, concurrent-session and never-VPN-before need a baseline. That is UEBA work, not a static rule |

## Endpoint (second batch)

| # | Detection | Key signal | ATT&CK | Mode | Rule(s) | Coverage |
|---|---|---|---|---|---|---|
| 31 | Execution from user-writable paths and containers | Binaries running from AppData/Temp/ProgramData, or from mounted ISO/VHD/LNK | T1204/T1553.005 | Risk | [`W20`](../rules/03-endpoint-windows/W20-rare-binary-from-user-writable-path.md) (rare hash in the fleet) · [`W12`](../rules/03-endpoint-windows/W12-iso-img-vhd-mount-execution.md) (ISO/VHD) · [`CLICKONCE-01`](../rules/03-endpoint-windows/CLICKONCE-01-clickonce-app-started.md) | **new** + existing |
| 32 | BYOVD | Vulnerable driver loads (loldrivers.io hash list), or new kernel driver services | T1068/T1562.001 | Alert | [`CS01`](../rules/07-crowdstrike-fdr/CS01-byovd-vulnerable-driver-load.md) | existing |
| 33 | Mass file modification | High-volume renames or writes with new extensions, or ransom-note filenames dropped across shares | T1486 | Alert | [`B12`](../rules/11-behaviour/B12-mass-file-modification.md) (OneDrive/SharePoint) · [`L10`](../rules/04-endpoint-linux/L10-mass-file-encryption-or-wiper.md) (Linux/ESXi) · [`X05`](../rules/08-correlation/X05-ransomware-precursor-chain.md) (precursor chain) · [`CS04`](../rules/07-crowdstrike-fdr/CS04-falcon-detections-passthrough.md) (Falcon's own ransomware verdicts) | partial: **Windows endpoint file writes are not collected.** Local-disk and file-share encryption is not visible until that changes |
| 34 | Linux persistence and reverse shells | authorized_keys edits, new cron or systemd units, bash -i >& /dev/tcp, curl \| sh | T1098.004/T1059.004 | Risk to Alert | [`L04`](../rules/04-endpoint-linux/L04-persistence-cron-systemd-ssh-keys.md) · [`L01`](../rules/04-endpoint-linux/L01-reverse-shell.md) · [`L02`](../rules/04-endpoint-linux/L02-download-and-execute-pipe.md) | existing |

## Network (second batch)

| # | Detection | Key signal | ATT&CK | Mode | Rule(s) | Coverage |
|---|---|---|---|---|---|---|
| 35 | DNS tunnelling / anomalous DNS | High-entropy or very long subdomains, TXT query volume, one host spamming a single domain | T1071.004 | Risk | [`CS03`](../rules/07-crowdstrike-fdr/CS03-dns-tunnelling.md) · [`CS28`](../rules/07-crowdstrike-fdr/CS28-dns-tunnel-seen-at-the-resolver.md) (at the resolver) · [`CS27`](../rules/07-crowdstrike-fdr/CS27-dns-to-an-external-resolver.md) (resolver bypass) | existing |

---

## The two meta-detections

| Meta | Why | Rule(s) | Coverage |
|---|---|---|---|
| **Log source silence** | If DC or EDR logs stop arriving, every detection above goes quiet without saying so | [`CP07`](../rules/13-controlplane/CP07-log-source-silent.md) (a feed or a DC stopped) · [`CS05`](../rules/07-crowdstrike-fdr/CS05-falcon-sensor-health-tamper.md) · [`CP04`](../rules/13-controlplane/CP04-crowdstrike-rfm-or-not-reporting.md) (Falcon sensor stopped or in RFM) | **new** + existing |
| **Honeytokens and canaries** | Close to zero false positives. They catch #6, #8 and #15 cheaply, and are ideal before a red team | [`D05`](../rules/16-deception/D05-honey-credential-used.md) (decoy creds in LSASS, honey DA) · [`D01`](../rules/16-deception/D01-honey-ad-account-activity.md) (honey SPN) · [`D02`](../rules/16-deception/D02-honey-entra-identity-signin.md) (honey Entra user) · [`D03`](../rules/16-deception/D03-honey-file-or-page-opened.md) (canary docs) · [`D04`](../rules/16-deception/D04-decoy-host-or-name-touched.md) (decoy hosts) | **new** + existing |

---

## Ship order

**If only five ship this quarter:** #1, #2, #8, #16, #17. In this repo that is `X02`, `E06`, `W01` + `WE09`,
`W06`, and `W05` + `CS05` + `CP06`. They catch most BEC, and most ransomware before encryption. Ship **`CP07` with
them**: those five are worth little if their sources can go silent unnoticed.

**Alert-grade standouts in the second batch:** #27 ADCS (`I09`), #32 BYOVD (`CS01`), #33 mass encryption (`B12`), and
#21 root use (`AWS-02`). Low volume, high signal.

**Tune before enabling:** #4, #6 and #7 (`I16`, `I03`, `I01`) need the baseline of DCs, shared hosts and service
accounts set first, or they will spam the queue. Each rule carries its baseline query.

**#33 is the last line of defence.** If `B12` fires, #16 and #17 already missed. Wire it to automated host isolation,
not a ticket.

**Build on UEBA, not static rules:** #28's dormant half and #30's VPN baseline get much better with per-user history.
They are natural fits for the risk side of an RBA rollout.

## Chaining the Risk items

Most *Risk* rows get far stronger when they line up on one host or user within 24 hours. The textbook ransomware
sequence is recon (#15), then remote execution (#14), then a shadow delete (#16). `X05` already encodes that chain on
one host, and it is exactly where RBA earns its keep. The other correlation rules (`X01` to `X07`) are the same idea for
the phishing, identity, VPN, WAF and help-desk paths.

## Data this set needs that the estate does not have yet

| Need | Rules waiting on it |
|---|---|
| AWS CloudTrail ingested (`logs-aws.cloudtrail-*`), ideally from an organisation trail | `AWS-02`, `AWS-03`, `AWS-04`, `AWS-05` |
| EKS control-plane audit logging enabled and shipped (`logs-kubernetes.audit_logs-*`) | `K8S-01` |
| PowerShell script block logging (4104) on across the Windows fleet | `WE20` |
| Member-server Security logs, not only domain controllers | `WE21` (and the server half of `WE22`) |
| Windows endpoint file-write telemetry (FDR subscription change, or `4663` on file servers) | the endpoint half of #33 |
| S3 data events, at least on sensitive buckets | the `GetObject` half of #23 |

Each of these rules carries its own probe query, so the gap can be confirmed in a minute before anyone builds on it.

# Visibility gaps

What this estate cannot see, what each gap costs, and the probe that confirms it. Compiled from the coverage
work on this repo; every row is either confirmed by a probe in this environment or explicitly marked unverified.
Re-run the probes before designing on any of it — a gap that closed is as costly to carry as one that opened.

## Absent: no amount of tuning fixes these

| Missing | Consequence | Rules that cannot fire | Probe |
|---|---|---|---|
| **4662 (Directory Service Access)** | No audit of directory object operations at all. This is the biggest hole in the AD story: it is the only DC-side record of *what* was read or written on an object. | `I01` DCSync, `AD02` replication rights, `AD04` DPAPI backup key, `AD09` gMSA read, `ldap-security-descriptor-enumeration`, `dcsync-with-origin`, and the ACL half of `bloodhound-smb-enumeration` | `event.code == "4662"` over 30 days — expect nothing |
| **5145 (Detailed File Share)** | No named-pipe record. Removes the *method* test from SMB collection: psexec/atexec/`\pipe\cert`/srvsvc all look alike. `relative_target_name` was **never populated**, so the field-level fallback does not exist either. | `WE14`, `certipy 03`, and the pipe-name version of BloodHound detection | `event.code == "5145"` — no rows for ~8 months |
| **1644 (Directory Service diagnostics)** | No LDAP search filter, no `SDFlags`. The most precise directory-collection signal there is, off because NTDS diagnostics Level 5 costs 10-50k EPS on a busy DC. | Any `SDFlags 0x4/0x5/0x7` rule | `event.code == "1644"` per DC — expect empty |
| **FDR named-pipe events** | Falcon in this feed has no pipe connect event, so the collector's own sensor cannot name the pipe either. | The BloodHound/coercion pipe rules | `event.action LIKE "*pipe*"` |
| **FDR share names** | `smbclientshareopenedetw` / `smbservershareopenedetw` exist but carry no `ShareName`, so FDR cannot separate an IPC$ sweep from data-share hunting. | Any FDR share-name rule | `registry`-style field probe on the share events |
| **5156 (Windows Filtering Platform)** | No per-connection attribution on the DC. ADWS queries reach LDAP through the DC's own web service and are logged as `::1`, and 5156 is the only thing that recovers the real client. | ADWS attribution in `ldap-directory-reach` (the `directory_sweep_adws` label exists to warn about exactly this) | `event.code == "5156"` |
| **Linux file and audit telemetry** | Process events only. No `authorized_keys` writes, no crontab edits, no systemd unit drops — so the Linux half of the October 2026 Cursor extension incident (its `@reboot` persistence) is invisible. | `editor-extension-ssh-backdoor` covers the process shape, not the persistence | write to `/tmp` on a lab host, look for a file event |
| **DHCPv6, LLMNR, NBT-NS** | No direct record of the poisoning vectors. Detection is only the victims' behaviour afterwards. | `poisoning-sink`, `ipv6-poisoning` are behavioural inferences, never proof | no source to probe |
| **DNS response size** | FDR `dnsrequest` has no response volume, so a tunnel's *direction* and payload cannot be measured — only its question names. | `dns-tunnelling` measures the query side only | field probe on `dnsrequest` |
| **Unmanaged hosts** | No sensor, no telemetry — and the VAPOR PANDA reporting says the framework explicitly inventories hosts without a Falcon agent before acting. Every endpoint rule in this library stops at the managed boundary. | all endpoint rules | compare Falcon host count to DNS/DHCP lease count |

## Unverified: probe before trusting anything built on them

| Needed | Rules that depend on it | Probe |
|---|---|---|
| **5136 / 5137** (DS Change auditing) | `dcshadow-rogue-dc`, `adminsdholder-modified` | `STATS n = COUNT(*) BY event.code` for both over 30 days |
| **4768 / 4769** (Kerberos on the DCs) | `pkinit-ticket-to-self` | same, plus `BY winlog.event_data.pre_auth_type` |
| **KDC 39 / 40 / 41** (System channel) | `kdc-certificate-mapping-failure` | `BY winevt.provider_name, event.code` |
| **4728 / 4732 / 4756** (group membership) | `domain-admins-member-added` | the Domain Admins rule caught nothing — check `event.code` presence first, then SID casing, then the field name |
| **4663** (object access) | the file-read half of NTDS theft | `event.code == "4663"` per DC |
| **Sysmon** | every `rules/` entry targeting `XmlWinEventLog` | `event.dataset`/`winlog.channel` probe — if absent, those rules are dead letters rather than coverage |

## What the gaps mean in combination

- **DCSync is not detectable here.** It needs 4662 and nothing else in this estate records the read. The compensating move is not a query: it is enabling Audit Directory Service Access with the default domain-NC SACL, which is cheap compared with 1644 and restores `I01`, `AD02`, `AD04`, `AD09` and the ACL half of the BloodHound rule at once. Until then, `dcsync-with-origin` should be treated as a reference rule, not a deployed one.
- **Directory collection is only visible from the network side.** With 4662, 5145 and 1644 all absent, `ldap-directory-reach` and the IPC$-only BloodHound rule are the entire coverage — they see *reach*, never *what was read*.
- **The FDR share and pipe losses push every SMB rule onto 5140**, which sees the share open and nothing about the pipe. That is why the share-hunting and BloodHound rules rely on absence conditions (no data-share opens, IPC$ only) rather than on names.
- **Unmanaged hosts are the strategy gap, not a rule gap.** Everything in this library assumes a sensor on the endpoint; the reported ARTEX-family tradecraft is web-facing and never touches an endpoint, which is a different telemetry problem entirely (WAF, API gateway, IdP).

## Rules kept as reference, not deleted

Per the library's own convention: a rule whose only source is missing stays in the tree, **marked at the top**, with the probe that proves the gap and a link to whatever replaced it. That is why `ldap-security-descriptor-enumeration` and `WE09`'s 4663 half are still present. Deleting them means re-deriving the research when the audit policy is fixed; shipping them unmarked means someone deploys a rule that returns zero rows and concludes the estate is clean.

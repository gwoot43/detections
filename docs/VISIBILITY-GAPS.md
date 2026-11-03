# Visibility gaps

Event codes and field names only, each classified: **log not collected** (the event never arrives) or
**field insufficient** (the event arrives but does not carry what the detection needs). Confirmed unless marked
**unverified**.

## Event codes

| Code | Type | Detections that cannot be made |
|---|---|---|
| `5145` | log not collected | Named-pipe method: `psexec`/`atexec`, `\pipe\cert` CA abuse, BloodHound's per-interface RPC. The pipe names themselves - `lsarpc`, `efsr`, `srvsvc`, `samr`, `wkssvc`, `winreg` - were never recorded, so even a restored feed would need the field populated (see below). |
| `1644` | log not collected | LDAP search: `SDFlags` security-descriptor collection, base-scope vs full-directory walk, the search filter itself. |
| `5156` | log not collected | Per-connection attribution on the DC: ADWS-sourced access cannot be traced to a client address. |
| `4663` | log not collected | File-read on the DC: `ntds.dit`, SAM/SECURITY hives, shadow-copy copy-out - NTDS theft by file rather than by command. |
| `5136` | **unverified** | Directory modify: DCShadow's DRS SPN add, AdminSDHolder ACL write, SYSVOL/GPO attribute tampering. |
| `5137` | **unverified** | Directory object creation: rogue NTDS Settings / server object under `CN=Sites,CN=Configuration`. |
| `4768` | **unverified** | Kerberos AS-REQ: PKINIT certificate logon, pre-auth downgrade, AS-REP roast targeting. |
| `4769` | **unverified** | Service tickets: ticket-to-self (UnPAC-the-hash), kerberoasting volume, RC4 downgrade. |
| `39` / `40` / `41` (KDC) | **unverified** | Certificate-mapping failures: another account's SID, no strong mapping, certificate older than the account. |
| `4728` / `4732` / `4756` | field insufficient | Tier-0 membership is possible in principle - the events arrive - but the Domain Admins rule matched nothing, so the SID field or its casing is the problem. |
| `4662` | field insufficient | Directory access is only partly observable: see `access_mask` below. Write-side detections work; read and control-access ones do not. |

## Fields and field values

| Field | Type | Detections that cannot be made |
|---|---|---|
| `winevt.event_data.access_mask` = `0x10`, `0x100` | field insufficient | DCSync and directory-replication detections: the replication rows are control access (`0x100`), which never arrives. Same for replication-rights grants, DPAPI backup-key reads, gMSA password reads, ACL/security-descriptor enumeration. `0x1` arrives, so write-side detections are possible. |
| `winevt.event_data.relative_target_name` | field insufficient | Pipe-name detections, even if `5145` returns - never populated, so `lsarpc`/`efsr`/`srvsvc`/`samr`/`wkssvc`/`winreg` cannot be identified. |
| `ShareName` on `smbclientshareopenedetw` / `smbservershareopenedetw` | field insufficient | FDR-side separation of an IPC$ sweep from data-share hunting - both rules must run on `5140` instead. |
| FDR named-pipe event type | log not collected | Coercion pipe-call detection from the sensor, and the BloodHound method test on the collector's own telemetry. `event.action LIKE "*pipe*"` returns nothing. |
| ADWS client address on the DC | field insufficient | Attribution of ADWS-sourced directory collection; it records `::1`, and `5156` would be needed to recover the real source. |
| `dns.question` response size | field insufficient | Tunnel direction and payload - only the query side is measurable. |
| Linux file events | log not collected | Linux persistence: `authorized_keys` writes, crontab `@reboot`, systemd unit drops. Process-shape detections still work. |
| DHCPv6, LLMNR, NBT-NS | log not collected | Direct poisoning detection; only victim-behaviour inference is possible. |
| `winlog.computer_name` vs `host.name` | field insufficient | Not a gap but a trap: they hold different values, so a rule grouping on `host.name` attributes events to the wrong machine. |
| Sysmon (`XmlWinEventLog`) | **unverified** | If absent, no Sysmon-channel detections exist: image loads, file creates, registry sets, pipe connects. |

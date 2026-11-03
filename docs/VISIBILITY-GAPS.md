# Visibility gaps

Event codes and field names only, with the detections that cannot be made because of each. Confirmed unless
marked **unverified**.

## Event codes

| Code | Detections that cannot be made |
|---|---|
| `5145` | Named-pipe detections: `psexec`/`atexec` method, `\pipe\cert` CA abuse, BloodHound's per-interface RPC (`srvsvc`, `samr`, `wkssvc`, `winreg`). The method test is lost, leaving only share-open breadth. |
| `1644` | LDAP search detections: `SDFlags` security-descriptor collection, base-scope vs full-directory walk, the search filter itself. |
| `5156` | Per-connection attribution on the DC: ADWS-sourced directory access cannot be traced to a client address, because ADWS arrives as `::1`. |
| `4663` | File-access detections on the DC: `ntds.dit` read, SAM/SECURITY hive read, shadow-copy copy-out, NTDS theft by file rather than by command. |
| `5136` | Directory-modify detections: DCShadow's DRS SPN add, AdminSDHolder ACL write, SYSVOL/GPO attribute tampering. |
| `5137` | Directory object-creation detections: rogue NTDS Settings / server object under `CN=Sites,CN=Configuration` (the object half of DCShadow). |
| `4768` | Kerberos AS-REQ detections: PKINIT certificate logon, pre-auth type downgrade, AS-REP roast targeting. |
| `4769` | Service-ticket detections: ticket-to-self (UnPAC-the-hash), kerberoasting volume, RC4 downgrade. |
| `39` / `40` / `41` (KDC) | Certificate-mapping detections: logon with another account's SID, no strong mapping, certificate older than the account. |
| `4728` / `4732` / `4756` | Collected - tier-0 membership detections are possible. The Domain Admins rule matched nothing, so the fault is the field or its casing, not the event. |
| `4662` | Collected, but see `access_mask` below - the masks decide which directory-access detections are possible. |

## Fields and field values

| Field | Detections that cannot be made |
|---|---|
| `winevt.event_data.access_mask` = `0x10`, `0x100` | DCSync and directory-replication detections: the replication-rights rows DCSync produces are control access (`0x100`), which never arrives. Same for replication-rights grants, DPAPI backup-key reads, gMSA password reads and ACL/security-descriptor enumeration. `0x1` arrives, so write-side detections are possible. |
| `winevt.event_data.relative_target_name` | Pipe-name detections, even if `5145` returns - the field was never populated. |
| `ShareName` on `smbclientshareopenedetw` / `smbservershareopenedetw` | FDR-side separation of an IPC$ sweep from data-share hunting. Both rules must run on `5140` instead. |
| FDR named-pipe event (`event.action LIKE "*pipe*"`) | Coercion pipe-call detection from the sensor side, and the BloodHound method test on the collector's own telemetry. |
| ADWS client address on the DC | Attribution of ADWS-sourced directory collection; `5156` would be needed. |
| `dns.question` response size | Tunnel direction and payload detections - only the query side is measurable. |
| Linux file events | Linux persistence detections: `authorized_keys` writes, crontab `@reboot`, systemd unit drops. Process-shape detections still work. |
| DHCPv6, LLMNR, NBT-NS | Direct poisoning detections. Only victim-behaviour inference is possible. |
| `winlog.computer_name` | Not a gap but a trap: it and `host.name` hold different values, so a rule grouping on `host.name` attributes events to the wrong machine. |
| Sysmon (`XmlWinEventLog`) | **unverified** - if absent, no Sysmon-channel detections (image loads, file creates, registry sets, pipe connects) exist at all. |

# Visibility gaps

Event codes and field names only, each classified: **log not collected** (the event never arrives) or
**field insufficient** (the event arrives but does not carry what the detection needs). Confirmed unless marked
**unverified**.

## Event codes

| Code | Type | Detections that cannot be made | Remediation |
|---|---|---|---|
| `5145` | log not collected | Named-pipe method: `psexec`/`atexec`, `\pipe\cert` CA abuse, BloodHound's per-interface RPC. The pipe names - `lsarpc`, `efsr`, `srvsvc`, `samr`, `wkssvc`, `winreg` - were never recorded either, so the field needs populating too. | Enable the **Detailed File Share** audit subcategory (`auditpol /set /subcategory:"Detailed File Share" /success:enable`) on DCs and file servers, then fix the pipeline's `relative_target_name` mapping. High volume - scope it to the servers that matter. |
| `1644` | log not collected | LDAP search: `SDFlags` security-descriptor collection, base-scope vs full-directory walk, the search filter itself. | Raise NTDS diagnostics to **Level 5**: `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics` → `15 Field Engineering` = `5`. 10-50k EPS on a busy DC, so run it as a bounded hunt window, or only on the DCs that hold the sensitive objects. |
| `5156` | log not collected | Per-connection attribution on the DC: ADWS-sourced access cannot be traced to a client address. | Enable **Filtering Platform Connection** (`auditpol /set /subcategory:"Filtering Platform Connection" /success:enable`) - extremely noisy, so scope it to the DCs and to the ports of interest, or use Falcon network events as the cheaper substitute. |
| `4663` | log not collected | File-read on the DC: `ntds.dit`, SAM/SECURITY hives, shadow-copy copy-out - NTDS theft by file rather than by command. | Enable **File System** auditing and add a SACL for `ReadData`/`ReadAttributes` on `C:\Windows\NTDS` (and the shadow-copy path). Object-level, so it only costs on those files. |
| `5136` | **unverified** | Directory modify: DCShadow's DRS SPN add, AdminSDHolder ACL write, SYSVOL/GPO attribute tampering. | Enable **Directory Service Changes** (`auditpol /set /subcategory:"Directory Service Changes" /success:enable`) and confirm a SACL covers `CN=System` and the configuration partition. |
| `5137` | **unverified** | Directory object creation: rogue NTDS Settings / server object under `CN=Sites,CN=Configuration`. | Same subcategory as `5136`, plus a SACL on the Sites container that audits **Create Child** - the site container is not covered by the default domain-NC SACL. |
| `4768` | **unverified** | Kerberos AS-REQ: PKINIT certificate logon, pre-auth downgrade, AS-REP roast targeting. | Enable **Kerberos Authentication Service** under Account Logon on the DCs (often on already, since it is required for most identity detections). |
| `4769` | **unverified** | Service tickets: ticket-to-self (UnPAC-the-hash), kerberoasting volume, RC4 downgrade. | Enable **Kerberos Service Ticket Operations** under Account Logon on the DCs. |
| `39` / `40` / `41` (KDC) | **unverified** | Certificate-mapping failures: another account's SID, no strong mapping, certificate older than the account. | No audit policy needed - the KDC writes these to the System channel by default. Fix collection of the System channel and keep the `Kdcsvc` provider filter. |
| `4728` / `4732` / `4756` | field insufficient | Tier-0 membership is possible in principle - the events arrive - but the Domain Admins rule matched nothing, so the SID field or its casing is the problem. | No audit change: verify `target_sid` exists and its casing in the pipeline, and compare `TO_UPPER(...)` against the RID rather than matching raw. |
| `4662` | field insufficient | Directory access is only partly observable: write-side works, read and control-access do not (see `access_mask`). | Add a domain-NC SACL entry auditing **Read Property** and **Control Access** on the domain object. This is the one change that restores several rules at once, and it is cheap compared with Level 5. |

## Fields and field values

| Field | Type | Detections that cannot be made | Remediation |
|---|---|---|---|
| `winevt.event_data.access_mask` = `0x10`, `0x100` | field insufficient | DCSync and directory-replication detections: the replication rows are control access (`0x100`), which never arrives. Same for replication-rights grants, DPAPI backup-key reads, gMSA password reads, ACL/security-descriptor enumeration. `0x1` arrives, so write-side detections are possible. | The SACL entry in the `4662` row above. Expect a volume increase on the DCs; scope by object (domain NC) rather than by container where you can. |
| `winevt.event_data.relative_target_name` | field insufficient | Pipe-name detections, even if `5145` returns - `lsarpc`/`efsr`/`srvsvc`/`samr`/`wkssvc`/`winreg` cannot be identified. | Pipeline work: map the raw `RelativeTargetName` field. The event carries it; the ingest does not. |
| `ShareName` on `smbclientshareopenedetw` / `smbservershareopenedetw` | field insufficient | FDR-side separation of an IPC$ sweep from data-share hunting - both rules must run on `5140` instead. | None - the Falcon event does not carry it. Workaround: `5140` (target-side) for share names, FDR for process context. |
| FDR named-pipe event type | log not collected | Coercion pipe-call detection from the sensor, and the BloodHound method test on the collector's own telemetry. | None available in this feed. Substitutes: `5145` (needs the audit work above) or Falcon support for a pipe-connect event. |
| ADWS client address on the DC | field insufficient | Attribution of ADWS-sourced directory collection; it records `::1`. | `5156` on the DCs to pair the connection with the real source, or fall back to Falcon network events for the DRS bind. |
| `dns.question` response size | field insufficient | Tunnel direction and payload - only the query side is measurable. | Pipeline or vendor gap; no sensor setting produces it. Use the query-side shape (uniqueness, label length) instead. |
| Linux file events | log not collected | Linux persistence: `authorized_keys` writes, crontab `@reboot`, systemd unit drops. | Deploy `auditd` rules (or Falcon FIM) on the Linux hosts and ship them to the same index family. |
| DHCPv6, LLMNR, NBT-NS | log not collected | Direct poisoning detection; only victim-behaviour inference is possible. | DHCP server logs plus a network sensor (Zeek/Suricata) on the segments that matter. Endpoint telemetry cannot see the broadcast. |
| `winlog.computer_name` vs `host.name` | field insufficient | Not a gap but a trap: they hold different values, so a rule grouping on `host.name` attributes events to the wrong machine. | Authoring fix: use `winlog.computer_name` for the event's Computer. |
| Sysmon (`XmlWinEventLog`) | **unverified** | If absent, no Sysmon-channel detections exist: image loads, file creates, registry sets, pipe connects. | Deploy Sysmon with the repo's config, or confirm the Elastic integration is producing `winlog.channel` events before trusting any `rules/` entry. |

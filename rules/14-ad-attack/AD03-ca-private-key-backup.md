---
id: AD03
name: Certificate authority private key backed up or exported (golden certificate)
category: ad-attack
status: todo
severity: critical
rank: 3
language: esql
index: logs-system.security*, logs-windows.forwarded*, logs-crowdstrike.fdr-*
mitre: [T1649, T1552.004]
data_source: AD CS audit events 4876/4877 on the CA, and CrowdStrike FDR process events
suppression:
  fields: [h]
  duration: 6h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Whoever holds the enterprise CA's private key can issue a valid certificate for any account, indefinitely, and revoking or resetting the account does not stop it. The only fix is rebuilding the PKI. Backing up the CA key is something a PKI team does a few times a year at most, so any backup or export of it outside a planned window is a critical event.

## Prerequisite
Events 4876 and 4877 need CA auditing enabled for backup and restore (the CA audit filter) plus "Audit Certification Services" on the CA. Set `ca_hosts` below to your CA servers.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded*, logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.code IN ("4876", "4877")                                  // CA backup started / completed
   OR event.action == "ProcessRollup2"
// Windows events: winlog.computer_name (with event forwarding, host.name is the collector); FDR: host.name
| EVAL h = TO_LOWER(MV_FIRST(SPLIT(COALESCE(winlog.computer_name, host.name), "."))),
       cl = TO_LOWER(COALESCE(process.command_line, "")),
       pname = TO_LOWER(COALESCE(process.name, ""))
| EVAL ca_host = h IN ("ca01", "ca02")                                   // your CA servers
| WHERE event.code IN ("4876", "4877")
   OR (pname == "certutil.exe"
       AND (cl LIKE "*-backupkey*" OR cl LIKE "*-backup *"
            OR (ca_host AND cl LIKE "*-exportpfx*")))
| KEEP @timestamp, h, event.code, user.name, winlog.event_data.SubjectUserName, winlog.event_data.BackupTypeDescription,
       process.command_line, process.parent.name
```
`-exportpfx` is only flagged on CA hosts, since exporting an ordinary certificate elsewhere is routine. `-backupdb` is not matched: it copies the database without the CA key.

## Suppression
Suppress by `h` for 6h. Alerts missing a key field are not suppressed. One backup writes a start and a completion event plus the command; a different host still alerts.

## Known false positives / exclusions
- Planned CA backups by the PKI team. Expected a few times a year; confirm against change control rather than excluding.
- Backup software that calls the CA backup API on a schedule. Exclude its service account inline once confirmed.

## Triage
- Confirm the backup was planned. If not, assume the CA key is compromised: plan a CA rebuild, and in the meantime hunt for certificate logons (4768 with certificate details) by privileged accounts.
- Find out who had admin access to the CA host and how (AD06 for CA configuration changes, W01 for credential theft on the CA).

## Test
Run a CA key backup on a lab CA and confirm the events.

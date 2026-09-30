---
id: X05
name: Ransomware precursor chain on one host
category: correlation
status: todo
severity: critical
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1486, T1490, T1562.001, T1489]
data_source: CrowdStrike FDR (W05/W06/CS01) on the same host in a short window
suppression:
  fields: [host.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Ransomware detonation is a recognisable sequence: disable defenses (W05 / CS01 BYOVD), then destroy backups (W06), then encrypt (mass file writes). Any two of these on one host within fifteen minutes is a detonation in progress, and catching it between defense-disable and encryption is the difference between one host and the whole estate.

## Query
```esql
FROM logs-crowdstrike.fdr-*
| WHERE @timestamp > NOW() - 30 minutes AND host.os.type == "windows"
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, "")), pname = TO_LOWER(COALESCE(process.name, "")), act = event.action
| EVAL stage = CASE(
      (cmd LIKE "*set-mppreference*disable*" OR cmd LIKE "*sc *stop*" AND (cmd LIKE "*windefend*" OR cmd LIKE "*csfalcon*")) OR act == "DriverLoad" AND TO_LOWER(TO_STRING(file.path)) LIKE "*\\temp\\*", "defense_disable",
      (pname == "vssadmin.exe" AND cmd LIKE "*delete shadows*") OR (pname == "wbadmin.exe" AND cmd LIKE "*delete*") OR (pname == "bcdedit.exe" AND cmd LIKE "*recoveryenabled no*"), "backup_destroy",
      (pname == "cipher.exe" AND cmd LIKE "*/w*") OR cmd LIKE "*vssadmin*resize*", "impact_prep",
      NULL)
| WHERE stage IS NOT NULL
| STATS stages = COUNT_DISTINCT(stage), which = VALUES(stage), cmds = VALUES(process.command_line)
    BY host.name, BUCKET(@timestamp, 15 minutes)
| WHERE stages >= 2
```

## Suppression
Suppress by `host.name` for 1h. Alerts missing a key field are not suppressed. Aggregating rule. Every new host still alerts.

## Known false positives / exclusions
- Backup software plus a Defender exclusion change in the same window is conceivable on a backup server. Exclude backup servers by hostname, or require one stage to be an unmistakable attacker action (shadow delete or BYOVD).

## Triage
- Isolate immediately and sweep the fleet for the same stages: ransomware runs in parallel across hosts. Pull the encryptor binary and block its hash fleet-wide.

## Test
In an isolated lab, run a benign shadow-copy delete plus a Defender exclusion within the window.
